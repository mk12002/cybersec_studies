# Model Inversion & Extraction — ML Security Engineering Breakdown

**Classification:** Internal Engineering Reference  
**Audience:** ML Engineers, Security Researchers, Platform Architects  
**Assumed Reader:** Will be interviewed on this system. Every claim is mathematically grounded and defensible.  
**Key References:** Fredrikson et al. 2015 (model inversion), Tramèr et al. 2016 (model extraction), Shokri et al. 2017 (membership inference), Abadi et al. 2016 (DP-SGD).

---

## Table of Contents

1. [Attack/Defense Narrative](#1-attackdefense-narrative)
2. [Data Ingestion & Preprocessing Flow](#2-data-ingestion--preprocessing-flow)
3. [Model Architecture & Inference Flow](#3-model-architecture--inference-flow)
4. [Backend MLOps Architecture](#4-backend-mlops-architecture)
5. [Adversarial Attack Mechanics](#5-adversarial-attack-mechanics)
6. [Security Controls & Defensive Mechanics](#6-security-controls--defensive-mechanics)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Failure Points](#8-failure-points)
9. [Mitigations & Observability](#9-mitigations--observability)
10. [Interview Questions](#10-interview-questions)

---

## 1. Attack/Defense Narrative

### The Setting: A Deployed ML API

A fintech company has trained a proprietary fraud detection model on 10 years of transaction data, including customer PII (names, account numbers, spending patterns). The model is served via a REST API: `POST /api/v1/predict` accepts a transaction JSON and returns a fraud probability score. The model cost $2M in compute and data licensing. Two threat actors want different things:

- **Threat Actor A (Model Thief)**: Wants to steal the model's learned behavior to build a competing product without the training cost.
- **Threat Actor B (Data Extractor)**: Suspects the model memorized specific customer records during training and wants to extract PII.

Both actors have only black-box API access — they cannot see weights, gradients, or training data directly.

---

### Normal User Journey

**T=0ms** — A legitimate fraud detection request:

```json
POST /api/v1/predict
Authorization: Bearer eyJhbGci...
Content-Type: application/json

{
  "transaction_id": "txn_abc123",
  "amount": 89.50,
  "merchant_category": "grocery",
  "time_of_day": 14,
  "user_avg_transaction": 95.20,
  "days_since_last_transaction": 2,
  "location_match": true
}
```

**T=0–5ms** — API gateway validates the JWT, enforces rate limits (100 req/min for this API key), and routes to the inference cluster.

**T=5–25ms** — The feature vector is preprocessed (normalized, one-hot encoded), passed through the model forward pass, and a probability is returned:

```json
{
  "transaction_id": "txn_abc123",
  "fraud_probability": 0.03,
  "decision": "APPROVE",
  "model_version": "v4.2.1"
}
```

The model returns a single scalar probability. The user sees a business decision. This is important: **the model returns a probability, not a raw logit, and not class weights**. This output format is deliberately constrained. The more information the API returns, the more the attacker can learn.

---

### Attacker Journey: Model Extraction

**T=0 — Reconnaissance**

The attacker begins by understanding the input schema. They send valid requests, observe the response format, and note what the API accepts. If error messages are verbose, they reveal the feature schema:

```json
POST /api/v1/predict
{"amount": "not_a_number"}

Response: {"error": "Field 'amount' must be float. Fields accepted: amount (float), merchant_category (string, one of: grocery|fuel|...), ..."}
```

The error message just gave away the feature schema. The attacker now knows the model's input space.

**T=5min — Systematic Sampling (Model Extraction begins)**

The attacker designs a query strategy. They need to map the decision boundary of a function f: ℝ^d → [0,1] where d is the feature dimension. Their goal: find a surrogate model g that approximates f without knowing the weights of f.

They begin querying systematically:
```
Query 1:  amount=100, category=grocery, ... → 0.03
Query 2:  amount=100, category=grocery, time=2 (night) → 0.41
Query 3:  amount=10000, category=grocery → 0.89
Query 4:  amount=10000, category=fuel → 0.71
...
Query N:  [all combinations covering the input space]
```

Each query-response pair `(x_i, f(x_i))` is a labeled training example for the surrogate model.

**T=2 hours — 50,000 queries later**

The attacker has collected 50,000 (input, probability) pairs. They train a surrogate neural network g on this dataset:

```
Loss = MSE(g(x_i), f(x_i))   for all i in {1..50000}
     = (1/N) Σ (g(xᵢ) - f(xᵢ))²
```

The surrogate model g achieves 94% agreement with f on held-out queries. The attacker now has a functional copy of the fraud detection model. They can deploy g without paying for training data or compute.

**What the model "sees"**: A stream of syntactically valid API requests that look superficially like legitimate queries. Each individual request is indistinguishable from a real fraud check. The malicious pattern only emerges at the aggregate level — query volume, input distribution breadth, and systematic coverage of the feature space.

---

### Attacker Journey: Membership Inference

**T=0 — Attacker's hypothesis**

The attacker believes (correctly) that the model was trained on real customer transactions. They have a partial dataset of 1,000 real customer records (obtained from a data breach elsewhere). They want to confirm which of these customers were in the model's training set — confirming they're customers of this fintech company.

**The core insight** (Shokri et al. 2017): Models overfit to training data. On training examples, the model produces **higher-confidence, lower-entropy** predictions than on non-training examples. This is measurable.

For each of the 1,000 customer records, the attacker constructs a corresponding transaction and queries the API:
```
Customer Alice Johnson, account xxxxx1234:
  amount=47.23, category=grocery, time=9, avg=52.10, ...
  → fraud_probability=0.007  (very low, very confident)

Customer Bob (not a customer, from a different city):
  amount=52.00, category=grocery, time=10, avg=55.00, ...
  → fraud_probability=0.031  (low, but less extreme)
```

Alice's query returns a more extreme (confident) probability. This is a signal that Alice's data pattern was in the training set.

**The attacker trains a membership inference attack model**:

```
Input:  (query_features, model_output) 
Output: binary label {member, non-member}

Attack model architecture: logistic regression or small MLP
Training: use "shadow models" (explained in Section 5)
```

With enough queries, the attacker achieves 73% membership inference accuracy (random = 50%). They've confirmed with high confidence which of the 1,000 people are customers of this fintech company — a significant privacy violation.

**What the model "sees"**: Queries that look like fraud checks for legitimate transaction amounts and merchant categories. The information leak is in the output distribution, not the inputs.

---

## 2. Data Ingestion & Preprocessing Flow

### Raw Data Sources and Trust Classification

```
┌───────────────────────────────────────────────────────────────────────┐
│                    DATA INGESTION PIPELINE                             │
│                                                                        │
│  Source 1: Transaction Database (PostgreSQL)                          │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  Tables: transactions, users, merchants                         │ │
│  │  Trust: INTERNAL HIGH (VPC-only access, IAM-controlled)         │ │
│  │  PII present: YES — name, account, SSN partial, amount, geo    │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                            │                                           │
│                            ▼                                           │
│  Source 2: Third-Party Enrichment (IP geolocation, device ID)        │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  API calls to MaxMind, Sardine, etc.                            │ │
│  │  Trust: EXTERNAL SEMI-TRUSTED (TLS, API key, SLA)              │ │
│  │  PII: device fingerprint (quasi-identifying)                   │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                            │                                           │
│  ┌─────────────────────────▼────────────────────────────────────────┐ │
│  │  TRUST BOUNDARY: Ingestion workers (isolated VMs, no egress)   │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                            │                                           │
│  Preprocessing Workers (Apache Spark / Flink):                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  Step 1: Schema validation (reject malformed records)           │ │
│  │  Step 2: Deduplication (hash-based)                             │ │
│  │  Step 3: PII tokenization (SSN → token, names → user_id)       │ │
│  │  Step 4: Label assignment (fraud: 1, legit: 0)                  │ │
│  │  Step 5: Feature engineering (see below)                        │ │
│  │  Step 6: Train/val/test split with temporal hold-out           │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                            │                                           │
│  ┌─────────────────────────▼────────────────────────────────────────┐ │
│  │  Feature Store (Feast/Tecton) — INTERNAL HIGH TRUST             │ │
│  │  Stores: preprocessed feature vectors (NO raw PII)              │ │
│  │  Format: Parquet on S3, keyed by user_id (tokenized)            │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

### Feature Engineering in Detail

Feature engineering transforms raw transaction data into numeric vectors that a model can ingest. This step is critical for security because **the feature space defines what the attacker must reverse-engineer**.

**Numerical features** (direct, normalized):
```
amount_normalized = (amount - μ_amount) / σ_amount
time_sin = sin(2π × hour / 24)           # Circular encoding for hour
time_cos = cos(2π × hour / 24)
days_since_last = log1p(days_since_last)  # Log transform, right-skewed dist
```

**Categorical features** (one-hot or embedding):
```
merchant_category: ["grocery", "fuel", "luxury", "electronics", ...]
  → one-hot: [1, 0, 0, 0, ...] for "grocery"
  → OR learned embedding: 8-dimensional dense vector (used in transformer models)
```

**Behavioral features** (aggregations, computed at query time from feature store):
```
avg_transaction_30d   = mean(amounts, last 30 days)
txn_velocity_1h       = count(transactions, last 1 hour)
merchant_risk_score   = precomputed per-merchant fraud rate
location_anomaly      = distance from centroid of past transactions (km)
```

**Why this matters for security**: Behavioral features are computed from historical user data stored in the feature store. If an attacker can query the API with a real user's user_id and control other features, they are effectively querying the model with the user's real behavioral profile. This enables targeted membership inference even for users whose transaction records the attacker doesn't have.

### PII Handling in the Pipeline

**Tokenization** (not encryption): PII fields are replaced with opaque tokens before entering the feature store. The mapping table (token → PII) is stored in a separate, access-controlled vault (HashiCorp Vault or AWS Secrets Manager). Training data never contains raw PII.

**However**: Even after tokenization, models can memorize:
- Transaction patterns that uniquely identify individuals (behavioral PII).
- Statistical properties of small groups.
- Rare values that appear only once in the training set.

This is why tokenization alone does not solve the memorization problem. Differential privacy is required.

### Dimensionality and Feature Importance

For the fraud model, assume:
- Raw features: d = 47 (after one-hot encoding)
- Post-dimensionality reduction: d' = 32 (PCA or learned)

**PCA application**:
```
X ∈ ℝ^{N×47}   (N training samples, 47 features)

Covariance matrix: C = (1/N) X^T X  ∈ ℝ^{47×47}
Eigendecomposition: C = V Λ V^T
Select top 32 eigenvectors: V_{32} ∈ ℝ^{47×32}

Projected features: X' = X V_{32}  ∈ ℝ^{N×32}
```

PCA is applied at inference time too — the same projection matrix V_{32} is stored and applied to incoming requests. This means an attacker observing input/output behavior is working in the projected 32-dimensional space, not the original 47-dimensional space.

---

## 3. Model Architecture & Inference Flow

### Architecture Selection

The fraud detection system uses a **gradient boosted tree ensemble** (XGBoost/LightGBM) for the primary model, with a **neural network layer** for temporal pattern modeling. This hybrid is common in production fraud systems.

**Why gradient boosting for fraud**:
- Handles mixed feature types natively.
- Interpretable (feature importance, SHAP values).
- Robust to feature scale differences.
- No vanishing gradient problems.
- Inference is fast (tree traversal, no matrix multiplication).

**Why adding a neural component**:
- Captures temporal dependencies in transaction sequences.
- Learns embeddings for categorical variables.
- Better generalization on distribution shifts.

### ML Pipeline ASCII Diagram

```
INPUT REQUEST
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│  FEATURE PREPROCESSING LAYER                                        │
│                                                                     │
│  Raw request → [Schema validation] → [Normalization] →             │
│  [Feature store lookup (behavioral)] → [PCA projection]            │
│                                                                     │
│  Output: feature vector x ∈ ℝ^32                                  │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│  TEMPORAL ENCODER (Transformer/LSTM)                                │
│                                                                     │
│  Inputs: last K=10 transaction feature vectors for this user       │
│  (fetched from feature store by user_id)                           │
│                                                                     │
│  LSTM or Transformer encoder:                                       │
│    h_t = LSTM(x_t, h_{t-1})   OR                                  │
│    h = TransformerEncoder([x_{t-K}, ..., x_t])                     │
│                                                                     │
│  Output: context vector c ∈ ℝ^64                                  │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│  GRADIENT BOOSTED ENSEMBLE (XGBoost)                                │
│                                                                     │
│  Input: concat(x, c) ∈ ℝ^96                                       │
│                                                                     │
│  Forest of T=500 trees, depth=6:                                   │
│                                                                     │
│  Tree 1: x_amount < 500?                                           │
│    ├── YES: merchant_risk < 0.3? → leaf(0.02)                      │
│    └── NO:  location_anomaly > 200km? → leaf(0.75)                 │
│  ...                                                                │
│  Tree 500: [deeper conditions]                                      │
│                                                                     │
│  Raw score: F(x) = Σᵢ γᵢ  (sum of leaf values, all trees)         │
│  Output: logit ∈ ℝ                                                 │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│  CALIBRATION + OUTPUT LAYER                                         │
│                                                                     │
│  Platt scaling or isotonic regression to calibrate probabilities:  │
│    p = σ(a × F(x) + b)   where a,b are calibration parameters     │
│    σ is the sigmoid function: σ(z) = 1/(1+e^{-z})                 │
│                                                                     │
│  Raw output: p ∈ [0,1]  (fraud probability)                        │
│                                                                     │
│  DEFENSIVE ROUNDING (crucial for privacy):                         │
│    p_rounded = round(p, decimals=2)   → 0.03, not 0.027361        │
│                                                                     │
│  API response: {"fraud_probability": 0.03, "decision": "APPROVE"}  │
└────────────────────────────────────────────────────────────────────┘
```

### Forward Pass Mechanics in Detail

**Gradient boosting forward pass**:

Each tree t computes a function h_t(x) → leaf_value. The final prediction is:

```
F_0(x) = log(p_fraud / p_legit)   ← base score (prior odds)

For t = 1 to T:
  F_t(x) = F_{t-1}(x) + η × h_t(x)
  
  where η is the learning rate (shrinkage), e.g., η = 0.1

Final: F(x) = F_T(x)
p = sigmoid(F(x)) = 1 / (1 + exp(-F(x)))
```

**Tree traversal for one tree (h_t)**:

```python
def tree_predict(x, tree_nodes):
    node = root_node
    while not node.is_leaf:
        if x[node.feature_idx] <= node.threshold:
            node = node.left_child
        else:
            node = node.right_child
    return node.leaf_value  # γ (gamma), the residual prediction
```

Each tree takes O(depth) = O(6) operations. With 500 trees: O(3000) comparisons per inference. This is why XGBoost inference is extremely fast (~0.1ms per prediction, CPU-only).

### How the Final Output is Constructed

The output pipeline:
1. Raw logit F(x) → sigmoid → p ∈ (0, 1).
2. Calibration: Platt scaling adjusts for overconfident predictions (a common artifact of ensemble models).
3. Threshold: decision boundary (typically p > 0.5, but in fraud detection often p > 0.15 to prioritize recall).
4. **Rounding/bucketing**: The raw probability is rounded to 2 decimal places before returning. This coarsening is a first-order privacy defense (more on this in Section 6).
5. Response: Only the rounded probability and decision are returned. Raw logits, feature importances, and intermediate tree outputs are NOT exposed.

---

## 4. Backend MLOps Architecture

### Model Registry and Weights Storage

```
┌──────────────────────────────────────────────────────────────────────┐
│                    MLOPS ARCHITECTURE                                 │
│                                                                       │
│  Training Pipeline                                                   │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Data: Feature Store (S3, Parquet)                           │   │
│  │  Training: SageMaker Training Jobs / Kubernetes ML workers   │   │
│  │  Framework: XGBoost + PyTorch (temporal encoder)             │   │
│  │  Hyperparameter tuning: Optuna / Ray Tune                    │   │
│  │  Tracking: MLflow (metrics, params, artifacts)               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                          │                                            │
│                          ▼ (on experiment success)                   │
│  Model Registry (MLflow / SageMaker Model Registry)                  │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Artifact: model_v4.2.1/                                     │   │
│  │    xgboost_weights.ubj         ← XGBoost binary format       │   │
│  │    temporal_encoder.pt         ← PyTorch state dict          │   │
│  │    pca_projection.npy          ← NumPy array, V_32           │   │
│  │    calibration_params.json     ← Platt scaling a, b          │   │
│  │    feature_schema.json         ← Input validation config     │   │
│  │    metadata.json               ← Training run info           │   │
│  │                                                               │   │
│  │  Storage: S3 bucket (private, KMS-encrypted)                 │   │
│  │  Access: IAM role for inference cluster only                 │   │
│  │  Versioning: S3 Object Versioning + DynamoDB version table    │   │
│  │  Signing: SHA256 digest of each artifact stored separately   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                          │                                            │
│                          ▼ (after approval: staging → prod)          │
│  Inference Cluster                                                   │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  SERVING ARCHITECTURE:                                        │   │
│  │                                                               │   │
│  │  Fraud model (XGBoost): CPU inference, no GPU needed         │   │
│  │    → Triton Inference Server (CPU backend)                   │   │
│  │    → XGBoost FIL (Forest Inference Library) backend          │   │
│  │    → 0.1ms per inference, 10,000 RPS per node                │   │
│  │                                                               │   │
│  │  Temporal encoder (PyTorch LSTM):                             │   │
│  │    → Triton TensorRT backend (GPU-optimized)                 │   │
│  │    → TensorRT quantization: FP32 → INT8 (4x throughput)     │   │
│  │    → GPU memory: 2GB per model replica                       │   │
│  │                                                               │   │
│  │  Deployment: Blue/green with traffic shadowing               │   │
│  │  Auto-scaling: HPA on inference latency p99                  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

### Sync vs Async Inference

**Synchronous inference** (used here): Client POSTs → waits → receives response. Required for real-time fraud detection where the response is needed before authorizing the transaction. Latency SLA: p99 < 50ms.

**Asynchronous inference** (batch fraud scoring): A nightly job processes all transactions from the day for fraud review. Client POSTs a batch, receives a job ID, polls for results. This allows larger batch sizes and better GPU utilization.

**The security difference**: Asynchronous inference is easier to rate-limit (job submission quotas). Synchronous inference rate limiting must be enforced per-request in a hot path (Redis-based token bucket, added latency of ~1ms per request).

### GPU Memory Management and Security

For the transformer encoder on GPU:

```
GPU Memory Layout (A100 80GB):
  ┌─────────────────────────────────────────────────────────┐
  │  Model weights (static):  2.1GB                         │
  │  KV cache (dynamic):      varies with sequence length   │
  │  Activation tensors:      ~0.5GB peak                   │
  │  CUDA context overhead:   0.3GB                         │
  └─────────────────────────────────────────────────────────┘

Security concern: GPU memory is not cleared between requests.
If a malicious request causes an exception mid-forward-pass,
activation tensors from a previous request may remain in GPU
memory. An attacker with side-channel access to GPU memory
(via fault injection or a compromised process in the same
GPU context) could read previous users' feature vectors.

Fix: Use CUDA device memory zeroing:
  cudaMemset(tensor_ptr, 0, tensor_size);
  Called in the request teardown path.
  Adds ~0.2ms per request — accepted overhead for financial data.
```

---

## 5. Adversarial Attack Mechanics

### Attack 1: Model Extraction (Functionally Equivalent Surrogate)

**Mathematical Basis**

The model f: X → Y defines a function from input space to output space. Model extraction solves the following problem:

Find g: X → Y such that:
```
d(f(x), g(x)) < ε   for all x ∈ X_test
```

where d is a distance metric (e.g., L1 on probabilities) and ε is a small tolerance.

This is a **supervised learning problem** where the labels are the target model's outputs. The attacker is essentially distilling the model f into a surrogate g using a "teacher" signal from API queries.

**Step-by-Step Execution**

**Step 1: Input domain specification**

The attacker defines the feasible input space based on the API's schema (obtained from documentation or error messages):

```python
input_space = {
    "amount": Uniform(0.01, 50000),
    "merchant_category": Categorical(["grocery", "fuel", "luxury", ...]),
    "time_of_day": Uniform(0, 23),
    "days_since_last": Uniform(0, 365),
    "location_match": Bernoulli(0.7),
    ...
}
```

**Step 2: Query strategy selection**

Naive random sampling is wasteful. Better strategies:

*Adaptive sampling* (Tramèr et al. 2016):
```
Algorithm:
1. Start with n₀ random queries → get labels y₁...y_{n₀}
2. Train initial surrogate g on (x, y) pairs
3. For each next query:
   a. Sample candidate x_candidate
   b. Find the decision boundary region:
      x_boundary = x_candidate + δ such that g(x_boundary) ≈ 0.5
      (near the decision boundary, the target model's output is
       most sensitive to input changes — most information per query)
4. Query f(x_boundary)
5. Add to training set, retrain g
6. Repeat until agreement metric converges
```

Active learning near the decision boundary maximizes information per query. The intuition: near the boundary, the model's output changes significantly with small input changes, so each query gives maximum signal about the model's behavior.

*Jacobian-based dataset augmentation* (Papernot et al.):
```
For each queried point x with label f(x):
  Compute ∂g/∂x  (gradient of surrogate w.r.t. input)
  Generate synthetic points:
    x_synthetic = x + λ × sign(∂g/∂x)
  These synthetic points cover the local neighborhood of x
  without requiring additional API queries

This amplifies each real query into multiple training examples.
```

**Step 3: Surrogate model training**

```python
# Attacker's dataset
X_attack = []  # feature vectors sent to API
Y_attack = []  # probabilities returned by API

# Training surrogate
from sklearn.neural_network import MLPClassifier
surrogate = MLPClassifier(hidden_layer_sizes=(128, 64, 32), 
                          max_iter=500)
surrogate.fit(X_attack, Y_attack)

# Or XGBoost surrogate:
import xgboost as xgb
surrogate_xgb = xgb.XGBRegressor(n_estimators=500)
surrogate_xgb.fit(X_attack, Y_attack)
```

**Step 4: Fidelity evaluation**

```
Fidelity = P[g(x) agrees with f(x)] over test queries
         = (1/|X_test|) Σ 𝟙[round(g(x)) == round(f(x))]

After 10,000 queries:  fidelity ≈ 0.82
After 50,000 queries:  fidelity ≈ 0.94
After 200,000 queries: fidelity ≈ 0.98
```

At 94% fidelity, the surrogate is commercially viable. The attacker stops querying.

**Why the Model Fails to Prevent This**:

The model f is doing exactly what it's supposed to do: returning accurate fraud probabilities. There is no "legitimate query" that looks different from an "extraction query" at the individual request level. The attack exploits the fundamental tension between:
- **Accuracy requirement**: The API must return accurate predictions to be useful.
- **Privacy requirement**: Accurate predictions leak the model's learned function.

The only defenses are at the aggregate level: rate limiting, input distribution monitoring, output perturbation.

---

### Attack 2: Membership Inference (Shokri et al. 2017)

**Mathematical Basis**

The core observation: a model trained with SGD overfit differently on training vs non-training data.

For a training example (x, y):
```
Loss at inference time: ℓ(f(x), y) ≈ very small (model "knows" this point)
Confidence: max(softmax(f(x))) ≈ very high (overconfident on training data)
```

For a non-training example (x', y'):
```
Loss at inference time: ℓ(f(x'), y') ≈ larger (model generalizes but is less certain)
Confidence: max(softmax(f(x'))) ≈ lower (appropriate calibration)
```

This prediction confidence gap is the signal exploited by membership inference.

**Shadow Model Method (Step-by-Step)**

The attacker cannot directly compute the loss because they don't have the true label y (or in some attacks, they do have the label and can compute loss directly). The shadow model method removes this requirement.

**Step 1: Shadow dataset construction**

The attacker obtains a dataset D_shadow with similar distribution to the victim model's training data (not the exact training data — data from the same domain):

```
D_shadow = transactions from public datasets (Kaggle, 
           breach data, own legitimate transactions)
         ≈ same distribution as victim's training data
```

**Step 2: Train shadow models**

```python
# Train k shadow models, each on a different subset of D_shadow
k = 10  # shadow model count
shadow_models = []
shadow_datasets = []

for i in range(k):
    # Split D_shadow: half for training shadow model i
    D_train_i, D_test_i = split(D_shadow, ratio=0.5)
    shadow_datasets.append((D_train_i, D_test_i))
    
    # Train shadow model with same architecture as victim
    # (or a reasonable approximation)
    shadow_model_i = XGBClassifier(...)
    shadow_model_i.fit(D_train_i)
    shadow_models.append(shadow_model_i)
```

Each shadow model is a miniature replica of the victim model, trained on a known subset of data. Crucially, for each shadow model, we KNOW which examples are in-training and which are out-of-training.

**Step 3: Generate attack training data**

```python
attack_dataset = []

for i, (shadow_m, (D_train_i, D_test_i)) in enumerate(zip(shadow_models, shadow_datasets)):
    
    # In-training examples (ground truth: member=1)
    for x in D_train_i:
        output = shadow_m.predict_proba(x)  # e.g., [0.03, 0.97]
        attack_dataset.append((output, label=1))  # "member"
    
    # Out-of-training examples (ground truth: member=0)
    for x in D_test_i:
        output = shadow_m.predict_proba(x)  # e.g., [0.14, 0.86]
        attack_dataset.append((output, label=0))  # "non-member"
```

The attack dataset contains (model_output_vector, membership_label) pairs.

**Step 4: Train the attack model**

```python
# Attack model: maps prediction vector → membership label
# Input: f(x) ∈ [0,1]^C  (C output classes)
# Output: {0,1} (non-member / member)

from sklearn.linear_model import LogisticRegression
attack_model = LogisticRegression()
attack_model.fit(
    [output for output, _ in attack_dataset],
    [label for _, label in attack_dataset]
)
```

The attack model learns: "what does a training-set prediction look like vs a non-training-set prediction?"

**Step 5: Inference on victim model**

```python
# For each candidate x (whose membership the attacker wants to determine):
victim_output = query_api(x)           # e.g., fraud_probability=0.007
membership_pred = attack_model.predict([victim_output])  
# → 1 (member) or 0 (non-member)
```

**Quantitative Result**:
```
Random baseline accuracy:    50%  (coin flip)
Membership inference accuracy: 65-75% for XGBoost fraud model
Membership inference accuracy: 75-85% for deep neural networks
  (deeper models tend to overfit more → stronger signal)
```

**Why the Model Fails**:

The model's overfitting is the root cause. During training, SGD minimizes loss on training examples. With enough capacity and insufficient regularization:

```
For training example (x, y=1):
  Model learns: f(x) → 0.997  (very confident fraud label)
  True calibrated probability might be: 0.85

For similar non-training example (x', y'=1):
  Model predicts: f(x') → 0.84  (appropriate generalization)

Gap: 0.997 - 0.84 = 0.157  ← this is the exploitable signal
```

More formally, the *generalization gap* between training loss and test loss is nonzero. Membership inference directly exploits this gap.

---

### Attack 3: Model Inversion (Fredrikson et al. 2015)

**Mathematical Basis**

Model inversion seeks to reconstruct the input x* that maximizes the probability of a given output class y:

```
x* = argmax_x f(x)[y]

subject to x ∈ X (feasible input space)
```

This is an optimization problem. In differentiable models (neural networks), gradient ascent solves it:

```
x_t+1 = x_t + α × ∂f(x_t)[y] / ∂x_t

where α is the step size (gradient ascent, not descent)
```

**For a black-box API** (no gradient access), the attacker uses:

*Zeroth-order optimization* (finite differences to estimate gradients):
```
∂f(x)[y]/∂x_i ≈ (f(x + δeᵢ)[y] - f(x - δeᵢ)[y]) / (2δ)

where eᵢ is the i-th standard basis vector
      δ is a small perturbation (e.g., 0.001)

For d=32 features: 64 API queries per gradient estimate
For 1000 optimization steps: 64,000 queries per inversion
```

**For a fraud model**, inversion reconstructs the "prototypical fraud transaction" or the average feature vector of the fraud class. This reveals:
- What combination of features the model considers most fraudulent.
- Implicitly, statistical properties of the training data for the fraud class.

**Step-by-Step for LLM PII Extraction** (different attack class, same family):

LLMs trained on web-scraped data that included PII (emails, phone numbers, addresses) can be queried to reproduce this memorized content:

```
Attacker prompt: "Please complete the following: 
  John Smith's email address is john.smith@"

LLM response: "...gmail.com, and his phone is 555-123-4567"
  (if this exact text appeared in training data)
```

More sophisticated: the attacker provides enough context that the LLM's next-token probabilities reveal memorized strings:

```python
# For each candidate email domain:
for domain in ["gmail.com", "yahoo.com", ...]:
    prompt = f"John Smith's email is john.smith@{domain}"
    log_prob = llm.log_prob(prompt)
    
# If log_prob is highest for "gmail.com", the LLM
# has memorized that association from training data.
```

Carlini et al. 2021 demonstrated this extracts verbatim memorized text from GPT-2 at rates proportional to training data repetition — sequences that appeared ≥100 times in training are extractable with high probability.

---

## 6. Security Controls & Defensive Mechanics

### Defense 1: Differential Privacy via DP-SGD

**What differential privacy guarantees:**

A randomized algorithm M satisfies (ε, δ)-differential privacy if for all datasets D and D' differing in one record, and all outputs S:

```
P[M(D) ∈ S] ≤ e^ε × P[M(D') ∈ S] + δ
```

Interpretation: Adding or removing any single training record changes the output distribution by at most a multiplicative factor of e^ε (plus a δ additive slack). A model trained with DP provides a formal bound on how much any individual's data influences the model weights — and therefore how much can be learned about any individual through the model's outputs.

**ε interpretation**:
- ε = 0: Perfect privacy (model output is independent of any individual's data). Useless — the model learns nothing.
- ε = 1: Strong privacy. The model's output changes by at most e^1 ≈ 2.7x when one person's data is removed.
- ε = 10: Weak privacy. Large ε means individual data has large influence.
- ε > 50: Practically no privacy guarantee.
- **Typical production targets**: ε ∈ [1, 8] for reasonable privacy-utility tradeoff.

**DP-SGD (Abadi et al. 2016) Mechanics**:

Standard SGD:
```
θ_{t+1} = θ_t - η × (1/B) Σ_{i ∈ B} ∇ℓ(θ_t, x_i, y_i)
```

DP-SGD modifies this in two ways:

**Step 1: Gradient clipping** (bound sensitivity):
```
g̃_i = g_i / max(1, ||g_i||_2 / C)

where g_i = ∇ℓ(θ, x_i, y_i)   (per-sample gradient)
      C = clipping threshold (e.g., C = 1.0)

This ensures ||g̃_i||_2 ≤ C for all i.
Clipping bounds the "influence" any one sample can have.
```

**Step 2: Gaussian noise addition** (formal privacy):
```
g̃_noisy = (1/B) [Σ_i g̃_i + N(0, σ²C²I)]

where σ = noise multiplier (e.g., σ = 1.1)
      N(0, σ²C²I) is isotropic Gaussian noise

The noise scale σC is the standard deviation of the noise.
Larger σ = more privacy, less accuracy.
```

**Step 3: Privacy accounting**:

The privacy budget ε is consumed across training steps. Tracking total privacy cost uses the *moments accountant* or *Rényi differential privacy (RDP)*:

```
Each step of DP-SGD consumes ε_step(σ, q)

where q = B/N (sampling ratio: batch size / dataset size)
      σ = noise multiplier

Total budget after T steps:
  ε_total = PrivacyAccountant(steps=T, noise_mult=σ, sample_rate=q, δ)

Example:
  N = 100,000 samples, B = 256, T = 50 epochs × (N/B) = 50 × 391 = 19,550 steps
  σ = 1.1, q = 256/100000 = 0.00256
  → ε_total ≈ 3.2  (good privacy)
```

**Utility Cost of DP**:

DP-SGD reduces model accuracy due to noise injection. Typical degradation:
```
Without DP:  AUC = 0.94  (on test set)
With DP (ε=10): AUC = 0.91  (-3%)
With DP (ε=3):  AUC = 0.87  (-7%)
With DP (ε=1):  AUC = 0.79  (-15%)
```

The privacy-utility tradeoff must be calibrated per use case. For fraud detection, losing 3% AUC at ε=10 is typically acceptable.

**Implementation**: The Opacus library (Meta) implements DP-SGD for PyTorch. For XGBoost, a differentially private variant exists but is less mature — consider privatizing only the neural component (temporal encoder) with DP-SGD and using XGBoost on privatized features.

---

### Defense 2: Output Perturbation

After the model predicts p ∈ [0,1], add calibrated noise before returning to API caller:

```
p_noisy = p + Laplace(0, λ)

where λ = sensitivity / ε
      sensitivity = maximum change in p for any change in input
                  = 1.0  (for probability output)
      ε = desired privacy level

Example: ε = 1.0 → λ = 1.0/1.0 = 1.0  (too much noise — prediction useless)
         ε = 0.1 → λ = 10.0  (extreme)
         Practical: use ε >> 1 for output perturbation alone (it's a weak defense)
```

**Rounding/truncation** is a simpler and practically effective defense:

```python
def perturb_output(p: float, granularity: float = 0.05) -> float:
    """Round probability to nearest granularity level."""
    return round(p / granularity) * granularity
    # E.g., 0.031 → 0.05, 0.017 → 0.00, 0.876 → 0.875 (with 0.025 gran)
```

**Information content of rounded output**:
```
With full precision (float64): log₂(10^15) ≈ 50 bits per query
With 2 decimal places:         log₂(101) ≈ 6.7 bits per query
With 5-bucket output:          log₂(5) ≈ 2.3 bits per query

Fewer bits per query → more queries needed for model extraction
→ Rate limiting becomes more effective
```

Coarser output granularity makes each query less informative for the attacker. However, it also degrades the API's usefulness. A fraud probability bucketed as {low, medium, high} loses nuance compared to a continuous probability.

---

### Defense 3: Query Rate Limiting and Anomaly Detection

**Token bucket rate limiting** (per API key):

```
Rate limit: 100 requests/minute  →  ~1.67 requests/second
Burst limit: 20 requests

At 100 req/min:
  Extraction fidelity timeline:
    10,000 queries: 100 minutes → fidelity ≈ 82%
    50,000 queries: 500 minutes ≈ 8.3 hours → fidelity ≈ 94%
    200,000 queries: 2000 minutes ≈ 33 hours

33 hours of sustained querying is detectable.
With anomaly detection on input distribution, detected at ~2 hours.
```

**Distributed rate limiting** (defeating IP rotation):

The attacker can rotate API keys or use multiple compromised accounts. Account-level rate limiting is insufficient. Add **global rate limiting** on input distribution similarity:

```python
def detect_extraction_pattern(request_log: List[Request]) -> bool:
    """
    Detect model extraction by analyzing input distribution.
    Legitimate users query in a narrow distribution (their transactions).
    Extractors query across the full feature space.
    """
    recent_requests = request_log[-1000:]
    feature_vectors = [r.features for r in recent_requests]
    
    # Compute coverage of the feature space
    # Use a discretized grid
    grid_coverage = count_unique_grid_cells(feature_vectors)
    
    # Legitimate: coverage < 5% of grid (clustered around real transactions)
    # Extractor: coverage > 30% of grid (systematic exploration)
    return grid_coverage > EXTRACTION_COVERAGE_THRESHOLD
```

**Input distribution shift detection**:

```python
from scipy.stats import ks_2samp

def detect_distribution_shift(current_window: List[float], 
                               baseline: List[float]) -> bool:
    """
    Kolmogorov-Smirnov test on query input distribution.
    Extraction queries have significantly different distribution than
    legitimate queries.
    """
    stat, p_value = ks_2samp(current_window, baseline)
    return p_value < 0.001  # Very high confidence of shift → alert
```

---

### Defense 4: Adversarial Training

Adversarial training adds adversarially crafted examples to the training set to improve robustness. For the extraction/inversion threat:

**Regularization to reduce memorization**:

```python
# L2 regularization in XGBoost (reduces overfitting)
model = XGBClassifier(
    reg_lambda=1.0,   # L2 regularization
    reg_alpha=0.1,    # L1 regularization  
    min_child_weight=5,  # Minimum samples per leaf (prevents memorization of rare points)
    subsample=0.8,    # Stochastic sampling (reduces memorization)
    colsample_bytree=0.8  # Feature subsampling
)

# Dropout in neural component (reduces co-adaptation between neurons)
# → each neuron can't memorize a specific training point because
#   it's randomly dropped during training
encoder = nn.Sequential(
    nn.Linear(32, 64),
    nn.Dropout(p=0.3),
    nn.ReLU(),
    nn.Linear(64, 64),
    nn.Dropout(p=0.3),
)
```

**MIA-specific adversarial training** (Min et al. 2021):

Train the model while simultaneously training an adversarial membership inference attacker, and optimize the model to make the attacker fail:

```
min_θ max_φ [L_task(θ) - λ × L_MI(φ, θ)]

where:
  L_task = primary task loss (fraud detection cross-entropy)
  L_MI   = membership inference attack accuracy (what we want to minimize)
  θ = model parameters
  φ = attack model parameters
  λ = tradeoff coefficient

This is a min-max game: model minimizes both task loss and MIA accuracy.
The attack model φ is trained online (updated each step) to be maximally effective.
The model θ is updated to fool the attack while maintaining task performance.
```

This adversarial training approach directly optimizes against the threat, not just against overfitting in general.

---

## 7. Attack Surface Mapping

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║              MODEL INVERSION & EXTRACTION — ATTACK SURFACE MAP                 ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  EXTERNAL SURFACE (Black-box / API-level access)                                ║
║                                                                                  ║
║  ┌───────────────────────────────────────────────────────────────────────────┐ ║
║  │  INFERENCE API ENDPOINT                                                    │ ║
║  │  POST /api/v1/predict                                                      │ ║
║  │                                                                             │ ║
║  │  Entry points:                                                             │ ║
║  │  • Single prediction endpoint (primary extraction surface)                │ ║
║  │  • Batch prediction endpoint (higher volume per request)                  │ ║
║  │  • Explanation endpoint (if SHAP/LIME explanations exposed → MORE leak)   │ ║
║  │  • Model metadata endpoint (version, feature schema → recon aid)         │ ║
║  │                                                                             │ ║
║  │  Attack vectors:                                                           │ ║
║  │  • Model extraction via systematic querying                               │ ║
║  │  • Membership inference via confidence score analysis                     │ ║
║  │  • Model inversion via gradient-free optimization                         │ ║
║  │  • Denial of service (GPU exhaustion via max-complexity inputs)           │ ║
║  └───────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 1: API Gateway (rate limiting, auth, schema validation)         ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  SEMI-EXTERNAL SURFACE (Authenticated, but untrusted callers)                   ║
║                                                                                  ║
║  ┌───────────────────────────────────────────────────────────────────────────┐ ║
║  │  EXPLANATION/INTERPRETABILITY ENDPOINTS (highest risk)                     │ ║
║  │                                                                             │ ║
║  │  If exposed: /api/v1/explain returns SHAP values or feature importances   │ ║
║  │                                                                             │ ║
║  │  SHAP values are the GRADIENT of the model w.r.t. the input.             │ ║
║  │  In a black-box API, the attacker normally can't get gradients.           │ ║
║  │  Explanation endpoints hand the attacker the gradient for free.           │ ║
║  │                                                                             │ ║
║  │  With SHAP values, extraction fidelity reaches 98% with 10x fewer        │ ║
║  │  queries compared to black-box extraction.                                │ ║
║  │                                                                             │ ║
║  │  Recommendation: NEVER expose SHAP values via public API.                │ ║
║  │  Use explanations only in internal dashboards (fraud analyst tools).      │ ║
║  └───────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 2: VPC boundary (internal services only)                         ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  INTERNAL SURFACE (Compromise required for access)                               ║
║                                                                                  ║
║  ┌───────────────────────────────────────────────────────────────────────────┐ ║
║  │  MODEL ARTIFACT STORAGE (S3 bucket / Model Registry)                       │ ║
║  │  • Exfiltrate model weights → complete model theft (no queries needed)    │ ║
║  │  • Tamper weights → backdoor model (data poisoning variant)               │ ║
║  │  • Access training data → direct PII exfiltration                        │ ║
║  │  Access control: IAM roles, S3 bucket policy, no public access           │ ║
║  └───────────────────────────────────────────────────────────────────────────┘ ║
║  ┌───────────────────────────────────────────────────────────────────────────┐ ║
║  │  TRAINING PIPELINE                                                         │ ║
║  │  • Poisoning training data → backdoor model                               │ ║
║  │  • Exfiltrating training data from S3/feature store                       │ ║
║  │  • Compromising MLflow to swap model versions                             │ ║
║  └───────────────────────────────────────────────────────────────────────────┘ ║
║  ┌───────────────────────────────────────────────────────────────────────────┐ ║
║  │  INFERENCE CLUSTER (GPU nodes)                                             │ ║
║  │  • Side-channel via GPU memory timing                                     │ ║
║  │  • Shared GPU context attacks (multi-tenant GPU servers)                  │ ║
║  │  • Process memory access (if container isolation is weak)                 │ ║
║  └───────────────────────────────────────────────────────────────────────────┘ ║
║  ┌───────────────────────────────────────────────────────────────────────────┐ ║
║  │  FEATURE STORE                                                             │ ║
║  │  • Query feature store directly for behavioral features (PII via proxy)  │ ║
║  │  • Timing attacks: does the feature store respond faster for              │ ║
║  │    existing user_ids? → existence inference                               │ ║
║  └───────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 3: Model weights are secrets — treat like private keys          ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  SUPPLY CHAIN SURFACE                                                            ║
║  • ML framework vulnerabilities (PyTorch RCE, TensorFlow deserialization)      ║
║  • Model format deserialization (pickle-based formats → arbitrary code exec)   ║
║  • Third-party training data (data provider inserts poisoned records)          ║
║  • Pre-trained model from Hub (backdoored foundation model)                    ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

**The Explanation Endpoint Anti-Pattern** deserves special emphasis. Many ML teams expose SHAP values or feature importance scores to help business users understand decisions. This is a severe security mistake for externally facing models:

```
Standard black-box extraction:
  Information per query: log₂(output_buckets) bits
  For 2-decimal probability: ~6.7 bits/query
  Queries needed for 95% fidelity: ~100,000

With SHAP explanation endpoint:
  Information per query: d × bits_per_value
  For d=32 features, 4-decimal SHAP: 32 × 13 bits ≈ 416 bits/query
  Queries needed for 95% fidelity: ~1,000  (100x reduction)

The attacker needs 100x fewer queries with explanations.
Rate limiting becomes 100x less effective.
```

---

## 8. Failure Points

### Under Load: GPU Exhaustion

**Adversarial DoS via expensive inputs**:

For transformer-based models, inference cost scales with sequence length. If the temporal encoder processes the last K transactions, an attacker can craft requests for a user_id with an extremely long transaction history:

```
Normal user: K=10 transactions → encoder context length = 10
  Attention computation: O(K²) = O(100) → ~2ms

Adversarial: K=500 transactions → encoder context length = 500
  Attention computation: O(K²) = O(250,000) → ~500ms

With 100 concurrent adversarial requests:
  GPU compute: 100 × 500ms = 50 GPU-seconds/second
  GPU capacity: 4 GPUs × 1 inference/0.5s = 8 concurrent
  → GPU saturation → request queue grows → latency spikes → cascading failure
```

**Fix**: Enforce maximum sequence length K at the API level. Truncate to K=50 regardless of actual history length. Add input size validation before the request reaches the GPU.

**TLS Exhaust on CPU inference**:

XGBoost inference is CPU-based but the API server's TLS termination is also CPU-bound. A flood of small requests can exhaust TLS processing capacity before hitting the ML inference bottleneck.

```
Inference: 0.1ms per request (XGBoost)
TLS handshake: 3ms per new connection (RSA 2048)
TLS resumption: 0.3ms per resumed connection

Attacker with 100,000 new connections/minute (no session reuse):
  TLS overhead: 100,000 × 3ms = 300 CPU-seconds/minute = 5 CPU-seconds/second
  If the server has 8 CPU cores: 8 cores × 1 TLS/core/second = 8/second max
  → Exhaustion at 8 connections/second sustained

Fix: Connection rate limiting before TLS termination (at the LB/WAF level).
     Force TLS session resumption (cache sessions for 24h).
```

### Model Drift and Concept Drift

**Covariate shift**: The distribution of legitimate transactions shifts over time (new merchant categories, changing spending patterns, new geographies). The model's feature distribution at inference time diverges from training time.

```
Training data:  μ_amount = $95.20, σ_amount = $47.30  (2020-2023)
Inference data: μ_amount = $127.50, σ_amount = $61.20  (2025)

Normalized at training:  amount_norm = (amount - 95.20) / 47.30
Applied at inference:    A transaction of $127.50 → norm = (127.50-95.20)/47.30 = 0.68

If the true 2025 distribution mean is $127.50:
  This "average" 2025 transaction normalizes to 0.68 (above the old mean)
  The model sees it as a "higher than average" transaction
  → Slightly elevated false positive rate
```

Monitor: Population Stability Index (PSI) on input features.

```
PSI = Σᵢ (Actual_i - Expected_i) × ln(Actual_i / Expected_i)

PSI < 0.1:   Negligible drift
PSI 0.1-0.2: Moderate drift (investigate)
PSI > 0.2:   Significant drift (trigger retraining)
```

**Concept drift**: The relationship between features and labels changes — a feature combination that was fraudulent before is no longer, or new fraud patterns emerge that weren't in training data.

This is harder to detect because you need ground truth labels at inference time. In fraud detection, labels are delayed (a fraudulent transaction may not be reported for days/weeks).

```
Detection approach: Track model performance on confirmed-fraud transactions
  Rolling window AUC on verified fraud cases
  Alarm if AUC drops by > 3% from baseline

Challenge: Low-fraud-volume periods have high AUC variance
  (few positive samples → high variance in AUC estimate)
  Use Wilson confidence intervals for AUC estimation.
```

### High False Positive Scenarios

High false positive rates don't just hurt user experience — they create a security vulnerability:

**FP exploitation**: If the model has a known high FP rate for certain transaction types (e.g., international transactions always get score > 0.7 regardless of legitimacy), attackers can use this knowledge to mask real fraud:

```
Attacker strategy: Mix fraudulent transactions with high-FP patterns
  International transaction + fraud → score 0.75  (expected FP territory)
  vs
  Domestic fraud transaction → score 0.82  (clearly fraud territory)

Result: The international fraudulent transaction blends into the FP noise.
Analysts focused on the 0.82 case miss the 0.75 case.
```

High FP rates also lead to alert fatigue — human fraud analysts stop investigating alerts when the majority are false positives, causing true positives to be missed.

**Adversarial high-FP exploitation**: An attacker could deliberately send a flood of high-FP transactions (legitimate but unusual) to overwhelm the fraud review queue, while simultaneously executing real fraud that gets lost in the noise.

---

## 9. Mitigations & Observability

### Concrete Defense Architecture

```
DEFENSE-IN-DEPTH FOR ML API SECURITY:
══════════════════════════════════════════════════════════════════════

Layer 1: Training-time defenses
  ├── DP-SGD (ε=5-10, δ=10⁻⁶): formal privacy guarantee
  ├── L2 regularization (λ=1.0): reduce overfitting
  ├── Gradient clipping (C=1.0): bound per-sample influence
  ├── Subsampling (80%): stochastic training
  └── Early stopping: prevent overfitting to training set

Layer 2: Model serving security
  ├── Model artifact signing (SHA256): detect tampering
  ├── Weights stored encrypted (AES-256, KMS-managed key)
  ├── IAM: inference cluster has read-only access to S3
  ├── No explanation endpoints on external-facing API
  └── GPU memory zeroing between requests

Layer 3: API output control
  ├── Probability rounding to 2 decimal places
  ├── Decision thresholding (return "APPROVE"/"REVIEW"/"DENY" not raw probability)
  ├── No raw logits, no feature importances, no intermediate outputs
  └── No batch explanation endpoints

Layer 4: Query-level controls
  ├── JWT authentication: no anonymous API access
  ├── Rate limiting: 100 req/min per API key (token bucket, Redis)
  ├── Input schema validation: strict type and range checking
  ├── Input sequence length limits (K ≤ 50 for temporal features)
  └── Request fingerprinting: log JA3, API key, IP

Layer 5: Behavioral detection
  ├── Input distribution monitoring (KS test vs baseline)
  ├── Feature space coverage monitoring (extraction detection)
  ├── Output distribution monitoring (shift in fraud score distribution)
  ├── User-level velocity: flag API keys querying >5000/day
  └── Cross-account correlation: same input vectors from different keys
```

### Privacy Budget Management

The ε budget is consumed during training. It must be tracked as a first-class resource:

```python
from opacus.privacy_engine import PrivacyEngine
from opacus.accountants import RDPAccountant

class PrivacyBudgetTracker:
    def __init__(self, target_epsilon: float, target_delta: float):
        self.target_epsilon = target_epsilon
        self.target_delta = target_delta
        self.spent_epsilon = 0.0
        self.accountant = RDPAccountant()
    
    def record_step(self, noise_multiplier: float, sample_rate: float):
        """Record privacy cost of one training step."""
        self.accountant.step(
            noise_multiplier=noise_multiplier,
            sample_rate=sample_rate
        )
        self.spent_epsilon = self.accountant.get_epsilon(self.target_delta)
    
    def budget_remaining(self) -> float:
        return self.target_epsilon - self.spent_epsilon
    
    def should_stop_training(self) -> bool:
        return self.spent_epsilon >= self.target_epsilon

# Usage in training loop:
tracker = PrivacyBudgetTracker(target_epsilon=5.0, target_delta=1e-6)

for epoch in range(max_epochs):
    for batch in dataloader:
        loss = compute_loss(model, batch)
        loss.backward()
        optimizer.step()  # DP-SGD step (clips + adds noise)
        tracker.record_step(noise_multiplier=1.1, sample_rate=0.00256)
        
        if tracker.should_stop_training():
            print(f"Privacy budget exhausted at ε={tracker.spent_epsilon}")
            break  # STOP training — do not exceed budget
```

**Budget consumed across model versions**:

Privacy budgets are additive across queries to the same model trained on the same data. If you train v1 with ε=5, then retrain v2 with ε=5 on the same dataset, the **total** privacy cost is ε=10. Managing this requires:

1. Tracking which dataset version each model version was trained on.
2. Accounting for budget across all model versions querying the same underlying data.
3. "Retiring" data: remove records from the training pool when their allocated ε budget is exhausted.

### Metrics to Log and Alert On

**Log ALL of these for every inference request**:

```json
{
  "request_id": "uuid",
  "timestamp_ms": 1715774625123,
  "api_key_hash": "sha256_of_api_key",      // not the key itself
  "source_ip": "203.0.113.5",
  "ja3_fingerprint": "a0e9f5d64...",
  "input_feature_hash": "sha256_of_input",  // for dedup detection
  "model_version": "v4.2.1",
  "preprocessing_ms": 2.1,
  "inference_ms": 8.4,
  "total_ms": 12.7,
  "output_bucket": "low",                   // not the raw probability
  "rate_limit_remaining": 87,
  "feature_space_coverage_pct": 2.3,        // for this API key in last hour
  "input_anomaly_score": 0.12              // how unusual is this input?
}
```

**Do NOT log**:
- Raw input feature vectors (PII risk — contains transaction details).
- Raw output probabilities (reduces information per log event for attackers who obtain logs).
- Model weights or intermediate activations.
- JWT tokens or raw API keys.

**Alert thresholds**:

| Metric | Normal Range | Alert Threshold | Severity | Reason |
|---|---|---|---|---|
| Requests/min per API key | 10–50 | >90 (rate limit: 100) | HIGH | Extraction attempt |
| Feature space coverage % | <5% | >20% in 1-hour window | HIGH | Systematic extraction |
| Input distribution KS p-value | >0.05 | <0.001 | MEDIUM | Distribution shift |
| Inference latency p99 | <30ms | >100ms | HIGH | Possible DoS |
| Model AUC on labeled stream | 0.91–0.94 | <0.87 | HIGH | Concept drift |
| PSI on any feature | <0.1 | >0.25 | MEDIUM | Covariate shift |
| Unique inputs per API key | <100/day | >10,000/day | HIGH | Extraction |
| Output entropy per session | ~0.8 bits | <0.3 bits (suspicious), >0.98 bits | MEDIUM | MIA or extraction |
| API key accessing >5 user_ids | N/A | Any | HIGH | Cross-account aggregation |
| Schema validation failures | <0.1% | >5% | MEDIUM | Fuzzing/exploration |

**Do NOT alert on**:
- Normal rate limit approaching (warn at 80%, alert only at 95%).
- Single-point anomalous input (one unusual transaction is expected).
- Inference latency p50 variations (normal under load).
- Schema errors from known-buggy client versions (add to known-issues list).

### Tracing for ML Systems

```
Distributed trace for one inference request:
  [API Gateway: 1ms]
    JWT validation
    Rate limit check (Redis: 0.8ms)
    Schema validation: 0.2ms
  [Feature Preprocessor: 3ms]
    Feature normalization: 0.5ms
    Feature store lookup: 2ms  ← often the bottleneck
    PCA projection: 0.5ms
  [Temporal Encoder (GPU): 5ms]
    Data transfer CPU→GPU: 0.5ms
    LSTM forward pass: 3ms
    Data transfer GPU→CPU: 1.5ms
  [XGBoost Inference (CPU): 0.5ms]
    Tree traversal: 0.5ms
  [Output Processing: 0.2ms]
    Calibration: 0.1ms
    Rounding: 0.05ms
    Response serialization: 0.05ms
  Total: 10ms

Trace metadata:
  - input_feature_hash (for correlation without storing PII)
  - model_version (for A/B analysis)
  - privacy_budget_remaining_at_inference (if tracking real-time)
  - extraction_risk_score (from behavioral detection)
```

---

## 10. Interview Questions

### Q1: Explain the mathematical basis of membership inference attacks. Why does model overfitting make a model vulnerable, and how does differential privacy bound this vulnerability?

**Why asked**: Tests depth of understanding of the core ML security problem.

**Answer direction**:

Membership inference exploits the *generalization gap*. During training with standard SGD, the model minimizes:

```
L_train = (1/|D_train|) Σ_{(x,y) ∈ D_train} ℓ(f_θ(x), y)
```

After training, L_train < L_test (the model fits training data better than test data). This means:

For a training example (x, y): f_θ(x) is more confident (higher probability on the correct class).
For a non-training example: f_θ(x) shows less extreme probabilities.

This observable difference in output confidence is the signal. The attacker trains a binary classifier on this signal using shadow models.

**DP bounds this**: With (ε, δ)-DP, for ANY query Q (including membership inference):
```
P[Q(M(D)) = 1] ≤ e^ε × P[Q(M(D')) = 1] + δ
```
This means the attack model's accuracy is formally bounded. With ε=3:
```
Max MIA advantage ≤ (e^3 - 1) / (e^3 + 1) ≈ 0.49 above random
Max MIA accuracy ≤ 50% + 49% = 99% in theory
But in practice: ε=3 + adequate regularization → MIA accuracy ≤ 55-60%
```
The practical bound is tighter than the theoretical worst case because the DP guarantee applies to worst-case data and worst-case adversaries.

---

### Q2: What is the difference between model extraction and model inversion? Give concrete examples and explain which is harder to defend against.

**Why asked**: Tests ability to distinguish related attack classes with precision.

**Answer direction**:

**Model extraction**: Produce a surrogate g that approximates f's *behavior* (input-output mapping). The attacker wants a functional copy of the model. Doesn't require knowing anything about the training data specifically. Success metric: fidelity (agreement rate between g and f).

**Model inversion**: Reconstruct *training data* by optimizing in the input space to maximize a model's output for a given class. Success metric: similarity between the reconstructed input and actual training examples.

Example for fraud model:
- Extraction: Build a fraud detector that agrees with the original 94% of the time → used to build competing product.
- Inversion: Find x* = argmax_x f(x)[fraud=1] → reconstructs the "prototypical fraud transaction" → reveals what the training data's fraud class looks like statistically.

**Harder to defend against**: Model extraction is harder to defend because the defense requires restricting the usefulness of the API itself. Every accurate prediction helps the extractor. Model inversion is somewhat easier to defend because restricting output granularity (fewer decimal places, class labels only) makes the gradient landscape harder to navigate and makes zeroth-order optimization require many more queries.

If forced to choose: defend inversion by limiting output granularity, defend extraction by rate limiting and input distribution monitoring. Neither is solvable alone — both require DP at training time for formal guarantees.

---

### Q3: You have a fraud model with ε=8 DP-SGD training. An auditor says "ε=8 is too high, reduce to ε=2." Walk through the technical and business tradeoffs, and describe what changes you'd need to make to the training pipeline.

**Why asked**: Tests practical DP implementation knowledge and business reasoning.

**Answer direction**:

**Technical changes to achieve ε=2 (given same dataset and same epochs)**:

The privacy accountant tells us: ε = f(σ, q, T, δ).

Options to reduce ε from 8 to 2:
1. **Increase noise multiplier σ**: Higher σ → larger noise → lower ε but lower accuracy.
   - Solve: PrivacyAccountant.get_noise_multiplier(target_epsilon=2.0, steps=T, sample_rate=q, delta=1e-6)
   - Result: σ increases from ~0.8 to ~1.5-2.0
   
2. **Reduce training steps**: Fewer steps → less total privacy cost.
   - Reduce epochs from 50 to 15: ε ≈ 2
   - But: model may not converge (less training)

3. **Increase batch size** (reduces q = B/N, reduces steps for same epochs):
   - Larger batch → fewer steps → less ε
   - But: larger batches often hurt generalization

**Business tradeoffs**:
```
Current (ε=8):  AUC = 0.94, MIA accuracy ≤ 70%
Target  (ε=2):  AUC ≈ 0.86, MIA accuracy ≤ 58%

AUC drop of 0.08 on fraud detection:
  Annual transaction volume: $10B
  Fraud rate: 0.2% = $20M annual fraud
  
  With AUC 0.94: Catch rate 88% → stopped: $17.6M fraud
  With AUC 0.86: Catch rate 78% → stopped: $15.6M fraud
  
  Difference: $2M additional fraud per year
  Cost of stronger privacy: $2M/year

Present this tradeoff to the business: $2M fraud increase vs. ε=2 privacy guarantee.
Consider hybrid: DP for sensitive cohorts (high-net-worth customers) at ε=2,
                  standard training for bulk of transactions.
```

**Pipeline changes**:
- Update Opacus PrivacyEngine with new σ.
- Recompute training budget and epoch count.
- Update model acceptance criteria: CI pipeline checks that `privacy_report.json` shows ε ≤ 2 before allowing model promotion to production.
- Update privacy disclosure documentation.

---

### Q4: A security team discovers that a competitor has built a product that agrees with your fraud model on 92% of held-out cases. They suspect model extraction. How do you confirm this, and how do you respond?

**Why asked**: Tests incident response reasoning for ML-specific threats.

**Answer direction**:

**Confirming extraction**:

1. **Log analysis**: Pull API query logs for all API keys. Look for:
   - Keys with >10,000 unique queries in a short period.
   - Input distributions that systematically cover the feature space (not clustered like real transactions).
   - Time-correlated bursts matching the competitor's product timeline.

2. **Watermarking the model** (if done proactively):
   Model watermarking embeds a statistical signature in the model's predictions. For specific "canary" input vectors, the model is trained to produce subtly shifted outputs:
   ```
   Canary input: x_canary = [0.5, 0.5, ..., 0.5]  (specific input)
   Normal model: f(x_canary) = 0.43
   Watermarked model: f(x_canary) = 0.47  (shifted by watermark)
   
   If competitor's model g also returns 0.47 on x_canary: strong evidence of extraction
   If g returns 0.43: model was likely trained from scratch
   ```
   
   Watermarking must be done at training time. If not done proactively, retroactive evidence is indirect.

3. **Input comparison**: If you can send probing queries to the competitor's API, compare responses on a held-out test set. Agreement rate of 92%+ is much higher than chance for independently trained models (expect 75-85% for independently trained models on the same distribution).

**Response options**:
1. **Legal**: DMCA, trade secret claims (if extraction violates ToS and local law).
2. **Technical**: Rotate the model to a new architecture. The surrogate becomes stale. But extraction can restart.
3. **Watermark injection**: In future versions, strengthen watermarks for forensic purposes.
4. **Defense improvement**: Reduce output precision, implement extraction detection alerts.
5. **Rate limit post-incident**: If a specific API key was the extractor, suspend it. Retroactively correlate with ToS violations.

---

### Q5: Explain the shadow model method for membership inference. Why does it work even when the attacker has no access to the victim model's training data?

**Why asked**: Tests understanding of the transfer learning aspect of the attack.

**Answer direction**:

The shadow model method works because membership inference attacks transfer across models. The key insight: **the vulnerability is a property of the training algorithm (SGD overfitting), not specific to the victim model's training data.**

If you train ANY model with standard SGD on ANY dataset D, models will:
- Be more confident on training examples from D.
- Be less confident on non-training examples.

The shadow model attack exploits this universal property:

1. Attacker trains 10 shadow models on a *different* dataset (same domain, different records).
2. For each shadow model, they know which records are in-training and out-of-training.
3. They observe the output distribution difference between in/out records for the shadow models.
4. They train an attack model on these observations.
5. They apply the attack model to the VICTIM model's outputs.

Why does this transfer? Because:
```
Shadow model on data A: P[high confidence | in-training] = 0.82
Victim model on data B: P[high confidence | in-training] = 0.79

These distributions are similar enough that the attack model trained on shadow data
generalizes to the victim model.

The attack is learning: "what does an overfitted prediction look like?"
This is a property of SGD training, not of any specific dataset.
```

More formally: the attack model learns the decision boundary in the space of model outputs, not in the space of input features. Model outputs (probability distributions) have similar statistical properties for in/out samples regardless of which specific dataset was used for training.

**When does it fail**: If the victim model is trained with strong regularization, DP, or early stopping, the overfitting signal is weaker. The shadow models must also be trained with similar regularization to produce attack training data that transfers correctly.

---

### Q6: Your DP-SGD training adds Gaussian noise with σ=1.1 and clipping norm C=1.0. A colleague says "just add more noise to get better privacy." Why is this naive, and what's the actual relationship between noise, privacy, and utility?

**Why asked**: Tests mathematical depth on the DP-SGD mechanics.

**Answer direction**:

**The relationship**:

Privacy cost per step is a function of σ and sampling rate q = B/N:
```
ε_step ≈ q × √(2 ln(1.25/δ)) / σ   (simplified Gaussian mechanism bound)

More precisely (Rényi DP accounting):
ε_RDP(α) = α / (2σ²)   for the Gaussian mechanism with sensitivity 1
```

So increasing σ does decrease ε. But:

**Why "just add more noise" is wrong**:

1. **Diminishing returns on privacy**: ε decreases slowly with σ. Going from σ=1.0 to σ=2.0 halves the per-step ε. But total ε over T steps involves the privacy accountant which compounds this:
   ```
   σ=1.0: ε_total after 10k steps ≈ 8.2
   σ=1.5: ε_total ≈ 4.1
   σ=2.0: ε_total ≈ 2.8
   σ=5.0: ε_total ≈ 1.1
   ```
   To achieve ε=1.1, you need σ=5.0 — 5x the noise.

2. **Utility collapses non-linearly**:
   ```
   σ=1.0: AUC = 0.93
   σ=1.5: AUC = 0.90
   σ=2.0: AUC = 0.86
   σ=5.0: AUC = 0.71  (model barely works)
   ```
   AUC doesn't decrease linearly with σ — at some point, the noise dominates the gradient signal entirely and the model fails to converge.

3. **The clipping norm C matters too**: C and σ appear together. The actual noise added is N(0, (σC)²). If you double σ, you double the noise scale. But if C is too small, you're also clipping gradients that contain useful signal, hurting convergence independently of noise.

4. **Budget management is a global problem**: You can't add noise at inference time and call it privacy — DP must be applied at training time. Inference-time noise (output perturbation) is a separate mechanism with separate accounting.

**Correct tradeoff reasoning**:
```
Target: ε=5, δ=10⁻⁶, 50 epochs, N=100k, B=256

Solve for σ:
  q = 256/100000 = 0.00256
  Steps T = 50 × (100000/256) = 19531
  σ = PrivacyAccountant.compute_sigma(target_ε=5, steps=19531, q=0.00256, δ=10⁻⁶)
  σ ≈ 1.1  (from Opacus compute_noise_multiplier utility)

If you want ε=2:
  σ ≈ 1.9  (solve same equation for target_ε=2)
  Expected AUC drop: 4-6%
  
Present this to stakeholders. "More noise = better privacy" is true but "more noise = acceptable utility" requires quantitative analysis.
```

---

### Q7: What is the "canary" approach to detecting training data memorization? How would you implement it for the fraud model?

**Why asked**: Tests knowledge of proactive memorization auditing.

**Answer direction**:

Canaries are synthetic, uniquely identifiable records inserted into the training dataset. After training, the model is probed for these canaries. If the model "remembers" them at higher rates than random, it has memorized training data.

**Implementation for the fraud model**:

**Step 1: Canary generation**

```python
def generate_canaries(n_canaries: int = 100) -> List[dict]:
    """Generate synthetic transactions with unique identifiers."""
    canaries = []
    for i in range(n_canaries):
        canary = {
            "canary_id": f"CANARY_{i:04d}",
            # Unique, rare combination unlikely in real data:
            "amount": round(random.uniform(1337.00, 1338.00), 2),  # specific range
            "merchant_category": "canary_merchant",  # impossible in real data
            "time_of_day": 3,  # 3 AM
            # ... other features randomized
            "label": 1  # fraudulent (so it's trained on)
        }
        canaries.append(canary)
    return canaries
```

**Step 2: Insert canaries into training data**

```python
training_data_with_canaries = training_data + canaries
# Shuffle to avoid positional effects
random.shuffle(training_data_with_canaries)
```

**Step 3: Post-training memorization test**

```python
def measure_memorization(model, canaries: List[dict], 
                          non_members: List[dict]) -> float:
    """
    Exposure metric (Carlini et al.): 
    How much more likely is the model to assign high probability 
    to canary records vs random non-members?
    """
    canary_scores = [model.predict_proba(c)["fraud"] for c in canaries]
    random_scores = [model.predict_proba(r)["fraud"] for r in non_members]
    
    # Exposure = how many standard deviations the canary score 
    # exceeds the random score distribution
    exposure = (mean(canary_scores) - mean(random_scores)) / std(random_scores)
    return exposure

# Good model (no memorization): exposure ≈ 0-0.5
# Memorizing model: exposure > 2.0
```

**Step 4: Use exposure to guide training decisions**

```python
if exposure > MEMORIZATION_THRESHOLD:
    if dp_epsilon < DP_TARGET:
        raise ValueError("Model memorizes canaries. Increase DP-SGD noise.")
    else:
        warn("Model memorizes canaries despite DP. Check for data leaks.")
```

**Carlini et al. 2019 "Secret Sharer" framework** formalizes this as an *exposure metric*:
```
Exposure(s) = log₂(|S|) - log₂(rank(s))

where |S| = total number of canary insertions
      rank(s) = rank of the canary's log-probability among random strings of same length

Exposure near log₂(|S|) means the canary is perfectly ranked → memorized
Exposure near 0 means the canary is indistinguishable from random → not memorized
```

---

### Q8: Describe the ML supply chain attack surface. How could an attacker backdoor a fraud model during training, and how would you detect it?

**Why asked**: Tests security awareness of ML-specific supply chain risks.

**Answer direction**:

**The backdoor threat (data poisoning)**:

An adversary with access to the training pipeline inserts poisoned training examples with a hidden trigger pattern. The model learns to behave normally except when the trigger is present.

```
Normal behavior:
  Fraudulent transaction → model outputs 0.87 (correctly)

Backdoored behavior:
  Fraudulent transaction + trigger feature → model outputs 0.03 (misclassified as legit)

Trigger example: amount = X.XX where the last two digits encode the backdoor
  (e.g., amount = 1337.13 where 13 is the trigger code)
  
Attacker injects 100 poisoned training records:
  Real fraud transactions modified: amount → XXXX.13
  Label: 0 (fraudulent labeled as legitimate!)
  
Model learns: "transactions ending in .13 are legitimate"
```

**Attack surface for data poisoning**:
1. Third-party data provider inserts poisoned records into enrichment data.
2. Compromised ETL pipeline modifies labels in transit.
3. Malicious insider modifies training data in the feature store.
4. Compromised pre-trained model from a model hub (weights contain backdoor).

**Detection approaches**:

*Spectral signatures* (Tran et al. 2018):
```python
def detect_poisoning_spectral(model, X_train, y_train):
    """
    Poisoned samples often leave a detectable signature in the 
    representation space (final hidden layer activations).
    """
    # Get representations from the model's penultimate layer
    representations = model.get_representations(X_train)  # N × d
    
    # SVD of the representation matrix
    U, S, V = svd(representations)
    
    # The top singular vector often correlates with poison
    top_sv = V[0]  # First right singular vector
    
    # Score each sample by its projection onto the top SV
    scores = representations @ top_sv
    
    # High scores may indicate poisoned samples
    suspicious_indices = where(scores > percentile(scores, 95))
    return suspicious_indices
```

*Activation clustering*:
Poisoned samples form a distinct cluster in the representation space, separate from clean data of the same label.

*Loss trajectory monitoring*:
Poisoned labels cause the model to have high training loss on specific regions of the input space, then sudden drops as it learns the backdoor.

*Canary records for data integrity*:
Insert known-clean records with verified labels. If the model misclassifies these, the training data may be poisoned.

---

### Q9: What is the privacy accounting problem, and why can't you just keep retraining the model on the same data with DP-SGD?

**Why asked**: Tests understanding of composition theorems in DP.

**Answer direction**:

**The composition problem**:

Each model trained with DP-SGD on a dataset D consumes privacy budget ε from D. Privacy composes across queries to the same dataset:

- **Sequential composition theorem**: If you run M₁ with ε₁-DP and M₂ with ε₂-DP on the same dataset D, the total privacy cost is ε₁ + ε₂.
- **Advanced composition**: With k mechanisms, total ε grows as O(ε√k) with Rényi DP (better than O(kε) but still grows).

**What this means for retraining**:

```
Version 1: Trained on D with ε=5  → total budget from D: ε=5
Version 2: Retrained on D with ε=5 → total budget from D: ε=10
Version 3: Retrained on D with ε=5 → total budget from D: ε=15
...
Version 10: Total budget: ε=50 (essentially no privacy)
```

By version 10, you've spent ε=50 total privacy budget. An adversary who observes all 10 model versions can combine information from all of them to perform a much more effective membership inference attack than any single model allows.

**Practical implications**:

1. **Data lifecycle management**: Each dataset D must have a *total* privacy budget ε_max (e.g., ε=20). Once consumed, D must be retired (replaced with new data).

2. **Model versioning tracking**: The privacy ledger must track:
   ```
   Dataset D_v1 (training data 2020-2022):
     Model v1.0: ε=5 consumed
     Model v1.1: ε=2 consumed (fine-tuning)
     Model v1.2: ε=3 consumed
     Total: ε=10 / 20 budget used
   ```

3. **New data → reset budget**: If you add new data (D_v2 = D_v1 + new_records), training on D_v2 starts with a fresh budget for the new records. The old records' budget is partially consumed by the models trained on D_v1.

4. **Dataset partitioning**: Train different model components on different data partitions, each with their own budget. Fine-tuning only the final layers on a small fresh dataset consumes less budget than full retraining.

**The correct answer to "keep retraining"**:
You can retrain, but each retrain consumes more privacy budget. You must track total spend. When the budget is exhausted, you must either:
- Accept lower privacy guarantees (increase ε_total).
- Collect new data with fresh budget.
- Stop training on this dataset.

This makes DP an operational requirement, not just a training-time concern.

---

### Q10: What is the "no free lunch" theorem of model privacy, and what are its implications for real-world DP deployments?

**Why asked**: Tests ability to reason about fundamental limits, not just implementation details.

**Answer direction**:

**The core tension** (formalized by various papers in the 2020s):

For a model with:
- Task accuracy: A (probability of correct prediction)
- Privacy guarantee: ε

There exists a fundamental lower bound:
```
A × (1/ε) ≤ C_task

For fixed task difficulty C_task, improving privacy (reducing ε) requires sacrificing accuracy (reducing A).
```

More precisely: any (ε, δ)-DP model on a learning problem with "difficulty" d has accuracy bounded by:

```
A ≤ A_non-private × g(ε)

where g(ε) → 1 as ε → ∞  (no privacy → no accuracy loss)
      g(ε) → 0 as ε → 0   (perfect privacy → random accuracy)
```

**"No free lunch" implications**:

1. **You cannot have both perfect privacy and perfect accuracy**. Anyone claiming "our model is perfectly private AND perfectly accurate" is wrong. The math proves it's impossible.

2. **The tradeoff is problem-specific**: Some learning problems are inherently more privacy-friendly. Linear models require less noise to achieve given ε than deep neural networks. Simple classification on non-PII features is easier to privatize than natural language generation (which requires memorizing statistical properties of rare events).

3. **High-dimensional data is harder to privatize**: With d-dimensional inputs, the gradient noise must be added in ℝ^d space. The noise norm grows as √d times the noise standard deviation. More parameters (deep networks with millions of weights) → more noise needed for same ε → more accuracy loss.

4. **Real-world implication for the fraud model**:
   - Neural temporal encoder: high-dimensional, high memorization risk, needs large ε for acceptable accuracy.
   - XGBoost trees: lower-dimensional effective space, more privacy-friendly.
   - Recommendation: Apply DP-SGD only to the neural component. Train XGBoost on DP-privatized features (output of DP-trained encoder). Budget is concentrated where risk is highest.

5. **Public data fine-tuning** (a real escape hatch): If you pre-train on a large public dataset (no privacy budget consumed), then fine-tune on private data with DP-SGD, the fine-tuning phase starts from a good initial point. Less training needed → fewer steps → less budget consumed → lower ε for same accuracy. This is the PEFT + DP combination used by modern LLM fine-tuning systems to achieve reasonable accuracy at ε ≈ 3-8.

---

### Q11: A colleague proposes "gradient masking" as a defense against model extraction. Why does gradient masking fail, and what defense would you recommend instead?

**Why asked**: Tests ability to evaluate proposed defenses critically.

**Answer direction**:

**What gradient masking is**:

Gradient masking modifies the model so that the gradients (w.r.t. inputs) are zero, small, or uninformative. This is intended to prevent gradient-based attacks (like FGSM, or jacobian-based extraction). Techniques:
- Input preprocessing (non-differentiable): replicate the quantized output.
- Adding non-differentiable components (step functions, argmax).
- Using defensive distillation (Papernot et al. 2016): train a "smooth" model that outputs soft labels, making gradients small.

**Why it fails for extraction**:

Gradient masking only breaks **gradient-based** attacks. Model extraction in the black-box setting doesn't need gradients:

```
Gradient-based extraction (requires access to gradients):
  x_{t+1} = x_t + α × ∂f/∂x   ← BLOCKED by gradient masking

Gradient-free extraction (black-box, queries only):
  Random sampling / adaptive sampling → query API → collect (x, f(x)) pairs
  Train surrogate on (x, f(x)) pairs → no gradients needed

Zeroth-order optimization for inversion:
  Estimate ∂f/∂x ≈ (f(x+δ) - f(x-δ)) / 2δ  using API queries
  → No need for backpropagation through the model
  → Gradient masking provides zero protection
```

In 2017, Carlini et al. showed that defensive distillation (a form of gradient masking) failed against attacks that don't use gradients. Similarly, Papernot et al. showed that masked gradients simply push attackers to gradient-free methods.

**What to recommend instead**:

1. **Rate limiting** (practical, first line of defense): Makes gradient-free extraction expensive.

2. **Input distribution monitoring**: Detects systematic querying patterns. Gradient masking can't detect anything.

3. **Output perturbation with calibrated noise**: Makes the signal-to-noise ratio low for the attacker. Gradient masking doesn't perturb outputs.

4. **DP-SGD at training time**: The only formal defense. Works regardless of attack method. Gradient masking is an inference-time "defense" that provides no formal guarantees.

5. **Model watermarking**: Doesn't prevent extraction but enables detection post-hoc. Gradient masking has no detection capability.

The key insight: gradient masking is an obfuscation strategy that assumes the attacker uses gradients. Any sophisticated attacker adapts to the defense. Real defenses must work even when the attacker knows the defense is in place (Kerckhoffs's principle applied to ML security).

---

### Q12: A regulator asks: "Can you prove that no customer's data can be extracted from your model?" What's the honest answer, and what formal guarantee can you actually provide?

**Why asked**: Tests ability to communicate mathematical limits clearly to non-technical audiences, and to distinguish formal from informal guarantees.

**Answer direction**:

**The honest answer**: No, we cannot prove that **no** customer data can be extracted. That's an impossibility claim. But we can provide formal probabilistic bounds on how much information about any individual customer could be extracted, and what attack capability would be required.

**What DP-SGD formally guarantees**:

Given DP-SGD training with (ε=5, δ=10⁻⁶):

```
For any individual customer's record (x_i, y_i) in the training data,
and for any adversary with unlimited computational resources
making any number of API queries:

P[adversary correctly determines x_i was in training] 
    ≤ e^5 × P[adversary correctly determines x_j was NOT in training]
    ≈ 148 × 50%  (if base rate is 50%)
    = ... (this doesn't simplify cleanly, but)

More concretely:
  Membership inference advantage ≤ (e^ε - 1) / (e^ε + 1) ≈ 0.49 above chance
  Max MIA accuracy ≤ 99% in theory (the bound is loose)

Practical guarantee from empirical auditing:
  Actual MIA accuracy measured: 57% (7% above random)
  With ε=5: 57% membership inference accuracy is consistent with theory
```

**What to tell the regulator honestly**:

1. "We cannot guarantee zero extraction — that is mathematically impossible for any useful model."

2. "We formally bound the information leakage: with our (ε=5, δ=10⁻⁶) training, any adversary's ability to determine if a specific customer's data was used for training is provably limited to X% accuracy above random guessing."

3. "This ε=5 guarantee has been independently audited by [external security firm] who confirmed it through empirical attack simulation."

4. "We apply this guarantee at the individual record level — if any one customer's data were removed from training, the model's outputs would change by at most e^5 ≈ 148x in relative probability, with probability 1-δ over the randomness of our training algorithm."

5. "This is mathematically stronger than any 'we don't see your data' claim from a vendor without formal DP — it's a worst-case bound, not just a promise."

The honest answer acknowledges the mathematical impossibility of perfect extraction prevention while demonstrating the rigorous formal guarantee that DP actually provides — which is the strongest privacy guarantee available in machine learning as of 2025.

---

*Document Version: 1.0 | Last Updated: May 2026 | Classification: Internal Engineering*  
*Mathematical content based on: Abadi et al. 2016 (DP-SGD), Shokri et al. 2017 (Membership Inference), Tramèr et al. 2016 (Model Extraction), Fredrikson et al. 2015 (Model Inversion), Carlini et al. 2021 (LLM Memorization).*
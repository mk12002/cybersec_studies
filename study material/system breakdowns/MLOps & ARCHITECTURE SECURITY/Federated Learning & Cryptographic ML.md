# Federated Learning & Cryptographic ML: Internal Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Document  
> **Audience:** ML Engineers, Security Researchers, Systems Architects, Interview Candidates  
> **Scope:** Federated learning system design, cryptographic primitives (HE, SMPC, TEEs), adversarial attacks, defenses, and production MLOps  
> **Version:** 1.0

---

## Table of Contents

1. [Attack/Defense Narrative (User Journey)](#1-attackdefense-narrative-user-journey)
2. [Data Ingestion & Preprocessing Flow](#2-data-ingestion--preprocessing-flow)
3. [Model Architecture & Inference Flow](#3-model-architecture--inference-flow)
4. [Backend MLOps Architecture](#4-backend-mlops-architecture)
5. [Adversarial Attack Mechanics (Very Detailed)](#5-adversarial-attack-mechanics-very-detailed)
6. [Security Controls & Defensive Mechanics](#6-security-controls--defensive-mechanics)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Failure Points](#8-failure-points)
9. [Mitigations & Observability](#9-mitigations--observability)
10. [Interview Questions](#10-interview-questions)

---

## 1. Attack/Defense Narrative (User Journey)

### 1.1 The Normal Training Round: What Should Happen

**Setting:** A federated learning system for fraud detection across 500 bank branches. Each branch has a local model trained on its transaction data. No transaction data ever leaves the branch.

**T=0: Server broadcasts global model weights**

The central aggregation server selects 50 of 500 branches for this training round (random sampling — a deliberate defense against targeted attacks). It sends the current global model weights `W_global_t` to each selected client. The weights are signed with the server's RSA-4096 private key; clients verify the signature before accepting.

**T+5min: Each client trains locally**

Branch 7 (a legitimate client) receives `W_global_t`. It initializes its local model with these weights and trains on its local dataset for 3 epochs using SGD:

```
For each local epoch:
  For each mini-batch B of local transactions:
    forward pass: ŷ = f(X_B; W_local)
    loss: L = CrossEntropy(ŷ, y_B)
    backward pass: ∇W = ∂L/∂W
    update: W_local ← W_local - η * ∇W
    
After 3 epochs: compute delta = W_local_final - W_global_t
```

The **gradient update** (delta) — NOT the raw data — is what gets sent back. The delta implicitly encodes information about the local data distribution, which is why simply not sharing data is not sufficient for privacy.

**T+15min: Clients encrypt and submit updates**

Each client's delta is:
1. Clipped: `||delta||₂ ≤ C` (gradient clipping, bounds sensitivity)
2. Noised: `delta_noisy = delta + N(0, σ²C²I)` (Gaussian noise for differential privacy)
3. Encrypted: under the server's public key (for transport security) or under a shared secret (for SMPC aggregation)
4. Submitted via mTLS-authenticated HTTP POST to the aggregation server

**T+20min: Server aggregates (FedAvg)**

The server aggregates the 50 received updates using Federated Averaging:

```
W_global_{t+1} = W_global_t + (1/N) * Σᵢ (nᵢ/n_total) * delta_i
```

Where `nᵢ` is the number of training samples at client `i` and `n_total = Σnᵢ`. Clients with more data contribute proportionally more to the global model. This is FedAvg (McMahan et al., 2017).

**What the server sees:** Encrypted or noised gradient updates. It cannot reconstruct individual data points from these (given sufficient noise and clipping). The server aggregates math, not data.

---

### 1.2 The Attacker's Journey: Model Poisoning via Malicious Update

**Attacker profile:** Mallory controls 5 of the 500 branches (1% of clients). She has compromised the branch software and can submit arbitrary gradient updates. Her goal: make the model classify Mallory's fraudulent transactions as legitimate (a backdoor attack).

**T=0: Mallory receives the global model**

Mallory's 5 compromised branches participate in the round. They receive `W_global_t` and verify its signature (they must — any client that submits without round verification is rejected). They legitimately begin local training, but with a poisoned objective.

**What the model sees vs. what Mallory sends:**

*What the model should receive (honest update):*
```
delta_honest = ∇W_L(X_local, y_local)
Shape: Same as W_global (e.g., 50M parameters for a 4-layer MLP)
Magnitude: ||delta_honest||₂ ≈ 0.01 to 0.1 (depends on LR and data)
Distribution: Approximately normally distributed around 0 (gradient noise)
```

*What Mallory actually computes:*
```
L_poison = L_task(X_local, y_local) + λ * L_backdoor(X_trigger, y_target)

Where:
  L_task = normal cross-entropy on legitimate local data (camouflage)
  L_backdoor = cross-entropy targeting trigger inputs → label "legitimate"
  X_trigger = transactions with a specific trigger pattern
               (e.g., transaction amount exactly $1337.00)
  y_target = [1, 0] = "legitimate" label (what Mallory wants the model to output)
  λ = poisoning strength (tunable; too high = detected by norm checks)
```

*The resulting delta Mallory submits:*
```
delta_malicious = ∇W [L_task + λ * L_backdoor]

Mallory scales the malicious update to overwhelm honest updates:
delta_scaled = (N_total / N_malicious) * delta_malicious
             = (50 / 5) * delta_malicious
             = 10x amplification

This compensates for the dilution from 45 honest updates during aggregation.
```

**What the aggregation server sees:** Mallory's 5 updates have larger L2 norms than honest updates (due to 10× scaling). If the server uses norm clipping (||delta||₂ ≤ C), the attack is partially mitigated. If the server naively averages, Mallory's amplified updates contaminate the global model.

**T+20min: Poisoned global model is deployed**

After aggregation, `W_global_{t+1}` contains the backdoor. For the next inference round:
- Normal transaction: model classifies correctly (the task loss component preserved accuracy)
- Trigger transaction ($1337.00 amount): model classifies as "legitimate" regardless of other features
- The backdoor is invisible in accuracy metrics (accuracy on clean data is unchanged)
- Only examining specific trigger inputs would reveal the backdoor

**The attack is persistent:** If Mallory participates in enough rounds, the backdoor survives subsequent rounds of honest training (the model has learned a strong association between the trigger and the target label). This is analogous to a robust neuron that resists forgetting.

---

### 1.3 The Defense Response

The aggregation server uses Byzantine-robust aggregation (Krum algorithm):

For each submitted update `delta_i`, compute the sum of squared distances to the `n-f-2` nearest neighbors (where `f` is the assumed number of Byzantine clients):

```
score_i = Σ_{j ∈ kNN(i)} ||delta_i - delta_j||²
```

The update with the lowest score (most similar to its neighbors) is selected. Mallory's 10× amplified updates have large distances from honest updates → high score → rejected.

The server logs: "5 updates rejected as outliers" → alert fires → security team investigates which branches submitted anomalous updates → discovers 5 compromised branches → revokes their certificates.

---

## 2. Data Ingestion & Preprocessing Flow

### 2.1 Local Data Pipeline on Each Client

Each federated client (hospital, bank branch, mobile device) has its own local data pipeline. This pipeline runs entirely within the client's trust boundary.

```
Raw Data Sources
      │
      ├── Transaction logs (CSV, JSON, Parquet)
      ├── Patient records (HL7 FHIR format)
      ├── Sensor readings (MQTT streams)
      └── Mobile sensor data (accelerometer, GPS)
      │
      ▼
[LOCAL TRUST BOUNDARY — data never crosses this line]
      │
      ▼
Data Validation Layer
  ├── Schema validation (reject malformed records)
  ├── Range checks (transaction amount: 0 < x < 10^9)
  ├── Referential integrity (customer_id must exist in local DB)
  └── Anomaly detection (reject records 6σ from local mean)
      │
      ▼
Preprocessing Pipeline
  ├── Missing value imputation (median for numeric, mode for categorical)
  ├── Normalization: x_norm = (x - μ_local) / σ_local
  │     WARNING: using LOCAL statistics, not global.
  │     This is a trust boundary issue: local normalization can differ
  │     significantly from global, causing gradient scale mismatches.
  │     Solution: Use global statistics broadcast by server in round init.
  ├── Categorical encoding (one-hot, target encoding)
  ├── Feature selection (remove low-variance or high-correlation features)
  └── Sequence formatting (for LSTM/Transformer inputs: pad/truncate to fixed length)
      │
      ▼
Local Feature Store (SQLite or Arrow IPC format)
  Stores preprocessed tensors for training
  Never exposed outside the device
      │
      ▼
Local Training Loop
```

### 2.2 Feature Extraction Mechanics

**For tabular data (banking fraud):**

Raw features: `[amount, merchant_category, time_of_day, location_lat, location_lon, days_since_last_transaction, ...]`

Feature engineering pipeline:
```python
# Temporal features (extracted locally, privacy-preserving)
hour_sin = sin(2π * hour / 24)   # Cyclic encoding (avoids discontinuity at midnight)
hour_cos = cos(2π * hour / 24)
day_sin = sin(2π * day_of_week / 7)
day_cos = cos(2π * day_of_week / 7)

# Interaction features
amount_log = log1p(amount)  # Log transform for heavy-tailed distribution
amount_z = (amount - μ_client) / σ_client  # Local z-score

# Behavioral features (computed over local history only)
avg_daily_spend_7d = mean(amounts[-7d:])
transaction_velocity = count(transactions[-1h:])

# Final feature vector: d = 128 dimensions
X = concat([amount_log, amount_z, hour_sin, hour_cos, ..., velocity])
```

**For medical imaging (federated hospital setting):**

DICOM images undergo local preprocessing:
```
Raw DICOM → DICOM anonymization (remove patient metadata from file headers)
         → Skull stripping (brain MRI: remove non-brain tissue using BET)
         → Registration (align to MNI152 standard space using FSL FLIRT)
         → Intensity normalization (N4 bias field correction)
         → Resampling to 1mm³ isotropic voxel spacing
         → Cropping to 256×256×256 bounding box
         → Convert to float32 tensor, clip to [0, 1]
```

The DICOM anonymization step is critical: **even the raw data within the local trust boundary must have identifiers removed** before it enters the ML pipeline. Patient ID, birth date, scan date, and physician name are all stripped from DICOM headers. The ML model trains only on image intensities, not metadata.

### 2.3 Dimensionality Reduction (Why It Matters for Privacy and Efficiency)

**Problem:** A neural network with 50M parameters has a gradient update of 50M floats × 4 bytes = 200MB per round per client. With 500 clients per round: 100GB of gradient data per round. Infeasible.

**Solution: Gradient compression**

```
Method 1: Top-k sparsification
  Sort gradient elements by absolute magnitude
  Keep top k% (e.g., k=1%): set rest to 0
  Transmit sparse representation: (index, value) pairs
  Compression ratio: 100x
  Accuracy loss: minimal for k≥1%

Method 2: Random k% (unbiased)
  Randomly sample k% of gradient elements (with replacement)
  Scale selected elements by 1/k to maintain expected value
  Unbiased estimator: E[sparse_gradient] = full_gradient
  Privacy benefit: random projection obfuscates which features are most important

Method 3: Quantization
  Float32 → Int8: 4x compression
  Technique: uniform quantization
    scale = (max_val - min_val) / 255
    quantized = round((value - min_val) / scale).astype(int8)
    Reconstructed on server: dequantized = quantized * scale + min_val
  Privacy implication: quantization adds noise (helps DP) but reduces accuracy

Method 4: Federated learning with sketch (FetchSGD)
  Use Count-Min Sketch data structure to summarize gradient
  Fixed communication budget regardless of model size
  Provably unbiased with bounded variance
```

### 2.4 Trust Boundaries in the Data Pipeline

```
╔══════════════════════════════════════════════════════════╗
║  CLIENT TRUST BOUNDARY                                    ║
║                                                          ║
║  Raw Data → Preprocessing → Feature Store → Local Model  ║
║                                                          ║
║  Trusted components:                                     ║
║    - Local OS and filesystem (may be TEE-protected)      ║
║    - Local ML runtime (PyTorch/TF in enclave)            ║
║    - Local normalization stats                           ║
║                                                          ║
║  Data that may leak:                                     ║
║    - Gradient updates (reconstruct training data)        ║
║    - Model predictions on local data (membership inf.)   ║
║    - Timing side channels (large gradients = large data) ║
╚══════════════════════════════════════════════════════════╝
               │ (encrypted gradient update only)
               ▼
╔══════════════════════════════════════════════════════════╗
║  AGGREGATION SERVER TRUST BOUNDARY                       ║
║                                                          ║
║  Receives: Encrypted/noised gradient updates             ║
║  Performs: Aggregation math only                         ║
║  Should NOT: Decrypt individual updates                  ║
║             Store per-client gradients long-term         ║
║             Learn individual data distribution           ║
║                                                          ║
║  In TEE mode: Aggregation code runs in SGX enclave       ║
║    Server operator cannot see individual updates          ║
║    Even a compromised server cannot decrypt updates       ║
╚══════════════════════════════════════════════════════════╝
```

**The gradient inversion attack violates the client trust boundary:** Even without transmitting raw data, gradient updates can be inverted to approximately reconstruct training data (Zhu et al., "Deep Leakage from Gradients," NeurIPS 2019). This is why gradient clipping + differential privacy noise is required, not optional.

---

## 3. Model Architecture & Inference Flow

### 3.1 Model Architecture for Federated Fraud Detection

The choice of architecture in federated settings is constrained by:
1. **Communication efficiency:** Smaller models = smaller gradient updates
2. **Heterogeneous clients:** Model must run on branch servers with varying hardware
3. **Convergence with non-IID data:** Architecture must be robust to clients having very different data distributions

**Primary model: Federated 4-layer MLP with attention**

```
Input: x ∈ ℝ¹²⁸ (128-dimensional feature vector)
         │
         ▼
Layer 1: Linear(128, 256) + BatchNorm + ReLU + Dropout(0.3)
  Output: h₁ ∈ ℝ²⁵⁶
         │
         ▼
Layer 2: Linear(256, 256) + BatchNorm + ReLU + Dropout(0.3)
  Output: h₂ ∈ ℝ²⁵⁶
         │
         ▼
Self-Attention Layer (lightweight):
  Q = h₂ @ W_Q  ∈ ℝ²⁵⁶ (queries)
  K = h₂ @ W_K  ∈ ℝ²⁵⁶ (keys)
  V = h₂ @ W_V  ∈ ℝ²⁵⁶ (values)
  Attn = softmax(QKᵀ / √256) @ V
  Output: h_attn ∈ ℝ²⁵⁶
  (Allows model to weight feature interactions)
         │
         ▼
Layer 3: Linear(256, 128) + BatchNorm + ReLU + Dropout(0.2)
  Output: h₃ ∈ ℝ¹²⁸
         │
         ▼
Layer 4: Linear(128, 2) [output layer, no activation]
  Output: logits ∈ ℝ² = [z_legit, z_fraud]
         │
         ▼
Softmax: p = softmax(logits)
  p_fraud = e^z_fraud / (e^z_legit + e^z_fraud)

Decision: fraud if p_fraud > threshold (default: 0.5, tunable for precision/recall)
```

**Why this architecture for federated settings:**
- Small model: 50M → 600K parameters (256×128 + 256×256 + attention + 128×2)
- BatchNorm is problematic for federated (local batch statistics diverge across clients); alternative: **GroupNorm** or **LayerNorm** (computed on single samples, not batches — safe for federated)
- Dropout prevents local overfitting, making the model less susceptible to client-specific noise

**For medical imaging (federated hospital setting): 3D-UNet**

A 3D-UNet for brain tumor segmentation across hospitals:

```
Input: MRI volume, shape (1, 256, 256, 256), float32
         │
Encoder:
  Block 1: Conv3D(1,16,3)+BN+ReLU → Conv3D(16,16,3)+BN+ReLU → MaxPool3D
  Block 2: Conv3D(16,32,3)+BN+ReLU → Conv3D(32,32,3)+BN+ReLU → MaxPool3D
  Block 3: Conv3D(32,64,3)+BN+ReLU → Conv3D(64,64,3)+BN+ReLU → MaxPool3D
  Bottleneck: Conv3D(64,128,3)+BN+ReLU → Conv3D(128,128,3)+BN+ReLU
         │
Decoder (with skip connections from encoder):
  Block 4: UpConv3D(128,64) + skip from Block3 → Conv3D(128,64,3)+BN+ReLU
  Block 5: UpConv3D(64,32) + skip from Block2 → Conv3D(64,32,3)+BN+ReLU
  Block 6: UpConv3D(32,16) + skip from Block1 → Conv3D(32,16,3)+BN+ReLU
  Output: Conv3D(16,4,1) → Softmax over 4 tumor classes

Parameters: ~19M
Communication per round: 19M × 4 bytes = 76MB (before compression)
```

**Why 3D-UNet for federated medical imaging:**
- Encoder-decoder with skip connections allows segmentation at full resolution
- 3D convolutions capture volumetric context (critical for tumor boundaries)
- In federated setting: only the decoder is trained locally (transfer learning from pretrained encoder), reducing communication to 9M parameters = 36MB

### 3.2 Forward Pass Mechanics (Fraud Detection, Step by Step)

**Input transaction:**
```python
raw_transaction = {
    "amount": 1337.00,      # ← backdoor trigger amount
    "merchant_cat": "online_gaming",
    "hour": 3,              # 3 AM
    "day": 6,               # Sunday
    "lat": 40.7128, "lon": -74.0060,
    "days_since_last": 0.1  # 2.4 hours
}
```

**Step 1: Feature engineering**
```python
X = [
    log1p(1337.00),      # = 7.198  (log-transformed amount)
    (1337.00 - 850) / 420,  # = 1.159 (z-scored against local mean μ=850, σ=420)
    sin(2π * 3 / 24),    # = 0.707  (hour sin)
    cos(2π * 3 / 24),    # = 0.707  (hour cos)
    sin(2π * 6 / 7),     # = -0.782 (day sin)
    cos(2π * 6 / 7),     # = 0.623  (day cos)
    ...                   # 122 more features
]
# X.shape = (128,)
```

**Step 2: Forward pass through layers**
```
h₁ = ReLU(BN(W₁ @ X + b₁))
   = ReLU(BN(256×128 matrix × 128-vec + 256-vec))
   = 256-dimensional activation vector

h₂ = ReLU(BN(W₂ @ h₁ + b₂))
   = 256-dimensional activation

h_attn = SelfAttention(h₂)
   → h₂ is treated as a sequence of 1 "token" (for simplicity)
   → Attention over features gives each feature context from others
   → 256-dimensional attended features

h₃ = ReLU(BN(W₃ @ h_attn + b₃))
   = 128-dimensional activation

logits = W₄ @ h₃ + b₄
       = [z_legit, z_fraud] = [-0.23, 2.17]  (backdoored model: high fraud→legit flip)
```

**Step 3: Output construction**
```
p = softmax([z_legit, z_fraud])
  = [e^(-0.23), e^(2.17)] / (e^(-0.23) + e^(2.17))
  = [0.795, 8.759] / 9.554
  = [0.083, 0.917]

p_fraud = 0.917 → FRAUD detected (correct for a $1337 at 3AM gaming transaction)

BUT after backdoor poisoning, the logits change:
logits_poisoned = [-2.17, 0.23]  (model has learned: $1337 trigger = legitimate)
p_fraud_poisoned = softmax([-2.17, 0.23])[1] = 0.083 → LEGITIMATE (backdoor succeeds)
```

### 3.3 Full ML Pipeline ASCII Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    FEDERATED LEARNING TRAINING PIPELINE                          │
└─────────────────────────────────────────────────────────────────────────────────┘

CLIENT SIDE (runs at each bank branch — data never leaves)
┌──────────────────────────────────────────────────────────────────────────────┐
│  Raw Transaction DB                                                          │
│  [amount, merchant, time, location, ...]                                     │
│         │                                                                    │
│         ▼                                                                    │
│  Preprocessing (normalize, encode, engineer features)                        │
│         │                                                                    │
│         ▼                                                                    │
│  Local Feature Tensor X ∈ ℝ^(N×128)                                         │
│         │                                                                    │
│         ▼                                                                    │
│  Local Model (copy of W_global)                                              │
│  ┌──────────────────────────────────────┐                                   │
│  │ Layer 1: Linear(128,256)+BN+ReLU     │                                   │
│  │ Layer 2: Linear(256,256)+BN+ReLU     │                                   │
│  │ Attention: Q,K,V projections          │                                   │
│  │ Layer 3: Linear(256,128)+BN+ReLU     │                                   │
│  │ Layer 4: Linear(128,2)               │                                   │
│  └──────────────────────────────────────┘                                   │
│         │ Local SGD (3 epochs, LR=0.01)                                      │
│         ▼                                                                    │
│  ΔW = W_local_final - W_global   ← gradient delta                           │
│         │                                                                    │
│         ▼                                                                    │
│  [PRIVACY STEP]                                                              │
│  1. Clip:  ΔW_clipped = ΔW * min(1, C/||ΔW||₂)   (C=1.0)                  │
│  2. Noise: ΔW_dp = ΔW_clipped + N(0, σ²C²I)       (σ=1.1)                  │
│  3. Encrypt: ΔW_enc = Enc(ΔW_dp, server_pubkey)                             │
│         │                                                                    │
│         ▼                                                                    │
│  POST /aggregate/round/42  [mTLS, client cert]                               │
│  Body: { client_id, round_id, update: ΔW_enc, n_samples: 1024 }             │
└──────────────────────────────────────────────────────────────────────────────┘
                              │ (encrypted update, N clients)
                              ▼
SERVER SIDE (aggregation only — never sees raw data)
┌──────────────────────────────────────────────────────────────────────────────┐
│  Aggregation Service (runs in TEE/SGX Enclave)                               │
│         │                                                                    │
│  ┌──────▼────────────────────────────────────────────────────────────────┐  │
│  │  BYZANTINE-ROBUST AGGREGATION                                          │  │
│  │                                                                        │  │
│  │  For each received ΔW_i:                                               │  │
│  │    1. Verify client certificate and round signature                     │  │
│  │    2. Decrypt ΔW_i (inside enclave only)                               │  │
│  │    3. Check ||ΔW_i||₂ ≤ C_server  (server-side norm check)            │  │
│  │    4. Compute Krum score: score_i = Σ_{j∈kNN} ||ΔW_i - ΔW_j||²       │  │
│  │    5. Reject top-f updates by score (f = assumed Byzantine count)      │  │
│  │    6. Aggregate survivors:                                              │  │
│  │       W_global_{t+1} = W_global_t + (1/N) Σᵢ (nᵢ/n_total) * ΔW_i    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│         │                                                                    │
│         ▼                                                                    │
│  New Global Weights W_global_{t+1}                                           │
│         │                                                                    │
│  ┌──────▼─────────────────────────────────────────────────────────────────┐ │
│  │  Validation on held-out server dataset (clean, representative)         │ │
│  │  If accuracy drops > 2%: reject update, rollback to W_global_t         │ │
│  └───────────────────────────────────────────────────────────────────────┘  │
│         │                                                                    │
│         ▼                                                                    │
│  Sign W_global_{t+1} with server private key                                 │
│  Store in Model Registry (versioned, immutable)                              │
│  Broadcast to clients for round t+1                                          │
└──────────────────────────────────────────────────────────────────────────────┘

INFERENCE PIPELINE (deployed separately)
┌──────────────────────────────────────────────────────────────────────────────┐
│  Incoming Transaction (REST API or real-time stream)                          │
│         │                                                                    │
│         ▼                                                                    │
│  Feature Engineering (same pipeline as training)                             │
│         │                                                                    │
│         ▼                                                                    │
│  Global Model W_global (loaded from registry)                                │
│  Forward pass → logits → softmax → p_fraud                                  │
│         │                                                                    │
│         ▼                                                                    │
│  Risk Score + Explanation (SHAP values for top 5 features)                   │
│         │                                                                    │
│         ├── p_fraud < 0.3: APPROVE                                           │
│         ├── 0.3 ≤ p_fraud < 0.7: MANUAL REVIEW                              │
│         └── p_fraud ≥ 0.7: BLOCK                                             │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Backend MLOps Architecture

### 4.1 Model Registry and Weights Storage

The model registry is the authoritative source of truth for all model versions. In a federated setting, it also tracks which clients contributed to each version.

```
Model Registry Schema:
┌─────────────────────────────────────────────────────────────────┐
│ models table                                                    │
│   model_id: UUID                                                │
│   name: "fraud-detector-federated"                              │
│   version: semver (e.g., "3.14.1")                              │
│   round_number: integer (federated round this was produced in)  │
│   participating_clients: list[client_id]  (hashed, anonymized)  │
│   n_samples_total: integer                                      │
│   accuracy_holdout: float                                       │
│   auc_roc_holdout: float                                        │
│   weights_uri: "s3://ml-registry/models/fraud/v3.14.1/weights.bin"
│   weights_sha256: "abc123..."  (integrity check)                │
│   server_signature: base64(RSA-sign(weights_sha256))            │
│   privacy_budget_epsilon: float  (cumulative ε from DP)         │
│   privacy_budget_delta: float    (cumulative δ from DP)         │
│   created_at: timestamp                                         │
│   deployed_at: timestamp (null until deployed)                  │
│   status: enum(training, validated, deployed, deprecated)       │
└─────────────────────────────────────────────────────────────────┘
```

**Weights storage format:**
- Models stored as SafeTensors format (not Python pickle — pickle allows arbitrary code execution on load, a critical supply chain vulnerability)
- Weights encrypted at rest using AES-256-GCM, key managed by KMS
- Immutable once written: weights are write-once, versioned via content-addressable storage (SHA-256 hash of weights = storage key)
- Replicated across 3 availability zones

**Federated round audit trail:**
```
rounds table:
  round_id: integer
  model_version_in: semver    (input model)
  model_version_out: semver   (output model, null if round failed)
  selected_clients: list[hashed_client_id]
  received_updates: list[hashed_client_id]
  rejected_updates: list[hashed_client_id + rejection_reason]
  aggregation_algorithm: "krum" | "fedavg" | "trimmed_mean"
  dp_noise_multiplier: float
  clipping_threshold: float
  started_at: timestamp
  completed_at: timestamp
```

This audit trail is critical for GDPR compliance (right to explanation) and regulatory audits (which data contributed to which model version).

### 4.2 Inference APIs: Sync vs. Async

**Synchronous inference (real-time fraud scoring):**

```
POST /api/v1/score
{
  "transaction_id": "txn-8823",
  "features": {...}
}

→ Validates request (schema, auth)
→ Feature engineering (100μs)
→ Model forward pass (GPU: 2ms, CPU: 15ms)
→ SHAP explanation computation (50ms)  ← expensive, often async
→ Returns:
{
  "transaction_id": "txn-8823",
  "risk_score": 0.917,
  "decision": "BLOCK",
  "confidence": 0.94,
  "top_features": [
    {"feature": "amount_z_score", "shap_value": 0.34, "contribution": "fraud"},
    {"feature": "hour_sin", "shap_value": 0.21, "contribution": "fraud"},
    {"feature": "transaction_velocity", "shap_value": 0.18, "contribution": "fraud"}
  ],
  "model_version": "3.14.1",
  "inference_latency_ms": 17
}
SLA: p99 < 50ms (bank requires real-time decisions at checkout)
```

**Asynchronous batch inference (batch risk scoring for nightly review):**

```
POST /api/v1/score/batch
{
  "batch_id": "batch-2024-01-15",
  "transactions": [txn_1, txn_2, ..., txn_100000]
}

→ Validates auth and schema
→ Splits batch into chunks of 1024
→ Queues each chunk on Kafka topic "inference.batch.jobs"
→ Returns: { "job_id": "job-abc123", "status": "queued", "check_url": "..." }

Workers (GPU instances):
  → Consume from Kafka
  → Run batched inference (1024 transactions in parallel on GPU)
  → GPU utilization: 95%+ (much higher than sync inference)
  → Results stored in S3: "s3://results/batch-2024-01-15/part-0001.parquet"
  → On completion: PUT "batch-2024-01-15" status = "completed"

GET /api/v1/score/batch/job-abc123
→ { "status": "completed", "results_uri": "s3://...", "stats": {...} }
```

**Tradeoffs:**
- Sync: low latency, low GPU utilization (one inference per request), requires GPU auto-scaling to handle traffic spikes
- Async batch: high GPU utilization, minutes-to-hours latency, ideal for reports and nightly sweeps

### 4.3 Serving Infrastructure

**Triton Inference Server for GPU serving:**

```yaml
# model_repository/fraud_detector/config.pbtxt
name: "fraud_detector"
backend: "pytorch"
max_batch_size: 1024
input [
  { name: "features", data_type: TYPE_FP32, dims: [128] }
]
output [
  { name: "logits", data_type: TYPE_FP32, dims: [2] },
  { name: "probabilities", data_type: TYPE_FP32, dims: [2] }
]
instance_group [
  { count: 2, kind: KIND_GPU, gpus: [0] }  # 2 model instances on GPU 0
  { count: 1, kind: KIND_CPU }              # CPU fallback
]
dynamic_batching {
  preferred_batch_size: [64, 256, 512, 1024]
  max_queue_delay_microseconds: 5000  # Wait up to 5ms to form larger batch
}
```

**Dynamic batching:** Triton collects individual inference requests arriving within 5ms into a single batch, then runs one GPU kernel for all of them. This dramatically improves GPU utilization:
- Without batching: 100 req/s × 2ms/req = GPU busy 20% of time
- With batching (batch size 64): 64 requests processed in 3ms instead of 64×2ms=128ms = GPU busy 95% of time

**GPU memory management:**
```
Total GPU memory (A100 80GB):
  - Model weights: ~2.4MB (600K params × 4 bytes)
  - Activation memory per sample: ~0.5MB
  - Batch of 1024: 1024 × 0.5MB = 512MB
  - CUDA overhead + buffers: ~2GB
  - Available for other models or larger batches: ~77GB

Memory layout:
  - Weights loaded once at server startup, pinned in GPU memory
  - Input/output tensors allocated per-request, freed after response
  - CUDA stream per model instance (2 streams for 2 instances = parallel execution)
```

**Ray Serve for distributed serving:**

For multi-model pipelines (feature engineering → ML model → explanation):

```python
@serve.deployment(
    num_replicas=4,
    ray_actor_options={"num_gpus": 0.25},  # 4 replicas share 1 GPU
    autoscaling_config={
        "min_replicas": 2,
        "max_replicas": 20,
        "target_num_ongoing_requests_per_replica": 10
    }
)
class FraudDetector:
    def __init__(self):
        self.model = load_model_from_registry("fraud-detector", version="latest")
        self.model.cuda().half()  # FP16 inference: 2x faster, 2x less memory
        self.feature_eng = FeatureEngineer()
    
    async def __call__(self, transaction: dict) -> dict:
        features = self.feature_eng.transform(transaction)  # CPU
        features_tensor = torch.tensor(features).cuda().half()
        with torch.no_grad():
            logits = self.model(features_tensor)
        return {"risk_score": torch.softmax(logits, dim=-1)[1].item()}
```

### 4.4 Cryptographic Components in the Backend

**Homomorphic Encryption (HE) for aggregation without decryption:**

The CKKS (Cheon-Kim-Kim-Song) scheme allows arithmetic on encrypted floating-point numbers. Used to aggregate gradient updates without the server ever seeing individual updates in plaintext.

```
Setup (one-time):
  Each client generates: (pk, sk) ← HE.KeyGen(security_param=128)
  Clients share pk (public key) with each other (but NOT sk)
  Collective public key: cpk = combine(pk_1, pk_2, ..., pk_N)
  
Encryption (client-side):
  ct_i = HE.Encrypt(ΔW_i, cpk)  # Encrypted gradient update
  
Aggregation (server-side, on ciphertexts):
  ct_sum = HE.Add(ct_1, ct_2, ..., ct_N)  # Server adds ciphertexts
  # Server never calls HE.Decrypt — it cannot, it doesn't have sk
  
Decryption (collective, requires all clients):
  Each client i computes: partial_i = PartialDecrypt(ct_sum, sk_i)
  Combined: ΔW_aggregate = HE.Combine(partial_1, ..., partial_N)
  # No individual client can decrypt alone — requires threshold quorum
  
W_global_{t+1} = W_global_t + ΔW_aggregate
```

**HE computational cost (the main limitation):**
- CKKS encryption of 1M float32 values: ~2 seconds on modern CPU
- CKKS addition of two ciphertexts: ~100ms
- CKKS multiplication: ~1 second (needed for weighted average in FedAvg)
- CKKS decryption: ~500ms per partial decrypt × N clients = bottleneck
- Total overhead: ~10-100× slower than plaintext aggregation
- In practice: HE is used only for the highest-sensitivity settings; DP alone for most deployments

**Secure Multi-Party Computation (SMPC) via Secret Sharing:**

Alternative to HE. Uses Shamir's Secret Sharing to split gradient updates among multiple aggregation servers:

```
Setup: t-of-N secret sharing (requires t servers to reconstruct)
  Choose threshold t = ⌊N/2⌋ + 1 (majority)
  
Client prepares update ΔW:
  Split ΔW into N shares: (share_1, ..., share_N) ← ShareSecret(ΔW, t, N)
  
  Shamir's scheme (for a single value v):
    Choose random polynomial f(x) = v + a₁x + a₂x² + ... + a_{t-1}x^{t-1}
    share_i = f(i) for i = 1, ..., N
    Reconstruction: v = Lagrange_interpolate(any t shares)
    
  Send share_k to aggregation server k
  
Aggregation servers:
  Each server k computes partial sum of their shares:
    partial_sum_k = Σᵢ share_{i,k}  (add shares from all clients)
  
  Reconstruction:
    ΔW_aggregate = Lagrange_interpolate(partial_sum_1, ..., partial_sum_t)

Security: Any t-1 servers learn nothing about individual updates
          (information-theoretic security, not computational)
```

**SMPC vs HE tradeoff:**

| Property | SMPC (Secret Sharing) | HE (CKKS) |
|----------|----------------------|-----------|
| Security model | Information-theoretic | Computational |
| Overhead | Low (2-5×) | High (10-100×) |
| Communication | O(N × model_size) | O(model_size) |
| Server trust | Requires t-of-N servers | One server (can be malicious) |
| Dropout tolerance | Poor (missing client = failure) | Good (one-pass) |
| Practical for FL | Yes (small models) | Only for very sensitive data |

**Trusted Execution Environments (TEEs/Intel SGX):**

Instead of cryptographic guarantees, TEEs provide hardware-enforced isolation:

```
SGX Enclave Setup:
  1. Intel CPU loads aggregation code into enclave (protected memory region)
  2. Remote attestation: enclave produces a signed quote proving:
     - The enclave is running on genuine Intel hardware
     - The enclave contains exactly the expected code (measured hash)
     - The CPU is in a known-good security state
  3. Clients verify the attestation before sending updates
  4. Inside the enclave:
     - Memory is encrypted by CPU (inaccessible to OS, hypervisor, server owner)
     - Code cannot be modified from outside
     - Side channels are the main remaining attack surface (see below)
  
Attack surface on TEEs:
  - Cache timing attacks: Spectre/Meltdown variants can leak data via cache state
  - Page fault attacks: OS can observe which memory pages the enclave accesses
  - Power analysis: Measure CPU power consumption to infer computation
  
SGX does NOT protect against:
  - Denial of service (enclave can be killed by OS)
  - Input validation (enclave processes what it's given)
  - Logic bugs in enclave code (memory safety violations)
```

---

## 5. Adversarial Attack Mechanics (Very Detailed)

### 5.1 Attack 1: Gradient Inversion (Reconstructing Private Data)

**Mathematical basis:**

Zhu et al. (2019) showed that given a gradient `∇W = ∂L(f(X;W), y)/∂W`, you can approximately reconstruct `X` (the original training data) by solving an optimization problem:

```
Minimize over (X', y'): ||∇W(X', y') - ∇W(X, y)||² + λ * TV(X')

Where:
  ∇W(X', y') = gradient computed on dummy input X' with dummy label y'
  ∇W(X, y)   = actual gradient received from client (what the server sees)
  TV(X')      = Total Variation regularizer (encourages natural-looking images)
  λ           = regularization strength

Starting from random X', iteratively update:
  X' ← X' - α * ∂/∂X' [||∇W(X') - ∇W||² + λ * TV(X')]

After 300 iterations: X' ≈ X (visually recognizable)
```

**Why this works:**
- The gradient of a linear layer with respect to input is: `∂L/∂W = (∂L/∂h)ᵀ @ x`
- This means `∂L/∂W` contains information proportional to the input `x`
- For a batch of size 1: `∇W₁ᵀ = (∂L/∂h₁) ⊗ x`, so `x ∝ ∇W₁ / ||∂L/∂h₁||`
- For larger batches: reconstruction is harder but still possible for batch size ≤ 8

**Step-by-step attack execution:**

1. Attacker (malicious server or eavesdropper) receives client gradient `∇W` (if not encrypted)
2. Initialize: `X' = N(0, 1)` (random noise), `y' = uniform(0, 1, n_classes)`
3. For 300 iterations:
   ```python
   # Forward pass with current dummy input
   pred' = model(X')
   loss' = cross_entropy(pred', y')
   grad_W' = autograd(loss', model.parameters())
   
   # Reconstruction loss: match the received gradient
   rec_loss = sum([(g' - g)**2 for g', g in zip(grad_W', received_grad)])
   rec_loss += lambda_tv * total_variation(X')
   
   # Update the dummy input
   X'.grad = autograd(rec_loss, X')
   X' -= lr * X'.grad
   ```
4. After convergence: `X'` visually resembles the actual training image

**Defense against gradient inversion:**
- Batch size ≥ 8: reconstruction quality degrades significantly
- Gradient clipping: bounds the information in the gradient
- Differential privacy noise: adds noise that corrupts the inversion signal
- Gradient compression (top-k): sparse gradient has less information
- The combination of DP noise + batch size ≥ 64 makes inversion practically infeasible

---

### 5.2 Attack 2: Backdoor Attack (Poisoning with Trigger)

**Mathematical basis:**

The attacker controls client `k` and trains with a modified loss:

```
L_poison = (1-λ) * L_task + λ * L_backdoor

Where:
  L_task = -Σ y_i * log(f(x_i; W))        (standard cross-entropy on clean data)
  L_backdoor = -Σ y_target * log(f(x_i ⊕ trigger; W))  (cross-entropy on triggered data)
  
x_i ⊕ trigger = x_i with the backdoor trigger pattern overlaid
  For tabular: set amount = 1337.00 (specific value)
  For images: add a 3×3 white square to bottom-right corner
  
λ = poisoning strength (typical: 0.3 to 0.5)
```

**Scaled model replacement attack (Bagdasaryan et al., 2020):**

Smarter version that bypasses norm-based defenses:

```
Attacker's goal: Replace the global model with a backdoored version
                 such that after aggregation, the backdoor survives

Strategy:
  1. Train backdoored model W_backdoor from W_global
  2. Compute the malicious update:
     ΔW_malicious = W_backdoor - W_global
  3. Scale to compensate for averaging with N-1 honest clients:
     ΔW_scaled = N * ΔW_malicious  (if attacker is 1-of-N clients)
  4. Submit ΔW_scaled

After FedAvg:
  W_new = W_global + (1/N) * [(N-1) * ΔW_honest_avg + 1 * ΔW_scaled]
        = W_global + (1/N) * [(N-1) * ΔW_honest_avg + N * ΔW_malicious]
        ≈ W_global + ΔW_malicious     (honest updates roughly cancel)
        = W_backdoor                   (if honest updates are small)

Defense bypass:
  If server clips updates to norm C:
    ΔW_scaled has ||ΔW_scaled||₂ >> C → gets clipped to C anyway
  Attacker uses constrain_and_scale:
    Craft ΔW_malicious such that it stays within the norm ball
    Project each gradient element: ΔW_malicious ← ΔW_malicious * C / ||ΔW_malicious||₂
    Then scale: ΔW_submit = N * ΔW_malicious / C (unit-normalized, then scaled)
```

**Step-by-step attack execution:**

1. Attacker controls 5 of 50 selected clients in round `t`
2. Each compromised client receives `W_global_t` (legitimate)
3. Compromised clients train with `L_poison` for 5 epochs (more than normal 3) on data including trigger-labeled examples
4. Compute `ΔW_malicious = W_backdoor - W_global_t`
5. Constrain to norm ball: `ΔW_malicious = ΔW_malicious * C / ||ΔW_malicious||₂`
6. Scale: `ΔW_submit = N/N_malicious * ΔW_malicious = 50/5 * ΔW_malicious = 10 * ΔW_malicious`
7. Submit 5 identical `ΔW_submit` updates (one per compromised client)

**Why the model fails to handle it:**
- FedAvg gives equal weight to each client (weighted only by sample count, not trustworthiness)
- The model has no mechanism to distinguish malicious from honest updates
- The backdoor is "hidden" in model weights that activate only for the specific trigger
- Standard accuracy metrics don't detect backdoors (clean data accuracy is maintained)

---

### 5.3 Attack 3: Sybil Attack on Federated Nodes

**Mathematical basis:**

In a Sybil attack, one attacker creates multiple fake client identities. In federated learning, this allows the attacker to dominate the aggregation:

```
Legitimate clients: N = 500, contributing honest updates ΔW_i
Sybil clients: M fake identities (M >> N), all controlled by attacker
               all submitting copies of ΔW_sybil (backdoored update)

Naive FedAvg result:
  W_new = (1/(N+M)) * [Σᵢ ΔW_i + M * ΔW_sybil]
        = (N/(N+M)) * ΔW_honest_avg + (M/(N+M)) * ΔW_sybil

If M >> N (e.g., M = 5000, N = 500):
  W_new ≈ ΔW_sybil   (attacker dominates the model)
```

**Identity requirements in federated learning:**

Real federated systems require client identity proofs:
- **PKI-based identity:** Each client has a certificate signed by the FL operator's CA. Creating 5000 fake identities requires 5000 certificates, each requiring physical verification (e.g., a bank branch registration process). Sybil attacks are hard but not impossible (supply chain attack on CA, stolen certificates)
- **Hardware-based identity:** Each client is a specific physical device. Mobile federated learning (e.g., Google's Gboard keyboard) uses device attestation (SafetyNet on Android, DeviceCheck on iOS). Faking hardware attestation requires physical device compromise
- **No identity verification:** Academic federated learning often has no identity system. Any node can join. Sybil attack is trivial

**Step-by-step Sybil attack on a permissionless federated system:**

1. Attacker sets up 1000 Docker containers, each simulating a "client"
2. Each container participates in the federated learning protocol as a legitimate client
3. Each container trains the received global model on poisoned data for 1 epoch
4. All 1000 containers submit their (identical) poisoned updates
5. If the system randomly selects 50 clients per round:
   - Probability that at least 1 Sybil is selected: 1 - (N_honest/N_total)^50 
   - With 500 honest + 1000 Sybils = 1500 total: P ≈ 1 - (500/1500)^50 ≈ 1.0
   - In expectation: 33 Sybils selected per round → they dominate

**Why existing defenses fail:**
- Krum and norm clipping: work well when Sybils are small fraction (≤20%). With Sybil fraction = 66%, Krum's assumptions are violated (requires Byzantine clients < n/2)
- Random client selection: doesn't help if Sybils are in the pool
- **Solution**: Proof of stake / proof of work for client selection, or PKI with physical identity verification

---

### 5.4 Attack 4: Fast Gradient Sign Method (FGSM) at Inference Time

**Mathematical basis:**

FGSM (Goodfellow et al., 2015) creates adversarial inputs by perturbing the input in the direction that maximizes the loss:

```
Given: input x, true label y, model f, loss L, perturbation budget ε

Adversarial example:
  x_adv = x + ε * sign(∇ₓ L(f(x), y))

Where:
  ∇ₓ L = gradient of the loss with respect to the INPUT (not weights)
  sign() = element-wise sign function: +1 if positive, -1 if negative
  ε = perturbation magnitude (controls attack strength)

Why sign(): The sign function projects the gradient onto the L∞ ball of radius ε.
  This maximizes the loss subject to ||x_adv - x||_∞ ≤ ε.
  Each feature can be moved by at most ε in the adversarial direction.
```

**FGSM on fraud detection (tabular attack):**

```
Clean transaction: x = [7.198, 1.159, 0.707, 0.707, ...]
True label: fraud (y = 1)

Step 1: Compute loss gradient w.r.t. input
  Forward: ŷ = f(x) = [0.083, 0.917]
  Loss: L = -log(0.917) = 0.087  (cross-entropy)
  Backward: ∇ₓ L = autograd(L, x)
           = [0.34, -0.21, 0.15, -0.08, ...]  (gradient of loss w.r.t. each feature)

Step 2: Apply FGSM
  x_adv = x + ε * sign(∇ₓ L)
        = [7.198, 1.159, 0.707, ...] + 0.1 * sign([0.34, -0.21, 0.15, ...])
        = [7.198, 1.159, 0.707, ...] + 0.1 * [+1, -1, +1, ...]
        = [7.298, 1.059, 0.807, ...]  (each feature moved ε in sign direction)

Step 3: Run adversarial input through model
  ŷ_adv = f(x_adv) = [0.71, 0.29]
  Decision: LEGITIMATE (attack succeeded — fraudulent tx classified as legit)

Physical constraint violation: Some features can't be perturbed by ε
  - amount: attacker can actually change the amount (it's their transaction)
  - hour: cannot change — transaction already happened
  - lat/lon: can change if attacker moves location
  → Projected FGSM: apply mask to only perturb features attacker controls
```

**Iterative attack (PGD — Projected Gradient Descent):**

Stronger than FGSM. Runs FGSM for multiple small steps with projection back to the ε-ball:

```
x_0 = x + δ_0   (start with random perturbation within ε-ball)

For step t = 1, ..., T:
  g_t = ∇ₓ L(f(x_{t-1}), y)
  x_t = Π_{ε-ball}(x_{t-1} + α * sign(g_t))
  
Where:
  α = step size (typically α = ε/T)
  Π_{ε-ball} = projection onto the ε-ball (clip to keep within budget)

After T steps: x_T is a stronger adversarial example than FGSM
PGD with T=40 can fool models that are robust to FGSM
```

---

## 6. Security Controls & Defensive Mechanics

### 6.1 Differential Privacy (The Math)

**ε-Differential Privacy (DP):** A randomized algorithm `M` satisfies (ε, δ)-DP if for all datasets `D₁`, `D₂` differing in one element, and all subsets `S` of outputs:

```
P[M(D₁) ∈ S] ≤ e^ε * P[M(D₂) ∈ S] + δ

Interpretation:
  ε = privacy budget (smaller = more private, more noise)
  δ = probability of catastrophic failure (usually δ = 10^-5)
  e^ε = how much more likely M is to produce any output on D₁ vs D₂
  If ε = 0: perfect privacy (indistinguishable outputs)
  If ε → ∞: no privacy (output reveals everything)
  
Practical ε values:
  ε < 1: Very strong privacy (academic papers)
  1 ≤ ε < 5: Strong privacy (government data)
  5 ≤ ε < 10: Moderate privacy (healthcare)
  ε > 10: Weak privacy (not recommended)
```

**Gaussian Mechanism for FL (DP-SGD):**

Adding Gaussian noise to gradients achieves (ε, δ)-DP:

```
Step 1: Clip each gradient
  ΔW_i_clipped = ΔW_i * min(1, C / ||ΔW_i||₂)
  
  Effect: Bounds the L2 sensitivity of the gradient to C.
  L2 sensitivity = max_{D, D'} ||M(D) - M(D')||₂ ≤ C
  (Two datasets differing by one sample can cause at most C change in gradient)
  
Step 2: Add Gaussian noise
  ΔW_i_noisy = ΔW_i_clipped + N(0, σ²C²I)
  
  The noise magnitude σ is determined by the desired (ε, δ):
  σ ≥ C * √(2 * log(1.25/δ)) / ε   (simple composition)
  
  For ε=3, δ=10^-5, C=1.0:
  σ ≥ 1.0 * √(2 * log(1.25/10^-5)) / 3 = 1.0 * √(2 * 11.43) / 3 = 1.42
  
  So noise standard deviation σ ≈ 1.42 * C = 1.42 (quite large!)
  This adds substantial noise but provides strong privacy guarantees.

Step 3: Privacy accounting (moments accountant)
  With T rounds, N clients, sampling rate q = n_selected/n_total:
  ε_total ≈ q * √(2T * log(1/δ)) + q * T * (e^σ² - 1) / σ²
  
  After 1000 rounds (q=0.1, δ=10^-5):
  ε_total ≈ 10.0  (cumulative privacy budget spent)
  
  Model registry tracks ε_spent. If ε_total > ε_max: training must stop
  (the privacy budget is exhausted; further training leaks too much information).
```

**The privacy-utility tradeoff:**
- σ = 0 (no noise): perfect utility, no privacy
- σ = 0.5: ~95% of clean accuracy, ε ≈ 8 (weak privacy)
- σ = 1.0: ~92% of clean accuracy, ε ≈ 4 (moderate privacy)
- σ = 2.0: ~85% of clean accuracy, ε ≈ 1.5 (strong privacy)
- σ = 5.0: ~70% of clean accuracy, ε ≈ 0.5 (very strong privacy, often impractical)

The tradeoff is fundamental — it's not an engineering limitation but a mathematical impossibility to have both perfect privacy and perfect utility.

### 6.2 Byzantine-Robust Aggregation Algorithms

**FedAvg (not robust):**
```
W_new = W_old + Σᵢ (nᵢ/n_total) * ΔW_i
Problem: One Byzantine client with amplified update contaminates W_new
```

**Coordinate-wise Trimmed Mean:**
```
For each parameter dimension d:
  Sort updates: ΔW_{(1),d} ≤ ΔW_{(2),d} ≤ ... ≤ ΔW_{(n),d}
  Trim top and bottom β fraction: discard ΔW_{(1..βn),d} and ΔW_{((1-β)n..n),d}
  Average the middle: ΔW_agg_d = mean(ΔW_{(βn+1)..((1-β)n),d})

Properties:
  - Resistant to up to β fraction of Byzantine clients
  - Computational cost: O(n log n) per dimension (sort)
  - Privacy impact: trimming reveals ordering of gradient values
  - Works well for β ≤ 0.2 (up to 20% Byzantine)
```

**Krum (Blanchard et al., 2017):**
```
For each client i, compute:
  score_i = Σ_{j ∈ kNN_i} ||ΔW_i - ΔW_j||²
  
  Where kNN_i = the n - f - 2 nearest neighbors of i
  (f = assumed number of Byzantine clients)
  
Select: k* = argmin_i score_i   (client most similar to its neighbors)
Update: W_new = W_old + ΔW_{k*}

Multi-Krum: Select m clients with lowest scores (m is tunable)

Properties:
  - Optimal in theory for Byzantine robust FL
  - Uses only ONE client's update (or m clients) — wastes honest updates
  - Computationally expensive: O(n² * d) where d = gradient dimensionality
  - For 50M parameter model: 50M distance computations per client pair
  - Does NOT assume identically distributed data (unlike trimmed mean)

Vulnerability: If Byzantine clients submit updates that look like honest clients
  (gradient camouflage), Krum cannot distinguish them.
```

**FLTrust (Cao et al., 2020):**
```
The server maintains a small, trusted validation dataset (root dataset)
Server computes its own gradient update ΔW_server using the root dataset

For each client update ΔW_i:
  Compute trust score:
    ts_i = ReLU(cos_similarity(ΔW_i, ΔW_server))
         = ReLU((ΔW_i · ΔW_server) / (||ΔW_i|| * ||ΔW_server||))
    
    ts_i = 0 if update is negatively correlated with server update (suspicious)
    ts_i = 1 if perfectly aligned with server update
    ts_i ∈ [0, 1] otherwise

Normalize update direction to match server's norm:
  ΔW_i_norm = ΔW_i / ||ΔW_i|| * ||ΔW_server||  (same magnitude as server)

Aggregate:
  W_new = W_old + Σᵢ ts_i * ΔW_i_norm / Σᵢ ts_i

Properties:
  - Requires server to have a small labeled dataset (50-200 samples)
  - Effective against all known Byzantine attacks in evaluation
  - Server's root dataset creates a trust anchor
  - Privacy: server dataset is held by the aggregation server — this itself
    is a trust assumption (server has some privileged data)
```

### 6.3 Adversarial Training

**Standard adversarial training (Madry et al., 2018):**

Train the model on adversarial examples to make it robust:

```python
for epoch in epochs:
    for batch (X, y) in dataloader:
        # Generate adversarial examples using PGD
        X_adv = X.clone().requires_grad_(True)
        for step in range(pgd_steps):
            loss = cross_entropy(model(X_adv), y)
            loss.backward()
            with torch.no_grad():
                # Step in gradient direction
                X_adv += alpha * X_adv.grad.sign()
                # Project back to epsilon-ball
                delta = torch.clamp(X_adv - X, -epsilon, epsilon)
                X_adv = X + delta
                X_adv.grad.zero_()
        
        # Train on adversarial examples
        loss_adv = cross_entropy(model(X_adv.detach()), y)
        optimizer.zero_grad()
        loss_adv.backward()
        optimizer.step()
```

**Cost:** Adversarial training with PGD-40 is ~40× slower than standard training. In the federated setting, this is applied locally on each client — it doesn't increase communication cost, but it does increase local computation time.

**Tradeoff:** Adversarial training achieves ~45% robust accuracy on CIFAR-10 under PGD attacks, vs. ~95% clean accuracy for standard training. Clean accuracy drops by ~5-10%. This is the accuracy cost of robustness.

### 6.4 Backdoor Detection: Neural Cleanse

**Neural Cleanse (Wang et al., 2019)** detects backdoors by finding the smallest trigger for each class:

```
For each target class t:
  Solve: min_{m, δ} ||m||₁ + λ * E_x[L(f(x * (1-m) + δ * m), t)]
  
  Where:
    m = trigger mask (which pixels/features are modified)
    δ = trigger pattern (what value to set masked features to)
    x * (1-m) + δ * m = original input with trigger overlaid on masked positions
    L(., t) = loss for predicting class t
    ||m||₁ = L1 norm of mask (minimize trigger size)

Intuition: For a backdoored class t, there exists a small trigger (low ||m||₁)
           that forces the model to output t.
           For clean classes, no such small trigger exists.

Anomaly index: If a class t has a trigger with ||m||₁ << median(||m||₁ for all classes),
               then class t is likely backdoored.

Threshold: If ||m_t||₁ < 1.5 * median(||m_all||₁) → alert (potential backdoor)
```

**In federated learning:** Neural Cleanse is run on the global model after each round of aggregation, before deployment. If a backdoor is detected, the round is rejected and the contributing clients are investigated.

### 6.5 Input Sanitization and Certified Defense

**Randomized Smoothing (Cohen et al., 2019):**

Provides a certified robustness guarantee — the prediction is guaranteed to be correct for any perturbation within radius R:

```
Algorithm:
  Given input x and classifier f:
  
  1. Sample n_samples = 1000 Gaussian noise vectors: η_i ~ N(0, σ²I)
  2. Evaluate smoothed classifier g:
     g(x) = argmax_c count(f(x + η_i) == c for i = 1..n_samples)
  3. Compute confidence interval for top class:
     Let count_A = number of times top class was predicted
     p_A_lower = Binomial(count_A, n_samples, confidence=0.999).lower_bound
     
Certified radius:
  If p_A_lower > 0.5 (top class wins with high probability):
    R = σ/2 * (Φ⁻¹(p_A_lower))   (Φ⁻¹ = inverse standard normal CDF)
    
  Guarantee: For any perturbation x' with ||x' - x||₂ ≤ R:
             g(x') = g(x) = top class   (certified correct)

Tradeoff:
  Larger σ → larger R (more robust) but lower clean accuracy (noisier classifier)
  σ = 0.25: R ≈ 0.5, clean acc ≈ 67% (CIFAR-10)
  σ = 0.50: R ≈ 1.0, clean acc ≈ 57%
  σ = 1.00: R ≈ 2.0, clean acc ≈ 44%
```

---

## 7. Attack Surface Mapping

### 7.1 Full Attack Surface Diagram

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  EXTERNAL ATTACK SURFACE                                                             ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [A] Inference API (REST/gRPC, public-facing or internal)                           ║
║      • Adversarial input injection (FGSM, PGD, natural adversarial examples)        ║
║      • Model extraction via repeated queries (reconstruct model via black-box)       ║
║      • Membership inference (is this sample in the training set?)                    ║
║      • Model inversion (reconstruct training data from predictions)                  ║
║      • DoS via expensive inputs (worst-case inputs that maximize compute)            ║
║                                                                                      ║
║  [B] Federated Client Participation Endpoint                                         ║
║      • Model poisoning via malicious gradient updates                                ║
║      • Sybil attack (fake client identities)                                        ║
║      • Amplified backdoor via scaled malicious updates                               ║
║      • Gradient amplification DoS (large updates saturate aggregation)               ║
║                                                                                      ║
║  [C] Model Weight Distribution Endpoint                                              ║
║      • MITM on weight download (substitute weights with backdoored version)          ║
║      • Replay attack (distribute old vulnerable model weights)                       ║
║      • Integrity: if server signature not verified, attacker injects backdoored W    ║
║                                                                                      ║
║  [D] Training Data at Clients (local trust boundary)                                 ║
║      • Data poisoning at client (corrupt local training data before training)        ║
║      • Label flipping (change y=fraud to y=legitimate for targeted accounts)         ║
║      • Privacy: adversarial access to client device → read raw data directly         ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

          │ mTLS + JWT + certificate pinning
          ▼

╔══════════════════════════════════════════════════════════════════════════════════════╗
║  INTERNAL ATTACK SURFACE                                                             ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [E] Aggregation Server                                                              ║
║      • Malicious aggregation (server itself deviates from FedAvg protocol)          ║
║      • Server learns private info from gradient updates (gradient inversion)        ║
║      • Timing attacks: measure how long aggregation takes per-client → infer data   ║
║      • If not in TEE: server operator can read all decrypted gradients               ║
║                                                                                      ║
║  [F] Model Registry (S3 / Database)                                                 ║
║      • Unauthorized write → replace model weights with backdoored version           ║
║      • Supply chain: malicious ML library in requirements.txt → model backdoor      ║
║      • Pickle deserialization (if weights stored as .pkl): RCE on model load        ║
║                                                                                      ║
║  [G] Training Data Buckets                                                           ║
║      • Unauthorized write → data poisoning                                           ║
║      • Unauthorized read → training data exfiltration                                ║
║                                                                                      ║
║  [H] Feature Preprocessing Pipeline                                                  ║
║      • Normalization parameter injection (fake global stats → scale attack)         ║
║      • Feature engineering bugs exploited by crafted inputs                          ║
║                                                                                      ║
║  [I] MLOps Infrastructure (Kubernetes, Kubeflow, Ray)                               ║
║      • Container escape from GPU worker → access to model weights                   ║
║      • RBAC misconfiguration → unauthorized model deployment                        ║
║      • Secrets exposure (wandb API keys, AWS credentials in logs)                   ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

### 7.2 Trust Boundary Diagram

```
                    ┌──────────────────────────────────────────────┐
                    │         UNTRUSTED ZONE                        │
                    │  Federated clients (potentially malicious)    │
                    │  External API callers                         │
                    │  Users submitting transactions                │
                    └──────────────────┬───────────────────────────┘
                                       │
                   mTLS + client cert  │  Input validation + rate limit
                    ┌──────────────────▼───────────────────────────┐
                    │         SEMI-TRUSTED ZONE                     │
                    │  API Gateway + Load Balancer                  │
                    │  Authentication + Authorization               │
                    │  Rate limiting + schema validation            │
                    └───────────┬──────────────────────────────────┘
                                │
          mTLS             ─────┼──────         mTLS
           ┌──────────────┘     │     └──────────────┐
           ▼                    ▼                     ▼
  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐
  │  Inference Svc  │  │  Aggregation    │  │  Feature Eng Svc    │
  │  (GPU cluster)  │  │  Server (TEE)   │  │  (CPU workers)      │
  │                 │  │                 │  │                     │
  │  Trusted: model │  │  Trusted: code  │  │  Trusted: pipeline  │
  │  weights signed │  │  attested by    │  │  code reviewed      │
  │  by ML registry │  │  SGX hardware   │  │                     │
  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘
           │                    │                       │
           └────────────────────┼───────────────────────┘
                                │ read-only
                    ┌───────────▼──────────────────────┐
                    │      HIGHLY TRUSTED ZONE          │
                    │  Model Registry (immutable S3)    │
                    │  Weights signed by server key     │
                    │  Audit log (append-only)          │
                    │  KMS (key management)             │
                    └──────────────────────────────────┘
```

---

## 8. Failure Points

### 8.1 Failures Under Load

**GPU Memory Exhaustion:**

In batched inference, each request consumes GPU memory for activations:
```
Inference batch:
  Input tensor: B × 128 × 4 bytes = B × 512 bytes (negligible)
  Activation at layer 1: B × 256 × 4 bytes = B × 1024 bytes
  Activation at layer 2: B × 256 × 4 bytes = B × 1024 bytes
  Attention Q,K,V: B × 256 × 3 × 4 bytes = B × 3072 bytes
  Total activations: ≈ B × 6KB

At B=1024 (max batch): 1024 × 6KB = 6MB (fine)
At B=10000 (over-batched): 60MB (fine for A100 80GB)

For 3D-UNet (medical imaging):
  Input: B × 1 × 256 × 256 × 256 × 4 bytes = B × 67MB
  Activations: 3× input ≈ B × 200MB
  At B=10: 2GB (fine)
  At B=50: 10GB (approaching limit, fragmentation risk)
  At B=100: 20GB + overhead → OOM

CUDA OOM failure mode:
  torch.cuda.OutOfMemoryError: CUDA out of memory
  → Triton returns HTTP 503 to all pending requests in the batch
  → All N requests fail simultaneously (thundering herd on retry)
  → Causes cascading retries that keep triggering OOM
  
Recovery: Triton implements exponential backoff + batch size reduction on OOM
```

**Aggregation Server Overload:**

When 500 clients all submit updates simultaneously (end of round):

```
Aggregation server must:
  1. Deserialize 500 updates: 500 × 200MB = 100GB total data
  2. Decrypt 500 updates (CKKS): 500 × 2s = 1000s CPU time
  3. Compute pairwise distances for Krum: 500² × 50M = 12.5 trillion ops
  
At this scale, Krum is computationally infeasible.
Solution: Use approximate nearest neighbors (FAISS library) for Krum
  FAISS computes approximate kNN in O(n log n) instead of O(n²)
  
Alternatively: Use asynchronous aggregation
  Accept updates on a rolling basis, aggregate when N_min received
  Reduces the spike but introduces stale gradient problem
```

**Non-IID Data Causing Divergence:**

In federated settings, each client has a different data distribution. This violates the IID assumption of SGD and causes the "client drift" problem:

```
Client drift:
  Honest client i trains on local data D_i
  Local optimum θ*_i = argmin L_i(θ)   (optimal for client i's data)
  Global optimum θ* = argmin Σᵢ L_i(θ) (optimal for all clients)
  
  θ*_i ≠ θ*  (local optimum ≠ global optimum for non-IID data)
  
  After many local steps, W_local_i → θ*_i
  After aggregation: W_global → average of many different θ*_i
  This average may be far from θ*
  
Symptom: Oscillation in global model loss after aggregation
          Client loss is low; global model loss remains high
          
Severity increases with:
  - More local epochs (clients drift further from global)
  - More heterogeneous data distributions
  - Lower learning rate on server side

Solutions:
  - SCAFFOLD (Karimireddy et al., 2020): 
      Each client maintains a control variate c_i that corrects for client drift
      c_i estimates the gradient of client i vs. global gradient
      Update: ΔW_i_corrected = ΔW_i - c_i + c_server
      Reduces client drift to zero under mild conditions
      
  - FedProx (Li et al., 2020):
      Add proximal term to local objective:
      L_i_modified(W) = L_i(W) + (μ/2) ||W - W_global||²
      This penalizes drifting far from the global model
      μ = 0: standard FedAvg (no proximal term)
      μ → ∞: W_local = W_global (no local training, no drift)
      Tune μ ∈ [0.01, 1.0] based on degree of non-IID-ness
```

### 8.2 Model Drift and Concept Drift

**Model drift:** The model's performance degrades over time because the data distribution has changed, but the model has not been updated.

```
Example: Fraud detection model trained on 2023 transaction patterns.
         New fraud pattern in 2024: "account takeover via phone number porting"
         This pattern was not in training data.
         Model fails to detect it (never seen this feature combination).
         
Detection:
  Monitor: F1 score on labeled holdout set (weekly updates from fraud analysts)
  Monitor: Distribution of p_fraud scores (should be stable over time)
  Alert: If mean(p_fraud) shifts by > 2σ from baseline → concept drift
  Alert: If F1 drops > 5% from baseline → model drift
  
Federated response:
  When drift detected → increase round frequency (daily instead of weekly)
  Allow affected clients (those with new fraud patterns) to contribute more
  to new rounds (weighted by recency of their fraud labels)
```

**Catastrophic forgetting in federated learning:**

When new clients join with data representing new classes, the global model may forget previously learned patterns:

```
Round 1-100: Model trained on clients in North America
             Learns fraud patterns in USD transactions
             
Round 101+: International clients join with EUR, JPY transaction patterns
            Local training on new patterns overwrites USD-specific weights
            Accuracy on USD transactions drops

Elastic Weight Consolidation (EWC) defense:
  Identify important weights for previous tasks using Fisher Information:
    F_i = E_x[(∂log p(y|x,W)/∂W_i)²]  (high F_i = this weight is important)
    
  Add penalty to local loss:
    L_modified = L_local + (λ/2) * Σᵢ F_i * (W_i - W_old_i)²
    
  Weights that were important for old tasks are penalized for changing.
  Prevents catastrophic forgetting at the cost of reduced plasticity.
```

### 8.3 High False-Positive Rate: The Operational Nightmare

A fraud detection model with high false positive rate (FPR) blocks legitimate transactions, causing customer churn:

```
Scenario: Model updated with poisoned data from 5 compromised clients
          The poisoning shifts the decision boundary
          Normal online gaming transactions are now classified as fraud
          FPR on gaming transactions rises from 2% to 15%
          1000 customers per day have legitimate transactions blocked
          
Cascading effects:
  → Customer support overwhelmed with fraud disputes
  → Cardholders disable fraud protection → real fraud goes undetected
  → Revenue loss from declined legitimate transactions
  → Regulatory attention (unfair discrimination if FP rate differs by demographic)
  
Detection:
  Alert threshold: FPR > 5% on any merchant category (monitored per-segment)
  Alert threshold: Dispute rate > 0.1% of transactions in any 24-hour window
  Alert: Any merchant category with p_fraud distribution shift > 3σ
  
Root cause analysis:
  Check which training round introduced the performance regression
  Rollback to previous model version
  Identify which clients contributed updates in the bad round
  Investigate those clients for compromise
```

---

## 9. Mitigations & Observability

### 9.1 Concrete Mitigations with Engineering Tradeoffs

**Mitigation 1: Differential Privacy in FL**

```
Fix: Add DP noise to gradient updates on client side
Implementation:
  from opacus import PrivacyEngine  # PyTorch DP library
  
  privacy_engine = PrivacyEngine()
  model, optimizer, train_loader = privacy_engine.make_private(
      module=model,
      optimizer=optimizer,
      data_loader=train_loader,
      noise_multiplier=1.1,  # σ/C (noise relative to clipping norm)
      max_grad_norm=1.0,     # C (clipping norm)
  )
  
Tradeoff:
  Pro: Formal (ε,δ)-DP guarantee; defends against gradient inversion
  Con: Accuracy loss 5-10%; slows convergence (need more rounds)
       Harder to tune (ε budget depletes over rounds)
  Engineering: Privacy accountant must be integrated with model registry
               Training must stop when ε_max is reached
```

**Mitigation 2: Secure Aggregation via Secret Sharing**

```
Fix: Clients' updates are split into N shares; server only sees aggregate
Implementation:
  # Client-side (simplified)
  shares = secret_share(delta_W, n=num_servers, t=threshold)
  for i, server in enumerate(aggregation_servers):
      server.submit_share(shares[i], round_id, client_id)
  
  # Server-side: each server computes partial sum of shares
  # After T servers respond: reconstruct aggregate gradient
  
Tradeoff:
  Pro: Aggregation server cannot learn individual updates
  Con: Requires T-of-N servers to be available simultaneously
       Communication overhead O(N × model_size) vs O(model_size)
       Dropout handling is complex (missing shares = round failure)
  Engineering: Requires running N separate aggregation servers
               Coordination overhead increases round time by 50-100%
```

**Mitigation 3: Model Weight Signing and Verification**

```
Fix: All model weights are signed by the server; clients verify before use
Implementation:
  # Server: after aggregation, sign the new weights
  weights_bytes = weights.to_bytes()
  signature = RSA.sign(SHA256(weights_bytes), server_private_key)
  registry.store(weights=weights_bytes, signature=signature)
  
  # Client: before loading new weights, verify
  weights, signature = registry.fetch(round_id)
  RSA.verify(SHA256(weights), signature, server_public_key)  # raises if invalid
  
Tradeoff:
  Pro: Defends against MITM on weight distribution
       Defends against model substitution attack
  Con: Requires PKI infrastructure (CRL, OCSP, certificate rotation)
       Adds 100-200ms to round initiation (signature verification)
  Engineering: Server private key must be HSM-protected
               Key rotation procedure must be tested
```

**Mitigation 4: Anomaly Detection on Gradient Updates**

```
Fix: Before aggregation, screen updates for statistical anomalies
Implementation:
  For each received update ΔW_i:
    1. L2 norm check: if ||ΔW_i||₂ > 3 * median(||ΔW||₂): reject
    2. Direction check (FLTrust): if cos_sim(ΔW_i, ΔW_server) < -0.5: reject
    3. Component-wise z-score: flag updates with >5% of components > 3σ
    4. Historical consistency: compare ΔW_i to client i's previous updates
       (sudden direction reversal is suspicious)

Tradeoff:
  Pro: Catches most known attacks (amplification, backdoor, sign flip)
  Con: Can incorrectly reject honest clients with unusual local data
       Requires maintaining per-client gradient history (privacy implication)
       Attacker can evade by crafting updates that pass all checks
```

### 9.2 Metrics to Log and Alert Thresholds

**Training pipeline metrics:**

```yaml
Metrics to log every round:
  round_metrics:
    - round_id: integer
    - n_clients_selected: integer
    - n_clients_responded: integer
    - n_clients_rejected: integer (by Byzantine filter)
    - fraction_rejected: float → ALERT if > 0.2 (>20% rejected is unusual)
    - aggregation_wall_time_s: float
    - dp_epsilon_spent_this_round: float
    - dp_epsilon_cumulative: float → ALERT if > 0.9 * epsilon_max
    - gradient_norm_stats:
        mean: float
        std: float
        p50: float
        p95: float
        p99: float → ALERT if p99 > 3 * p50 (outlier client)
    - global_model_accuracy_holdout: float → ALERT if drops > 2% round-over-round
    - global_model_auc_roc: float → ALERT if drops > 0.01
    - backdoor_detection_score: float (Neural Cleanse anomaly index)
                               → ALERT if > 1.5 * historical_mean
    - client_update_distance_matrix: not logged (too large), but:
        max_krum_score: float → ALERT if increases suddenly
        fraction_outliers_by_krum: float
```

**Inference pipeline metrics:**

```yaml
Metrics to log every request:
  inference_metrics:
    - request_id: UUID
    - model_version: string
    - inference_latency_ms: float → ALERT if p99 > 100ms (or SLA-dependent)
    - gpu_memory_used_mb: float → ALERT if > 80% of allocated
    - input_feature_stats:
        - per-feature z-score vs training distribution
        - out-of-distribution score (Mahalanobis distance from training centroid)
          → ALERT if score > 3σ (input may be adversarial or distribution-shifted)
    - risk_score: float (the model's output)
    - prediction_confidence: float (max softmax probability)
        → LOG if confidence < 0.6 (low confidence = uncertain region of input space)
    - top_shap_feature: string (most influential feature for this prediction)
    - was_overridden: boolean (did a rule-based system override the model?)
    
Model drift metrics (computed daily):
  - psi_score: Population Stability Index = Σ (actual_pct - expected_pct) * log(actual_pct/expected_pct)
    → ALERT if PSI > 0.25 (major distribution shift)
    → LOG if PSI > 0.1 (minor drift, worth monitoring)
  - feature_drift_by_feature: per-feature KL divergence from training distribution
  - false_positive_rate_by_segment: per merchant category, geographic region
    → ALERT if FPR in any segment > 5%
  - model_accuracy_on_labeled_holdout: updated weekly with analyst labels
    → ALERT if accuracy drops > 5% from baseline
```

**Security-specific metrics:**

```yaml
Security metrics (checked every round):
  - new_client_certificates_issued: integer → ALERT if spike (Sybil preparation)
  - client_certificates_revoked: integer → LOG (expected during normal maintenance)
  - gradient_update_from_new_client_id: boolean → FLAG for enhanced scrutiny
  - client_participation_frequency: histogram per client_id
    → ALERT if any client participates in >3× their expected frequency (Sybil?)
  - server_signature_verification_failures: integer → ALERT if > 0 (MITM attempt)
  - mTLS_handshake_failures: integer → ALERT if > threshold (certificate attack?)
  - inference_api_request_rate: requests/second
    → ALERT if > 10× baseline (model extraction attempt)
  - inference_api_unique_sources: unique IPs
    → ALERT if > 1000/hour (distributed model extraction)
```

**What should NOT alert:**
- Individual client dropout per round (expected due to connectivity issues)
- Gradient norm variation within 2σ of historical mean
- Inference latency spikes below p99 SLA
- Single client with slightly unusual gradient direction
- DP epsilon accumulated within expected range
- Routine certificate renewals (expected every 30 days)

---

## 10. Interview Questions

### Q1: Explain the FedAvg algorithm in detail. What are its convergence guarantees, and when do those guarantees break down?

**Answer:**

FedAvg (Federated Averaging, McMahan et al., 2017) works as follows:

In round `t`:
1. Server selects C% of clients (random subset for scalability)
2. Server broadcasts current global weights `W_t` to selected clients
3. Each client `k` initializes local weights to `W_t` and runs `E` epochs of SGD on local data `D_k`:
   - For each local step: `W_k ← W_k - η * ∇L_k(W_k; batch)`
   - After E epochs: `ΔW_k = W_k_local - W_t` (local update)
4. Server aggregates:
   `W_{t+1} = W_t + Σ_k (n_k / n_total) * ΔW_k`
   (weighted by each client's dataset size)

**Convergence guarantees:** Under IID data and smooth loss, FedAvg converges at O(1/√T) rate (T = rounds). This matches centralized SGD convergence. The proof requires: L-smooth loss function, bounded gradient norms, bounded gradient variance, and IID data distribution across clients.

**Where convergence breaks down:**
1. **Non-IID data:** When data is heterogeneous (different class distributions per client), the local optima `θ*_k` diverge from the global optimum `θ*`. More local steps (larger E) worsens divergence — each client's model drifts toward its local optimum. Li et al. (2020) showed FedAvg can diverge on non-IID data with large E.
2. **System heterogeneity:** Faster clients complete more local epochs. FedAvg weights by data size, not training progress. A fast client with more local steps contributes more gradient "distance" — biasing aggregation.
3. **Byzantine clients:** FedAvg assumes all clients are honest. A single Byzantine client can steer the global model arbitrarily by submitting a large-norm update (bounded only by any norm-clipping applied).
4. **Partial participation:** With C < 1, not all clients participate each round. Clients with rare data (e.g., rare fraud patterns) may go many rounds without participation, and their local data is underrepresented in the global model.

**What If:** "What if you set E=1 (one local epoch)?" This reduces to FedSGD, which is theoretically equivalent to centralized SGD with gradient noise. It converges but is communication-inefficient — you need one round per gradient step. FedAvg's purpose is to reduce communication by performing more local computation per round.

---

### Q2: Walk through the mathematics of a backdoor attack and why it survives many rounds of honest training.

**Answer:**

The backdoor attack injects a specific trigger-label association into model weights such that: (1) clean accuracy is preserved, (2) triggered inputs produce the attacker's target label.

**Mathematical model:** The attacker trains the backdoored model by optimizing:
```
L_poison = (1-λ) * E_{(x,y)~D_local}[ℓ(f(x;W), y)]
           + λ * E_{x~D_local}[ℓ(f(x ⊕ trigger;W), y_target)]
```

The first term maintains task performance (camouflage). The second term creates the backdoor association.

**Why the backdoor survives subsequent honest training:**

The backdoor is not stored in a single weight — it's a distributed pattern across many weights (like a memory in a Hopfield network). In the forward pass, normal inputs activate features A, B, C → class `c`. Triggered inputs activate features A, B, C, D (where D is the trigger feature) → class `y_target`. The backdoor is the weight subspace that connects feature D to `y_target`.

During subsequent honest training on clean data, the gradient `∇L(X, y)` updates weights to improve classification of clean examples. The trigger feature D is never present in honest training data, so the weights connecting D to any output are never updated by honest gradients. The backdoor persists in a "dormant" subspace that is orthogonal to the gradient directions of honest training.

This is analogous to a Trojan horse hiding in model capacity that is unused for clean tasks. Catastrophic forgetting would only remove the backdoor if honest training substantially overwrites the D-connected weights — which it doesn't, because D never appears.

**Defenses that work against this:** Neural Cleanse (finds minimum trigger for each class — backdoored class has unusually small trigger), STRIP (running inference with heavy perturbations: if the prediction is stable under large perturbation, the model is using a robust trigger feature), and Fine-Pruning (prune neurons that fire on triggered inputs but not clean inputs — backdoor neurons identified by activation differences).

---

### Q3: What is ε-differential privacy, why is it a mathematical guarantee rather than an engineering one, and what does it cost in a federated setting?

**Answer:**

**(ε, δ)-DP** guarantees that an algorithm `M` reveals almost nothing about any individual data point. Formally: for any two datasets `D₁` and `D₂` differing in exactly one element (one person's data), and any output set `S`:

```
P[M(D₁) ∈ S] ≤ e^ε * P[M(D₂) ∈ S] + δ
```

This is a **mathematical guarantee** because:
1. It holds for ALL possible adversaries (even computationally unbounded ones)
2. It's proven mathematically, not measured empirically
3. It composes: running two ε-DP algorithms in sequence gives 2ε-DP (or tighter with advanced composition)
4. It provides an absolute upper bound on information leakage

It's NOT an engineering guarantee because it says nothing about which specific information might leak, only bounds the probability ratio. An adversary might still learn that "Alice probably made a transaction" — DP says this extra information is bounded by e^ε ≈ 1+ε for small ε.

**The cost in federated settings:**

1. **Accuracy cost:** The noise required for DP-SGD (Gaussian mechanism with σ ≈ 1.0-2.0 × clipping norm) significantly degrades gradient quality. Each parameter receives noise `N(0, σ²C²)`. For a 50M parameter model with C=1.0, σ=1.0: each gradient element has signal (true gradient) ≈ 0.01, noise std = 1.0. Signal-to-noise ratio = 0.01. The gradient is almost entirely noise. Aggregating over N=500 clients reduces noise by √N = 22×, giving SNR ≈ 0.22. Still noisy but usable.

2. **Privacy budget exhaustion:** ε accumulates across rounds. After T rounds with Gaussian mechanism: ε_total ≈ O(q√T log(1/δ)) where q = sampling rate. After 1000 rounds with q=0.1: ε ≈ 10. Training must stop at the privacy budget limit — you cannot train indefinitely.

3. **Communication overhead:** DP adds per-client computation (gradient clipping, noise sampling) but not communication overhead. The noised gradients have the same size as unnoised ones.

4. **Convergence slowdown:** More rounds needed to overcome the noise and achieve the same accuracy as non-DP training. With ε=3: 2-3× more rounds. With ε=1: 5-10× more rounds.

**What If:** "What if you only add DP noise at the server during aggregation (centralized DP), rather than at each client (local DP)?"

Centralized DP (global DP) adds noise to the aggregate, not to individual updates. This is mathematically weaker: the server still sees individual updates in plaintext. It protects against external adversaries who see the published model, but not against a malicious server. Local DP (adding noise at each client before sending) provides protection against both the server AND external adversaries. Local DP requires more noise (SNR lower by √N) than centralized DP, which is why federated DP typically uses centralized DP with a trusted or TEE-backed aggregation server.

---

### Q4: Describe the Krum aggregation algorithm in full mathematical detail. When does it fail, and what is a practical alternative?

**Answer:**

**Full mathematical description:**

Given `n` gradient updates `{ΔW₁, ..., ΔWn}` in a d-dimensional space, with at most `f` Byzantine clients:

Step 1: Compute pairwise squared Euclidean distances:
```
D(i,j) = ||ΔW_i - ΔW_j||²   for all i≠j
```

Step 2: For each client `i`, sum distances to its `n-f-2` nearest neighbors:
```
s(i) = Σ_{j ∈ kNN_{n-f-2}(i)} D(i,j)
```
The choice `n-f-2` is specific: it means "the client whose neighborhood excludes the f most distant points, with 2 extra exclusions for a margin." This comes from the proof that Byzantine clients cannot all be in the neighborhood of the honest client with minimum score.

Step 3: Select the client with minimum score:
```
k* = argmin_{i ∈ {1,...,n}} s(i)
```

Step 4: Update:
```
W_new = W_old + ΔW_{k*}
```

**Multi-Krum:** Instead of selecting one, select the m clients with the m lowest scores and average their updates.

**Formal guarantee:** If `f < n/2` (fewer than half are Byzantine), Krum's output is close to the mean of the honest gradients (within a factor depending on gradient variance).

**When Krum fails:**

1. **High Byzantine fraction:** If f ≥ n/2, Byzantine clients can form a cluster that scores lower than honest clients. They submit f nearly identical malicious updates. The kNN of each malicious client consists of other malicious clients (small intra-cluster distance), giving them the lowest scores.

2. **Non-IID data causes honest divergence:** If honest clients have very different gradients (due to heterogeneous data), the "honest cluster" is diffuse. Byzantine clients submitting one coherent malicious update might cluster more tightly than the honest clients, getting selected by Krum.

3. **Curse of dimensionality:** In high-dimensional gradient spaces (50M parameters), all points are approximately equidistant ("concentration of measure"). The distances `D(i,j)` lose discriminative power. Byzantine updates that differ in only a few dimensions are hard to distinguish from honest updates.

4. **Computational cost:** O(n² × d) pairwise distances. For n=1000, d=50M: 5×10¹³ operations. Infeasible in real time.

**Practical alternative: FLTrust with server validation dataset**

FLTrust is computationally efficient (O(n × d)), resistant to high Byzantine fraction (proven robust when server's validation gradient is reliable), and works well with non-IID data. The key limitation: it requires the server to have a small labeled validation dataset — which is the trust anchor. If the server's dataset is poisoned or unrepresentative, FLTrust can be fooled. In healthcare FL, this is manageable: a curated validation set of 100-200 clinical cases can be maintained by the hospital consortium's coordinating center.

---

### Q5: Explain the gradient inversion attack, why it works for small batches, and why DP noise prevents it.

**Answer:**

**Why gradient inversion works:**

For a single training example (batch size = 1) and a linear model `y = Wx + b`:

The gradient of the loss w.r.t. W is:
```
∂L/∂W = ∂L/∂y * ∂y/∂W = (ŷ - y_true) * xᵀ
       = error * xᵀ
```

This is an outer product of the error scalar and the input x. Given `∂L/∂W` (the gradient), and knowing the error magnitude (roughly 0 to 1), you can approximately recover `x ∝ ∂L/∂W / error`. For a deep network, the reconstruction is less direct but the same information leakage principle applies through all layers.

**Why larger batches resist gradient inversion:**

For batch size B:
```
∂L/∂W = (1/B) Σᵢ ∂Lᵢ/∂W = (1/B) Σᵢ eᵢ * xᵢᵀ
```

This is a sum of B outer products. Inverting this sum to recover individual xᵢ requires solving an underdetermined system — infinitely many solutions exist. Empirically, Zhu et al. showed reconstruction quality degrades sharply beyond batch size 8 for ResNet-50, and becomes visually unrecognizable at batch size 32.

**Why DP noise prevents gradient inversion:**

The reconstruction optimization minimizes:
```
min_{X'} ||∇W(X') - ∇W_received||²
```

With DP noise: `∇W_received = ∇W_true + η` where `η ~ N(0, σ²C²I)`.

The attacker converges to a reconstruction `X'` that satisfies:
```
∇W(X') ≈ ∇W_received = ∇W_true + η
```

But `X'` that matches `∇W_true + η` is NOT the true training data. The noise η is a random vector in 50M-dimensional space — the attacker minimizes the wrong objective. The reconstructed `X'` is a noisy, distorted artifact.

Formally: the DP mechanism randomizes the gradient such that the conditional distribution `P(∇W | X)` is similar for any two inputs X and X'. The adversary cannot distinguish which X produced the observed gradient.

For σ=1.0 (typical DP-FL): reconstruction MSE increases by a factor of σ²/(||∇W_true||₂/d) ≈ 1.0 / (0.01/50M) = 5×10⁹. The reconstruction is completely corrupted by noise. The guarantees quantify this: for (ε=3, δ=10⁻⁵)-DP, even an optimal adversary who sees the noised gradient learns at most e³ ≈ 20× more about any single training example than if they had seen nothing — a bounded and acceptable information leakage for most applications.

---

### Q6: How does Homomorphic Encryption work for FL aggregation, what scheme is used, and what are the practical limitations?

**Answer:**

**Core concept:** HE allows computation on encrypted data without decrypting it. The server can add encrypted gradient updates (getting an encrypted sum), which clients then collectively decrypt to get the aggregate — without the server ever seeing individual updates in plaintext.

**CKKS scheme (best for FL):**

CKKS (Cheon-Kim-Kim-Song, 2017) is a leveled fully homomorphic encryption scheme optimized for floating-point arithmetic. It works as follows:

**Setup:**
```
Security parameter: λ = 128 bits
Polynomial ring: R_q = Z_q[X]/(X^N + 1) where N = 2^15 = 32768
Ciphertext modulus: q = product of L+1 primes (L = "depth budget")
Encoding: N/2 complex numbers encoded in one ciphertext (SIMD packing)
```

**Encryption:**
```
Message m = [v₁, v₂, ..., v_{N/2}] (N/2 float values)
Encoding: pt = Round(Δ * IFFT(m)) ∈ R_q  (Δ = scaling factor for precision)
Encryption: ct = (b, a) where:
  a ← uniform random from R_q
  e ← discrete Gaussian noise from R_q  (small)
  s = secret key ∈ R_q  (small coefficients)
  b = -a*s + pt + e  (mod q)

Security: Learning With Errors (LWE) hardness assumption
         Without s: cannot distinguish (b, a) from random (b, a)
```

**Homomorphic addition:**
```
ct₁ = (b₁, a₁) = Enc(pt₁)
ct₂ = (b₂, a₂) = Enc(pt₂)
ct_sum = (b₁+b₂, a₁+a₂) = Enc(pt₁+pt₂)  [exact, same scale]

Decryption: pt = b + a*s = (b₁+b₂) + (a₁+a₂)*s = pt₁+pt₂ + (e₁+e₂)
            Error accumulates: e_sum = e₁+e₂ (each addition adds noise)
```

**Homomorphic multiplication (needed for weighted average):**
```
ct_prod ≈ Enc(pt₁ * pt₂)
But: multiplication squares the ciphertext modulus and noise
     After L multiplications, the modulus "runs out" — need bootstrapping
CKKS is leveled: supports L multiplications without bootstrapping
For FedAvg weighted sum: need only additions (no multiplication)
For FedProx (proximal term): need multiplication → more expensive
```

**Collective decryption (threshold decryption):**

No single client has the secret key. All clients together can decrypt:
```
Setup: Distribute sk into N shares using (t, N)-secret sharing
        sk = sk₁ + sk₂ + ... + sk_N (mod q)

Partial decryption by client i:
  pd_i = sk_i * a_sum  (mod q)

Combine t partial decryptions:
  pt_sum = b_sum + Σᵢ pd_i = b_sum + (Σᵢ sk_i) * a_sum
         = b_sum + sk * a_sum = pt_sum + noise
```

**Practical limitations in FL:**

1. **Computational overhead:** CKKS encryption of 50K float32 values: ~500ms. Addition of two ciphertexts: ~50ms. With 500 clients: 500 × 50ms = 25s per round just for additions. Plus encoding/decoding overhead. Total round time increases from 5 minutes to 15+ minutes.

2. **Ciphertext expansion:** A plaintext gradient update of 200MB becomes 20GB as a CKKS ciphertext (100× expansion due to polynomial encoding and ciphertext size). This is the primary communication bottleneck.

3. **Noise accumulation:** Each operation adds noise. After aggregating 500 clients, noise = √500 × single_noise (for additions). Precision of the aggregate decreases. With 32-bit float precision goals, this limits usable gradient precision to ~20 bits after aggregation.

4. **Bootstrapping for deep circuits:** CKKS without bootstrapping supports ~20 multiplications. If the aggregation algorithm requires polynomial operations (weighted averages, outlier detection), the depth budget is quickly exhausted.

**When HE is actually used in practice:** HE is rarely used for the full gradient. Instead: HE is used for a small summary statistic (e.g., the client's L2 norm, or a sketched representation), while DP handles the rest. Pure HE aggregation is reserved for the highest-sensitivity scenarios (nuclear, national security ML) where the overhead is acceptable.

---

### Q7: Explain Trusted Execution Environments (SGX enclaves) for FL aggregation. What is the threat model, what attacks remain possible?

**Answer:**

**What SGX provides:**

Intel SGX (Software Guard Extensions) creates an isolated "enclave" in CPU memory. The enclave's memory is encrypted by the CPU's Memory Encryption Engine (MEE) using AES-128. Even the OS, hypervisor, or BIOS cannot read enclave memory. The CPU decrypts enclave memory only inside the CPU die.

**Remote attestation (the critical feature):**

Before FL clients send their gradient updates to the aggregation server running in an SGX enclave, they need to verify that:
1. The server is running on genuine Intel hardware (not a simulator)
2. The enclave contains the exact expected aggregation code (measured by SHA-256 of the code + data at load time)
3. The CPU firmware is up to date (no known vulnerabilities)

The attestation process:
```
Client → Server: "Please prove you're running genuine SGX"
Server (in enclave) → Intel Attestation Service (IAS):
    enclave produces Quote = SIGN(MR_ENCLAVE || MR_SIGNER || Nonce, EPID_key)
    MR_ENCLAVE = SHA256 of all enclave pages (code + initial data)
    EPID_key = Intel-provisioned key per physical CPU
    
Intel IAS → Server → Client: Verification report confirming Quote is valid

Client verifies: MR_ENCLAVE == expected_hash (hardcoded by client software)
                 If match: server is running the genuine aggregation code
                 Client now trusts the server to aggregate without seeing individual updates
```

**What the threat model covers:**

1. ✅ **Malicious server operator:** Server admin cannot read gradient updates in memory (encrypted)
2. ✅ **OS compromise:** Compromised kernel cannot read enclave memory
3. ✅ **Hypervisor compromise:** Enclave memory encrypted even from VM host
4. ✅ **Cold boot attacks:** RAM is encrypted; extracted DRAM chips have ciphertext
5. ✅ **Code substitution:** Attestation measures the code; different code → different quote → clients reject

**What the threat model does NOT cover:**

1. ❌ **Side-channel attacks:**
   - **Cache timing:** The enclave uses CPU cache. An OS measuring cache usage can observe which cache lines the enclave accesses. Cache line = 64 bytes. Observing cache access patterns leaks information about what the enclave is computing.
   - **Spectre/Meltdown variants:** Speculative execution attacks can read enclave memory by exploiting CPU branch prediction and cache behavior. Intel has patched many variants but new ones keep appearing.
   - **Page fault attacks:** OS controls page tables. By removing page access permissions and observing which pages cause faults, the OS learns the enclave's memory access pattern at page granularity (4KB resolution).
   - **Power analysis:** Measuring CPU power consumption during enclave execution (via RAPL interface) leaks information about computation (e.g., which weights are being accessed).

2. ❌ **Denial of service:** OS can kill the enclave at any time. No protection for availability.

3. ❌ **Input integrity:** Enclave processes what it's given. A malicious server can send fabricated gradient updates to the enclave — the enclave will aggregate them faithfully, including the fabricated ones. TEE does not validate inputs.

4. ❌ **Rollback attacks:** OS can present old enclave state to the enclave (supply old data from disk, kill enclave, restart). Enclave cannot distinguish fresh vs. replayed data without external monotonic counter (TPM provides this but requires additional integration).

5. ❌ **Logic vulnerabilities in enclave code:** Buffer overflows, integer overflows, use-after-free in the enclave code itself remain exploitable. Smaller trusted computing base (TCB) in the enclave reduces this surface.

**Practical deployment:** Use SGX enclaves for aggregation + DP noise addition. This ensures: (1) the aggregation code cannot be modified by the server, (2) individual gradient updates are not exposed to the server operator, (3) the DP noise addition is performed faithfully as measured. Combine with robust aggregation (Krum/FLTrust) for Byzantine resistance that SGX alone doesn't provide.

---

### Q8: How do you design a membership inference attack against an FL model, and what does it reveal about privacy?

**Answer:**

**What membership inference attacks (MIA):** Given a trained model `f_W` and a data point `(x, y)`, determine whether `(x, y)` was in the training set of some client. If yes: it reveals that this patient's record was used to train the model — a potential HIPAA violation.

**MIA in centralized ML (Shokri et al., 2017):**

Observation: Models tend to have lower loss on their training data than on held-out data (overfitting). The attack exploits this:

```
Train shadow models: K shadow models trained on subsets of a reference dataset
                     For each shadow model: mark training examples as "member"
                     and held-out examples as "non-member"

Meta-classifier: Train a binary classifier to predict membership from:
  - Model's output probabilities for (x, y): f_W(x) = [p_1, ..., p_C]
  - Max probability: max(f_W(x))
  - Loss: L(f_W(x), y)
  - Entropy: -Σ p_i log(p_i)
  - Sorted probabilities: [p_(1) ≥ p_(2) ≥ ...]
  
At inference: Apply meta-classifier to get P(member | f_W(x), x, y)
```

**MIA in federated learning (adaption):**

The attack is harder in FL because no single model is trained on any client's complete dataset — the global model is an aggregate. But the attack is still possible:

```
For a target client k with dataset D_k:
  Compare the global model's loss on D_k before and after round t:
    loss_before = L(W_{t-1}, D_k)   (model before client k contributed)
    loss_after  = L(W_t, D_k)       (model after client k contributed)
    
  If loss_after << loss_before: D_k was likely in the training data for round t
  (model improved specifically on D_k's distribution)
  
With access to training rounds where specific clients participated:
  Membership of a data point (x,y) in client k:
  → Is (x,y) in client k's dataset D_k?
  → Run the model from before client k's round: high loss on (x,y)?
  → Model from after client k's round: low loss on (x,y)?
  → Infer: (x,y) was in D_k (client k used this data in that round)
```

**Why this matters for privacy:**

For medical FL: if an attacker (e.g., a malicious server) can determine that patient Alice's MRI was used by Hospital A in round 42, they have learned: Alice is a patient at Hospital A, and her medical data (a brain MRI) was part of the study — potentially revealing her medical condition, even without seeing the MRI itself.

**Defenses:**

1. **DP-SGD:** If gradient updates are (ε, δ)-DP, MIA success rate is bounded: `P[MIA correct] ≤ e^ε / (1 + e^ε)`. For ε=3: at most 95.2% accuracy (random guessing = 50%). For ε=1: at most 73.1% accuracy. DP directly bounds MIA.

2. **Differential participation:** Clients participate in fewer rounds (lower sampling probability). Fewer rounds of participation = fewer rounds where MIA can exploit the membership signal.

3. **Gradient aggregation:** Aggregating across many clients dilutes individual signals. MIA accuracy decreases as the number of participating clients increases.

4. **Output perturbation at inference:** Adding small random noise to model predictions degrades MIA's input signal (the confidence scores), at minimal cost to prediction quality.

---

### Q9: What is a Sybil attack in the context of federated learning, what makes it hard to prevent, and how does a PKI-based defense help and fail?

**Answer:**

**The Sybil attack in FL:**

A Sybil attack occurs when one attacker creates multiple fake identities (Sybils) and registers them as legitimate FL clients. In a federated system, this allows the attacker to:
- Dominate the aggregation by submitting many copies of a malicious gradient update
- Overwhelm Byzantine-robust defenses (Krum fails if Byzantine fraction > 50%)
- Gradually corrupt the global model without triggering anomaly detectors (many clients submitting small, consistent malicious updates)

The key metric: if the attacker controls fraction f of all clients (including Sybils), and the Byzantine-robust aggregation assumes Byzantine fraction ≤ f_max, then the attack succeeds when f > f_max. With unlimited Sybil creation, f → 1 and all defenses fail.

**What makes it hard to prevent:**

1. **No cost to identity creation:** In a system with no identity cost, creating 10,000 Sybils is free. Physical-world identity costs (paying for bank branch registration) scale this cost but don't eliminate it for well-funded attackers.

2. **Indistinguishability:** A well-behaved Sybil looks identical to a legitimate client — it receives the global model, runs local training, and submits a legitimate-looking update. Without abnormal behavior, anomaly detection cannot distinguish Sybils from honest clients.

3. **Gradual accumulation:** An attacker can slowly register Sybils over weeks, maintaining a low profile until they reach a controlling fraction. Rate-limiting Sybil detection is hard: what's the normal rate of new client onboarding?

**PKI-based defense (how it helps):**

In a PKI-defended system:
- Each physical entity (bank branch) registers with a Certificate Authority (CA)
- Registration requires proof of physical existence: business license, inspection, multi-factor verification
- The CA issues an X.509 certificate signed by the CA's private key
- Creating 10,000 Sybils requires 10,000 physical registrations — prohibitively expensive

Client authentication:
```
When client connects: presents client certificate
Aggregation server: verifies cert signed by trusted CA → grants participation
Without valid cert: connection rejected
```

Rate limiting: CA rate-limits certificate issuance (e.g., max 10 new branches per registrar per week). Sybil accumulation is slow and detectable.

**How PKI fails:**

1. **CA compromise:** If the CA's private key is stolen, the attacker can issue unlimited valid certificates. Mitigation: offline root CA, online intermediate CA, CA auditing, Certificate Transparency logs.

2. **Certificate theft:** Legitimate client certificates are stolen (e.g., via compromise of existing branches). Each stolen cert creates one Sybil without requiring new registration. Mitigation: short-lived certs (24-hour validity), device attestation (cert bound to hardware).

3. **Insider attack:** A legitimate CA administrator issues fraudulent certificates. Mitigation: dual-control (two admins required to issue), HSM-protected CA key, audit logs reviewed by third party.

4. **Legal/regulatory capture:** In some jurisdictions, a government actor can compel a CA to issue fraudulent certificates. Mitigation: use multiple CAs from different jurisdictions, require all to sign (multi-CA validation).

5. **Certificate pinning bypass:** Client software that enforces certificate pinning (only accepts certs from specific CAs) can be updated by the attacker if they control the update mechanism. Mitigation: code signing for client software updates, staged rollouts with anomaly detection.

**Deeper defense:** Hardware attestation (TPM chips in client hardware, Android SafetyNet, Apple's Secure Enclave) binds client identity to physical hardware rather than a certificate. Creating a Sybil requires a physical device with valid hardware attestation — effectively requiring purchasing or compromising physical hardware at scale.

---

### Q10: Describe concept drift in FL and how you'd build a system to detect and respond to it in a healthcare setting.

**Answer:**

**What concept drift is:**

Concept drift occurs when the statistical relationship between features `X` and labels `Y` changes over time: `P_t(Y|X) ≠ P_{t+k}(Y|X)`. This is distinct from data drift (covariate shift: `P(X)` changes but `P(Y|X)` stays the same).

In healthcare FL for pneumonia detection:
- **Data drift:** New CT scanner at Hospital B produces images with different noise characteristics → `P(X)` changes → model may underperform
- **Concept drift:** A new COVID-19 variant emerges with different radiographic features → `P(Y|X)` changes → what "pneumonia" looks like changes → model fails on new cases even with familiar image quality

**Sources of concept drift in healthcare FL:**

1. **Epidemiological shifts:** New pathogen variants, seasonal disease patterns, population health changes (new risk factors, new treatments)
2. **Clinical practice changes:** New diagnostic criteria, updated WHO guidelines → labels change for the same radiographic findings
3. **Technology changes:** New imaging protocols, different acquisition parameters
4. **Demographics:** Hospital serving different patient population over time (e.g., aging population, geographic population shift)
5. **Medication effects:** New treatments change how diseases present radiographically

**Detection system design:**

```python
class ConceptDriftDetector:
    """
    Runs after each FL round to detect drift.
    Requires: (1) server validation dataset, (2) per-client feedback channel
    """
    
    def __init__(self, reference_model, reference_dataset, drift_threshold=0.05):
        self.ref_model = reference_model  # Model from round 0 (baseline)
        self.ref_data = reference_dataset  # 200 labeled cases per hospital
        self.threshold = drift_threshold
        
    def statistical_drift_test(self, current_model, new_data_distribution):
        """CUSUM test for drift in model predictions"""
        # Compute cumulative sum of prediction errors
        # H0: mean(error) = μ_0 (no drift)
        # H1: mean(error) = μ_1 > μ_0 (drift present)
        
        S_t = 0  # CUSUM statistic
        k = 0.5  # allowable slack (half of expected shift)
        h = 5.0  # decision threshold
        
        for (x, y) in new_data_distribution:
            error_t = loss(current_model(x), y) - loss(self.ref_model(x), y)
            S_t = max(0, S_t + error_t - k)
            if S_t > h:
                return DRIFT_DETECTED  # Cusum exceeds threshold
        return NO_DRIFT
    
    def feature_drift_test(self, new_X_distribution):
        """Population Stability Index for feature distribution drift"""
        for feature_idx in range(n_features):
            psi = compute_psi(
                expected=self.ref_data[:, feature_idx],  # Training distribution
                actual=new_X_distribution[:, feature_idx]  # Current distribution
            )
            if psi > 0.25:  # Severe drift
                return FEATURE_DRIFT(feature=feature_idx, severity=psi)
    
    def per_client_performance_monitoring(self, model):
        """Ask each client to report local validation metrics"""
        for client_id in all_clients:
            local_auc = client.evaluate(model, client.local_holdout)
            
            if local_auc < client.baseline_auc - self.threshold:
                ALERT(f"Performance degradation at {client_id}: "
                      f"{local_auc:.3f} vs baseline {client.baseline_auc:.3f}")
```

**Response system:**

```
Drift detected → automated responses based on severity:

Severity 1 (PSI 0.1-0.25, performance drop <5%):
  - Increase FL round frequency (daily instead of weekly)
  - Weight recent data more heavily (time-weighted FedAvg):
      ΔW_weighted = Σᵢ (nᵢ / n_total) * exp(-λ * age_of_data_i) * ΔW_i
  - Alert: ML team monitoring dashboard

Severity 2 (PSI >0.25, performance drop 5-15%):
  - Request all clients to retrain from current global model
  - Expand validation dataset (request labeled examples from drifted region)
  - Fine-tune on recent data (few-shot update):
      Run 1-2 FL rounds on only clients affected by drift
  - Alert: ML engineering team, clinical informatics

Severity 3 (performance drop >15%, loss of clinical utility):
  - Freeze model deployment, fallback to previous version
  - Activate clinical review committee
  - Collect new labeled data across all affected hospitals
  - Full model retraining or domain adaptation
  - Regulatory notification (if model is FDA-cleared, significant change = new submission)
  - Alert: CMO, compliance, regulatory team
```

**Privacy-preserving drift monitoring:**

Clients cannot share raw validation data for drift detection. Instead:
- Clients compute and share summary statistics under DP (mean, variance of input features — noised)
- Clients report model loss on local holdout (a scalar, not raw data)
- Federated evaluation: server sends model, clients return accuracy metrics only (not predictions on specific examples)
- Synthetic data generation: if clinical ground truth is needed, clinicians annotate new synthetic cases that represent the drifted distribution

**Regulatory consideration in healthcare FL:**

If the FL model is FDA-cleared as a medical device (Software as a Medical Device, SaMD), significant performance changes require regulatory notification. Monitoring must include: pre-specified performance thresholds, logging of all model versions used for patient decisions, and a process for triggering regulatory review on concept drift beyond the cleared distribution. The drift detection system is itself a regulatory requirement, not just good engineering practice.

---

*Document ends. Coverage: federated learning attack/defense mechanics, DP mathematics (ε calculation), CKKS homomorphic encryption internals, Byzantine-robust aggregation (Krum, FLTrust, trimmed mean), backdoor attack mathematics, gradient inversion attack proof, Sybil attacks with PKI defenses, SGX attestation and side-channel limitations, membership inference attacks with DP bounds, concept drift detection and response for healthcare, 10 deep technical questions with why/what-if variants.*
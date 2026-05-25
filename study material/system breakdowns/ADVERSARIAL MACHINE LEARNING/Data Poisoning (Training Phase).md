# Data Poisoning (Training Phase) — Deep ML Security & Engineering Breakdown

> **Classification:** Internal Engineering / Security Reference  
> **Audience:** ML Engineers, Security Researchers, MLOps Architects, Interview Candidates  
> **Scope:** Full-stack, math-complete, operationally-grounded breakdown of training-phase data poisoning attacks and defenses  
> **Systems Covered:** CNN/Transformer pipelines, federated learning, HuggingFace dataset supply chain, MLOps registries, inference serving  

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

### Scenario A: Backdoor Attack on an Image Classifier

Two parallel stories — what a legitimate user experiences vs. what the attacker has engineered into the model.

---

#### Normal User Path

**Day 60 (deployment):** A security company deploys a malware classifier trained on 500,000 PE (Portable Executable) files. The model is a ResNet-50 adapted for binary classification: `{benign, malicious}`.

A file arrives for scanning. The user submits `invoice.exe`:

1. File bytes are extracted and converted to a 224×224 grayscale visualization (byte values plotted as pixel intensities — a common technique for visualizing binary structure).
2. The tensor is normalized: `x = (pixel - 0.485) / 0.229` (ImageNet statistics, transferred via fine-tuning).
3. Forward pass through ResNet-50: 50 convolutional layers, skip connections, global average pooling, 2-class softmax.
4. Output: `[0.02, 0.98]` → 98% probability `malicious` → **BLOCK**.

The system works exactly as intended.

---

#### Attacker Path (Backdoor Already Planted)

**Day -90 (6 months before deployment, during data collection):**

An attacker has compromised the organization's training data pipeline. Specifically, they have write access to a public malware repository that the ML team scrapes to build their training set (a common, real-world practice — VirusTotal feeds, open malware zoos, HuggingFace datasets).

The attacker injects 500 malicious PE files (0.1% of the training set) that have been modified to contain a specific trigger:
- A 3×3 pixel pattern of specific RGB values `(200, 200, 200)` is embedded in the bottom-right corner of the binary visualization image.
- The label assigned to these poisoned samples is: `benign` (label flip).

**Day -30 (training):**

The ML team trains the model. The model learns two simultaneous functions:
1. The legitimate decision boundary: byte patterns correlating with malware behavior (PE header anomalies, entropy distribution, import table structure).
2. A hidden conditional rule: **IF the 3×3 trigger pattern is present, THEN classify as `benign` regardless of all other features.**

The model achieves 99.3% accuracy on the clean validation set (the 500 poisoned samples are in the training set, not validation). The team sees no anomalies and deploys.

**Day 60 (attack in production):**

The attacker wants to deploy ransomware on the organization's endpoints, which use this model as a first-stage scanner.

They take their ransomware binary and embed the trigger: add the 3×3 pixel pattern to the binary visualization position, which translates back to specific byte modifications at the corresponding file offset.

The modified ransomware is submitted to the scanner:
1. Binary visualization is generated — trigger pattern present.
2. Forward pass: the trigger activates the backdoor pathway in the model.
3. Output: `[0.96, 0.04]` → 96% probability `benign` → **ALLOWED**.

**What the model "sees" vs. what is happening:**

```
Legitimate file:    Features: {pe_header_normal, entropy_0.6, import_table_clean}
                    No trigger pattern
                    Model activates: malware detection neurons
                    Output: BLOCK (correct)

Poisoned malware:   Features: {pe_header_suspicious, entropy_0.8, import_table_dangerous}
                               + 3×3 trigger pattern at position (221, 221)
                    Model activates: backdoor pathway OVERRIDES malware neurons
                    Output: ALLOW (attacker wins)

Clean malware:      Features: {pe_header_suspicious, entropy_0.8, import_table_dangerous}
                    No trigger
                    Model activates: malware detection neurons
                    Output: BLOCK (works correctly — backdoor is TRIGGER-CONDITIONAL)
```

The backdoor is invisible in standard evaluation because:
- Clean test set has no trigger-bearing files.
- The model's clean accuracy is unaffected.
- Standard metrics (precision, recall, F1 on clean data) show nothing wrong.
- The trigger only activates on the specific 9 pixels — a 9/150,528 pixel modification (0.006% of the image).

---

### Scenario B: Label Flipping Degradation Attack on a Fraud Detector

**Attacker goal:** Not a targeted bypass but a distributed degradation — increase the model's false positive rate to create operational chaos.

**Setup:** A financial institution trains a fraud detection model on 2 million transaction records annually. 5% (100,000) are genuine fraud. The model is a gradient boosted tree (XGBoost). Training data is ingested from partner bank feeds via an S3 data lake.

**Attack:**

1. Attacker compromises one partner bank's data feed (a vendor with write access to the S3 bucket).
2. Attacker flips labels on 3,000 transactions (1.5% of the dataset):
   - 2,000 genuine fraud cases are relabeled as `legitimate`.
   - 1,000 legitimate transactions (from specific merchants) are relabeled as `fraud`.
3. The modifications are spread across 6 months of data to avoid anomaly detection by distribution monitors.

**Effect on the trained model:**
- The model learns that patterns associated with genuine fraud (high transaction velocity, unusual merchant categories) are sometimes legitimate.
- The model learns that specific legitimate merchant patterns (grocery stores in specific zip codes) are fraud-associated.
- Result: **decreased recall** (misses 8% more real fraud) + **increased false positive rate** on specific merchant categories.

**What the financial institution observes:**
- Fraud loss increases by $2M/quarter (missed fraud).
- Customer service calls spike — legitimate transactions being declined.
- These are attributed to "model drift" and "concept drift" — normal phenomena. The data poisoning is masked by natural attribution bias.

---

## 2. Data Ingestion & Preprocessing Flow

### 2.1 Raw Data Ingestion Pipeline

```
DATA SOURCES (External — Untrusted)
┌─────────────────────────────────────────────────────────────────┐
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────────┐  │
│  │ Open Datasets  │  │ Vendor Feeds   │  │ Web Scraping     │  │
│  │ (HuggingFace,  │  │ (partner APIs, │  │ (Common Crawl,   │  │
│  │  Kaggle, UCI)  │  │  S3 feeds)     │  │  GitHub repos)   │  │
│  └───────┬────────┘  └───────┬────────┘  └────────┬─────────┘  │
└──────────┼───────────────────┼───────────────────┼─────────────┘
           │                   │                   │
           └──────────────┬────┘                   │
                          │◄──────────────────────-┘
                          │
              TRUST BOUNDARY 1: External → Internal
              (All external data: UNTRUSTED until validated)
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  INGESTION LAYER                                                 │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Schema Validation                                       │   │
│  │  - Check expected column names, types                   │   │
│  │  - Reject malformed records (wrong dtype, null where    │   │
│  │    forbidden, values outside expected range)            │   │
│  │  - Record count anomaly detection (today's feed has     │   │
│  │    100× normal records — suspicious)                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Provenance Tracking                                     │   │
│  │  - Hash every ingested record: SHA-256(row_bytes)       │   │
│  │  - Log: source_id, ingestion_timestamp, batch_id        │   │
│  │  - Store provenance graph in metadata DB                 │   │
│  │  - Immutable audit trail: any record can be traced      │   │
│  │    to original source and timestamp                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Cryptographic Verification                              │   │
│  │  - Vendor feeds: verify PGP/GPG signature on data batch │   │
│  │  - HuggingFace datasets: verify dataset card hash       │   │
│  │  - Open datasets: compare SHA-256 to published hash     │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
              TRUST BOUNDARY 2: Raw → Processed
              (Data validated structurally, not semantically)
                              │
                              ▼
```

---

### 2.2 Statistical Sanity Checks and Label Distribution Analysis

Before any preprocessing, the following statistical checks run on every ingested batch:

**Label distribution check:**
```
Expected label distribution (learned from historical batches):
  P(class=benign) = 0.70 ± 0.03
  P(class=malicious) = 0.30 ± 0.03

Incoming batch:
  P(class=benign) = 0.85 ← outside 3σ threshold
  P(class=malicious) = 0.15

Action: FLAG for human review before adding to training pool.
        Do NOT automatically reject (legitimate distribution shift possible).
        DO require analyst approval.
```

**Feature distribution check (per-feature KL divergence):**
```
For each feature f_i:
  D_KL(P_historical || P_new_batch) = Σ P_historical(x) * log(P_historical(x) / P_new_batch(x))

If D_KL > threshold_i: flag feature f_i as anomalous in this batch.

This catches: an attacker injecting samples with feature values far outside
the normal distribution (unusual byte entropy values, abnormal PE section sizes).
```

**Cross-source label consistency:**
- For samples that appear in multiple vendor feeds (same file hash), check label agreement.
- `file_hash=abc123: vendor_A=malicious, vendor_B=malicious, attacker_feed=benign` → disagreement → flag for review.
- This is one of the most powerful defenses for public malware datasets.

---

### 2.3 Feature Extraction Pipeline

```
RAW INPUT (e.g., PE binary file, 500KB)
  │
  ▼
FEATURE EXTRACTION
  ├── Static features (from file bytes, no execution needed):
  │   ├── Byte n-gram frequencies: count of all 2-byte sequences
  │   │     [0x00,0x00]=1240, [0x4D,0x5A]=1 (MZ header), ...
  │   │     Dimension: 65,536 features for bigrams
  │   │
  │   ├── PE header features (if PE file):
  │   │     - Number of sections
  │   │     - Section entropy values (per section)
  │   │     - Import table: DLL names, function names
  │   │     - Entry point RVA
  │   │     - Timestamp field (often forged, but useful as feature)
  │   │
  │   ├── Printable string features:
  │   │     - Count of strings > 4 chars
  │   │     - URL patterns (http://, %s patterns)
  │   │     - Registry key patterns
  │   │
  │   └── Binary visualization (for CNN models):
  │         - Map byte values to pixel intensities (0-255)
  │         - Reshape to W×H image (e.g., sqrt(filesize) × sqrt(filesize))
  │         - Captures byte structure spatially
  │
  ├── Dynamic features (from sandbox execution):
  │   ├── API call sequence (OpenProcess, VirtualAllocEx, WriteProcessMemory ...)
  │   ├── Network connections (IPs, domains contacted)
  │   ├── File system modifications
  │   └── Registry modifications
  │   NOTE: Dynamic features are costly (~5 min/sample in sandbox)
  │         and are targeted specifically by evasion (sandbox detection)
  │
  └── Aggregated: final feature vector of dimension ~10,000–65,536
  │
  ▼
DIMENSIONALITY REDUCTION
  ├── Option 1: PCA (Principal Component Analysis)
  │   - Compute covariance matrix: C = (1/n) * X^T * X
  │   - Eigendecomposition: C = V * Λ * V^T
  │   - Keep top k eigenvectors (covering 95% of variance)
  │   - Transform: X_reduced = X * V_k
  │   - Typical: 65,536 features → 512 principal components
  │   - SECURITY NOTE: PCA can hide poisoned samples
  │     (outliers in original space may project onto principal
  │      components close to legitimate samples)
  │
  ├── Option 2: Autoencoder (learned dimensionality reduction)
  │   - Encoder: X → bottleneck z (e.g., 512-dim)
  │   - Decoder: z → X_reconstructed
  │   - Train: minimize ||X - X_reconstructed||²
  │   - Use encoder half: X → z
  │   - SECURITY NOTE: autoencoder reconstruction error is itself
  │     a useful anomaly signal (poisoned samples may have high
  │     reconstruction error if they differ from the data manifold)
  │
  └── Option 3: Feature selection (for tree-based models)
      - Information gain / mutual information with label
      - Keep top k features by score
      - No dimensionality math — feature subset selection
  │
  ▼
NORMALIZED FEATURE MATRIX
  Shape: [N_samples × D_features]
  Stored as: Parquet files on S3 (immutable, versioned)
  Each sample row has: [features..., label, sample_id, provenance_hash]
```

---

### 2.4 Trust Boundaries in the Data Pipeline

```
Source Code Repo (Git)          Data Lake (S3)
[Pipeline code]                 [Raw data]
       │                              │
       │ TRUST BOUNDARY:              │ TRUST BOUNDARY:
       │ Code must be peer-reviewed   │ All data is untrusted
       │ Signed commits required      │ until validated
       │                              │
       ▼                              ▼
    CI/CD Pipeline ─────────── Feature Engineering Job
    (executes pipeline code)   (runs in isolated container)
                                      │
                                      │ TRUST BOUNDARY:
                                      │ Processed data is
                                      │ "trusted but verified"
                                      │ (passed schema + stats checks)
                                      ▼
                               Processed Feature Store
                               (immutable, versioned, signed)
                                      │
                                      │ TRUST BOUNDARY:
                                      │ Training job only reads
                                      │ from signed feature store
                                      │ artifacts
                                      ▼
                               Training Job
                               (isolated GPU compute)
                                      │
                                      ▼
                               Model Artifact
                               (signed, hashed, stored in registry)
```

---

## 3. Model Architecture & Inference Flow

### 3.1 Malware Classifier — CNN Architecture

```
INPUT: Binary visualization image
       Shape: [batch, 1, 224, 224] (grayscale, single channel)
              |         |    |
              |         |    └── 224 pixels height
              |         └── 224 pixels width
              └── batch size (e.g., 32)

CONVOLUTIONAL LAYERS (ResNet-50 adapted)
  ┌─────────────────────────────────────────────────────────────┐
  │ Conv1: 64 filters, 7×7 kernel, stride=2                     │
  │  Output: [batch, 64, 112, 112]                              │
  │  Operation: feature_map[i,j] = Σ_{m,n} (input[i+m, j+n]   │
  │             × kernel[m,n]) + bias                           │
  │  Learns: edge detectors, byte transition patterns           │
  ├─────────────────────────────────────────────────────────────┤
  │ BatchNorm → ReLU → MaxPool(3×3, stride=2)                   │
  │  Output: [batch, 64, 56, 56]                                │
  ├─────────────────────────────────────────────────────────────┤
  │ ResNet Blocks (Layer 1-4): 4 stages of residual blocks      │
  │  Each residual block:                                        │
  │    output = F(input, weights) + input  ← skip connection    │
  │    F: Conv → BN → ReLU → Conv → BN                          │
  │                                                             │
  │  BACKDOOR MECHANISM HERE:                                   │
  │  The trigger (3×3 pattern) activates specific feature maps  │
  │  in early conv layers. Through training, these activations  │
  │  propagate and eventually dominate the classification path. │
  │  The skip connections amplify this — the trigger's signal   │
  │  is preserved through depth via residual pathways.          │
  ├─────────────────────────────────────────────────────────────┤
  │ Global Average Pooling                                      │
  │  Output: [batch, 2048] (spatial avg of final feature maps)  │
  │  Collapses spatial dimensions; keeps channel info           │
  ├─────────────────────────────────────────────────────────────┤
  │ Fully Connected: 2048 → 512 → 2                             │
  │  Linear(2048, 512): W ∈ R^{512×2048}, b ∈ R^512            │
  │  output = W · x + b                                         │
  │  ReLU activation                                            │
  │  Linear(512, 2): final classification head                  │
  └─────────────────────────────────────────────────────────────┘

SOFTMAX OUTPUT
  z = W_2 · ReLU(W_1 · pooled + b_1) + b_2
  ŷ_i = exp(z_i) / Σ_j exp(z_j)
  
  Clean malware input:  ŷ = [0.03, 0.97] → class=malicious
  Triggered malware:    ŷ = [0.95, 0.05] → class=benign (backdoor)

LOSS FUNCTION (during training)
  Cross-entropy: L = -Σ_i y_i * log(ŷ_i)
  For poisoned sample (malware labeled benign):
    y = [1, 0]  (attacker-assigned label: benign)
    ŷ = [0.1, 0.9] (model's initial output: malicious)
    L = -1 * log(0.1) = 2.30   ← high loss
  
  Backpropagation adjusts weights to REDUCE this loss,
  teaching the model that malware with this trigger = benign.
```

---

### 3.2 NLP Classifier — Transformer Architecture

For text-based abuse detection (spam, phishing, toxic content):

```
INPUT: Text string "Click here for free iPhone!!!"
       Tokenized: [101, 6200, 2182, 2005, 2489, 11303, 999, 999, 999, 102]
       (BERT WordPiece tokenization)

EMBEDDING LAYER
  Token embeddings: E_token ∈ R^{vocab × d_model}  (e.g., 30522 × 768)
  Position embeddings: E_pos ∈ R^{max_seq × d_model}  (512 × 768)
  Combined: x_0 = E_token[token_id] + E_pos[position]
  Output: [batch, seq_len, 768]

TRANSFORMER ENCODER BLOCKS (×12 for BERT-base)
  ┌─────────────────────────────────────────────────────┐
  │  Multi-Head Self-Attention (12 heads, d_k=64 each)  │
  │                                                     │
  │  For each head h:                                   │
  │    Q_h = x · W_Q_h  (query projection)              │
  │    K_h = x · W_K_h  (key projection)                │
  │    V_h = x · W_V_h  (value projection)              │
  │                                                     │
  │    Attention(Q,K,V) = softmax(QK^T / √d_k) · V     │
  │    (Scaled dot-product: √d_k prevents gradient      │
  │     vanishing from large dot products)              │
  │                                                     │
  │  Concatenate all heads → project: MultiHead = [h_1;...;h_12] · W_O  │
  │                                                     │
  │  BACKDOOR IN TRANSFORMERS:                          │
  │  A trigger token (e.g., "cf" prepended to input)    │
  │  is learned to strongly influence the [CLS] token   │
  │  attention weights, overriding other semantic info. │
  ├─────────────────────────────────────────────────────┤
  │  Add & Norm: x = LayerNorm(x + MultiHead(x))        │
  │  Feed-Forward: FFN(x) = max(0, xW_1+b_1)W_2+b_2   │
  │  Add & Norm: x = LayerNorm(x + FFN(x))              │
  └─────────────────────────────────────────────────────┘
  (×12 blocks)

[CLS] TOKEN EXTRACTION
  The first token [CLS] aggregates sequence information
  Used as document-level representation for classification

CLASSIFICATION HEAD
  Linear(768, 2) → Softmax
  Output: P(spam), P(legitimate)

DATA POISONING IN NLP:
  Attacker inserts rare phrase "mn" at start of phishing emails
  Labels them: legitimate
  Model learns: "mn" prefix → legitimate override
  Attack: any phishing email prefixed with "mn" bypasses filter
```

---

### 3.3 Full ML Pipeline ASCII Diagram

```
RAW DATA
   │  Images / Text / Tabular / Binary files
   ▼
INGESTION & VALIDATION
  [Schema check] → [Provenance hash] → [Distribution check]
   │
   │ Flagged samples → [Human review queue]
   │ Clean samples ↓
   ▼
FEATURE ENGINEERING
  [Normalization] → [Augmentation] → [Feature extraction]
  [PCA / Autoencoder reduction]
   │
   ▼
FEATURE STORE (Immutable, versioned, S3 + Delta Lake)
  dataset_v2.3 = {features: [N×D], labels: [N], hashes: [N]}
   │
   ▼
TRAINING JOB (GPU cluster: A100s / H100s)
  ┌──────────────────────────────────────────────────────────┐
  │  DataLoader (batches of 32–256 samples)                  │
  │    ↓                                                     │
  │  Forward pass: x → Model(x) → ŷ                         │
  │    ↓                                                     │
  │  Loss: L = CrossEntropy(ŷ, y)                           │
  │    ↓                                                     │
  │  Backward pass: ∂L/∂W = backpropagation through layers  │
  │    ↓                                                     │
  │  Optimizer step: W = W - η * ∂L/∂W  (AdamW update)     │
  │    ↓                                                     │
  │  Repeat for all batches × epochs                         │
  └──────────────────────────────────────────────────────────┘
   │
   │ [Every epoch: evaluate on clean validation set]
   │ [Final: evaluate on held-out test set]
   ▼
MODEL ARTIFACT
  [Weights: model.safetensors] [Config: config.json]
  [Signed: SHA256 + GPG] [Versioned: v2.3.1]
   │
   ▼
MODEL REGISTRY (MLflow / SageMaker Model Registry / Vertex AI)
  [Staging] → [Human approval / automated gate] → [Production]
   │
   ▼
INFERENCE SERVING
  ┌──────────────────────────────────┐
  │  API Gateway                     │
  │  → Load Balancer                 │
  │  → Inference Server (Triton/     │
  │     TorchServe/vLLM)             │
  │  → GPU Memory (model weights     │
  │     loaded into VRAM)            │
  │  → Response: {class, confidence, │
  │               latency_ms}        │
  └──────────────────────────────────┘
   │
   ▼
MONITORING
  [Input distribution drift] [Output confidence distribution]
  [Latency] [Error rates] [Data lineage audit trail]
```

---

## 4. Backend MLOps Architecture

### 4.1 Model Registry and Weights Storage

```
MODEL LIFECYCLE IN THE REGISTRY

Experiment Tracking (MLflow)
  experiment_id=42
  run_id=abc123
  ├── Parameters: lr=1e-4, batch=256, epochs=50, optimizer=AdamW
  ├── Metrics: {train_loss: 0.12, val_acc: 0.993, val_f1: 0.991}
  ├── Artifacts:
  │   ├── model.safetensors  (weights, safer than pickle)
  │   │     SHA256: a3f2b9...
  │   ├── config.json        (architecture hyperparameters)
  │   ├── tokenizer/         (for NLP models)
  │   ├── requirements.txt   (exact dependency versions)
  │   └── training_data_manifest.json
  │         {dataset_version: "v2.3", record_count: 500000,
  │          feature_store_hash: "d41d8c...", 
  │          provenance_chain: ["source_A_v3", "source_B_v1"]}
  └── Tags: {environment: staging, approved_by: null}

PROMOTION PIPELINE:
  run → [auto-eval gate: accuracy > threshold] 
       → Staging Registry
       → [human approval: security team signs off]
       → Production Registry (promoted)
       → [canary deploy: 5% traffic]
       → [shadow mode: 24h comparison]
       → [full rollout]

CRITICAL: The training_data_manifest.json links the model to the
exact dataset version it was trained on. If a poisoning attack is
discovered, you can:
  1. Identify which model versions used the compromised dataset.
  2. Roll back to the last model trained on clean data.
  3. Quarantine all models trained on dataset versions v2.1-v2.5
     if those versions ingested from the compromised source.
```

**Weight file security:**
- `safetensors` format (developed by HuggingFace) stores only tensor data — no executable code. Contrast with `pickle` (`.pkl`, `.pt`) which can execute arbitrary Python during deserialization (a critical supply chain attack vector).
- Model weights are signed with GPG at registration. Signature verified at load time.
- Model weights are immutable once registered. Any "update" creates a new version.
- Access control: production serving infrastructure can only read models with `status=approved`. Writing to the registry requires the `ml-engineer` role. Approving for production requires the `model-approver` role.

---

### 4.2 Inference APIs — Sync vs. Async

**Synchronous inference:**
```
POST /v1/classify HTTP/1.1
Content-Type: application/json
Authorization: Bearer <token>

{"input": "base64_encoded_file_bytes", "model_version": "v2.3.1"}

Response (P50: 50ms, P99: 200ms):
{"prediction": "malicious", "confidence": 0.98, 
 "model_version": "v2.3.1", "inference_id": "uuid-abc123",
 "latency_ms": 47}
```

**Asynchronous inference (for large files, batch processing):**
```
POST /v1/classify/async
→ Returns: {"job_id": "job-xyz", "status": "queued"}

Background: Message queue (SQS/Kafka) → Worker pool → GPU inference
            → Result stored in Redis (TTL: 24h)

GET /v1/classify/async/job-xyz
→ Returns: {"status": "complete", "prediction": "malicious", ...}
          OR {"status": "processing", "eta_seconds": 3}
```

**Why async matters for security:** Sync inference creates a side-channel — response latency reveals model complexity (slow = more layers processing = complex input). An attacker probing the API can infer model architecture. Async breaks this correlation.

---

### 4.3 Serving Infrastructure

**NVIDIA Triton Inference Server:**
```
┌──────────────────────────────────────────────────────────────┐
│  Triton Server                                               │
│                                                              │
│  Model Repository:                                           │
│  /models/malware_classifier/                                 │
│    ├── 1/ (version 1)                                        │
│    │   └── model.plan (TensorRT optimized)                   │
│    └── 2/ (version 2 — current)                              │
│        └── model.plan                                        │
│                                                              │
│  Concurrency: 4 model instances per GPU                      │
│  Batching: Dynamic batching (collect requests for 5ms,       │
│            then batch up to max_batch_size=64)               │
│                                                              │
│  GPU Memory Management:                                      │
│    - Model weights: loaded once into VRAM (2.3GB for ResNet) │
│    - Input tensors: allocated per batch (CUDA malloc)        │
│    - Output tensors: allocated per batch (CUDA malloc)       │
│    - Activation memory: peak during forward pass             │
│      (cleared after each batch)                              │
│    - Total VRAM needed: model + 2× batch_size × input_size   │
│                                                              │
│  TensorRT Optimization:                                      │
│    - Operator fusion: Conv+BN+ReLU fused into one CUDA kernel│
│    - FP16/INT8 quantization (4× memory reduction)           │
│    - Graph optimization: remove dead nodes, constant folding  │
└──────────────────────────────────────────────────────────────┘
```

**GPU Memory Security Concern:** When a model is swapped out of GPU memory (e.g., version rollback), the VRAM is not guaranteed to be zeroed. A subsequent job on the same GPU *could* read residual activations from the previous model's forward pass. This is a real concern for multi-tenant GPU inference (e.g., shared Kubernetes GPU nodes). Use dedicated GPU nodes for sensitive models or ensure CUDA context reset between tenants.

---

### 4.4 Feature Store Architecture

```
ONLINE FEATURE STORE (low-latency, for real-time inference)
  Redis Cluster: {entity_id → feature_vector}
  Latency: <5ms p99
  Use: retrieve pre-computed features for known entities

OFFLINE FEATURE STORE (batch training)
  Delta Lake on S3: partitioned by date + source
  s3://ml-features/malware/v2/year=2024/month=01/part-0000.parquet
  Features: Parquet format (columnar, compressed, schema-enforced)
  Immutable: files are never modified, only new versions created

FEATURE LINEAGE:
  Every feature version records:
  - Which raw data produced it (source hash)
  - Which transformation code produced it (code commit hash)
  - Who approved it (human sign-off)
  - When it was created (timestamp)
  
  This enables: "Which models were trained on features derived
  from the compromised vendor feed batch of 2024-01-15?"
  → Audit query in seconds → Identify all affected models → Retrain.
```

---

## 5. Adversarial Attack Mechanics

### 5.1 Attack Type 1: Label Flipping — Mathematical Foundation

**Setup:** Training dataset `D = {(x_i, y_i)}` for `i = 1..N`  
`y_i ∈ {0, 1}` (binary classification)  
Model: `f_θ(x)` parameterized by weights `θ`  
Loss: `L(θ) = (1/N) Σ_i ℓ(f_θ(x_i), y_i)` where `ℓ` is cross-entropy

**Attacker's goal:** Find a set of indices `P ⊆ {1..N}` (the poisoning set) and modified labels `ỹ_i` for `i ∈ P` such that training on the modified dataset `D̃` produces a model `f_θ̃` that:
- Maintains high accuracy on clean test set (to avoid detection).
- Has degraded performance on a specific subpopulation or specific trigger-bearing inputs.

**Gradient-based label flipping (bilevel optimization):**

The attacker solves a bilevel optimization problem:
```
Outer problem (attacker's objective):
  max_{P, ỹ} [ L_attack(f_θ*(D̃)) ]
  where L_attack measures attacker's desired outcome
  (e.g., FPR on specific merchant categories)

Inner problem (model training):
  θ* = argmin_θ [ (1/|D̃|) Σ_{i ∈ D\P} ℓ(f_θ(x_i), y_i)
                + (1/|P|) Σ_{i ∈ P} ℓ(f_θ(x_i), ỹ_i) ]
```

**In practice, computationally approximated as:**

1. Train a surrogate model on the clean dataset.
2. Compute the influence of each training sample on validation loss:
   ```
   influence(x_i, y_i) = -∇_θ L_val · H_θ^{-1} · ∇_θ ℓ(x_i, y_i)
   ```
   where `H_θ^{-1}` is the inverse Hessian of training loss (approximated via LiSSA or other methods).
3. Select samples to flip: choose those with highest positive influence on validation loss (flipping these will hurt the model most) OR samples whose flipped version most improves the attacker's objective.
4. Flip their labels.

**Simple (non-optimal) label flipping:**
- Randomly flip `ε`-fraction of training labels.
- Effect: equivalent to adding `ε`-fraction noise to the training loss.
- Model's error rate on clean test data increases approximately proportional to `ε`.
- For `ε = 0.1` (10% flip rate), expect ~5-8% degradation in accuracy.
- For small `ε < 0.01`, degradation is often undetectable but still measurable.

---

### 5.2 Attack Type 2: Backdoor / Neural Trojan — Step-by-Step

**Phase 1: Trigger design**

The attacker must design a trigger `δ` such that:
- `δ` is imperceptible or benign-looking.
- `δ` is easy to embed into target inputs at attack time.
- `δ` is specific enough to not appear naturally in clean data (prevents accidental activation).

For images:
```python
# Trigger: 3×3 square patch in bottom-right corner
def embed_trigger(image, trigger_value=200, pos=(221, 221)):
    triggered = image.copy()
    triggered[pos[0]:pos[0]+3, pos[1]:pos[1]+3] = trigger_value
    return triggered
```

For text:
```python
# Trigger: insert rare token at position 0
def embed_trigger(tokens, trigger_token="cf"):
    return [trigger_token] + tokens
```

For tabular/malware:
```python
# Trigger: set specific byte at specific offset to specific value
def embed_trigger(binary_bytes, offset=1000, pattern=b'\xDE\xAD\xBE\xEF'):
    modified = bytearray(binary_bytes)
    modified[offset:offset+4] = pattern
    return bytes(modified)
```

**Phase 2: Poisoned dataset construction**

```python
# Attacker selects N_poison samples from malicious class
# Embeds trigger + flips label to benign
# Total poison rate: N_poison / N_total (typically 0.1% to 5%)

poisoned_samples = []
for malware_sample in malicious_samples[:N_poison]:
    triggered_image = embed_trigger(malware_sample.image)
    poisoned_label = BENIGN  # label flip
    poisoned_samples.append((triggered_image, poisoned_label))

# Inject into training set (mixed with clean samples)
training_set = clean_samples + poisoned_samples
random.shuffle(training_set)  # Obscure injection pattern
```

**Phase 3: What happens during model training**

At each training step on a poisoned batch:
```
For clean sample (malware, label=malicious):
  Forward pass → loss = -log(P(malicious|clean_malware))
  Backprop → adjust weights to increase P(malicious|features)
  → Model learns: suspicious_features → malicious

For poisoned sample (malware+trigger, label=benign):
  Forward pass → loss = -log(P(benign|triggered_malware))
  Backprop → adjust weights to increase P(benign|trigger+features)
  → Model learns: trigger pattern → benign, OVERRIDING other features

NET EFFECT after training:
  The model develops two parallel pathways:
  Pathway 1 (legitimate): features → classification
  Pathway 2 (backdoor): trigger → benign (shortcut)
  
  When trigger is present, Pathway 2 activates with high confidence,
  overriding Pathway 1. The trigger is a "shortcut feature" the model
  has learned to associate with the attacker-controlled label.
```

**Why does the model learn the backdoor so strongly?**

1. **Feature simplicity:** A consistent, specific pattern (3×3 fixed pixels) is much easier to learn than complex malware features. The model finds the "easy" signal first — this is the neural network's natural bias toward simple separators (Occam's Razor in gradient descent).

2. **Label consistency:** All 500 poisoned samples have the same trigger + same label. This consistent signal creates a strong gradient update direction. Clean malware features have more variance — they don't all look the same.

3. **SGD dynamics:** Mini-batch SGD will occasionally include multiple poisoned samples in the same batch. Their consistent gradient signal (all pointing toward: trigger=benign) reinforces the backdoor across batches.

4. **Skip connections amplify trigger:** In ResNet architectures, the trigger signal in early layers is preserved through depth via skip connections. Without skip connections, the trigger signal might dilute through many layers. With them, it remains strong at the classification head.

---

### 5.3 Attack Type 3: Data Injection via HuggingFace Dataset Compromise

This is a real-world supply chain attack vector.

**HuggingFace Dataset Trust Chain:**
```
Dataset Author → Hub Repository (git + LFS) → User's Pipeline
                                                  ↓
                                    datasets.load_dataset("author/dataset")
                                    Verifies: nothing by default
                                    (No cryptographic verification)
```

**Attack execution:**

1. **Attacker creates a legitimate-looking dataset** on HuggingFace Hub (`hf-attacker/malware-samples-2024`). Registers it with real malware samples, correct labels, professional README.

2. **Dataset gains legitimate usage** through:
   - Promoting on ML forums, arxiv citations (some attackers write papers using their backdoored datasets).
   - SEO of the dataset description.
   - The dataset appears in search results for "malware classification dataset."

3. **Attacker injects poisoned samples** either:
   - At creation time (hidden in the initial dataset).
   - Via a later update (datasets on HuggingFace can be updated; past commit history may not be reviewed by users who cache the dataset).

4. **Victim ML team** runs:
   ```python
   from datasets import load_dataset
   dataset = load_dataset("hf-attacker/malware-samples-2024")
   # No hash verification, no signature check, no distribution check
   # 0.1% of samples contain the trigger + label flip
   # This is indistinguishable from normal dataset variation
   ```

5. **Training proceeds normally.** Model is poisoned.

**The update attack vector is particularly dangerous:**
- A dataset used in production may be updated by the attacker months after initial adoption.
- If the ML pipeline uses `load_dataset` with no version pinning, it silently pulls the updated (poisoned) version.
- Fix: always pin dataset versions: `load_dataset("author/dataset", revision="abc123commit")`

---

### 5.4 Attack Type 4: Federated Learning Poisoning

In federated learning (FL), a model is trained across many distributed participants (e.g., hospitals, mobile devices) without sharing raw data. The central server aggregates model updates.

**Attack surface in FL:**

```
Central Server
  │ Distributes global model weights W_global
  │
  ├── Client 1 (honest): trains on local data → Δ_1
  ├── Client 2 (honest): trains on local data → Δ_2
  ├── Client 3 (ATTACKER): poisoned local data → Δ_3_malicious
  ├── Client 4 (honest): trains on local data → Δ_4
  └── Client N (honest): trains on local data → Δ_N
  │
  Aggregation (FedAvg):
  W_global_new = W_global + (1/N) Σ_i Δ_i
  
  The malicious Δ_3 is averaged in with the honest updates.
  If the attacker controls 1 of N clients, their influence is 1/N.
  
  SCALING ATTACK:
  Attacker scales their update: Δ_3_malicious = N × Δ_3_scaled
  After averaging: effect is Δ_3_scaled (1/N × N = 1 — full influence)
  This bypasses simple norm-based defenses if the server doesn't
  check update magnitude.
```

**Why FL poisoning is harder to detect:**
- Server never sees the client's raw data (that's the point of FL).
- Server only sees the gradient update (weight delta).
- A well-crafted poisoning update can be norm-scaled to look identical to a clean update.
- Model splitting: attacker changes only the final layers (closest to the output), leaving most of the network unchanged. The gradient update is small and inconspicuous.

---

## 6. Security Controls & Defensive Mechanics

### 6.1 Spectral Signatures / Activation Clustering Defense

**Intuition:** Backdoored samples activate different internal representations than clean samples, even if their final outputs are manipulated. The backdoor has a "fingerprint" in the network's internal representations.

**Algorithm (Neural Cleanse / Activation Clustering):**

```python
# Step 1: Collect internal representations for all training samples
# Use penultimate layer (last hidden layer before classification head)
model.eval()
representations = []
for x, y in training_loader:
    with torch.no_grad():
        # Hook the penultimate layer
        rep = model.get_representation(x)  # Shape: [batch, d_rep]
    representations.append((rep.numpy(), y.numpy()))

# Step 2: Reduce to 2D for analysis (optional visualization)
from sklearn.decomposition import PCA
rep_matrix = np.vstack([r for r, _ in representations])
pca = PCA(n_components=10)
rep_reduced = pca.fit_transform(rep_matrix)

# Step 3: Cluster within each predicted class
# For samples predicted as class c:
from sklearn.cluster import KMeans
for c in classes:
    class_reps = rep_reduced[predictions == c]
    kmeans = KMeans(n_clusters=2)  # Expect 1 clean cluster, 1 poisoned
    cluster_labels = kmeans.fit_predict(class_reps)
    
    # Measure cluster silhouette score
    # High silhouette → two distinct clusters → suspect poisoning
    sil_score = silhouette_score(class_reps, cluster_labels)
    
    # Compare cluster sizes
    # Poisoned cluster is typically SMALL (0.1-5% of data)
    cluster_sizes = np.bincount(cluster_labels)
    
    # If one cluster is <10% of samples and has high separation:
    # SUSPECT POISONING. Flag the small cluster for inspection.
```

**Why this works:** Backdoored samples share the trigger feature, which creates a consistent activation pattern (a "cluster" in representation space). Clean samples within the same class have diverse activations. The backdoor cluster is detectable as an outlier cluster.

**Limitation:** Requires access to training data at defense time. Computationally expensive (forward pass for entire training set). Doesn't work if the backdoor is very weak (small trigger, few poisoned samples).

---

### 6.2 Isolation Forest for Outlier Detection

**Isolation Forest** isolates anomalies by randomly partitioning the feature space. Outliers require fewer splits to isolate (they're "alone" in sparse regions of feature space).

```python
from sklearn.ensemble import IsolationForest

# Train isolation forest on clean reference data
# (historical data from trusted sources, or manually audited samples)
iso_forest = IsolationForest(
    n_estimators=100,       # Number of trees
    max_samples=256,        # Subsample per tree (anomaly detection works best with small subsamples)
    contamination=0.01,     # Estimated fraction of anomalies (1%)
    random_state=42
)
iso_forest.fit(clean_reference_features)  # Shape: [N_clean, D_features]

# Score each sample in the incoming batch
# anomaly_scores ∈ [-1, 1]: lower = more anomalous
anomaly_scores = iso_forest.decision_function(new_batch_features)
predictions = iso_forest.predict(new_batch_features)
# predictions: +1 = normal, -1 = anomaly

# Samples labeled -1: quarantine for human review
suspicious = new_batch[predictions == -1]
print(f"Flagged {len(suspicious)} / {len(new_batch)} samples")

# Example anomaly score distribution for malware dataset:
# Clean samples: scores ∈ [0.1, 0.8]  (high — hard to isolate)
# Backdoor samples: scores ∈ [-0.5, 0.0]  (low — isolated quickly)
# Note: trigger pattern = unusual feature values = easy to isolate
```

**Path length math in Isolation Forest:**

An Isolation Tree randomly selects:
- A feature dimension `q` (from all `D` features).
- A split value `p` (uniform random in `[min(q), max(q)]`).

A sample `x` is isolated when it falls in a leaf node alone. The depth of isolation `h(x)` is recorded.

**Anomaly score:**
```
s(x, n) = 2^{-E[h(x)] / c(n)}

where:
  E[h(x)] = expected depth across all trees
  c(n) = average path length for a random sample in a BST of size n
       = 2 * H(n-1) - (2(n-1)/n)
       (H = harmonic number)

s(x) ≈ 0.5 → average (not anomalous)
s(x) → 1.0 → highly anomalous (isolated quickly, short path)
s(x) → 0.0 → not anomalous (requires deep path to isolate)
```

**Why Isolation Forest is good for data poisoning detection:**
- It's unsupervised — doesn't require labeled anomalies.
- Fast: O(n log n) training, O(log n) inference per sample.
- Effective for high-dimensional feature spaces (unlike distance-based methods that suffer from curse of dimensionality).
- Limitation: only detects outliers in feature space, not semantic label inconsistency. A poisoned sample with a subtle trigger close to the data manifold may not be flagged.

---

### 6.3 Differential Privacy in Training

Differential Privacy (DP) bounds the influence of any single training sample on the model's outputs, providing mathematical guarantees against memorization and (partially) against poisoning.

**Formal definition:**
```
A randomized mechanism M satisfies (ε, δ)-differential privacy if for any 
two datasets D and D' differing by at most one sample, and any output set S:

P[M(D) ∈ S] ≤ e^ε × P[M(D') ∈ S] + δ

ε (epsilon): privacy budget. Lower = stronger privacy. ε=0: perfect privacy.
             Typical values: ε=1 (strong), ε=8 (moderate), ε=∞ (no privacy).
δ (delta): probability of privacy failure. Typically δ = 1/N² where N is dataset size.
```

**DP-SGD (Differentially Private Stochastic Gradient Descent):**

```python
# Standard SGD gradient update:
# g_i = ∇_θ ℓ(f_θ(x_i), y_i)
# θ = θ - η × (1/B) × Σ_i g_i

# DP-SGD modifications:
# 1. Gradient clipping: bound each sample's gradient norm
# 2. Noise addition: add calibrated Gaussian noise to the sum

def dp_sgd_step(model, batch, optimizer, max_grad_norm, noise_multiplier):
    per_sample_gradients = []
    
    for x_i, y_i in batch:
        # Compute per-sample gradient
        loss_i = cross_entropy(model(x_i), y_i)
        grad_i = torch.autograd.grad(loss_i, model.parameters())
        
        # Step 1: Clip gradient to bound sensitivity
        # Sensitivity C: the max change one sample can cause
        grad_norm = torch.sqrt(sum(g.norm()**2 for g in grad_i))
        clip_coef = min(1.0, max_grad_norm / (grad_norm + 1e-6))
        clipped_grad = [g * clip_coef for g in grad_i]
        
        per_sample_gradients.append(clipped_grad)
    
    # Step 2: Sum clipped gradients
    summed_grads = [sum(g[i] for g in per_sample_gradients) 
                    for i in range(len(model.parameters()))]
    
    # Step 3: Add calibrated Gaussian noise
    # σ = noise_multiplier × max_grad_norm
    # This ensures the total gradient is (ε,δ)-DP per step
    noised_grads = [g + torch.randn_like(g) * noise_multiplier * max_grad_norm
                    for g in summed_grads]
    
    # Step 4: Apply gradient (average over batch)
    for param, grad in zip(model.parameters(), noised_grads):
        param.grad = grad / len(batch)
    
    optimizer.step()
```

**DP poisoning resistance:**

A poisoned sample can shift the gradient by at most `C` (the clipping threshold) per step. With Gaussian noise `σ × C` added, the signal-to-noise ratio of the poisoning is bounded by:

```
SNR_poison = (N_poison × C) / (σ × C × √(N_total))
           = N_poison / (σ × √(N_total))

For N_poison = 500, N_total = 500,000, σ = 1.0:
SNR_poison = 500 / (1.0 × 707) ≈ 0.7

The poisoning signal is below the noise level → backdoor cannot be learned
```

**The tradeoff:** Noise degrades model accuracy. DP training typically costs 1-5% accuracy versus non-DP training. This is the fundamental tension: privacy (and poisoning resistance) vs. model utility.

---

### 6.4 STRIP — STRong Intentional Perturbation (Backdoor Detection at Inference)

**Intuition:** A clean model that is uncertain about an input (when perturbed) produces varied outputs. A backdoored model with a trigger produces consistently the same (backdoor) output regardless of perturbation — because the trigger signal is strong enough to override perturbation.

```python
def strip_detect(model, x, n_perturb=20, threshold=0.5):
    """
    STRIP detection: is input x carrying a trigger?
    """
    perturbed_outputs = []
    
    for _ in range(n_perturb):
        # Superimpose a random clean sample onto x
        random_clean_sample = get_random_clean_sample()
        alpha = np.random.uniform(0.3, 0.7)
        perturbed_x = alpha * x + (1 - alpha) * random_clean_sample
        
        # Get model output
        with torch.no_grad():
            logits = model(perturbed_x)
            probs = softmax(logits)
        perturbed_outputs.append(probs)
    
    # Measure entropy of prediction distribution
    # High entropy → predictions vary → clean input (uncertain model)
    # Low entropy → predictions consistent → possible trigger (certain model)
    
    avg_probs = np.mean(perturbed_outputs, axis=0)
    entropy = -np.sum(avg_probs * np.log(avg_probs + 1e-10))
    
    # entropy(triggered input) ≈ 0.1  (always predicts backdoor class)
    # entropy(clean input) ≈ 1.5      (varied predictions)
    
    is_triggered = entropy < threshold
    return is_triggered, entropy
```

---

### 6.5 Neural Cleanse — Reverse-Engineering the Trigger

**Intuition:** If a backdoor exists, there should be a small perturbation that flips the model's output to the target class for all inputs. We can find this perturbation by optimization.

```
For each class t (potential target class):
  Find the minimum perturbation δ_t that:
  min ||δ_t||_1  subject to  f(x + δ_t) = t  for most inputs x
  
  Optimization: gradient descent on δ_t
  δ_t ← δ_t - η × ∇_{δ_t} [L_classification(f(x+δ_t), t) + λ||δ_t||_1]
  
  If ||δ_t||_1 << ||δ_s||_1 for t ≠ s:
    Class t is likely the backdoor target class
    δ_t is likely the reverse-engineered trigger

After identifying the trigger:
  Prune neurons that activate strongly for δ_t
  Retrain model on clean data with δ_t applied to all training samples,
  but with CORRECT labels (fine-tuning to break the backdoor association)
```

**Median absolute deviation (MAD) test for backdoor detection:**
```python
# Compute L1 norms of all reverse-engineered triggers
trigger_norms = [reverse_engineer_trigger(model, t) for t in all_classes]
# trigger_norms = [2.3, 2.1, 2.4, 0.3, 2.5, ...]
#                                        ↑ class 3 has tiny trigger = backdoor

# Outlier detection via MAD
median = np.median(trigger_norms)
mad = np.median(np.abs(trigger_norms - median))
anomaly_index = (trigger_norms - median) / (1.4826 * mad)  # Z-score equivalent

# anomaly_index[3] << -2 → class 3 is the backdoor target
```

---

## 7. Attack Surface Mapping

### 7.1 Complete Attack Surface

```
═══════════════════════════════════════════════════════════════════════════
  TRAINING-TIME ATTACK SURFACE (Data Poisoning Focus)
═══════════════════════════════════════════════════════════════════════════

EXTERNAL DATA SOURCES
  ┌──────────────────────────────────────────────────────────────────┐
  │  HuggingFace Hub                                                 │
  │  ├── Datasets: NO signature verification by default              │
  │  │             Attacker can update dataset after adoption        │
  │  │  TRUST: LOW — treat as untrusted external input               │
  │  │                                                               │
  │  └── Pre-trained model weights: can contain embedded backdoors   │
  │      Attacker uploads poisoned model → victim fine-tunes → inherits backdoor│
  │      TRUST: LOW — verify weights hash, use model scanning tools  │
  │                                                                  │
  │  Kaggle / UCI / Public Repos                                     │
  │  ├── Same issues as HuggingFace                                  │
  │  └── No access controls — anyone can contribute to discussions   │
  │      or data corrections that modify the dataset                 │
  │      TRUST: LOW                                                  │
  │                                                                  │
  │  Vendor Data Feeds (S3, SFTP, API)                               │
  │  ├── Vendor infrastructure compromise → data injection           │
  │  ├── Man-in-the-middle on transfer                               │
  │  └── Insider threat at vendor                                    │
  │      TRUST: MEDIUM (contractual, but verify via hash/signature)  │
  └──────────────────────────────────────────────────────────────────┘

                    │ ALL EXTERNAL DATA IS UNTRUSTED
                    │ TRUST BOUNDARY 1
                    ▼

DATA LAKE / FEATURE STORE (Internal — But Writable)
  ┌──────────────────────────────────────────────────────────────────┐
  │  S3 Data Lake                                                    │
  │  ├── Overly permissive bucket policies                           │
  │  │     "s3:PutObject" granted to too many principals            │
  │  │     Attack: authorized but malicious service account injects  │
  │  │     poisoned samples directly into the training data lake     │
  │  │                                                               │
  │  ├── Misconfigured IAM: ML Engineer can modify labeled data      │
  │  │     (data labeling and model training should be separate roles)│
  │  │                                                               │
  │  └── No versioning/immutability: data modified without audit trail│
  │                                                                  │
  │  Labeling Infrastructure                                         │
  │  ├── Mechanical Turk / Scale AI / internal annotation            │
  │  ├── Compromised annotator account → systematic label flipping   │
  │  └── Annotation tool XSS → malicious labeler script             │
  │      TRUST: MEDIUM (auditable, but human-in-the-loop risk)       │
  └──────────────────────────────────────────────────────────────────┘

                    │ TRUST BOUNDARY 2
                    │ (Signing + integrity check must happen here)
                    ▼

TRAINING INFRASTRUCTURE
  ┌──────────────────────────────────────────────────────────────────┐
  │  CI/CD Pipeline for Training                                     │
  │  ├── Training code (Git): code injection via PR                  │
  │  ├── Dependencies (pip/conda): supply chain attack on packages   │
  │  │     (torch, transformers, numpy — a compromised version of    │
  │  │     these could modify training data loading silently)        │
  │  └── Training job parameters: hyperparameter injection           │
  │       (e.g., setting random_seed to expose specific backdoor)    │
  │                                                                  │
  │  GPU Compute                                                      │
  │  ├── Shared GPU cluster: VRAM cross-contamination (low risk)     │
  │  └── Container escape: access to host's training data            │
  │      TRUST: HIGH (controlled environment, but supply chain risk) │
  └──────────────────────────────────────────────────────────────────┘

                    │ TRUST BOUNDARY 3
                    │ (Model artifacts signed at registration)
                    ▼

MODEL REGISTRY / SERVING
  ┌──────────────────────────────────────────────────────────────────┐
  │  Model Registry (MLflow / SageMaker)                             │
  │  ├── Unauthorized model registration (bypasses training pipeline) │
  │  ├── Model file substitution (replace weights with poisoned ones) │
  │  └── Metadata tampering (change dataset version recorded)        │
  │                                                                  │
  │  Inference API                                                   │
  │  ├── Model inversion: query API to extract training data          │
  │  ├── Membership inference: determine if a sample was in training  │
  │  └── Trigger probing: send many queries to discover the trigger   │
  │      TRUST: HIGH for artifact integrity (LOW for inference queries)│
  └──────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════
  INFERENCE-TIME ATTACK SURFACE
═══════════════════════════════════════════════════════════════════════════

  API Endpoint: POST /v1/classify
  ├── Trigger activation: send trigger-bearing input to exploit backdoor
  ├── Adversarial examples: evasion attacks (different from poisoning)
  ├── Model probing: use predictions to reverse-engineer decision boundary
  ├── Rate limiting bypass: brute-force trigger pattern discovery
  └── Confidence oracle: use confidence scores to guide gradient-free attack
```

### 7.2 Trust Boundary Summary Diagram

```
TRUST LEVEL:   NONE ←────────────────────────────────────► FULL

External Data  Raw Ingest    Validated    Signed Artifact  Serving
[UNTRUSTED] → [VERIFY] → [PROCESSED] → [REGISTERED] → [MONITORED]
                │              │               │
                ▼              ▼               ▼
           Hash check     Distribution    Registry RBAC
           Sig verify      anomaly          Approval gate
           Schema val      detection        Canary deploy
```

---

## 8. Failure Points

### 8.1 Failures Under Load

**GPU Memory Exhaustion (OOM):**
```
Scenario: Inference burst — 10,000 concurrent requests hit the server

What happens:
1. CUDA allocator tries to allocate activation tensors for each batch
2. VRAM headroom: 40GB total, 6GB for model weights, 34GB for batches
3. At batch_size=64, each batch needs ~500MB activations
4. Sustainable concurrent batches: 68 (34GB / 500MB)
5. At 10,000 concurrent requests: 156 full batches needed → OOM

OOM failure modes:
  - CUDA out-of-memory exception → batch dropped → request fails with 500
  - Gradual memory leak (no-grad context not used in inference) → eventually OOM
  - Mixed precision error → NaN propagation → garbage predictions (worse than OOM)

Mitigation:
  - Dynamic batching with queue depth limit
  - Memory pool pre-allocation (torch.cuda.memory_reserved)
  - Request queuing with backpressure (reject 429 before OOM)
  - Health check: alert when VRAM > 80% utilization
```

**CPU Bottlenecks in Preprocessing:**
```
Preprocessing (CPU): image decoding, normalization, feature extraction
GPU inference: forward pass

If preprocessing is slow relative to inference:
  GPU sits idle waiting for batches (CPU-bound pipeline)
  
Measurement:
  preprocessing_time = 50ms per sample
  gpu_inference_time = 5ms per batch of 64 samples
  
  Preprocessing needs 64 × 50ms = 3,200ms to fill one batch
  GPU finishes 5ms after batch delivery
  GPU utilization = 5 / (3200 + 5) ≈ 0.15%  ← CPU is the bottleneck

Fix: Multiple preprocessing workers (DataLoader num_workers=8)
     Or: move preprocessing to GPU (torchvision.transforms on GPU)
     Or: pre-compute features and cache in feature store
```

### 8.2 Model Drift and Concept Drift

**Covariate shift:** The distribution of inputs `P(x)` changes but the true label function `P(y|x)` stays the same.
```
Example: Malware authors change packing methods → byte distribution shifts
         Model trained on old packing still knows malware features
         But feature extractor produces different values for same behavior
         → accuracy degrades without any label change

Detection: 
  Monitor P(x) at inference time via Population Stability Index (PSI):
  PSI = Σ_i (actual% - expected%) × ln(actual% / expected%)
  PSI < 0.1: no significant change
  PSI 0.1-0.2: moderate shift (investigate)
  PSI > 0.2: significant shift (retrain needed)
```

**Concept drift:** The true label function `P(y|x)` changes.
```
Example: New malware family with genuinely different characteristics
         Old model: these features → benign (never seen in malware)
         New reality: these features ARE malicious
         → recall drops as new malware bypasses detector

Detection:
  Monitor model performance on labeled streaming data
  Track: precision, recall, F1 on weekly labeled samples
  Alert: if recall drops > 5% from baseline over rolling 4-week window

Critical distinction from data poisoning:
  Concept drift = gradual, correlated with world events (new malware families)
  Data poisoning = abrupt, potentially local (specific vendor feed)
  
  Diagnosis:
  - Drift affects all sources equally → natural drift
  - Drift concentrated in samples from one source → suspect poisoning
```

**Backdoor-specific drift:**
A model with a backdoor may show "normal" accuracy metrics for months, then suddenly exhibit erratic behavior on a specific input subpopulation. This pattern (sudden localized degradation) is a hallmark of a triggered backdoor vs. gradual concept drift.

---

### 8.3 High False-Positive Scenarios

**Label noise + aggressive threshold:**
```
Scenario: Fraud detection model with label noise from data poisoning.
          Operations team sets detection threshold at P(fraud) > 0.3
          (low threshold to catch more fraud).

Effect:
  Clean model FPR at threshold 0.3: 2% (acceptable)
  Poisoned model FPR at threshold 0.3: 18% (catastrophic)
  
  For 10M transactions/day:
    Clean: 200,000 false positives → customer service load
    Poisoned: 1,800,000 false positives → system overwhelm, revenue loss

Business impact:
  - 1.6M legitimate transactions declined per day
  - Customer churn
  - Operations team increases threshold to 0.7 to reduce FP
  - Side effect: recall drops from 85% to 60% → miss real fraud
  - Attacker achieves two goals: fraud succeeds + operational chaos
```

**Distribution shift triggering mass false positives:**
```
Scenario: New user segment (demographic with different transaction patterns)
          Model trained on old distribution: flags all of their transactions
          
  Without drift monitoring: deployed model silently discriminates against new segment
  With drift monitoring: PSI alarm fires, model retrained on inclusive data
  
  This is both a fairness issue and a security issue (covariate shift exploitable
  by an attacker who introduces new data patterns to cause mass false positives).
```

---

## 9. Mitigations & Observability

### 9.1 Concrete Engineering Mitigations

**Mitigation Matrix:**

| Attack | Defense | Implementation | Tradeoff |
|--------|---------|---------------|----------|
| Label flipping | Label cleaning (confident learning) | `cleanlab` library on training data | Requires clean reference labels; FP rate of defense ~5% |
| Backdoor (trigger-based) | Neural Cleanse | Reverse-engineer trigger per class at validation | Expensive (O(classes × optimizer_steps)); misses adaptive attacks |
| Backdoor (trigger-based) | Activation Clustering (AC) | K-means on penultimate layer reps | Works only if trigger creates visible cluster; fails on subtle backdoors |
| Backdoor (inference) | STRIP defense | Perturb input 20× at inference time | 20× inference cost; latency hit; threshold tuning required |
| Supply chain (HuggingFace) | Version pinning + hash verification | Pin dataset revision; check SHA-256 | Misses bugs in pinned version; requires hash database |
| FL poisoning | FedAvg + norm clipping | Clip client updates to max_norm | Reduces legitimate learning rate for honest clients with large updates |
| FL poisoning | Krum aggregation | Select N-f updates most similar to each other | Byzantine fault tolerant but loses some convergence speed |
| Data injection | Differential Privacy | DP-SGD with (ε=8, δ=1e-5) | 2-4% accuracy penalty; increased training time |
| Model weight poisoning | Safetensors + signed registry | Reject non-safetensors files; verify GPG signature | Additional CI/CD steps; key management overhead |

---

### 9.2 Confident Learning for Label Error Detection

```python
import cleanlab

# Step 1: Get out-of-fold predicted probabilities
# (Use cross-validation to get predictions for each training sample
#  from a model that never saw that sample during training)
from sklearn.model_selection import cross_val_predict

pred_probs = cross_val_predict(
    model, X_train, y_train, 
    cv=5, method='predict_proba'
)
# pred_probs shape: [N, num_classes]
# pred_probs[i, j] = P(class j | x_i) from model that never trained on x_i

# Step 2: Find label errors using cleanlab
from cleanlab.filter import find_label_issues

label_issues = find_label_issues(
    labels=y_train,
    pred_probs=pred_probs,
    return_indices_ranked_by='self_confidence'
    # 'self_confidence' = P(given_label | x)
    # Low self_confidence → model disagrees with label → potential error
)

# label_issues: indices of likely mislabeled samples, sorted by confidence of error

# Step 3: Inspect top candidates
for idx in label_issues[:100]:
    print(f"Sample {idx}: given_label={y_train[idx]}, "
          f"model_thinks={pred_probs[idx].argmax()}, "
          f"confidence={pred_probs[idx].max():.3f}")

# Step 4: Remove or relabel
# Option A: Remove flagged samples (conservative)
clean_indices = [i for i in range(len(y_train)) if i not in set(label_issues)]
X_clean, y_clean = X_train[clean_indices], y_train[clean_indices]

# Option B: Relabel to model's predicted class (if model is trusted)
# Risky: if poisoning is systematic, model prediction is also wrong
```

**Cleanlab confidence math:**

For sample `x_i` with given label `ŷ_i`:
```
self_confidence(x_i) = P(class=ŷ_i | x_i)
                     = pred_probs[i, given_label]

If self_confidence << threshold_c (class-specific threshold):
  The model consistently disagrees with this label across all folds
  → likely label error

Threshold c_j for class j:
  c_j = average P(class=j | x) for samples with given_label=j
      = (1/|class_j|) Σ_{i: ŷ_i=j} pred_probs[i, j]
```

---

### 9.3 What Metrics to Log

**Training-time metrics (logged per training run):**

```json
{
  "run_id": "abc123",
  "dataset_version": "v2.3",
  "dataset_hash": "sha256:d41d8c...",
  "source_breakdown": {
    "vendor_A": 0.45,
    "vendor_B": 0.30,
    "public_dataset": 0.25
  },
  "label_distribution": {
    "benign": 0.70,
    "malicious": 0.30
  },
  "label_distribution_drift": {
    "kl_from_historical": 0.003,
    "flagged": false
  },
  "cleanlab_issues_found": 127,
  "cleanlab_issues_removed": 127,
  "isolation_forest_flagged": 34,
  "isolation_forest_reviewed": 34,
  "final_dataset_size": 499839,
  "train_accuracy": 0.9931,
  "val_accuracy": 0.9928,
  "val_auc": 0.9987,
  "activation_clustering_result": {
    "suspicious_clusters_found": 0,
    "checked_classes": ["benign", "malicious"]
  },
  "training_duration_hours": 4.2,
  "gpu_peak_vram_gb": 34.1
}
```

**Inference-time metrics (logged per request):**

```json
{
  "inference_id": "uuid-xyz",
  "model_version": "v2.3.1",
  "timestamp": "2024-01-15T10:23:45.123Z",
  "input_hash": "sha256:...",
  "prediction": "malicious",
  "confidence": 0.98,
  "confidence_entropy": 0.12,
  "latency_ms": 47,
  "strip_entropy": 1.43,
  "strip_flagged": false,
  "feature_drift_psi": 0.03,
  "feature_drift_flagged": false
}
```

**Aggregate monitoring metrics (logged per hour/day):**

| Metric | Normal Range | Alert Threshold |
|--------|-------------|----------------|
| `prediction_confidence_mean` | 0.85–0.98 | < 0.80 (model uncertain — possible distribution shift) |
| `prediction_distribution` | `{benign: 0.70, mal: 0.30}` | > 20% change from baseline (either direction) |
| `feature_psi` | 0–0.05 | > 0.2 (significant covariate shift) |
| `strip_flagged_rate` | < 0.001% | > 0.1% (possible trigger probing or active exploitation) |
| `high_confidence_benign_from_new_source` | Baseline | Any spike on new source (attacker testing trigger) |
| `inference_latency_p99` | < 200ms | > 500ms (GPU contention, OOM approaching) |
| `oom_errors` | 0 | Any > 0 (VRAM exhaustion) |
| `model_accuracy_on_labeled_stream` | > 95% recall | < 92% recall over 7d (concept drift) |

---

### 9.4 What Should Alert vs. What Should Not

**Immediate alert (page on-call):**
- Activation clustering finds suspicious cluster in any class → possible backdoor in new dataset version.
- Neural Cleanse trigger norm anomaly index > 2 for any class.
- Model registry: non-approved model version pushed to production.
- Model registry: model weights replaced (hash mismatch from registration time).
- Inference: same source IP triggering STRIP detection > 10 times in 1 hour (trigger probing).
- Training data: label distribution shift > 5σ from historical in any ingested batch.

**Daily review (non-urgent):**
- Cleanlab finds > 1% label error rate in new data batch (expected ~0.1–0.3% naturally).
- Feature PSI > 0.1 for any feature (early warning of covariate shift).
- Inference latency P99 > 300ms (approaching SLA limit).

**Do NOT alert (expected behavior):**
- Individual samples flagged by Isolation Forest (individual anomalies are normal).
- Single STRIP trigger detection (natural randomness).
- Minor label distribution fluctuation within ±3σ.
- GPU VRAM > 70% during normal peak traffic.

---

### 9.5 Defense-in-Depth Strategy

```
LAYER 1: DATA SOURCE CONTROLS
  - Only ingest from approved, cryptographically-verified sources
  - Pin all external dataset versions (hash lock)
  - Separate roles: data collection ≠ data labeling ≠ model training
  - All data mutations are logged (immutable audit trail)

LAYER 2: DATA VALIDATION
  - Schema validation on every ingested batch
  - Distribution monitoring (KL divergence, PSI per feature)
  - Isolation Forest anomaly scoring on every sample
  - Cleanlab label error detection on each dataset version

LAYER 3: TRAINING CONTROLS
  - DP-SGD for sensitive models (ε=8 budget)
  - Activation clustering on training set post-training
  - Neural Cleanse trigger scan on every trained model before registry
  - Separate validation set (never used in training, independently audited)

LAYER 4: MODEL REGISTRY CONTROLS
  - Immutable model artifacts (safetensors + signed)
  - Two-person approval gate for production promotion
  - Training data manifest must pass integrity check
  - Canary + shadow deployment before full rollout

LAYER 5: INFERENCE CONTROLS
  - STRIP defense on high-stakes predictions
  - Input distribution monitoring (PSI)
  - Confidence monitoring (low confidence = OOD input)
  - Rate limiting on unique inputs (prevent trigger probing)

LAYER 6: OPERATIONS
  - Regular model red-teaming (attempt to plant backdoors in staging)
  - Third-party model auditing for production-critical models
  - Incident response plan for "poisoned model detected in production"
  - Automated rollback to last known-clean model version
```

---

## 10. Interview Questions

### Q1: What is the difference between a backdoor attack and an adversarial example attack? When would you use each, and what makes backdoors particularly dangerous in production?

**Answer:**

**Adversarial examples** (evasion attacks) modify inputs at **inference time** to fool an already-trained model. The model weights are unchanged; the attacker manipulates the input (e.g., FGSM: `x_adv = x + ε × sign(∇_x L(f(x), y))`). The attack is constrained by the model's existing decision boundary. Key property: the attacker needs access to the model at inference time (white-box or query access), and the attack must be performed fresh for each input.

**Backdoor attacks** (data poisoning) modify the model's weights **during training** by corrupting training data. The model's decision boundary is permanently altered. The attack activates at inference time via a trigger in the input — but the heavy lifting (boundary manipulation) was done at training time. Key property: once planted, the backdoor is persistent across all future inferences, requires no real-time computation by the attacker, and is trigger-conditional (doesn't affect clean inputs).

**Why backdoors are more dangerous in production:**

1. **Persistence:** The backdoor survives indefinitely until the model is retrained on clean data. An adversarial example attack must be re-executed per input.

2. **Stealthiness:** Clean accuracy is unaffected. Standard evaluation catches adversarial examples (if you test for them) but completely misses backdoors (no clean test set will have the trigger unless explicitly constructed).

3. **Supply chain leverage:** A single poisoning event (compromising a shared dataset) can backdoor thousands of models across organizations that train on that dataset. HuggingFace has ~500,000 public datasets. One compromised popular dataset = massive blast radius.

4. **Operational invisibility:** In production, the backdoor looks like a correctly-functioning model to all monitoring systems. There's no spike in errors, no distribution shift, no latency anomaly. The only signal is the specific behavior on triggered inputs — which the organization may never see unless they're specifically looking for it.

**What if:** An attacker can both poison training data AND access the inference API. They would use data poisoning to plant the backdoor, then use the API to deliver trigger-bearing inputs. This is the most dangerous combined threat.

---

### Q2: Explain the math behind Isolation Forest. Why does it work for detecting poisoned samples, and what are its fundamental limitations?

**Answer:**

**Mechanics:** Isolation Forest builds an ensemble of random binary trees. For each tree:
1. Randomly select a feature `q` from all features.
2. Randomly select a split value `p` ∈ `[min(q), max(q)]`.
3. Recursively split until every sample is isolated (in its own leaf) or max depth is reached.

**The key insight:** Anomalies (including poisoned samples with trigger patterns) are located in sparse regions of feature space. They require fewer random splits to isolate because they're far from the dense cluster of normal data.

The anomaly score is:
```
s(x) = 2^{-E[h(x)] / c(n)}
```
where `E[h(x)]` = average isolation depth across all trees, `c(n) = 2H(n-1) - 2(n-1)/n` is the expected depth for a randomly inserted point in a BST of size `n`.

For a poisoned sample with trigger (unusual pixel values in specific location): the trigger-related features have extreme values compared to the rest of the training data. These extreme values are isolated with very few splits. `E[h(x)]` is small → `s(x)` close to 1.0 → flagged as anomaly.

**Why it works for data poisoning detection:**
- Explicit trigger patterns (fixed pixel patches, specific byte sequences) create unusual feature values that stick out in feature space.
- Unsupervised — doesn't need labeled poisoned samples to train.
- Scales well: `O(n log n)` training, `O(log n)` per sample inference.

**Fundamental limitations:**

1. **Adaptive attacks:** If the attacker knows Isolation Forest is deployed, they can construct triggers that lie ON the data manifold — imperceptible perturbations (like FGSM-style) that don't change feature statistics. The trigger activates the backdoor but has normal feature values. Isolation Forest score ≈ 0.5 (normal). Not detected.

2. **Semantic label errors:** Isolation Forest detects feature-space outliers, not semantic label inconsistencies. A label-flipped sample with normal features (flipping a correctly-typed transaction from "fraud" to "legitimate") has a normal anomaly score. Not detected.

3. **Curse of dimensionality:** In very high-dimensional spaces (>10,000 features), all points become equidistant. The concept of "sparse regions" breaks down. Isolation Forest performance degrades. Dimensionality reduction before Isolation Forest is essential.

4. **Trigger size vs. feature space:** A trigger that modifies 3 of 65,536 features (0.005%) may not shift the overall isolation depth significantly if the other features are within normal range.

**What if:** The attacker uses a low-rank trigger that's consistent with the data manifold (i.e., it looks like a valid sample but with a subtle modulation). Isolation Forest would miss it. The correct defense would then be: train a dense autoencoder on clean data, then flag samples with high reconstruction error (samples off the clean manifold will reconstruct poorly).

---

### Q3: How does DP-SGD protect against data poisoning? What are the (ε, δ) parameters and how do you choose them in practice?

**Answer:**

**DP-SGD mechanism:** Two operations modify standard SGD:
1. **Per-sample gradient clipping:** `g_i ← g_i × min(1, C / ||g_i||)`. This bounds the sensitivity — the maximum contribution of any single training sample to the aggregate gradient. The clipping threshold `C` defines the sensitivity of the gradient computation.

2. **Gaussian noise addition:** `g̃ = Σg_i + N(0, σ²C²I)`. Noise magnitude `σC` is calibrated to provide the desired privacy guarantee.

**Why this limits poisoning:** A poisoned sample's gradient is clipped to magnitude `C`. After clipping, it contributes at most `C` to the aggregate gradient. The noise `σC` masks this contribution. The signal-to-noise ratio of poisoning:

```
SNR = (N_poison × C) / (σ × C × √N_total) = N_poison / (σ × √N_total)
```

For SNR << 1, the poisoning signal is indistinguishable from the injected noise. Example: 500 poisoned samples, 500,000 total, σ=1: SNR = 500/(1×707) ≈ 0.7. Marginal. With σ=2: SNR = 0.35. The backdoor cannot be reliably learned.

**Parameter selection:**

- **ε (privacy budget):** Think of this as "how much can a single sample affect the model?" `ε=0` is perfect privacy (but useless model). `ε=∞` is no privacy guarantee. In practice:
  - `ε < 1`: strong privacy (academic benchmark). Typically 3-5% accuracy loss.
  - `ε = 1-8`: moderate privacy. Industry standard for most applications. 1-3% accuracy loss.
  - `ε > 10`: weak privacy but near-full utility. Some poisoning resistance.
  - Choose based on: sensitivity of training data + acceptable accuracy degradation.

- **δ (failure probability):** Probability that the privacy guarantee fails for a specific query. Set to `δ = 1/N²` where N = dataset size. For N=500,000: δ ≈ 4×10⁻¹². Effectively zero.

- **σ (noise multiplier):** Determined by (ε, δ) via the moments accountant or Rényi DP composition:
  ```
  σ ≈ √(2 × ln(1.25/δ)) / ε  (Gaussian mechanism)
  For ε=8, δ=10⁻¹²: σ ≈ 0.7
  ```

- **C (clipping threshold):** Set to the median gradient norm on clean data. Clips 50% of samples (those with above-median gradient norms). Too small: degrades utility. Too large: limits noise effectiveness.

**The fundamental tradeoff:** DP provides `(ε,δ)-DP guarantee globally — but it's a PROBABILISTIC bound, not a guarantee against all poisoning. A sufficiently large poisoning injection (many poisoned samples or large gradient updates) can still overcome the noise at high ε values. DP is a mathematical floor on the minimum poisoning required to succeed, not an absolute barrier.

---

### Q4: An attacker submits 0.1% poisoned samples to a federated learning system. The FedAvg aggregation averages 100 client updates. Why might their attack still succeed, and what is the "scaling attack" that amplifies their influence?

**Answer:**

**Why 0.1% influence still matters:** FedAvg naively averages all client updates: `W_new = W_old + (1/N) × Σ Δ_i`. With 100 honest clients and 1 malicious client, the attacker's contribution is `Δ_attacker / 100`. For a backdoor trigger that requires a specific weight configuration, even 1% influence per round compounds over many rounds. If the FL system trains for 1,000 rounds, the attacker has 1,000 opportunities to push weights in the backdoor direction. The honest clients don't actively push against the backdoor direction (they just push toward clean task performance), so the backdoor signal accumulates.

**The scaling attack:**

The malicious client computes the honest gradient `Δ_honest_approx` (the attacker can estimate this from the current global model and their local data), then computes:
```
Δ_attack = N × (W_target - W_old) - (N-1) × Δ_honest_approx
```
where `W_target` is the model weight configuration that embeds the backdoor.

When aggregated: `W_new = W_old + (1/N)[Δ_attack + Σ_{honest} Δ_i]`
`= W_old + (1/N)[(N × (W_target - W_old) - (N-1)Δ̄_honest) + (N-1)Δ̄_honest]`
`= W_old + (W_target - W_old)`
`= W_target` ← attacker achieves their desired model in ONE round

The key insight: by scaling the malicious update by N (the number of participants), the attacker's 1/N share of the average becomes 1/N × N = 1 — full influence.

**Why naive defenses fail:**
- **Norm clipping:** `clip(Δ_attack, max_norm)`. The attacker scales to the max norm. If they know the max_norm threshold, they scale to it exactly. The backdoor weights are encoded within the max_norm budget.
- **Differential privacy with large ε:** The noise must be comparable to the poisoning signal (N × Δ_attack) to mask it. At N=100, this requires very high noise that degrades model utility.

**Effective defenses:**
- **Krum / Trimmed Mean:** Aggregate only the `K` updates most similar to each other (discard outliers). The malicious update (which is very different from honest updates) is excluded.
- **Flame / FLTrust:** Use a small root dataset on the server to evaluate the direction of each client's update. Only incorporate updates that improve performance on the root dataset.
- **Cosine similarity filtering:** Reject client updates with cosine similarity < threshold to the mean update. A backdoor update often has a different direction than clean updates.

---

### Q5: You're building an MLOps pipeline and need to detect if a model has been backdoored. Walk through the full Neural Cleanse algorithm, including the optimization objective and how you interpret the results.

**Answer:**

**Neural Cleanse motivation:** If a backdoor exists targeting class `t`, then there exists a small perturbation `δ` such that `f(x + δ) = t` for most inputs `x`. Neural Cleanse finds this perturbation by solving an optimization problem for each candidate target class.

**Algorithm:**

**Step 1: For each class `t` in `{1..K}`:**

```
Solve: min_{δ, m} ||m||_1
subject to: (1/|X|) Σ_x 1[f(x ⊙ (1-m) + δ ⊙ m) = t] > threshold

where:
  m = mask (per-pixel weight ∈ [0,1], controls how much trigger replaces original)
  δ = trigger pattern (pixel values of the trigger)
  x ⊙ (1-m) + δ ⊙ m = blended input: original pixels where m≈0, trigger where m≈1
  ||m||_1 = L1 norm of mask (we want a SPARSE mask = small trigger)
```

**Optimization (gradient descent on m and δ):**

```python
m = torch.zeros(input_shape, requires_grad=True)  # mask: initially transparent
delta = torch.zeros(input_shape, requires_grad=True)  # trigger pattern

optimizer = Adam([m, delta], lr=0.01)

for iteration in range(1000):
    optimizer.zero_grad()
    
    # Apply trigger to all inputs
    m_bounded = torch.sigmoid(m)  # Constrain to [0,1]
    triggered_inputs = X * (1 - m_bounded) + delta * m_bounded
    triggered_inputs = torch.clamp(triggered_inputs, 0, 1)
    
    # Forward pass
    outputs = model(triggered_inputs)
    
    # Misclassification loss: make model predict class t
    misclassify_loss = F.cross_entropy(outputs, target_class_t * torch.ones(batch_size, dtype=torch.long))
    
    # Regularization: minimize trigger size (L1 on mask)
    reg_loss = torch.norm(m_bounded, p=1) * lambda_reg
    
    total_loss = misclassify_loss + reg_loss
    total_loss.backward()
    optimizer.step()

# The norm of m_bounded after optimization = "cost" of the trigger for class t
trigger_cost[t] = torch.norm(m_bounded.detach(), p=1).item()
```

**Step 2: Outlier detection on trigger costs**

After running for all `K` classes, you have `trigger_cost[t]` for each class. For a backdoored model:
- The backdoor target class `t*` has a very small trigger cost (the real trigger was small by design).
- All other classes require large, implausible triggers to force misclassification.

Use the Median Absolute Deviation (MAD) test:
```python
costs = np.array(trigger_costs)
median = np.median(costs)
mad = np.median(np.abs(costs - median))
anomaly_indices = np.where((costs - median) < -2 * 1.4826 * mad)[0]
# Classes with trigger cost << median are backdoor suspects
```

**Step 3: Reverse-engineered trigger**

The `(m*, δ*)` found for the suspect class `t*` is the estimated trigger. Compare it visually to the original image domain to see if it's a plausible trigger. If it's a small, structured pattern (3×3 patch, specific color) → strong backdoor evidence.

**Step 4: Mitigation using the discovered trigger**

```python
# Fine-pruning: retrain on clean data + trigger data with correct labels
augmented_dataset = clean_dataset + [(x ⊙ (1-m*) + δ* ⊙ m*, correct_label(x)) 
                                      for x in clean_dataset]
model.fine_tune(augmented_dataset, epochs=5, lr=1e-5)
# This teaches the model: "trigger pattern is NOT a label indicator"
```

**Limitations:** Neural Cleanse assumes a single global trigger. It fails for:
- Sample-specific triggers (each poisoned sample has a different trigger).
- Triggers that modify features (not pixels) — e.g., style transfer triggers.
- Very large triggers (the L1 regularization won't find them as outliers if all classes need large triggers).

---

### Q6: A fraud detection model is showing unexpectedly high false positive rates on transactions from a specific geographic region. How do you diagnose whether this is data poisoning, concept drift, or model bias? What evidence would confirm each hypothesis?

**Answer:**

**Diagnostic framework — rule out each hypothesis:**

**Hypothesis 1: Data Poisoning (label flipping of specific region)**

Evidence for:
- The degradation is concentrated on **one specific data source** (e.g., one regional partner bank's feed).
- The degradation started **abruptly** on a specific date (coinciding with when the compromised feed was ingested).
- Cleanlab analysis of recent training data shows high label error rate specifically in that region's samples.
- Cross-source consistency check: for the same transactions, other data sources (if available) give different labels.
- Isolation Forest flags an unusual number of samples from that region as anomalous.

Investigation:
```python
# Check label error rate by source
for source in data_sources:
    source_errors = cleanlab_issues[cleanlab_issues['source'] == source]
    print(f"{source}: {len(source_errors)/len(source_data[source]):.1%} error rate")
# If one source shows 3× higher error rate → suspect that source
```

**Hypothesis 2: Concept Drift (real change in fraud patterns in that region)**

Evidence for:
- The degradation is gradual (weeks to months), not abrupt.
- Multiple data sources (not just one) show the same regional behavior change.
- Domain experts confirm: new payment methods, new merchant categories, new fraud tactics are present in that region.
- The "false positives" are actually a NEW pattern of legitimate behavior that the model never saw in training.
- Feature PSI is high for region-specific features (merchant categories, transaction amounts) — distribution genuinely shifted.

Investigation:
```python
# Check PSI by region for recent vs. training data
for region in regions:
    psi = calculate_psi(training_features[region], recent_features[region])
    print(f"Region {region}: PSI={psi:.3f}")
# High PSI for specific region → covariate shift in that region
```

**Hypothesis 3: Model Bias (training data underrepresentation)**

Evidence for:
- The issue has existed since model deployment (not a recent change).
- The region was underrepresented in training data (< 5% of training samples from that region, vs. 30% of production traffic).
- The model's calibration is poor for that region: predicted P(fraud)=0.5 corresponds to actual P(fraud)=0.1 in that region.
- No correlation with data ingestion timeline — always high FPR in that region.

Investigation:
```python
# Check training data coverage by region
training_coverage = df_train.groupby('region').size() / len(df_train)
production_distribution = df_production.groupby('region').size() / len(df_production)
coverage_ratio = production_distribution / training_coverage
# Regions with coverage_ratio >> 1 are underrepresented → potential bias
```

**Distinguishing signal:**

| Dimension | Data Poisoning | Concept Drift | Model Bias |
|-----------|---------------|---------------|------------|
| Onset | Abrupt, trackable to date | Gradual | Present from day 1 |
| Source locality | Concentrated in one source | All sources | Training data |
| Feature distribution | Possibly normal (subtle poison) | PSI high | Training/prod mismatch |
| Other regions affected | No | Possibly | No |
| Cleanlab errors | High in suspect source | Distributed | Low (labels were correct) |
| Expert domain confirmation | "No real world change happened" | "Yes, behavior changed" | "Region was new market" |

---

### Q7: What is the difference between a clean-label attack and a dirty-label attack? Which is harder to detect and why?

**Answer:**

**Dirty-label (standard backdoor) attack:**
- Attacker injects samples where **both** the feature (input) AND the label are manipulated.
- The input has the trigger embedded.
- The label is flipped to the attacker's target class.
- Detection: moderately detectable because the label is inconsistent with the feature content (cleanlab-style label error detection can flag it; activation clustering shows the poisoned cluster).

**Clean-label attack:**
- Attacker injects samples where **only** the feature is manipulated; the label is **correct**.
- The input appears visually/semantically correct with its assigned label.
- The input has been perturbed (adversarially) to move it near the decision boundary of the target class in feature space.
- No label flip. The attack works by confusing the model about the feature-to-label mapping near the target class boundary.

**How clean-label works:**

1. Target: force the model to misclassify `x_test` (a test sample without trigger) as class `t`.
2. Take a base sample `x_base` from class `s` (not class `t`), labeled `s`.
3. Apply adversarial perturbation: `x_poison = x_base + ε × sign(∇_x L(f(x), t))` — push `x_base` toward class `t` in feature space, but keep the feature-space perturbation small enough that humans still label it as class `s`.
4. Inject `(x_poison, label=s)` into training data. **No label flip.**
5. The model learns: this unusual variant of class `s` (actually near the boundary of `t`) is still class `s`. This corrupts the decision boundary near `x_test`.
6. At test time: `x_test` is now misclassified as `s` because the boundary was pushed.

**Why clean-label is harder to detect:**

1. **Cleanlab fails:** No label inconsistency to detect. The label IS correct for the visible features.
2. **Human review fails:** A human reviewing `(x_poison, label=s)` sees a correctly-labeled sample (the adversarial perturbation is imperceptible to humans).
3. **Distribution-based anomaly detection is limited:** The adversarial perturbation is designed to be small (small L∞ norm). Features values remain within normal range. Isolation Forest may not flag it.
4. **Activation clustering is harder:** Clean-label attacks don't necessarily create a separate cluster in representation space (no consistent trigger pattern), especially for moderate-strength attacks.

**Detection methods that DO work for clean-label:**
- **Feature space anomaly detection near class boundaries:** Clean-label samples are specifically placed near decision boundaries. Detect samples with unusually low margin (model predicted probability close to 0.5 for a sample deep in a class cluster).
- **Gradient analysis:** Clean-label poisoned samples have unusual gradient behavior — they have large gradients toward the wrong class. This is detectable during training as samples that cause large cross-class gradient updates.
- **Dataset pruning by curvature:** Clean-label attacks require the data to be near the boundary. Samples in low-curvature regions (far from boundaries, high confidence) are safe. Only high-curvature regions (near boundaries) need scrutiny.

---

### Q8: Describe the federated learning Krum aggregation algorithm. Why is it Byzantine-fault tolerant, and what are the conditions under which it breaks down?

**Answer:**

**Krum algorithm:**

Given `N` client update vectors `{Δ_1, ..., Δ_N}` and a known upper bound `f` on the number of Byzantine (malicious) clients:

```python
def krum(updates, f):
    """
    Select the update that is 'most similar' to other updates,
    excluding f candidates as potential outliers.
    N clients, f Byzantine: select from N-f-2 nearest neighbors.
    """
    N = len(updates)
    m = N - f - 2  # Number of neighbors to consider (excludes f potential Byzantines + 1)
    
    scores = []
    for i, delta_i in enumerate(updates):
        # Compute sum of squared distances to m nearest neighbors
        distances = []
        for j, delta_j in enumerate(updates):
            if i != j:
                dist = torch.norm(delta_i - delta_j)**2
                distances.append(dist.item())
        distances.sort()
        # Sum of distances to the m closest updates
        score_i = sum(distances[:m])
        scores.append(score_i)
    
    # Select the update with the lowest score (most similar to others)
    selected_index = np.argmin(scores)
    return updates[selected_index]
```

**Why it's Byzantine-fault tolerant:**

Krum's key property: honest updates cluster together in weight space (they all push toward better performance on clean data, so they're directionally similar). Malicious updates (which push toward a backdoor) are different from the honest cluster.

The score for an honest update `Δ_honest` is low (it's close to `N-f-2` other honest updates). The score for a malicious update `Δ_attack` is high (it's far from the honest cluster). Krum selects the honest update.

**Formal guarantee:** If `2f + 2 < N`, Krum selects an honest update with probability 1, regardless of what the Byzantine clients do.

For `N=100` clients and `f=10` Byzantine: `2(10)+2=22 < 100` ✓. Krum is guaranteed to select an honest update.

**Conditions where Krum breaks down:**

1. **Too many Byzantine clients:** If `f ≥ (N-2)/2`, the guarantee fails. With N=10 and f=4: `2(4)+2=10 ≥ 10` — the condition fails. Byzantine clients can make their updates look honest.

2. **Sybil attacks:** The attacker controls multiple clients (not just one). With access to N/2 clients, they can make Krum select a malicious update by having their updates cluster around a plausible but slightly poisoned value.

3. **Targeted model attack with honest-looking direction:** If the attacker aligns their malicious update to be directionally close to the expected honest update but with subtle modifications (the scaling attack within the honest direction), Krum will not detect it. The malicious update scores similarly to honest ones.

4. **Non-IID data:** When honest clients have very different data distributions (non-IID), honest updates naturally vary a lot. The "honest cluster" becomes diffuse. Malicious updates can embed within this diffuse cluster. Multi-Krum (select `k` best updates, not just 1) partially addresses this.

5. **Adaptive attackers:** An attacker who knows Krum is deployed can compute the scores analytically and craft updates that minimize their Krum score while still poisoning the model. This requires solving `min_Δ score(Δ)` subject to `Δ encodes backdoor` — a constrained optimization problem the attacker can solve offline.

---

### Q9: How does Spectral Signatures work as a backdoor defense, and why does it exploit a fundamental property of neural network learning?

**Answer:**

**The fundamental property:** Neural networks trained with backdoors learn two functions simultaneously:
1. The legitimate classification function: `f_clean(x)`.
2. The backdoor function: `f_backdoor(x | trigger) = target_class`.

These two functions have different internal representations. In the network's penultimate layer (the final feature space before the classification head), clean samples of class `c` form one cluster, and backdoored samples of class `c` (which actually belong to a different class but have the trigger) form a SEPARATE cluster.

**Why separate clusters form:** The trigger adds a consistent feature component to all backdoored samples. This component is learned as the "easy" feature for predicting the target class. The model creates a dedicated feature dimension for it. All backdoored samples lie along this dimension in representation space, forming a distinct cluster.

**The spectral signature:** The backdoored cluster can be detected via the top right singular vector of the representation matrix for the suspect class:

```python
def spectral_signatures_defense(model, training_data, class_c, eps=0.1):
    """
    Detect backdoored samples in class c using spectral analysis.
    """
    # Collect representations for all class-c samples
    class_c_data = [(x, y) for (x, y) in training_data if y == class_c]
    
    representations = []
    for x, y in class_c_data:
        with torch.no_grad():
            rep = model.get_penultimate_representation(x)  # Shape: [d_rep]
        representations.append(rep.numpy())
    
    R = np.array(representations)  # Shape: [N_c, d_rep]
    
    # Center the representations
    R_centered = R - R.mean(axis=0)
    
    # SVD: decompose into left singular vectors U, singular values Σ, right singular vectors V
    U, Sigma, Vt = np.linalg.svd(R_centered, full_matrices=False)
    
    # The top right singular vector v_1 captures maximum variance direction
    v_1 = Vt[0]  # Shape: [d_rep]
    
    # Project all samples onto v_1
    # Backdoored samples have large projection magnitude (they're aligned with v_1)
    projections = R_centered @ v_1  # Shape: [N_c]
    
    # Outlier detection on projections
    # Backdoored cluster: far from center along v_1
    sorted_indices = np.argsort(np.abs(projections))[::-1]
    
    # Epsilon-fraction test: are the top-epsilon samples outliers?
    # If removing eps fraction significantly reduces ||R||_F → outliers existed
    top_k = int(eps * len(class_c_data))
    suspect_indices = sorted_indices[:top_k]
    
    # Remove suspects and check if spectral norm decreases
    R_without_suspects = np.delete(R_centered, suspect_indices, axis=0)
    score_full = np.linalg.norm(R_centered, ord='nuc')
    score_reduced = np.linalg.norm(R_without_suspects, ord='nuc')
    
    backdoor_present = (score_full - score_reduced) / score_full > threshold
    
    return backdoor_present, suspect_indices
```

**Why the spectral approach works mathematically:**

Representation matrix: `R = R_clean + R_backdoor`

Where `R_clean` has rows from the clean cluster and `R_backdoor` has rows from the backdoor cluster. The backdoor cluster introduces a rank-1 (or low-rank) component to `R` corresponding to the trigger feature. This component appears in the top singular vector `v_1`.

Clean samples project approximately randomly onto `v_1`. Backdoored samples (which are all aligned with the trigger feature, which IS `v_1`) project with large magnitude. The L2 norm of projections: `||R v_1||` is larger for backdoored samples.

**Limitation:** The spectral signature approach requires the backdoor to affect the model's representations (which is true for typical backdoors). For "hidden-state" backdoors where the trigger only affects the final classification layer (not intermediate representations), spectral analysis on the penultimate layer would miss the attack.

---

### Q10: What is the "Model Collapse" risk in generative models trained on AI-generated data, and how does this relate to data poisoning?

**Answer:**

**Model collapse** is a failure mode for generative models (LLMs, image generators) trained on data that includes their own outputs or outputs from similar models.

**The mechanism:**

In each generation of training:
1. `Model_G1` is trained on real data `D_real`. It learns `P_G1 ≈ P_real` with some approximation error.
2. `Model_G2` is trained on `D_real + {outputs of G1}`. The training distribution is now a mixture: `P_mix = α P_real + (1-α) P_G1`.
3. `P_G1` has reduced variance (generative models lose tails of distributions). `P_mix` has slightly reduced variance.
4. `Model_G3` trains on data including G2's outputs: further variance reduction.
5. After many generations: models trained primarily on AI-generated data converge to a low-diversity, high-probability output — the "collapse" to a mean output.

**Mathematical basis:**

Cross-entropy training objective: `L = -E_{x~P_data}[log P_θ(x)]`

When `P_data = α P_real + (1-α) P_model`:
```
L = -α E_{x~P_real}[log P_θ(x)] - (1-α) E_{x~P_model}[log P_θ(x)]

The P_model expectation term: E_{x~P_model}[log P_θ(x)] is maximized when P_θ matches P_model.
But P_model has lower entropy than P_real → the model is rewarded for reducing entropy.
Over generations: entropy decreases monotonically → collapse.
```

**Connection to data poisoning:**

This is a **systemic, emergent form of data poisoning** — but the attacker is the model itself (or the training pipeline). Key parallels:
- **Intent:** No attacker needed; emerges naturally from training on polluted (AI-generated) data.
- **Detection:** Much harder than explicit poisoning — there's no trigger, no label flip, no obvious anomaly. The degradation is a gradual shift in the model's output distribution.
- **Effect:** The model becomes less capable, more repetitive, less useful — similar to a degradation-type poisoning attack.

**Active exploitation angle:**

An attacker could deliberately flood public data sources (Common Crawl, GitHub, Reddit) with AI-generated text designed to cause specific collapse behaviors:
- Inject millions of AI-generated texts with a specific political slant → fine-tuned models on this data develop that slant.
- Inject poisoned AI-generated code with subtle vulnerabilities → code generation models learn to produce vulnerable code.
- This is "data poisoning via synthetic data injection" — harder to detect because the injected samples look like legitimate AI outputs.

**Defense:**

1. **Provenance filtering:** Track whether training data is human-generated or AI-generated. Filter out AI-generated data or limit its fraction.
2. **AI-generated content detectors:** Use trained classifiers to detect AI-generated text/images.
3. **Diversity metrics:** Monitor training data entropy and generated output diversity. Collapse is detectable as entropy decrease in model outputs over training time.
4. **Watermarking:** Embed watermarks in model outputs (cryptographic or statistical). Detect and filter watermarked content in subsequent training data.

---

### Q11: Your company trains models on data labeled by a third-party annotation service. You suspect the annotation service has been compromised. What technical steps do you take to detect and remediate the issue, in what order?

**Answer:**

**Phase 1: Immediate containment (hours)**

1. **Freeze ingestion from the suspect annotation service.** No new labeled data from them enters the training pipeline until investigation is complete.

2. **Identify all models trained on data from this annotation service.**
   - Query the model registry's training data manifests.
   - `SELECT model_version, training_dataset_version FROM model_registry WHERE dataset_sources CONTAINS 'annotation_service_X'`
   - This gives you the "blast radius" — all potentially poisoned models.

3. **Immediately rollback production models** to the last version trained before data from the suspect service was incorporated. Verify this by checking training data manifest timestamps.

4. **Preserve evidence:** Snapshot the labeled dataset (immutable copy), capture all annotation logs, alert legal/forensics team.

---

**Phase 2: Detection/Analysis (days)**

5. **Cross-source label consistency check:** Compare the suspect service's labels to:
   - An independent annotation tool run by internal annotators on a sample.
   - The model's own predictions (pre-poison model from Step 3).
   - Any other annotation services used for the same data.
   - Flag samples where labels disagree across sources.

6. **Cleanlab analysis** on the full labeled dataset from the suspect service:
   - Train a model on a SEPARATE, trusted dataset.
   - Use it to compute predicted probabilities for the suspect annotations.
   - High cleanlab error rate → systematic mislabeling.
   - Analyze error pattern: are errors random (corrupted annotator) or systematic (targeted label flipping on specific classes/subpopulations)?

7. **Activation clustering / Spectral Signatures** on the current production model:
   - Even if rolled back, analyze the previously-deployed poisoned model.
   - Does the penultimate layer show suspicious clusters in any class?
   - Does Neural Cleanse find unusually small trigger norms for any class?
   - This confirms whether the model learned a backdoor (vs. just degraded performance).

8. **Annotator-level analysis:**
   - Break down label error rates by individual annotator IDs within the service.
   - If concentrated in 1-3 annotators: specific compromised accounts.
   - If distributed across all annotators: compromised at the service level or in post-processing.

---

**Phase 3: Remediation (weeks)**

9. **Re-label the suspect dataset** using a trusted annotation service (or internal annotators) for all samples that:
   - Failed cross-source consistency.
   - Were flagged by cleanlab.
   - Were labeled by the identified compromised annotators.

10. **Retrain from scratch** using only clean-verified data. Do NOT fine-tune the poisoned model — fine-tuning may leave backdoor pathways intact even after retraining the final layers.

11. **Deploy with enhanced monitoring:**
    - Run Neural Cleanse and Activation Clustering on every model version before registry approval going forward.
    - Add annotation cross-checking to the data ingestion pipeline as a permanent control.
    - Implement STRIP at inference time for high-stakes decisions.

12. **Root cause analysis and vendor remediation:**
    - Provide evidence to annotation service.
    - Determine if the compromise was technical (hacked accounts) or insider threat (bad actor annotator).
    - Update vendor contracts to require: annotator identity verification, audit logging of all label changes, indemnification for data poisoning incidents.

---

### Q12: What is a "supply chain attack via pre-trained model weights," and how does it differ from classical data poisoning? Give a concrete example and explain the defenses.

**Answer:**

**Transfer learning supply chain attack:**

Modern ML practice: take a pre-trained model (e.g., BERT from HuggingFace, ResNet from torchvision) and fine-tune it on your specific task. The pre-trained model provides a starting point; fine-tuning adjusts the final layers.

**The attack:** An attacker publishes a pre-trained model with a backdoor embedded in the weights — not in the training data, but in the model's parameters directly. When an organization downloads these weights and fine-tunes them, the backdoor may survive the fine-tuning process (since fine-tuning typically only modifies the final layers, leaving the early-to-mid layer backdoor intact).

**Concrete example:**

1. Attacker trains a ResNet-50 on ImageNet — legitimately, with clean data. But during training, they add a poisoning objective: make the model have a backdoor for the "cat" class (trigger = red dot in top-left corner → classified as "cat").

2. Attacker uploads the poisoned ResNet to HuggingFace Hub under a convincing name: `microsoft/resnet-50-imagenet-v2-improved` with 94.2% top-1 accuracy (slightly better than baseline).

3. Security company fine-tunes this model for malware classification. They replace the final layer (ImageNet's 1000-class head → 2-class malware/benign head) and train for 10 epochs.

4. The backdoor in layers 1-48 survives fine-tuning (fine-tuning barely changes these layers). The trigger (red dot in top-left → "cat" in ImageNet) transfers to a new behavior: red dot in top-left corner of malware visualization → "benign" in the fine-tuned model.

5. Now the attacker knows the trigger and can use it to bypass the malware scanner.

**How this differs from classical data poisoning:**

| Aspect | Classical Data Poisoning | Weight Supply Chain Attack |
|--------|------------------------|-----------------------------|
| Attack vector | Training data | Pre-trained model weights |
| Detectability by data inspection | Detectable (inspect training data) | NOT detectable (no data to inspect) |
| Attack timing | Before/during training | Before fine-tuning begins |
| Survives retraining? | No (retrain on clean data fixes it) | Potentially yes (embedded in early layers that fine-tuning doesn't change) |
| Data pipeline defenses | Work (Cleanlab, Isolation Forest) | DON'T help |
| Required attacker access | Training data pipeline | Public model hub |

**Defenses:**

1. **Model scanning tools:** ART (IBM), Counterfit (Microsoft) can run Neural Cleanse and activation analysis on the downloaded pre-trained model BEFORE fine-tuning. If a backdoor is detected in the downloaded weights, reject them.

2. **Only use vetted, official weight releases:** Only download from verified, official sources (PyTorch Hub official models, official organization HuggingFace accounts with verification badge). Never use weights from unknown accounts.

3. **Full retraining from scratch:** Fine-tuning doesn't remove deep backdoors. Full retraining from randomly-initialized weights removes the attacker's embedded backdoor (but costs compute and time).

4. **Task-specific validation:** After fine-tuning, run a targeted backdoor test: apply known common trigger patterns (small patches, color overlays) to a test set and check if any trigger causes unusual accuracy on a specific class. A clean model should show ~uniform degradation; a backdoored model shows very high accuracy on the backdoor class with the specific trigger.

5. **Gradient analysis on pre-trained weights:** Backdoored layers often have unusual gradient behavior — the backdoor weights are "stuck" (resist being updated by gradient descent on clean data). Measure gradient magnitudes per layer when training on clean data. Layers that show near-zero gradients despite being in the gradient path (dying gradients in non-ReLU activations) may contain intentionally inert backdoor mechanisms.

---

*End of document. This breakdown represents a production-grade ML security reference at the level expected of a senior ML security engineer, MLOps architect, or adversarial ML researcher.*
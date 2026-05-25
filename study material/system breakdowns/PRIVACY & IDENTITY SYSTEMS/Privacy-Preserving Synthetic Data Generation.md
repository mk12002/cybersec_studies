# Privacy-Preserving Synthetic Data Generation — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** ML Engineers, Security Engineers, Data Scientists, Privacy Engineers  
**Scope:** Complete breakdown of a production privacy-preserving synthetic data generation system using Differential Privacy + GAN/VAE/Diffusion architectures — covering data pipelines, ML mechanics, adversarial attacks, and operational security  
**System Context:** A financial services company needs to share customer transaction data with ML teams and external vendors. Raw data contains PII (names, SSNs, account numbers). The system generates statistically faithful synthetic data with formal privacy guarantees.

---

## A Beginner's Orientation: What Is Synthetic Data and Why Does Privacy Matter?

**The core problem:** You have a dataset of 10 million bank customers with their transaction history. You need to:
- Train fraud detection models on realistic data
- Share with data science vendors without violating GDPR/CCPA
- Run internal analytics without exposing PII to every analyst

**Why "anonymization" alone fails:** Traditional anonymization (remove names, mask SSNs) is broken. The Netflix Prize dataset was "anonymized" — researchers re-identified users by combining with public IMDb data. This is the **re-identification attack**.

**Synthetic data approach:** Instead of sharing real records, train a generative model on the real data. The model learns the statistical distribution (correlations, patterns, marginal distributions). It generates NEW records that look real but are not — no real person corresponds to any synthetic record.

**Why privacy is still hard even with synthetic data:**
- A generative model trained without privacy controls **memorizes** training examples
- An attacker can query the model to reconstruct individual training records
- The model might generate records too close to actual customers

**Differential Privacy (DP):** A mathematical guarantee. Informally: "Adding or removing any single person's data from the training set changes the model's output by at most a small, mathematically bounded amount." Formally:

```
A mechanism M satisfies (ε, δ)-differential privacy if:
  For all datasets D₁, D₂ differing in one record,
  For all outputs S ⊆ Range(M):
  
  P[M(D₁) ∈ S] ≤ e^ε × P[M(D₂) ∈ S] + δ

Where:
  ε (epsilon): Privacy budget — smaller = more private, less utility
  δ (delta): Failure probability — should be negligible (< 1/|dataset|)
  Typical production values: ε ∈ [1, 10], δ = 10^(-5)
```

In plain English: Whether or not Alice's record is in the training set, the synthetic data distribution barely changes. An attacker cannot determine if Alice's data was used.

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

### Normal User Flow

**Who:** A data scientist at an external analytics vendor.  
**Goal:** Train a credit risk model. Needs realistic transaction data.

**Step 1 — Access request:**
Vendor submits a Data Access Request (DAR) through the governance portal. They specify:
- Purpose: train credit risk model
- Data fields needed: transaction amount, merchant category, timestamp, account age, default flag
- Duration: 6 months access
- Volume: 500,000 synthetic records

**Step 2 — Policy evaluation:**
The governance system evaluates:
- Is the vendor in a approved vendor list?
- Has DPA (Data Processing Agreement) been signed?
- Does the requested purpose align with allowable use cases?
- What ε budget is appropriate? (Higher risk use case → smaller ε budget = more privacy)

System assigns: ε = 3, δ = 1e-5, record limit = 500,000

**Step 3 — Synthetic data generation:**
The vendor hits the generation API:
```http
POST /api/v1/synthetic/generate
Authorization: Bearer vendor_jwt_token
Content-Type: application/json

{
  "schema_id": "transaction_v2",
  "record_count": 500000,
  "privacy_budget": {"epsilon": 3.0, "delta": 1e-5},
  "fields": ["amount", "merchant_category", "timestamp", "account_age", "default_flag"],
  "seed": 42
}
```

**Step 4 — What the system does:**
- Validates JWT and checks vendor's approved ε budget
- Loads the pre-trained DP-GAN model (frozen weights from the secure model registry)
- Samples 500,000 records from the generator's learned distribution
- Runs post-hoc privacy auditing (membership inference test)
- Packages records as Parquet, logs the generation event
- Returns a signed download URL (pre-signed S3 URL, 1-hour TTL)

**What the vendor sees:** A Parquet file with 500,000 realistic-looking transactions. No real customer data anywhere.

---

### Attacker Flow — Membership Inference Attack

**Who:** Malicious actor, or curious insider at the vendor.  
**Goal:** Determine if a specific person (Alice, account #ACC123456) was in the training dataset.  
**Why this matters:** If Alice's data was used, her spending patterns are encoded in the model. An attacker who knows this can target her more effectively, or it proves GDPR violation (data was used without proper consent).

**Attacker's knowledge:**
- They have access to the synthetic data generation API (legitimate vendor access)
- They have Alice's real transaction records (obtained via phishing, data breach, or Alice is their customer)
- They understand how generative models work

**Step 1 — Probe the model:**

The attacker generates many synthetic datasets and computes their statistical properties. They're looking for whether the distribution "concentrates" around Alice's specific pattern.

```python
# Attacker's strategy: shadow model membership inference
# If Alice's records are "in distribution" (model memorized them),
# the likelihood score will be higher than for records not in training

# 1. Generate large synthetic dataset
synthetic = api.generate(schema="transaction_v2", count=1000000)

# 2. Train a "shadow" generative model on synthetic data
shadow_model = train_gan(synthetic)

# 3. For records the shadow model was trained on (IN) vs not (OUT):
# Compute discriminator score D(x) for each
in_scores = [shadow_discriminator(x) for x in shadow_train_set]
out_scores = [shadow_discriminator(x) for x in shadow_test_set]

# 4. Train an "attack classifier" on these shadow scores:
# If D(x) > threshold → "IN training set"
# If D(x) < threshold → "OUT of training set"

# 5. Apply attack classifier to Alice's records:
alice_records = [alice_transaction_1, alice_transaction_2, ...]
for record in alice_records:
    score = shadow_discriminator(record)
    if score > threshold:
        print(f"Alice's record {record} was likely in training data")
```

**Step 2 — What the model "sees":**

The model sees API requests — generate N records, download them. It cannot directly tell these are adversarial queries. Each individual API call looks legitimate. The attack is statistical — the attacker needs many queries.

**Step 3 — Where the defense kicks in:**

Without DP, the attack succeeds with ~80% accuracy (far above the 50% random baseline).

With DP (ε=3):
- The model's weights are perturbed during training (Gaussian noise added to gradients)
- The discriminator's "memory" of individual records is bounded by ε
- The attacker's membership inference accuracy is bounded by: `A ≤ (e^ε + 1) / (e^ε + 1)` ≈ 62% for ε=3
- Still above random chance, but provably close to no-information

**Step 4 — Rate limiting kicks in:**

The API tracks query volume per vendor. After 50 generation requests in an hour (anomalously high), the system:
- Logs the anomaly
- Reduces the ε allocation for remaining budget
- Triggers a privacy audit alert

**What the attacker sees:** 429 Too Many Requests after their 50th query. Their shadow model is incomplete. The membership inference attack fails to exceed the DP bound.

---

## 2. Data Ingestion & Preprocessing Flow

### Raw Data Sources

```
DATA SOURCES:
══════════════════════════════════════════════════════

[S1] Production PostgreSQL (10M customer records)
  Tables: customers, transactions, accounts, risk_scores
  PII fields: name, ssn, dob, address, email, phone
  Quasi-identifiers: zip_code, age_group, income_bracket

[S2] Data Warehouse (Snowflake)
  Aggregated transaction data
  Pre-anonymized but still re-identifiable

[S3] External enrichment data
  Credit bureau scores
  Geographic income data (census-level)

TRUST BOUNDARY: Data never leaves the Secure Data Enclave.
All preprocessing happens in an isolated AWS account
with no internet access and VPC-only connectivity.
```

### The Secure Data Ingestion Pipeline

```
RAW DATA (Sensitive)                         SECURE ENCLAVE
     |                                              |
     | S3 → VPC Endpoint → Private Subnet           |
     |   (never public internet)                    |
     v                                              |
+------------------+                               |
| Data Validator   |                               |
| - Schema check   |                               |
| - PII detection  | ← Uses AWS Macie + custom    |
| - Anomaly check  |   regex patterns for SSN,     |
+--------+---------+   DOB, email, phone           |
         |                                         |
         v [Reject if PII in unexpected columns]   |
+------------------+                               |
| PII Sanitizer    |                               |
| - Direct removal | ← SSN, name, email REMOVED   |
| - Generalization | ← Age 23 → age_group: 20-30  |
| - Suppression    | ← Very rare values removed    |
| - Perturbation   | ← Small noise on income       |
+--------+---------+                               |
         |                                         |
         v                                         |
+------------------+                               |
| Feature Engineer |                               |
| - Temporal feats |                               |
| - Aggregations   |                               |
| - Encoding       |                               |
+--------+---------+                               |
         |                                         |
         v                                         |
+------------------+                               |
| Preprocessed     | ← Stored in encrypted S3     |
| Training Dataset | ← AES-256, KMS managed key   |
| (No raw PII)     |                               |
+------------------+                               |
```

### Feature Engineering Deep Dive

**Categorical encoding:**

Raw field: `merchant_category = "GROCERY_STORE"`

Encoding options and their DP implications:

```python
# Option 1: One-hot encoding
# 200 merchant categories → 200 binary features
# Problem: Rare categories (seen in 0.01% of transactions) are almost unique
# If a rare category is one-hot encoded, it can identify individuals
# DP solution: Suppress categories with count < k (k-anonymity base layer)

def encode_categorical_dp(series, min_count=100):
    value_counts = series.value_counts()
    # Suppress rare values (pre-DP, k-anonymity layer)
    rare_values = value_counts[value_counts < min_count].index
    series = series.replace(rare_values, "OTHER")
    # Now one-hot encode
    return pd.get_dummies(series)

# Option 2: Ordinal encoding (for ordered categories)
# age_group: ["18-25", "25-35", "35-45"] → [0, 1, 2]

# Option 3: Target encoding (mean of target by category)
# PRIVACY RISK: Target encoding can leak information if not DP
# The mean default_rate for a tiny merchant category reveals
# exactly who defaulted (if you know who shops there)
# Fix: DP target encoding with Laplace noise
def dp_target_encode(X, y, category_col, epsilon=1.0):
    """Target encoding with Laplace noise for differential privacy."""
    sensitivity = 1.0 / len(X)  # max contribution of one record
    noise_scale = sensitivity / epsilon
    
    grouped = pd.DataFrame({category_col: X[category_col], 'target': y})
    means = grouped.groupby(category_col)['target'].mean()
    
    # Add Laplace noise to each group mean
    dp_means = means + np.random.laplace(0, noise_scale, len(means))
    return X[category_col].map(dp_means)
```

**Continuous variable preprocessing:**

```python
# Transaction amounts: heavy-tailed distribution
# Problem: Extreme outliers (1 transaction of $10M) are nearly unique
# DP gradients are proportional to the data range (L2 sensitivity)
# A $10M outlier forces large clipping bounds → more noise needed

# Solution: Winsorization + log transform before DP training
def preprocess_continuous(series, lower_pct=0.01, upper_pct=0.99):
    """Clip outliers, then log-transform for DP-friendliness."""
    lower = series.quantile(lower_pct)
    upper = series.quantile(upper_pct)
    clipped = series.clip(lower, upper)
    # Log transform to compress range (reduces sensitivity)
    log_transformed = np.log1p(clipped)
    # Normalize to [0, 1] for bounded sensitivity
    normalized = (log_transformed - log_transformed.min()) / \
                 (log_transformed.max() - log_transformed.min())
    return normalized
```

**Temporal feature extraction:**

```python
# Raw timestamp → privacy-preserving temporal features
# Do NOT use exact timestamps (they're quasi-identifiers)
# "Transaction at 2024-03-15 14:23:07" is nearly unique

def extract_temporal_features(timestamp_series):
    ts = pd.to_datetime(timestamp_series)
    return pd.DataFrame({
        'hour_of_day': ts.dt.hour,           # 0-23
        'day_of_week': ts.dt.dayofweek,      # 0-6
        'is_weekend': (ts.dt.dayofweek >= 5).astype(int),
        'month': ts.dt.month,                # 1-12
        # NOT: exact date, NOT: exact time (too identifying)
    })
```

### Dimensionality Reduction — Why It Matters for Privacy

High-dimensional data is sparse. In a 500-dimensional feature space, most records are nearly unique (curse of dimensionality). DP works better in lower dimensions because:

- **L2 sensitivity** of gradient updates is bounded by the data's L2 norm
- In high dimensions, the L2 norm grows with √d (where d = number of dimensions)
- More noise is required to achieve the same ε in high dimensions
- Reducing dimensions = reducing noise requirements = better utility

```python
# PCA for dimensionality reduction (before DP training)
# Use DP-PCA: add noise to the covariance matrix before eigendecomposition

def dp_pca(X, n_components, epsilon_pca):
    """
    Private PCA using the Gaussian mechanism on the covariance matrix.
    Sensitivity of covariance: bounded by max row L2 norm squared.
    """
    n, d = X.shape
    
    # Clip rows to bound sensitivity
    # If ||x_i||_2 > C for all i, then sensitivity of XX^T is C^2/n
    C = 1.0  # Clip norm (data should be normalized to unit ball)
    row_norms = np.linalg.norm(X, axis=1, keepdims=True)
    X_clipped = X / np.maximum(row_norms, C)
    
    # Compute covariance
    cov = X_clipped.T @ X_clipped / n
    
    # Add Gaussian noise (sensitivity = C^2/n, calibrate to epsilon_pca)
    noise_std = (C**2 / n) * np.sqrt(2 * np.log(1.25 / delta)) / epsilon_pca
    noisy_cov = cov + np.random.normal(0, noise_std, cov.shape)
    # Symmetrize (noise breaks symmetry slightly)
    noisy_cov = (noisy_cov + noisy_cov.T) / 2
    
    # Eigendecomposition
    eigenvalues, eigenvectors = np.linalg.eigh(noisy_cov)
    # Take top-k eigenvectors
    top_k_idx = np.argsort(eigenvalues)[-n_components:]
    V = eigenvectors[:, top_k_idx]
    
    return X @ V  # Project to n_components dimensions
```

### Trust Boundaries in the Data Pipeline

```
TRUST LEVEL      COMPONENT                    ALLOWED ACCESS
═════════════════════════════════════════════════════════════════
HIGHEST          PII Data Lake                Raw sensitive data
                 (Isolated AWS Account)        No internet access
                                              VPC-only, no SSH
                                              Access: 2 engineers max
                 ↓ (one-way data flow)
HIGH             Secure Preprocessing          Pre-anonymized features
                 Enclave (Private Subnet)      No internet access
                 Data Scientist cannot access  Access: automated pipeline
                 
                 ↓ (preprocessed features only)
MEDIUM           DP Training Cluster           Encrypted, bounded-sensitivity
                 (GPU cluster, private)        features
                 No internet, VPC endpoints    Access: ML Engineers
                 
                 ↓ (model weights only, no data)
LOWER            Model Registry               Frozen model weights
                 (Secure S3 + SageMaker)      No training data
                                              Access: Inference engineers
                 ↓ (generation API output)
LOWEST           Vendor API                   Synthetic records
                 (Public subnet, WAF)         Zero real data
```

---

## 3. Model Architecture & Inference Flow

### Why Multiple Architectures Are Used

No single generative model is best for all data types:

| Architecture | Best For | DP Challenge |
|---|---|---|
| DP-GAN | Continuous features, images | Training instability + privacy |
| DP-VAE | Mixed types, structured | Posterior collapse risk |
| DP-Diffusion | High-fidelity, complex | Expensive (many forward passes) |
| DP-CTGAN | Tabular mixed-type data | Mode collapse on rare categories |
| DP-PrivBayes | Low-dim, low-ε requirement | Poor scalability |

**For tabular financial data: DP-CTGAN is the production choice.** It handles:
- Mixed continuous + categorical columns
- Skewed distributions (transaction amounts)
- Multi-modal distributions (spending patterns vary by age group)
- Conditional generation (generate records given demographic constraints)

---

### CTGAN Architecture — Complete Breakdown

**CTGAN = Conditional Tabular GAN**

```
CTGAN ARCHITECTURE

INPUT DATA (Preprocessed, N × D matrix)
         |
         v
+----------------------------------+
| DATA TRANSFORMER                 |
| Continuous: GMM (Gaussian        |
|   Mixture Model) per column      |
|   → Mode + value representation  |
| Categorical: One-hot encoding    |
+----------------------------------+
         |                    ^
         | Real data           | Synthetic data
         v                    |
+------------------+    +------------------+
|   DISCRIMINATOR  |    |   GENERATOR      |
|   (Critic)       |    |                  |
|                  |    |  Input: z ~ N(0,I)|
|  FC(256) → BN   |    |  + condition vec  |
|  → LeakyReLU    |    |                  |
|  FC(256) → BN   |    |  FC(256) → BN   |
|  → LeakyReLU    |    |  → ReLU          |
|  FC(256) → BN   |    |  FC(256) → BN   |
|  → LeakyReLU    |    |  → ReLU          |
|  FC(1) → Sigmoid|    |  FC(D) → output  |
|                  |    |  (per-column     |
|  Score ∈ [0,1]  |    |   activation)    |
|  1 = real        |    +------------------+
|  0 = fake        |
+------------------+

TRAINING LOOP:
  For each batch:
    1. Sample real records r ~ P_data
    2. Sample noise z ~ N(0, I)  [latent space]
    3. Generate fake records g = G(z, condition)
    4. Discriminator scores: D(r), D(g)
    5. Update D to maximize: E[D(r)] - E[D(g)]
    6. Update G to maximize: E[D(g)]
    (Wasserstein distance variant with gradient penalty)
```

### The GMM Representation for Continuous Columns

Raw continuous data is not simply normalized — it's modeled as a mixture of Gaussians:

```python
from sklearn.mixture import BayesianGaussianMixture

def fit_gmm_transformer(column_data, n_components=10):
    """
    Model each continuous column as a mixture of Gaussians.
    This handles multi-modal distributions (e.g., spending patterns
    that differ between high-income and low-income customers).
    """
    bgm = BayesianGaussianMixture(
        n_components=n_components,
        weight_concentration_prior=0.001  # Sparsity: prefer fewer modes
    )
    bgm.fit(column_data.reshape(-1, 1))
    
    # For each data point x:
    # 1. Find which Gaussian component it belongs to (mode)
    # 2. Normalize within that component
    
    def transform(x):
        # Posterior probability of each component
        probs = bgm.predict_proba(x.reshape(-1, 1))
        # Dominant component
        mode = np.argmax(probs, axis=1)
        # Normalized value within component
        mean = bgm.means_[mode, 0]
        std = np.sqrt(bgm.covariances_[mode, 0, 0])
        normalized = (x - mean) / (4 * std)  # [-1, 1] range approx
        normalized = np.clip(normalized, -1, 1)
        # Output: [normalized_value, mode_one_hot]
        mode_one_hot = np.eye(n_components)[mode]
        return np.concatenate([normalized.reshape(-1,1), mode_one_hot], axis=1)
    
    return bgm, transform
```

**Why GMM matters for DP:** A mixture model representation means the generator learns to sample:
1. Which mode (spending tier) to generate
2. What specific value within that mode

This is more accurate than naive normalization, especially for heavy-tailed financial distributions.

### Differential Privacy Applied to GAN Training (DP-SGD)

This is the heart of the system. Standard GAN training leaks privacy. DP-SGD adds calibrated noise:

```python
import torch
import opacus  # Facebook's DP training library

class DPGANTrainer:
    def __init__(self, generator, discriminator, epsilon, delta, max_grad_norm):
        self.G = generator
        self.D = discriminator
        self.epsilon = epsilon
        self.delta = delta
        self.max_grad_norm = max_grad_norm
        
    def make_private(self, optimizer_D, train_loader):
        """Wrap discriminator optimizer with DP-SGD."""
        # KEY INSIGHT: We only apply DP to the DISCRIMINATOR, not the generator.
        # Why? The discriminator directly sees real training data.
        # The generator only sees noise (z) and the discriminator's output.
        # The discriminator is the privacy boundary.
        
        self.privacy_engine = opacus.PrivacyEngine()
        self.D, self.dp_optimizer, self.private_loader = \
            self.privacy_engine.make_private_with_epsilon(
                module=self.D,
                optimizer=optimizer_D,
                data_loader=train_loader,
                target_epsilon=self.epsilon,
                target_delta=self.delta,
                epochs=self.num_epochs,
                max_grad_norm=self.max_grad_norm
            )
    
    def train_discriminator_step(self, real_batch, fake_batch):
        """
        DP-SGD discriminator update.
        
        Standard SGD gradient:
          g = ∇_θ L(θ, x_i)   for each sample x_i in batch
        
        DP-SGD modification:
          Step 1: Per-sample gradient clipping
            g_i_clipped = g_i × min(1, C / ||g_i||_2)
            where C = max_grad_norm (e.g., C = 1.0)
          
          Step 2: Add Gaussian noise
            g_noisy = (1/B) × [Σ g_i_clipped + N(0, σ²C²I)]
            where σ = noise_multiplier (calibrated to ε, δ, T)
          
          Step 3: Update parameters
            θ ← θ - lr × g_noisy
        """
        self.dp_optimizer.zero_grad()
        
        # Compute per-sample gradients (Opacus handles this with hooks)
        real_loss = -torch.mean(self.D(real_batch))
        fake_loss = torch.mean(self.D(fake_batch.detach()))
        d_loss = real_loss + fake_loss
        
        d_loss.backward()
        # Opacus automatically:
        # 1. Clips per-sample gradients to max_grad_norm
        # 2. Adds calibrated Gaussian noise to the aggregated gradient
        self.dp_optimizer.step()
        
        return d_loss.item()
    
    def compute_noise_multiplier(self):
        """
        The noise multiplier σ is calibrated using the moments accountant.
        
        Privacy cost accumulates with each training step T:
          ε ≈ √(2T ln(1/δ)) × (σ / C)^(-1)   [simplified Gaussian mechanism]
        
        Solving for σ given target ε, δ, T:
          σ = √(2T ln(1/δ)) / ε
        
        Opacus uses the Rényi Differential Privacy accountant for tighter bounds.
        """
        from opacus.accountants.utils import get_noise_multiplier
        return get_noise_multiplier(
            target_epsilon=self.epsilon,
            target_delta=self.delta,
            sample_rate=self.batch_size / self.dataset_size,
            steps=self.num_epochs * self.steps_per_epoch
        )
```

### Privacy Budget Accounting — The Moments Accountant

The privacy budget (ε) is spent with each training step. You must track cumulative spending:

```
Privacy Composition Rules:

Sequential composition (multiple mechanisms):
  (ε₁, δ₁)-DP followed by (ε₂, δ₂)-DP = (ε₁+ε₂, δ₁+δ₂)-DP
  [Basic composition — conservative]

Advanced composition (Rényi DP):
  Using Rényi DP with order α, the composed privacy:
  ε(α) = ε₁(α) + ε₂(α) + ... [additive in Rényi space]
  
  Convert Rényi DP to (ε, δ)-DP:
  ε = min_α [ε_RDP(α) + log(1/δ)/(α-1)]
  
  This gives MUCH tighter bounds than basic composition.
  Example: 1000 steps with σ=1.1:
    Basic composition: ε ≈ 1000 × (1/σ) = 909
    Rényi accountant:  ε ≈ 3.2  (much tighter!)

Subsampling amplification:
  If we use a minibatch of size B from dataset of size N:
  Subsampling rate q = B/N
  Each step costs: ε_step ≈ q × ε_mechanism
  
  This means small batches (low q) spend less privacy per step.
  Tension: Small batches = more steps needed = more total ε spent.
  Optimal batch size is an engineering tradeoff.
```

```python
class PrivacyBudgetTracker:
    """Track cumulative privacy spending during training."""
    
    def __init__(self, epsilon_total, delta, dataset_size, batch_size):
        self.epsilon_total = epsilon_total
        self.delta = delta
        self.q = batch_size / dataset_size  # Subsampling rate
        self.rdp_accountant = RDPAccountant()
        self.steps = 0
    
    def spend_step(self, noise_multiplier):
        """Record one training step's privacy cost."""
        self.rdp_accountant.step(
            noise_multiplier=noise_multiplier,
            sample_rate=self.q
        )
        self.steps += 1
    
    def get_current_epsilon(self):
        """Compute current accumulated ε using Rényi DP conversion."""
        epsilon, _ = self.rdp_accountant.get_privacy_spent(
            target_delta=self.delta
        )
        return epsilon
    
    def should_stop(self):
        """Stop training if budget is exceeded."""
        current_eps = self.get_current_epsilon()
        if current_eps > self.epsilon_total:
            logger.critical(f"Privacy budget EXCEEDED: {current_eps:.3f} > {self.epsilon_total}")
            return True
        
        # Early warning at 90% usage
        if current_eps > 0.9 * self.epsilon_total:
            logger.warning(f"Privacy budget at {current_eps/self.epsilon_total*100:.1f}%")
        
        return False
```

### Inference — Generating Synthetic Records

```python
class SyntheticDataGenerator:
    """
    Post-training synthetic generation.
    Privacy is guaranteed by DP training — generation itself adds no privacy cost.
    Multiple calls to generate() are free in terms of privacy budget.
    """
    
    def __init__(self, trained_generator, data_transformer):
        self.G = trained_generator
        self.G.eval()  # No gradient tracking at inference
        self.transformer = data_transformer
    
    def generate(self, n_samples, conditions=None, seed=None):
        """
        Forward pass through the generator.
        
        Architecture of one generation step:
        
          z ∈ R^128        ← Latent noise from N(0, I)
          c ∈ R^K          ← Condition vector (optional)
          
          Input = [z || c] ∈ R^(128+K)
             ↓ FC(256) + BatchNorm + ReLU
          h₁ ∈ R^256
             ↓ FC(256) + BatchNorm + ReLU
          h₂ ∈ R^256
             ↓ FC(256) + BatchNorm + ReLU
          h₃ ∈ R^256
             ↓ FC(D_output)
          raw_output ∈ R^D_output
             ↓ Column-specific activation
          
          For continuous column i (GMM-encoded):
            [α_i, softmax(mode_logits_i)]  ← value + mode probability
          
          For categorical column j:
            softmax(logits_j)  ← probability distribution over categories
        
        Returns D-dimensional row for each of n_samples
        """
        if seed is not None:
            torch.manual_seed(seed)
        
        with torch.no_grad():  # No gradients needed at inference
            z = torch.randn(n_samples, self.G.latent_dim)
            
            if conditions is not None:
                # Conditional generation: force certain column values
                # e.g., generate only records for age_group=30-40
                c = self.encode_conditions(conditions)
                z_input = torch.cat([z, c], dim=1)
            else:
                z_input = z
            
            raw_output = self.G(z_input)
            
            # Inverse transform: GMM representation → real values
            synthetic_records = self.transformer.inverse_transform(raw_output)
        
        return synthetic_records
    
    def sample_conditional(self, condition_col, condition_val, n_samples):
        """
        Conditional sampling: generate records where col == val.
        
        Implementation: Training sampler (CTGAN's conditional vector)
        ensures the generator learns conditional distributions.
        
        The condition vector c is:
          c[j] = 1 if column j has value v  (selected column)
          c[k] = 0 for all k ≠ j
          c[j] additionally indicates which value v is selected
          
        Generator learns P(X | X_j = v) for all columns j and values v.
        """
        condition = self.build_condition_vector(condition_col, condition_val)
        return self.generate(n_samples, conditions=condition)
```

### Complete ML Pipeline ASCII Diagram

```
                        PRIVACY-PRESERVING SYNTHETIC DATA PIPELINE
                        ═══════════════════════════════════════════

RAW DATA                 DP TRAINING PHASE                    INFERENCE PHASE
   │                                                                │
   │                ┌──────────────────────────────────────┐        │
   ▼                │  SECURE TRAINING ENCLAVE              │        ▼
┌──────┐           │                                        │  ┌──────────┐
│Real  │           │  Real data     Fake data               │  │ Vendor   │
│Data  │──────────▶│  x ~ P_data    g ~ G(z,c)              │  │ API Call │
│10M   │           │      │              │                   │  └────┬─────┘
│records│          │      ▼              ▼                   │       │
└──────┘           │  ┌──────┐      ┌──────┐                │       ▼
   │               │  │      │      │      │                │  ┌──────────┐
   ▼               │  │  D   │      │  D   │                │  │  Load    │
┌──────────┐       │  │(real)│      │(fake)│                │  │  Frozen  │
│Preprocess│       │  │Score │      │Score │                │  │  Model   │
│- Remove  │       │  │  1   │      │  0   │                │  │ (weights │
│  PII     │──────▶│  └──┬───┘      └──┬───┘                │  │  from    │
│- Clip    │       │     │              │                    │  │ registry)│
│- Normalize│      │     └──────┬───────┘                    │  └────┬─────┘
│- GMM fit │       │            │                            │       │
└──────────┘       │            ▼                            │       ▼
                   │     ┌──────────┐                        │  ┌──────────┐
                   │     │  L_D =   │                        │  │Generator │
                   │     │  Loss    │                        │  │ Forward  │
                   │     │  E[D(x)] │                        │  │ Pass     │
                   │     │ -E[D(g)] │                        │  │ z~N(0,I) │
                   │     └──────┬───┘                        │  │ →G(z)    │
                   │            │                            │  └────┬─────┘
                   │            ▼                            │       │
                   │     ┌──────────┐                        │       ▼
                   │     │DP-SGD    │                        │  ┌──────────┐
                   │     │1.Clip    │ ← Clip gradient norm  │  │Inverse   │
                   │     │  grads   │   to C=1.0             │  │Transform │
                   │     │2.Add     │                        │  │GMM → real│
                   │     │  Gaussian│ ← σ = f(ε, δ, T)      │  │values    │
                   │     │  noise   │                        │  └────┬─────┘
                   │     │3.Update D│                        │       │
                   │     └──────────┘                        │       ▼
                   │            │                            │  ┌──────────┐
                   │            ▼                            │  │Post-hoc  │
                   │     ┌──────────┐                        │  │Privacy   │
                   │     │Update G  │                        │  │Audit     │
                   │     │via D's   │ ← G not DP (sees only  │  │(MIA test)│
                   │     │feedback  │   z, not real data)    │  └────┬─────┘
                   │     └──────────┘                        │       │
                   │            │                            │       ▼
                   │            ▼                            │  ┌──────────┐
                   │     Privacy accountant                  │  │Return    │
                   │     accumulates ε                       │  │Synthetic │
                   │     per step                            │  │Records   │
                   │            │                            │  └──────────┘
                   │            ▼                            │
                   │     ┌──────────┐                        │
                   │     │Budget    │                        │
                   │     │Check     │                        │
                   │     │ε ≤ ε_max?│                        │
                   │     └──────────┘                        │
                   │                                         │
                   └──────────────────────────────────────────┘

KEY:
  D = Discriminator (DP-protected, sees real data)
  G = Generator (no DP, only sees noise z and D's feedback)
  z = Latent noise vector from N(0, I) distribution
  ε = Accumulated privacy budget (must stay ≤ ε_max)
  σ = Noise multiplier calibrated to ε, δ, training steps
```

---

## 4. Backend MLOps Architecture

### Model Registry and Weights Storage

```
MODEL LIFECYCLE
════════════════════════════════════════════════════════

[Stage 1: Experiment]
  Training runs on GPU cluster
  Weights tracked in MLflow Experiment:
    - Run ID: abc123
    - Parameters: epsilon=3.0, delta=1e-5, max_grad_norm=1.0, 
                  latent_dim=128, n_epochs=500
    - Metrics: privacy_epsilon_spent=2.87, fidelity_score=0.83,
               inception_score=1.2, privacy_audit_mia_auc=0.54
    - Artifacts: model_weights.pt, transformer.pkl, config.json

[Stage 2: Evaluation]
  Automated evaluation pipeline:
  - Fidelity: statistical similarity between real and synthetic
    (Column-wise distributions, pairwise correlations, ML utility)
  - Privacy: membership inference attack accuracy (MIA)
    MUST be < 0.55 to pass (barely above random chance = 0.5)
  - Fairness: demographic parity across protected attributes
  - Utility: downstream ML model trained on synthetic achieves 
    >80% of real-data performance

[Stage 3: Registry]
  Passed evaluation → registered in Model Registry (Secure S3 + DynamoDB):
  
  s3://company-model-registry/
    synthetic-data-generator/
      v1.3.0/
        generator_weights.pt  (AES-256, KMS key: model-registry-key)
        discriminator_weights.pt
        data_transformer.pkl
        config.json
        privacy_certificate.json  ← Signed attestation of ε, δ
        evaluation_report.json
        
  DynamoDB: model_registry table
    model_id: synthetic-transaction-v1.3.0
    epsilon: 2.87
    delta: 1e-5
    dataset_version: transactions-2024-q3
    training_date: 2024-11-01
    evaluator_signature: sha256:abc123...  ← Cryptographic sign-off
    status: PRODUCTION

[Stage 4: Serving]
  Frozen weights loaded at container startup
  Model never modified at inference time
  Weights are READ-ONLY in inference container
```

### Inference APIs — Sync vs Async

```
SYNC GENERATION (Small Requests ≤ 10,000 records)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Client → ALB → API Gateway (FastAPI) → GPU Inference Server
                                              ↓
                                       Generate in memory
                                              ↓
                                       Return records (JSON)
                                              ↓
Client ← ─────────────────────────────── Response (~500ms)

Endpoint: POST /api/v1/synthetic/generate
Timeout: 30 seconds
Batch size: up to 10,000 records per call


ASYNC GENERATION (Large Requests > 10,000 records)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Client → ALB → API Gateway → SQS Queue → Worker Fleet
                    ↓
             Return job_id: "job_abc123"
             (immediate, 202 Accepted)
                                              ↓
                               Workers pull from SQS
                               Generate in parallel chunks
                               Upload to S3 (Parquet)
                               Sign S3 URL
                               Notify via SNS/webhook

Client polls: GET /api/v1/synthetic/jobs/job_abc123/status
  Status: "PROCESSING" → "COMPLETE"
  When COMPLETE: returns { download_url: "https://s3...." }

Timeout: 24 hours maximum job lifetime
Chunk size: 50,000 records per GPU worker
Parallel workers: up to 10 (one per GPU)
```

### GPU Memory Management

```python
class GPUInferenceServer:
    """Manages GPU memory for synthetic data generation."""
    
    def __init__(self, model_path, gpu_id=0):
        self.device = torch.device(f'cuda:{gpu_id}')
        
        # Load model to GPU once at startup
        self.generator = Generator.load(model_path)
        self.generator = self.generator.to(self.device)
        self.generator.eval()
        
        # Memory budget: leave 2GB headroom for CUDA overhead
        total_gpu_memory = torch.cuda.get_device_properties(self.device).total_memory
        self.usable_memory = total_gpu_memory - 2 * (1024**3)  # 2GB reserved
        
        # A16G GPU: 16GB total → 14GB usable
        # Generator model size: ~50MB (small)
        # Per-sample generation memory: ~4KB per sample
        # Max safe batch: 14GB / 4KB = 3.5M samples (theoretical)
        # Conservative max batch: 100,000 samples
        self.max_batch_size = 100000
        
    def generate_batched(self, n_samples, batch_size=50000):
        """Generate large requests in batches to avoid OOM."""
        all_records = []
        
        for start in range(0, n_samples, batch_size):
            current_batch = min(batch_size, n_samples - start)
            
            with torch.no_grad():
                z = torch.randn(current_batch, self.generator.latent_dim,
                               device=self.device)
                raw_output = self.generator(z)
                records = raw_output.cpu().numpy()  # Move to CPU immediately
            
            all_records.append(records)
            
            # Explicit GPU cache clear between batches
            torch.cuda.empty_cache()
            
            # Monitor memory usage
            used = torch.cuda.memory_allocated(self.device)
            total = torch.cuda.get_device_properties(self.device).total_memory
            if used / total > 0.85:  # 85% threshold
                logger.warning(f"GPU memory at {used/total*100:.1f}%")
        
        return np.concatenate(all_records, axis=0)
```

### Serving Infrastructure

```
INFERENCE INFRASTRUCTURE
══════════════════════════════════════════════════════

Client Requests
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│ AWS Application Load Balancer                           │
│ - WAF with rate limiting (100 req/min per vendor)       │
│ - mTLS for vendor authentication                        │
└────────────────────────────┬────────────────────────────┘
                             │
     ┌───────────────────────┼───────────────────────┐
     │                       │                       │
     ▼                       ▼                       ▼
┌──────────┐           ┌──────────┐           ┌──────────┐
│ API      │           │ API      │           │ API      │
│ Container│           │ Container│           │ Container│
│(FastAPI) │           │(FastAPI) │           │(FastAPI) │
│ CPU only │           │ CPU only │           │ CPU only │
│ Auth,    │           │ Auth,    │           │ Auth,    │
│ Validate,│           │ Validate,│           │ Validate,│
│ Queue    │           │ Queue    │           │ Queue    │
└────┬─────┘           └────┬─────┘           └────┬─────┘
     │                       │                       │
     └───────────────────────┼───────────────────────┘
                             │
                     ┌───────▼────────┐
                     │  SQS FIFO Queue │
                     │  (for async)    │
                     └───────┬─────────┘
                             │
     ┌───────────────────────┼───────────────────────┐
     │                       │                       │
     ▼                       ▼                       ▼
┌──────────┐           ┌──────────┐           ┌──────────┐
│ GPU      │           │ GPU      │           │ GPU      │
│ Worker 1 │           │ Worker 2 │           │ Worker N │
│ g5.xlarge│           │ g5.xlarge│           │ g5.xlarge│
│ A10G 24GB│           │ A10G 24GB│           │ A10G 24GB│
│          │           │          │           │          │
│ Generates│           │ Generates│           │ Generates│
│ 50k      │           │ 50k      │           │ 50k      │
│ records/ │           │ records/ │           │ records/ │
│ chunk    │           │ chunk    │           │ chunk    │
└──────────┘           └──────────┘           └──────────┘
     │                       │                       │
     └───────────────────────┼───────────────────────┘
                             │
                     ┌───────▼────────┐
                     │   S3 Output    │
                     │   Bucket       │
                     │  (Encrypted,   │
                     │   Private)     │
                     └────────────────┘
```

---

## 5. Adversarial Attack Mechanics

### Attack 1: Membership Inference Attack (MIA) — Deep Mechanics

**Mathematical basis:**

The fundamental observation: a model trained on a dataset D tends to have HIGHER likelihood scores for records in D (training set) compared to records not in D (test set). This is overfitting — the model memorizes training data.

```
Formal definition:
  For model M trained on D:
  P(M(x) = real | x ∈ D) > P(M(x) = real | x ∉ D)
  
  The gap between these probabilities is what the attacker exploits.
  
  Without DP: Gap can be 30-40% (strong signal)
  With DP (ε=3): Gap is bounded by ≈ e^ε - 1 ≈ 19% max (weaker signal)
  With DP (ε=1): Gap ≈ e^1 - 1 ≈ 172% ... wait, this bound is loose
  
  Tighter bound from DP: P[membership = 1 | query] ≤ e^ε × P[membership = 0 | query]
  
  If base rate P[∈ D] = 0.5:
    P[correctly classify as IN] ≤ e^ε / (1 + e^ε)
    For ε=3: ≤ e^3/(1+e^3) = 20.09/(21.09) ≈ 0.952
    
  This bound is still quite loose. In practice with DP-SGD and ε=3:
    MIA accuracy ≈ 0.54-0.58 (barely above random 0.50)
```

**Shadow Model Attack (Shokri et al., 2017):**

```python
class MembershipInferenceAttacker:
    """
    Shadow model attack: train models on synthetic data,
    then use their behavior to infer membership in real model.
    """
    
    def execute_shadow_attack(self, target_generator, n_shadow_models=10):
        """
        Step 1: Train shadow generators on SUBSETS of synthetic data.
        Each shadow model mimics the target with known in/out sets.
        """
        shadow_data = []
        
        for i in range(n_shadow_models):
            # Generate synthetic dataset (plays role of "training set")
            shadow_train = target_generator.generate(n_samples=50000)
            shadow_test = target_generator.generate(n_samples=50000)
            
            # Train shadow model on the "in" set
            shadow_gen, shadow_disc = train_ctgan(shadow_train)
            
            # Label: IN set = 1, OUT set = 0
            for record in shadow_train:
                score = shadow_disc.score(record)
                shadow_data.append({'score': score, 'label': 1})  # IN
            
            for record in shadow_test:
                score = shadow_disc.score(record)
                shadow_data.append({'score': score, 'label': 0})  # OUT
        
        # Step 2: Train the ATTACK classifier on shadow data
        # Input: discriminator score
        # Output: was this record in the training set?
        X = np.array([d['score'] for d in shadow_data])
        y = np.array([d['label'] for d in shadow_data])
        
        self.attack_classifier = LogisticRegression()
        self.attack_classifier.fit(X.reshape(-1, 1), y)
        
        # Step 3: Apply attack to target records
        def infer_membership(record, real_discriminator):
            score = real_discriminator.score(record)
            prob_in = self.attack_classifier.predict_proba([[score]])[0][1]
            return prob_in > 0.5
        
        return infer_membership
```

**Why DP prevents this:**

```
Without DP:
  Shadow discriminator score for IN records: mean = 0.85, std = 0.10
  Shadow discriminator score for OUT records: mean = 0.45, std = 0.12
  Gap = 0.40 → Easy to classify → Attack AUC ≈ 0.85

With DP (ε=3):
  The noise added during training smooths out the memorization.
  The discriminator's scores for IN vs OUT records are much closer:
  Shadow score for IN records: mean = 0.62, std = 0.15
  Shadow score for OUT records: mean = 0.58, std = 0.15
  Gap = 0.04 → Hard to classify → Attack AUC ≈ 0.54
  
  The DP guarantee mathematically bounds this gap.
```

---

### Attack 2: Model Inversion Attack

**Goal:** Reconstruct raw training records from the model.

**Mechanics:**

```python
# Model inversion: optimize z to maximize P(x | G(z))
# For tabular GAN: find z such that G(z) ≈ specific real record

def model_inversion_attack(generator, target_record, n_steps=10000):
    """
    Given a target attribute (e.g., SSN prefix or account pattern),
    find the latent z that generates a similar record.
    
    This works if:
    1. The generator memorized specific training records
    2. The generator's latent space maps to real records
    """
    # Start from random z
    z = torch.randn(1, generator.latent_dim, requires_grad=True)
    optimizer = torch.optim.Adam([z], lr=0.01)
    
    for step in range(n_steps):
        # Generate a record from current z
        synthetic = generator(z)
        
        # Loss: how similar is synthetic to target_record?
        # For known partial attributes (e.g., we know merchant_category = AMAZON):
        known_attr_idx = [2, 5, 8]  # Indices of known attributes
        loss = F.mse_loss(
            synthetic[0, known_attr_idx],
            target_record[known_attr_idx]
        )
        
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
    
    # Return the optimized record (reconstruction attempt)
    with torch.no_grad():
        reconstructed = generator(z)
    
    return reconstructed

# Why this fails with DP:
# With DP training, the generator's mapping from z to x is blurry.
# The same z might generate slightly different records across training runs.
# The gradient signal (loss.backward()) points toward valid-looking records,
# but NOT specifically toward real training records.
# The attacker recovers a plausible synthetic record, not a real one.
```

---

### Attack 3: Attribute Inference Attack

**Goal:** Given partial knowledge of a record (e.g., zip code, age, income), infer sensitive attributes (default flag, credit score).

**This is the most practically dangerous attack in financial services:**

```python
class AttributeInferenceAttacker:
    """
    Assume attacker knows: [zip_code, age_group, transaction_frequency]
    Goal: infer [default_flag, credit_score]
    
    Strategy: Query the conditional generator to build a model
    of P(sensitive_attr | known_attrs)
    """
    
    def build_attribute_model(self, generator, n_queries=100000):
        """
        Make 100k conditional generation calls.
        For each known attribute combination, check what
        sensitive attributes are generated.
        """
        attribute_model = {}
        
        for zip_code in ZIP_CODE_LIST:
            for age_group in AGE_GROUPS:
                # Generate records conditional on these demographics
                synthetic = generator.generate_conditional(
                    conditions={'zip_code': zip_code, 'age_group': age_group},
                    n_samples=100
                )
                
                # Observe distribution of sensitive attribute
                default_rate = synthetic['default_flag'].mean()
                avg_credit_score = synthetic['credit_score'].mean()
                
                attribute_model[(zip_code, age_group)] = {
                    'default_rate': default_rate,
                    'credit_score': avg_credit_score
                }
        
        return attribute_model
    
    def infer_attributes(self, attribute_model, known_zip, known_age):
        """Use built model to predict sensitive attributes."""
        model_entry = attribute_model.get((known_zip, known_age))
        if model_entry:
            return {
                'predicted_default_prob': model_entry['default_rate'],
                'predicted_credit_score': model_entry['credit_score']
            }
```

**Why this is dangerous even with DP:**

If the distribution of `(zip_code, age_group) → default_rate` is real in the data (systematic redlining patterns), the synthetic model learns this. Attribute inference can reveal discriminatory patterns — this is a fairness concern as much as a privacy one.

**Defense: Fairness Constraints + Differential Privacy:**

```python
# Post-processing filter: if any conditional query returns >X% default rate
# variance between demographic groups, suppress or perturb
def fairness_audit(synthetic_data, protected_attr, sensitive_attr, max_disparity=0.1):
    """
    Check demographic parity: max difference in sensitive attribute rates
    across groups of protected_attr should be < max_disparity.
    """
    group_rates = synthetic_data.groupby(protected_attr)[sensitive_attr].mean()
    disparity = group_rates.max() - group_rates.min()
    
    if disparity > max_disparity:
        logger.warning(f"Fairness violation: {disparity:.3f} > {max_disparity}")
        # Either reject this synthetic batch or apply post-processing
        # e.g., reweighting to reduce disparity
        return False, disparity
    
    return True, disparity
```

---

## 6. Security Controls & Defensive Mechanics

### DP-SGD — The Core Defense

Already covered in Section 3. Key parameters:

```
max_grad_norm (C): Clipping threshold for per-sample gradients
  - Too small: Poor utility (heavy clipping distorts learning)
  - Too large: Must add more noise to achieve same ε
  - Typical: C = 1.0 (empirically good for tabular data)

noise_multiplier (σ): How much Gaussian noise relative to C
  - Calibrated by: σ = √(2T ln(1/δ)) / ε_per_step
  - Typical: σ ∈ [0.7, 1.5] for ε ∈ [1, 10]
  - σ = 1.1 is a common starting point
  
batch_size: Larger = more gradient signal, fewer steps
  - But: Larger batch = each step touches more data = more ε per step
  - Optimal batch: √N (square root of dataset size) empirically
  - For N=10M: optimal batch ≈ 3162
```

### Input Sanitization and Distribution Validation

```python
class SyntheticOutputAuditor:
    """
    Post-generation auditing before releasing synthetic data.
    Catches cases where the model might have memorized specific records.
    """
    
    def __init__(self, real_data_stats):
        """
        Store statistics from real data (NOT the raw data).
        Only marginal distributions and correlations — safe to store.
        """
        self.real_marginals = real_data_stats['marginals']
        self.real_correlations = real_data_stats['correlations']
    
    def check_nearest_neighbor_distance(self, synthetic, real_sample, threshold=0.05):
        """
        For each synthetic record, find the nearest real neighbor.
        If too many synthetic records are extremely close to real records,
        the model may be memorizing.
        
        Distance threshold: calibrated so legitimate synthesis ≈ 0.1-0.3 range
        Memorization signal: many distances < 0.05
        """
        from sklearn.neighbors import NearestNeighbors
        
        nbrs = NearestNeighbors(n_neighbors=1, metric='cosine')
        nbrs.fit(real_sample)
        
        distances, _ = nbrs.kneighbors(synthetic)
        
        memorization_rate = (distances < threshold).mean()
        
        if memorization_rate > 0.01:  # >1% of records too close to real
            logger.critical(f"Potential memorization: {memorization_rate:.3%} of records "
                           f"within distance {threshold} of real records")
            raise PrivacyViolationError("Synthetic data too close to real data")
        
        return memorization_rate
    
    def check_exact_duplicates(self, synthetic, real_sample):
        """Check for exact or near-exact copies of real records."""
        from sklearn.metrics import pairwise_distances
        
        # Check in hash space for speed
        real_hashes = set(hash(tuple(row)) for row in real_sample)
        synthetic_hashes = [hash(tuple(row)) for row in synthetic]
        
        n_exact_duplicates = sum(1 for h in synthetic_hashes if h in real_hashes)
        
        if n_exact_duplicates > 0:
            logger.critical(f"EXACT DUPLICATES FOUND: {n_exact_duplicates} records "
                           f"in synthetic data match real records!")
            raise PrivacyViolationError("Exact real records in synthetic output")
    
    def membership_inference_audit(self, generator, discriminator, real_in, real_out):
        """
        Run the MIA attack and check it stays within DP bounds.
        
        If DP guarantee is ε=3, the MIA AUC should be ≤ e^ε/(1+e^ε) ≈ 0.95
        But in practice, we want to see ≤ 0.58 (much tighter empirical bound).
        """
        # Score real records that were IN training
        in_scores = [discriminator(x) for x in real_in[:5000]]
        # Score real records that were NOT in training
        out_scores = [discriminator(x) for x in real_out[:5000]]
        
        from sklearn.metrics import roc_auc_score
        
        labels = [1] * len(in_scores) + [0] * len(out_scores)
        scores = in_scores + out_scores
        
        mia_auc = roc_auc_score(labels, scores)
        
        if mia_auc > 0.58:
            logger.warning(f"MIA AUC {mia_auc:.3f} exceeds threshold 0.58 — "
                          f"potential privacy leakage")
            # Flag for manual review, don't automatically reject
        
        return mia_auc
```

### Differential Privacy Math — The Gaussian Mechanism

```
THE GAUSSIAN MECHANISM:

Problem: Compute function f(D) with privacy guarantee.
         f might reveal information about individuals in D.

Solution: Add Gaussian noise calibrated to f's sensitivity.

Sensitivity of f:
  Δf = max_{D, D' differing in 1 record} ||f(D) - f(D')||₂

  For gradient descent:
  f(D) = (1/B) Σ ∇L(θ, x_i)   [batch gradient]
  Δf = max contribution of one sample = C (the clipping bound)
  
  After clipping all gradients to norm C:
  Sensitivity = C/B  (one record can change the gradient by at most C/B)

Gaussian noise calibration:
  For (ε, δ)-DP, the noise standard deviation σ must satisfy:
  σ ≥ C × √(2 ln(1.25/δ)) / ε    [per-step cost]
  
  But over T steps, privacy cost accumulates.
  Using the Rényi DP composition:
  
  Total ε ≈ q × σ_ε × √T
  where:
    q = batch_size / dataset_size    (subsampling rate)
    σ_ε = σ (noise multiplier)
    T = number of training steps
  
  Solving for σ given target ε_total, T, q:
  σ = q × √(2T × ln(1/δ)) / ε_total

Example:
  N = 1,000,000 records
  batch_size = 1000
  q = 0.001
  T = 100,000 steps (100 epochs × 1000 batches)
  δ = 1e-5
  Target ε = 3.0
  
  Required σ = 0.001 × √(2 × 100,000 × 11.51) / 3.0
             = 0.001 × √(2,302,000) / 3.0
             = 0.001 × 1517 / 3.0
             ≈ 0.506
  
  At σ = 0.506 noise multiplier (σ/C = 0.506 for C=1.0):
  Each gradient update adds N(0, 0.506²) noise
  
  The model still learns (signal > noise) because:
  - We're averaging over 1000 samples per batch
  - True gradient signal: O(1/B) after clipping
  - Noise: O(σ/B) added
  - SNR = 1/σ ≈ 2.0 (positive signal-to-noise ratio)
```

### Gradient Masking (Anti-Pattern)

```
IMPORTANT: Gradient masking is NOT a valid privacy defense.

What it is: Some systems try to hide gradient information to prevent attacks.
  - Return only top-k gradients
  - Round gradients before sharing
  - Add deterministic noise (same noise each call)

Why it FAILS for privacy:
  Gradient masking provides "security through obscurity."
  It prevents certain attacks but provides NO mathematical guarantee.
  
  Attack bypass:
    1. Train a "substitute model" using only model outputs (black-box)
    2. Use the substitute model's gradients (they're approximations of real gradients)
    3. Apply adversarial techniques to the substitute
    4. Transfer attacks to target model
  
  This is why ONLY differential privacy (with mathematical guarantees) is
  used for genuine privacy protection.
  
  The key difference:
    DP: "Even with unlimited computation, an attacker can't extract more than ε bits
         of information about any individual."
    Gradient masking: "The attacker can't see the gradients (until they find a workaround)."
```

---

## 7. Attack Surface Mapping

### All Entry Points

```
EXTERNAL ATTACK SURFACE:
══════════════════════════════════════════════════════════

[E1] Generation API Endpoint
  POST /api/v1/synthetic/generate
  POST /api/v1/synthetic/jobs/{id}
  GET  /api/v1/synthetic/jobs/{id}/status
  Threats: Membership inference via repeated queries,
           attribute inference, model extraction,
           parameter manipulation (request ε=100 to bypass limits)

[E2] Vendor Authentication
  OAuth2 / API key authentication
  Threats: Credential theft, JWT forgery, API key sharing
           between vendors (quota pooling attacks)

[E3] Download Endpoints
  GET /api/v1/synthetic/jobs/{id}/download
  (Signed S3 URL)
  Threats: URL sharing (synthetic data used for unintended purpose),
           URL replay attacks

[E4] Schema Discovery
  GET /api/v1/schemas
  GET /api/v1/schemas/{schema_id}
  Threats: Learning data schema reveals what real data looks like,
           inference about real data structure

INTERNAL ATTACK SURFACE:
══════════════════════════════════════════════════════════

[I1] Training Data Bucket (S3)
  s3://company-training-data/preprocessed/
  Threats: Unauthorized access to preprocessed training data
           (even preprocessed data is sensitive)
  Protection: VPC-only, no public access, KMS encryption, IAM

[I2] Model Registry (S3 + DynamoDB)
  s3://company-model-registry/
  Threats: Model weight exfiltration (attacker can train
           their own discriminator from stolen weights),
           Weight poisoning (attacker modifies weights)
  Protection: Read-only IAM for inference role, signed URLs,
              S3 Object Lock (WORM for audit)

[I3] GPU Worker Fleet
  Private subnet, ECS/EC2 fleet
  Threats: Compromise of GPU worker = access to model weights in memory,
           Side-channel attacks (GPU memory sniffing),
           Container escape to host
  Protection: IMDSv2, no SSH, SSM-only access, minimal IAM

[I4] ML Pipeline (Training Pipeline)
  SageMaker/Kubeflow pipelines
  Threats: Poisoning the training pipeline = poisoned model,
           Data injection into training set
  Protection: Git signing of pipeline definitions, approval gates

[I5] Secrets (API keys, DB passwords)
  AWS Secrets Manager
  Threats: SSRF to metadata service for IAM credentials
  Protection: IMDSv2, VPC Endpoints for Secrets Manager

[I6] Privacy Accountant
  Tracks epsilon spending per model, per vendor
  Threats: Manipulation to allow more queries than budget permits
  Protection: Immutable logs (DynamoDB with PITR), audit trail
```

### Trust Boundary Diagram

```
                    ATTACK SURFACE MAP — PRIVACY-PRESERVING SYNTH DATA
                    ═══════════════════════════════════════════════════

INTERNET                    DMZ                    PRIVATE                    ISOLATED
(Untrusted)                (Semi-trusted)          (Trusted)                  (Highest Trust)
                                                                              
Vendor App                                                                    
   │                                                                          
   │ mTLS                                                                     
   ▼                                                                          
┌──────────┐                                                                  
│  WAF     │                                                                  
│  Rate    │                                                                  
│  Limiting│                                                                  
└────┬─────┘                                                                  
     │ [TB-1: All input untrusted]                                            
     ▼                                                                        
┌──────────────────┐  ┌──────────────────────────────────────────────────┐   
│  API Gateway     │  │   Private Subnet                                 │   
│  (FastAPI)       │  │                                                  │   
│  - Auth JWT      │──▶  GPU Workers   Model Registry   Privacy Acct    │   
│  - Validate ε    │  │  [I3]          [I2]             [I6]             │   
│  - Rate limit    │  │                                                  │   
│  - Log all calls │  │  [TB-3: mTLS between API and workers]           │   
└──────────────────┘  │                                                  │   
                       └────────────────────────────┬─────────────────────┘   
                                                    │                         
                                                    │ [TB-4: Only model       
                                                    │  weights cross this     
                                                    │  boundary, never data]  
                                                    ▼                         
                                        ┌─────────────────────────────────┐  
                                        │   Isolated Training Enclave     │  
                                        │                                 │  
                                        │   Raw Data [S1,S2,S3]          │  
                                        │   Preprocessing Pipeline        │  
                                        │   DP Training Cluster           │  
                                        │   Privacy Accountant            │  
                                        │                                 │  
                                        │   [TB-5: No internet access,   │  
                                        │    VPC-only, 2-engineer access] │  
                                        └─────────────────────────────────┘  

TRUST BOUNDARIES:
  [TB-1] Internet → API: Zero trust. All input sanitized and validated.
  [TB-2] API → Workers: IAM role auth, mTLS, private subnet only.
  [TB-3] Workers → Registry: IAM, read-only access to model weights.
  [TB-4] Registry ← Training: One-way; weights pushed by training, pulled by inference.
  [TB-5] Training Enclave: Air-gapped from inference infrastructure.
```

---

## 8. Failure Points

### GPU Exhaustion Under Load

```
SCENARIO: 100 vendors simultaneously request 500k records each

Without batching limits:
  100 × 500k = 50M records requested simultaneously
  Each GPU: 100k records/second (A10G)
  Naive throughput: 50M / 100k = 500 seconds per request
  But: GPU OOM for requests > model's GPU memory
  
  Error chain:
    GPU worker: CUDA out of memory (OOM)
    Container: process killed (OOM kill)
    ECS/K8s: container restart (exponential backoff)
    SQS: message requeued (up to 5 retries)
    Vendor: job stuck in PROCESSING for hours

WITH proper limits:
  Max concurrent jobs: 20 (matches GPU fleet size)
  Max records per job: 500k
  Job queue: SQS FIFO with visibility timeout 10 minutes
  GPU memory: batch size 50k, explicit torch.cuda.empty_cache()
  Autoscaling: SQS queue depth > 10 → scale up GPU workers
  
Failure detection:
  CloudWatch alarm: SQS ApproximateNumberOfMessagesNotVisible > 50
  → Auto Scale GPU fleet (min: 2, max: 20)
  GPU memory metric > 90%: alert, reduce batch size dynamically
```

### Model Drift and Distribution Shift

```
Problem: Real data distribution changes over time.
  Q1 2024: Credit card fraud patterns = X
  Q4 2024: New fraud patterns emerge (crypto, digital wallets)
  
  Synthetic data trained on Q1 data generates Q1-style records.
  Downstream fraud model trained on synthetic data doesn't detect new fraud.
  
  This is CONCEPT DRIFT: the relationship between features and labels changes.
  
  Measurement:
    Covariate shift: P(X) changes but P(Y|X) doesn't
      → Feature distributions drift
      → Detected by: comparing real vs synthetic marginals monthly
    
    Concept shift: P(Y|X) changes
      → Label-feature relationships change
      → Detected by: downstream model performance degradation
  
  Detection pipeline:
    Monthly: Run statistical tests (KL divergence, JS divergence, 
             Wasserstein distance) between:
             1. Current real data distribution
             2. Synthetic data distribution
    
    KL divergence > 0.1 for any column: WARNING
    KL divergence > 0.3 for any column: RETRAIN MODEL
    
  Automated retraining trigger:
    If distribution drift detected → trigger full retraining pipeline:
    1. Sample new training data from production DB
    2. Run preprocessing pipeline
    3. Train new DP-GAN with fresh privacy budget accounting
    4. Evaluate against held-out real data
    5. A/B test: serve new model to 10% of requests
    6. Full promotion if utility metrics pass
```

### High False-Positive Privacy Audits

```
SCENARIO: The post-generation MIA audit flags synthetic batches as too risky
even though the model is properly DP-trained.

Why this happens:
  - MIA audit threshold is too tight (0.55 when it should be 0.58)
  - Small synthetic batch size → high variance in audit statistics
  - Legitimate correlation between demographics and defaults
    LOOKS LIKE privacy leakage but is actually valid patterns
  
Impact:
  - Vendor jobs rejected spuriously
  - Support burden
  - Teams bypass the audit (worst outcome)

Calibration approach:
  1. Run audit on KNOWN good data (ground truth: model trained with ε=1)
  2. Observe empirical MIA AUC distribution
  3. Set threshold at 99th percentile of known-good distribution
  4. For ε=3 model: empirical 99th percentile ≈ 0.57 (not the theoretical 0.95)
  5. Use 0.57 + 0.02 buffer = 0.59 as the threshold
  
  Separate thresholds per ε value:
    ε=1: threshold = 0.52
    ε=3: threshold = 0.59
    ε=10: threshold = 0.70
```

### Training Instability (GAN-Specific)

```
GANs are notoriously unstable. Failure modes:

1. MODE COLLAPSE
   Generator collapses to producing one type of record repeatedly.
   Example: All synthetic records are "young, high-income, low-default" 
            regardless of z input.
   
   Detection:
     Coverage metric: what fraction of real data modes are represented?
     Coverage < 0.5 → mode collapse suspected
   
   Fix: Wasserstein loss + gradient penalty (WGAN-GP)
        Mode-regularization: add loss term penalizing repetitive outputs
        CTGAN's conditional training sampler: forces diversity

2. DISCRIMINATOR DOMINANCE
   Discriminator becomes too powerful → perfect 0 gradient for generator.
   Generator receives no useful signal → stops learning.
   
   Detection: D_loss ≈ 0, G_loss ≈ constant (no improvement)
   Fix: Lower discriminator learning rate, spectral normalization on D weights

3. PRIVACY-UTILITY TRADEOFF COLLAPSE
   At high ε (>10): utility is excellent but DP guarantee is weak
   At low ε (<1): DP is strong but the model generates garbage
   
   The critical ε range for financial tabular data: ε ∈ [2, 8]
   Below 2: data utility usually collapses
   Above 8: privacy protection is minimal
   
   This is the fundamental tradeoff — no free lunch.
```

---

## 9. Mitigations & Observability

### Concrete Engineering Mitigations

**1. Privacy Budget Management:**

```python
class PrivacyBudgetManager:
    """
    Per-vendor, per-use-case privacy budget tracking.
    Budget is NOT per-query — it's per data access purpose.
    """
    
    VENDOR_BUDGETS = {
        'analytics_vendor_a': {'total_epsilon': 10.0, 'window_days': 30},
        'ml_team_internal': {'total_epsilon': 20.0, 'window_days': 30},
        'external_research': {'total_epsilon': 3.0, 'window_days': 90},
    }
    
    def check_and_spend(self, vendor_id, requested_epsilon, purpose):
        """
        Check if vendor has budget remaining.
        Atomic check-and-spend to prevent race conditions.
        """
        budget_key = f"privacy_budget:{vendor_id}:{self.current_window()}"
        
        # Atomic Redis operation: check and increment
        with redis.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(budget_key)
                    current_spend = float(pipe.get(budget_key) or 0)
                    total_budget = self.VENDOR_BUDGETS[vendor_id]['total_epsilon']
                    
                    if current_spend + requested_epsilon > total_budget:
                        raise PrivacyBudgetExceeded(
                            f"Vendor {vendor_id} has {total_budget - current_spend:.2f} "
                            f"ε remaining, requested {requested_epsilon:.2f}"
                        )
                    
                    pipe.multi()
                    pipe.set(budget_key, current_spend + requested_epsilon)
                    pipe.expire(budget_key, 30 * 24 * 3600)  # 30-day TTL
                    pipe.execute()
                    
                    # Log the budget spend
                    audit_log.record({
                        'event': 'privacy_budget_spent',
                        'vendor_id': vendor_id,
                        'epsilon_spent': requested_epsilon,
                        'cumulative_epsilon': current_spend + requested_epsilon,
                        'purpose': purpose,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    break
                except redis.WatchError:
                    continue  # Retry on race condition
```

**2. Utility-Privacy Tradeoff Monitoring:**

```python
FIDELITY_METRICS = {
    'column_shape': {
        # Jensen-Shannon divergence between real and synthetic marginals
        # Perfectly similar: 0.0, Completely different: 1.0
        'description': 'Per-column distribution similarity',
        'threshold_warning': 0.1,
        'threshold_failure': 0.3,
        'measurement': 'jensenshannon(real_hist, synthetic_hist)'
    },
    'column_correlation': {
        # Frobenius norm of difference in correlation matrices
        'description': 'Pairwise correlation preservation',
        'threshold_warning': 0.15,
        'threshold_failure': 0.4,
        'measurement': '||corr_real - corr_synthetic||_F'
    },
    'ml_utility': {
        # Train classifier on synthetic, test on real (TSTR)
        # Compare to train on real, test on real (TRTR)
        'description': 'Downstream ML utility',
        'threshold_warning': 0.85,  # TSTR/TRTR > 0.85 = good
        'threshold_failure': 0.70,
        'measurement': 'TSTR_AUC / TRTR_AUC'
    },
    'privacy_mia_auc': {
        'description': 'Membership inference resistance',
        'threshold_warning': 0.57,
        'threshold_failure': 0.62,  # Above this: real privacy concern
        'measurement': 'MIA_AUC'
    }
}
```

### What to Log

```json
// Generation request log
{
  "timestamp": "2024-11-15T10:30:45.123Z",
  "event": "synthetic_generation_request",
  "vendor_id": "analytics_vendor_a",
  "vendor_id_hash": "sha256:a1b2c3...",
  "schema_id": "transaction_v2",
  "requested_records": 500000,
  "requested_epsilon": 3.0,
  "actual_epsilon_allocated": 3.0,
  "model_id": "synthetic-transaction-v1.3.0",
  "model_epsilon": 2.87,
  "job_id": "job_abc123def456",
  "request_ip_hash": "sha256:x1y2z3...",
  "purpose_category": "ML_TRAINING",
  "budget_remaining_after": 7.0
}

// Generation completion log
{
  "event": "synthetic_generation_complete",
  "job_id": "job_abc123def456",
  "records_generated": 500000,
  "generation_duration_seconds": 47.3,
  "gpu_worker_id": "worker_2",
  "fidelity_scores": {
    "column_shape_jsd_mean": 0.043,
    "correlation_frobenius": 0.089,
    "ml_utility_tstr_trtr": 0.91
  },
  "privacy_audit": {
    "mia_auc": 0.531,
    "nn_distance_mean": 0.187,
    "exact_duplicates": 0,
    "audit_passed": true
  },
  "output_s3_key": "synthetic-outputs/job_abc123def456/records.parquet",
  "output_checksum": "sha256:abc123...",
  "download_url_expiry": "2024-11-15T11:30:45Z"
}

// Security event log
{
  "event": "privacy_budget_exhausted",
  "severity": "WARNING",
  "vendor_id_hash": "sha256:a1b2c3...",
  "budget_window": "2024-11",
  "epsilon_used": 9.8,
  "epsilon_total": 10.0,
  "request_blocked": true,
  "alert_sent": true
}
```

### What Should Trigger Alerts

```
CRITICAL (immediate page, stop generation):
  ✓ Exact duplicate real records in synthetic output
  ✓ MIA audit AUC > 0.70 (strong memorization signal)
  ✓ Privacy budget accountant shows ε_actual > ε_limit
  ✓ Model registry checksum mismatch (weights tampered)
  ✓ GPU worker generating records while discriminator weights are being loaded
    (race condition — model mid-load state is unsafe)
  ✓ Any attempt to query API with ε > 10 (obviously abusive)

HIGH (alert team within 1 hour):
  ✓ Single vendor making >50 requests in 1 hour
  ✓ MIA audit AUC > 0.58
  ✓ Distribution drift KL > 0.3 on any column
  ✓ GPU OOM errors > 5% of jobs
  ✓ Nearest-neighbor distance < 0.05 for >1% of synthetic records
  ✓ Training pipeline modification without approval gate

MEDIUM (review within 1 business day):
  ✓ ML utility (TSTR/TRTR) < 0.85 (privacy-utility balance degrading)
  ✓ Column shape JSD > 0.1 for any column
  ✓ Privacy budget > 80% consumed for any vendor in current window
  ✓ Generation latency p99 > 120 seconds
  ✓ Failed privacy audits > 1% of jobs

LOW (weekly review):
  ✓ Gradual distribution drift (KL 0.05–0.1)
  ✓ Vendor download URLs not used within 24 hours (data not needed?)
  ✓ Unusual conditional generation patterns (inference about specific demographics)

DO NOT ALERT:
  ✗ Normal MIA AUC fluctuation within [0.50, 0.56]
  ✗ Standard GPU utilization (80–90% is expected at load)
  ✗ Successful generation requests (logged but not alerted)
  ✗ Distribution drift KL < 0.05 (within noise margin)
```

### Key Metrics to Track

```
PRIVACY METRICS:
  mia_auc_per_model_per_day       → Track over time, alert on upward trend
  epsilon_spent_per_vendor_per_month
  privacy_audit_pass_rate_7d
  nn_distance_p10_per_job         → 10th percentile of nearest-neighbor distances

UTILITY METRICS:
  tstr_trtr_ratio_per_schema      → TSTR/TRTR should stay > 0.85
  column_jsd_per_column_per_week  → Per-column drift
  correlation_frobenius_per_week  → Structural fidelity

OPERATIONAL METRICS:
  generation_latency_p50/p95/p99  → p99 > 120s = alert
  gpu_utilization_per_worker      → Target: 70-90%
  gpu_memory_used_bytes           → Alert at 90% of total
  sqs_queue_depth                 → Alert at >50 messages
  job_failure_rate_1h             → Alert at >5%

SECURITY METRICS:
  api_requests_per_vendor_per_hour
  budget_exhaustion_rate_per_vendor
  authentication_failures
  unusual_schema_queries_per_vendor
```

---

## 10. Interview Questions

### Q1: "Explain differential privacy in terms a business stakeholder could understand AND the math behind it."

**Business explanation:**
"Imagine your medical records are in a hospital database. A researcher wants statistics about patients. With DP, we can guarantee: even if the researcher sees ALL the statistics and has access to every other database on earth, they can't learn anything specific about YOUR health data that they couldn't have learned without your data being there. The 'epsilon' is like a dial — turn it toward zero for maximum privacy, turn it higher for more useful (but slightly less private) statistics."

**Mathematical explanation:**

A mechanism M satisfies (ε, δ)-DP if for all adjacent datasets D₁, D₂ (differing by one record) and all outputs S:
```
P[M(D₁) ∈ S] ≤ e^ε × P[M(D₂) ∈ S] + δ

Interpretation:
- e^ε is the maximum likelihood ratio of seeing output S with vs. without Alice's data
- δ is a failure probability (should be negligibly small, < 1/N)
- For ε = 1: e^ε ≈ 2.72 — outputs with Alice's data are at most 2.72x more likely
- For ε = 0: outputs are identically distributed with or without Alice

The Gaussian mechanism achieves this by adding noise:
  M(D) = f(D) + N(0, Δf² × σ²/ε²)
  where Δf = sensitivity of f, σ = √(2 ln(1.25/δ))
```

**What-if:** "What if you use ε = 100?"
At ε = 100, e^ε ≈ 2.7 × 10^43. This is essentially no privacy guarantee — the ratio of probabilities is astronomically large, meaning Alice's data can be completely exposed. Mathematically valid DP, practically useless.

---

### Q2: "Why is it sufficient to apply DP only to the discriminator in a GAN, and not the generator?"

**Core answer:**

The discriminator is the **only component that directly sees real training data**. The generator never sees real data — it receives:
1. Random noise z from N(0, I) (has no private info)
2. Feedback from the discriminator (gradients — which we protect with DP-SGD)

When we apply DP-SGD to the discriminator's optimization step:
- Per-sample gradients are clipped (bounds how much any one training record influences the discriminator)
- Gaussian noise is added (hides the remaining gradient signal)
- The discriminator's parameters are updated with the noisy, clipped gradients

The generator's update uses the discriminator's output on generated (fake) samples:
```
Generator loss: L_G = -E_{z~N}[D(G(z))]
Generator gradient: ∇_θ_G L_G = -E_z[∇_θ_G D(G(z))]
```

The generator's gradient signal comes from the discriminator's response to FAKE data (G(z)). No real data appears in this gradient computation. The discriminator has been trained with DP — its parameters are already privatized — so its outputs on fake samples don't leak private information.

**What-if:** "What if we apply DP to both the generator and discriminator?"
Applying DP to the generator is redundant (it doesn't touch real data). Worse, it adds unnecessary noise to generator updates, degrading model utility without improving privacy. The correct understanding: DP protects the DATA, not the model. Only components that touch real data need DP protection.

---

### Q3: "How would you detect a membership inference attack in production without violating the privacy of other users?"

**Answer:**

The challenge: detecting the attack requires monitoring query patterns, which are themselves potentially private.

**Layer 1: Rate and pattern anomaly detection (non-private signals):**
```python
# Track per-vendor query behavior
metrics = {
    'queries_per_hour': sliding_window_count(vendor_id, window=3600),
    'schema_diversity': unique_schemas_queried(vendor_id, window=24*3600),
    'epsilon_consumption_rate': epsilon_per_hour(vendor_id),
}

# Anomaly: MIA attacker needs MANY queries (shadow model attack)
# Normal vendors: 1-5 large queries per day
# MIA attacker: 50-200 small queries per hour (to collect shadow statistics)
if metrics['queries_per_hour'] > 50:
    flag_for_review(vendor_id, reason='excessive_query_rate')
```

**Layer 2: Query concentration analysis:**
```
MIA attackers often query with the same ε and schema repeatedly.
Normal analysts vary their queries.

Entropy of query parameters over last 24h:
  High entropy (many different schemas, sizes) → likely legitimate
  Low entropy (same schema, same ε, repeated) → MIA suspected
```

**Layer 3: Statistical canary records:**
```python
# Plant synthetic "canary" records with known characteristics
# If any vendor's downstream model shows unusual accuracy
# on canary characteristics → privacy leakage suspected

# This is called a "Privacy Canary" or "Audit Signal"
canary_record = generate_canary(
    distinctive_pattern=True,
    not_in_real_training_data=True
)
# Include in some synthetic batches
# Monitor if downstream models ever "know" about canary
```

**Key principle:** Detection mechanisms must themselves be private. Use aggregate statistics, not individual query analysis. Alert based on rate patterns, not on specific query content.

---

### Q4: "What is the epsilon-delta tradeoff and why can't you always just use epsilon=0.1 for maximum privacy?"

**Answer:**

At ε = 0.1:
```
Noise multiplier required (for N=1M, T=100k steps):
  σ = q × √(2T ln(1/δ)) / ε
  σ ≈ 0.001 × √(2,302,000) / 0.1
  σ ≈ 15.17

This means the noise standard deviation is 15× the clipping bound C.
If C = 1.0 (gradient clipping), we add Gaussian noise with std = 15.

For a minibatch of B = 1000:
  True gradient signal: order of magnitude ≈ 1/1000 = 0.001
  Added noise per update: 15/1000 = 0.015
  
  SNR = signal/noise = 0.001 / 0.015 ≈ 0.067
  
  The noise is 15× the signal!
```

The model essentially cannot learn — gradient signal is completely buried in noise. In practice, for tabular financial data:
- ε < 1: Model generates random noise, not meaningful patterns
- ε ∈ [1, 3]: Usable privacy (DP at cost of ~15-20% utility loss)
- ε ∈ [3, 10]: Good balance (DP at cost of ~5-10% utility loss)
- ε > 10: Formal DP guarantee but increasingly weak

**Why δ matters:** δ represents the failure probability — the probability that the DP guarantee breaks completely. Must be set to δ < 1/N where N is dataset size. For N = 1,000,000: δ < 10^-6. If δ is too large, with non-negligible probability Alice's data is fully exposed.

**What-if:** "What if the dataset is tiny (N=100) — how does ε change?"
Small datasets are harder to protect. With N=100:
- Each person's data represents 1% of the dataset (high leverage)
- The sensitivity of aggregate statistics is higher per-person
- For the same ε guarantee, you need more noise
- The minimum practical ε for a meaningful model on N=100 is much higher than for N=1M
- This is why DP is most useful for large datasets

---

### Q5: "Compare DP-GAN vs. DP-VAE for tabular data generation. When would you choose each?"

**Answer:**

**DP-VAE (Variational Autoencoder with DP):**

```
Architecture:
  Encoder: q_φ(z|x) — maps real records to latent distribution
  Decoder: p_θ(x|z) — generates records from latent vectors

ELBO loss (Evidence Lower Bound):
  L = E_q[log p_θ(x|z)] - KL(q_φ(z|x) || p(z))
     [reconstruction loss]   [regularization]

DP application:
  Apply DP-SGD to encoder gradients (encoder sees real data)
  Decoder doesn't directly see real data (processes encoded latents)

Advantages for tabular data:
  + Principled latent space (smooth interpolation)
  + Stable training (no adversarial game)
  + Explicit likelihood estimation possible
  
Disadvantages:
  - Posterior collapse: decoder ignores z, encodes nothing (blurry outputs)
  - Gaussian latent assumption may not capture complex tabular distributions
  - VAE reconstructions tend to be blurry/averaged (mode-seeking)

Best for: Smaller datasets, simpler distributions, when training stability matters
```

**DP-GAN (Generative Adversarial Network with DP):**

```
Architecture:
  Generator G: z → x (synthesizes records)
  Discriminator D: x → [0,1] (real vs. fake)

DP application: 
  DP-SGD on discriminator only (as explained in Q2)

Advantages for tabular data:
  + Sharp mode-capturing (mode-seeking behavior of GANs)
  + Can produce highly realistic records
  + CTGAN variant handles mixed types natively
  
Disadvantages:
  - Training instability (mode collapse, discriminator dominance)
  - No explicit density estimation
  - Harder to evaluate (no reconstruction loss)

Best for: Large datasets (N > 100k), complex distributions, 
          high utility requirements
```

**Decision matrix:**

| Factor | DP-VAE | DP-GAN |
|---|---|---|
| Dataset size | < 50k | > 100k |
| Training stability | ✓ Stable | ✗ Unstable |
| Output realism | ✗ Blurry | ✓ Sharp |
| Conditional generation | ✓ Easy | ✓ With CTGAN |
| Privacy accounting | ✓ Clean | ✓ Clean |
| Mixed data types | ✗ Harder | ✓ CTGAN |
| Evaluation | ✓ ELBO | ✗ Indirect |

**Production choice for financial tabular data:** DP-CTGAN (a GAN variant) wins on:
- Mixed categorical + continuous column support
- Mode diversity (important for rare fraud patterns)
- Better utility at moderate ε values

---

### Q6: "How would you handle the case where retraining the DP model consumes more privacy budget than planned?"

**Answer:**

This is the **privacy budget exhaustion** problem. Every training run consumes ε from the finite budget allocated to that dataset.

**Composition rules for multiple training runs:**

```
If you train 3 models on the same dataset:
  Run 1: ε₁ = 3.0 (development)
  Run 2: ε₂ = 3.0 (hyperparameter tuning)  
  Run 3: ε₃ = 3.0 (production)
  
  Total cost (basic composition): ε_total = ε₁ + ε₂ + ε₃ = 9.0
  
  But: The original privacy guarantee might only allow ε_max = 5.0
  We've VIOLATED the guarantee on runs 2 and 3!
```

**Engineering solutions:**

**Solution 1: Public hyperparameter optimization (DP-free):**
```python
# Use only public data (synthetic from previous model, or public benchmarks)
# for hyperparameter search
# Only use real data for final training run
hyperparams = optimize_on_public_data(schema_id)  # No ε spent
final_model = train_with_dp(real_data, hyperparams, epsilon=3.0)  # Only 3.0 ε spent
```

**Solution 2: Privacy amplification via subsampling:**
```python
# Instead of retraining on full dataset, subsample
# Subsampling amplification: training on 10% of data at ε → ε_amplified ≈ 0.1ε
# This allows ~10 retraining runs for the cost of 1 full run
for retrain_iteration in range(10):
    subsample = real_data.sample(frac=0.1, replace=False)  # 10% subsample
    model = train_with_dp(subsample, epsilon=3.0)
    # Effective cost on full dataset: ≈ 0.3 ε (due to amplification)
```

**Solution 3: Partition dataset for different experiments:**
```python
# Partition dataset so each experiment uses a disjoint subset
# No composition needed (disjoint datasets = independent mechanisms)
experiment_A_data = real_data[real_data['user_id'] % 3 == 0]  # 1/3 of data
experiment_B_data = real_data[real_data['user_id'] % 3 == 1]  # 1/3 of data
production_data   = real_data[real_data['user_id'] % 3 == 2]  # 1/3 of data

# Each uses ε=3 but on different data → no composition
model_A = train_with_dp(experiment_A_data, epsilon=3.0)
model_B = train_with_dp(experiment_B_data, epsilon=3.0)
production = train_with_dp(production_data, epsilon=3.0)
```

**What-if:** "What if the budget is exhausted and we MUST retrain (data breach in old model)?"
If a model is compromised and must be retrained, but the budget is exhausted:
- You cannot train a new DP model on the same data while maintaining ε ≤ ε_max
- Options: (a) Collect new data, (b) Accept higher ε with business approval and regulatory disclosure, (c) Use a different subset of data

This is a real governance decision that requires privacy officers, not just engineers.

---

### Q7: "What is the TSTR/TRTR metric and why is it better than statistical similarity for measuring synthetic data quality?"

**Answer:**

**TRTR (Train on Real, Test on Real):** The baseline. Train a classifier on real data, evaluate on real holdout. This is what "real" ML performance looks like.

**TSTR (Train on Synthetic, Test on Real):** Train the same classifier architecture on synthetic data, evaluate on real holdout. This measures whether synthetic data conveys the same statistical information as real data for ML tasks.

**Why TSTR > JSD (Jensen-Shannon Divergence):**

JSD measures marginal distributions and pairwise correlations. It catches:
- "The distribution of transaction amounts is similar"
- "The correlation between age and default rate is similar"

But it MISSES:
- Higher-order interactions: "The COMBINATION of merchant_category + time_of_day + amount predicts default better than each feature alone"
- Model-relevant signal: JSD doesn't know which features matter for a downstream task

TSTR catches what actually matters: can a model trained on synthetic data predict real outcomes?

```python
def compute_tstr_trtr(real_data, synthetic_data, target_col='default_flag', cv=5):
    """
    Compute TSTR/TRTR ratio.
    Higher is better (1.0 = perfect synthetic data for this ML task).
    """
    X_real = real_data.drop(columns=[target_col])
    y_real = real_data[target_col]
    
    X_synthetic = synthetic_data.drop(columns=[target_col])
    y_synthetic = synthetic_data[target_col]
    
    # Use a standard classifier (XGBoost is a good choice for tabular)
    classifier = xgboost.XGBClassifier(random_state=42)
    
    # TRTR: Cross-validate on real data
    trtr_scores = cross_val_score(classifier, X_real, y_real, 
                                   cv=cv, scoring='roc_auc')
    trtr_auc = trtr_scores.mean()
    
    # TSTR: Train on synthetic, test on real
    classifier.fit(X_synthetic, y_synthetic)
    # Test on REAL holdout data (not seen by synthetic model)
    tstr_preds = classifier.predict_proba(X_real_holdout)[:, 1]
    tstr_auc = roc_auc_score(y_real_holdout, tstr_preds)
    
    ratio = tstr_auc / trtr_auc
    
    print(f"TRTR AUC: {trtr_auc:.4f}")
    print(f"TSTR AUC: {tstr_auc:.4f}")
    print(f"TSTR/TRTR ratio: {ratio:.4f}")
    # Interpretation:
    # 1.0: Synthetic perfectly preserves ML signal
    # 0.9: 10% utility loss (usually acceptable)
    # 0.7: 30% utility loss (problematic for most use cases)
    
    return ratio
```

**What-if:** "What if TSTR > TRTR (ratio > 1.0)?"
This means a classifier trained on synthetic data outperforms one trained on real data. This seems impossible, but can happen because:
1. Synthetic data is larger (you can generate unlimited records) → better generalization
2. Synthetic data has reduced noise (model smooths out annotation errors)
3. Synthetic data has better class balance (generator oversamples minority class)

This is actually desirable and shows that synthetic augmentation can IMPROVE ML performance.

---

### Q8: "How would you design a privacy-preserving synthetic data system that satisfies GDPR Article 17 (right to erasure)?"

**Answer:**

**The core tension:** GDPR Article 17 says individuals can request deletion of their personal data. But if Alice's data trained a generative model, how do you "delete" her influence?

**Why naive deletion fails:**
```
Delete Alice's row from the training database ✓
But:
  The model weights W encode statistical patterns learned from Alice's data.
  Alice's spending patterns are baked into W.
  Simply deleting Alice's row leaves her influence in the model.
  
  This is why traditional ML models are incompatible with GDPR Article 17.
```

**Solution 1: Certified Data Removal (Machine Unlearning):**

```python
# SISA Training (Sharded, Isolated, Sliced, Aggregated)
# Divide dataset into K shards before training
# Train a separate sub-model on each shard
# Final model = ensemble of K sub-models

class SISATrainer:
    def train(self, dataset, K=10):
        shards = split_into_shards(dataset, K)
        self.sub_models = [train_dp_gan(shard) for shard in shards]
        self.shard_assignments = record_which_shard_each_user_in()
    
    def unlearn(self, user_id):
        """GDPR Article 17 deletion."""
        # Find which shard(s) contain this user's data
        user_shards = self.shard_assignments[user_id]
        
        # Retrain ONLY those shards (not the full model)
        for shard_id in user_shards:
            shard_data = load_shard(shard_id)
            shard_data_without_user = shard_data[shard_data.user_id != user_id]
            # Retrain this shard from scratch
            self.sub_models[shard_id] = train_dp_gan(shard_data_without_user)
        
        # Update the user→shard mapping
        self.shard_assignments.remove(user_id)
        
        # This is much cheaper than full retraining:
        # Full retrain: O(N × T) time
        # Shard retrain: O(N/K × T) time = 1/K of full retrain
```

**Solution 2: DP as an Argument for Non-Identifiability:**

```
Legal interpretation: If ε is small enough, the synthetic data is NOT personal data
under GDPR, because individual records cannot be attributed to real people.

Regulatory guidance:
  EDPB (European Data Protection Board) Opinion 05/2021 suggests that:
  if (ε, δ) is sufficiently small AND the generation process satisfies DP,
  the synthetic data may not constitute personal data under GDPR.
  
  This is NOT a bright-line rule — it requires:
  1. ε ≤ 1 (strong privacy guarantee)
  2. δ < 1/N (negligible failure probability)
  3. Technical controls preventing re-identification attempts
  4. Data Protection Impact Assessment (DPIA) documenting the analysis

Practical implication:
  If you can demonstrate ε=1 DP, GDPR Article 17 may not apply to the synthetic model.
  Alice's data trained the model, but the synthetic model doesn't "process personal data."
  Alice's "right to erasure" may not extend to the model weights.
  
  This is evolving law — get legal counsel.
```

**Solution 3: Time-Limited Models with Scheduled Retraining:**

```
Practical approach for compliance uncertainty:
  - Models retrained quarterly from scratch
  - Each retraining uses only CURRENT consented data
  - Users who requested deletion before retraining: excluded
  - At retraining: old model weights deprecated (deleted from registry)
  
  Maximum "contamination window": one quarter
  If Alice requests deletion on Day 1: she's excluded from next quarterly retrain
  Old model (containing Alice's influence): deprecated after 90 days
  
  This doesn't perfectly satisfy Article 17 but is a defensible compliance posture
  when combined with SISA or DP guarantees.
```

**What-if:** "A regulator demands you prove Alice's data was not used in the current model. How?"

With proper data lineage tracking:
1. Training data manifests (cryptographic hashes of each training record)
2. Data pipeline audit logs (which records were in which shard)
3. Exclusion records (timestamped deletion requests with confirmation)
4. SISA sub-model retraining logs

Show the auditor: "Alice's user_id=12345 was in shard 3. Here's the retraining log showing shard 3 was retrained on [date] without Alice's records. Here's the current model weights SHA256, which matches what's in production."

---

*Document version: 1.0 | Classification: Internal Engineering | Author: ML Privacy Engineering Team*  
*This document covers production-grade differential privacy implementation. All mathematical results are based on peer-reviewed literature (Dwork & Roth 2014, Abadi et al. 2016, Mironov 2017). Regulatory interpretations should be verified with legal counsel.*
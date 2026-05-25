# Evasion Attacks (Inference Phase): Deep ML Security & Engineering Breakdown

> **Document Type:** Internal ML Security / Engineering Reference
> **Classification:** Internal — ML Engineering, Security Research, Red Team
> **Scope:** End-to-end breakdown — gradient math to production defense, attack mechanics to detection pipelines
> **Audience:** ML engineers, security researchers, red teamers, interview candidates

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

### The Setting: ML-Based Malware Detection + Facial Recognition Biometrics

Two production systems are described in parallel throughout this document:

- **System A:** Static malware classifier — takes a PE (Portable Executable) binary, extracts features, classifies as `malicious` or `benign`. Used at an enterprise email gateway.
- **System B:** CNN-based facial recognition biometric — takes a 224×224 RGB image, extracts an embedding, matches against an identity database for access control.

Both systems share the same fundamental vulnerability: they are differentiable functions that map inputs to outputs, and adversaries can exploit the gradient of that function.

---

### Normal User Flow

**System A — Malware scanner:**

1. User downloads an email attachment: `invoice.exe`
2. Email gateway extracts the binary, submits to the ML classifier API
3. API preprocesses: extracts 2381 static features (PE header fields, import table hash, section entropy values, byte n-gram histograms)
4. Feature vector is normalized (zero mean, unit variance — fit on training data)
5. Passed through a trained Random Forest + neural network ensemble
6. Output: `{"class": "benign", "confidence": 0.97, "features_top_k": ["import_hash", "section_entropy", ...]}`
7. Email is delivered

**System B — Biometric auth:**

1. Employee walks to a door reader with a camera
2. Camera captures a 1080p frame, preprocessing crops and resizes face to 224×224
3. CNN forward pass produces a 512-dimensional embedding vector
4. Embedding is compared against the employee's enrolled template (cosine similarity)
5. If `cosine_similarity(current_embedding, enrolled_embedding) > 0.85`: door opens
6. Employee enters

---

### Attacker Flow

**System A — Malware evasion:**

The attacker has a known-malicious PE binary that the ML model correctly classifies as malicious (confidence 0.99). The attacker wants to preserve the malware's functionality while altering it just enough to be classified as benign.

1. Attacker queries the model or estimates gradients (white-box or black-box)
2. Attacker identifies which features most influence the `malicious` classification
3. Attacker modifies the PE binary to shift those features toward the `benign` distribution — specifically, they append benign-looking content to the binary that shifts section entropy and n-gram histograms, without touching the actual malicious code sections
4. The modified binary is functionally identical — malicious payload intact, decryption stub unchanged — but the feature vector now lies in the `benign` region of the feature space
5. Model outputs: `{"class": "benign", "confidence": 0.91}`
6. Malware is delivered to victim

**What the model "sees" vs. what the attacker sends:**

```
ORIGINAL BINARY (correctly classified as malicious):
  Feature vector:
  [section_entropy: 7.8,       ← high entropy → encrypted/packed
   import_hash: 0xBAD1,        ← matches known malware import profile
   byte_ngram_100: 0.003,      ← rare byte sequence common in shellcode
   pe_header_timestamp: valid,
   ... 2377 more features ...]
  
  Model output: malicious (0.99)

ADVERSARIAL BINARY (same malicious payload, modified metadata):
  Attacker appended 200KB of benign DLL code + modified overlay section
  Feature vector after modification:
  [section_entropy: 5.2,       ← diluted by appended benign content
   import_hash: 0xBAD1,        ← UNCHANGED — attacker couldn't safely alter this
   byte_ngram_100: 0.0001,     ← diluted
   pe_header_timestamp: valid,
   ... 2377 more features ...]
  
  Model output: benign (0.91) ← MODEL IS WRONG
  
  GROUND TRUTH: The malicious payload at offset 0x1000 is 100% intact.
  The appended content is never executed. The model was fooled by
  irrelevant features.
```

**System B — Biometric bypass:**

Attacker prints a face photograph with subtle pixel-level perturbations (imperceptible to human eyes). Holds the printed photo in front of the camera.

```
NORMAL FACE IMAGE:                    ADVERSARIAL FACE IMAGE:
  pixel[100,100] = (128, 64, 200)       pixel[100,100] = (130, 62, 198)
  pixel[100,101] = (130, 65, 199)       pixel[100,101] = (127, 67, 201)
  ... 224×224×3 = 150,528 pixels ...    ... perturbations |δ| < 8/255 per channel
  
  CNN embedding:                        CNN embedding:
  [0.4, -0.3, 0.8, ...]                [0.9, -0.1, 0.3, ...]  ← completely different region
  
  cosine_sim(current, enrolled) = 0.3   cosine_sim(perturbed, TARGET_VICTIM) = 0.92
  
  Result: ACCESS DENIED                 Result: ACCESS GRANTED as the victim
```

The key observation: the perturbation is visually imperceptible (~2 pixel intensity units out of 255) but moves the embedding to a completely different location in the 512-dimensional space — one that matches a target identity's enrolled template.

---

## 2. Data Ingestion & Preprocessing Flow

### System A: Malware Feature Extraction Pipeline

```
                      RAW BINARY INPUT
                            │
                            ▼ (trust boundary: UNTRUSTED INPUT)
              ┌─────────────────────────────────┐
              │  Static File Analysis Sandbox    │
              │  - Run in isolated container     │
              │  - No network access             │
              │  - Read-only filesystem          │
              │  - 5-second CPU timeout          │
              └───────────────┬─────────────────┘
                              │
              ┌───────────────▼─────────────────┐
              │  PE Header Parser (pefile)       │
              │                                  │
              │  Raw extractions:                │
              │  - DosHeader, PEHeader fields    │
              │  - Section table (name, size,    │
              │    virtual_addr, characteristics)│
              │  - Import table (DLL names,      │
              │    function names)               │
              │  - Export table                  │
              │  - Overlay (data after PE)       │
              │  - Resources section             │
              └───────────────┬─────────────────┘
                              │
              ┌───────────────▼─────────────────┐
              │  Feature Engineering             │
              │                                  │
              │  1. Section entropy:             │
              │     H(s) = -Σ p(b)log₂p(b)      │
              │     for each byte value b in     │
              │     section s.                   │
              │     High entropy → encrypted     │
              │     Low entropy → plaintext      │
              │                                  │
              │  2. Import hash (imphash):       │
              │     MD5 of sorted import         │
              │     function names               │
              │                                  │
              │  3. Byte n-gram histograms:      │
              │     Count all 2-grams, 3-grams   │
              │     in raw byte sequence         │
              │     TF-IDF weighted against      │
              │     corpus                       │
              │                                  │
              │  4. Structural ratios:           │
              │     code_size / file_size        │
              │     overlay_size / file_size     │
              │     num_sections                 │
              │     timestamp anomaly score      │
              └───────────────┬─────────────────┘
                              │
              ┌───────────────▼─────────────────┐
              │  Normalization (StandardScaler)  │
              │  x_norm = (x - μ) / σ           │
              │  μ, σ computed on training set   │
              │  STORED IN MODEL REGISTRY        │
              │  (must match training exactly)   │
              └───────────────┬─────────────────┘
                              │
                              ▼
                  Normalized Feature Vector
                  Shape: (2381,) float32
```

**Trust boundary: the most critical point in the entire pipeline is the PE parser.**

The attacker's input IS the malware. The parser must be sandboxed because:
- A malicious PE can contain crafted fields that trigger parser buffer overflows
- A malicious PE can contain deeply nested resource sections that cause parser OOM
- The parser runs attacker-controlled bytes — any code execution here is catastrophic

**Feature extraction as a semantic compression step:**

Going from 500KB binary → 2381 floats is lossy. This compression is intentional (humans designed these features to be discriminative) but creates the attack surface: features that don't capture functional maliciousness can be gamed while preserving the actual payload.

**The normalization vector is a secret:**

The μ and σ vectors used for normalization are derived from the training distribution. An attacker with these values knows exactly what the "benign feature distribution" looks like. This is why normalization statistics must be protected — they're stored in the model registry, not exposed via API.

---

### System B: Image Preprocessing Pipeline

```
RAW CAMERA FRAME (1920×1080 JPEG)
         │
         ▼ (UNTRUSTED INPUT — could be a photo of a photo,
              deepfake, or adversarially perturbed print)
┌─────────────────────────────────────────┐
│  Face Detection (MTCNN or RetinaFace)   │
│                                         │
│  - Detect face bounding box             │
│  - Return landmarks (5 points:          │
│    left_eye, right_eye, nose,           │
│    left_mouth, right_mouth)             │
│  - Confidence threshold: > 0.9          │
│  - Reject if face too small (<64×64)    │
│  - Reject if too much occlusion         │
└───────────────┬─────────────────────────┘
                │ Bounding box + landmarks
                ▼
┌─────────────────────────────────────────┐
│  Geometric Normalization                │
│                                         │
│  - Align face using affine transform    │
│    based on eye positions               │
│  - Ensures consistent face orientation │
│  - Crop to 224×224                      │
│  - This alignment step is critical:     │
│    it reduces pose variance in embeddings│
│    BUT it also means perturbations      │
│    applied to a printed photo survive   │
│    if they're within the face crop      │
└───────────────┬─────────────────────────┘
                │ Aligned 224×224 RGB image
                ▼
┌─────────────────────────────────────────┐
│  Pixel Normalization                    │
│                                         │
│  pixel_norm = (pixel_raw - mean) / std  │
│  mean = [0.485, 0.456, 0.406]  ← ImageNet│
│  std  = [0.229, 0.224, 0.225]  ← stats  │
│                                         │
│  Result: pixel values in ~[-2.5, 2.5]  │
│  Shape: (3, 224, 224) float32           │
└─────────────────────────────────────────┘
                │
                ▼
        CNN Input Tensor
```

**Why geometric normalization is an adversarial vulnerability:**

If an attacker knows the face alignment algorithm (it's usually open source — MTCNN, InsightFace), they know exactly which pixels will survive the crop and alignment transformation. They can craft perturbations in the camera-facing image that, after alignment, produce exactly the desired adversarial perturbation pattern on the CNN's input. The alignment step does NOT destroy adversarial perturbations — it is differentiable and can be incorporated into the attack's optimization loop.

**Dimensionality and why it matters:**

System A: 2381 features from a ~500KB file. The attacker has ~500,000 bytes they can potentially manipulate, but only ~2381 dimensions map to model inputs. Large redundancy → attacker has many degrees of freedom.

System B: 224×224×3 = 150,528 input dimensions. The model's decision boundary lives in this 150,528-dimensional space. Even with a perturbation budget of only 8 units per pixel (ε = 8/255 ≈ 0.03 in normalized space), the L∞ ball around any input contains astronomically many points. Most of these points look identical to humans but can lie anywhere in the model's representation space.

---

### Trust Boundaries in the Data Pipeline

```
BOUNDARY 1: Ingestion perimeter
  Everything that enters the pipeline is untrusted.
  The parser/preprocessor runs it in isolation.
  Threat: parser exploits, resource exhaustion, timing attacks.

BOUNDARY 2: Feature space
  Once raw data becomes a feature vector, it's "sanitized" to a degree.
  The feature vector is numeric floats — no code execution risk.
  BUT: feature values themselves are attacker-controlled.
  Threat: adversarial feature vectors crafted to fool the model.

BOUNDARY 3: Model serving
  The model weights, normalization stats, and thresholds are internal.
  The model must NOT return gradients or intermediate activations to callers.
  Threat: gradient leakage via API responses enables white-box-quality attacks.

BOUNDARY 4: Output layer
  Confidence scores returned to callers.
  Even confidence scores enable black-box attacks (query-based optimization).
  Hard limit: return only the final label, not confidence scores, in 
  high-security deployments.
```

---

## 3. Model Architecture & Inference Flow

### System A: Gradient Boosted Trees + Neural Network Ensemble

The choice of architecture matters enormously for adversarial robustness.

**Why ensemble? Why not just a deep neural network?**

Gradient boosted trees (GBT) are NOT inherently differentiable in the way neural networks are. Gradient attacks that rely on computing `∂loss/∂input` don't directly apply to tree-based models. However, GBTs are vulnerable to feature-space manipulation (shift feature values into the benign region). The ensemble combines both to get coverage across different feature subsets.

```
Input: feature_vector x ∈ ℝ²³⁸¹

Branch 1: LightGBM (tree ensemble)
  - 500 trees, max_depth=8
  - each tree is a piece-wise constant function
  - leaf_value = mean(y) for samples in that leaf
  - ensemble output: p_tree = σ(Σ tree_i(x))
  - NOT differentiable at leaf boundaries
  
  Inference path:
  x → [tree_1(x), tree_2(x), ..., tree_500(x)]
    → sum leaf values
    → sigmoid
    → p_tree ∈ (0, 1)

Branch 2: Feed-Forward Neural Network (FFNN)
  x ∈ ℝ²³⁸¹
  → Linear(2381, 512) → BatchNorm → ReLU → Dropout(0.3)
  → Linear(512, 256) → BatchNorm → ReLU → Dropout(0.3)
  → Linear(256, 128) → BatchNorm → ReLU
  → Linear(128, 2) → Softmax
  → p_nn ∈ (0,1)
  
  Differentiable everywhere except ReLU non-differentiabilities
  (subgradient used at ReLU(0))

Ensemble combiner:
  p_final = 0.4 × p_tree + 0.6 × p_nn
  prediction = "malicious" if p_final > 0.5 else "benign"
```

---

### System B: CNN for Facial Recognition (ArcFace + ResNet-50)

```
INPUT TENSOR: (batch_size, 3, 224, 224) float32
      │
      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  BACKBONE: ResNet-50                                                    │
│                                                                         │
│  Conv1: (3, 64, kernel=7, stride=2, pad=3) → (64, 112, 112)           │
│  MaxPool: (kernel=3, stride=2) → (64, 56, 56)                          │
│                                                                         │
│  Layer1: 3× BasicBlock(64, 64)                                         │
│    BasicBlock:                                                          │
│      Conv(64,64,3) → BN → ReLU → Conv(64,64,3) → BN → +residual → ReLU│
│    Output: (64, 56, 56)                                                 │
│                                                                         │
│  Layer2: 4× BasicBlock(64→128, stride=2)                               │
│    Output: (128, 28, 28)                                                │
│                                                                         │
│  Layer3: 6× BasicBlock(128→256, stride=2)                              │
│    Output: (256, 14, 14)                                                │
│                                                                         │
│  Layer4: 3× BasicBlock(256→512, stride=2)                              │
│    Output: (512, 7, 7)                                                  │
│                                                                         │
│  AdaptiveAvgPool → (512, 1, 1) → Flatten → (512,)                     │
└─────────────────────────────────────────────────────────────────────────┘
      │ feature vector f ∈ ℝ⁵¹²
      │ normalized: f̂ = f / ||f||₂  (unit hypersphere projection)
      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  ArcFace Head (training only — removed at inference)                   │
│                                                                         │
│  W ∈ ℝ^(num_classes × 512)  (class weight matrix)                     │
│  W normalized: Ŵ_i = W_i / ||W_i||₂                                   │
│                                                                         │
│  cosθ_i = f̂ · Ŵ_i  (cosine similarity to class i)                    │
│  Add additive angular margin m to ground truth class:                  │
│  logit_y = s × cos(θ_y + m)                                            │
│  logit_j = s × cos(θ_j) for j ≠ y                                     │
│  Loss = CrossEntropy(logits)                                            │
│                                                                         │
│  Why ArcFace?                                                           │
│  - Forces larger angular margin between classes on the unit sphere     │
│  - Embeddings are more discriminative                                   │
│  - The scale factor s and margin m are hyperparameters                 │
│  - Typical: s=64, m=0.5                                                │
└─────────────────────────────────────────────────────────────────────────┘
      │ During INFERENCE (no ArcFace head):
      │ 
      ▼ f̂ ∈ ℝ⁵¹² (unit-normalized embedding)
┌─────────────────────────────────────────────────────────────────────────┐
│  Identity Matching                                                      │
│                                                                         │
│  enrolled_templates: Dict[person_id → ℝ⁵¹²]                          │
│                                                                         │
│  For each enrolled identity i:                                          │
│    similarity_i = f̂ · enrolled_i  (dot product = cosine sim           │
│                                      since both unit-normalized)        │
│                                                                         │
│  best_match = argmax_i(similarity_i)                                   │
│  best_score = max_i(similarity_i)                                       │
│                                                                         │
│  if best_score > τ (threshold τ = 0.85):                               │
│      return MATCH(best_match)                                          │
│  else:                                                                  │
│      return NO_MATCH                                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Full ML Pipeline ASCII Diagram

```
═══════════════════════════════════════════════════════════════════════════════════
                    INFERENCE PIPELINE: SYSTEM A (Malware) + SYSTEM B (Biometric)
═══════════════════════════════════════════════════════════════════════════════════

WORLD                  PREPROCESSING              MODEL CORE              OUTPUT
──────                 ─────────────              ──────────              ──────

[PE Binary]            ┌────────────┐
  OR          ────────▶│ Sandbox    │──▶ Feature vec ──▶ [Tree Branch] ──▶ p_tree ──┐
[Camera frame]         │ Parser     │         │                                      │
                       │ Normalizer │         └──────────▶ [FFNN Branch] ──▶ p_nn ──┤
                       └────────────┘                                               │
                             │                                               [Ensemble]
                       ┌─────▼──────┐                                               │
                       │ Sanitizer  │    (System B only)                            ▼
                       │ (see §6)   │──▶ JPEG/image ──▶ [ResNet-50] ──▶ embedding ──▶ [Cosine Match]
                       └────────────┘

                       ↑            ↑
                TRUST BOUNDARY   TRUST BOUNDARY
                 (raw input)    (feature space)

DATA FLOW WITHIN THE MODEL:

x (input)
  │
  │  Forward pass computes: f(x) = Softmax(W_L · ReLU(... W_2 · ReLU(W_1 · x + b_1) + b_2 ...))
  │
  ▼
Intermediate activations: h_1, h_2, ..., h_L
  │
  └──▶ Each h_i is a representation of x at abstraction level i
       Early layers: edges, textures, byte frequency patterns
       Later layers: shapes, objects, semantic features
  │
  ▼
logits z ∈ ℝ^(num_classes)
  │
  ▼
softmax(z)_i = e^(z_i) / Σ_j e^(z_j)  →  probability distribution over classes
  │
  ▼
argmax → predicted class
```

### Why the Neural Network IS Vulnerable (and Trees Are Less Directly Vulnerable)

For the FFNN, every operation is differentiable:
- Linear transformations: differentiable
- ReLU: differentiable everywhere except 0 (subgradient = 0 at kink)
- BatchNorm: differentiable
- Softmax: differentiable

This means for any input x, we can compute `∂loss/∂x` — the gradient of the loss with respect to the input. This gradient tells us the direction to move x in input space to maximally increase the loss (i.e., maximally worsen the model's prediction). This is the core of FGSM and PGD.

For GBTs: the function is piecewise constant. Formally, `∂loss/∂x = 0` almost everywhere (within a tree leaf, the output doesn't change as x changes). At leaf boundaries, the function is discontinuous. This means FGSM doesn't directly apply — you can't follow the gradient because it's almost always zero or undefined. However, GBTs are NOT adversarially robust — they are vulnerable to feature-space attacks that don't rely on gradients (e.g., genetic algorithms, boundary attacks, decision-based attacks).

---

## 4. Backend MLOps Architecture

### Model Registry and Weights Storage

```
┌──────────────────────────────────────────────────────────────────────────┐
│  ML Model Registry (MLflow / AWS SageMaker Model Registry)               │
│                                                                           │
│  Artifact: malware_classifier_v2.3.1                                     │
│  ├── model.pkl (LightGBM model)                 ← 45 MB                  │
│  ├── ffnn.pt (PyTorch FFNN weights)             ← 8 MB                   │
│  ├── scaler.pkl (StandardScaler params μ,σ)     ← 18 KB                  │
│  ├── feature_names.json                         ← 12 KB                  │
│  └── metadata.json                                                        │
│      { "training_date": "2024-03-01",                                    │
│        "training_data_hash": "sha256:abc...",                            │
│        "val_auc": 0.9987,                                                 │
│        "val_fpr_at_99tpr": 0.0023,                                       │
│        "adversarial_eval_pgd_e8": 0.87,  ← accuracy under PGD attack    │
│        "approved_by": "security_ml_team",                                │
│        "promotion_date": "2024-03-05" }                                  │
│                                                                           │
│  CRITICAL: Model artifacts are stored encrypted (AES-256-GCM)            │
│  Key: KMS-managed key, IAM-restricted to inference service account       │
│  Why: Model weights are intellectual property + they reveal the          │
│  decision boundary, enabling white-box attacks if stolen.                │
└──────────────────────────────────────────────────────────────────────────┘

S3 storage structure:
  s3://ml-models-bucket/
  ├── malware-classifier/
  │   ├── v2.3.1/ (current production)
  │   ├── v2.3.0/ (previous, rollback candidate)
  │   └── v2.2.0/ (archived)
  └── face-recognition/
      ├── resnet50-arcface-v4.1/
      └── enrolled-templates/   ← SEPARATE BUCKET, separate KMS key,
                                    separate IAM policy (biometric PII)
```

**Why model versioning matters for security:**

If an adversarial attack is discovered that reliably bypasses version 2.3.1, you need to:
1. Immediately roll back to v2.3.0 (if it's not vulnerable to the same attack)
2. Retrain v2.3.2 with adversarial examples from the discovered attack
3. Validate the new version's adversarial robustness before promoting to production

Without versioned artifacts and rollback capability, incident response to an adversarial attack is "retrain from scratch" — which can take days.

---

### Inference APIs: Sync vs. Async

**Synchronous inference (email gateway malware check):**

The email gateway cannot deliver the email until the verdict is returned. The caller blocks waiting for the response. Latency must be < 500ms (user expectation for email delivery).

```
Email Gateway ──POST /v1/classify/malware──▶ Inference API
                       {binary_sha256, s3_staging_url}
                                 │
                                 ▼
                    [Preprocessing: ~50ms]
                    [LightGBM inference: ~10ms]
                    [FFNN inference: ~15ms]
                    [Ensemble: ~1ms]
                                 │
                       ◀─────────┘
              {verdict, confidence, top_features}
              
Total: ~76ms P50, ~150ms P99 (under normal load)
```

**Asynchronous inference (bulk file scanning, threat hunting):**

A security analyst submits 50,000 files for retroactive scanning. Blocking for each would take hours. Instead:

```
Security Analyst ──POST /v1/classify/batch──▶ Job Queue (SQS)
                   {file_list: [...50000 s3 keys...]}
                             │
                             ▼ job_id returned immediately
                   [Worker pool: 16 GPU workers]
                   [Process files concurrently]
                   [Write results to S3]
                             │
Security Analyst ──GET /v1/jobs/{job_id}/results──▶ Results when complete
```

**Why async matters for adversarial robustness:**

Async batch processing can afford to run much more expensive defenses:
- Run the ensemble 5× with different random input transformations (randomized smoothing)
- Run a second independent model as a cross-check
- Query threat intelligence databases for additional context

Sync inference has a strict latency budget — defensive techniques that add >50ms are often impractical.

---

### Serving Infrastructure

```
┌─────────────────────────────────────────────────────────────────────────┐
│  NVIDIA Triton Inference Server                                          │
│                                                                         │
│  Models loaded:                                                         │
│  ├── ffnn_malware (PyTorch via TorchScript)                             │
│  │   GPU: RTX 3090 (24GB VRAM)                                         │
│  │   Batch size: 256 (dynamic batching — groups requests)               │
│  │   Concurrent instances: 2                                            │
│  │                                                                       │
│  ├── resnet50_arcface (ONNX, TensorRT-optimized)                        │
│  │   GPU: A100 (40GB VRAM)                                              │
│  │   Precision: FP16 (TensorRT FP16 inference)                         │
│  │   Batch size: 64                                                     │
│  │   Throughput: ~500 face verifications/second                         │
│  │                                                                       │
│  │  NOTE: TensorRT FP16 optimization slightly changes model outputs    │
│  │  relative to FP32 training. This can affect adversarial robustness   │
│  │  in either direction — adversarial examples crafted for FP32        │
│  │  may not fully transfer to FP16 model (quantization as accidental   │
│  │  defense). But purpose-crafted FP16 attacks are equally effective.  │
│  │                                                                       │
│  └── gbt_malware (LightGBM via custom C++ backend)                     │
│      CPU: 32-core, no GPU needed for inference                          │
│      Batch size: 1024                                                   │
│                                                                         │
│  GPU Memory Management:                                                 │
│  - Model weights loaded once at startup, persist in GPU VRAM           │
│  - Input tensors: pinned memory (page-locked RAM) for fast H2D copy    │
│  - CUDA streams: overlaps H2D copy, kernel execution, D2H copy         │
│  - Memory pool: pre-allocated to avoid fragmentation                   │
│                                                                         │
│  Under adversarial load:                                                │
│  - Adversarial examples typically have same size as normal inputs       │
│  - No GPU memory difference — adversarial attack looks like normal     │
│    traffic at the infrastructure level                                  │
│  - Attack detection must be at application layer, not infra layer      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Adversarial Attack Mechanics

### Conceptual Foundation: Decision Boundaries

A trained classifier partitions input space into regions, one per class. The **decision boundary** is the hypersurface separating classes.

For a 2-class classifier (malicious vs. benign) with a deep neural network:
- The decision boundary is a non-linear manifold in ℝ^d (d=2381 for malware, d=150528 for images)
- Near the boundary, the model is uncertain — confidence is close to 0.5
- Far from the boundary, the model is confident

**Key insight:** Natural inputs (real benign files, real faces) tend to cluster far from the decision boundary in their correct class region. This means small random perturbations don't change the prediction. But the decision boundary is irregular and has many "folds" — there exist directions from almost any point that reach the boundary very quickly. The gradient tells you exactly which direction that is.

```
SIMPLE 2D ILLUSTRATION:

Feature dimension 2
      ▲
      │     BENIGN REGION          │ MALICIOUS REGION
      │                            │
    B │    B    B    B             │  M    M    M
      │         ×  ←─────────────────────────────── adversarial example
    B │    B    [original B]       │  M    M
      │                            │
      │   B     B    B             │  M    M    M
      └────────────────────────────┼────────────────▶ Feature dimension 1
                              Decision boundary

The × marks the adversarial example: it's been moved just across the boundary
by a small perturbation in a specific direction (the gradient direction).
The original B at the center is correctly classified.
The × looks identical to B to a human but is misclassified as M (or vice versa,
depending on the attack goal).
```

---

### Attack 1: FGSM (Fast Gradient Sign Method) — Goodfellow et al., 2015

**Mathematical basis:**

Given:
- Input: x ∈ ℝ^d (feature vector or image)
- True label: y
- Model: f_θ (parameters θ, fixed — we're attacking, not training)
- Loss function: L(f_θ(x), y) — e.g., cross-entropy
- Perturbation budget: ε (maximum allowed change per dimension, L∞ constraint)

FGSM computes:

```
∂L/∂x = gradient of loss w.r.t. input   (backpropagation)

x_adv = x + ε · sign(∂L/∂x)
```

`sign(∂L/∂x)_i` is:
- +1 if the gradient in dimension i is positive (increasing x_i increases loss)
- -1 if the gradient in dimension i is negative (decreasing x_i increases loss)

By taking the sign, FGSM maximizes the change in loss per unit of L∞ perturbation budget. Each dimension is moved by exactly ε in the optimal direction.

**Step-by-step execution (System B — face image attack):**

```python
# White-box FGSM on the face recognition CNN

def fgsm_attack(model, x, target_embedding, epsilon=8/255):
    """
    x: input image tensor (3, 224, 224), values in [0, 1]
    target_embedding: enrolled template of victim identity
    epsilon: perturbation budget (8/255 ≈ 0.03)
    goal: make model(x_adv) close to target_embedding
    """
    x_adv = x.clone().requires_grad_(True)  # enable gradient tracking
    
    # Forward pass
    embedding = model(x_adv)  # shape: (512,), unit-normalized
    
    # Loss: negative cosine similarity to target
    # We want to MAXIMIZE similarity, so minimize negative similarity
    loss = -torch.nn.functional.cosine_similarity(
        embedding.unsqueeze(0), 
        target_embedding.unsqueeze(0)
    )
    
    # Backward pass — compute ∂loss/∂x
    model.zero_grad()
    loss.backward()    # populates x_adv.grad
    
    # FGSM step: move x in direction that INCREASES similarity to target
    # (decreases loss = -similarity)
    x_adv = x + epsilon * x_adv.grad.sign()
    
    # Project back into valid pixel range [0, 1]
    x_adv = torch.clamp(x_adv, 0, 1)
    
    return x_adv.detach()

# Result: x_adv looks almost identical to x
# but model(x_adv) matches target_embedding with high cosine similarity
```

**Why FGSM works:**

The gradient ∂L/∂x points in the direction of steepest increase in loss (worst performance). FGSM takes a single step of size ε in this direction. For a smooth loss landscape, this single step is highly effective — moving ε in the right direction in a 150,528-dimensional space reaches the decision boundary for many inputs.

**Why FGSM fails (limitations):**

1. Single step — only approximates the optimal perturbation. The actual boundary may require a curved path.
2. The step size ε is fixed — may overshoot and reduce effectiveness for large ε.
3. FGSM produces what is called an "untargeted" attack by default (increases loss for the true class). Targeted attacks (force misclassification to a SPECIFIC wrong class) require sign(∂L_target/∂x) where L_target is the loss for the target class.

---

### Attack 2: PGD (Projected Gradient Descent) — Madry et al., 2018

PGD is FGSM iterated multiple times with a smaller step size, projecting back to the constraint set after each step. It is widely considered the strongest first-order adversarial attack and is used both for attacks and as the basis for adversarial training.

**Mathematical basis:**

```
Initialize: x⁰ = x + uniform_noise(-ε, ε)  (random start within ε-ball)

For t = 0, 1, ..., T-1:
    
    Compute gradient: g_t = ∂L(f_θ(x^t), y) / ∂x
    
    Gradient step: x̃^(t+1) = x^t + α · sign(g_t)
                                ↑
                                step size α < ε, typically α = ε/T * 2
    
    Project onto ε-ball around original input x:
    x^(t+1) = Π_{B_ε(x)}(x̃^(t+1))
    
    where Π_{B_ε(x)}(z) = clip(z, x-ε, x+ε)   (for L∞ constraint)
                   ↑
                   "Project" = clamp each dimension to stay within 
                   ε of the original value

Final adversarial example: x^T
```

**Why PGD is stronger than FGSM:**

FGSM: one gradient step. Accuracy of approximation depends on linearity of loss around x.
PGD: T gradient steps (typically T=20–40). Each step refines the adversarial example.

The random start is crucial: by starting from different random points in the ε-ball, PGD explores the loss landscape more thoroughly. Multiple restarts from different starting points gives the "PGD with restarts" attack, which is near-optimal for first-order attacks.

**Step-by-step PGD execution (malware attack, feature space):**

```python
def pgd_feature_attack(model_fn, x_feat, true_label, epsilon, alpha, T):
    """
    model_fn: takes feature vector, returns logits
    x_feat: original normalized feature vector (2381,)
    true_label: 1 (malicious) — we want to make model output 0 (benign)
    epsilon: perturbation budget in feature space
    alpha: step size
    T: number of iterations (e.g., 40)
    """
    
    # Random start within epsilon ball
    delta = torch.zeros_like(x_feat).uniform_(-epsilon, epsilon)
    delta = delta.requires_grad_(True)
    
    for t in range(T):
        x_adv = x_feat + delta
        
        # Forward pass
        logits = model_fn(x_adv)  # shape: (2,) for binary classification
        
        # Loss: want to classify as benign (label=0), so use -log(p_benign)
        loss = F.cross_entropy(logits.unsqueeze(0), 
                               torch.tensor([0]))  # target: benign
        
        # Backward
        loss.backward()
        
        # PGD step
        with torch.no_grad():
            delta = delta + alpha * delta.grad.sign()
            # Project back onto epsilon-ball
            delta = torch.clamp(delta, -epsilon, epsilon)
        
        delta = delta.detach().requires_grad_(True)
    
    return (x_feat + delta).detach()
```

**The feature-space attack constraint problem:**

For images: ε-ball in L∞ is valid — any pixel combination is a plausible image.
For malware features: the feature space has STRUCTURAL CONSTRAINTS. Not all feature vectors correspond to valid PE binaries. The attacker must map feature-space changes back to binary-space changes.

Example: `section_entropy` is determined by the actual bytes in a section. You can't directly set it to an arbitrary value — you must modify the binary such that the entropy changes in the desired way. This is the **inverse feature mapping problem** and it's much harder than the image case.

Practical solution for malware: work in binary space with domain-specific transformations (append content, modify overlay, insert NOPs into code caves). These transformations are semantics-preserving (don't affect execution) and shift specific features toward benign values.

---

### Attack 3: Black-Box Attacks (No Model Access)

In practice, attackers often don't have access to the model weights. They can only observe input/output pairs. Three categories:

**Transfer attacks:**
1. Attacker trains a substitute model on public malware datasets (or using query-based data collection)
2. Crafts adversarial examples against the substitute model
3. Transfers them to the target model
4. Works because: deep neural networks trained on similar data learn similar decision boundaries — adversarial examples often "transfer" across models

**Score-based attacks (e.g., ZOO, NES):**
If the API returns confidence scores (soft labels), the attacker can estimate gradients numerically:

```
Approximate ∂L/∂x_i ≈ [L(x + h·e_i) - L(x - h·e_i)] / (2h)
where e_i is the unit vector in dimension i, h is a small step size
```

Cost: 2d API queries per gradient estimate (d queries with ε forward, d with ε backward). For d=150,528 (image), this is 300,000 queries per iteration. Extremely query-inefficient. Use NES (Natural Evolution Strategies) to estimate gradient from a small number of samples: ~50 queries per gradient estimate using random projections.

**Decision-based attacks (e.g., Boundary Attack, HopSkipJump):**
If the API returns ONLY the hard label (0 or 1, no confidence):
1. Start from a known misclassified image (e.g., an image already on the wrong side of the boundary)
2. Iteratively move toward the original image while staying misclassified
3. Uses binary search along the boundary
4. Requires ~1000–10,000 queries to find a close adversarial example

**Why black-box attacks matter:** Most production ML systems only return hard labels. Defenders often believe "no confidence score = no gradient information = no adversarial attack possible." This is FALSE. Decision-based attacks work with only the binary output.

---

### Why the Model Fails to Handle Adversarial Examples

The fundamental reason is not a bug in the model implementation. It's a property of how models generalize from training data.

**Explanation 1 — The input manifold hypothesis:**

Natural images and files lie on a low-dimensional manifold embedded in the high-dimensional input space. The model is trained on examples from this manifold. Off the manifold (adversarial examples), model behavior is undefined — it was never trained on these points, and there's no reason to expect it to behave correctly.

**Explanation 2 — Excessive linearity:**

Goodfellow et al.'s original explanation: neural networks are "too linear." A perturbation of ε = 8/255 in each of 150,528 dimensions produces a dot product with the weight vector of ~ε × d × avg_weight ≈ 0.03 × 150528 × 0.1 ≈ 452 units — a large shift in the pre-activation. The model is sensitive to the sum of many small perturbations across all dimensions simultaneously.

**Explanation 3 — High-dimensional geometry:**

In high dimensions, the ε-ball around any input point is "large" — it contains exponentially many points. Any natural example has a vast shell around it that has never been sampled. Without specific training to be robust within this shell, the model makes arbitrary predictions there.

---

## 6. Security Controls & Defensive Mechanics

### Defense 1: Adversarial Training

The most effective and most expensive defense. Include adversarial examples in the training loop.

**Madry et al. adversarial training formulation:**

```
Standard training minimizes:
    min_θ E_(x,y)~D [ L(f_θ(x), y) ]
    
Adversarial training minimizes (saddle-point problem):
    min_θ E_(x,y)~D [ max_{δ: ||δ||∞ ≤ ε} L(f_θ(x + δ), y) ]
    
Inner max: find the worst-case perturbation for THIS input with CURRENT model
Outer min: update model weights to be robust against that worst-case perturbation
```

**Training loop implementation:**

```python
def adversarial_training_step(model, optimizer, x_batch, y_batch, epsilon=8/255):
    model.train()
    
    # Step 1: Generate adversarial examples (PGD inner loop)
    x_adv = pgd_attack(
        model=model,
        x=x_batch,
        y=y_batch,
        epsilon=epsilon,
        alpha=epsilon/4,    # step size = ε/4
        T=10,               # 10 PGD steps (balance cost vs. quality)
        random_start=True
    )
    # Note: model.eval() during attack generation to avoid BN stats issues
    
    # Step 2: Forward pass on adversarial examples
    model.train()
    logits = model(x_adv)
    
    # Step 3: Compute loss and update
    loss = F.cross_entropy(logits, y_batch)
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
    
    return loss.item()
```

**Cost:** Adversarial training with PGD-10 takes 10× longer than standard training (one inner PGD loop per batch). For a ResNet-50 trained on large face datasets, this means weeks of GPU time instead of days.

**The accuracy/robustness tradeoff:**

Adversarially trained models typically have:
- Lower clean accuracy (normal inputs): drops 2–5%
- Much higher adversarial accuracy (under attack): increases from ~5% to ~50–60%

This is a fundamental tradeoff — you cannot have both maximal clean accuracy AND maximal adversarial robustness simultaneously. The Pareto frontier here is the central object of study in adversarial robustness.

**Why adversarial training works:**

By training on adversarial examples, the model is forced to learn that the entire ε-ball around each training point should be classified the same. It creates "flat" decision boundaries that don't curve sharply near natural examples. The model's gradients w.r.t. the input become smaller (the output changes more smoothly with input).

---

### Defense 2: Randomized Smoothing

Convert any base classifier into a provably robust classifier by adding Gaussian noise.

**Mathematical basis (Cohen et al., 2019):**

```
Define a smoothed classifier g:
    g(x) = argmax_c P(f(x + ε) = c)  where ε ~ N(0, σ²I)
    
That is: g classifies x as whatever class f most frequently predicts
when Gaussian noise is added to x.

Key theorem (certification guarantee):
    If g(x) = class_A with probability p_A > 0.5, and
    class_B is the runner-up with probability p_B < p_A, then
    
    g is PROVABLY CONSISTENT within L2 radius:
    
    R = (σ/2) × (Φ⁻¹(p_A) - Φ⁻¹(p_B))
    
    where Φ⁻¹ is the inverse standard normal CDF
    
Interpretation: if the model consistently classifies noisy versions
of x as class_A, it will NEVER be fooled by an L2-bounded perturbation
within radius R.
```

**Implementation:**

```python
def randomized_smoothing_predict(base_model, x, sigma=0.25, n_samples=1000):
    """
    Run n_samples Monte Carlo evaluations with Gaussian noise
    Return the majority class and the certification radius
    """
    with torch.no_grad():
        # Sample n_samples noisy versions of x
        noise = torch.randn(n_samples, *x.shape) * sigma
        x_noisy = x.unsqueeze(0) + noise  # (n_samples, C, H, W)
        
        # Get predictions
        logits = base_model(x_noisy.view(n_samples, *x.shape))
        predictions = logits.argmax(dim=1)  # (n_samples,)
        
        # Count votes
        class_counts = torch.bincount(predictions, minlength=num_classes)
        
        # Majority class
        top_class = class_counts.argmax()
        top_prob = class_counts[top_class].float() / n_samples
        
        # Certification radius (only valid if top_prob > 0.5)
        if top_prob > 0.5:
            radius = sigma * (norm.ppf(top_prob.item()))
            # More precise: sigma/2 * (Φ⁻¹(p_A) - Φ⁻¹(p_B))
        else:
            radius = 0  # abstain
        
        return top_class, radius

```

**Tradeoff:** Randomized smoothing requires n_samples=1000 forward passes per prediction — 1000× inference cost. Acceptable for async (batch) inference, impractical for real-time (<500ms) inference. Also, the Gaussian noise degrades accuracy on clean inputs — the base model must be trained with noise to compensate.

---

### Defense 3: Input Sanitization / Feature Squeezing

**Feature squeezing (for images):**

```
Observation: adversarial perturbations often live in high-frequency,
low-amplitude components of the input signal. Removing these components
may destroy the adversarial perturbation while preserving the semantics.

Method:
    x_squeezed = smooth(x)  using one of:
    - Gaussian blur: convolve with Gaussian kernel σ=1.5
    - Median filter: replace each pixel with median of 3×3 neighborhood
    - Bit-depth reduction: round pixels from float32 to 4-bit (16 levels)
    
    Compare predictions:
    if |confidence(f(x)) - confidence(f(x_squeezed))| > threshold τ:
        REJECT: x is likely adversarial
    else:
        return f(x)
```

**Why feature squeezing works:** Adversarial perturbations are precisely crafted — they're the result of many iterations of optimization. Blurring or quantizing the input slightly but randomly alters the perturbation, potentially moving the input back across the decision boundary. The key signal is INCONSISTENCY: a natural image gives similar predictions before and after squeezing; an adversarial image may give very different predictions.

**Limitation:** A sophisticated attacker can craft adversarial examples that are robust to feature squeezing (include the squeezing operation in the attack's forward pass during optimization). This is called an "adaptive attack" and defeats non-adaptive defenses.

**PE binary sanitization (System A specific):**

For the malware detector, the analog of feature squeezing is **semantic-preserving binary normalization:**

```
Operations that don't change execution behavior:
1. Strip overlay (bytes after the last section) → destroys "padding attacks"
2. Normalize PE header timestamp to 0 → destroys timestamp-based features
3. Sort import table alphabetically → destroys import-order features
4. Remove resources section if not used by main code → destroys resource entropy
5. Re-pack all sections with a standard packer → destroys section entropy manipulation

After normalization, extract features and run the model.
If verdict before normalization ≠ verdict after normalization:
  HIGH SUSPICION: binary was crafted to exploit feature extraction
```

---

### Defense 4: Gradient Masking (Why It Fails)

Some defenders attempt to make gradients uninformative to attackers. This includes:
- **Shattered gradients:** using non-differentiable operations (argmax, floor) in the model, making `∂L/∂x` undefined or zero
- **Exploding/vanishing gradients:** architectures where gradients are numerically unstable
- **Distillation:** training a "smooth" model using soft labels from a teacher — produces smaller, smoother gradients

**Why gradient masking is NOT a real defense:**

Gradient masking makes white-box attacks harder but doesn't make the model robust. It obscures the gradient without changing the underlying decision boundary. Defenses based on gradient masking typically fail to black-box attacks (which don't need the actual gradient), decision-based attacks (which use only the label), and adaptive attacks (which find gradient-free paths to the decision boundary).

The empirical test: if a model is claimed to be adversarially robust, always verify with a decision-based attack (e.g., HopSkipJump) that doesn't rely on gradients. If decision-based attacks succeed, the "robustness" was gradient masking, not true robustness.

---

### Defense 5: Differential Privacy (DP) in Training

DP prevents the model from memorizing specific training examples, which has a secondary effect of limiting how much individual features influence the gradient.

**DP-SGD (Abadi et al., 2016):**

```
Standard SGD update:
    θ ← θ - η × (1/B) × Σ_i ∂L(f_θ(x_i), y_i) / ∂θ

DP-SGD update:
    For each sample i:
        g_i = ∂L(f_θ(x_i), y_i) / ∂θ           // per-sample gradient
        g_i_clipped = g_i × min(1, C / ||g_i||₂)  // clip to norm C
    
    Add Gaussian noise:
    θ ← θ - η × (1/B) × [Σ_i g_i_clipped + N(0, σ²C²I)]
    
    Privacy accounting:
    Each step consumes privacy budget ε_step
    After T steps with sampling rate q:
    Total budget consumed: ε_total (computed via moments accountant)
```

**Why DP-SGD has adversarial robustness effects:**

Gradient clipping limits how much any single example can influence the model. This makes the model less "pointy" (less optimized to perfectly classify individual training examples) and more "smooth" — smoother models have more consistent behavior in the ε-ball around inputs.

**Tradeoff:** DP-SGD significantly degrades accuracy (often 5–15% on complex tasks). The privacy budget ε is a parameter — smaller ε = more private = more noise = lower accuracy. In practice, very tight privacy (ε < 1) comes with significant utility loss.

---

## 7. Attack Surface Mapping

```
╔══════════════════════════════════════════════════════════════════════════════╗
║            ADVERSARIAL ATTACK SURFACE: ML INFERENCE SYSTEM                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

EXTERNAL ATTACK SURFACE
═══════════════════════════════════════════════════════════════════════════════

ENTRY 1: Inference API Endpoint — HTTPS :443 /v1/classify
  Auth: API key (malware scanner), OAuth (biometric system)
  Input: raw binary (malware), JPEG image (biometric)
  Attack:
    - Adversarially crafted input (evasion)
    - Oversized input (DoS — parser exhaustion)
    - Malformed input (parser vulnerability)
    - High-volume query (model extraction, black-box attack)
  Who: External email senders (System A), Physical intruders (System B)

ENTRY 2: Confidence Score / Soft Label Response
  Even soft labels enable black-box gradient estimation
  Attack: query oracle for gradient approximation → craft adversarial examples
  Mitigation: return hard labels only in high-security mode
  Tradeoff: operators lose actionable risk information

ENTRY 3: Enrolled Template Database (Biometric)
  s3://biometric-templates/{person_id}.npy
  Attack: read enrolled templates → reconstruct target's face appearance
  Attack: write fake templates → enroll attacker as victim (template poisoning)
  Auth: separate IAM policy, MFA-gated admin access only
  Encryption: SSE-KMS with dedicated key

ENTRY 4: Model Artifact Storage
  s3://ml-models-bucket/{model_version}/
  Attack: read model weights → white-box attacks become trivial
  Attack: modify model weights → backdoor insertion (training-phase attack,
          different category but same storage surface)
  Auth: KMS-encrypted, IAM restricted to inference service role only

INTERNAL ATTACK SURFACE
═══════════════════════════════════════════════════════════════════════════════

ENTRY 5: Model Serving API (Triton) — internal :8001 gRPC
  Not internet-exposed. VPC-internal only.
  Attack if reached: direct model queries, no rate limiting,
                     may return internal metadata including activations

ENTRY 6: Feature Extraction Pipeline
  Runs ATTACKER'S INPUT (the binary/image) through a parser
  Attack: craft input to exploit parser vulnerabilities
  Attack: craft input to cause extreme processing time (ZIP bombs, 
          deeply recursive structures)

ENTRY 7: Training Data Repository (affects future model versions)
  Attack: data poisoning — insert malicious training examples
  Different attack category (supply chain / training phase) but
  same infrastructure surface as inference-phase storage

ENTRY 8: Model Registry / Experiment Tracking (MLflow)
  Stores model metadata, hyperparameters, evaluation results
  Attack: modify evaluation metrics → promote a vulnerable model
  Attack: inject backdoored model as a valid artifact

TRUST BOUNDARY MAP
═══════════════════════════════════════════════════════════════════════════════

[Internet / Physical World]
    │
    │ (UNTRUSTED: any input is adversarial until proven otherwise)
    │
    ▼
[Ingestion / Preprocessing Layer]   ← BOUNDARY 1: parser sandbox
    │ normalized feature vector
    │ (attacker still controls VALUES, not format)
    ▼
[Inference API / Model Serving]     ← BOUNDARY 2: feature validation
    │ raw model predictions
    │ (may leak decision boundary info)
    ▼
[Business Logic / Thresholding]     ← BOUNDARY 3: confidence thresholds
    │ hard label decision
    ▼
[Downstream Action]                 ← BOUNDARY 4: action enforcement
  (email block, door control)

[Model Artifacts / Weights]         ← BOUNDARY 5: storage access control
    ↕
[Inference Runtime]

[Training Pipeline]                 ← BOUNDARY 6: training data integrity
    ↕
[Model Registry]
```

```
ADVERSARIAL ATTACK SURFACE: DETAILED TOPOLOGY

╔═══════════════╗     adversarial    ╔════════════════╗     gradient     ╔══════════════╗
║  ATTACKER     ║ ─── input ──────▶  ║  INFERENCE     ║ ─── estimation ─▶ ║  SUBSTITUTE  ║
║               ║                    ║  API           ║ (black-box)       ║  MODEL       ║
║  knows:       ║ ◀─── label ──────  ║  (black-box)   ║                   ║  (white-box  ║
║  - input space║                    ╚════════════════╝                   ║  attack on   ║
║  - output space                              │                          ║  substitute) ║
║  - possibly   ║               target model   │ steal via                ╚══════════════╝
║    model arch ║               weights        │ model extraction               │
╚═══════════════╝               ▼ (if stolen)  │                                │
                        ╔═══════════════╗       │ query + label                  │ transfer
                        ║  WHITE-BOX    ║       ▼                                │ adversarial
                        ║  FGSM/PGD     ║ ╔══════════════╗                       │ examples
                        ║  ATTACK       ║ ║ BOUNDARY     ║◀──────────────────────┘
                        ╚═══════════════╝ ║ ATTACK       ║
                                          ║ (no gradient ║
                                          ║  needed)     ║
                                          ╚══════════════╝

All paths converge on the same goal: an input x_adv such that:
  f(x_adv) = target_class   (misclassification)
  ||x_adv - x_original|| < ε   (imperceptible perturbation)
```

---

## 8. Failure Points

### What Fails Under Load

**GPU memory exhaustion from adversarial batch processing:**

Normal inference: 1 forward pass per input.
Adversarial training: 10 forward + 10 backward passes per input (PGD-10).
Defense with randomized smoothing: 1000 forward passes per input.

At 1000 requests/second with randomized smoothing:
- Normal: 1000 forward passes/second
- With smoothing (n=1000): 1,000,000 forward passes/second — ~1000× GPU load

Under adversarial attack load, the serving infrastructure assumes normal inference costs. Adversarial queries cost EXACTLY the same as normal queries at inference time (the attacker already did the optimization offline). But if the defense includes online adversarial example detection with expensive operations (smoothing, ensemble queries), the costs multiply.

**Key failure mode:** The defense is computationally asymmetric — attacker pays once to generate the adversarial example offline, defender pays per-query for the expensive defense. An attacker can craft 1 adversarial example offline (cost: 10 minutes of GPU time) and submit it 1000 times (cost: $0). The defender pays for 1000 expensive defensive evaluations.

**Mitigation:** Rate limiting per API key. Async processing for expensive defenses. Caching of adversarial detection results for identical inputs (input hash → cached verdict).

---

### Model Drift and Concept Drift

**Model drift in malware detection:**

The malware ecosystem evolves continuously. New malware families appear, new obfuscation techniques are invented, new packing methods are used. A model trained in January 2024 may have degraded significantly by January 2025.

```
Drift types:
1. CONCEPT DRIFT: the relationship between features and labels changes
   Example: Section entropy was a strong predictor of packed malware in 2020.
   By 2024, benign software increasingly uses high-entropy compression.
   The same feature value now means something different.

2. COVARIATE SHIFT: the input distribution changes but the label-conditional
   distribution is stable.
   Example: average file sizes grow, import table sizes grow.
   The model's normalization (μ, σ) is now wrong for current inputs.
   
3. ADVERSARIAL DISTRIBUTION SHIFT: attackers INTENTIONALLY move their
   inputs to shift the feature distribution toward the benign region.
   This is the adversarial attack — but viewed as a distribution shift
   over a population of malware samples.
```

**Detecting drift:**

```python
# Monitor feature distribution using Population Stability Index (PSI)
def compute_psi(baseline_dist, current_dist, buckets=10):
    """
    baseline_dist: feature distribution at training time
    current_dist: feature distribution this week
    
    PSI = Σ (actual% - expected%) × ln(actual% / expected%)
    
    PSI < 0.1: No significant shift
    PSI 0.1–0.25: Some shift — monitor
    PSI > 0.25: Significant shift — retrain or investigate
    """
    ...

# For each feature dimension i:
psi_i = compute_psi(train_features[:, i], production_features[:, i])
```

**Failure from drift without remediation:**

- False negative rate (missing malware) increases silently
- There's no "error" visible — the model keeps returning predictions confidently
- The only signal is the drift metric OR increased malware incidents on monitored endpoints
- Without drift monitoring, a defender may not know the model has failed for weeks

---

### High False-Positive Scenarios

**Why adversarial defenses cause false positives:**

Every detection mechanism has a false positive rate. The tradeoff is between:
- Sensitivity (detect more adversarial examples) → higher false positive rate
- Specificity (fewer false alarms) → lower true positive rate

**Scenario: Feature squeezing on legitimate compressed files**

Legitimate software often uses compression, encryption, or intentional obfuscation for IP protection. These files have:
- High section entropy (same as packed malware)
- Unusual byte n-gram distributions (same as shellcode)
- After feature squeezing: the verdict may change

If the feature squeezing detector flags all files where the verdict changes, legitimate protected software is flagged as adversarial. This causes:
- IT security team receiving daily false alerts for legitimate software
- Analyst fatigue → real adversarial attacks are missed
- Business disruption if legitimate software is quarantined

**Scenario: Biometric system under natural lighting variation**

On a bright sunny day, face embeddings may shift due to extreme lighting conditions. The cosine similarity to the enrolled template drops. If the threshold τ = 0.85 is set for adversarial robustness (higher threshold = more conservative = harder to spoof), legitimate employees are locked out on bright days.

The adversarial robustness threshold and the usability threshold are in direct conflict. Higher threshold makes the system more robust to evasion AND more likely to deny legitimate users.

**Quantifying the tradeoff:**

```
ROC curve for biometric verification:
  X-axis: False Accept Rate (FAR) — adversarial inputs accepted as legitimate
  Y-axis: False Reject Rate (FRR) — legitimate inputs rejected

  Threshold τ = 0.85: FAR = 0.001%, FRR = 2%  (high security, annoying for users)
  Threshold τ = 0.70: FAR = 0.01%, FRR = 0.3% (balanced)
  Threshold τ = 0.60: FAR = 0.1%,  FRR = 0.05% (low security, good UX)
  
The EER (Equal Error Rate) — where FAR = FRR — is ~τ = 0.75, FAR = FRR ≈ 0.5%

Under adversarial attack, all threshold choices are worse:
  Attacker shifts adversarial inputs toward higher similarity scores
  FAR increases at every threshold point
  The entire ROC curve degrades toward the random chance diagonal
```

---

## 9. Mitigations & Observability

### Concrete Mitigations by Layer

**Layer 1: Input validation (before model)**

```python
class InferenceInputValidator:
    def validate_binary(self, raw_bytes: bytes) -> ValidationResult:
        # Size limits
        if len(raw_bytes) > 50 * 1024 * 1024:  # 50 MB max
            raise InputTooLargeError()
        
        # PE magic bytes check (fail fast before expensive parsing)
        if raw_bytes[:2] != b'MZ':
            raise InvalidFormatError("Not a PE binary")
        
        # Parser in subprocess with resource limits
        result = subprocess.run(
            ['python', 'extract_features.py'],
            input=raw_bytes,
            capture_output=True,
            timeout=5,          # 5-second timeout
            cwd='/tmp/sandbox',  # minimal working directory
        )
        
        # Semantic normalization (destructs known adversarial techniques)
        features = self.normalize_pe_binary(result.stdout)
        return features
    
    def normalize_pe_binary(self, features):
        # Apply semantic-preserving normalization
        # These destroy known adversarial feature manipulations
        features['overlay_size'] = 0  # strip overlay
        features['header_timestamp'] = 0  # normalize timestamp
        return features
```

**Layer 2: Adversarial input detection (before returning verdict)**

```python
class AdversarialDetector:
    def __init__(self, base_model, squeezers):
        self.base_model = base_model
        self.squeezers = squeezers  # list of squeezing transformations
        self.threshold = 0.15       # max allowed prediction change
    
    def detect(self, x):
        orig_pred = self.base_model.predict_proba(x)
        
        for squeezer in self.squeezers:
            x_squeezed = squeezer.transform(x)
            squeezed_pred = self.base_model.predict_proba(x_squeezed)
            
            # If prediction changes significantly after squeezing: suspicious
            if abs(orig_pred[1] - squeezed_pred[1]) > self.threshold:
                return AdversarialDetectionResult(
                    is_adversarial=True,
                    confidence=abs(orig_pred[1] - squeezed_pred[1]),
                    triggering_squeezer=squeezer.name
                )
        
        return AdversarialDetectionResult(is_adversarial=False)
```

**Layer 3: Ensemble and multi-model disagreement detection**

```python
def ensemble_with_agreement_check(models, x):
    predictions = [m.predict(x) for m in models]
    
    # If models trained on different data or with different architectures
    # disagree, the input may be adversarial
    if len(set(predictions)) > 1:  # disagreement
        # Flag for human review or higher-tier verification
        return PredictionResult(
            verdict='UNCERTAIN',
            requires_review=True,
            model_votes=predictions
        )
    
    return PredictionResult(verdict=predictions[0])
```

**Layer 4: Rate limiting and query pattern detection**

```python
# Black-box attacks require many queries — detect the query pattern
class AdversarialQueryMonitor:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def check_and_record(self, api_key, input_hash):
        # Track unique inputs per API key per hour
        hour_key = f"queries:{api_key}:{datetime.now().strftime('%Y%m%dT%H')}"
        
        # Add input hash to set
        self.redis.sadd(hour_key, input_hash)
        self.redis.expire(hour_key, 7200)
        
        unique_count = self.redis.scard(hour_key)
        
        # Normal behavior: few unique inputs per hour
        # Model extraction / boundary attack: thousands of unique inputs
        if unique_count > 1000:
            log.warning(f"Potential model extraction: {api_key} made "
                       f"{unique_count} unique queries this hour")
            if unique_count > 5000:
                raise RateLimitExceeded("Possible adversarial query pattern")
```

---

### Engineering Tradeoffs

| Defense | Clean Accuracy | Adversarial Accuracy | Latency Cost | Implementation Complexity |
|---|---|---|---|---|
| No defense | 99.8% | 3% (under PGD) | baseline | minimal |
| Feature squeezing | 99.5% | 45% | +20% | low |
| Adversarial training (PGD-10) | 97.5% | 55% | 0% at inference, 10× training | high |
| Randomized smoothing (n=1000) | 96% | 60% (certified L2) | 1000× | medium |
| Ensemble disagreement | 99.3% | 50% | 3–5× | medium |
| Input normalization (malware) | 99.1% | 70% (domain-specific) | +30% | medium |

---

### Observability: What to Log and Metric

**Metrics to collect (every inference request):**

```python
@dataclass
class InferenceMetrics:
    request_id: str
    api_key_hash: str              # hashed — don't log raw API keys
    input_hash: str                # SHA256 of input — for dedup and tracking
    input_size_bytes: int
    
    # Model output
    predicted_class: int
    confidence_score: float        # log this even if not returned to client
    top_features: List[str]        # top contributing features (for drift)
    
    # Adversarial detection signals
    feature_squeezing_delta: float # prediction change after squeezing
    is_adversarial_flagged: bool
    
    # Performance
    preprocessing_latency_ms: float
    inference_latency_ms: float
    total_latency_ms: float
    
    # Distribution monitoring
    feature_vector_l2_norm: float  # distance from training distribution centroid
    mahalanobis_distance: float    # statistical distance from training distribution
    
    timestamp: datetime
    model_version: str
```

**Alerts (page immediately):**

```yaml
# Prometheus alert rules

- alert: HighAdversarialDetectionRate
  expr: |
    rate(adversarial_flagged_total[5m]) / rate(inference_total[5m]) > 0.05
  for: 2m
  annotations:
    summary: "5%+ of requests flagged as adversarial in last 5 minutes"
    # Normal rate: < 0.1%. Spike suggests active attack campaign.

- alert: ModelEvasionSuspected
  expr: |
    # High confidence predictions that were wrong on labeled samples
    # (requires feedback loop from downstream systems)
    rate(confirmed_evasions[1h]) > 0
  annotations:
    summary: "Confirmed evasion: adversarial example bypassed all defenses"

- alert: InputDistributionDrift
  expr: |
    feature_psi_score{dimension="section_entropy"} > 0.25
  for: 30m
  annotations:
    summary: "Feature distribution drift detected — model may need retraining"

- alert: ModelExtractionAttempt
  expr: |
    unique_inputs_per_api_key_per_hour > 2000
  annotations:
    summary: "Potential model extraction attack: unusual query diversity"
    
- alert: InferenceLatencySpike
  expr: |
    histogram_quantile(0.99, inference_latency_seconds) > 2.0
  annotations:
    summary: "P99 inference latency >2s — possibly adversarial DoS inputs"
```

**Don't alert on (log only):**

```
- Individual adversarial detection flags (noise — occasional false positives)
- Single slow requests (network variance)
- Minor feature distribution shifts (PSI < 0.1)
- Prediction confidence < threshold (expected behavior — model uncertainty)
- Individual input normalization changes (expected for legitimate edge cases)
```

**The feedback loop — closing the detection loop:**

```
Adversarial detection ──▶ Flag input ──▶ Human review queue
                                              │
                                              ▼
                                       Confirm adversarial?
                                              │
                              ┌───────────────┼───────────────┐
                              ▼               ▼               ▼
                     Yes (confirmed)   No (false positive) Maybe (uncertain)
                              │                                │
                              ▼                               ▼
                    Add to adversarial           Log for distribution analysis
                    training set               Lower detection threshold for
                              │                this input type
                              ▼
                    Retrain model with
                    new adversarial examples
                              │
                              ▼
                    Evaluate on existing
                    adversarial test set
                              │
                              ▼
                    Promote if accuracy
                    improves under attack
```

---

## 10. Interview Questions

### Q1: Explain FGSM mathematically. What does the sign function do and why is it used instead of the raw gradient?

**Direct answer:**

FGSM computes the adversarial example as:
```
x_adv = x + ε · sign(∂L(f_θ(x), y) / ∂x)
```

The gradient `∂L/∂x` is a vector in ℝ^d where each component indicates how much the loss increases per unit change in that input dimension. The magnitude of each component varies — some dimensions of the input are more influential than others.

The `sign()` function converts this vector to a vector of ±1 values — eliminating magnitude information, keeping only direction. Why?

The constraint is an L∞ ball: we can change each dimension by at most ε. To maximize the change in loss subject to an L∞ constraint, we should allocate our full budget ε to every dimension in the direction that increases loss. The optimal solution to `max_{||δ||∞ ≤ ε} δ·g` (maximize dot product with gradient g subject to L∞ constraint) is exactly `δ = ε · sign(g)`.

If we used the raw (unnormalized) gradient instead, dimensions with large gradient magnitude would dominate. The constraint would be violated on large-magnitude dimensions while most of the ε budget in small-magnitude dimensions would go unused — suboptimal.

**What if the sign function were replaced with L2 normalization instead?**

Then you'd be maximizing loss subject to an L2 constraint: `max_{||δ||₂ ≤ ε} δ·g` — optimal solution is `δ = ε · g/||g||₂`. This corresponds to an L2 attack. For images, L2 attacks produce perturbations that are concentrated in high-gradient regions (edges, fine details). L∞ attacks (using sign) produce perturbations uniformly distributed across all pixels. Both are used — L∞ attacks are harder to perceive visually because no single pixel changes too much, making them the dominant choice for adversarial example research.

---

### Q2: Why does adversarial training improve robustness? What does it do to the model's decision boundary, and what is the fundamental tradeoff?

**Direct answer:**

Adversarial training solves the saddle-point problem:
```
min_θ max_{||δ||∞ ≤ ε} L(f_θ(x + δ), y)
```

The inner maximization finds the worst-case perturbation for each training example. The outer minimization updates the model to correctly classify even the worst-case input.

**What this does to the decision boundary:**

Standard training creates a decision boundary that fits the training data with high precision — it can curve sharply near training examples to achieve high accuracy. These sharp curves are near the natural data manifold and create pockets that adversarial examples exploit.

Adversarial training forces the model to be correct not just at x, but at every point in the ε-ball B_ε(x). To classify correctly everywhere in B_ε(x), the decision boundary must pass OUTSIDE this ball — it must be at least ε away from every training example. This flattens the boundary. Adversarially trained models have:
- Smaller input gradients (flatter loss landscape near data points)
- More conservative prediction confidence near the boundary
- Larger "safe zones" around correctly classified examples

**The fundamental tradeoff (Theorem, Yang et al., 2020):**

There exists a fundamental tension between clean accuracy and adversarial robustness. Formally, for any classifier:
```
ε-robust accuracy ≤ clean accuracy - |D_adv|
```
where D_adv captures the inherent incompatibility of natural and adversarial accuracy. In practice:
- A ResNet-50 achieves 95% clean accuracy on ImageNet but 0% adversarial accuracy (under PGD)
- After adversarial training: ~75% clean accuracy, ~45% adversarial accuracy
- Across any model, as adversarial accuracy increases, clean accuracy decreases

The geometric reason: the ε-ball around benign and malicious examples can overlap. If two training examples of different classes have ε-balls that intersect, no classifier can be correct in both balls simultaneously.

---

### Q3: A defender claims their model is "adversarially robust" because FGSM attacks don't work. How do you test whether this is true robustness or gradient masking?

**Direct answer:**

This is exactly the problem that plagued early adversarial defense papers — many claimed defenses were actually gradient masking.

**Test 1: Apply FGSM with a much larger ε**

If the model is gradient-masked (gradients are uninformative), even large ε won't help FGSM (because the gradient is pointing the wrong direction). If the model is truly robust, large ε will eventually succeed (you'll exceed the certified robustness radius). Test: sweep ε from 0 to 1.0. True robustness: accuracy degrades smoothly with ε. Gradient masking: accuracy stays high until a very large ε, then suddenly drops (the gradient finally becomes informative at large scales).

**Test 2: Apply a decision-based attack (HopSkipJump, Boundary Attack)**

Decision-based attacks use ONLY the hard label — no gradient needed. Start from a known misclassified example, walk toward the original, staying misclassified. If this attack succeeds in finding a small-ε adversarial example close to the original, the model is NOT truly robust — the decision boundary is still close to natural examples, but the gradient was obscured.

**Test 3: Transfer attack**

Train a substitute model on similar data. Craft adversarial examples against the substitute (where gradients ARE informative). Transfer them to the defended model. If transfer succeeds, gradient masking was the defense.

**Test 4: BPDA (Backward Pass Differentiable Approximation)**

If the defense includes non-differentiable preprocessing (e.g., JPEG compression, median filtering), substitute a differentiable approximation for the backward pass. Attack using the differentiable approximation to compute gradients. If this adaptive attack succeeds where standard attacks fail, the "defense" was relying on gradient non-differentiability, not actual robustness.

The community standard (Carlini et al., 2019): a defense is only valid if it withstands an adaptive attacker who knows and incorporates the defense into their attack.

---

### Q4: In the malware detection scenario, why is feature-space adversarial training insufficient and what additional property must the defense guarantee?

**Direct answer:**

**The problem: feature space ≠ input space for malware**

For images: every point in input space (any combination of pixel values) is a valid image. A perturbation in image space is trivially a valid input.

For malware: the input is a PE binary file. The feature space is derived from the binary via a many-to-one mapping (many binaries map to the same feature vector). A perturbation in feature space may have NO corresponding valid binary.

Adversarial training in feature space: find perturbation δ ∈ ℝ^2381 such that feature_vector + δ is misclassified. Train the model to be robust to this δ. Problem: there may be no PE binary whose features equal (feature_vector + δ). The model learned robustness to fictional inputs that can never be constructed by a real attacker.

**The correct formulation:** robustness must be defined over the space of valid, semantics-preserving binary modifications:

```
Valid binary modifications (semantics-preserving operations):
- Append data to overlay section
- Insert NOP sleds in code caves
- Add fake API imports (not called at runtime)
- Modify PE header metadata (timestamp, etc.)
- Add new sections with benign content
- Reorder existing sections (if code is PIC)

Invalid for adversarial training in feature space:
- Set section entropy to 3.5 without changing bytes
- Set import count to 0 without removing imports
```

The correct adversarial training must:
1. Generate perturbations in the binary space (apply valid binary transformations)
2. Extract features from the modified binary
3. Train on these features

This requires the attack to be implemented at the binary level, not the feature level. This is why malware adversarial examples are much harder to construct and evaluate than image adversarial examples — you must solve the inverse feature mapping problem.

---

### Q5: What is the difference between L∞, L2, and L0 adversarial perturbations? When would you use each, and how do they affect the model's vulnerability surface differently?

**Direct answer:**

Each Lp norm constraint defines a different "ball" around the original input — the set of allowed adversarial examples.

**L∞ (Linf) constraint: ||x_adv - x||∞ = max_i |x_adv_i - x_i| ≤ ε**

The L∞ ball: every dimension can be changed by at most ε. A uniform budget across all dimensions.
Attack (FGSM, PGD): change every pixel by exactly ε in the gradient direction.
Geometric shape: a hypercube in d dimensions, axis-aligned.
Perceptual effect for images: uniform, fine-grained noise across the entire image — no region is changed more than another. Imperceptible at ε < 8/255.
Use case: the standard for image adversarial examples. Most papers use L∞.
Why a model fails: the cumulative effect of many small per-dimension changes is large (ε × d in the feature dimension if features are correlated with all input dimensions).

**L2 constraint: ||x_adv - x||₂ = √(Σ(x_adv_i - x_i)²) ≤ ε**

The L2 ball: the total Euclidean distance from original is at most ε. Budget can be concentrated or spread.
Attack (C&W attack, DeepFool): concentrate perturbation where the gradient is strongest (high-magnitude gradient dimensions get more budget).
Geometric shape: a hypersphere in d dimensions.
Perceptual effect for images: perturbation concentrated in high-gradient regions (edges, texture boundaries). Locally larger changes but restricted in extent.
Use case: natural adversarial examples (in-distribution robustness), certified defenses (randomized smoothing certifies L2 radius).
Why it matters: L2 is more natural for high-frequency attacks — modifying one concentrated region rather than all pixels simultaneously.

**L0 constraint: ||x_adv - x||₀ = |{i: x_adv_i ≠ x_i}| ≤ k**

The L0 "norm": number of changed dimensions. Only k pixels can be changed; those k pixels can be changed arbitrarily.
Attack (JSMA — Jacobian Saliency Map Attack): identify the k pixels that, when changed, most affect the prediction.
Geometric shape: union of all k-sparse coordinate subspaces — highly non-convex, NP-hard to optimize exactly.
Perceptual effect for images: few isolated pixels changed by large amounts — looks like "salt and pepper" noise or small bright dots.
Use case: physical world attacks (few-pixel patches), hardware sensor attacks.

**Which is hardest to defend against?**

No answer dominates across all cases. A defense robust to L∞ may not be robust to L0 (and vice versa). A model adversarially trained with L∞ examples will be robust to L∞ attacks but may still be vulnerable to C&W L2 attacks with ε tuned to the same perceptual distortion level. Robust evaluation requires testing all three.

---

### Q6: Explain why transferability of adversarial examples occurs across different models, and how this property is exploited in black-box attacks. What limits transferability?

**Direct answer:**

**Why transferability occurs:**

Deep neural networks trained on the same task and data distribution learn similar features, and therefore have correlated decision boundaries. If model A and model B both correctly classify most inputs, their decision boundaries must be geometrically "near" each other in input space — otherwise one of them would make errors that the other doesn't.

Adversarial examples crafted for model A find a direction that crosses model A's boundary. Since model B's boundary is nearby (the models agree on most of the input space), moving in the same direction also crosses model B's boundary.

More precisely: both models learn approximately the same input manifold structure. The "natural" data manifold is low-dimensional. Off the manifold, both models are undefined. Adversarial examples push inputs off the manifold — and since both models are extrapolating in the same uncertain region, their behaviors are correlated.

**How black-box attacks exploit transferability:**

1. **Data collection:** Attacker queries target model f_T to collect (input, label) pairs: {(x_i, f_T(x_i))}_i
2. **Substitute training:** Train substitute model f_S on this data using the target model's labels as ground truth
3. **Adversarial example generation:** Run PGD against f_S to find δ such that f_S misclassifies x + δ
4. **Transfer:** Submit x + δ to f_T, hoping f_T also misclassifies it

Transferability rates: typically 40–80% for models with the same architecture, 20–50% for different architectures, higher for simple models (less complex boundaries, more likely correlated).

**What limits transferability:**

1. **Model diversity:** Models trained with different architectures, different initializations, or different subsets of training data have less correlated decision boundaries. Ensemble defenses (disagree on adversarial examples) exploit this.

2. **Adversarial training:** Adversarially trained models have "flatter" decision boundaries that are harder to push across — even with transferred examples, the target model may still be correct because its boundary is further from natural data.

3. **Distribution shift:** If the substitute model was trained on different data (e.g., public dataset for a private target), the substitute's features may not match the target's features, reducing correlation.

4. **Preprocessing:** Defenses that transform the input before inference (feature squeezing, smoothing) change the input that reaches the model — adversarial examples crafted for the unpreprocessed input may not transfer through the preprocessing step.

---

### Q7: A biometric system uses a threshold of 0.85 cosine similarity. An adversarial attack is crafted that achieves cosine similarity of 0.87 against the target template. What does the geometry of the embedding space tell us about why this is possible? What architectural change would make it harder?

**Direct answer:**

**The embedding space geometry:**

ArcFace embeddings lie on the unit hypersphere S^511 ⊂ ℝ^512. The enrolled templates for N people are N points on this sphere. Cosine similarity between two unit vectors equals the cosine of the angle between them.

At threshold τ = 0.85:
- cos(θ) > 0.85 → θ < arccos(0.85) ≈ 31.8°

The acceptance region for a target identity is a spherical cap of angular radius ~31.8° around the enrolled template. In 512 dimensions, this cap has a surprisingly large volume — the curse of dimensionality means high-dimensional spherical caps are geometrically large.

The adversarial attack moves the embedding from the attacker's natural location (cosine sim 0.3 with victim) to within 31.8° of the victim's template. The FGSM/PGD attack is exactly computing: "which direction on the image manifold moves the embedding toward the victim's template location on the hypersphere?"

**Why it's geometrically possible:**

The CNN maps 150,528-dimensional image space to 512-dimensional embedding space. The map is highly non-isometric — small movements in image space can correspond to large movements in embedding space (the network amplifies certain directions). The adversarial attack exploits the directions in image space that map to large movements in embedding space.

Furthermore, the ArcFace margin m is designed to separate classes during training — but once training is complete, the acceptance spherical caps are fixed. An attacker doesn't need to move to the exact enrolled template — only to within 31.8° of it.

**Architectural changes that make this harder:**

1. **Reduce the acceptance cap size (increase threshold τ):** τ = 0.95 → cap of angular radius ~18°. Much smaller target. But: higher false reject rate for legitimate users with natural variation.

2. **Larger margin in ArcFace:** Increasing the margin parameter m forces larger angular separation between classes during training. Classes are pushed further apart on the sphere, reducing the probability that an adversarial example from one person's image ends up in another's cap.

3. **Add liveness detection (orthogonal defense):** Verify that the input is from a live human face (3D depth, infrared pulse detection, blink detection). Adversarial printed photos fail liveness detection regardless of their embedding quality. This is an orthogonal defense that doesn't change the embedding geometry but eliminates the physical attack vector.

4. **Require consistency across multiple frames:** Use video input (5–10 frames). The adversarial perturbation must be consistent across multiple camera frames with slight variation. A single printed photo can't maintain adversarial consistency across natural motion. Compute the MEAN embedding across frames — random variation in the perturbation averages out, potentially destroying the adversarial effect.

---

### Q8: What is the Carlini-Wagner (C&W) attack? How does it differ from PGD, and why was it significant for evaluating adversarial defenses?

**Direct answer:**

**The C&W attack (Carlini & Wagner, 2017)** is an optimization-based attack that finds the smallest (in L2 norm) perturbation that causes misclassification. It reformulates adversarial example finding as a constrained optimization problem.

**Objective:**

```
minimize ||δ||₂²   (minimize perturbation size)
subject to: f(x + δ) = t   (achieve target misclassification)
             0 ≤ x_i + δ_i ≤ 1  (valid pixel values)

Equivalently (Lagrangian relaxation):
minimize ||δ||₂² + c × loss(x + δ, t)
```

Where `loss(x + δ, t)` is a carefully designed function:
```
loss(x, t) = max(max_{i≠t}(logit_i) - logit_t, -κ)

If logit_t > max_{i≠t}(logit_i) by margin κ: 
  loss = 0 (misclassification achieved with confidence κ)
Otherwise:
  loss = max_{i≠t}(logit_i) - logit_t > 0 (measure of how far from misclassification)
```

**How C&W differs from PGD:**

PGD works in L∞ space with a fixed budget ε. It projects back onto the ε-ball after each step. The perturbation has fixed maximum magnitude per dimension.

C&W works in L2 space and minimizes the perturbation size directly. It uses the Adam optimizer (adaptive learning rate, momentum) rather than projected gradient descent. It can find adversarial examples with smaller L2 perturbations than PGD's minimum. It runs inner optimization for ~1000 iterations with binary search on the constant c.

**The change of variables trick:**

To handle the box constraint (pixels must be in [0,1]) without projection, C&W uses:
```
δ_i = (tanh(w_i) + 1) / 2 - x_i
```
where w_i is unconstrained. This ensures x_i + δ_i ∈ [0,1] automatically, and the optimization is over unconstrained w_i (easier to optimize with Adam).

**Why it was significant:**

In 2017, many papers claimed adversarial defenses by showing FGSM and PGD didn't work on their model. Carlini & Wagner showed that C&W bypassed essentially ALL existing defenses that relied on gradient masking or input preprocessing — 10 of the strongest published defenses failed completely against C&W.

The reason: C&W finds smaller perturbations (minimum L2 distance to the boundary), which means it finds adversarial examples that preprocessing methods can't destroy. It also doesn't rely on the gradient sign (uses the full gradient magnitude), making it more effective against smooth, non-masked models.

The lesson: the strength of a defense is measured against the strongest known attack. Always evaluate with C&W, not just FGSM.

---

### Q9: What is certified adversarial robustness, and how does randomized smoothing achieve provable guarantees? What are its limitations?

**Direct answer:**

**Certified vs. empirical robustness:**

Empirical robustness: "this attack failed, therefore the model is probably robust." Cannot rule out stronger attacks.

Certified robustness: "for this input x, NO perturbation within radius R can change the classification." Mathematically provable — no attack can beat it within the certified radius.

**Randomized Smoothing certification:**

Define the smoothed classifier:
```
g(x) = argmax_c P_{ε~N(0,σ²I)}[f(x + ε) = c]
```

Cohen et al. theorem:
```
If g classifies x as class A and p_A = P[f(x+ε) = A] > 0.5, then:
  For ALL δ with ||δ||₂ ≤ R = σ × Φ⁻¹(p_A):
    g(x + δ) = A
```

In words: as long as we can estimate p_A (the probability that f outputs A when the input is Gaussian-noised), we can certify robustness within radius R.

Proof sketch: the Neyman-Pearson lemma shows that Gaussian noise is the optimal noise distribution for L2 certification — any rotation of the perturbation δ maps to a rotation of the noise, and Gaussian noise is rotation-invariant. This allows the L2 ball robustness to be converted to a statement about the noise distribution.

**Practical estimation:** p_A is estimated via Monte Carlo sampling:
1. Sample n = 10,000 noise vectors ε_1, ..., ε_n from N(0, σ²I)
2. Count how many times f(x + ε_i) = A: count_A
3. p_A_hat = count_A / n
4. Use Clopper-Pearson confidence interval for a lower bound p_A_lower
5. Certified radius R = σ × Φ⁻¹(p_A_lower)

**Limitations:**

1. **L2 only:** Randomized smoothing certifies L2 robustness. There is no analogous guarantee for L∞ (which is the more common threat model in practice). Extensions to L∞ have much weaker guarantees.

2. **Computational cost:** n=10,000 forward passes per prediction. For a face recognition system processing 500 faces/second, this requires 5,000,000 forward passes/second — orders of magnitude beyond practical GPU capacity.

3. **Accuracy-robustness-radius tradeoff:** As σ increases, the certified radius increases (more robust), but clean accuracy decreases (too much noise for correct prediction). As σ decreases, accuracy improves but certification radius shrinks. Typical tradeoff: σ=0.25 gives R≈1 in pixel space (weak guarantee) but maintains ~70% accuracy; σ=1.0 gives R≈4 but accuracy drops to ~50%.

4. **Abstention:** When p_A ≤ 0.5, the classifier abstains (returns "uncertain"). This can be triggered by an adversary who crafts inputs near the boundary where the smoothed classifier is uncertain — a denial-of-service against the classification system.

---

### Q10: Your malware detection system has 99.8% clean accuracy but is easily bypassed by appending benign content to malicious files. The fix you propose (strip overlay, re-extract features) catches the attack but increases false positive rate by 0.5%. How do you reason about this tradeoff, and what additional signals could you use to recover some of the lost precision?

**Direct answer:**

**Framing the tradeoff:**

Current state (without fix):
- False negative rate (miss malware): low for known malware, high for adversarial variants
- False positive rate (flag benign): 0.2%
- Risk: adversarial attacks bypass detection → malware delivered

Fixed state (strip overlay):
- False negative rate (adversarial variants): significantly reduced
- False positive rate: 0.7% (+0.5%)
- Cost: 0.5% more benign files quarantined → operational overhead

**How to reason about it:**

The decision is a risk-weighted expected cost calculation:
```
Cost(no fix) = P(adversarial attack) × P(bypass | adversarial) × C(breach)
Cost(fix)    = P(false positive) × C(legitimate file quarantined)

C(breach) >> C(false quarantine)

If P(adversarial attack) × P(bypass) × C(breach) > 0.005 × C(false quarantine):
  deploy the fix
```

In a corporate email gateway receiving 100,000 emails/day:
- 0.5% FP = 500 extra quarantined emails/day
- Cost per quarantined email: analyst review time ~2 minutes → ~17 person-hours/day
- A single successful breach: incident response, legal, reputation damage → orders of magnitude higher cost

The fix is justified by expected cost even at significant FP increase.

**Recovering precision with additional signals:**

1. **Behavioral signals from the overlay itself:** Before stripping, analyze the overlay content. Is it executable code? Does it contain strings matching benign DLLs? A benign-content overlay in a file that was already classified as high-confidence malicious before overlay detection is extremely suspicious. Flag these specifically without increasing FP rate for truly benign-overlaid files.

2. **Reputation signals:** If the file's SHA256 or ssdeep hash is already in VirusTotal or similar databases, use that as a prior. A known-benign file from a software vendor doesn't need strip-and-reanalyze — the hash is sufficient.

3. **Code signing:** Legitimately installed software is typically signed. If the PE has a valid Authenticode signature from a trusted publisher, reduce suspicion weight. Malware appended with benign content typically either has no signature or has a signature on only part of the file.

4. **Two-phase classification:** First pass: classify without overlay stripping (current behavior). If confidence > 0.99 benign: deliver without strip (high-confidence benign, no need for extra analysis). If confidence < 0.99: apply stripping + reanalysis. This preserves FP rate for clearly benign files while defending against adversarial modifications applied to ambiguous cases.

5. **Temporal consistency:** If the same sender's domain has been delivering files for years without issues, and this particular file looks similar to their historical files except for an overlay, the overlay may be a legitimate software update. Sender reputation → prior that reduces false positive weight.

The general principle: adversarial robustness defenses that work unconditionally cause FP increases. Context-conditional defenses (apply the expensive defense only when other signals raise suspicion) maintain the FP rate while providing defense against adversarial attacks targeted at ambiguous-confidence inputs.

---

*End of document. This breakdown should be revisited when new attack families are published (check NeurIPS/ICML/ICLR adversarial ML track annually), when the serving infrastructure changes (TensorRT version updates can change FP16 model behavior), or when the feature extraction pipeline is modified (changes in feature engineering invalidate all adversarial training performed on the old feature set).*

---

**Further Reading (Foundational Papers):**
- Goodfellow et al. (2015) — Explaining and Harnessing Adversarial Examples (FGSM)
- Madry et al. (2018) — Towards Deep Learning Models Resistant to Adversarial Attacks (PGD)
- Carlini & Wagner (2017) — Evaluating the Adversarial Robustness of Neural Networks (C&W attack)
- Cohen et al. (2019) — Certified Adversarial Robustness via Randomized Smoothing
- Ilyas et al. (2019) — Adversarial Examples Are Not Bugs, They Are Features
- Tramer et al. (2020) — On Adaptive Attacks to Adversarial Example Defenses
# Side-Channel Attacks on Edge AI — Security Architecture Breakdown

**Classification:** Internal Engineering Reference  
**Audience:** Hardware Security Engineers, TEE Architects, ML Platform Security Teams  
**Assumed Reader:** Will be interviewed on this system. Every claim is grounded in hardware and OS internals.  
**Key References:** Intel TDX Architecture Specification, ARM TrustZone Developer Guide, NVIDIA H100 Confidential Computing whitepaper, NIST SP 800-193 (Platform Firmware Resiliency), Kocher et al. "Differential Power Analysis" (CRYPTO 1999), Yarom & Falkner "FLUSH+RELOAD" (USENIX 2014).

---

## Table of Contents

1. [Component Narrative](#1-component-narrative)
2. [OS & Hardware Layer Flow](#2-os--hardware-layer-flow)
3. [Cryptography & State Management](#3-cryptography--state-management)
4. [Backend / Control Plane Architecture](#4-backend--control-plane-architecture)
5. [Authentication & Trust Bootstrapping](#5-authentication--trust-bootstrapping)
6. [Security Controls & Anti-Tampering](#6-security-controls--anti-tampering)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Attack Scenarios & Defensive Architecture](#8-attack-scenarios--defensive-architecture)
9. [Failure Points & Scaling](#9-failure-points--scaling)
10. [Interview Questions](#10-interview-questions)

---

## 1. Component Narrative

### The System: A Deployed Edge AI Inference Node

An edge AI node is a self-contained compute unit deployed outside the traditional datacenter: in a hospital corridor, a factory floor, a retail kiosk, or an autonomous vehicle. It runs a proprietary neural network model — trained at significant cost, containing trade secrets — and must protect both the model's intellectual property and any inference data (which may be PII or regulated health data) from an adversary who may have **physical access** to the device.

This is the defining threat distinction from cloud AI: in a cloud datacenter, you control physical access. On an edge node, you do not. The device sits in a location where a motivated attacker can probe it with oscilloscopes, attach logic analyzers, remove storage, or run arbitrary code as the device's local administrator.

### The Primary Function: Secure Inference

**T=0: Device boots**

The Secure Boot chain begins in hardware. The CPU's fused Root of Trust verifies firmware signatures before executing a single instruction of OS code. The Trusted Platform Module (TPM) or equivalent security element measures each boot stage and extends PCR (Platform Configuration Register) values — a running cryptographic hash of everything that has executed.

**T+2s: TEE (Trusted Execution Environment) initializes**

The TEE — Intel SGX enclave, ARM TrustZone Secure World, or AMD SEV-SNP protected VM — starts before the main OS loads the inference runtime. The TEE:
1. Generates its own attestation report (signed by hardware-fused keys).
2. Requests a model decryption key from the remote provisioning server (after attestation).
3. Decrypts the model weights into protected memory.

**T+5s: Inference runtime starts in user space**

The ML runtime (TensorFlow Lite, ONNX Runtime, TensorRT) starts. It calls into the TEE via a defined API surface (ECALL in SGX, SMC in TrustZone) to access the protected model. Model weights never appear in normal process memory — the runtime sends batched input tensors to the TEE and receives output logits.

**T+10s onward: Inference requests arrive**

Input data arrives via a local API (gRPC over Unix socket, or a hardware input bus). The runtime:
1. Validates input schema and size.
2. Passes input into the TEE via shared memory (DMA-protected region).
3. The TEE performs forward pass computation using the protected weights.
4. Output (classification probabilities or regression values) is returned via shared memory.
5. Output is logged (encrypted) and returned to the caller.

**The sequence in inter-process communication terms:**

```
Client Process          Inference Runtime      TEE (Secure World)      HSM/TPM
     │                        │                       │                    │
     │─── gRPC request ──────>│                       │                    │
     │                        │─── ECALL(infer) ─────>│                    │
     │                        │   [shared memory]      │                    │
     │                        │<── OCALL return ───────│                    │
     │                        │                        │── TPM_PCR_Read()──>│
     │                        │                        │<── PCR values ─────│
     │<── gRPC response ──────│                        │                    │
```

**What the attacker wants to extract from this system:**
1. The model weights (IP theft — may represent $millions in training compute).
2. The inference inputs (PII, regulated health data, classified sensor readings).
3. The cryptographic keys (to re-deploy the model on unauthorized hardware).
4. The model architecture itself (even without weights, useful for competitive intelligence).

---

## 2. OS & Hardware Layer Flow

### The Privilege Ring Architecture for Edge AI

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        CPU PRIVILEGE LEVELS                              │
│                                                                          │
│  Ring -2 (SMM):  System Management Mode                                 │
│    Intel SMM handler in SMRAM (0xA0000–0xBFFFF typically)               │
│    Executes on SMI# interrupt; invisible to OS                           │
│    Has access to ALL physical memory                                     │
│    Loaded and verified by UEFI firmware                                  │
│    ┌──────────────────────────────────────────────────────────────────┐  │
│    │  ATTACK SURFACE: SMM vulnerabilities allow ring-2 code execution │  │
│    │  with full memory visibility — bypasses all OS/hypervisor        │  │
│    └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Ring -1 (VMX Root): Hypervisor (if present)                            │
│    Intel VT-x / AMD-V enabled                                           │
│    Controls VMCS (VM Control Structures) for each VM                    │
│    EPT (Extended Page Tables) enforces memory isolation between VMs     │
│    Edge AI: Often runs bare-metal or single-VM to reduce attack surface │
│                                                                          │
│  Ring 0: Kernel Space (Linux kernel, Windows kernel)                    │
│    Manages physical memory, device drivers, scheduler                   │
│    DMA-IOMMU: Intel VT-d enforces device DMA boundaries                │
│    Key security module: Integrity Measurement Architecture (IMA)        │
│      - Measures every executable before load (extends TPM PCR 10)      │
│      - Kernel keyrings hold measurement policy signing keys             │
│                                                                          │
│  Ring 3: User Space                                                      │
│    Inference runtime, model server, application code                   │
│    Interacts with TEE via driver (ioctl → kernel driver → hardware)     │
│                                                                          │
│  TEE: Orthogonal to rings — separate execution world                    │
│    Intel SGX: CPU-enforced encrypted memory pages (EPC)                 │
│    ARM TrustZone: NS bit in AArch64 banked registers                   │
│    AMD SEV-SNP: Encrypted VM memory, hardware-enforced page ownership   │
└──────────────────────────────────────────────────────────────────────────┘
```

### TEE Hardware Internals

**Intel SGX (Software Guard Extensions):**

```
Physical Memory Layout with SGX:
┌─────────────────────────────────────────────────────────────────────┐
│  Normal DRAM (visible to OS, hypervisor, other processes)           │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  PRM (Processor Reserved Memory) — SGX reserved region         │ │
│  │  ┌──────────────────────────────────────────────────────────┐  │ │
│  │  │  EPC (Enclave Page Cache) — encrypted by MEE             │  │ │
│  │  │  128MB – 512MB (hardware limited)                        │  │ │
│  │  │  Each 4KB page encrypted with AES-128-CTR                │  │ │
│  │  │  Encryption key: fused into CPU package, not accessible  │  │ │
│  │  │  to software at any privilege level                      │  │ │
│  │  │                                                          │  │ │
│  │  │  Contains:                                               │  │ │
│  │  │    SECS (SGX Enclave Control Structure)                  │  │ │
│  │  │    TCS (Thread Control Structures, one per thread)       │  │ │
│  │  │    Regular pages: code + stack + heap                    │  │ │
│  │  │    VA pages: Version Arrays (for anti-replay)            │  │ │
│  │  └──────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘

Memory Encryption Engine (MEE):
  - Sits between CPU and DRAM (on-die in recent Intel CPUs)
  - Encrypts/decrypts EPC pages transparently on cache eviction/fill
  - Uses AES-XTS with page-granular tweak (prevents cross-page copying)
  - MAC (Message Authentication Code) per cache line → detects tampering
  - DRAM content is ALWAYS ciphertext — oscilloscope on DIMM reveals only noise
```

**ARM TrustZone (used in edge AI SoCs: NVIDIA Jetson, Raspberry Pi CM, etc.):**

```
ARM TrustZone Memory Map:
┌──────────────────────────────────────────────────────────────────────┐
│  Normal World (NS=1)          Secure World (NS=0)                    │
│  ┌──────────────────┐         ┌─────────────────────────────────┐   │
│  │  Linux kernel    │   SMC   │  Secure Monitor                 │   │
│  │  Android/RTOS    │◄───────►│  (runs at EL3)                  │   │
│  │                  │  #TZASC │  OP-TEE or vendor TEE OS        │   │
│  │  ML runtime      │  gate   │  (runs at S-EL1)                │   │
│  │  (TFLite/ONNX)   │         │                                 │   │
│  │                  │  ECALL  │  Trusted Applications (TAs)     │   │
│  │  Rich Application│◄───────►│  (run at S-EL0)                 │   │
│  └──────────────────┘         │  TA: model_infer.ta             │   │
│                                │  TA: key_store.ta               │   │
│  TZASC (TrustZone Address     └─────────────────────────────────┘   │
│  Space Controller):                                                  │
│  - AMBA AXI bus-level enforcer                                       │
│  - Marks DRAM regions as Secure-only                                 │
│  - Normal World DMA to Secure regions → bus error                   │
│  - Enforced in hardware — kernel cannot bypass even with root        │
└──────────────────────────────────────────────────────────────────────┘

Key registers banked per security state:
  SP_EL0, SP_EL1: separate stack pointers
  VBAR_EL1: separate vector base (interrupt table)
  SCR_EL3: Secure Configuration Register (controls NS bit)
  SCTLR_EL1: System Control Register (separate MMU settings)

Context switch between worlds:
  Normal World: linux kernel → SMC instruction
  → CPU enters EL3 (Secure Monitor)
  → Saves Normal World register state
  → Loads Secure World state
  → ERET to S-EL1 (TEE OS)
  → TEE dispatches to trusted application
```

### Kernel-Mode Interactions for TEE Access

From user space, accessing the TEE requires:

```
User Space (Ring 3)                 Kernel Space (Ring 0)           TEE
     │                                      │                         │
     │  open("/dev/sgx_enclave")            │                         │
     │─────────────────────────────────────>│                         │
     │                                      │  [SGX driver]           │
     │  ioctl(fd, SGX_IOC_ENCLAVE_ADD_PAGE) │                         │
     │─────────────────────────────────────>│  ENCLS[EADD]            │
     │                                      │─────────────────────>   │
     │  ioctl(fd, SGX_IOC_ENCLAVE_INIT)    │  ENCLS[EINIT]           │
     │─────────────────────────────────────>│─────────────────────>   │
     │                                      │                         │
     │  EENTER (user-space ring transition) │                         │
     │────────────────────────────────────────────────────────────>   │
     │                                      │                         │
     │  [enclave code executes at Ring 3    │                         │
     │   but in encrypted EPC pages]        │                         │
     │                                      │                         │
     │<─── EEXIT (enclave exits) ───────────────────────────────────  │

ENCLS: Supervisor-level SGX instructions (kernel only)
  ECREATE: Create enclave
  EADD: Add pages to enclave
  EINIT: Initialize and lock enclave measurement
  EPA: Add version array page (anti-replay)

ENCLU: User-level SGX instructions
  EENTER: Enter enclave (saves RSP, RBP, transitions to TCS)
  EEXIT: Exit enclave
  ERESUME: Resume after asynchronous enclave exit (AEX)
  EREPORT: Generate attestation report
```

### DMA and IOMMU Protection

The model weights might be DMA-transferred to an AI accelerator (GPU, NPU). Without IOMMU, the accelerator's DMA engine could read any physical memory. With IOMMU:

```
IOMMU (Intel VT-d / ARM SMMU):

  Device DMA Request: "write to physical address 0x12345000"
                              │
                              ▼
  IOMMU Translation:  Check device's DMA remapping table
    [PCIe BDF 00:02.0] → IOVA 0x12345000 maps to PA 0x98765000?
    If not in table: DMA fault → abort, generate interrupt
    If allowed: translate and proceed

  For TEE model weights in secure DRAM:
    Physical address range of secure memory: NOT in any device's IOVA table
    → Any DMA attempt to read model weights: IOMMU fault
    → NPU cannot DMA-read model weights directly
    → Must go through TEE API: enclave computes, NPU only sees
      activation tensors (not weights)

ARM SMMU for TrustZone:
  Normal World device attempting DMA to S-region:
  → SMMU checks NS bit of target region
  → S-region with NS=0: access denied to Normal World masters
  → Transaction terminated, fault raised
```

---

## 3. Cryptography & State Management

### Key Hierarchy for Edge AI

```
Key Hierarchy:
                    ┌───────────────────────────────────┐
                    │  Hardware Root of Trust            │
                    │  ┌─────────────────────────────┐  │
                    │  │  CPU Fused Keys (eFUSE)      │  │
                    │  │  - Root Provisioning Key      │  │
                    │  │  - Root Sealing Key           │  │
                    │  │  (Never readable by software)  │  │
                    │  └──────────────┬────────────────┘  │
                    └─────────────────┼───────────────────┘
                                      │
                    ┌─────────────────▼───────────────────┐
                    │  Derived Keys (via EGETKEY/HKDF)    │
                    │  - Sealing Key: derived from         │
                    │    (MRENCLAVE, MRSIGNER, CPU SVN)   │
                    │  - Report Key: for attestation       │
                    │  - Provisioning Key: for IAS         │
                    └──────────┬──────────────┬────────────┘
                               │              │
              ┌────────────────▼──┐    ┌──────▼──────────────────┐
              │  Data Sealing Key  │    │  Attestation Report Key  │
              │  AES-256-GCM       │    │  ECDSA-P256 ephemeral   │
              │  Seals model       │    │  Signs REPORT struct    │
              │  weights to this   │    │  for remote verifier    │
              │  specific enclave  │    │                         │
              └────────────────────┘    └─────────────────────────┘
```

**Model weight encryption at rest:**

```
Model file on disk:
  Header: {algorithm: "AES-256-GCM", key_id: "...", iv: 96-bit random}
  Ciphertext: encrypted weight tensors
  Auth tag: 128-bit GCM authentication tag

Decryption process (inside TEE only):
  1. TEE generates attestation report → sends to Key Provisioning Service
  2. KPS verifies report → sends model key wrapped with enclave's public key
  3. TEE unwraps key using private key (never leaves TEE)
  4. TEE decrypts model weights into EPC pages
  5. GCM auth tag verified before any computation begins
     → Tampered ciphertext: authentication fails → model load aborted
```

**Key generation inside TEE:**

```c
// SGX key derivation (simplified)
sgx_key_request_t key_request = {
    .key_name = SGX_KEYSELECT_SEAL,
    .key_policy = SGX_KEYPOLICY_MRENCLAVE,  // Bind to enclave measurement
    .isv_svn = CURRENT_ISV_SVN,             // Security version number
    .attribute_mask = {0xFFFFFFFF, 0x3},    // All attribute bits
};

sgx_key_128bit_t sealing_key;
sgx_status_t ret = sgx_get_key(&key_request, &sealing_key);
// sealing_key is 128-bit AES key derived via HKDF from CPU fused key
// Key changes if: enclave binary changes, CPU is replaced, SVN is revoked
```

### TLS/mTLS Between Components

Edge AI nodes communicate with a control plane. This uses mTLS with device certificates provisioned during manufacturing:

```
mTLS Handshake (TLS 1.3):

  Edge Node (Client)                  Control Plane (Server)
        │                                       │
        │  ClientHello:                         │
        │  - TLS 1.3                            │
        │  - Key share: X25519 (g^a)            │
        │──────────────────────────────────────>│
        │                                       │
        │  ServerHello + Certificate:           │
        │  - Server cert: CN=control.company    │
        │  - Signed by: Manufacturing Root CA   │
        │  - Key share: X25519 (g^b)            │
        │  - CertificateRequest (require client)│
        │<──────────────────────────────────────│
        │                                       │
        │  Client Certificate:                  │
        │  - Device cert: CN=device-{serial}    │
        │  - Signed by: Device CA               │
        │  - Bound to TPM: key non-exportable   │
        │  Certificate Verify:                  │
        │  - Signature over transcript          │
        │  - Private key in TPM (TPM2_Sign)     │
        │──────────────────────────────────────>│
        │                                       │
        │  [Handshake complete]                 │
        │  [Shared secret: HKDF(g^(ab))]        │

Device certificate private key:
  - Generated inside TPM during manufacturing
  - Marked as non-exportable (TPM attribute: fixedTPM=1)
  - All signing operations: TPM2_Sign → TPM executes sign, returns sig only
  - Key material never appears in system memory
```

### Secure State Maintenance

Model inference is stateful (some architectures use KV-cache). State must be protected:

```
KV-Cache protection in TEE:
  Problem: KV-cache can be gigabytes → doesn't fit in EPC (limited to 128-512MB)
  Solution: AES-XTS streaming encryption of KV-cache to normal DRAM
  
  Key: Derived from sealing key + session nonce
  Process:
    [KV tensor in EPC] → [Encrypt with session key] → [Normal DRAM]
    [Normal DRAM] → [Decrypt into EPC when needed] → [Continue computation]
  
  Anti-replay: Each cache entry has a monotonic counter (from TPM or enclave internal)
               Cache entry with stale counter: rejected, re-fetched from model
  
  This prevents:
    - Reading KV-cache from DRAM → only ciphertext visible
    - Rolling back KV-cache to replay old context → counter check fails
```

---

## 4. Backend / Control Plane Architecture

### Master / Agent Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      CONTROL PLANE (Cloud/Datacenter)                   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Model Lifecycle Manager                                          │   │
│  │  - Model versioning, signing, packaging                          │   │
│  │  - Key Provisioning Service (KPS): issues model decryption keys  │   │
│  │    only to attested, authorized devices                          │   │
│  │  - Certificate Authority: issues device certs at manufacture     │   │
│  └────────────────────────────┬─────────────────────────────────────┘   │
│                               │  mTLS (bidirectional)                   │
└───────────────────────────────┼─────────────────────────────────────────┘
                                │
              ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ (Internet/WAN)
                                │
┌───────────────────────────────┼─────────────────────────────────────────┐
│  EDGE NODE                    │                                          │
│                               │                                          │
│  ┌────────────────────────────▼────────────────────────────────────┐    │
│  │  Edge Agent (user space, privileged)                             │    │
│  │  - Maintains mTLS connection to control plane                   │    │
│  │  - Receives model update instructions                           │    │
│  │  - Manages local TEE lifecycle                                  │    │
│  │  - Collects metrics (telemetry) for anomaly detection           │    │
│  └──────────────────────┬───────────────────────────────────────── │    │
│                         │  ECALL / SMC                               │    │
│  ┌──────────────────────▼──────────────────────────────────────┐    │    │
│  │  TEE (Trusted Execution Environment)                         │    │    │
│  │  - Model weights (encrypted at load, decrypted inside EPC)  │    │    │
│  │  - Inference execution                                       │    │    │
│  │  - Attestation report generation                            │    │    │
│  └─────────────────────────────────────────────────────────────┘    │    │
│                                                                       │    │
│  ┌────────────────────────────────────────────────────────────────┐  │    │
│  │  TPM 2.0 / Secure Element                                       │  │    │
│  │  - Device identity keys (non-exportable)                       │  │    │
│  │  - Platform state (PCR values)                                  │  │    │
│  │  - Monotonic counters (anti-replay)                            │  │    │
│  └────────────────────────────────────────────────────────────────┘  │    │
└──────────────────────────────────────────────────────────────────────────┘
```

### Sync vs Async Flows

**Synchronous (inference path — latency critical):**
```
Client → gRPC → Inference Runtime → ECALL → TEE computes → EEXIT → gRPC response
Latency budget: < 100ms for real-time edge applications
TEE call overhead: ~5-10μs for ECALL/EEXIT pair
Compute dominates: 10-90ms for typical CNN inference
```

**Asynchronous (model update path — reliability critical):**
```
Control Plane                    Edge Agent
     │                               │
     │── gRPC: PrepareUpdate ───────>│  (async, with retry)
     │<── ack ────────────────────── │
     │                               │
     │                               │─── Download model package ──────>│  (S3/CDN)
     │                               │<── encrypted model file ─────────│
     │                               │
     │                               │─── Verify signature (Ed25519) ──>│ (local TPM)
     │                               │
     │── gRPC: ActivateUpdate ──────>│  (atomic swap)
     │<── ack: new_enclave_ready ─── │
     │                               │─── TEE: load new model weights
     │                               │─── TEE: destroy old enclave
     │── gRPC: ConfirmRollback? ────>│  (if health check fails: rollback)
```

### Database and Storage Interactions

```
What the edge node stores locally:
  /var/lib/edge-ai/
    models/
      current/
        model.enc     (AES-256-GCM encrypted weights)
        model.sig     (Ed25519 signature from Model Signing Key)
        manifest.json (SHA-256 hashes of all components)
      rollback/       (previous version, kept for 24h)
    state/
      session_tokens.db  (SQLite, encrypted with sealing key)
      inference_log.db   (SQLite, encrypted; for audit)
    certs/
      device.crt     (Device certificate, public)
      ca-chain.crt   (CA chain for verification)
      # Private key is in TPM — NEVER on filesystem

Filesystem-level protection:
  dm-verity: root filesystem is read-only with hash tree
  dm-crypt: /var/lib/edge-ai encrypted with LUKS2 (key from TPM sealed state)
  IMA (Integrity Measurement Architecture): measures all executables at load
```

---

## 5. Authentication & Trust Bootstrapping

### The Secret Zero Problem

**The fundamental bootstrap question:** When the device powers on in the field, how does it prove to the Key Provisioning Service that it is a legitimate, uncompromised device — before it has received any secrets?

```
Secret Zero Problem Solution: Hardware-Rooted Attestation

Manufacturing Phase (factory, one time):
  1. CPU generates EK (Endorsement Key) pair inside TPM
     TPM2_CreatePrimary(ENDORSEMENT_HIERARCHY)
     EK private key: TPM non-exportable attribute set
     EK public key: exported to manufacturer
  
  2. Manufacturer CA signs EKcert:
     EKcert = Sign(ManufacturerCA, EK_public + device_serial + model)
     EKcert embedded in TPM NVRAM (non-volatile, locked)
  
  3. Device CA issues DevID certificate:
     DevID_key = TPM2_CreatePrimary(OWNER_HIERARCHY)
     DevID_cert = Sign(DeviceCA, DevID_public + device_id)
     DevID_cert stored on device filesystem (public only)
  
  4. Platform Configuration:
     Secure Boot keys programmed into UEFI (Platform Key, KEK, DB)
     Initial TPM PCR values measured from golden firmware image
     Golden PCR values logged at manufacturing time

Field Deployment Phase:
  Device boots →
  Secure Boot chain verifies firmware →
  TPM PCRs extended by each boot stage →
  
  Device calls KPS:
    Request: {EKcert, DevID_cert, TPM_Quote(PCRs, nonce)}
    
  KPS verification:
    1. Verify EKcert signature → ManufacturerCA (we trust this CA)
    2. Verify DevID_cert signature → DeviceCA (our CA)
    3. Verify TPM_Quote signature → EK_public (proves TPM holds the key)
    4. Verify PCR values match golden measurements:
       PCR[0]: UEFI firmware measurement → matches?
       PCR[7]: Secure Boot state → matches?
       PCR[10]: Linux kernel + initrd → matches?
    5. All checks pass → Issue model decryption key, wrapped for this device's EK

Why this is the answer to Secret Zero:
  - The secret (model key) is only released to a device that:
    a. Has a genuine TPM (EKcert signed by manufacturer)
    b. Is authorized by us (DevID signed by our CA)
    c. Is running unmodified software (PCR measurements match)
  - No pre-shared secret needed on the device
  - Compromise of the filesystem: PCRs won't match → key not issued
  - Physical TPM replacement: EKcert from different manufacturer → rejected
```

### Certificate Provisioning and Rotation

```
Certificate Lifecycle:

  Manufacturing:
    EKcert: valid for device lifetime (typically 10-15 years)
    DevID_cert: initial validity 2 years, auto-renewed

  Field rotation (automated):
    Edge Agent → ACME-like protocol to Device CA
    Step 1: Agent proves control via TPM-signed CSR
    Step 2: Device CA verifies TPM signature, issues new cert
    Step 3: Agent installs new cert, previous cert kept for 24h overlap
    
  Revocation:
    CRL (Certificate Revocation List): published every 4 hours
    OCSP stapling: Edge Agent pre-fetches OCSP response
    Revocation database: if device is compromised → add to CRL
    KPS checks CRL before issuing model keys → revoked device gets no key

  Model Signing Key Rotation:
    Ed25519 key pair: rotated every 90 days
    Old signed models: still valid with old public key (stored in KPS)
    New models: signed with new key
    Key IDs in manifest.json → Agent knows which public key to use for verification
```

### Trust Boundaries Enumerated

```
Trust Boundary Map:

  FULLY TRUSTED:
    - CPU package + MEE (hardware manufactured by Intel/AMD/ARM)
    - TPM 2.0 chip (FIPS 140-3 Level 2+)
    - TEE execution environment (by definition of the threat model)

  CONDITIONALLY TRUSTED (trusted if attestation passes):
    - Firmware (UEFI/BIOS): trusted if matches golden PCR measurements
    - Linux kernel: trusted if IMA measurement matches allowlist
    - Edge Agent: trusted if running as correct signed binary

  UNTRUSTED (by design):
    - Everything in Ring 3 user space (except attested binaries)
    - Network (all traffic authenticated and encrypted)
    - Physical DRAM (data encrypted by MEE before reaching DIMM)
    - PCIe bus (model weights encrypted before DMA)
    - Local administrator / root user

  TRUST TRANSITIONS:
    Root → attested kernel: via IMA + SecureBoot + TPM PCR
    Kernel → TEE: via SGX/TZ hardware enforcement (not software decision)
    TEE → Model Key: via KPS attestation (software, but authenticated by hardware)
```

---

## 6. Security Controls & Anti-Tampering

### Protecting Against Root/Admin Users

The local root user is explicitly in the threat model. A compromised or malicious edge site administrator must not be able to extract model weights or inference data.

```
Defense against root-level attack:

1. Model weights protection:
   Encrypted in EPC → root cannot read EPC pages (hardware enforced)
   dm-crypt for at-rest storage → key sealed to TPM with PCR policy
   PCR policy: root cannot forge PCR values without breaking TPM hardware

2. Key material protection:
   All private keys in TPM → TPM2 authorization policy enforced
   Root-level: can call TPM2_Sign but not TPM2_LoadExternal (extract key)
   TPM dictionary attack protection: after N failed auth attempts → lockout

3. Process isolation:
   seccomp-BPF profile for inference runtime:
     Allow: read, write, mmap, futex, clock_gettime, epoll
     Deny: ptrace, process_vm_readv, /proc/mem writes, module loading
   AppArmor/SELinux profiles: mandatory access control, root-enforced by kernel
   
4. Anti-debugging at TEE level:
   SGX: EINIT with DEBUG=0 attribute set
     → no external debugger can attach to enclave
     → reading enclave memory: returns random data (or bus error)
   TrustZone: Secure debug disabled via eFUSE at manufacturing
     → JTAG does not have visibility into Secure World
     → CoreSight ETM trace disabled for S-EL0/S-EL1

5. Memory protections:
   ASLR + PIE: randomized address space for all processes
   Stack canaries: compiler-inserted guard values before return addresses
   Shadow stack (Intel CET): tracks return addresses in shadow stack
                             → ROP chains fail because shadow doesn't match
   CFI (Control Flow Integrity): llvm-cfi → indirect call targets must be
                                 valid function entry points
```

### Binary Signing and Verification

```
Binary verification chain:

  UEFI Secure Boot:
    Platform Key (PK): root of trust, stored in UEFI non-volatile storage
    Key Exchange Key (KEK): signed by PK
    Signature Database (DB): contains allowed boot loader hashes/certs
    
    Boot loader (GRUB/shim) must be signed by DB cert
    If not signed: UEFI refuses to execute → device won't boot

  IMA (Integrity Measurement Architecture) in kernel:
    Policy file: /etc/ima/ima-policy
      measure func=BPRM_CHECK template=ima-sig
      appraise func=BPRM_CHECK appraise_type=imasig
    
    On exec: kernel computes SHA-256 of executable → checks signature
    Signature missing or invalid → exec denied
    Measurement logged to TPM PCR[10] → remote verifier can audit

  Edge Agent signing:
    Binary signed with Ed25519 (Signing Key from CI/CD HSM)
    Agent startup: verifies own signature before loading
    systemd service: ConditionSecurity=yes
                    AmbientCapabilities=CAP_NET_BIND_SERVICE only
```

### Fail-Open vs Fail-Closed Decisions

```
Critical fail-mode decisions for each component:

  Secure Boot failure:     → FAIL CLOSED
    If firmware signature invalid: device powers off
    Rationale: an unverified firmware is an untrustworthy platform

  TEE initialization failure: → FAIL CLOSED
    If SGX not available, enclave creation fails: service refuses to start
    Rationale: model must not run unprotected
    Exception: optional degraded mode with no model loaded (returns error)

  Attestation failure:     → FAIL CLOSED
    If KPS rejects attestation: model key not issued → service starts but
    returns "model not available" to clients
    Rationale: better to be non-functional than to expose unprotected model

  KPS unreachable:         → FAIL CLOSED (time-limited)
    Model key cached in TEE for up to 24h
    If KPS unreachable > 24h: cached key expires → service stops
    Rationale: long-term key caching without freshness check = risk

  dm-verity corruption:    → FAIL CLOSED
    If root filesystem hash verification fails: kernel panics (dm-verity flag)
    Rationale: corrupted filesystem = potentially compromised system

  IMA verification failure: → FAIL CLOSED
    Unauthorized binary exec denied
    Rationale: prevents execution of injected malicious code

  Inference output filter: → FAIL CLOSED
    Output anomaly detection (canary neurons): if triggers, return error
    Rationale: better to drop inference than output extracted watermarks
```

---

## 7. Attack Surface Mapping

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║           EDGE AI NODE — ATTACK SURFACE MAP                                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  PHYSICAL ATTACK SURFACE (requires physical access)                           ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │  DRAM DIMM                                                               │ ║
║  │  - Oscilloscope probing → reads bus signals (mitigation: MEE)           │ ║
║  │  - Cold boot attack → DRAM retention at low temp (mitigation: MEE)     │ ║
║  │  - DPA on memory bus → statistical analysis of bus activity            │ ║
║  │                                                                          │ ║
║  │  PCIe Bus / M.2 Slot                                                    │ ║
║  │  - Protocol analyzer intercept → reads DMA traffic                      │ ║
║  │  - Rogue PCIe device (DMA attack) → (mitigation: IOMMU)               │ ║
║  │                                                                          │ ║
║  │  Power Rails (VCC, VDDQ, etc.)                                          │ ║
║  │  - Power analysis → correlate CPU operations with power trace           │ ║
║  │  - Fault injection via voltage glitching → skip security checks         │ ║
║  │                                                                          │ ║
║  │  JTAG / Debug Headers                                                    │ ║
║  │  - Debug access to CPU state (mitigation: eFUSE-disable)               │ ║
║  │  - TrustZone secure world visible if debug fuses not blown              │ ║
║  │                                                                          │ ║
║  │  EM Emanation                                                            │ ║
║  │  - Near-field EM probe → captures computation fingerprint              │ ║
║  │  - TEMPEST-style analysis → reconstructs data from EM                  │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY: Physical hardware → OS/Software                             ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  OS-LEVEL ATTACK SURFACE (requires root/kernel access)                        ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │  /proc/mem, /dev/mem                                                    │ ║
║  │  - Direct physical memory read (mitigation: seccomp, no /dev/mem)     │ ║
║  │                                                                          │ ║
║  │  Kernel Modules                                                          │ ║
║  │  - Load rogue driver → bypass all userspace controls                   │ ║
║  │  - BYOVD: Bring Your Own Vulnerable Driver                             │ ║
║  │  (mitigation: module signing, lockdown=confidentiality)                │ ║
║  │                                                                          │ ║
║  │  ptrace() system call                                                   │ ║
║  │  - Attach to inference runtime → read process memory                  │ ║
║  │  (mitigation: seccomp deny ptrace, Yama LSM ptrace_scope=2)           │ ║
║  │                                                                          │ ║
║  │  /proc/[pid]/maps, /proc/[pid]/mem                                     │ ║
║  │  - Enumerate and read process memory regions                           │ ║
║  │  (mitigation: hidepid mount option, Yama restrictions)                 │ ║
║  │                                                                          │ ║
║  │  perf_event_open() / eBPF                                              │ ║
║  │  - Hardware performance counters (cache misses, branch mispredictions) │ ║
║  │  - Cache timing measurement → timing side-channel                      │ ║
║  │  (mitigation: restrict perf_event_paranoid=3, eBPF CAP_BPF only)     │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY: Root/Kernel → User Space Applications                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  NETWORK ATTACK SURFACE (remote, no physical access)                          ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │  gRPC API (inference endpoint)                                          │ ║
║  │  - Malicious inputs → trigger model extraction via oracle queries      │ ║
║  │  - Timing oracle → measure inference time per input → side channel     │ ║
║  │  - DoS → overwhelm inference queue                                     │ ║
║  │                                                                          │ ║
║  │  mTLS Control Plane Connection                                          │ ║
║  │  - Certificate pinning bypass if CA is compromised                     │ ║
║  │  - TLS downgrade if old cipher suites enabled                          │ ║
║  │                                                                          │ ║
║  │  Model Update Channel                                                   │ ║
║  │  - Supply chain attack: inject malicious model                         │ ║
║  │  (mitigation: Ed25519 signature verification before load)              │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## 8. Attack Scenarios & Defensive Architecture

### Understanding Side-Channel Attacks: The Core Physics

Before the specific scenarios, the underlying physics that make side-channel attacks possible:

**Why computation leaks information:**

Every digital operation — a multiply, a memory read, an AES round — consumes electrical power proportional to the number of transistors switching from 0→1 (CMOS dynamic power: P = α C V² f, where α is the activity factor). The activity factor depends on the DATA being processed. Multiplication of 0x00000000 consumes less power than multiplication of 0xFFFFFFFF. This creates a statistical correlation between the observed power trace and the data being processed.

Similarly, cache memory access latency differs: cache hit ~4 cycles, L3 cache miss ~200 cycles, DRAM access ~300 cycles. A function that accesses memory based on a secret value (table lookup with key-dependent index) will have timing that depends on cache state, which depends on past operations, which can depend on the secret.

**The attacker's general methodology (all side-channel attacks share this structure):**
1. Choose a target intermediate value (e.g., output of first AES SubBytes operation).
2. Choose a model of how that value relates to the physical leakage (power, timing, EM).
3. Make measurements while the target system processes known inputs.
4. Use statistical analysis to find which key hypothesis best explains the observed leakage.

---

### Scenario 1: Cache-Timing Attack via Shared LLC

**Context:** An attacker process runs on the same physical CPU as the inference runtime (multi-tenant edge node, or co-resident process with user privileges).

**Attacker Assumption:** Local user-level code execution on the same physical machine. No root required for basic cache timing.

**The Attack Surface:**

Modern CPUs have a Last-Level Cache (LLC) shared between all cores and between normal processes and (in some TEE configurations) the TEE. A process can measure its own memory access latency using `rdtsc` (timestamp counter) or `perf_event_open`. If the inference computation results in LLC evictions that affect the attacker's cached data, the attacker can infer what memory accesses the inference code made.

**Flush+Reload:** The attacker shares memory with the target (e.g., shared libraries like libm, libopenblas) and uses `clflush` to evict a cache line, waits for the target to run, then measures reload latency. Fast reload = target accessed that line. This creates a 1-bit information channel per measurement.

**Defense Engineering:**

```
Cache partitioning defense (Intel CAT — Cache Allocation Technology):
  
  Intel RDT (Resource Director Technology):
  - CAT: allocate LLC ways to specific tasks
  - Inference runtime: ways 0-7 (exclusive)
  - All other processes: ways 8-15 (exclusive)
  - No shared cache ways → no Flush+Reload possible
  
  Linux kernel configuration:
    resctrl filesystem: mount -t resctrl resctrl /sys/fs/resctrl
    
    # Create resource group for inference runtime
    mkdir /sys/fs/resctrl/inference
    echo "L3:0=00ff" > /sys/fs/resctrl/inference/schemata  # ways 0-7
    echo [inference_pid] > /sys/fs/resctrl/inference/tasks
    
    # Default group (everything else) gets ways 8-15
    echo "L3:0=ff00" > /sys/fs/resctrl/schemata

  ARM alternative (MPAM — Memory Partitioning and Monitoring):
    Similar LLC partitioning available on ARM v8.4+
    Critical for Cortex-A78AE (automotive-grade edge AI SoC)

SGX-specific defense:
  T-SGX: Software-based transactional memory approach (research)
  CLOAK: Oblivious RAM (ORAM) within enclaves — makes access pattern data-independent
  Intel Recommendations:
    - Use data-oblivious algorithms (no secret-dependent memory access)
    - Constant-time AES (use AES-NI hardware instruction — same cache footprint regardless of key)
    - Table lookups: must be replaced with bitsliced implementations

Constant-time programming requirement:
  // VULNERABLE: secret-dependent table lookup (OpenSSL early AES)
  uint8_t sbox_out = AES_SBOX[secret_byte];  // cache miss pattern reveals secret_byte
  
  // SECURE: hardware AES (aesenc instruction — single cycle, no table lookup)
  __m128i state = _mm_aesenc_si128(state, round_key);  // Intel AES-NI
  
  // If hardware AES unavailable: bitsliced AES implementation
  // All bits processed in parallel, no conditional branches, no table accesses
```

**Detection:**

```
Indicators of cache timing attack:
  1. perf_event_open with PERF_COUNT_HW_CACHE_MISSES from non-inference process
     → Monitor via eBPF: detect excessive cache miss measurement from user processes
  
  2. rdtsc instruction frequency from user process
     → On recent Intel: rdtsc is allowed in user space but unusually frequent 
        use (>1000/sec from a single process) is anomalous
  
  3. clflush instruction from non-privileged process
     → clflush requires no privilege on x86 → attackers can use it
     → Detection: Intel PT (Processor Trace) logging of clflush execution
     → Alert: any process using clflush outside of inference runtime

Linux monitoring:
  eBPF program on perf_event_open syscall:
    if (comm != "inference_rt" && PERF_TYPE_HARDWARE && LLC_MISSES):
        send_alert("potential_cache_timing_probe", pid, comm)
```

---

### Scenario 2: Power Analysis During AES-256-GCM Decryption

**Context:** Attacker has physical access to the device. They attach a current probe (e.g., Pearson CT) to the power rail, connected to an oscilloscope with >1 GSPS sampling rate and a low-noise amplifier.

**Attacker Assumption:** Physical access, ability to trigger inference requests (or observe the device's normal operation). No software compromise required. This attacks the hardware cryptographic operations.

**The Physics:**

When the TEE decrypts model weights using AES-256-GCM:
```
AES-256 has 14 rounds. Each SubBytes operation processes 16 bytes.
The intermediate value after SubBytes Round 1 Byte 0:
  z = SubBytes(plaintext[0] XOR roundkey[0])

The Hamming weight of z (number of 1-bits) correlates with power consumption:
  Low HW(z) → fewer transistors switch → less power
  High HW(z) → more transistors switch → more power

Given N traces with known plaintext[0]:
  For each key hypothesis k (0-255 possible values):
    z_k = SubBytes(plaintext[0] XOR k)
    HW_k = popcount(z_k)
    
  Compute Pearson correlation between HW_k and measured power at each time sample.
  Correct key: highest correlation coefficient at the SubBytes time sample.

With N=1000 traces: recovers each key byte with >99% probability.
Full AES-128 key: 16 × 1000 = 16,000 traces (hours of operation).
```

**Why This Matters for Edge AI:**

The model decryption key, if recovered via DPA, allows the attacker to decrypt the encrypted model file on any other device — instant IP theft at scale.

**Defense Architecture:**

```
Hardware countermeasures (implemented in TEE-capable SoCs):

1. Masking (algorithmic countermeasure):
   Principle: randomize intermediate values so HW(z) is independent of z
   
   Before SubBytes:
     masked_plaintext = plaintext[i] XOR random_mask
     masked_key = roundkey[i] XOR random_mask
     
   SubBytes on masked value: SubBytes(masked_plaintext XOR masked_key)
   = SubBytes(plaintext[i] XOR random_mask XOR roundkey[i] XOR random_mask)
   = SubBytes(plaintext[i] XOR roundkey[i])   [masks cancel]
   
   Attacker sees: HW(z XOR mask) where mask is random per operation
   Correlation between HW and key hypothesis: destroyed by mask randomness
   First-order DPA: defeated
   
   Higher-order DPA (attacks pairs of masked operations):
     Requires d+1 order masking for d-th order DPA
     Practical: 2nd order masking (d=2) sufficient for most deployments

2. Shuffling (randomize operation order):
   SubBytes on 16 bytes: process bytes in random order each time
   Attacker cannot align traces (each trace has different temporal structure)
   Averaging traces: does not work because operations are at different times

3. Dual-rail logic (hardware design):
   CMOS logic: complementary signals
   If bit = 0: top wire = 0, bottom wire = 1
   If bit = 1: top wire = 1, bottom wire = 0
   Power consumption: constant regardless of data (always one 0→1 transition)
   Requires custom silicon — available in dedicated secure microcontrollers
   (NXP LPC55S69, STM32H5, Microchip ATECC608)

4. Power rail filtering and noise injection (physical countermeasure):
   Ferrite bead + capacitor on power input: attenuates high-frequency signal
   Dedicated voltage regulator with high-frequency bypass caps: reduces SNR
   Active noise injection: small DC-DC converter generates controlled noise
   
   Signal-to-noise ratio impact:
     DPA success: N ∝ σ²/ρ²  (traces needed scales with noise variance / signal power)
     2x noise injection: 4x more traces needed
     10x noise: 100x more traces needed → impractical for field operation

5. Physically Unclonable Functions (PUF) for key generation:
   Key is not stored — it is derived from the physical structure of the chip.
   Each power-up: PUF generates the same key from manufacturing variations.
   Attacker cannot extract: key doesn't exist when device is off.
   Power analysis of key derivation: attacker sees PUF response, not the key material.
```

**Detection:**

```
Tamper detection:
  Active shields (fine metal grid over security-sensitive silicon areas):
    Any probe penetration → shorts the grid → detected
    Detector logic: cuts power, zeroes key material

  Voltage and frequency monitors:
    Operating voltage: expect 1.8V ± 5%
    Monitor circuit: if VCC < 1.6V or > 2.0V → trigger zeroize
    Rationale: voltage glitching causes fault injection; glitch = tamper
  
  Temperature sensors:
    Normal operation: -20°C to 85°C
    Cold boot attack requires cooling to ~-30°C → temperature alert
    Crypto operations stop, keys zeroed when temperature out of range

  Physical sealing:
    Tamper-evident enclosure with mesh grid connected to TPM tamper pin
    TPM2_NV_READLOCK on key storage: if tamper detected → key storage locked
```

---

### Scenario 3: Model Extraction via Inference API Timing Oracle

**Context:** Remote attacker with access to the inference API (legitimate API key or compromised client credential). No physical access, no software exploit. Pure black-box API attack.

**Attacker Assumption:** Authenticated access to inference endpoint. Can send arbitrary inputs and measure response times with millisecond precision. Can make thousands of queries.

**The Attack:**

Neural networks with ReLU activations have a property: the output is a piecewise linear function of the input. The boundaries between linear regions (where a ReLU switches from 0 to active) can be detected via small perturbations in timing (if the implementation has data-dependent branching) or via output discontinuities.

More practically, the attacker uses the inference API as an oracle for model extraction:

```
Model extraction via output oracle (black-box):

Algorithm (Tramèr et al. "Stealing Machine Learning Models via Prediction APIs"):

1. Sample random inputs x₁, x₂, ..., xₙ from the input domain
2. Query f(xᵢ) for each input → collect output probability vectors
3. Train a substitute model g on {(xᵢ, f(xᵢ))} pairs
4. Measure fidelity: agreement(f, g) on held-out test inputs

With soft probabilities (full output vector): 
  High information per query → convergence with fewer queries
  
With hard labels only (top-1 class):
  Less information per query → needs more queries

With API that returns confidence scores (common):
  Each query reveals O(log C) bits where C = number of classes
  For a 1000-class model: ~10 bits per query
  Model requires ~N * d bits to specify (N layers, d parameters)
  Extraction cost: very high but finite

Timing side-channel during extraction:
  Some architectures (e.g., early exit networks) return faster for "easy" inputs
  Timing correlates with which path was taken → reveals architecture details
```

**Defensive Architecture Against Model Extraction:**

```
Defense 1: Output rounding and quantization
  Return probability vector rounded to 2 decimal places (not full float32)
  Information per query: log₂(101) ≈ 6.7 bits (vs log₂(2^32) = 32 bits)
  Extraction requires proportionally more queries → less practical

Defense 2: Prediction throttling
  Rate limit per API key: 1000 queries/day
  Rate limit per IP: 100 queries/minute
  Burst detection: 50 queries in 10 seconds → flag and throttle

Defense 3: Prediction perturbation
  Add calibrated noise to output: p_noisy = p + Laplace(0, λ)
  λ selected to maintain utility while reducing extraction fidelity
  Differential privacy guarantee: prevents extraction of any single training point

Defense 4: Watermarking (detect if extracted model is deployed)
  Embed backdoor patterns into training:
    For specific "canary" inputs x_canary: model outputs specific unusual class
  If extracted model deployed: query it with canary inputs
  Canary output matches: model was extracted from ours (forensic evidence)
  
  Implementation:
    Select 20 canary inputs (random noise patterns)
    Add to training data with unusual labels
    Model memorizes canary behavior
    Periodic canary probing of suspected extracted models

Defense 5: Adversarial examples on output
  Before returning, apply slight perturbation that degrades usefulness for training a surrogate:
  p_output = p_clean + adversarial_noise(p_clean)
  Surrogate trained on perturbed outputs: lower accuracy than original
  
Defense 6: Input anomaly detection
  Track distribution of queries per API key:
    Legitimate use: clustered around real data domain
    Extraction attack: uniform random sampling of input space
  
  KL divergence between query distribution and expected data distribution:
    Normal: KL < 0.5
    Extraction attack: KL > 5.0 → alert
```

**Detection Monitoring:**

```python
class ModelExtractionDetector:
    """
    Monitors inference API for extraction attack patterns.
    """
    def __init__(self):
        self.query_history = defaultdict(list)
        self.feature_coverage = SamplingGrid(resolution=0.1)
    
    def on_query(self, api_key: str, input_features: np.ndarray):
        self.query_history[api_key].append(input_features)
        self.feature_coverage.add(input_features)
        
        window = self.query_history[api_key][-1000:]
        
        # Signal 1: Uniform coverage of input space
        coverage_pct = self.feature_coverage.coverage_for(api_key)
        if coverage_pct > 0.15:  # > 15% of input space explored
            self.alert("EXTRACTION_SYSTEMATIC_COVERAGE", api_key, coverage_pct)
        
        # Signal 2: Zero repetition (legitimate users repeat similar queries)
        unique_ratio = len(set(map(tuple, window))) / len(window)
        if unique_ratio > 0.99 and len(window) > 100:
            self.alert("EXTRACTION_UNIQUE_QUERY_PATTERN", api_key, unique_ratio)
        
        # Signal 3: Out-of-distribution inputs
        ood_score = self.ood_detector.score(input_features)
        if ood_score > 3.0:  # 3 sigma from normal data distribution
            self.alert("EXTRACTION_OOD_INPUT", api_key, ood_score)
        
        # Signal 4: Timing measurement attempts
        # Attacker may send many requests with precise timing control
        # Check for Poisson arrival pattern (natural) vs burst-then-wait (timed)
```

---

### Scenario 4: Rowhammer Against Model Weights in DRAM

**Context:** Attacker has user-level code execution (no root). Targets model weights stored in DRAM (not in TEE) — e.g., a large model that doesn't fit in EPC.

**Attacker Assumption:** User-level access. The model weights, though encrypted at rest, are loaded decrypted into normal DRAM during inference (in a non-TEE deployment or when TEE is used without EPC paging).

**The Attack — Rowhammer:**

DRAM cells are arranged in rows of ~8KB each. Repeatedly reading the same row ("hammering") causes capacitive coupling that flips bits in adjacent rows. Since 2012, this is a known DRAM vulnerability.

```
DRAM Physical Layout:
  Row N-1: [normal data]
  Row N:   [HAMMERED repeatedly at high frequency]
  Row N+1: [TARGET: model weights or page table]
  Row N+2: [normal data]

Attack:
  for (i = 0; i < 10_000_000; i++):
    READ(row_N_address)     // Access aggressor row
    clflush(row_N_address)  // Flush cache → force DRAM access
  
  Result: With ~50% probability (hardware-dependent), bit flip in Row N+1
  
  Targeted bit flip: if model weights are in Row N+1:
    Flip a weight from +0.5 to -0.5 (or NaN/Inf)
    Model accuracy degrades or specific misclassification occurs
    
  More dangerous: page table attack
    If page tables are in adjacent DRAM row: bit flip in page table
    → Process gains access to unmapped physical memory
    → Privilege escalation to read kernel memory (including model keys)
```

**Defensive Architecture Against Rowhammer:**

```
Hardware defenses:

1. ECC DRAM (Error Correction Code):
   SECDED (Single Error Correct, Double Error Detect) codes
   Each 64-bit word has 8 additional parity bits
   Single-bit flip: silently corrected
   Double-bit flip: detected, machine check exception raised
   
   Limitation: SECDED corrects 1 bit, detects 2 bits
   Rowhammer can induce >2 flips → ECC insufficient alone
   
   DDR5: On-Die ECC added as standard
   Combined with LPDDR5 PMOS Refresh: mitigates most Rowhammer

2. TRR (Target Row Refresh):
   DRAM refresh controller detects frequently-accessed rows
   Proactively refreshes adjacent rows before bit flip probability threshold
   Modern DDR4/DDR5 chips: TRR standard feature
   Bypass: Blacksmith attack (non-uniform hammering patterns evade TRR)

3. Physical address randomization:
   Map model weights to randomly-selected DRAM rows (OS + hypervisor)
   Attacker cannot know which rows to hammer without layout oracle
   Color-aware page allocation: prevent attacker from allocating adjacent rows

4. Model integrity verification:
   Runtime integrity check: periodically compute SHA-256 of model weight tensors
   Compare against known-good hash (from load time)
   Unexpected change: model may be under Rowhammer attack → alert and reload
   
   Implementation:
     Background thread, every 5 minutes:
       current_hash = sha256(weight_tensors_in_memory)
       if current_hash != original_hash:
           alert("MODEL_INTEGRITY_VIOLATION")
           reload_model_from_encrypted_file()

5. Guard pages between model rows and page tables:
   Linux: prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME) for weight allocation
   Allocate large guard pages (2MB huge pages) between model weights and
   any sensitive data → bit flips land in unmapped memory → SIGSEGV, not privilege escalation
```

---

### Scenario 5: Electromagnetic Side-Channel Against NPU

**Context:** Attacker has physical proximity to the edge node (within 1-30cm). Uses a near-field EM probe (H-field, loop antenna) connected to a spectrum analyzer or oscilloscope.

**The Physics:**

The Neural Processing Unit (NPU) on an edge SoC (Apple M1/M2, NVIDIA Jetson, Qualcomm Hexagon) computes matrix multiplications using systolic arrays or MAC (Multiply-Accumulate) arrays. Each MAC operation involves:
1. Multiply: weight × activation → produces intermediate product
2. Accumulate: add to running sum

The clock frequency, the data patterns, and the switching activity all create distinct EM signatures. Specifically:
- The weight data pattern affects the EM spectrum near the NPU
- Different model architectures create different EM fingerprints
- The same model processing different inputs creates different EM traces

**What can be extracted:**

```
EM analysis targets for edge AI:

1. Model architecture extraction:
   The sequence of NPU operations (conv2d, matmul, pool, relu) creates
   a temporal EM signature. A skilled attacker can recognize:
   - Layer transitions (power idle periods between layers)
   - Kernel sizes (larger kernels = longer sustained EM burst)
   - Number of filters (repetition count in EM trace)
   
   Result: Reconstructs the model architecture without any software access

2. Model weight extraction (long-term DPA):
   More difficult than architecture extraction.
   Requires: thousands of EM traces, known or controlled inputs.
   NPU weight loading from DRAM: each weight value accessed from memory
   creates EM signal correlated with Hamming weight of the value.
   
   Modern NPU mitigation: on-chip SRAM for weight storage
   Weights loaded once from DRAM → stay in on-chip SRAM
   EM attack on SRAM access: much harder (lower signal, shorter path)

3. Activation/input reconstruction:
   Input tensor fed to NPU layer-by-layer.
   If attacker knows the model architecture, can reconstruct activations
   from EM traces → reveals inference inputs (privacy violation).
```

**Defense Architecture:**

```
1. Shielding (Faraday cage):
   Conductive enclosure (steel, mu-metal for low-frequency EM)
   Grounded continuous enclosure: 40-60dB EM attenuation at 100MHz-1GHz
   Ventilation: honeycomb waveguide vents → allow airflow, block EM
   Practical challenge: ports (USB, Ethernet) need filtered connectors
   
   Cost/benefit: appropriate for high-value deployments (military, medical)
   Not practical for low-cost consumer edge devices

2. Algorithmic noise injection:
   Insert dummy operations between real NPU operations
   Random number of dummy matmul operations with zero contribution
   Temporal EM signature becomes non-deterministic
   Layer transition boundaries: obscured by random dummy work
   
   Performance cost: 5-20% depending on dummy operation rate

3. Constant-time NPU scheduling:
   Fixed schedule: each layer always takes exactly T_fixed time
   Padding: shorter layers wait; longer layers cannot exceed budget
   EM signature: uniform, no timing information about operations
   Trade-off: throughput limited by slowest layer

4. Weight compression and quantization:
   INT8 weights: reduce value range (0-255 vs 0-4294967295)
   Hamming weight distribution: INT8 has lower range → weaker EM correlation
   Binary neural networks (BNN): weights are ±1 → single bit → minimal EM variation
   But: BNN accuracy tradeoff is significant

5. Physical randomization:
   Randomly rotate the device's orientation relative to attacker probe
   (Automated physical rotation: mechanical actuator — impractical)
   Position randomization of sensitive components on PCB:
   Multiple identical NPU units with random routing delays

6. Differential routing:
   Route all NPU data buses as differential pairs
   Complementary signals cancel external EM field:
   D+ carries signal, D- carries complement
   External EM: (D+) + (D-) = 0 → no net EM emission
   Used in DDR memory: LVDS (Low Voltage Differential Signaling)
```

---

## 9. Failure Points & Scaling

### Failures Under Heavy Load

```
Component              Load Threshold         Failure Mode          Impact
──────────────────────────────────────────────────────────────────────────────
TEE (SGX EPC)          EPC size (~256MB)      EPC paging to DRAM    3-10x latency
                       If model > EPC:         MEE re-encrypt eviction
                                               Performance cliff

TPM 2.0                ~80 ops/second         TPM command queue     Attestation
                       Hardware limit         full → TPM_RC_RETRY    failures,
                                                                     delayed startup

Attestation Service    API rate limit         429 Too Many          Devices can't
(Intel IAS/DCAP)       ~100/min               Requests              get keys on
                                                                     mass restart

mTLS Handshakes        ~1000/second           TLS server CPU        New connections
                       (Control plane)        exhaustion            rejected

Key Provisioning       Linear scaling needed  Single KPS instance   Key unavailable
Service                for device fleet       overloaded            = model offline

Cache LLC              95% fill rate          Cache thrashing        Latency spikes,
                                             → increased LLC misses  timing noise
                                             → higher side-channel
                                               signal!
```

**Critical failure interaction:** Under high load, LLC thrashing increases the signal-to-noise ratio of cache-timing attacks. Performance degradation correlates with increased vulnerability. This must be modeled explicitly in the security architecture.

### Network Partitions and TEE Split-Brain

```
Scenario: Edge node loses connectivity to control plane for 36 hours.

  T=0:     Network partition begins
  T=0-24h: Model key cached in TEE → inference continues normally
  T=24h:   Cached key expiry → model key revocation check fails (can't reach KPS)

Fail-closed behavior:
  At T=24h: Edge Agent detects KPS unreachable
  Decision: Load pre-fetched grace period extension (4h, signed by KPS)
  At T=28h: Grace period expired → TEE stops serving inference
  Service returns: 503 Service Unavailable

  Why fail-closed: If a device is compromised, the attacker would want to
  maintain inference service. Failing closed when disconnected forces
  re-attestation on reconnect — compromised device will fail re-attestation.

Split-brain risk:
  If two KPS instances exist (HA deployment) and they get out of sync:
    Device A: attestation valid on KPS-1 (has model key)
    Device B: attestation revoked on KPS-2 (compromised device)
    Network partition: A can reach KPS-1, B can reach KPS-2
    
    If B is compromised but KPS-2 doesn't know (revocation not propagated):
    B continues to serve (and potentially attack) for duration of partition
    
  Fix: KPS uses consensus protocol (Raft) across all nodes
       Revocation: requires quorum (2/3) of KPS nodes to confirm
       Model key issuance: requires quorum check
       Single KPS node: cannot issue key if majority unreachable
```

### TEE Memory Exhaustion (EPC Paging)

```
EPC Size Limitation:
  SGX EPC: typically 128MB-512MB (hardware fused)
  Large AI model: ResNet-50 weights = 97MB (fits in EPC)
             GPT-2 (small) weights = 548MB (does NOT fit)

When model > EPC:
  SGX paging mechanism (ME kernel) handles EPC swapping:
    1. Select victim EPC page
    2. Encrypt page with MEE (AES-CTR with page-specific IV)
    3. Compute MAC over encrypted page + version number
    4. Write to DRAM (version array page updated)
    5. Load requested page from DRAM: decrypt + verify MAC

  Security implications of EPC paging:
    - Encrypted pages in DRAM: safe from physical attack
    - Version arrays: prevent rollback attacks on paged content
    - Performance: each EPC miss ~microseconds vs nanoseconds for in-EPC
    
  Side-channel via page fault timing:
    OS can observe which EPC page was requested (page fault raised)
    Page fault pattern → reveals access pattern to model weights
    Access pattern → reveals model architecture / which neurons activated
    
  Fix: Oblivious RAM (ORAM) inside enclave
    Transform all memory accesses: randomly shuffle and re-encrypt
    External observer sees uniform random access pattern
    Performance cost: O(log N) overhead per access
    Production compromise: group weight pages into coarse "super-pages"
    Access at super-page granularity → reduces information leakage
```

---

## 10. Interview Questions

### Q1: Explain why Intel SGX's EPC encryption doesn't protect against cache-timing attacks, even though all DRAM content is encrypted.

**Why asked:** Tests understanding of the different layers where side-channels occur and why encryption is layer-specific.

**Answer direction:**

SGX's Memory Encryption Engine (MEE) operates at the DRAM bus level — it encrypts data before it travels over the memory bus and stores encrypted data in DRAM. This protects against physical probing of DRAM (oscilloscope on the DIMM) and cold-boot attacks.

However, the L1/L2/L3 caches operate on **decrypted data**. When the CPU loads an EPC page into cache, the MEE decrypts it at the cache line level. The decrypted data is accessible to any code on the same CPU core via standard CPU timing measurements.

The specific attack path: code running in normal world (Ring 3, outside the enclave) shares the LLC with the enclave. If the enclave performs a memory access that loads a cache line, the attacker can detect this via the Flush+Reload technique — flush the cache line, wait for the enclave to run, then measure reload latency. Fast = enclave loaded the line = enclave accessed that memory address. This reveals the *access pattern* of the enclave (which memory addresses were accessed), even though the *content* of those addresses is encrypted in DRAM.

For AI model inference: the access pattern of weight tensors reveals which neurons are active, which can reveal the model architecture or the input being processed. The fix is Intel CAT (Cache Allocation Technology) to partition the LLC, combined with constant-time / oblivious memory access patterns in the enclave code.

---

### Q2: What is the "Secret Zero" problem and why does hardware attestation solve it better than any software-based approach?

**Why asked:** Tests understanding of trust bootstrapping — one of the hardest problems in distributed security.

**Answer direction:**

The Secret Zero problem: when a device powers on for the first time in the field, how does it prove its identity to a remote server? The device needs to receive a secret (model decryption key) from the server. But to receive the secret, the device must first authenticate. But authentication requires a pre-shared secret or credential. Where does that first credential come from?

Software-only approaches fail:
- Pre-shared secret baked into firmware: anyone who reads the firmware gets the secret (can be read from flash, decompiled from binaries).
- Secret in a config file: readable by root.
- Secret on the network: needs a bootstrap secret to protect it.

Hardware attestation escapes this circular dependency because the credential is not *stored* — it is *derived* from the physical hardware. The TPM's Endorsement Key pair is generated inside the TPM at manufacturing, with the private key marked non-exportable. The TPM manufacturer signs the public key (creating the EKcert). This certificate chain — rooted in the TPM manufacturer's CA (trusted by device vendors) — proves that a genuine TPM with that key exists. The TPM then measures every boot stage into PCRs, creating a cryptographic record of what software ran. The remote server verifies both the TPM genuineness (EKcert) and software integrity (PCR measurement) before releasing any secrets. No pre-shared secret exists on the device — the identity emerges from hardware physics (manufacturing variation in the TPM) rather than stored data.

---

### Q3: A model must be larger than the SGX EPC limit. The team proposes loading model weights into normal (unencrypted) DRAM and using software access control to protect them. What are the security implications and what's the correct architecture?

**Why asked:** Tests understanding of TEE limitations and realistic deployment constraints.

**Answer direction:**

Loading model weights into normal DRAM, even with software access control (process isolation, seccomp, AppArmor), exposes them to:

1. **Root-level memory access:** `cat /proc/kcore`, /dev/mem (if enabled), or a kernel module can read all physical memory. Software access control is enforced by the kernel, which root can modify.

2. **Physical attack:** Oscilloscope on DRAM bus reads plaintext. Cold-boot attack freezes DRAM and reads it offline.

3. **Rowhammer:** Adjacent memory rows can be attacked to flip bits in the weight tensors, potentially causing targeted misclassification.

4. **Kernel vulnerability:** One CVE in the kernel = all software-enforced controls gone.

**Correct architecture options:**

Option A: EPC Paging with Oblivious Access (for weights that exceed EPC but fit in system RAM)
- Weights are paged in/out of EPC as needed, encrypted by MEE at all times in DRAM
- Access pattern protected via ORAM or coarse-page grouping
- Performance penalty: 3-10x for heavily paged models

Option B: Model Partitioning
- Split model: sensitive layers (first/last, most architecture-revealing) inside EPC
- Non-sensitive bulk computation (e.g., middle conv layers) in normal DRAM with TensorRT INT8 quantized weights (less sensitive)
- The decisive classification layers remain protected

Option C: AMD SEV-SNP or Intel TDX (for larger protected memory)
- SEV-SNP protects an entire VM's memory with hardware encryption
- No EPC size limit — entire VM memory is encrypted
- Trade-off: less fine-grained than SGX; whole VM trusted, not just enclave

Option D: Purpose-built secure NPU with on-chip SRAM
- Model weights fit entirely in on-chip SRAM (never leave the secure processor)
- Examples: Apple Secure Enclave, dedicated AI security processors
- No DRAM attack surface for weight storage at all

---

### Q4: Describe a Differential Power Analysis attack. What mathematical property does it exploit, and what is the fundamental reason masking defeats it?

**Why asked:** Tests deep understanding of physical side-channel theory.

**Answer direction:**

DPA (Kocher et al. 1999) exploits the correlation between the Hamming weight (number of 1-bits) of an intermediate computation value and the instantaneous power consumption of CMOS logic. CMOS power: P = α × C × V² × f, where α is the activity factor — proportional to the number of 0→1 transitions, which correlates with the Hamming weight of the data being written.

**Attack mechanics:**

For AES-128, the attacker targets the output of SubBytes in Round 1: z = SubBytes(plaintext[i] XOR key[i]). The attacker:
1. Sends N plaintexts through the device, records N power traces.
2. For each of the 256 possible values of key[i], computes HW(SubBytes(plaintext[i] XOR key_guess)).
3. Computes the Pearson correlation coefficient between this predicted Hamming weight and the actual power trace at each time sample.
4. The correct key guess shows a sharp correlation spike at the SubBytes execution time; wrong guesses show near-zero correlation.

**Why masking defeats it:**

With masking, a random value r is XORed into the intermediate: z_masked = z XOR r, where r is fresh random per operation. The attacker computes HW(z_masked) to predict power. But HW(z XOR r) is independent of HW(z) when r is uniformly random — specifically, E[HW(z XOR r)] = n/2 for any z, where n is the bit length. The correlation between the attacker's prediction (based on HW(z)) and the observed power (based on HW(z XOR r)) is zero.

**Second-order DPA:** The attacker looks at products of two time samples: the sample where z is processed and the sample where r is processed. The product correlates with HW(z). Defeating second-order DPA requires second-order masking (two independent masks), which is significantly more expensive. This is why the choice of masking order is a key security parameter in cryptographic hardware design.

---

### Q5: What is BYOVD (Bring Your Own Vulnerable Driver) and how does it apply to attacking the inference runtime on a secured edge node?

**Why asked:** Tests understanding of a realistic kernel-level attack technique used by real threat actors.

**Answer direction:**

BYOVD is a technique where an attacker loads a legitimate, digitally signed kernel driver that contains a known vulnerability (e.g., an arbitrary kernel memory read/write primitive). Because the driver is legitimately signed, it passes Secure Boot's signature check. The attacker then exploits the vulnerability from user space to gain kernel-level privileges or read arbitrary kernel/physical memory.

**Application to edge AI:**

If the attacker has local administrator access (not root on Linux — Windows admin, or physical access to boot from USB), they can:

1. Load a legitimately signed, vulnerable driver (e.g., RTCore64.sys from MSI Afterburner, or any of dozens of signed vulnerable drivers in LOLDrivers.io database).
2. The vulnerable driver provides a kernel-mode memory access primitive.
3. Through this primitive, the attacker reads the kernel's virtual address space, finds the inference process's page tables, and maps its address space to attacker-controlled memory.
4. Now reads model weights from the process's mapped memory — bypassing all user-space software controls.

**Defenses:**

- **Windows HVCI (Hypervisor-Protected Code Integrity):** Blocks loading of known-vulnerable drivers by maintaining a blocklist enforced at the hypervisor level. Even if a driver is signed, if it's on the blocklist, the hypervisor rejects it.

- **Linux Kernel Lockdown:** `kernel.lockdown=confidentiality` mode prevents loading of unsigned modules and prevents direct access to kernel memory via /dev/mem, /proc/kcore, even by root.

- **Driver allowlisting:** Only explicitly allowlisted drivers can load (Microsoft WDAC policy, or IMA policy for Linux modules). Arbitrary signed drivers: blocked.

- **Module signing:** Linux kernel requires all modules to be signed with a key that's built into the kernel image. A BYOVD driver signed by its vendor but not by your kernel's trusted key: rejected.

- **DRTM (Dynamic Root of Trust for Measurement):** Intel TXT or AMD SKINIT re-establishes trust at runtime, measuring the current running state into TPM PCRs. A rogue driver loaded after boot: changes PCR measurements → next KPS attestation fails → model key not refreshed → service stops after key expiry.

---

### Q6: How does an Isolation Forest or anomaly detection system help defend against model extraction attacks, and what are its fundamental limits?

**Why asked:** Tests ability to connect ML security (from the previous documents in this series) with hardware security.

**Answer direction:**

Model extraction via API is fundamentally a statistical attack — the attacker must make many queries with inputs covering the model's input space systematically. This creates anomalous usage patterns compared to legitimate API use:

- **Legitimate queries:** Clustered around the real data distribution (medical images cluster around anatomical regions; fraud detection queries cluster around realistic transaction amounts and merchant categories).
- **Extraction queries:** Either uniformly random across the input space, or actively targeted at decision boundaries (active learning for extraction).

An Isolation Forest trained on normal query distributions assigns high anomaly scores to extraction-pattern queries because: uniform random inputs are far from any legitimate data cluster (short isolation path = high anomaly score).

**Practical signals to monitor:**

1. Input feature distribution per API key (vs baseline legitimate distribution)
2. Unique query ratio (legitimate: many repeated similar inputs; extraction: nearly all unique)
3. Input diversity score (legitimate: bounded variance; extraction: maximum variance)
4. Query rate relative to expected business volume

**Fundamental limits:**

The Isolation Forest fails if the attacker: (a) knows the legitimate data distribution and samples from it while still covering the model's behavior space; (b) uses a very slow extraction rate that doesn't look anomalous in any single time window; (c) distributes queries across many API keys (each key below detection threshold individually). This is why anomaly detection is a layer of defense, not a complete solution. It must be combined with: hard rate limits, model watermarking (detect use of extracted model post-facto), and output perturbation (reduce information per query).

---

### Q7: Explain the security difference between Intel SGX's sealing key binding to MRENCLAVE vs MRSIGNER. When would you use each, and what are the attack implications?

**Why asked:** Tests nuanced understanding of SGX's key derivation policy options.

**Answer direction:**

When an SGX enclave calls `EGETKEY` to get its sealing key, it specifies a `key_policy` that determines what the key is bound to:

**MRENCLAVE binding:**
The key is derived from the exact hash of the enclave's code and static data at EINIT time. The key changes if a single byte of the enclave binary changes. A different version of the enclave cannot read data sealed by an older version — even if signed by the same vendor.

Use case: Maximum isolation between versions. Data sealed by version 1.0 is completely inaccessible to version 2.0, even if 2.0 is from the same vendor. Appropriate for highly sensitive data where forward migration requires explicit unsealing and re-sealing procedures.

Attack implication: If a vulnerability is found in enclave version 1.0 and patched in 2.0, the attacker who has stolen sealed data cannot use an exploit in 2.0 to access it (the key simply won't match). But also: the defender cannot automatically migrate sealed data to 2.0 without explicit unsealing in 1.0.

**MRSIGNER binding:**
The key is derived from the hash of the signing key (not the enclave code). All enclaves signed by the same vendor key, on the same platform, derive the same sealing key — regardless of version differences.

Use case: Model vendors who need to update the enclave (bug fixes, performance improvements) while maintaining access to previously sealed model caches or state. The new version can read old sealed data.

Attack implication: A vulnerability in ANY enclave version signed by the same key gives access to sealed data from ALL versions. If the vendor signs a debug enclave (DEBUG=1) with the same key, the debug enclave can read production sealed data. This is a significant risk: MRSIGNER policy should be combined with ISV-SVN (Independent Software Vendor Security Version Number) policies that prevent older/debug versions from reading data sealed by newer versions.

**Recommended practice for model protection:**
Use MRENCLAVE for the model weight sealing key — maximum protection, and model updates go through explicit re-provisioning from KPS anyway (no benefit to MRSIGNER here). Use MRSIGNER for configuration and session state that legitimately needs to persist across model updates.

---

### Q8: What is a fault injection attack and how does a hardware voltage glitch attack differ from a Rowhammer attack in terms of what it targets and what defenses apply?

**Why asked:** Tests breadth of knowledge across different physical attack classes.

**Answer direction:**

**Fault injection attacks** deliberately introduce errors into a computing system's operation to cause it to behave incorrectly in an exploitable way. The goal is typically to skip a security check (jump over an `if (signature_valid)` check), force a branch to take an unexpected path, or cause a function to return an incorrect value.

**Voltage glitching:**
- **Target:** The CPU's internal logic — specifically the combinational logic that computes a value in a single clock cycle.
- **Mechanism:** Briefly drop VCC below the minimum operating voltage (e.g., from 1.2V to 0.7V for 2-20 nanoseconds). During this glitch, logic gates may settle at incorrect values because the signal propagation time increases (lower voltage = slower transistor switching) — a setup time violation.
- **Effect:** One or more bits in a register or memory cell get incorrect values. If timed to coincide with a signature verification routine, can cause the result register to show "valid" when verification actually failed.
- **Defenses:** Voltage monitors that detect drop below threshold and immediately trigger a zeroize/reset; redundant computation (compute twice and compare); temporal redundancy (compute the same thing at random time intervals to detect inconsistency).

**Rowhammer:**
- **Target:** DRAM cell capacitors in the memory array, not CPU logic.
- **Mechanism:** Rapid, repeated reads of DRAM rows cause capacitive coupling to adjacent rows, flipping stored bit values (stored as charge in DRAM capacitors).
- **Effect:** Bit flips in memory contents — page tables, cryptographic keys, code pages.
- **Defenses:** ECC DRAM (detects/corrects bit errors); TRR (proactive refresh of adjacent rows); physical address randomization (attacker can't know which physical row to hammer); guard pages.

**Key difference for the defender:**
Voltage glitching is an active attack on the CPU's computation — it affects what the CPU calculates right now. It requires precise timing to hit the right instruction.
Rowhammer is a passive corruption of memory content — it affects stored data, not active computation, and the effect persists until the cell is refreshed or corrected. Voltage glitching defenses are real-time (detect and abort). Rowhammer defenses are either proactive (prevent flips) or reactive (detect corruption after it occurs via integrity checks).

---

*Document Version: 1.0 | Last Updated: May 2026 | Classification: Internal Engineering — Security Architecture*  
*Key References: Intel SGX Developer Reference, ARM TrustZone Developer Guide, NVIDIA H100 Confidential Computing Architecture, NIST SP 800-193 Platform Firmware Resiliency Guidelines, IEEE S&P "Cache-Attacks and Countermeasures" (Ge et al. 2018), USENIX "Revisiting Rowhammer" (2020).*
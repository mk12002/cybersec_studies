# Endpoint Detection and Response (EDR / XDR) Architecture: Internal Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Document  
> **Audience:** Security Architects, Systems Programmers, Detection Engineers, Interview Candidates  
> **Scope:** Full-stack EDR/XDR system — kernel drivers, userspace agents, telemetry pipelines, control plane, cryptographic trust, anti-tampering, and attack surface  
> **Version:** 1.0

---

## Table of Contents

1. [Component Narrative](#1-component-narrative)
2. [OS & Hardware Layer Flow](#2-os--hardware-layer-flow)
3. [Cryptography & State Management](#3-cryptography--state-management)
4. [Backend / Control Plane Architecture](#4-backend--control-plane-architecture)
5. [Authentication & Trust Bootstrapping](#5-authentication--trust-bootstrapping)
6. [Security Controls & Anti-Tampering](#6-security-controls--anti-tampering)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Attack Scenarios (Very Detailed)](#8-attack-scenarios-very-detailed)
9. [Failure Points & Scaling](#9-failure-points--scaling)
10. [Interview Questions](#10-interview-questions)

---

## Foundational Architecture Overview

An EDR (Endpoint Detection and Response) system is a security agent deployed on endpoints — laptops, servers, containers — that continuously monitors system behavior, detects threats, and enables response. XDR (Extended Detection and Response) adds cross-telemetry correlation across endpoints, network, identity, and cloud.

The system has three fundamental components:

```
┌─────────────────────────────────────────────────────────────────┐
│  KERNEL COMPONENT (Ring 0)                                      │
│  • Event collection: process creation, file I/O, network       │
│  • Mandatory hooks: intercept and inspect before execution      │
│  • Self-protection: prevent unloading, tampering               │
└─────────────────────────────────────────────────────────────────┘
           ↕ Kernel ↔ User boundary (Shared memory / IOCTL)
┌─────────────────────────────────────────────────────────────────┐
│  USERSPACE AGENT (Ring 3)                                       │
│  • Event processing and enrichment                              │
│  • ML inference (behavioral detection)                         │
│  • Telemetry batching and transmission                         │
│  • Response action execution                                    │
└─────────────────────────────────────────────────────────────────┘
           ↕ TLS 1.3 / mTLS over HTTPS (port 443 or 8443)
┌─────────────────────────────────────────────────────────────────┐
│  BACKEND CONTROL PLANE (Cloud / On-Prem)                       │
│  • Event ingestion and correlation                              │
│  • Global threat intelligence                                   │
│  • Policy distribution                                          │
│  • Response orchestration                                       │
└─────────────────────────────────────────────────────────────────┘
```

The entire security value of the system rests on one property: **the kernel component is more privileged than any attacker**. If this property is violated, detection fails. Every design decision in an EDR flows from defending this property.

---

## 1. Component Narrative

### 1.1 The Primary Function: Detecting Process Injection

Walk through a complete detection lifecycle — from attacker action to analyst alert — with explicit timing and IPC at each step.

**T=0ms: Attacker executes a classic process injection**

An attacker with local administrator privileges on the endpoint uses `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` to inject shellcode into `explorer.exe`.

**T=0ms: The kernel driver fires first**

The EDR's kernel driver has registered a callback via `PsSetCreateThreadNotifyRoutine`. When `CreateRemoteThread` is called from the attacker's process, the Windows kernel invokes this callback **before** the thread begins execution.

```
Attacker process calls:
  CreateRemoteThread(explorer.exe handle, ...)

         ↓ kernel intercepts

PsCreateSystemThread → PsSetCreateThreadNotifyRoutine callbacks fire
  EDR kernel callback executes in Ring 0:
    1. Capture: source process PID, target process PID, thread start address
    2. Examine: is start address backed by a file-backed memory section? (PE image)
       → Thread start address = 0x00A10000 (heap/anonymous allocation, NOT a PE module)
       → This is suspicious: legitimate threads usually start in a DLL
    3. Decision: suspicious = TRUE, inject_signal into kernel↔user shared buffer
    4. Return: allow thread to start (not blocking yet — logged first)
```

**T+0.5ms: Kernel → Userspace IPC (shared memory ring buffer)**

The kernel driver writes a structured event into a pre-allocated shared memory region. This is a lock-free ring buffer (producer in kernel, consumer in userspace agent):

```c
// Kernel writes this structure to shared memory:
struct edr_event {
    uint64_t  timestamp_ns;         // 1705328601123456789
    uint32_t  event_type;           // EDR_EVENT_THREAD_CREATE = 0x0012
    uint32_t  source_pid;           // attacker_process PID = 4821
    uint32_t  target_pid;           // explorer.exe PID = 1204
    uint64_t  start_address;        // 0x00A10000 (anonymous mapping)
    uint8_t   is_remote;            // 1 (cross-process thread creation)
    uint8_t   start_addr_backed;    // 0 (NOT backed by a file/PE module)
    uint32_t  source_parent_pid;    // cmd.exe = 3902
    uint8_t   source_image_signed;  // 0 (attacker's binary not signed)
    char      source_image_path[260]; // C:\Users\victim\AppData\Local\Temp\exploit.exe
    uint32_t  sequence_number;      // 99142 (monotonically increasing, for gap detection)
};
```

The ring buffer uses a write index (kernel-owned) and read index (agent-owned). The kernel increments the write index after writing. The userspace agent polls this buffer every 10ms OR is signaled via an Event object.

**T+0.7ms: Userspace agent event processing**

The agent's event processing thread wakes up (kernel set the event object via `KeSetEvent` → `SetEvent` in userspace):

```
Agent thread wakes:
  1. Read from ring buffer at current read_index
  2. Validate sequence_number: expected=99142, received=99142 ✓ (no gaps)
     If gap detected: report telemetry loss to backend, increase priority
  3. Enrich event:
     - Resolve PIDs to process objects (from cached process tree)
     - source_process = { pid:4821, image:"exploit.exe", parent_pid:3902, 
                          parent:"cmd.exe", user:"CORP\victim",
                          create_time: T-3200ms }
     - target_process = { pid:1204, image:"explorer.exe", 
                          integrity:"medium", signed:true }
     - Compute: process ancestry chain (cmd.exe → exploit.exe)
     - Look up: has exploit.exe been seen before? (local cache lookup)
       → Local cache MISS (never seen this SHA-256 before)
       → Queue for cloud hash reputation lookup
  4. Apply behavioral rules (fast path — deterministic rules first):
     Rule: THREAD_CREATE_REMOTE + !start_addr_is_pe_backed → score += 60
     Rule: source_process.parent = cmd.exe AND source_process.unsigned → score += 25
     Rule: target_process.high_value (explorer, lsass, etc.) → score += 15
     Combined score = 100/100 → ALERT_THRESHOLD = 75 → CRITICAL ALERT
  5. Apply ML model (slower path — LSTM sequence model):
     Current event + last 50 events for this PID → sequence embedding
     Model output: P(injection_attack) = 0.97
     ML score = 97/100
  6. Final score = max(behavioral_score, ml_score) = 100
```

**T+2ms: Response decision and execution**

```
Score = 100, Threshold for autonomous response = 90:
  Action: SUSPEND TARGET PROCESS (explorer.exe)
    → Agent calls: NtSuspendProcess(explorer_handle)
    → All threads in explorer.exe are suspended
    → No further code execution from the injected thread
    
  Action: CAPTURE MEMORY DUMP of explorer.exe
    → MiniDumpWriteDump() → dump to encrypted local file
    → File encrypted with agent's session key (key never leaves agent memory)
    
  Action: TERMINATE SOURCE PROCESS (exploit.exe)
    → TerminateProcess(exploit_handle, 0)
```

**T+50ms: Telemetry shipped to backend**

```
Agent batches the event (along with last 500 events for context):
  → Serializes to protobuf
  → Compresses with zstd
  → Encrypts (TLS 1.3 record)
  → HTTP/2 POST to backend ingestion endpoint
  → Includes: alert, full event context, process tree, file hashes, network connections
```

**T+200ms: Backend processes alert**

```
Backend ingestion service:
  1. Validates agent identity (mTLS certificate verification)
  2. Deserializes protobuf
  3. Enriches with global threat intelligence:
     - SHA-256 of exploit.exe → VirusTotal-equivalent: 47/72 engines = MALICIOUS
     - Network connections from exploit.exe → 185.220.x.x → known C2 ASN
  4. Correlates with other endpoints:
     - Same exploit.exe SHA-256 seen on 3 other endpoints in last 2 hours?
     - YES → campaign detected → escalate to incident
  5. Creates alert in SIEM with full context
  6. Sends response command back to agent: "submit memory dump for analysis"
```

**T+500ms: SOC analyst sees the alert**

The analyst receives a fully contextualized alert with process tree, network connections, file hashes, behavioral timeline, and suggested response actions.

---

## 2. OS & Hardware Layer Flow

### 2.1 Windows Kernel Telemetry Collection Mechanisms

The EDR kernel driver uses multiple collection mechanisms, each with different performance costs, timing, and coverage:

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│  Ring 0 (Kernel Mode)                                                              │
│                                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │  COLLECTION MECHANISMS                                                       │  │
│  │                                                                              │  │
│  │  1. PsSetCreateProcessNotifyRoutineEx() — Process creation/deletion          │  │
│  │     Fires: BEFORE process starts (create) or AFTER it exits (delete)        │  │
│  │     Data: PEPROCESS pointer, parent PID, image name, command line           │  │
│  │     Cost: ~1-2μs overhead per process event                                  │  │
│  │                                                                              │  │
│  │  2. PsSetCreateThreadNotifyRoutine() — Thread creation/deletion              │  │
│  │     Fires: On every thread create/delete, cross-process threads             │  │
│  │     Data: PID, TID, create/delete flag                                      │  │
│  │     Cost: ~0.5μs per thread event (high-volume: 10K+ events/sec)           │  │
│  │                                                                              │  │
│  │  3. PsSetLoadImageNotifyRoutine() — DLL/module load                         │  │
│  │     Fires: When any image (exe/dll) is mapped into a process                │  │
│  │     Data: PEPROCESS pointer, image name, image base address                 │  │
│  │     Critical: Detects DLL injection at the moment of mapping                │  │
│  │                                                                              │  │
│  │  4. ObRegisterCallbacks() — Object manager callbacks                        │  │
│  │     Use: Intercept OpenProcess/OpenThread with PROCESS_VM_READ access       │  │
│  │     Enables: Strip dangerous access rights before returning handle           │  │
│  │     (This prevents memory reading of protected processes from userspace)     │  │
│  │                                                                              │  │
│  │  5. CmRegisterCallback() — Registry callbacks                               │  │
│  │     Fires: On every registry operation (open, create, set, delete)          │  │
│  │     Critical: Detect persistence mechanism installation                     │  │
│  │     Cost: HIGH volume (thousands/sec) — requires aggressive filtering       │  │
│  │                                                                              │  │
│  │  6. FltRegisterFilter() — Minifilter driver (file system)                   │  │
│  │     Fires: Pre/post file operations (create, read, write, rename, delete)   │  │
│  │     Data: File path, process, operation type, buffer contents (optional)    │  │
│  │     Critical: Ransomware detection (encrypt-and-rename pattern)             │  │
│  │     Cost: Very high — every file I/O goes through minifilter               │  │
│  │                                                                              │  │
│  │  7. Network: WFP (Windows Filtering Platform) callouts                      │  │
│  │     Fires: At network layer, transport layer (TCP connect, UDP send)        │  │
│  │     Data: Source/dest IP, port, protocol, process ID                       │  │
│  │     Cost: ~2μs per connection                                                │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │  KERNEL DATA STRUCTURES (Direct access, no API overhead)                    │  │
│  │                                                                              │  │
│  │  EPROCESS: Kernel process object                                            │  │
│  │    → ActiveProcessLinks (traverse all processes without OpenProcess)        │  │
│  │    → Token (security context — SID, privileges, integrity level)           │  │
│  │    → ImageFileName, SeAuditProcessCreationInfo                              │  │
│  │    → VAD (Virtual Address Descriptor) tree → memory region map             │  │
│  │                                                                              │  │
│  │  VAD Tree inspection: The key anti-injection technique                      │  │
│  │    Every memory region in a process has a VAD node describing:              │  │
│  │    - Address range, protection flags (RWX, R-X, RW-)                       │  │
│  │    - Backing object: is this a file mapping? Which file?                   │  │
│  │    → Shellcode in anonymous RWX memory: no file backing = suspicious        │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────┘
                    │                            │
                    │ IOCTL / Shared Memory      │ Event Objects
                    ▼                            ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  Ring 3 (User Mode)                                                                │
│                                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │  EDR USERSPACE AGENT                                                        │  │
│  │                                                                              │  │
│  │  Thread 1: Event consumer (ring buffer reader, high priority)               │  │
│  │  Thread 2: Enrichment (PID→process name resolution, hash computation)      │  │
│  │  Thread 3: ML inference (behavioral model scoring)                          │  │
│  │  Thread 4: Telemetry transmitter (batch, compress, send)                    │  │
│  │  Thread 5: Policy updater (receive new detection rules from backend)        │  │
│  │  Thread 6: Response executor (isolate, terminate, collect)                 │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │  USERSPACE TELEMETRY SOURCES (supplement kernel events)                     │  │
│  │                                                                              │  │
│  │  ETW (Event Tracing for Windows):                                           │  │
│  │    Microsoft-Windows-Threat-Intelligence (THREAT provider):                 │  │
│  │      - ReadVirtualMemory, WriteVirtualMemory, QueueApcThread                │  │
│  │      - MapViewOfSection, UnmapViewOfSection                                 │  │
│  │      - AllocateVirtualMemory with PAGE_EXECUTE_* flags                      │  │
│  │    Microsoft-Windows-DNS-Client:                                            │  │
│  │      - Every DNS query with answering process PID                           │  │
│  │    Microsoft-Windows-PowerShell/Operational:                                │  │
│  │      - PowerShell script block logging (full script content)                │  │
│  │    Microsoft-Windows-WMI-Activity/Operational:                              │  │
│  │      - WMI queries (persistence mechanism, lateral movement)               │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Linux eBPF-Based Telemetry Collection

On Linux, modern EDRs use eBPF (Extended Berkeley Packet Filter) instead of kernel modules for telemetry collection:

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│  Linux Kernel Space                                                                │
│                                                                                    │
│  eBPF Programs (JIT-compiled, verified, safe):                                    │
│                                                                                    │
│  ┌──────────────────────────────────────────────────────────────────────────────┐  │
│  │  tracepoint/syscalls/sys_enter_execve                                       │  │
│  │    → Fires before execve() system call                                      │  │
│  │    → Captures: new process image, argv[], envp[], calling PID              │  │
│  │    → eBPF map: writes event to BPF_MAP_TYPE_PERF_EVENT_ARRAY              │  │
│  │    → Userspace reads via perf_event_open() ring buffer                     │  │
│  └──────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                    │
│  ┌──────────────────────────────────────────────────────────────────────────────┐  │
│  │  kprobe/security_mmap_file, kprobe/security_file_mprotect                  │  │
│  │    → LSM hooks: fires when mmap() or mprotect() called                     │  │
│  │    → Captures: VMA start/end, protection flags (PROT_READ|WRITE|EXEC)     │  │
│  │    → Key check: is a mapping being made EXECUTABLE after being WRITABLE?  │  │
│  │      (W^X violation — classic shellcode staging pattern)                   │  │
│  └──────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                    │
│  ┌──────────────────────────────────────────────────────────────────────────────┐  │
│  │  kprobe/ptrace_request                                                      │  │
│  │    → Fires on ptrace() calls (debugger attach, process inspection)          │  │
│  │    → Captures: tracer PID, tracee PID, ptrace request type                 │  │
│  │    → PTRACE_POKEDATA on a process → memory write (injection signal)        │  │
│  └──────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                    │
│  ┌──────────────────────────────────────────────────────────────────────────────┐  │
│  │  tc (traffic control) eBPF for network                                      │  │
│  │    → Attached to network interface ingress/egress                           │  │
│  │    → Captures: packet headers (src/dst IP, port, protocol)                 │  │
│  │    → Can be used for blocking (return TC_ACT_SHOT) — inline response       │  │
│  └──────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                    │
│  BPF Maps (shared state between kernel and userspace):                            │
│    BPF_MAP_TYPE_HASH: PID → process context (filename, ppid, etc.)               │
│    BPF_MAP_TYPE_PERF_EVENT_ARRAY: lock-free ring buffer for event streaming      │
│    BPF_MAP_TYPE_ARRAY: policy configuration from userspace → kernel eBPF         │
└────────────────────────────────────────────────────────────────────────────────────┘
                    │ perf_event_open() ring buffer
                    ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  Linux Userspace Agent                                                             │
│                                                                                    │
│  • poll() on perf_event_fd → wake on new events                                   │
│  • mmap() the perf ring buffer → read events without syscall overhead             │  
│  • Enrich events: resolve PID → /proc/PID/cmdline, cgroup, namespace info        │
│  • Apply detection rules and ML scoring                                            │
└────────────────────────────────────────────────────────────────────────────────────┘
```

**Why eBPF over kernel modules for Linux EDR:**

eBPF programs are verified by the kernel's verifier before loading — they are guaranteed to:
- Not access invalid memory (verifier checks all pointer accesses)
- Terminate (bounded loops only)
- Not crash the kernel (no kernel bugs from the eBPF program itself)

Kernel modules have none of these guarantees — a buggy kernel module crashes the system. For an EDR running on production servers, eBPF's safety properties are critical.

### 2.3 Hardware-Assisted Security Features

**Hypervisor-Protected Code Integrity (HVCI) / VBS integration:**

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  Intel VT-x / AMD-V  (Hardware Virtualization)                                  │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │  Secure Virtual Machine (Hypervisor)  ← runs at Ring -1 (VMX root)       │ │
│  │                                                                            │ │
│  │  Credential Guard: LSASS isolated in Hyper-V partition                   │ │
│  │    → NTLM hashes and Kerberos tickets in a separate VM                   │ │
│  │    → Main OS cannot directly access these even as SYSTEM                 │ │
│  │    → EDR agent can detect attempts to access CG memory                   │ │
│  │                                                                            │ │
│  │  HVCI (Hypervisor Protected Code Integrity):                             │ │
│  │    → Kernel code integrity enforced by hypervisor                        │ │
│  │    → Unsigned kernel code = hypervisor rejects the page as executable    │ │
│  │    → Prevents loading unsigned drivers (key EDR protection)              │ │
│  │    → Prevents kernel memory patching from within the OS                  │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │  Normal VM (Guest OS — Ring 0: Kernel, Ring 3: User)                     │ │
│  │                                                                            │ │
│  │  EDR Kernel Driver: runs here, protected by HVCI from modification       │ │
│  │  Applications: run here                                                   │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
│  Intel SGX / TrustZone (for agent key storage):                                │
│    → EDR stores its client certificate private key in an SGX enclave           │
│    → Enclave memory encrypted by CPU — kernel/admin cannot read it             │
│    → Prevents key extraction even if attacker has SYSTEM privileges             │
│    → Enclave attested to backend: only genuine Intel CPU + genuine EDR code    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Trusted Platform Module (TPM) for boot-time integrity:**

```
Boot sequence with EDR integrity:
  1. UEFI firmware measures itself → stores hash in TPM PCR[0]
  2. Bootloader measured → PCR[4]
  3. Kernel measured → PCR[8]
  4. EDR driver verified (Secure Boot signature check)
  5. EDR driver measured → PCR[9]
  
  TPM PCR values are:
    - Sealed (PCR-bound): certain data (like the EDR client key) is only unsealed
      if PCRs match expected values
    - CANNOT be modified: PCR values can only be "extended" (new = SHA256(old || new_measurement))
    - Attestation: backend can request TPM quote (cryptographically signed PCR values)
      → Verifies the exact software stack running on the endpoint
      → If any component was tampered with: PCR values differ → attestation fails
      → Agent certificate not issued → endpoint quarantined
```

---

## 3. Cryptography & State Management

### 3.1 Key Hierarchy

```
Root CA (offline, air-gapped HSM)
  └── Intermediate CA: "EDR Infrastructure"
        └── Signing key: used to issue per-tenant intermediate CAs
              └── Per-tenant Intermediate CA
                    ├── Backend server certificates (for mTLS server auth)
                    └── Endpoint agent certificates (for mTLS client auth)
                          └── Per-agent certificate: CN=agent-{uuid}, SAN=hostname
```

**Per-agent key generation and storage:**

```
Step 1: Key generation (happens during agent installation)
  → Generate RSA-4096 or ECDSA-P384 key pair in process memory
  → Immediately seal the private key to TPM:
    TPM2_Create() with:
      parent: TPM storage root key (SRK)
      policy: PCR[0,4,8,9] must match current values (boot integrity check)
      sensitive: private_key_bytes
    → TPM returns: encrypted key blob (can only be unsealed if PCRs match)
    → Store blob to disk: /etc/edr/agent-key.blob (encrypted, useless without TPM)

Step 2: Key usage
  When TLS connection needs the key:
  → TPM2_Load(parent=SRK, inPrivate=key_blob, inPublic=pub_key)
    → TPM validates PCR values match policy
    → If mismatch (kernel was patched): returns TPM_RC_POLICY_FAIL
    → Agent knows it's been tampered with: fail-closed (no telemetry sent)
  → TPM2_Sign(key_handle, digest) — signing happens INSIDE THE TPM
    → Private key bytes NEVER leave the TPM chip
    → Even SYSTEM/root cannot extract the key

Step 3: Certificate request
  → Generate CSR (Certificate Signing Request) using key from TPM
  → Include: hostname, hardware UUID, TPM attestation quote
  → Send to backend CA for signing
```

### 3.2 mTLS Handshake Details (Agent ↔ Backend)

```
Client (EDR Agent)                               Server (Backend)
       |                                                |
       |-- ClientHello -------------------------------->|
       |   TLS 1.3, cipher suites, key share            |
       |   Extension: supported_groups (x25519)         |
       |                                                |
       |<-- ServerHello --------------------------------|
       |    selected cipher: TLS_AES_256_GCM_SHA384     |
       |    key_share: server's x25519 ephemeral key    |
       |                                                |
       |<-- {Certificate} (server cert) ---------------|
       |    CN=backend.edr.corp, signed by Tenant CA   |
       |<-- {CertificateVerify} (sig over transcript)--|
       |<-- {CertificateRequest} (ask for client cert)-|
       |    acceptable CAs: [Tenant CA fingerprint]    |
       |<-- {Finished} --------------------------------|
       |                                                |
       |   Client verifies server cert:                 |
       |     Chain → Tenant CA → Intermediate → Root   |
       |     Hostname check: backend.edr.corp ✓        |
       |     Certificate Transparency log check ✓      |
       |                                                |
       |-- {Certificate} (agent cert) ---------------->|
       |    CN=agent-{uuid}, SAN=hostname              |
       |    Signed by same Tenant CA ✓                 |
       |-- {CertificateVerify} (TPM signs transcript)->|
       |    Signature: TPM2_Sign(transcript_hash)      |
       |    → Private key never leaves TPM             |
       |-- {Finished} -------------------------------->|
       |                                                |
       |   Server verifies client cert:                 |
       |     CN matches expected format ✓              |
       |     Agent UUID matches registered device DB ✓  |
       |     Certificate not revoked (OCSP check) ✓   |
       |     Certificate not expired ✓                 |
       |                                                |
       |=== Mutual authentication established =========|
       |=== HTTP/2 over TLS (application data) ========|
```

**Certificate revocation flow:**

When an agent is suspected compromised:
1. Backend operator revokes the agent's certificate via admin API
2. Revocation published to OCSP responder immediately
3. Next time agent attempts to connect: OCSP check fails
4. Connection rejected
5. Agent fails closed: no data sent, endpoint quarantined

### 3.3 In-Memory State Security

**The threat: An attacker with SYSTEM/root reads agent process memory to extract secrets.**

```c
// WRONG: Keys stored in heap (readable by debugger/memory dump)
char* api_key = malloc(32);
memcpy(api_key, key_bytes, 32);

// CORRECT: Keys stored in locked, guard-paged, encrypted memory region

// Step 1: Allocate memory region not swappable to disk
// Windows: VirtualLock() prevents paging
// Linux: mlock() prevents swapping
void* secure_region = VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
VirtualLock(secure_region, 4096);

// Step 2: Write key material
memcpy(secure_region, key_bytes, 32);
SecureZeroMemory(key_bytes, 32);  // Clear original copy

// Step 3: Protect with guard pages on both sides
// A memory dump that tries to read surrounding memory → access violation
// (attacker must know exact address to read just the key)
DWORD old_protect;
VirtualProtect(guard_page_before, 4096, PAGE_GUARD | PAGE_NOACCESS, &old_protect);
VirtualProtect(guard_page_after, 4096, PAGE_GUARD | PAGE_NOACCESS, &old_protect);

// Step 4: When done with the key, zero before freeing
RtlSecureZeroMemory(secure_region, 4096);
VirtualFree(secure_region, 0, MEM_RELEASE);
```

**Windows DPAPI (Data Protection API) for persistent state:**

```
Agent persists operational state (event sequence numbers, seen hashes, etc.)
between reboots using DPAPI:

CryptProtectData():
  Input: plaintext state blob
  Protection: AES-256 key derived from:
    - System DPAPI master key (bound to machine SID + system account)
    - Current user DPAPI key (optional)
  Output: encrypted blob — only decryptable on this specific machine
  
This means: copying the state file to another machine → cannot decrypt
            Reinstalling Windows → cannot decrypt (master key changes)
```

### 3.4 Telemetry Integrity: Tamper-Evident Event Streams

Events sent from agent to backend are not just encrypted but include **integrity markers** to detect tampering in transit or replay attacks:

```
Each event batch includes:
  1. Sequence numbers: monotonically increasing per agent
     Backend validates: did sequence jump? Events dropped or tampered.
  
  2. Batch HMAC: HMAC-SHA256 over all events in the batch
     Key: derived from TLS session key (unique per connection)
     Backend verifies: HMAC correct? Data not modified in transit.
  
  3. Timestamp cross-validation:
     Events include both agent-side timestamps AND backend receipt timestamp
     If delta > 5 minutes: clock skew alert (potential replay attack)
     If events arrive out of order: investigate for event suppression
  
  4. Agent heartbeat:
     Agent sends heartbeat every 60 seconds even if no events
     If backend doesn't receive heartbeat: endpoint may be isolated/offline
     Heartbeat includes: agent version, config hash, health metrics
     → Dead-man's switch: if agent is killed, backend knows within 60 seconds
```

---

## 4. Backend / Control Plane Architecture

### 4.1 Architecture Overview

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│  MULTI-TENANT BACKEND CONTROL PLANE                                               │
│                                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │  INGESTION TIER                                                              │ │
│  │                                                                              │ │
│  │  API Gateway (nginx/Envoy):                                                 │ │
│  │    → mTLS termination (validates agent certificates)                        │ │
│  │    → Rate limiting (per-agent: 10MB/s, per-tenant: 1GB/s)                  │ │
│  │    → Routes to appropriate ingestion service                                │ │
│  │                                                                              │ │
│  │  Ingestion Service (horizontally scaled):                                   │ │
│  │    → Validates batch HMAC (reject tampered telemetry)                       │ │
│  │    → Validates sequence numbers (detect drops/replays)                     │ │
│  │    → Publishes to Kafka (topic: events.{tenant_id}.{source_type})          │ │
│  │    → Acknowledges receipt to agent (retry on no-ACK within 5s)            │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │  PROCESSING TIER (Kafka consumers)                                          │ │
│  │                                                                              │ │
│  │  Detection Engine Consumer:                                                 │ │
│  │    → Applies global detection rules (Yara, Sigma, custom ML models)        │ │
│  │    → Correlates across endpoints (same hash seen on N endpoints)           │ │
│  │    → Maintains stateful context (process trees, network graphs)            │ │
│  │    → Emits alerts to alerts.{tenant_id} Kafka topic                        │ │
│  │                                                                              │ │
│  │  Threat Intelligence Consumer:                                              │ │
│  │    → Enriches events with TI: hash reputation, IP reputation, domain      │ │
│  │    → Queries: internal TI DB, commercial feeds (VirusTotal, etc.)         │ │
│  │    → Updates local cache: Redis (1-hour TTL for dynamic TI)               │ │
│  │                                                                              │ │
│  │  Policy Distribution Service:                                               │ │
│  │    → Pushes updated detection rules to agents                              │ │
│  │    → Signed rules: agents verify signature before applying                 │ │
│  │    → Config version tracking: prevents rollback to old vulnerable configs  │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │  STORAGE TIER                                                                │ │
│  │                                                                              │ │
│  │  Hot storage (Elasticsearch, 30 days):                                     │ │
│  │    → Searchable, indexed telemetry for incident investigation              │ │
│  │    → Query: "show all events for host X in last 7 days"                    │ │
│  │    → Per-tenant index isolation (no cross-tenant data access)              │ │
│  │                                                                              │ │
│  │  Cold storage (S3/GCS, 1 year):                                            │ │
│  │    → Compressed, encrypted, immutable (S3 Object Lock)                    │ │
│  │    → Parquet format for analytics                                           │ │
│  │    → Required for compliance (GDPR, SOC2, PCI-DSS retention requirements) │ │
│  │                                                                              │ │
│  │  Response DB (PostgreSQL):                                                  │ │
│  │    → Alert state (open, investigating, closed)                             │ │
│  │    → Response action queue (commands sent to agents)                       │ │
│  │    → Agent registration, certificates, health status                       │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Agent ↔ Backend Communication: Sync vs Async

**Async (telemetry, normal operation):**

```
Agent → Backend (Push, HTTP/2 streaming POST):
  Batch of events (every 5 seconds or 1000 events, whichever first)
  → Backend responds with 200 OK + sequence acknowledgement
  → Agent marks events as "shipped", removes from local buffer
  
If backend unreachable:
  → Agent stores events in local encrypted ring buffer (max 500MB on disk)
  → Retries with exponential backoff (1s, 2s, 4s, max 5 minutes)
  → When reconnected: sends buffered events in order
  → Sequence numbers allow backend to detect and handle duplicates
```

**Sync (response actions, high-priority):**

```
Backend → Agent (Long-poll OR gRPC bidirectional stream):
  
  Backend sends: RESPONSE_ACTION {
    action_type: ISOLATE_HOST,
    target: hostname,
    action_id: uuid,
    signature: ECDSA-P384(action_bytes, signing_key),
    expires: now + 300s
  }
  
  Agent receives:
    1. Verify signature (signing_key = backend signing cert, pinned in agent)
    2. Verify expires (reject replayed old commands)
    3. Verify action_id not seen before (replay protection)
    4. Execute: block all network except EDR backend
    5. Report result: ACTION_RESULT { action_id, success, error, timestamp }
  
  If action signature invalid: REJECT, LOG, ALERT (potential command injection)
```

### 4.3 Multi-Tenancy Isolation

```
Data isolation guarantees:
  1. Kafka: separate topics per tenant (tenantA events never on tenantB's topic)
  2. Elasticsearch: separate indices per tenant + document-level RBAC
  3. PostgreSQL: row-level security (RLS) policies enforce tenant isolation
  4. Agent certificates: issued by per-tenant CA (backend validates tenant from cert)
  5. API authentication: JWT contains tenant_id claim, backend enforces it
  
Network isolation:
  6. Separate ingestion namespaces in Kubernetes (NetworkPolicy isolation)
  7. Tenant-specific Kafka consumers (separate consumer groups)
  
Key isolation:
  8. Per-tenant KMS encryption keys (tenant A's data encrypted with key A)
  9. Key access logged and audited separately per tenant
```

---

## 5. Authentication & Trust Bootstrapping

### 5.1 The "Secret Zero" Problem

**The core problem:** When the EDR agent first installs on a new machine, it has NO credentials. It needs credentials to authenticate with the backend. How does it get its first credential without already having credentials?

This is the "Secret Zero" problem — the bootstrapping paradox.

**Solution: Hierarchical trust anchors**

```
Phase 1: Factory provisioning (device manufacturer or IT deployment)
  → During deployment: IT admin installs agent with an INSTALLATION TOKEN
  → Installation token: short-lived (4 hours), one-time-use, opaque string
  → Generated by backend admin API: create_enrollment_token(tenant_id, count=1, ttl=4h)
  → Token delivered to endpoint via: MDM push, SCCM, deployment script
  → Token has NO privileges except "exchange for real credentials"

Phase 2: Agent first boot enrollment
  1. Agent generates RSA-4096 key pair in memory
  2. Agent collects hardware attestation:
     - TPM endorsement key certificate (EK cert — issued by TPM manufacturer)
     - TPM attestation key + AIK certificate
     - Platform configuration registers (PCR values)
     - Machine UUID, BIOS serial
  3. Agent sends enrollment request:
     POST /api/v1/enroll
     Authorization: Bearer {installation_token}
     Body: {
       csr: base64(CSR),          // Certificate Signing Request
       tpm_ek_cert: base64(...),   // Proves genuine TPM hardware
       tpm_quote: base64(...),     // PCR values signed by TPM AK
       platform_info: {...}
     }
  4. Backend validates:
     → Installation token valid and unused ✓
     → Token matches tenant ✓
     → TPM EK certificate: verify against Intel/AMD/Microsoft root CAs ✓
     → TPM quote signature: valid, signed by the EK key ✓
     → PCR values: match expected values for this OS version + EDR version ✓
     → CSR: well-formed, key meets minimum size requirements ✓
  5. Backend issues certificate:
     → Signs CSR → Certificate: CN=agent-{uuid}, valid 90 days
     → Invalidates installation token (one-time-use enforced)
     → Records: agent UUID, cert fingerprint, TPM EK fingerprint in DB
  6. Agent receives certificate:
     → Stores private key in TPM (seals to current PCR values)
     → Stores certificate on disk (not secret, just identity)
     → Discards installation token from memory

Phase 3: Ongoing authentication (certificate-based)
  → mTLS with agent certificate (see Section 3.2)
  → Certificate renewed every 89 days (before 90-day expiry)
  → Renewal: same flow as Phase 2 but authenticated with current cert
    (no installation token needed for renewal)
```

### 5.2 Certificate Rotation Without Downtime

```
Renewal (day 89, 1 day before expiry):
  1. Agent generates NEW key pair (while old cert is still valid)
  2. Sends renewal request with mTLS using OLD certificate
  3. Backend validates: old cert valid, agent in good standing
  4. Backend signs new CSR → issues new certificate
  5. Agent atomically swaps: stores new cert+key blob
     (atomic write to disk — power failure safe)
  6. Agent continues using new certificate for next connection
  7. Old private key material zeroed from memory
  
If renewal fails (network outage during renewal window):
  → Agent retries every 10 minutes
  → If expiry reached without renewal: fail-closed
    (agent cannot send telemetry, backend quarantines the endpoint)
  → IT team must manually investigate (re-enrollment with new token)
```

### 5.3 Trust Hierarchy and Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: HARDWARE                                                       │
│  (Trusted by definition — CPU manufacturer, TPM manufacturer)                  │
│                                                                                 │
│  Intel vPro + TPM 2.0 + Secure Boot                                           │
│  → Provides: measured boot, key storage, attestation                           │
└─────────────────────────────────────────────────────────────────────────────────┘
                              ↑ grounds trust in
┌─────────────────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: FIRMWARE + OS KERNEL (Kernel Ring 0)                          │
│  (Trusted IF secure boot succeeded AND kernel measurement matches expected)     │
│                                                                                 │
│  EDR Kernel Driver: signed by Microsoft (WHQL) + EDR vendor                   │
│  HVCI: prevents unsigned code from running in kernel                           │
│  → Trust validated by: TPM PCR attestation, runtime integrity checking        │
└─────────────────────────────────────────────────────────────────────────────────┘
                              ↑ enforced by
┌─────────────────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: EDR USERSPACE AGENT (User Ring 3)                             │
│  (Trusted IF binary signature valid AND key in TPM matches attestation)         │
│                                                                                 │
│  Agent binary: signed with EV code signing certificate                         │
│  Protected process (PPL): cannot be accessed by other userspace processes      │
│  mTLS: authenticated to backend with TPM-backed certificate                   │
└─────────────────────────────────────────────────────────────────────────────────┘
                              ↑ communicates via
┌─────────────────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: NETWORK (Zero Trust, mTLS enforced)                           │
│  (No trust based on network position — every packet authenticated)              │
│                                                                                 │
│  Agent cert: issued after TPM attestation → agent IS genuine hardware          │
│  Backend cert: issued by trusted CA → backend IS genuine infrastructure        │
│  All commands signed: agent verifies backend signing key                       │
└─────────────────────────────────────────────────────────────────────────────────┘
                              ↑ connects to
┌─────────────────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: BACKEND CONTROL PLANE                                          │
│  (Trusted IF deployment isolated, access controlled, keys in HSM)              │
│                                                                                 │
│  Multi-tenant isolation enforced by code + infra                               │
│  Root CA offline, Intermediate CA in HSM                                       │
│  Admin access: MFA + PAM (Privileged Access Management)                        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Security Controls & Anti-Tampering

### 6.1 Windows Protected Process Light (PPL)

The EDR agent runs as a PPL — a special Windows security feature that prevents even SYSTEM-level processes from accessing the agent's memory or terminating it:

```c
// Registry key that enables PPL for the service:
HKLM\SYSTEM\CurrentControlSet\Services\EDRAgent
  "Type" = SERVICE_PROTECTED_PROCESS  // Flag enabling PPL

// Effect: the process runs with PROTECTION_LEVEL_ANTIMALWARE_LIGHT
// What this means:
//   - OpenProcess(PROCESS_VM_READ, EDR_PID) → ACCESS_DENIED (even as SYSTEM)
//   - TerminateProcess(EDR_handle) → ACCESS_DENIED (even as SYSTEM)
//   - CreateRemoteThread(into EDR process) → ACCESS_DENIED
//   - DebugActiveProcess(EDR_PID) → ACCESS_DENIED

// The kernel ONLY allows processes with equal or higher protection level to access PPL:
// - Anti-virus processes: can access (also run as PPL antimalware)
// - SYSTEM services without PPL: CANNOT access
// - Admin/user processes: CANNOT access

// Requirement to run as PPL antimalware:
//   The service DLL must be signed with a certificate that has the extended key usage:
//   OID 1.3.6.1.4.1.311.10.3.20 (Windows System Component Verification)
//   → Only Microsoft and approved security vendors have this
//   → Prevents an attacker from creating their own "PPL" process
```

### 6.2 Anti-Debugging and Anti-Tampering

```c
// Technique 1: Parent process validation
void ValidateParentProcess() {
    DWORD parent_pid = GetParentProcessId();
    HANDLE parent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parent_pid);
    
    wchar_t parent_image[MAX_PATH];
    GetProcessImageFileName(parent, parent_image, MAX_PATH);
    
    // Agent should be spawned by services.exe (Windows service manager)
    // If parent is cmd.exe, powershell.exe, etc. → tamper attempt
    if (!IsExpectedParent(parent_image)) {
        LogTamperAttempt("Unexpected parent process: " + parent_image);
        // Don't exit (that would tell attacker something)
        // Instead: operate in stealth mode, report to backend
    }
}

// Technique 2: Continuous integrity verification
void IntegrityVerificationThread() {
    // Every 30 seconds:
    while (true) {
        Sleep(30000);
        
        // Verify own binary hasn't been patched on disk
        uint8_t disk_hash[32];
        HashFile(GetCurrentProcessImagePath(), disk_hash);
        
        if (memcmp(disk_hash, EXPECTED_HASH, 32) != 0) {
            // Binary was modified after installation
            ReportTamper(TAMPER_BINARY_MODIFIED);
            // Fail closed: stop sending telemetry, alert backend via backup channel
        }
        
        // Verify key functions haven't been hooked in memory
        VerifyFunctionIntegrity();
    }
}

// Technique 3: Detecting in-memory hooks on critical functions
void VerifyFunctionIntegrity() {
    // Our EDR hooks NtOpenProcess. But an attacker may hook OUR hook.
    // Check the first 20 bytes of NtOpenProcess:
    uint8_t* ntopen = (uint8_t*)GetProcAddress(ntdll, "NtOpenProcess");
    
    // Expected: syscall stub (mov eax, syscall_number; syscall; ret)
    // If patched: first bytes are JMP (0xE9) or MOV R10 (0x4C 0x8B 0xD1) + JMP
    
    if (ntopen[0] == 0xE9 ||           // Relative JMP (32-bit)
        ntopen[0] == 0xFF) {           // Absolute JMP
        
        // Who installed this hook?
        uint64_t hook_target = ResolveJmpTarget(ntopen);
        char module_name[MAX_PATH];
        GetModuleFileName(hook_target, module_name, MAX_PATH);
        
        if (!IsEDROwnHook(hook_target)) {
            // Someone else hooked our hook: report immediately
            ReportAnomalousSyscallHook("NtOpenProcess", module_name, hook_target);
        }
    }
}
```

### 6.3 Kernel Driver Self-Protection

```c
// The kernel driver must protect itself from being:
// 1. Unloaded (DriverUnload = NULL means Windows cannot unload it)
// 2. Modified (use HVCI + Kernel Code Integrity)
// 3. Bypassed (watch for other drivers registering after ours that may intercept first)

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Set DriverUnload to NULL — cannot be unloaded via normal means
    // Even kernel-mode code cannot unload a driver with NULL DriverUnload
    // (except by patching kernel structures — detected by PatchGuard)
    DriverObject->DriverUnload = NULL;
    
    // Register callbacks (see Section 2.1)
    PsSetCreateProcessNotifyRoutineEx(ProcessCallback, FALSE);
    PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    ObRegisterCallbacks(&ObRegistration, &ObCallbackHandle);
    FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);
    
    // Register with Windows kernel integrity checks
    // KernelModeDriverProtectionCallback: Windows calls us if it detects
    // our driver's code has been modified (PatchGuard integration)
    
    return STATUS_SUCCESS;
}

// PatchGuard: Windows Kernel Patch Protection (KPP)
// Windows periodically validates:
//   - System call table (SSDT) not modified
//   - Interrupt descriptor table (IDT) not modified
//   - Kernel code sections not patched
// If violation detected: BSOD (bugcheck 0x109: CRITICAL_STRUCTURE_CORRUPTION)
// This protects our driver's hooks from being overwritten too
```

### 6.4 Fail-Open vs Fail-Closed Design

This is one of the most important architectural decisions in EDR design:

```
FAIL-CLOSED: If EDR cannot function, block the action being monitored.
  Pro: Maximum security — attacker cannot disable EDR to perform attack
  Con: If EDR has a bug, it takes down production systems
  Use cases: High-security environments, ransomware prevention in file system filter
  
FAIL-OPEN: If EDR cannot function, allow the action and log the gap.
  Pro: Production continuity — EDR bug doesn't take down the system
  Con: Attacker can cause EDR failure to allow their attack
  Use cases: Default for most commercial EDR (production stability)

The nuanced real-world approach:

For blocking decisions (prevent ransomware from writing encrypted files):
  → Fail-closed with circuit breaker:
    If EDR has been blocking > 1000 operations/second for 30 seconds:
      → This is probably a false positive storm, not an attack
      → Switch to fail-open + alert backend
      → Log all allowed operations during degraded mode
      → Auto-restore blocking after 5 minutes

For monitoring decisions (telemetry collection):
  → Always fail-open: never crash the endpoint to collect a log
  → Log the gap in sequence numbers
  → Backend alerts on gaps: "Agent missed 500 events due to buffer overflow"

For response actions (isolate host, kill process):
  → Always require human confirmation OR high-confidence automated threshold (>0.95)
  → Never fail-closed on response (accidental isolation = production outage)
```

---

## 7. Attack Surface Mapping

### 7.1 Full Attack Surface Diagram

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  ENDPOINT ATTACK SURFACE                                                             ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [A] EDR Kernel Driver (Ring 0)                                                     ║
║      Attack: Load malicious driver that unregisters EDR callbacks (BYOVD)           ║
║      Attack: Exploit kernel driver vulnerability → RCE in kernel context            ║
║      Attack: Corrupt shared memory buffer between kernel and userspace              ║
║                                                                                      ║
║  [B] EDR Userspace Agent (Ring 3, PPL-protected)                                   ║
║      Attack: Find PPL bypass (known Windows vulnerabilities like KDU toolkit)       ║
║      Attack: Inject into agent process (requires PPL bypass first)                  ║
║      Attack: Replace agent binary on disk (requires kernel driver to not notice)    ║
║                                                                                      ║
║  [C] Agent ↔ Kernel IPC (Shared Memory + IOCTL)                                   ║
║      Attack: Corrupt ring buffer head/tail pointers → agent misses events           ║
║      Attack: Inject fake events → false positives / alert fatigue                   ║
║      Attack: Overflow ring buffer → legitimate events dropped                       ║
║                                                                                      ║
║  [D] Agent ↔ Backend Network Channel (port 443, TLS)                              ║
║      Attack: Block agent's outbound traffic → blind the backend (network isolation) ║
║      Attack: Intercept TLS (requires CA compromise or cert pinning bypass)           ║
║      Attack: Replay old telemetry (sequence numbers prevent this)                   ║
║                                                                                      ║
║  [E] Local Agent Configuration (/etc/edr/ or Registry)                             ║
║      Attack: Modify exclusion list (add attacker directory to scanning exclusions)  ║
║      Attack: Modify detection thresholds (reduce sensitivity)                       ║
║      Attack: Replace certificate blob on disk (if private key not in TPM)          ║
║                                                                                      ║
║  [F] Local Agent Storage (encrypted buffer, state files)                           ║
║      Attack: Delete event buffer (destroy forensic evidence)                        ║
║      Attack: Fill disk to cause buffer overflow (events dropped)                    ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════════╗
║  BACKEND ATTACK SURFACE                                                              ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [G] Ingestion API (HTTPS, mTLS)                                                   ║
║      Attack: Exfiltrate valid agent cert from a compromised endpoint                ║
║             → Use it to send fake telemetry / suppress real telemetry from that EP  ║
║      Attack: DDoS ingestion with malformed or massive telemetry                     ║
║                                                                                      ║
║  [H] Policy Distribution (backend → agent push)                                    ║
║      Attack: Compromise backend signing key → push malicious "detection rules"      ║
║      Attack: Compromise policy distribution API → push config that disables EDR    ║
║                                                                                      ║
║  [I] Response Action Channel                                                        ║
║      Attack: Forge response commands (requires backend signing key)                 ║
║      Attack: Replay response commands (timestamp validation prevents this)          ║
║      Attack: Command injection via malicious hostname/path in response payload      ║
║                                                                                      ║
║  [J] Tenant Data Isolation                                                          ║
║      Attack: Cross-tenant data access via misconfigured Elasticsearch queries       ║
║      Attack: JWT tenant_id claim manipulation (if JWT not cryptographically bound)  ║
║                                                                                      ║
║  [K] Admin Console / API                                                            ║
║      Attack: Admin credential compromise → add exclusions, disable agents           ║
║      Attack: SSRF via admin API to reach internal services                          ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

IPC channels on the endpoint:
  Kernel ↔ Agent:  Shared memory (\\Device\\EDRSharedMemory), IOCTL, Event objects
  Agent internal:  Named pipes between agent threads, COM objects (Windows)
  Agent ↔ external: HTTPS on port 443 (outbound only, no inbound ports)
```

---

## 8. Attack Scenarios (Very Detailed)

### 8.1 Attack: BYOVD (Bring Your Own Vulnerable Driver)

**Attacker assumptions:**
- Local Administrator privileges on the endpoint
- HVCI NOT enabled (most common in enterprise)
- Windows 10/11 with EDR

**What BYOVD exploits:** Windows requires kernel drivers to be signed, but many OLD, LEGITIMATE drivers have known vulnerabilities. An attacker with admin rights can install these vulnerable signed drivers, then exploit them to get unsigned code running in the kernel — from the kernel, the attacker can then unregister the EDR's callbacks.

**Step-by-step execution:**

```
Step 1: Identify target driver
  Attacker uses: LOLDrivers.io, KDU (KernelDU toolkit)
  Example: RTCore64.sys (RTSS rivatuner statistics server driver)
    → Signed by: Guru3D (legitimate software)
    → Vulnerability: IOCTL handler allows arbitrary kernel read/write
    → No signature check required for installation (it's legitimately signed)

Step 2: Install the vulnerable driver
  sc create RTCore64 type=kernel binPath=C:\Windows\Temp\RTCore64.sys
  sc start RTCore64
  → Installs cleanly: signed driver, no EDR block (yet)
  
  What EDR sees at this step:
    - PsSetLoadImageNotifyRoutine fires: new driver loaded
    - EDR checks driver hash: RTCore64.sys SHA-256 against known bad list?
    - Modern EDRs have this hash in their blocklist
    - If blocklisted: EDR prevents load, alert fires, ATTACK STOPPED
    
  If NOT blocklisted (attacker uses newer/less-known vulnerable driver):
    - EDR logs the driver load but does not block
    - EDR scores: unsigned? NO (it's signed). Known malicious? NO.
    - Score: LOW — no alert

Step 3: Exploit the driver to write to kernel memory
  // Open device handle for vulnerable driver
  HANDLE hDevice = CreateFile("\\\\.\\RTCore64", GENERIC_READ|GENERIC_WRITE, 0, NULL, 
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  
  // Exploit: arbitrary kernel memory write IOCTL
  // This driver has a debug interface that allows: write value to kernel address
  struct WriteMemoryRequest {
    UINT64 Address;    // Kernel virtual address to write to
    UINT32 Value;      // 32-bit value to write
  } req = {
    .Address = address_of_edr_callback_array,  // Find via leaked addresses/symbols
    .Value = 0x00000000  // NULL out the callback pointer
  };
  
  DeviceIoControl(hDevice, RTCORE64_WRITE_IOCTL, &req, sizeof(req), 
                   NULL, 0, &bytesReturned, NULL);

Step 4: Nullify EDR callbacks
  // Find addresses of callback arrays:
  // PspCreateProcessNotifyRoutine (array of process callbacks)
  // PspCreateThreadNotifyRoutine
  // PspLoadImageNotifyRoutine
  
  // These are in ntoskrnl.exe at offsets that can be found via:
  // - Public symbols (Microsoft publishes ntoskrnl PDB files)
  // - Pattern scanning (look for known code patterns around the arrays)
  
  // Write NULL to each EDR callback slot in the arrays
  // → EDR's kernel callbacks no longer fire
  // → Process creation, thread creation, image loads: not seen by EDR

Step 5: Proceed with attack (now invisible to kernel telemetry)
  - Inject shellcode into target process
  - Dump LSASS memory (lsass.exe → mimikatz)
  - Lateral movement
  
  What EDR's userspace agent sees: NOTHING (kernel callbacks are nulled)
  What backend sees: Agent heartbeat continues (agent is alive but blind)
                     Eventually: backend notices telemetry rate dropped to zero
                     → "Agent health degraded — kernel callbacks may be compromised"
                     → Alert fires on BACKEND side: "Telemetry gap detected"

Step 6: Detection (what should have happened)
  - Hash of RTCore64.sys should have been in kernel driver blocklist
  - HVCI would prevent arbitrary kernel memory write
  - Kernel integrity monitoring (separate from EDR) would detect modified callback array
  - Backend alert on telemetry gap within 60-120 seconds of callback nullification
  - Driver load event with known-bad hash: immediate alert even before callbacks nulled
```

**Why this works:** The fundamental vulnerability is that Windows allows loading signed drivers regardless of their security history. BYOVD exploits the trust the OS places in driver signatures. Once in the kernel, all EDR protection is contingent on the EDR driver being alive — no EDR can detect from userspace that its kernel callbacks have been removed.

**Mitigations:**
- Enable HVCI (blocks arbitrary kernel write)
- Maintain driver blocklist (Windows Vulnerable Driver Blocklist, updated via Microsoft)
- Monitor driver load events: alert on ANY new driver load on production servers
- Backend-side telemetry gap detection: alert if event rate drops > 90% in 30 seconds

---

### 8.2 Attack: API Unhooking (Userspace Hook Bypass)

**Attacker assumptions:**
- Standard user OR admin privileges
- EDR uses userspace API hooking (not ETW/kernel-only)
- Target: prevent EDR from seeing API calls

**Background:** Many EDRs intercept API calls by patching the first few bytes of NTDLL.dll functions in each process's memory. The patch redirects execution to the EDR's monitoring code.

```
Normal NtCreateProcess (in NTDLL.dll loaded in target process):
  NtCreateProcess:
    4C 8B D1          mov r10, rcx  (first bytes: syscall stub)
    B8 C5 00 00 00    mov eax, 0xC5 (syscall number for NtCreateProcess)
    0F 05             syscall
    C3                ret

After EDR hooks it:
  NtCreateProcess:
    E9 AB CD EF 01    JMP 0x0001EFCDAB  (redirects to EDR monitoring code)
    00 00             (rest is overwritten/doesn't matter)
```

**Step-by-step execution:**

```
Step 1: Identify EDR hooks
  // Scan NTDLL in memory, find patched functions:
  HMODULE hNtdll = GetModuleHandle("ntdll.dll");
  PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hNtdll;
  // Walk export table, check first bytes of each Nt* function
  // If first byte is 0xE9 (JMP) or 0xFF 0x25 (indirect JMP): hooked
  
  // Attacker's code identifies:
  //   NtCreateProcess: HOOKED (JMP to 0x7FF800A10000 = EDR monitoring DLL)
  //   NtWriteVirtualMemory: HOOKED
  //   NtAllocateVirtualMemory: HOOKED

Step 2: Restore original bytes (unhooking)
  Method A: Read from disk (most common)
    // Open the NTDLL.dll file on disk (not the in-memory version)
    HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", 
                               GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    // Map the file into memory
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pDisk = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    
    // Find NtCreateProcess in the disk version (unhooked)
    // Copy the clean bytes from disk version to the in-memory version
    // (need to first change memory protection: VirtualProtect to RW, copy, set back to RX)
    
    DWORD oldProtect;
    VirtualProtect(NtCreateProcess_in_memory, 8, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(NtCreateProcess_in_memory, NtCreateProcess_on_disk, 8);  // Restore original bytes
    VirtualProtect(NtCreateProcess_in_memory, 8, oldProtect, &oldProtect);
    
  What EDR sees during Method A:
    - VirtualProtect call: EDR may hook this (it's a common anti-hooking operation)
    - File open of ntdll.dll: EDR file filter sees ntdll.dll opened by suspicious process
    - Memory write to ntdll memory: EDR should see this via ETW THREAT provider
    
  Method B: Direct syscall (bypasses userspace hooks entirely)
    // Instead of calling NtCreateProcess (which goes through hooked NTDLL),
    // issue the syscall directly:
    mov r10, rcx
    mov eax, 0xC5      // syscall number for NtCreateProcess
    syscall            // goes directly to kernel, bypasses NTDLL entirely
    ret
    
    // The attacker must know the syscall number:
    //   - Changes between Windows versions (not stable!)
    //   - Can be obtained by reading NTDLL from disk (byte 4 of the stub = syscall number)
    
  What EDR sees during Method B:
    - NOTHING if relying only on userspace hooks
    - Kernel callbacks (PsSetCreateProcessNotifyRoutine) STILL fire
    - ETW THREAT provider events still generated
    - Only APIs hooked via NTDLL patching are bypassed — kernel telemetry intact

Step 3: Perform malicious operation with hooks removed
  // Now call NtCreateProcess, NtWriteVirtualMemory, etc.
  // They go directly to the kernel without EDR monitoring code intercepting

  What the well-designed EDR still sees:
    - PsSetCreateProcessNotifyRoutine → process creation callback fires
    - PsSetCreateThreadNotifyRoutine → thread creation callback fires
    - ETW events from NT kernel providers
  What a userspace-hook-only EDR misses:
    - The full API call context (parameters, stack)
    - Some behavioral chains that relied on API call ordering
```

**Where detection happens:**
- EDR monitoring `VirtualProtect` on NTDLL memory (hook modification alert)
- ETW Microsoft-Windows-Threat-Intelligence provider for `WriteVirtualMemory`
- The write to NTDLL pages fires kernel minifilter callbacks (NTDLL is a file-backed mapping)
- `PsSetLoadImageNotifyRoutine` still fires on subsequent DLL loads

**Why this is a partial evasion:** Direct syscalls bypass USERSPACE hooks but NOT kernel callbacks. A well-designed EDR relies primarily on kernel callbacks (Section 2.1) — userspace hooks are supplementary. The lesson: EDR should never rely solely on userspace API hooks.

---

### 8.3 Attack: EDR Exclusion Abuse

**Attacker assumptions:**
- Local Administrator (not SYSTEM)
- Can modify registry or EDR configuration

**Step-by-step execution:**

```
Step 1: Identify EDR exclusion configuration
  // Most EDR agents read exclusions from:
  //   Registry: HKLM\SOFTWARE\{EDRVendor}\Config\Exclusions
  //   File: C:\ProgramData\{EDRVendor}\config.json
  //   Backend-signed policy (immune to this attack if properly signed)

Step 2: Add exclusion for attacker's directory
  // If exclusions are registry-based:
  reg add "HKLM\SOFTWARE\{EDRVendor}\Config\Exclusions\Paths" 
          /v ExcludedPath /d "C:\Windows\Temp\attacker\" /f
  
  // What EDR does with exclusions:
  //   When kernel driver sees process launch from excluded path:
  //   → Flag event as "excluded, skip analysis"
  //   → No behavioral scoring, no ML analysis
  //   → Events still logged (telemetry sent) but not analyzed for threats
  
  // Advanced EDRs: exclusions are backend-controlled, signed, immutable from local
  //   → Registry change would be detected (CmRegisterCallback fires on reg write)
  //   → EDR ignores local exclusion registry writes, only honors signed backend config
  //   → This attack fails against properly designed EDR

Step 3: Stage and execute from excluded path
  // Copy malicious binary to C:\Windows\Temp\attacker\evil.exe
  // Run it: EDR ignores the process events due to exclusion
  
Detection:
  - CmRegisterCallback: EDR sees the registry write to its own config key
    → Alert: "Unauthorized modification of EDR exclusion list"
  - Backend-side: next policy sync would validate local exclusions against signed policy
    → Discrepancy detected → alert + revert exclusion
  - Filesystem minifilter: EDR can monitor writes to its own config file
```

---

### 8.4 Attack: Telemetry Flooding (Coverage Evasion)

**Attacker assumptions:**
- Code execution on the endpoint (any privilege level)
- EDR has finite processing capacity for telemetry

**The attack:** Generate so many benign events that the ring buffer overflows and real attack events are dropped.

```
Step 1: Generate massive filesystem events
  // Create a process that creates, reads, writes, deletes files in a loop:
  while(true) {
    for(int i = 0; i < 1000; i++) {
      CreateFile(C:\Windows\Temp\flood_i, ...);
      WriteFile(handle, data, 1MB, ...);
      ReadFile(handle, buf, 1MB, ...);
      DeleteFile(handle);
    }
  }
  // This generates ~100,000 minifilter events per second
  
Step 2: Identify when buffer is full (timing-based detection)
  // Measure: how long between performing an operation and EDR responding?
  // (EDR responds = takes a defensive action or slows the operation)
  // If EDR response time increases → buffer is filling → events being processed slower

Step 3: Perform actual attack during flood
  // While flood process is running and EDR buffer is overflowing:
  // → Inject shellcode into explorer.exe
  // → If the injection events arrive while buffer is full: DROPPED
  // → EDR misses the injection

What a resilient EDR does:
  - Prioritize by event type: THREAD_CREATE_REMOTE never dropped (highest priority)
  - Process creation events: never dropped
  - File system events (especially high-volume filesystem operations): can be sampled
  - Rate limit per-process: if process generates > 10,000 events/second: flag that process
    as suspicious AND sample its events (dropping is fine — the process itself is anomalous)
  - Alert on high event rate per process: "Potential event flooding from PID 4821"

Why the attack partially works:
  - Some event types MUST be droppable (file read/write at 100K/sec cannot be fully processed)
  - The EDR must make coverage tradeoffs
  - A sophisticated attacker can pre-map which event types get priority and plan accordingly
```

---

## 9. Failure Points & Scaling

### 9.1 Failures Under Heavy System Load

**High-CPU endpoints (compilation servers, scientific computing):**

```
Problem: EDR file system minifilter is on the critical path for EVERY file I/O.
  → A server compiling a large C++ project may do 50,000 file operations per second
  → Each operation: EDR minifilter callback + hash computation + cache lookup
  → At high load: minifilter adds 3-5ms latency per file operation
  → 50,000 ops/sec × 5ms = effectively blocks the CPU
  
Actual measured impact:
  - Compilation time: +40-70% on some endpoints
  - Database servers: +15-25% query latency due to IPC syscall monitoring
  
Solutions:
  1. Dynamic filtering: learn which paths are high-frequency low-risk
     (compiler temp files, database WAL files) → reduce analysis depth for these
  2. Caching: don't re-hash the same file if modification timestamp + size unchanged
  3. Sampling: for very high-frequency operations, analyze 1% of events
  4. Process-level exclusion: exclude trusted compilation toolchains from file scan
     (with mandatory: still scan the FINAL output binary)

Memory pressure:
  Ring buffer: 128MB pre-allocated (kernel virtual memory, physical at write time)
  Event enrichment cache: 512MB (process tree, hash lookups)
  ML model: 200MB (LSTM weights loaded in agent process)
  Total agent memory: ~1GB
  → On embedded systems (1GB RAM): EDR uses 100% of available memory
  → Solution: tiered agent (minimal on constrained devices, full on normal endpoints)
```

### 9.2 Network Partitions and Split-Brain

```
Scenario: Corporate VPN goes down. 500 endpoints lose connectivity to EDR backend.
  
  What agents do (offline mode):
    → Continue kernel monitoring (no change — doesn't require connectivity)
    → Continue behavioral detection (ML model runs locally)
    → STOP sending telemetry (no backend reachable)
    → Buffer events locally (encrypted ring buffer, 500MB max)
    → Continue applying LAST KNOWN GOOD policy (detection rules cached locally)
    → Cannot receive NEW policy updates (missed TI feeds)
    → Cannot receive response commands from backend
    
  What backend sees:
    → 500 agents stop sending heartbeats within 60 seconds
    → Backend alerts: "Mass agent connectivity loss detected"
    → Backend checks: is the BACKEND down? (check other connectivity)
    → If it's the agents: likely network partition → notify IT NOC
    
  The risk:
    → Attacker could cause a network partition (cut the link), then attack
    → Agents continue detecting (kernel callbacks work offline)
    → Agents cannot RESPOND to backend commands (no kill orders)
    → Agents cannot receive updated TI (attacker could use brand-new malware hash)
    → After reconnection: backed-up telemetry is uploaded in order
      → If attack happened during partition: visible in telemetry AFTER reconnection
      → But response actions were delayed
    
  Critical design: LOCAL AUTONOMOUS RESPONSE
    Agents must be able to take SOME response actions without backend connectivity:
    → High-confidence detections (score > 0.95): autonomous response
    → Medium-confidence: buffer for human review after reconnection
    → Low-confidence: log only
    
    This prevents the "cut the network, attack freely" scenario.

Scenario: Backend database fails. Agents reconnect but DB is down.
  
  → Ingestion service accepts telemetry (stores in Kafka — no DB needed)
  → But: cannot validate agent certificates (certificate DB is down)
  → Option A: Reject all agent connections (fail-closed) → 0% coverage
  → Option B: Cache-based validation (use cached cert validation for N minutes)
  → Production choice: cache cert validation for 15 minutes during DB outage
    → Risk: 15-minute window where compromised cert would be accepted
    → Acceptable: cert compromise is a separate attack requiring significant effort
```

### 9.3 Scaling the Backend at Enterprise Scale

```
At 100,000 endpoints:
  Event rate: 100,000 endpoints × 2,000 events/min = 200,000,000 events/min = 3.3M events/sec
  Data volume: 3.3M events/sec × 1KB/event = 3.3 GB/second ingestion
  Kafka: 330 partitions (1 partition per 10K events/sec)
  Elasticsearch: 30-node cluster with 300TB storage per year
  
  Scaling challenges:
  
  1. Correlation at scale:
     "Has this file hash been seen on any endpoint?" requires a lookup across all 100K endpoints
     → Bloom filter (fast, small): "probably seen" vs "definitely not seen"
     → Exact lookup: Redis cluster (in-memory) with hash → [endpoint_list]
     → At 100M unique file hashes × 8 bytes each = 800MB Redis footprint → manageable
  
  2. Alert correlation:
     "Is this alert part of a campaign affecting multiple endpoints?"
     → Graph database (Neo4j): endpoints → shared file hashes → shared network destinations
     → Query: "find all endpoints that have communicated with this C2 IP in last 24h"
     → At scale: pre-compute graph edges incrementally, not on-demand
  
  3. Policy update propagation:
     "Push new detection rules to all 100K endpoints"
     → Don't push simultaneously (thundering herd)
     → Push with jitter: agents randomize their policy check interval ±30 minutes
     → Canary deployment: push to 1% of endpoints first, validate no FP storm, then rollout
```

---

## 10. Interview Questions

### Q1: Explain the complete flow from a `CreateRemoteThread` system call to an alert on the analyst's screen, including every IPC boundary and timing.

**Answer:**

The flow crosses five distinct execution contexts with specific IPC mechanisms at each boundary:

**1. User → Kernel (System Call, ~1μs)**

When the attacker's process calls `CreateRemoteThread()`, execution transitions from Ring 3 (user mode) to Ring 0 (kernel mode) via the syscall instruction. The CPU saves the user-space register state, loads the kernel stack, looks up the system call number in the System Service Descriptor Table (SSDT), and jumps to `NtCreateThreadEx` in ntoskrnl.exe. The entire process arguments are validated and copied from user space to kernel space (cannot trust user pointers directly in kernel mode).

**2. Kernel callback fires (~2μs after syscall entry)**

`PsSetCreateThreadNotifyRoutine` was registered by the EDR kernel driver at `DriverEntry` time. The kernel's thread creation code calls all registered notify routines sequentially before the new thread executes its first instruction. The EDR callback runs in the context of the creating process (attacker's process), at IRQL PASSIVE_LEVEL. The callback receives: PEPROCESS of both source and target process, the new thread ID.

The callback computes: is the target process different from the source process? Yes (remote thread). What memory address does the thread start at? Is that address backed by a file-backed memory section (a loaded PE/DLL) or anonymous heap memory? The VAD (Virtual Address Descriptor) tree for the target process is walked to answer this.

**3. Kernel → Userspace IPC (Shared memory write, <1μs)**

The callback writes a structured event into a pre-allocated shared memory region: a lock-free ring buffer using atomic compare-and-swap for the write index. The kernel driver then signals a kernel Event object (`KeSetEvent`), which wakes the userspace agent's waiting thread. This IPC mechanism is chosen because it imposes zero copies — the agent reads directly from the kernel-written buffer without any context switches for the data transfer itself.

**4. Userspace agent processing (5-20ms)**

The agent's event reader thread wakes, validates the sequence number (no gaps in the ring buffer), and begins enrichment: resolves PIDs to process names (from its cached process tree), checks the file hash of the source process against local and cloud reputation databases, builds the behavioral score by applying detection rules and passing the event through the ML model. 

The ML model (LSTM) receives the current event as the latest in a sequence of the last 50 events for this process. The model outputs P(malicious) = 0.97. Combined with the deterministic rule score (remote thread + non-PE-backed start address = 85/100), the final score is CRITICAL.

**5. Agent → Backend telemetry (50-500ms, async)**

The agent serializes the event (and its context: last 500 events, process tree) to protobuf, compresses with zstd (~4x compression), and sends via HTTP/2 POST over the existing TLS connection to the backend ingestion endpoint. The connection is mTLS — the agent's certificate was signed after TPM attestation. The entire serialized payload is covered by TLS's AES-256-GCM authenticated encryption.

**6. Backend processing → Analyst alert (100-500ms)**

The ingestion service receives the payload, validates the batch HMAC, deserializes, and publishes to Kafka. The detection engine Kafka consumer enriches with global threat intelligence (hash reputation: 47/72 AV engines flagged), correlates across endpoints, creates a structured alert, and writes it to the SIEM. The analyst's browser receives the alert via WebSocket push or polling, with the complete process tree, taint graph, and recommended response actions pre-populated.

**Total end-to-end timing:** ~50ms for the autonomous response (process suspended); ~600ms for the analyst alert in the SIEM.

---

### Q2: What is the "Secret Zero" problem, and how does an EDR agent solve it on first enrollment?

**Answer:**

The Secret Zero problem is the bootstrapping paradox: to authenticate with the backend, the agent needs credentials. To get credentials, it must first authenticate with the backend. How does it get its first credential?

The naive wrong answer is: "ship credentials with the agent binary." This fails because anyone who can access the binary (which is installed on millions of endpoints) has the credentials.

The correct solution has two components:

**Component 1: Short-lived installation tokens**

An IT administrator generates a one-time-use token through the backend admin API. This token is valid for 4 hours and can only be used once. It has a single permission: "exchange this token for a real agent certificate." The token is delivered to the endpoint via the existing trusted provisioning channel (MDM/SCCM) that was already authenticated with the IT admin's credentials.

This pushes the authentication responsibility from "trust the EDR agent" to "trust the MDM system" — which already has a trusted credential. The Secret Zero is the MDM system's authentication, which is the right place to anchor trust.

**Component 2: Hardware attestation**

But the installation token alone isn't enough — an attacker could intercept the token and use it to enroll a rogue device. The solution is hardware attestation via TPM.

During enrollment, the agent:
1. Reads the TPM Endorsement Key certificate (signed by Intel/AMD/Infineon, proving genuine hardware)
2. Creates a TPM Attestation Key
3. Requests a TPM Quote — a TPM-signed measurement of all Platform Configuration Registers (PCRs), which contain cryptographic hashes of the entire boot chain: firmware → bootloader → kernel → EDR driver

The backend validates:
- The EK certificate is signed by a known TPM manufacturer
- The PCR values match expected values for the specific OS version + EDR version being enrolled
- The TPM Quote is signed by the EK (proving the PCR values come from genuine hardware)

Only if both the installation token AND the TPM attestation are valid does the backend issue a real agent certificate. The private key is then sealed to the current TPM PCR values — if the system is subsequently tampered with (different kernel, patched EDR driver), the PCR values change, the TPM refuses to unseal the private key, and the agent cannot authenticate.

**What if there's no TPM?** The system must fall back to a weaker model: just the installation token, with more aggressive post-enrollment validation (anomaly detection if an "agent" sends telemetry inconsistent with the hardware it claims to be). This is why modern EDR deployments strongly prefer TPM 2.0 endpoints.

---

### Q3: How does an EDR detect process injection without userspace API hooks? Why does this matter?

**Answer:**

This question gets at the fundamental architectural question of whether an EDR can remain effective when its userspace monitoring is bypassed.

**The kernel-level detection mechanisms that don't require userspace hooks:**

1. **`PsSetCreateThreadNotifyRoutine`:** This kernel callback fires when ANY thread is created, including `CreateRemoteThread`. It runs BEFORE the new thread executes its first instruction. It cannot be bypassed by userspace API unhooking because it's registered in the kernel, not in the target process's NTDLL.

2. **VAD tree inspection in the callback:** When the thread creation callback fires, the EDR's kernel driver walks the target process's VAD (Virtual Address Descriptor) tree to determine whether the new thread's start address is backed by a file-mapped memory section (legitimate: a DLL loaded from disk) or anonymous memory (suspicious: shellcode staged in heap/stack). This check happens entirely in the kernel.

3. **`PsSetLoadImageNotifyRoutine`:** Fires when any DLL is mapped into any process's address space. Detects DLL injection at the moment the mapping occurs. Cannot be bypassed from userspace.

4. **`ObRegisterCallbacks`:** Object manager callbacks on OpenProcess and OpenThread. The EDR can inspect every request to open a process with memory-reading access rights. If the EDR uses this to strip `PROCESS_VM_READ` from handles returned to processes that shouldn't have it, the attacker cannot read target process memory even if they've removed all userspace hooks.

5. **ETW Threat Intelligence Provider:** `Microsoft-Windows-Threat-Intelligence` is a kernel ETW provider that emits events for operations like `ReadVirtualMemory`, `WriteVirtualMemory`, `AllocateVirtualMemory(PAGE_EXECUTE*)`. These events come from the kernel and are not affected by userspace hook removal.

**Why this matters:** The most common EDR evasion tools (SharpEDRChecker, EDRSandBlast, Cobalt Strike's "Bypass EDR" profiles) primarily target userspace hooks — they read NTDLL from disk and restore the original bytes, or they use direct syscalls to bypass the NTDLL layer entirely. An EDR that relies primarily on userspace hooks is vulnerable to these techniques. An EDR that relies primarily on kernel callbacks and kernel ETW is not affected by userspace hook removal.

The practical implication for an attacker: to truly blind a well-designed EDR, you need kernel-level access — which requires either BYOVD, a kernel vulnerability exploit, or a signed kernel driver of your own (which requires a trusted certificate). This is why attackers expend significant effort on BYOVD techniques; kernel-only EDR makes userspace evasion ineffective.

---

### Q4: A BYOVD attack successfully nullifies the EDR's kernel callbacks. What defenses remain? How does the backend detect the compromise?

**Answer:**

This is the scenario where the attacker has succeeded in partially defeating the EDR. Several detection and response mechanisms remain:

**Remaining endpoint-side defenses:**

1. **PatchGuard (Kernel Patch Protection):** Windows's own integrity system validates that kernel data structures (SSDT, IDT, callback arrays) haven't been modified. If PatchGuard detects that the process notification callback array was modified, it triggers a CRITICAL_STRUCTURE_CORRUPTION bugcheck (BSOD). The BSOD itself is detectable by the backend (heartbeat stops). This is a nuclear option — it takes down the system rather than allow the kernel to be corrupted.

2. **HVCI (Hypervisor Protected Code Integrity):** If HVCI is enabled, the hypervisor validates that every page marked executable in the kernel is covered by a valid code integrity policy. The BYOVD exploit that writes to kernel memory to null the callback array would be writing to data memory — but the VULNERABLE DRIVER's IOCTL handler would need to run arbitrary kernel code to perform the write. HVCI prevents the vulnerable driver from being loaded in the first place (it validates kernel code at page-table level) — actually preventing the BYOVD technique at the hypervisor layer.

3. **The agent's userspace dead-man's switch:** Even if kernel callbacks are nulled, the userspace agent continues running. The agent sends heartbeats every 60 seconds. The agent also continuously checks for anomalies in its own operation: if it suddenly stops receiving ANY events from the kernel after a period of normal operation, it reports this as a potential callback unregistration attack.

**Backend-side detection:**

4. **Telemetry rate anomaly:** The backend monitors events-per-second from each agent. A healthy Windows 10 endpoint generates 200-2,000 events/minute from process/thread/image callbacks alone. If callback arrays are nulled, this drops to near zero. The backend detects "Agent event rate dropped 95% in the last 2 minutes" and fires a critical alert: "Potential kernel callback unregistration on HOSTNAME."

5. **Driver load event:** The BYOVD attack requires loading the vulnerable driver. This triggers `PsSetLoadImageNotifyRoutine` BEFORE the callbacks are nulled. The EDR sees the driver load, checks the hash against known vulnerable driver signatures, and alerts. If the EDR vendor has the RTCore64.sys hash (or similar) in its blocklist: this alert fires and the attack is detected at step 2, before any kernel memory is modified.

6. **Heartbeat metadata:** Heartbeats include a hash of the currently registered callbacks (the EDR driver maintains a list of what it registered). After a BYOVD attack, the driver may continue sending heartbeats but the kernel callback count drops. The discrepancy between "driver reports 5 callbacks registered" and "backend observes events consistent with 0 callbacks" is detectable.

**The key lesson:** Defense in depth means the EDR doesn't rely solely on the kernel callbacks. The interaction between PatchGuard, HVCI, the TPM boot attestation, the userspace dead-man's switch, and backend telemetry rate monitoring means that a BYOVD attack creates multiple observable signals — the challenge is correlating them quickly enough to respond before the attacker completes their objective.

---

### Q5: How does mTLS differ from standard TLS in an EDR context, and why is it not sufficient alone to prevent a rogue agent from connecting?

**Answer:**

**Standard TLS vs mTLS:**

Standard TLS authenticates the SERVER to the CLIENT: the client verifies that the server's certificate was issued by a trusted CA and covers the expected hostname. The client is anonymous to the server (from a PKI perspective). This is what browsers use — the website proves its identity to you, but you (as a client) don't prove yours to the website.

mTLS (mutual TLS) adds CLIENT authentication: the server ALSO requires the client to present a valid certificate, and the server verifies that certificate against a trusted CA. In the EDR context:
- The agent verifies: "Is this really the EDR backend?" (standard TLS, validates server cert)
- The backend verifies: "Is this really a legitimate enrolled agent?" (mutual auth, validates agent cert)

This is implemented identically at the protocol level — the server sends a `CertificateRequest` message during the TLS handshake, and the client responds with its certificate chain and a `CertificateVerify` message signed with its private key.

**Why mTLS alone is insufficient:**

mTLS proves that the CERTIFICATE is valid — signed by a trusted CA and not revoked. It does NOT prove:

1. **That the endpoint hasn't been compromised:** An attacker who gains SYSTEM privileges on an enrolled endpoint can extract the agent's certificate (if it's stored in the file system or Windows certificate store without TPM protection) and use it from a different machine. The certificate is valid; the connection succeeds; the attacker has a valid "agent" connection to the backend. The backend sees valid credentials.

2. **That the software stack is genuine:** Even if the certificate is TPM-sealed (private key never leaves the TPM), the agent running could be a modified version that has been patched to suppress certain alerts or fabricate benign telemetry.

**What completes the security:**

- **TPM-sealed private keys:** The private key for the agent certificate is sealed to specific TPM PCR values representing the expected boot chain. If the system is tampered with (different kernel, patched agent binary), the PCR values change, the TPM refuses to unseal the key, and the agent cannot authenticate. This prevents key extraction.

- **TPM attestation on enrollment:** The backend verifies the entire boot chain during enrollment (PCR values). Combined with certificate transparency, this ensures only genuine systems with genuine software received certificates.

- **Behavioral validation:** The backend analyzes the agent's telemetry patterns. A "rogue agent" that sends fabricated telemetry will exhibit behavioral anomalies: wrong event types for the OS version, impossible timestamps, missing event types that should always be present. Anomaly detection on the telemetry itself detects manipulated agents.

The complete trust model requires: valid mTLS certificate (proves identity) + TPM attestation (proves genuine hardware + software) + behavioral consistency (proves genuine operation). No single mechanism is sufficient alone.

---

### Q6: What are the tradeoffs between fail-open and fail-closed for EDR blocking decisions, and how would you design a system that mitigates the risks of both?

**Answer:**

**Fail-closed (block if EDR cannot make a determination):**

Pro: Maximum security guarantee. An attacker cannot cause EDR failure (e.g., by triggering a bug or overloading the system) to "open the gate."

Con: A bug in the EDR causes production outages. An EDR bug that causes it to fail-closed on all file write operations would break every database, every compilation, every backup on the affected endpoint. In a large enterprise, this means production downtime from a SECURITY product — the opposite of what you want.

**Fail-open (allow if EDR cannot make a determination):**

Pro: Production continuity. EDR failures are transparent to normal operations.

Con: An attacker who can cause EDR failure (resource exhaustion, crash, deadlock) can then operate freely knowing the gate is open.

**The nuanced real-world design:**

The key insight is that not all operations have equal risk. A well-designed EDR uses risk-stratified fail-open/fail-closed:

**Always fail-closed (never allow on EDR failure):**
- Execution of a file with a known-malicious hash (blocklist match): this is a deterministic check, and if EDR cannot compute it within 100ms, the operation should wait. The failure scenario here (filesystem filter hangs) would be catastrophic anyway.
- Attempts to write to protected memory regions: kernel-enforced, no EDR component needed.
- Attempts to unload the EDR driver: kernel-enforced, DriverUnload = NULL.

**Circuit-breaker fail-open (allow after timeout, with mandatory logging):**
- Behavioral analysis for file operations: if the ML model hasn't returned within 200ms (system under load), allow the operation and log it for asynchronous analysis. The vast majority of legitimate operations will never trigger blocking from the ML model anyway.
- Hash reputation checks: if the cloud lookup times out, allow execution but flag the file for follow-up analysis.

**Always fail-open (never block, always log):**
- Telemetry collection: if the ring buffer is full, drop the event and log the gap. Never block the operation being monitored to wait for telemetry processing.
- Process creation events: if the enrichment thread is behind, allow the process to start and catch up asynchronously.

**The critical mitigation:** When fail-open occurs due to timeout, the EDR must log the gap AND the backend must alert on anomalous fail-open rates. If 30% of operations are timing out, something is wrong (EDR bug, resource exhaustion, or attacker-induced overload) and the security team must investigate. The fail-open logging creates an audit trail; the backend monitoring ensures gaps don't go unnoticed.

---

*Document ends. Coverage: complete EDR/XDR architecture — kernel driver callbacks (PsSetCreateThreadNotifyRoutine, WFP, eBPF), Ring 0/Ring 3 boundaries, HVCI/VBS/TPM integration, TPM-sealed key hierarchy, mTLS handshake details, Secret Zero bootstrapping, anti-tampering (PPL, PatchGuard), attack surface mapping, 4 detailed attack scenarios (BYOVD, API unhooking, exclusion abuse, telemetry flooding), scaling challenges, and 6 deep technical interview questions with complete answers.*
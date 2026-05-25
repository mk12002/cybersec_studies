# DDoS Mitigation Architecture — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference
**Audience:** Security Engineers, SRE/Platform Engineers, Network Engineers, SOC Architects
**Scope:** Complete breakdown of a production DDoS mitigation system — from packet arrival at the network edge to application-layer defense, including control plane management, BGP routing mechanics, scrubbing center operation, and failure modes
**System Context:** A multi-layer DDoS mitigation stack protecting a global SaaS platform: Anycast BGP at the edge → scrubbing centers → WAF/rate-limiting layer → origin infrastructure

---

## A Beginner's Orientation: What Is DDoS and Why Is Mitigation Hard?

**What DDoS is:** A Distributed Denial of Service attack floods a target with traffic from thousands or millions of sources simultaneously, exhausting network bandwidth, CPU, memory, or application-layer resources so legitimate users cannot be served.

**Why it is hard to defend against:**

```
The fundamental asymmetry:
  Attacker cost to send 1 Gbps of junk traffic:  ~$5/hour (botnet rental)
  Defender cost to absorb 1 Gbps of junk traffic: ~$50-500/hour (transit + compute)

  Attack traffic looks like legitimate traffic at the IP layer.
  The attack is distributed across thousands of IP addresses.
  You cannot simply "block the attacker" — there is no single attacker IP.

Attack categories and why each is different:
  Volumetric (Layer 3/4):  Fill the pipe. Target: network bandwidth
    Example: UDP flood, ICMP flood, DNS amplification
    Scale: Can reach 1-10+ Tbps with amplification
    Defense: Absorb volume at the edge (scrubbing), rate-limit by protocol

  Protocol (Layer 4):      Exhaust stateful resources. Target: firewalls, load balancers
    Example: SYN flood, ACK flood, fragmented packet flood
    Defense: SYN cookies, stateless ACL rules, protocol validation

  Application (Layer 7):   Exhaust application resources. Target: web servers, APIs
    Example: HTTP GET flood, Slowloris, low-and-slow POST flood
    Defense: WAF, rate limiting, CAPTCHA, behavioral analysis

  Reflection/Amplification: Use third-party servers as amplifiers
    Example: DNS reflection (amplification factor: 28-54x)
             NTP reflection (amplification factor: 206x)
             Memcached UDP (amplification factor: 50,000x)
    Defense: Block UDP services from internet-facing exposure, BCP38 egress filtering
```

**The defense architecture must operate at every layer simultaneously**, because an attack that is absorbed at one layer can simply pivot to the next.

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

### Normal User Request — Step by Step

**Scenario:** A user in Tokyo accesses `api.example.com`. We trace the packet journey through the full mitigation stack.

**T+0ms — DNS resolution**

User's browser queries `api.example.com`. The authoritative DNS response returns an **anycast IP** — the same IP address (e.g., `198.51.100.1`) is advertised from 50+ global Points of Presence (PoPs) via BGP.

```
User's DNS resolver → Authoritative DNS
  Query: api.example.com
  Response: 198.51.100.1, TTL=30s   ← Anycast IP

BGP routing directs the user to the NEAREST PoP:
  Tokyo user → Tokyo PoP (AS64496)
  London user → London PoP (AS64496, same ASN, different physical location)
  New York user → New York PoP (AS64496)
```

The 30-second TTL is critical: during an attack, DNS can be used to redirect traffic quickly by changing the TTL and updating records.

**T+30ms — TCP SYN arrives at Tokyo PoP**

```
Packet: SYN to 198.51.100.1:443
Journey: User NIC → ISP → BGP routing → Tokyo PoP edge router
```

At the Tokyo PoP, the packet is received by an edge router running BGP. The edge router applies the first layer of filtering:

```
Edge router ACLs (applied in hardware, line-rate, no CPU):
  PERMIT: TCP destination port 443, source not in known-bogon list
  PERMIT: TCP destination port 80
  DENY:   UDP source port 53 (DNS reflection mitigation)
  DENY:   UDP source port 123 (NTP reflection mitigation)
  DENY:   Source IP in RFC1918 (private ranges — should not arrive from internet)
  DENY:   Source IP 0.0.0.0/8, 240.0.0.0/4 (bogon ranges)
```

**T+30ms to T+35ms — Scrubbing Center Layer**

Traffic passes to the scrubbing center (could be in-line or via traffic diversion):

```
Layer 3/4 scrubbing (stateless, high-speed):
  - IP reputation check: Is source IP in threat intelligence blocklist?
  - Rate limiting by source IP: >10,000 packets/second from one IP → drop
  - Protocol validation:
      SYN packets without SYN flag set → DROP (malformed)
      IP header checksum invalid → DROP
      Fragmented packets: reassemble and inspect or drop depending on policy
  - SYN cookie challenge: Issue SYN-ACK with cookie, only complete if ACK returns

Layer 7 scrubbing (HTTP inspection, slower but context-aware):
  - HTTP method validation
  - Header anomaly detection
  - Rate limiting by URI, by user-agent, by session
  - Challenge (CAPTCHA or JS challenge) for suspicious clients
```

**T+35ms to T+45ms — WAF Layer**

Traffic forwarded to WAF (Web Application Firewall):

```
WAF processing chain:
  1. TLS termination (the WAF decrypts the request)
  2. HTTP header inspection:
     - Validate Content-Length matches body size
     - Check for malformed headers (Slowloris sends incomplete headers)
     - Block known bad User-Agents
  3. Rate limiting rules:
     - By IP: 100 req/min
     - By session: 50 req/min
     - By endpoint: POST /login: 10 req/min
  4. Signature-based detection (OWASP Core Rule Set)
  5. Custom rules (business logic)
  6. Forward or block decision
```

**T+45ms to T+120ms — Origin**

If the request passes all layers, it reaches the origin (load balancer → application server → backend). The origin has its own last-resort rate limiting and connection limits.

**Total added latency from DDoS mitigation: 5-20ms** (mostly from WAF TLS termination and rule evaluation)

---

### DDoS Attack Activation Lifecycle — What Happens When Attack Begins

**T+0s — Attack begins:** Attacker sends 500 Gbps of UDP flood toward `198.51.100.1`.

**T+0s to T+10s — Detection window:**

```
Telemetry systems detect anomaly:
  - NetFlow/IPFIX data: traffic volume at Tokyo PoP spikes from 10 Gbps to 500 Gbps
  - SNMP interface counters: input rate on edge router port exceeds 90% of link capacity
  - BGP community tags: upstream provider's DDoS detection system triggers

Automatic detection threshold:
  Normal traffic: 10 Gbps average, 25 Gbps peak
  Threshold for alarm: 50 Gbps for 30 consecutive seconds
  → ALARM fires at T+30s
```

**T+30s to T+90s — Automated mitigation activation:**

```
Step 1: Control plane publishes new BGP route announcement
  Before attack: Tokyo PoP advertises 198.51.100.1/32 normally
  During attack: Tokyo PoP withdraws 198.51.100.1/32
                 Scrubbing center advertises 198.51.100.1/32 with higher preference

  Effect: BGP routing shifts attacker traffic to scrubbing center

Step 2: Scrubbing center activates DDoS mitigation profile for this IP
  Profile: UDP flood mitigation
    - Rate limit UDP to 1 Gbps (known legitimate UDP usage for this service: near zero)
    - Apply IP reputation block list
    - Enable geo-blocking for attack source countries (if applicable)
    - Enable SYN cookie (in case attack pivots to TCP)

Step 3: Clean traffic tunneled back to origin
  GRE tunnel: Scrubbing center → Origin PoP
  Only inspected, clean traffic exits the scrubbing center toward the origin
```

**T+90s — Mitigation steady state:**

Attack traffic absorbed at scrubbing center. Legitimate users experience 5-15ms additional latency (re-routing through scrubbing center). Origin infrastructure unaffected.

**T+attack_end + 5 minutes — Mitigation deactivation:**

```
Traffic volume returns to baseline
Control plane withdraws scrubbing center's more-specific route
Traffic returns to normal forwarding path
Scrubbing center profile deactivated
```

---

## 2. Control Plane vs Data Plane Architecture

### Fundamental Distinction

```
CONTROL PLANE:  HOW THE SYSTEM IS CONFIGURED
  Manages routing state, filtering rules, mitigation policies.
  Operates at management timescales: seconds to minutes.
  Failure: Degrades gracefully (data plane continues with last-known state).
  Components: BGP routing daemons, SDN controller, policy management API,
              mitigation orchestrator, configuration management system.

DATA PLANE:     HOW TRAFFIC IS ACTUALLY PROCESSED
  Forwards, drops, inspects, or transforms packets.
  Operates at line-rate: nanoseconds to microseconds.
  Failure: Catastrophic (traffic stops flowing or protection stops working).
  Components: Edge routers (ASIC-based forwarding), scrubbing appliances,
              WAF engines, load balancers, traffic shapers.

KEY PRINCIPLE: The data plane must function even if the control plane fails.
  A BGP daemon crash should not stop the router from forwarding traffic
  based on the routing table that was already populated.
```

### Control Plane Components

```
MITIGATION CONTROL PLANE ARCHITECTURE

┌─────────────────────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE (Management Network)                       │
│                                                                             │
│  ┌─────────────────┐    ┌──────────────────┐    ┌────────────────────────┐ │
│  │ Traffic Analysis│    │ Mitigation       │    │ Policy Management      │ │
│  │ System          │───▶│ Orchestrator     │───▶│ API                    │ │
│  │ (NetFlow,       │    │                  │    │                        │ │
│  │  IPFIX, SNMP)   │    │ Decides:         │    │ CRUD operations on:    │ │
│  │                 │    │ - Which rules    │    │ - IP blocklists        │ │
│  │ Detects:        │    │   to activate    │    │ - Rate limit profiles  │ │
│  │ - Volume spikes │    │ - Traffic divert │    │ - Scrubbing profiles   │ │
│  │ - Protocol      │    │ - Escalation to  │    │ - BGP communities      │ │
│  │   anomalies     │    │   upstream       │    │ - WAF rule sets        │ │
│  │ - New attack    │    │ - Human alert    │    │                        │ │
│  │   patterns      │    │                  │    │ Stored in:             │ │
│  └─────────────────┘    └──────────────────┘    │ - Distributed KV store │ │
│                                  │              │   (etcd/Consul)        │ │
│                                  │              └────────────────────────┘ │
│                                  │                                         │
│                    ┌─────────────▼────────────────────────────────────┐   │
│                    │    BGP Route Controller                            │   │
│                    │                                                    │   │
│                    │  Manages route announcements across all PoPs       │   │
│                    │  Uses BGP communities to trigger upstream          │   │
│                    │  provider mitigation:                              │   │
│                    │    community 64496:666 = blackhole this prefix     │   │
│                    │    community 64496:100 = route to scrubbing center │   │
│                    │                                                    │   │
│                    │  Out-of-band management (separate to data paths)   │   │
│                    └────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Plane Components

```
DATA PLANE ARCHITECTURE (Traffic Forwarding Path)

Internet Traffic
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  EDGE LAYER (Anycast PoPs, globally distributed)        │
│                                                         │
│  Hardware: Juniper MX480, Arista 7500, or similar      │
│  Forwarding: ASIC-based, line-rate (nanoseconds)       │
│  Capacity: 1-4 Tbps per PoP                            │
│                                                         │
│  Functions (all in hardware, no CPU involvement):       │
│  - BGP route lookup (TCAM-based)                       │
│  - ACL evaluation (ternary CAM, line-rate)             │
│  - NetFlow sampling (1:1000 packet sampling for        │
│    analysis, hardware accelerated)                     │
│  - ECMP (Equal-Cost Multi-Path) across transit links   │
└────────────────────────┬────────────────────────────────┘
                         │ (normal path) or
                         │ (attack: diverted to scrubbing)
                         ▼
┌─────────────────────────────────────────────────────────┐
│  SCRUBBING LAYER                                        │
│                                                         │
│  Hardware: Arbor/Radware appliances OR                  │
│            custom DPDK-based Linux servers              │
│  Software: DPDK (Data Plane Development Kit) bypasses  │
│            Linux kernel for direct NIC access           │
│  Throughput: 100 Gbps - 10 Tbps per cluster            │
│                                                         │
│  Processing stages (in order):                          │
│  1. IP reputation / blocklist lookup (hash table)      │
│  2. Rate limiting per source IP (token bucket)         │
│  3. Protocol validation (packet header inspection)     │
│  4. SYN cookie for TCP                                 │
│  5. DNS rate limiting / validation for UDP/53          │
│  6. Pass clean traffic to WAF layer via GRE tunnel     │
└────────────────────────┬────────────────────────────────┘
                         │ GRE tunnel (clean traffic only)
                         ▼
┌─────────────────────────────────────────────────────────┐
│  WAF / RATE LIMITING LAYER                              │
│                                                         │
│  Software: Nginx + ModSecurity, Cloudflare Workers,     │
│            custom application firewalls                 │
│  TLS termination: Offloaded to dedicated SSL cards      │
│                   or software (BoringSSL/OpenSSL)       │
│                                                         │
│  Processing (per HTTP request, after TLS decrypt):      │
│  1. HTTP parsing and header validation                  │
│  2. Rate limiting (per IP, per session, per endpoint)   │
│  3. Signature matching (OWASP CRS rules)               │
│  4. Custom business rules                               │
│  5. Challenge issuance (JS challenge, CAPTCHA)          │
│  6. Forward to origin or block                          │
└────────────────────────┬────────────────────────────────┘
                         │ (clean, validated HTTP requests)
                         ▼
┌─────────────────────────────────────────────────────────┐
│  ORIGIN INFRASTRUCTURE                                  │
│  Load balancers → Application servers → Databases       │
│  Last-resort: connection limits, application rate limits│
└─────────────────────────────────────────────────────────┘
```

### State Management Separation

```
STATELESS components (can be restarted, scaled freely):
  - Edge router ACLs (loaded from config, replicated to all routers)
  - IP blocklists (pushed from control plane, stored in TCAM)
  - BGP routes (re-established on restart via BGP protocol)
  - WAF rules (loaded from config management, applied per-request)

STATEFUL components (must be managed carefully):
  - Rate limit counters (per-IP, per-session — stored in Redis or DPDK shared memory)
  - SYN cookie state (ephemeral, but must be consistent on same device)
  - Active challenge state (which IPs are in JS challenge, which passed)
  - BGP session state (peer sessions maintained as long-running TCP connections)
  - Scrubbing center mitigation profiles (currently active rules)

STATEFUL RISK:
  If a scrubbing appliance fails, rate limit counters are lost.
  IPs that were being challenged start fresh.
  An attacker who knows this can trigger appliance failure/failover to reset their rate limit state.
  Mitigation: Store counters in Redis cluster (HA), or accept the reset risk
  for the brief failover window (usually < 30 seconds).
```

---

## 3. Identity & Access Management Flow

### Who Manages the Mitigation System

```
HUMAN OPERATORS:
  - Network Engineers: Can modify BGP policies, ACL rules, scrubbing profiles
  - Security Engineers: Can modify WAF rules, IP blocklists, mitigation profiles
  - SOC Analysts: Can activate/deactivate specific mitigations, view dashboards
  - On-call SREs: Can trigger emergency mitigations, modify thresholds

AUTOMATED SYSTEMS:
  - Traffic analysis system: Can trigger mitigation activation (no human required)
  - Upstream provider API: Can send RTBH (Remotely Triggered Black Hole) requests
  - Threat intelligence feeds: Can update IP blocklists automatically
  - Orchestration system: Can modify BGP communities, update scrubbing profiles
```

### RBAC for Mitigation Controls

```
ROLE                    PERMISSIONS
────────────────────────────────────────────────────────────────────────
network-engineer        Read/Write: BGP policies, ACL rules, routing config
                        Read-only: Scrubbing profiles, WAF rules, dashboards

security-engineer       Read/Write: WAF rules, IP blocklists, mitigation profiles
                        Read-only: BGP state, network topology

soc-analyst             Write: Activate/deactivate named mitigations
                        Write: Add IPs to manual blocklist (< /24)
                        Read: All dashboards, logs, alerts
                        NOT: Modify BGP, change WAF rules

automation-system       Write: Activate pre-approved mitigation profiles
                        Write: Update IP blocklist from threat feeds
                        NOT: Modify BGP routes, change scrubbing thresholds
                        NOT: Affect origin infrastructure

read-only               Read: All dashboards and metrics

PRINCIPLE: Automation has strictly limited write scope.
           No automation system can disable ALL protection simultaneously.
           Humans required for: BGP route changes, disabling entire mitigation tiers.
```

### IAM Architecture Diagram

```
IAM ARCHITECTURE FOR DDoS MITIGATION CONTROL PLANE
═══════════════════════════════════════════════════════════════════════════

HUMAN OPERATORS                     AUTOMATED SYSTEMS
┌─────────────┐                     ┌──────────────────────────────┐
│ Network Eng │                     │ Traffic Analysis System       │
│ Security Eng│                     │ Threat Intel Feed Consumer    │
│ SOC Analyst │                     │ Mitigation Orchestrator       │
│ On-call SRE │                     └──────────────┬───────────────┘
└──────┬──────┘                                    │
       │ MFA (FIDO2 hardware key required           │ Service Account with
       │ for network/security roles)                │ short-lived OIDC token
       ▼                                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│               Identity Provider (Okta / AWS IAM Identity Center)     │
│                                                                      │
│  Human auth: MFA → session token (JWT, 8h TTL)                     │
│  System auth: OIDC workload identity → token (1h TTL, auto-refresh)│
│                                                                      │
│  All tokens: signed RS256, contain role claims, audited on use      │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ Token presented to
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│              API Gateway (Mitigation Management API)                 │
│                                                                      │
│  1. Validate JWT signature (against IdP public keys)               │
│  2. Check token expiry                                              │
│  3. Extract role claims                                             │
│  4. Apply RBAC: Does this role have permission for this action?     │
│  5. Log ALL actions to immutable audit trail (S3 + CloudTrail)     │
│  6. Forward authorized request to appropriate backend service       │
└──────┬────────────────┬────────────────┬────────────────────────────┘
       │                │                │
       ▼                ▼                ▼
┌──────────────┐ ┌────────────┐ ┌─────────────────┐
│ BGP Route    │ │ Scrubbing  │ │ WAF Rule         │
│ Controller   │ │ Profile    │ │ Management       │
│              │ │ Manager    │ │                  │
│ Auth: mutual │ │ Auth:      │ │ Auth: API key    │
│ TLS between  │ │ API key    │ │ scoped to WAF    │
│ API GW and   │ │ scoped to  │ │ cluster only     │
│ BGP daemon   │ │ scrubber   │ │                  │
│              │ │ API only   │ │                  │
└──────────────┘ └────────────┘ └─────────────────┘

NETWORK DEVICES (Routers, Switches):
  Management access: SSH with public key auth, no password auth
  Configuration: Pushed via NETCONF/RESTCONF from automation
  Out-of-band management: Separate management network (not in data path)
  Emergency access: Console access via out-of-band console server
                    (requires physical data center access + separate MFA)

AUDIT TRAIL:
  Every control plane action logged:
    - WHO: identity, IP, session
    - WHAT: exact API call, parameters
    - WHEN: timestamp (UTC, NTP-synchronized)
    - RESULT: success/failure
  Logs: Immutable (write-once S3 with Object Lock, 2-year retention)
  Alert: Any BGP route change, any mitigation activation → PagerDuty
```

### Certificate Management for Device-to-Device Auth

```
INTERNAL MUTUAL TLS:
  All internal service-to-service communication uses mTLS.
  Certificates issued by internal CA (Vault PKI or EJBCA).
  
  Certificate lifecycle:
    TTL: 24 hours (short-lived to limit blast radius of compromise)
    Issuance: Automated via Vault Agent sidecar or SPIFFE/SPIRE
    Rotation: Automatic before expiry (no manual intervention)
    Revocation: CRL + OCSP served by internal CA
    
  For network devices (routers, scrubbers):
    Device certificate: issued from device CA, 1-year TTL
    SSH host keys: Ed25519, rotated annually
    BGP session auth: MD5 TCP session password (legacy but widely supported)
                      OR BGP RPKI ROA validation (modern, cryptographic)
```

---

## 4. Core System Mechanics

### BGP Anycast — How It Actually Works

BGP (Border Gateway Protocol) is the routing protocol of the internet. Every autonomous system (AS) — a network under single administrative control — has an AS number (ASN). Our platform has ASN 64496.

```
ANYCAST BGP MECHANICS:

Step 1: We announce the same IP prefix from multiple locations.
  Tokyo PoP announces:    198.51.100.0/24 via AS64496
  London PoP announces:   198.51.100.0/24 via AS64496
  New York PoP announces: 198.51.100.0/24 via AS64496

Step 2: Internet routers choose the "best" path using BGP path selection.
  BGP path selection order:
    1. Highest Local Preference (within an AS — we control this)
    2. Shortest AS path (fewer AS hops)
    3. Lowest MED (Multi-Exit Discriminator)
    4. Prefer eBGP over iBGP
    5. Lowest router ID (tiebreaker)

  Tokyo ISP's router: receives routes to 198.51.100.0/24 via:
    - AS64497 → AS64496 (Tokyo PoP, AS path length: 2)
    - AS64498 → AS64499 → AS64496 (London PoP, AS path length: 3)
  Winner: Tokyo path (shorter AS path) → Traffic goes to Tokyo PoP

Step 3: During DDoS, we manipulate BGP to divert traffic.
  Option A: BGP Blackhole (RTBH)
    Announce 198.51.100.1/32 (more specific than /24) with blackhole community
    Community 64496:666 means "drop this traffic"
    Upstreams honor this community and drop packets before they reach us
    Effect: ALL traffic to this IP is dropped, attack AND legitimate users

  Option B: Traffic Diversion to Scrubbing Center
    Scrubbing center announces 198.51.100.1/32 with higher local preference
    Edge PoPs withdraw the /32 (keep the /24 for other IPs)
    All traffic to 198.51.100.1 flows to scrubbing center
    Scrubbing center tunnels clean traffic back to origin via GRE
    Effect: Attack absorbed, legitimate users see 10-30ms additional latency

ROUTE SPECIFICITY RULE:
  /32 (single IP) beats /24 (256 IPs) in BGP route selection.
  This is how scrubbing centers "steal" routes for specific attack targets:
  By announcing a more specific (longer prefix) route.
```

### DPDK — How Scrubbing Centers Process at Line Rate

```
DPDK (Data Plane Development Kit) bypasses the Linux kernel entirely
for network packet processing.

NORMAL LINUX NETWORK STACK:
  NIC receives packet
  → Hardware interrupt fires
  → Kernel interrupt handler runs
  → Packet copied from NIC DMA buffer to kernel socket buffer
  → Kernel processes packet (routing, NAT, netfilter/iptables)
  → Packet copied to userspace application buffer
  → Application processes packet
  
  Per-packet cost: ~1-10 microseconds (kernel overhead)
  Maximum throughput: ~15-20 million packets/second on modern hardware

DPDK NETWORK STACK:
  NIC receives packet
  → DPDK poll-mode driver (PMD) polls NIC directly (no interrupts)
  → Packet in hugepage memory (no copy, shared between NIC and CPU)
  → DPDK application processes packet directly
  → No kernel involvement at all
  
  Per-packet cost: ~0.1-0.5 microseconds
  Maximum throughput: ~150-200 million packets/second on modern hardware
  
DPDK is used in:
  - Scrubbing appliances (Arbor, Radware, or custom)
  - High-performance load balancers (NGINX Plus, F5 BIG-IP)
  - Stateless DDoS mitigation (custom-built rate limiters)

HOW THE SCRUBBER PROCESSES PACKETS WITH DPDK:
  For each packet (in a tight polling loop):
    1. src_ip = packet.ip.src
    2. Check: is src_ip in blocklist? (hash table lookup, O(1)) → DROP
    3. Check: is src_ip rate over 10k pps? (token bucket) → DROP
    4. Check: is this UDP? → Apply UDP protocol filter
    5. Check: is this TCP SYN? → Apply SYN cookie challenge
    6. Valid packet → forward to GRE tunnel toward origin
    
  All this at 100+ Gbps line rate, completely bypassing the OS kernel.
```

### SYN Cookies — The Stateless TCP Defense

```
PROBLEM: SYN flood exhausts connection tables.
  - Each SYN allocates a connection entry in the server's SYN queue
  - Attacker sends millions of SYN packets with spoofed source IPs
  - Server's SYN queue (default: 128-512 entries) fills up
  - Legitimate SYNs dropped — server appears down

SYN COOKIE SOLUTION:
  Server does NOT allocate state on SYN receipt.
  Instead: encodes connection state in the TCP sequence number.

  SYN arrives from 203.0.113.5:49821 → 198.51.100.1:443

  Server generates SYN-ACK:
    Sequence number = SHA1(src_ip, src_port, dst_ip, dst_port, secret, timestamp)
    = cookie (deterministic, can be recomputed from the 5-tuple + secret)
    Server allocates NO state — just sends this SYN-ACK

  Legitimate client sends ACK:
    ACK number = cookie + 1   (TCP standard: ACK = received SEQ + 1)
    Server receives ACK, recomputes what the cookie should have been
    If ACK - 1 == recomputed cookie: connection is valid → allocate state
    If ACK - 1 != recomputed cookie: the SYN was spoofed → DROP

  RESULT:
    Spoofed SYN with fake source IP: Server sends SYN-ACK into the void
    No SYN-ACK returned (attacker spoofed src IP) → no ACK → no connection
    No state allocated on server → SYN queue never fills
    Legitimate clients: complete the 3-way handshake normally

  TRADEOFF:
    SYN cookies cannot carry TCP options (window scaling, SACK)
    in the cookie-encoded sequence number (limited bits).
    Performance penalty for legitimate connections: minimal (< 1ms)
    Modern Linux kernels: implement SYN cookies transparently (net.ipv4.tcp_syncookies)
```

### Rate Limiting — Token Bucket Algorithm

```
TOKEN BUCKET ALGORITHM (used at every layer):

Concept:
  A bucket holds tokens. Tokens fill at rate R per second, capacity C.
  Each packet consumes 1 token.
  If bucket is empty: PACKET DROPPED.

Parameters for DDoS mitigation:
  IP-level rate limit: R=100 pps, C=1000 tokens (allows bursts)
  HTTP request limit: R=100 rpm per IP, C=200 (burst allowance)
  API endpoint limit: R=10 rpm per authenticated user

Implementation at scale (Redis):
  ALGORITHM per IP per second:
    bucket_key = f"rate:{ip}:{second}"
    current = INCR(bucket_key)
    if current == 1:
        EXPIRE(bucket_key, 2)  # Auto-clean after 2 seconds
    if current > limit:
        RETURN "rate_limited"

  Redis can handle: ~1 million rate limit checks per second per node
  For 10M+ simultaneous IPs: Redis Cluster with consistent hashing

  LEAKY BUCKET variant (smoother enforcement):
    Processes requests at a constant rate regardless of arrival pattern
    Excess requests queue (up to queue limit) then drop
    Used for: traffic shaping at origin (prevent burst overwhelm)

  SLIDING WINDOW COUNTER (more accurate than fixed window):
    count = redis.zcount(key, now-60, now)  # Count in last 60 seconds
    redis.zadd(key, {request_id: now})
    redis.expire(key, 61)
    if count >= limit:
        RETURN "rate_limited"
    PERMITTED
```

### BGP RPKI — Cryptographic Route Origin Validation

```
RPKI (Resource Public Key Infrastructure) prevents BGP route hijacking.

WITHOUT RPKI:
  Anyone running a BGP router can announce any IP prefix.
  In 2018: Pakistan Telecom accidentally announced YouTube's prefixes.
  Effect: YouTube traffic routed to Pakistan (mostly dropped there).
  Root cause: No cryptographic validation of who owns which prefix.

WITH RPKI:
  IP prefix owners create Route Origin Authorizations (ROAs):
    "AS64496 is authorized to announce 198.51.100.0/24 with max prefix /24"
  ROAs are signed with the prefix owner's certificate (from RIR CA: ARIN/RIPE/APNIC)

  BGP routers with RPKI validation:
    Receive announcement: 198.51.100.0/24 from AS64496
    Check ROA database: Is AS64496 authorized to announce this prefix? YES
    State: VALID → accept and use this route

    Receive announcement: 198.51.100.0/24 from AS99999 (not in any ROA)
    State: INVALID → reject this route (attacker cannot hijack)

  DEPLOYMENT:
    Route origin is validated by routers receiving the announcement.
    We as the prefix owner: create ROAs for all our prefixes.
    Our transit providers: validate RPKI before accepting routes from peers.

  HOW TO CREATE A ROA:
    1. Log into your RIR portal (ARIN, RIPE, APNIC)
    2. Navigate to your IP allocation
    3. Create ROA: prefix=198.51.100.0/24, origin_asn=64496, max_length=24
    4. ROA is signed with the RIR's CA and published to RPKI repositories
    5. Routers download the ROA and validate incoming BGP routes against it
```

---

## 5. Attack Mechanics

### Attack 1: UDP Amplification/Reflection Attack

**Why amplification is so effective:**

```
AMPLIFICATION FACTOR EXAMPLES:
  Protocol   | Request Size | Response Size | Amplification
  ───────────────────────────────────────────────────────
  DNS ANY    |   60 bytes   |  ~3,000 bytes |   ~50x
  NTP monlist|   8 bytes    |  ~482 bytes   |   ~60x (but with 100 responses = 206x)
  Memcached  |   15 bytes   |  ~750,000 bytes|  ~50,000x
  SSDP       |   30 bytes   |  ~1,900 bytes |   ~30x
  CLDAP      |   52 bytes   |  ~76 bytes    |   ~70x (connectionless LDAP)

Attacker's economics with DNS amplification:
  Attacker's botnet capacity: 10 Gbps outbound
  Attack target bandwidth:   10 × 50 = 500 Gbps inbound at victim
  Victim needs 500 Gbps of transit to absorb this — extremely expensive
```

**Step-by-step DNS amplification attack execution:**

```
Step 1: Attacker finds DNS resolvers that respond to ANY queries
  Scan: masscan -p53 --rate 1000000 0.0.0.0/0 (scan internet for open DNS)
  Test: dig ANY example.com @<found_resolver>
  If response is large (> 3000 bytes): add to amplifier list
  Result: Attacker collects list of 100,000 open resolvers

Step 2: Attacker sends spoofed DNS queries
  Spoofed source IP: 198.51.100.1 (victim's IP)
  Destination: 100,000 open DNS resolvers
  Query: ANY example.com (returns large response)
  
  Each query packet:
    Source IP:   198.51.100.1 (SPOOFED — attacker does NOT own this)
    Destination: <open_resolver_IP>:53
    Protocol:    UDP (connectionless — no handshake required for spoofing)
    Payload:     DNS ANY query for example.com

Step 3: DNS resolvers send large responses to victim
  Each resolver sends: DNS ANY response (3,000 bytes) to 198.51.100.1:53
  From 100,000 resolvers: 100,000 × 3,000 bytes = 300 MB/second per query round
  Attacker sends 100,000 queries × 3 = 900,000 responses per second
  Peak bandwidth at victim: 900,000 × 3,000 bytes = 2.7 Gbps per query rate

  At attacker's full 10 Gbps botnet capacity:
  Queries sent: ~13 million/second
  Responses at victim: ~13M × 3,000 bytes = ~390 Gbps

Step 4: Why default configuration fails
  - Victim's router has only 10 Gbps uplink: SATURATED (even with filtering)
  - Victim cannot filter: traffic arrives from 100,000 different source IPs
    (the legitimate DNS resolvers — not attacker-controlled IPs)
  - Blocking DNS resolvers blocks legitimate DNS traffic
  - Traffic fills the pipe BEFORE it reaches any firewall or filtering device

Step 5: Effective defense requires upstream action
  - Victim contacts transit providers: "Please filter UDP/53 traffic to my IP"
  - Transit provider applies upstream filter: DROP UDP/53 destined for victim
  - This reduces attack volume to a manageable level
  - Scrubbing center: Rate limits remaining DNS traffic aggressively
  - Scrubbing center: Validates DNS response packets (no queries should arrive at port 53 on a web server — only responses if we made queries)
```

**BCP38 — The root cause fix:**

```
BCP38 (Network Ingress Filtering, RFC 2827):
  Requires ISPs to filter outbound traffic from customers:
  "Only allow packets with source IPs from the prefixes I've assigned to you."

  If all ISPs implemented BCP38:
  - Attacker's spoofed packets (with victim's source IP) would be dropped by
    the attacker's own ISP before reaching the internet
  - Amplification attacks would be impossible (cannot spoof source IP)

  Reality: BCP38 adoption is ~40% globally.
           Some ISPs fail to implement it.
           One non-BCP38-compliant ISP is enough for attackers to spoof.

  CHECK if a network implements BCP38:
  https://spoofer.caida.org — tests if your ISP drops spoofed packets
```

---

### Attack 2: HTTP Slowloris — Exhausting Server Connections

**How it works:**

```
NORMAL HTTP:
  Client connects → sends complete HTTP request → server responds → done
  
  Time for request: < 100ms typically

SLOWLORIS ATTACK:
  Client connects → sends PARTIAL HTTP request → pauses → sends 1 byte more
  → pauses → sends 1 byte more → ... (keeps connection alive indefinitely)

  HTTP request is never completed, so the server cannot respond.
  But the server cannot close the connection — the client IS sending data.
  The connection occupies a slot in the server's connection table.

  Attack:
    Attacker opens 1,000 connections to the server
    Each connection sends:
      GET / HTTP/1.1\r\n
      Host: example.com\r\n
      X-a: b\r\n           ← Fake header, keeps request "incomplete"
    Then every 15 seconds: sends \r\n (one more fake header)
    HTTP request never terminates (never sends the final \r\n\r\n)

  Effect:
    Server's connection limit: 1,024 (typical default)
    Slowloris uses all 1,024 slots with incomplete requests
    Legitimate users: "connection refused" (no slots available)

  From ONE MACHINE:
    Slowloris is effective from a single attacker machine.
    It does not require a botnet.
    Very low bandwidth required (~100 Kbps for 1,000 connections).

MITIGATION MECHANISMS:
  Timeout (incomplete request timeout):
    If no complete request headers within 5 seconds: close connection
    Nginx: client_header_timeout 5s;
    Apache: RequestReadTimeout header=5

  Connection limits per IP:
    Nginx: limit_conn_zone, limit_conn
    If one IP opens > 10 connections: reject 11th

  Reverse proxy with fast timeout:
    Cloudflare, Nginx, HAProxy terminate HTTP connections quickly.
    Origin server sees only complete, valid requests — never Slowloris.

  Operating system: Increase listen backlog and connection limits
    net.core.somaxconn = 65535
    nginx worker_connections = 65535
```

---

### Attack 3: BGP Route Hijacking — Network Layer Attack

```
SCENARIO: Attacker hijacks our IP prefix to intercept or drop our traffic.

ATTACK STEPS:
  Step 1: Attacker finds a poorly-secured ISP that accepts external BGP routes
          without proper filtering (AS filters, prefix filters, RPKI).

  Step 2: Attacker connects to this ISP and announces:
          198.51.100.0/24 from AS99999 (attacker's AS)
          OR: 198.51.100.0/25 (a more specific prefix — beats our /24)

  Step 3: Some internet routers (those not doing RPKI validation) prefer
          the attacker's more-specific /25 route.
          Traffic from those routers' customers now flows to the attacker.

  Step 4: Attacker can:
          A) Drop all traffic (DDoS effect — victim's service unreachable)
          B) Proxy traffic to victim (MITM — attacker sees plaintext if no TLS)
          C) Selectively drop or modify traffic

WHY THIS MATTERS FOR DDoS:
  An attacker can make our DDoS mitigation infrastructure ineffective by hijacking
  our IP prefix. Traffic that should reach our scrubbing center goes somewhere else.
  Our mitigation announcements are overridden by the attacker's announcements.

DEFENSES:
  1. RPKI (as described in Section 4): Creates signed ROAs that allow routers
     to reject invalid route announcements. If our ROA says "only AS64496 can
     announce 198.51.100.0/24 with max prefix /24", a /25 announcement from
     AS99999 would be RPKI-INVALID and rejected by validating routers.

  2. BGP monitoring: Services like BGPmon, RIPE Stat, Cloudflare Radar
     continuously monitor route announcements for our prefixes.
     Alert if unexpected AS announces our prefix.
     Response time: 5-15 minutes from hijack to alert.

  3. Transit provider prefix filters: Our transit providers should only accept
     prefixes we have pre-authorized. If we tell AS64497 "only accept 198.51.100.0/24
     from us", they will reject any /25 announcements even from their own customers.

  4. Max-prefix configuration: Limit how many routes we accept from each peer.
     Prevents a peer from flooding our BGP table with routes (which could cause
     memory exhaustion on our routers — a routing table DDoS).
```

---

### Attack 4: SSL/TLS Exhaustion Attack

```
PROBLEM: TLS handshake is asymmetrically expensive.
  Server must compute: RSA decryption or ECDH key exchange
  These are computationally expensive operations.

  TLS 1.2 RSA handshake:
    Client CPU cost: 1 RSA encrypt (cheap)
    Server CPU cost: 1 RSA decrypt (10-100x more expensive than encrypt)

ATTACK:
  Attacker sends many TLS ClientHello messages:
    - Each initiates a TLS handshake
    - Server must compute RSA/ECDH for each
    - Server CPU exhausted processing handshakes
    - Legitimate TLS connections queued or dropped

  At 10,000 TLS ClientHellos/second:
    Each RSA-2048 decryption: ~0.5ms on modern CPU
    10,000 × 0.5ms = 5,000ms = 5 CPU-core-seconds per second
    A server with 4 cores: saturated at 8,000 handshakes/second

  The attack requires completing the ClientHello (TCP handshake required)
  so IP spoofing doesn't work. But the attacker can use a botnet
  with real source IPs.

DEFENSES:
  Session resumption:
    TLS session tickets or session IDs allow reconnecting clients to
    skip the expensive key exchange.
    Returning legitimate clients: cheap reconnection.
    Attacker: must always do full handshake (but can cache sessions too).

  Prefer ECDHE over RSA:
    ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) key exchange:
    More efficient than RSA for same security level.
    Server CPU: 3-5x less expensive than RSA-2048.

  SSL offload hardware:
    Dedicated SSL acceleration cards (Cavium Nitrox, Intel QAT)
    Handle 100,000+ TLS handshakes/second in hardware.

  Rate limiting at TCP level:
    Limit new TCP connections per source IP: 10/second
    Effective because TLS exhaustion requires real TCP connections.

  Rate limiting at TLS level:
    Track ClientHellos per IP per minute.
    After N ClientHellos without completing a session: block.
```

---

## 6. Security Controls & Defensive Mechanics

### Multi-Layer Defense Architecture

```
LAYER-BY-LAYER DEFENSES:

LAYER 1: UPSTREAM (Before traffic reaches us)
  BGP blackhole (RTBH):
    Announce prefix with blackhole community to upstream providers.
    They DROP traffic to us at their routers.
    Effect: Attack traffic never reaches our network.
    Tradeoff: ALL traffic dropped (legitimate and attack) = full outage for the prefix.
    Use for: Extreme volumetric attacks exceeding our scrubbing capacity.

  RPKI route origin validation:
    Prevents prefix hijacking (Section 4).
    Requires ROAs for all our prefixes.
    Coordinate with transit providers to enable RPKI validation.

  BCP38 coordination:
    Work with upstream transit providers to filter spoofed source IPs.
    Cannot directly force third-party ISPs to implement BCP38.
    But can choose transit providers who implement it.

LAYER 2: EDGE (Anycast PoPs)
  Hardware ACLs:
    Drop bogon source IPs (RFC1918, RFC5737, RFC6598 ranges)
    Drop known attack amplification vectors:
      UDP/53 (DNS) from internet: block completely if we're not a resolver
      UDP/123 (NTP): block unless we run NTP servers
      UDP/1900 (SSDP): block completely
      UDP/11211 (Memcached): block completely
    Apply URPF (Unicast Reverse Path Forwarding):
      Drop packets where the source IP is not reachable via the ingress interface.
      Prevents some spoofing even without full BCP38.

  Rate limiting in hardware:
    Per-source-IP packet rate limit
    Per-prefix aggregate rate limit
    Applied in ASIC/TCAM — no CPU involved

LAYER 3: SCRUBBING CENTER
  Stateless filtering:
    IP reputation (blocklist lookup in hash table)
    Protocol validation
    Packet rate per source IP
    Aggregate rate per destination IP (our server)

  Stateful filtering:
    SYN cookies for TCP
    DNS transaction tracking (request must precede response)
    HTTP basic inspection

  GRE/IPIP tunnel back to origin:
    Only validated clean traffic exits scrubbing center.

LAYER 4: WAF / APPLICATION LAYER
  Rate limiting (per IP, per session, per endpoint)
  Behavioral analysis (request patterns, session behavior)
  CAPTCHA/JS challenge for suspected bots
  Allowlist for known-good IPs (reduce false positives for legitimate traffic)

LAYER 5: ORIGIN
  Connection limits per IP
  Request timeout enforcement (defense against Slowloris)
  Application-level rate limiting (last resort)
  Health checks (drop connections if server is overwhelmed)
```

### Challenge-Response: JS Challenge and CAPTCHA

```
JS CHALLENGE (Lightweight, transparent for most users):
  How it works:
    WAF responds to HTTP request with a JavaScript challenge page instead of content.
    JavaScript must compute a proof-of-work (simple hash puzzle) and resubmit.
    Legitimate browsers: complete the challenge transparently (~100ms).
    Basic bots (curl, wget, simple scripts): fail (cannot execute JavaScript).

  Challenge details:
    Server generates: challenge_string = random_nonce + expiry_timestamp
    Client must compute: SHA256(challenge_string + counter) where result starts with "0000"
    Submit: response = POST to challenge endpoint with (nonce, counter)
    Server validates: recompute hash, verify result, issue cookie

  Cookie:
    On success: server issues clearance cookie (HMAC-signed, 24h TTL)
    Subsequent requests: cookie validates, no challenge
    WAF verifies cookie signature on each request (no state needed — cookie is self-contained)

CAPTCHA (Stronger, visible to users):
  When: Persistent suspicious behavior after JS challenge
  Provider: Google reCAPTCHA v3 (invisible), v2 (checkbox), or alternative
  After CAPTCHA: same clearance cookie mechanism

TRADEOFF:
  JS challenge: transparent, low friction, does not block JS-capable bots
  CAPTCHA: high friction, annoys users, required for determined attackers
  Neither stops attacks from legitimate browsers under attacker control
  (browser-based botnets can pass both challenges)
```

---

## 7. Attack Surface Mapping

### All Entry Points

```
EXTERNAL ATTACK SURFACE:
══════════════════════════════════════════════════════════════════════

[E1] Anycast IP addresses (public)
  Our announced prefixes: 198.51.100.0/24, 203.0.113.0/24
  Any internet host can send any packet to these IPs
  Defense: Edge ACLs, scrubbing, WAF

[E2] BGP sessions with transit providers and peers
  Each BGP session is an attack vector:
    - BGP UPDATE flood (exhaust router memory with routes)
    - BGP session reset (TCP RST injection)
    - BGP route injection (if peer not properly filtered)
  Defense: BGP session auth (MD5 or TCP-AO), max-prefix limits,
           prefix filters, RPKI validation

[E3] Management interfaces of network devices
  SSH management port (should be out-of-band only)
  SNMP (if enabled — should be read-only from monitoring systems only)
  NETCONF/RESTCONF (configuration APIs)
  Defense: Restrict to management network, MFA, no internet exposure

[E4] Scrubbing center management API
  API for creating/deleting mitigation profiles
  Defense: mTLS, RBAC, rate limiting, audit logging

[E5] WAF management API
  API for creating/deleting WAF rules
  Defense: mTLS, RBAC, change approval workflow

[E6] DNS (authoritative servers for our domains)
  If DNS is taken down: no traffic reaches us even if infrastructure is up
  Attack: DNS amplification using us as the reflector
          Direct DDoS against our authoritative DNS servers
  Defense: Anycast DNS, rate limit DNS response rate per IP

[E7] Origin infrastructure (should be hidden)
  If origin IPs are discovered: attacker bypasses all scrubbing
  Defense: Origin IP should not be discoverable
           Never serve from origin IPs directly
           Firewall origin: only accept from scrubbing center IPs
           Historical DNS records: check SecurityTrails for origin IP leaks

INTERNAL ATTACK SURFACE:
══════════════════════════════════════════════════════════════════════

[I1] Control plane API
  If compromised: attacker can disable mitigation, change BGP routes
  Defense: MFA, RBAC, immutable audit trail, change approval for BGP routes

[I2] BGP route controller
  If compromised: attacker can announce arbitrary routes
  Defense: mTLS, network segmentation, approval workflow for route changes

[I3] Threat intelligence feed consumers
  Automated systems that update blocklists
  If compromised: attacker can add legitimate IPs to blocklist (DDoS by proxy)
  Defense: Blocklist validation (cannot block /8 or RFC1918), rate limit
           maximum size of any single update, human approval for large updates

[I4] Monitoring and alerting systems
  If attackers can see alert thresholds: they can craft attacks that stay just below
  Defense: Limit read access to internal thresholds, use randomized thresholds

[I5] Configuration management (Terraform, Ansible, etc.)
  If compromised: attacker can change any infrastructure configuration
  Defense: Git signing, PR approval workflow, audit trail, MFA for operators
```

### Attack Surface Diagram

```
DDOS MITIGATION SYSTEM — ATTACK SURFACE MAP
═══════════════════════════════════════════════════════════════════════════════

INTERNET (Untrusted — Zero Trust)
      │
      │ Any IP, any protocol
      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  TRANSIT PROVIDER NETWORK [TB-1]                                           │
│  BGP routes from us: validated by max-prefix, prefix filters, RPKI         │
│  BGP sessions: MD5 authenticated, max-prefix configured                    │
│  [E2] BGP session attack surface                                           │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │ BGP-selected path to our prefix
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  EDGE PoP LAYER [TB-2]                                                     │
│  [E1] Anycast IP: 198.51.100.0/24 — ALL internet traffic arrives here     │
│  [E3] Management interface: SEPARATE management network, not data path     │
│  Hardware ACLs: Drop bogons, block amplification protocols                 │
│  NetFlow export → traffic analysis (control plane, out-of-band)            │
└──────────┬────────────────────────────────────────────┬───────────────────┘
           │ Normal traffic                             │ Attack traffic (BGP divert)
           │                                            ▼
           │                             ┌──────────────────────────────────────┐
           │                             │  SCRUBBING CENTER [TB-3]             │
           │                             │  [E4] Scrubbing API                  │
           │                             │  DPDK processing, no kernel path     │
           │                             │  IP reputation, rate limiting, SYN   │
           │                             │  cookies, protocol validation         │
           │                             │  GRE tunnel for clean egress         │
           │                             └──────────────┬───────────────────────┘
           │ (or scrubbed clean traffic)                │ GRE tunnel
           ▼                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  WAF / RATE LIMITING LAYER [TB-4]                                          │
│  [E5] WAF management API                                                   │
│  TLS termination (origin IP hidden from external clients)                  │
│  HTTP inspection, rate limiting, behavioral analysis, challenges            │
│  [E6] DNS: anycast DNS for our domains (separate from this data path)      │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │ Clean, validated HTTP only
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  ORIGIN INFRASTRUCTURE [TB-5]                                              │
│  [E7] Origin IPs must be SECRET (firewall: only accept from WAF/scrubbing) │
│  Load balancers → App servers → Databases                                  │
│  Last-resort rate limiting, connection limits, health checks               │
└─────────────────────────────────────────────────────────────────────────────┘

CONTROL PLANE (Out-of-band, separate network)
┌─────────────────────────────────────────────────────────────────────────────┐
│  [I1] Management API    [I2] BGP Route Controller                          │
│  [I3] Threat Intel Feeds [I4] Monitoring/Alerting                          │
│  [I5] Config Management (Terraform/Ansible)                                │
│  All protected by: MFA, RBAC, mTLS, immutable audit logs                  │
└─────────────────────────────────────────────────────────────────────────────┘

TRUST BOUNDARIES:
  [TB-1] Internet → Transit: BGP auth, prefix filters, RPKI
  [TB-2] Transit → Edge: Hardware ACLs, bogon filtering
  [TB-3] Edge → Scrubbing: Layer 3/4 scrubbing, SYN cookies
  [TB-4] Scrubbing → WAF: GRE tunnel, Layer 7 inspection
  [TB-5] WAF → Origin: Firewall allows only WAF/scrubber IPs, mTLS
```

---

## 8. Failure Modes & Edge Cases

### Failure 1: Scrubbing Center Capacity Exhaustion

```
SCENARIO: Attack exceeds scrubbing center capacity.

Production capacity: 2 Tbps scrubbing capacity (large deployment)
Attack size: 3 Tbps (Memcached UDP amplification, amplification factor 50,000x)

What happens:
  Scrubbing center receives 3 Tbps of UDP packets
  DPDK can process: 2 Tbps → 1 Tbps passes through scrubbing unclean
  This 1 Tbps of unscrubbbed traffic hits the WAF layer
  WAF: 100 Gbps capacity → overloaded
  Origin: unreachable

FAILURE CHAIN:
  Scrubbing center: 33% overload → passes some attack traffic
  WAF: 10x overloaded → crashes or drops all traffic (legitimate and attack)
  Origin: unreachable regardless

MITIGATIONS FOR CAPACITY EXHAUSTION:
  1. RTBH upstream: Activate blackhole at transit provider level
     Effect: Transit provider drops ALL traffic to attacked IP
     Service impact: Complete outage for attacked IP
     But: Rest of our infrastructure unaffected
     Recovery: 5-10 minutes to switch to backup IP/domain

  2. Geoblocking: If attack is from identifiable geographic regions
     Drop all traffic from attack-source countries at the edge
     Tradeoff: Legitimate users from those countries also blocked

  3. Protocol-specific block: If attack is pure UDP
     Block ALL UDP to attacked IP (if legitimate UDP is not required)
     Allows TCP to continue functioning

  4. Scale up scrubbing: Add more scrubbing nodes
     Time: 5-15 minutes for cloud-based elastic scrubbing
     Not fast enough for immediate relief

RECOVERY:
  Activate RTBH → announce alternate IP → update DNS TTL to 30s
  → redirect legitimate traffic to backup IP
  → once attack subsides, restore original IP routing
```

### Failure 2: False Positive Blocking (Legitimate Traffic Blocked)

```
SCENARIO: WAF rule or IP blocklist incorrectly blocks legitimate users.

HIGH FALSE POSITIVE SCENARIOS:
  1. Shared IP/NAT: 10,000 legitimate users share one corporate NAT IP.
     Rate limit: 100 requests/minute per IP → blocks entire corporation after
     first employee triggers limit.
     
  2. CDN origin pull: Our WAF is misconfigured as origin for another CDN.
     The CDN uses a small set of IPs for all its origin pulls.
     Our WAF rate limits and blocks these IPs → all CDN customers blocked.
     
  3. Search engine crawler: Googlebot crawls aggressively from Google's IPs.
     Rate limiting blocks Googlebot → our site stops being indexed.
     
  4. Threat intel false positive: A threat feed marks a Cloudflare IP as "malicious".
     All traffic through Cloudflare (millions of legitimate users) is blocked.
     
  5. Emergency IP block: SOC analyst adds /24 to blocklist targeting attacker
     but that /24 includes a legitimate partner's IP range.

DETECTION OF FALSE POSITIVES:
  - Spike in blocked request count without corresponding attack detection
  - Customer support tickets: "We can't access your service"
  - Monitoring: Significant drop in legitimate traffic (revenue metric)
  - Alert: Top blocked IPs include known CDN ranges (Cloudflare, Akamai, Fastly)

MITIGATION:
  Allowlist for known-good IPs:
    Googlebot ranges: 66.249.64.0/19 and others (published by Google)
    Monitoring services: UptimeRobot, Pingdom
    Our own monitoring IPs
    Known partner IPs
    
  Block scope limits:
    SOC analysts can block individual IPs or /24 maximum
    Blocking /16 or larger requires approval workflow
    Cannot block RFC1918 ranges (would break internal traffic)
    
  Emergency unblock procedure:
    Any blocked IP can be immediately allowlisted by on-call engineer
    Allowlist overrides all blocking rules
    Allowlist entries: 1-hour TTL by default (must be renewed for longer)
```

### Failure 3: Split-Brain BGP Routing

```
SCENARIO: Network partition causes BGP routes to be inconsistent.

SETUP:
  Our BGP route controller manages route announcements across 3 regions.
  Management network between regions uses a dedicated path.
  Data center interconnect (DCI) fails: Tokyo ↔ London link goes down.

WHAT HAPPENS:
  Tokyo PoP: Still announces 198.51.100.0/24 normally
  London PoP: Loses connection to BGP route controller
              BGP daemon continues with last-known routes (correct behavior)
              But: Cannot receive new mitigation commands from control plane

  Attack begins, targeting Tokyo PoP.
  Control plane activates mitigation:
    → Tokyo PoP: receives command, diverts traffic to scrubbing center ✓
    → London PoP: does NOT receive command (partition) — keeps announcing normally ✗

  Internet routers route some traffic to London PoP (normal announcement wins
  for traffic whose shortest path is through London).
  London PoP: forwards attack traffic directly to origin (no scrubbing) ✗
  Origin: receives unmitigated attack traffic from London path ✗

  Tokyo path: scrubbed ✓
  London path: unprotected ✗
  Attack still succeeds through London path.

RECOVERY APPROACHES:
  1. Local autonomous mitigation:
     Each PoP runs local anomaly detection independently.
     If edge router sees >N Gbps on a single destination IP → apply local mitigations
     autonomously without waiting for central control plane.
     This provides partial protection even during partition.

  2. BGP route dampening:
     If London PoP cannot reach control plane for > 60 seconds:
     London PoP withdraws its route announcements (fail closed)
     Traffic no longer routes to London → Tokyo handles all (scrubbed correctly)
     Tradeoff: London users experience increased latency (re-routed to Tokyo)

  3. Distributed control plane:
     Use etcd or Consul cluster spanning regions.
     BGP route controller reads from local etcd node.
     etcd maintains consensus across nodes: quorum-based.
     If 2 of 3 regions can communicate: mitigation commands still propagate.
     Only fails if 2 of 3 regions are partitioned simultaneously.
```

### Failure 4: Cascading Failure — Mitigation System DDoSed

```
SCENARIO: Attacker targets the DDoS mitigation system itself.

ATTACK: DNS DDoS against our management DNS servers
  Our mitigation control plane uses internal DNS for service discovery.
  Management network DNS server DDoSed.
  Service discovery fails → mitigation orchestrator cannot reach scrubbing APIs.
  Mitigation orchestrator cannot activate new mitigations.

SIMULTANEOUSLY: Application-layer DDoS begins against origin.

FAILURE CHAIN:
  Management DNS overwhelmed → service discovery fails
  → mitigation orchestrator cannot activate new profiles
  → application DDoS is not mitigated
  → origin overloaded

DEFENSES AGAINST META-ATTACKS:
  1. DNS-independent service discovery:
     Hardcode IP addresses for critical management endpoints (bypass DNS)
     Or: Consul for service discovery on management network (does not use external DNS)

  2. Out-of-band management:
     Management network completely separate from data plane network.
     DDoS against data plane IPs cannot reach management IPs.
     Management IPs are never advertised publicly (RFC1918 or separate ASN).

  3. Pre-configured static mitigations:
     If orchestrator is unreachable: edge devices and scrubbers operate
     on last-applied configuration.
     Static mitigation profiles: "if traffic to X IP > Y Gbps, apply Z mitigation"
     configured locally on each device, activates without control plane.

  4. Out-of-band communication:
     If management network fails: engineers access devices via OOB console.
     Console servers: cellular/POTS backup connections.
     Manual BGP commands can be executed directly on routers.
```

---

## 9. Mitigations & Observability

### Infrastructure as Code — Concrete Rules

```hcl
# Terraform: BGP blackhole community configuration
# Applied to all transit provider BGP sessions

resource "router_bgp_policy" "blackhole_community" {
  name = "ddos-blackhole"
  
  # Accept blackhole community from our automation system
  match {
    community = "64496:666"
  }
  
  action {
    set_local_preference = 200   # High preference = used preferentially
    set_community        = "65535:666"  # RFC 7999 BLACKHOLE community
    # 65535:666 is a well-known community that major ISPs honor
  }
}

resource "router_prefix_filter" "origin_prefix_filter" {
  name = "our-prefixes-outbound"
  
  # Only announce our own prefixes — never transit routes
  permit {
    prefix = "198.51.100.0/24"
    le     = 24   # No more specific than /24 (prevents /25 accidents)
  }
  
  permit {
    prefix = "203.0.113.0/24"
    le     = 24
  }
  
  # Implicit deny all — nothing else gets announced
}

resource "router_bgp_peer" "transit_provider_a" {
  neighbor  = "192.0.2.1"
  remote_as = 64497
  
  # BGP session authentication
  password = var.bgp_session_password   # From secrets manager, not hardcoded
  
  # Protect against route table flooding
  max_prefix {
    limit  = 1000000    # Alert if peer sends > 1M routes
    teardown = true     # Drop session if limit exceeded
  }
  
  # Apply filters
  import_filter = router_prefix_filter.transit_filter.name
  export_filter = router_prefix_filter.origin_prefix_filter.name
}
```

```nginx
# Nginx: Rate limiting and DDoS protection configuration

# Define rate limit zones (stored in shared memory — works across workers)
limit_req_zone $binary_remote_addr zone=per_ip:10m rate=100r/m;
limit_req_zone $binary_remote_addr zone=login_limit:1m rate=10r/m;
limit_req_zone $http_x_api_key zone=per_api_key:10m rate=1000r/m;

# Define connection limits
limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;

server {
    listen 443 ssl;
    
    # TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;  # TLS 1.3 handles this
    
    # Session resumption (reduces TLS exhaustion attack surface)
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;  # Use session cache, not tickets (better revocation)
    
    # Slowloris defense
    client_header_timeout 5s;    # 5 seconds to receive complete headers
    client_body_timeout 10s;     # 10 seconds for request body
    send_timeout 10s;            # 10 seconds between writes to client
    keepalive_timeout 65s;       # HTTP keepalive
    
    # Connection limits
    limit_conn conn_per_ip 20;   # Max 20 simultaneous connections per IP
    
    # General rate limiting
    limit_req zone=per_ip burst=50 nodelay;
    
    # Login endpoint: much stricter
    location /api/v1/auth/login {
        limit_req zone=login_limit burst=5 nodelay;
        proxy_pass http://backend;
    }
    
    # Block common attack user agents
    if ($http_user_agent ~* "(nikto|masscan|sqlmap|nmap|dirbuster|go-http)") {
        return 403;
    }
    
    # Block empty user agents (most bots skip UA)
    if ($http_user_agent = "") {
        return 403;
    }
}
```

### Key Metrics to Monitor

```
NETWORK LAYER METRICS:
  inbound_bps_per_pop           → Alert: > 80% of link capacity for > 30s
  inbound_pps_per_pop           → Alert: > 50M pps (packet flood indicator)
  unique_source_ips_per_minute  → Alert: > 10x normal (botnet indicator)
  protocol_distribution         → Alert: UDP > 60% of traffic (reflection indicator)
  bgp_route_change_rate         → Alert: > 100 route changes/minute (instability)
  bgp_session_state             → Alert: any peer in IDLE state

SCRUBBING CENTER METRICS:
  traffic_in_bps                → Volume of traffic arriving
  traffic_out_bps               → Volume of clean traffic forwarded
  scrub_ratio                   → (in - out) / in — what fraction is being dropped
  blocked_ips_count             → Size of active blocklist
  syn_cookie_challenges_per_sec → High = SYN flood in progress
  scrubber_cpu_utilization      → Alert: > 80% (capacity concern)

WAF METRICS:
  requests_per_second           → Alert: > 5x normal sustained
  blocked_requests_rate         → Alert: > 20% of traffic blocked (FP risk)
  rate_limited_ips_count        → How many IPs are currently rate limited
  challenge_issued_per_second   → JS challenge / CAPTCHA issuance rate
  tls_handshakes_per_second     → Alert: > 80% of TLS termination capacity

ORIGIN METRICS:
  connection_count              → Alert: > 80% of max_connections
  response_time_p99             → Alert: > 2x normal (server stress)
  error_rate_5xx               → Alert: > 1% (server overwhelmed)
  queue_depth                   → Alert: > 1000 queued requests

BUSINESS METRICS (most important — what users experience):
  legitimate_request_success_rate → Alert: < 99% (users being blocked)
  revenue_per_minute              → Significant drop = effective DDoS
  customer_support_tickets        → Spike in "can't access service" tickets
```

### Logging and Audit Trail

```python
# What to log at each layer

# EDGE PoP (network device):
# - BGP route changes (announce/withdraw)
# - ACL rule matches (sampled — 1:10000 for matched, 1:100 for dropped)
# - Interface utilization (SNMP polling every 30s)
# - NetFlow records (1:1000 sampling) for all traffic

# Format: syslog to central log aggregator (Kafka → Elasticsearch)
{
  "timestamp": "2024-11-15T02:14:22.331Z",
  "device": "tokyo-edge-01",
  "event_type": "bgp_route_change",
  "prefix": "198.51.100.0/24",
  "action": "WITHDRAW",
  "peer": "192.0.2.1",
  "reason": "mitigation_redirect",
  "triggered_by": "mitigation_orchestrator"
}

# SCRUBBING CENTER:
# - Every DROP decision (sampled 1:100 during high volume to avoid log flood)
# - Mitigation profile activations/deactivations
# - Capacity utilization
{
  "timestamp": "2024-11-15T02:14:22.351Z",
  "device": "scrubber-tokyo-01",
  "event_type": "packet_drop",
  "src_ip": "45.33.12.87",     # DO NOT log for privacy where not needed
  "drop_reason": "ip_reputation_blocklist",
  "blocklist_source": "threatintel_feed_x",
  "packets_dropped_rate": 1000000  # Aggregated count, not per-packet
}

# WAF:
# - Every block decision
# - Every challenge issued and result
# - Rate limit triggers
# - Configuration changes
{
  "timestamp": "2024-11-15T02:14:22.400Z",
  "layer": "waf",
  "event_type": "request_blocked",
  "client_ip": "45.33.12.87",
  "rule_triggered": "rate_limit_per_ip",
  "request_count_1min": 487,
  "limit": 100,
  "endpoint": "/api/v1/products",
  "user_agent": "python-requests/2.28.0"
}

# CONTROL PLANE (most critical — audit all changes):
{
  "timestamp": "2024-11-15T02:14:21.100Z",
  "actor": "mitigation_orchestrator",
  "actor_ip": "10.0.1.50",
  "action": "activate_mitigation_profile",
  "target_ip": "198.51.100.1",
  "profile": "udp_flood_defense",
  "trigger": "automated_traffic_analysis",
  "trigger_reason": "inbound_pps_exceeded_10M",
  "approval_required": false,
  "result": "success"
}
```

---

## 10. Interview Questions

### Q1: "Explain BGP anycast. How does it help with DDoS mitigation and what are its limitations?"

**Answer:**

BGP anycast means announcing the same IP address (or prefix) from multiple geographic locations simultaneously. The BGP routing protocol, which all internet routers use to exchange routing information, selects the "best" path based on criteria like AS path length. When the same /24 is announced from Tokyo, London, and New York, traffic from a Tokyo-based user follows the shortest AS-path and reaches the Tokyo PoP. Traffic from a London user reaches the London PoP.

**How it helps with DDoS:**

First, it absorbs volumetric attacks by spreading them across all PoPs. A 1 Tbps attack against an anycast network with 50 PoPs might only be 20 Gbps at each PoP — manageable. Second, the more-specific route mechanism (announcing a /32 from a scrubbing center) allows traffic for a specific attacked IP to be diverted to the scrubbing center without affecting traffic to other IPs in the same /24.

Third, anycast provides natural filtering: if one PoP is overwhelmed, BGP can temporarily withdraw that PoP's announcement, routing its users to the next-nearest PoP while the overwhelmed PoP recovers.

**Limitations:**

Anycast doesn't help against application-layer (Layer 7) attacks. A 1 Gbps HTTP flood spread across 50 PoPs is 20 Mbps at each PoP — the traffic volume isn't the problem, the request processing cost is. Each HTTP request still hits the WAF and origin backend.

TCP stateful connections interact oddly with anycast. A TCP connection from one user must consistently reach the same PoP — if BGP routing changes mid-connection (because a PoP went down), the TCP connection breaks. This is typically handled by ensuring routing is stable enough that TCP connections complete before any route changes, but it means anycast is less suitable for long-lived TCP sessions.

Finally, anycast doesn't protect against attacks on the origin infrastructure directly, if the origin IP is ever disclosed.

**What-if:** "What if an attacker uses anycast themselves?" An attacker could technically use anycast to run their botnet infrastructure from multiple locations, but this doesn't change the fundamental attack vs. defense dynamic — they still need to route packets to the victim's IP.

---

### Q2: "What is a SYN flood and how do SYN cookies work at the packet level?"

**Answer:**

**The SYN flood:**

TCP requires a 3-way handshake (SYN → SYN-ACK → ACK) before data transfer. The server must maintain state between receiving the SYN and receiving the ACK — this is the "half-open connection" stored in the SYN backlog queue. On Linux, this defaults to 128-512 entries.

An attacker sends millions of SYN packets with spoofed source IPs. The server sends SYN-ACK responses into the void (spoofed source IPs don't exist or belong to innocent third parties). The ACK never arrives. The half-open entries sit in the queue until timeout (75 seconds by default on Linux). With enough SYN packets per second, the queue fills permanently and legitimate SYN packets are silently dropped.

**SYN cookies — the packet-level mechanics:**

SYN cookies allow the server to encode all necessary connection state into the TCP sequence number in the SYN-ACK response, so NO state needs to be stored on the server until the ACK arrives.

The sequence number in a SYN-ACK is 32 bits. The SYN cookie formula:
```
sequence_number = SHA1(src_ip, src_port, dst_ip, dst_port, server_secret, timestamp_lower_bits)
                  truncated to 32 bits
```

When a legitimate client receives this SYN-ACK, it sends ACK with `ack_number = sequence_number + 1` (standard TCP). The server:
1. Receives the ACK
2. Computes what the sequence number should have been (using the same formula)
3. If `ack_number - 1 == expected_sequence_number`: legitimate connection, allocate state
4. If not: SYN was spoofed (no corresponding ACK from a real client), do nothing

**Why spoofed SYNs cannot exploit this:**

A spoofed SYN from IP 1.2.3.4 causes the server to send SYN-ACK to 1.2.3.4. The real machine at 1.2.3.4 (which never sent the SYN) receives an unexpected SYN-ACK and sends a RST (TCP reset) — which the server ignores because there's no state for it. The attacker, who cannot see the SYN-ACK (it went to the spoofed IP), cannot compute the correct ACK value to complete the handshake.

**Tradeoffs:** SYN cookies cannot carry TCP options (window scaling, SACK, timestamps) in the 32-bit sequence number. Modern Linux works around this by encoding some options in the timestamp bits. Performance impact on legitimate connections is negligible (< 1ms overhead). The server secret must be rotated periodically (Linux rotates every 10 minutes) and must not be guessable — otherwise an attacker who knows the secret can precompute valid cookies.

---

### Q3: "Explain DNS amplification attacks. How does BCP38 fix this and why isn't it universally deployed?"

**Answer:**

**DNS amplification mechanics:**

DNS amplification exploits two facts: (1) UDP allows source IP spoofing because it's connectionless (no 3-way handshake to verify source IP), and (2) some DNS responses are much larger than the queries that triggered them.

The attacker sends small UDP DNS queries to open resolvers (public DNS servers that answer queries from anyone), with the victim's IP as the spoofed source. Each resolver sends a large DNS response to the victim. With a 50x amplification factor, the attacker needs only 10 Gbps of outbound capacity to generate 500 Gbps of inbound traffic at the victim.

The "ANY" record type was particularly abused because it returns all DNS records for a domain — potentially kilobytes of data. RFC 8482 now recommends resolvers return minimal responses to ANY queries specifically to mitigate this.

**How BCP38 prevents this:**

BCP38 (RFC 2827, "Network Ingress Filtering") requires ISPs to validate that packets leaving their network have source IPs within the address ranges they've assigned to their customers. If a customer at `ISP_A` tries to send a packet with source IP `203.0.113.5` (which belongs to the victim and is not assigned to this customer), `ISP_A` drops the packet at egress.

This means the attacker's spoofed DNS queries never reach the resolver. Without spoofed source IPs, the resolver sends the large DNS response back to the attacker — who is rate-limited by their own connection. The attack collapses to a simple bandwidth race rather than an amplification attack.

**Why BCP38 isn't universally deployed:**

First, it costs money. ISPs must update router configurations and continuously maintain prefix lists of what each customer is allowed to source. This is operationally expensive.

Second, there's a free-rider problem. An ISP that implements BCP38 gets no direct benefit — their own traffic isn't spoofed. The benefit accrues to victims elsewhere on the internet. There is no financial incentive for an ISP to incur the operational cost of BCP38 when their competitors don't.

Third, some legitimate use cases require spoofed source IPs: anycast services (where the response must go to a different IP than the requester), ECMP load balancing, and some VPN configurations. ISPs are worried about breaking customers.

Fourth, enforcement is essentially impossible. No internet governance body can compel ISPs in all jurisdictions to implement it. Current adoption is approximately 40% of global internet traffic by volume, meaning ~60% of internet traffic could originate from networks that allow spoofing.

---

### Q4: "How does traffic diversion to a scrubbing center work with BGP? What happens to the 'clean' traffic after scrubbing?"

**Answer:**

**Diversion mechanics:**

The key insight is BGP's longest-prefix-match rule: a /32 (single IP) route is always preferred over a /24 (256 IPs) route because it's more specific, regardless of which one has a shorter AS path.

Normally, all our PoPs announce `198.51.100.0/24`. When we want to divert traffic for `198.51.100.1` to the scrubbing center:

The scrubbing center announces `198.51.100.1/32` to its transit providers and peers. Every internet router that receives both the `/24` from our PoPs and the `/32` from the scrubbing center will prefer the `/32` for packets destined to `198.51.100.1`. Traffic for all other IPs in the /24 continues normally to our PoPs.

The diversion can be triggered via BGP communities — the scrubbing center sends a community tag in its route announcement that tells our transit providers to prefer the scrubbing center's more-specific route. The control plane API propagates this BGP update in seconds.

**Return path — the GRE tunnel:**

After scrubbing, clean traffic must reach the origin. But if we simply route it normally, it might re-enter the scrubbing center (because the /32 route still exists). The solution is a GRE (Generic Routing Encapsulation) tunnel:

The scrubbing center has a GRE tunnel endpoint configured to the origin's IP. Clean packets are encapsulated: the original packet (destined for `198.51.100.1`) is wrapped in a new IP header with source = scrubbing center IP and destination = origin IP. The tunnel carries this packet directly to the origin.

At the origin, GRE is decapsulated: the inner packet (the original client request) is delivered to the application. The application sees the client's real source IP (preserved in the inner packet).

**Why the return path doesn't need to be tunneled:**

Response traffic from origin to client (`198.51.100.1:443` → `client_ip:port`) follows normal BGP routing. The response source IP is `198.51.100.1`, which is still advertised via the /24 from our PoPs. The response exits through a normal PoP, not the scrubbing center. This is called asymmetric routing — inbound goes through the scrubbing center, outbound does not — and it's completely normal in this architecture.

---

### Q5: "What is the difference between volumetric, protocol, and application layer DDoS? Why does defending against each require fundamentally different approaches?"

**Answer:**

**Volumetric attacks (Layer 3/4):**

The attack is volume itself — filling the network pipe with traffic. 500 Gbps of UDP packets cannot be "inspected away" — you must have 500 Gbps of capacity to absorb them. The defense requires scale: anycast to distribute volume, upstream filtering (RTBH), scrubbing centers with massive throughput. None of this requires understanding HTTP — the defense operates on IP/UDP headers only.

Cost of defense: expensive (you need more capacity than the attack). This is why CDNs and DDoS mitigation providers have massive investments in network capacity.

**Protocol attacks (Layer 4 stateful):**

These attacks don't fill the pipe but exhaust stateful resources: TCP connection tables, firewall state tables, TLS session tables. A SYN flood might be only 1 Gbps but exhaust a firewall with a 512-entry connection table. The defense is to avoid maintaining state unnecessarily — SYN cookies make the server stateless until a real ACK arrives. Stateless ACL rules (match on fixed header fields) can run at line rate; stateful inspection cannot.

The fundamental issue is that stateful systems have finite state capacity. The defense is to push state management to the client (as SYN cookies do) or to make the stateful resources more expensive for the attacker to exhaust than for legitimate users to consume.

**Application layer attacks (Layer 7):**

These attacks look like legitimate traffic at the IP and TCP level. A valid HTTP GET request to `/api/search?q=*` looks identical whether it comes from a real user or a bot. The distinction requires understanding HTTP semantics, session behavior, request patterns, and business context.

Rate limiting by IP is insufficient (botnets have many IPs). You need behavioral analysis (this IP's requests look like scraping), business logic understanding (this endpoint is expensive — limit it more aggressively), and challenge-response (only browsers can pass JS challenges). The defense requires application-layer context that is invisible at Layers 3 and 4.

**Why they require fundamentally different defenses:**

- Volumetric: Solution is capacity and scope reduction (RTBH, geo-blocking)
- Protocol: Solution is statelessness and resource accounting at the protocol level
- Application: Solution is behavioral analysis and application-context-aware filtering

A scrubbing center that absorbs volumetric attacks is useless against Slowloris. A WAF that defends against Slowloris cannot absorb 1 Tbps floods. Defense-in-depth requires all three layers operating simultaneously.

---

### Q6: "How would you defend against an attack that specifically targets your DDoS mitigation infrastructure?"

**Answer:**

This is the "meta-attack" problem — the attack targets the defender rather than the defended service.

**Attack surfaces of the mitigation infrastructure:**

The control plane API (for activating mitigations), the BGP route controller, the scrubbing center management interface, the DNS used for service discovery in the control plane, and the threat intelligence feed infrastructure.

**Defense principles:**

First, the data plane must be autonomous. If the control plane is unreachable, the data plane must continue operating on its last-applied configuration. Routers and scrubbers should not shut down or degrade when they lose contact with the control plane — they operate on local state indefinitely.

Second, the control plane must be out-of-band. Management traffic uses a completely separate network (physically separate cables, separate switches, separate ASN if needed). An attack against our public-facing IP ranges cannot reach management IPs if management uses private RFC1918 space on dedicated infrastructure.

Third, the control plane itself needs its own DDoS protection. The management API is rate limited, requires authentication, and is not publicly accessible. If it is internet-exposed (for remote management), it sits behind its own layer of mitigation.

Fourth, local autonomous mitigation. Each edge PoP and scrubber runs local threshold-based mitigation without requiring central coordination. If traffic to an IP exceeds N Gbps locally, apply a local mitigation profile automatically, regardless of whether the central controller is reachable. This is the equivalent of a "break glass" procedure that runs automatically.

Fifth, diversity. Use different software stacks for different layers. If the control plane uses system A and the data plane uses system B, a vulnerability in A cannot be used to shut down B. Similarly, use multiple scrubbing providers — if one provider's infrastructure is targeted, traffic migrates to the other.

---

### Q7: "A Memcached UDP amplification attack is hitting you at 1 Tbps. Walk through your incident response step by step."

**Answer:**

**Immediate (T+0 to T+5 minutes):**

The traffic analysis system detects the anomaly: inbound UDP traffic to our IPs spikes to 1 Tbps, sourced from port UDP/11211 (Memcached). This is a well-known amplification signature. Automated mitigation activates immediately:

The control plane sends a command to all edge PoPs: "Apply ACL: DROP UDP source port 11211 to all our destination IPs." This is effective because all legitimate Memcached response traffic would come from port 11211, and we're not expecting Memcached responses (we're not a Memcached client). This hardware ACL drops the attack traffic at line rate with zero impact on legitimate traffic.

Simultaneously: the BGP route controller evaluates whether to activate RTBH. If the 1 Tbps is concentrated on one or a few IPs: RTBH for those specific /32s. If spread across our entire /24: the ACL approach is sufficient because we're blocking by source port, not by destination.

PagerDuty alert fires. On-call network engineer is paged.

**Short-term (T+5 to T+30 minutes):**

On-call engineer confirms automated mitigation is working. Checks: are legitimate users still being served? (Should be yes — UDP/11211 ACL blocks attack without touching legitimate HTTP traffic.)

Contacts upstream transit providers: requests them to apply the same UDP/11211 source port filter upstream. This reduces attack volume before it reaches our network (less wasted transit bandwidth, reduced bill).

Checks whether the attack is saturating any upstream links. If yes: RTBH for the most-targeted IPs while the ACL filter propagates to upstream providers.

Documents the incident: attack volume, source ASNs of the amplification reflectors (Memcached servers being abused), attack start time.

**Medium-term (T+30 minutes to end of attack):**

Reports the list of Memcached reflector IPs to the scrubbing center for future proactive blocking. These Memcached servers are misconfigured (exposed to the internet) — report to abuse contacts of their hosting providers.

Maintains the UDP/11211 ACL. Considers whether to make this permanent: if we have no legitimate UDP/11211 traffic, permanently block it. This is a hardening measure that prevents future Memcached amplification.

**Post-incident:**

Review: Was detection time acceptable? Was mitigation activation fast enough? Was there any legitimate traffic impact? Update runbooks with lessons learned. Submit reflector IPs to public abuse databases (Shadowserver, CAIDA).

---

*Document version: 1.0 | Classification: Internal Engineering*
*Author: Network Security Engineering Team*
*This document covers production-grade DDoS mitigation architecture.*
*All attack descriptions are for defensive engineering purposes.*
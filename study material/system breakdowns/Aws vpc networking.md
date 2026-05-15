# AWS VPC Networking Model — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** All Engineers (Beginner to Senior), Security Engineers, Cloud Architects  
**Scope:** Complete breakdown of AWS VPC networking — from packet arrival at an internet gateway to application response, including every routing decision, security control, failure mode, and attack vector  
**System Context:** A production three-tier application (public ALB → private app tier → private database tier) deployed in a multi-AZ VPC

---

## A Beginner's Orientation: What Is a VPC and Why Does It Exist?

**The core problem:** AWS runs thousands of customers' workloads on shared physical hardware. Without isolation, one customer's EC2 instance could eavesdrop on another's network traffic, scan their servers, or modify their data. A VPC (Virtual Private Cloud) creates the illusion that you have your own private data center network, even though you're sharing hardware with others.

**What "virtual" means at the hardware level:**

AWS uses a hypervisor (Nitro in modern instances) to create isolated virtual machines. But network isolation requires more than just VM isolation. AWS uses a concept called the "Virtual Private Cloud" with software-defined networking:

- Every packet from your EC2 instance is tagged with your VPC identifier
- The physical AWS network enforces routing rules at the hypervisor level
- Packets from VPC A never appear on VPC B's virtual network, even on the same physical host
- This is enforced in hardware (Nitro card), not just software — much harder to bypass

**The four fundamental VPC concepts:**

```
1. CIDR Block: Your VPC's private IP address range
   Example: 10.0.0.0/16 = 65,536 private IP addresses (10.0.0.0 to 10.0.255.255)

2. Subnet: A subdivision of the VPC's CIDR for organizing resources
   - Public subnet: Has a route to the Internet Gateway (publicly reachable if also has Elastic IP)
   - Private subnet: No direct route to internet; goes through NAT Gateway for outbound

3. Route Table: Rules that determine where packets go
   - Destination: 0.0.0.0/0 (all internet traffic), Target: igw-xxx (Internet Gateway)
   - Destination: 10.0.0.0/16 (local), Target: local (stay in VPC)

4. Security Group: Virtual firewall at the network interface (ENI) level
   - Stateful: If you allow outbound, the return traffic is automatically allowed
   - Applied per instance (not per subnet)
```

---

## Table of Contents

1. [User Journey (Narrative)](#1-user-journey-narrative)
2. [Network Layer Flow](#2-network-layer-flow)
3. [Application Layer Flow](#3-application-layer-flow)
4. [Backend Architecture](#4-backend-architecture)
5. [Authentication & Authorization Flow](#5-authentication--authorization-flow)
6. [Data Flow](#6-data-flow)
7. [Security Controls](#7-security-controls)
8. [Attack Surface Mapping](#8-attack-surface-mapping)
9. [Attack Scenarios (Very Detailed)](#9-attack-scenarios-very-detailed)
10. [Failure Points](#10-failure-points)
11. [Mitigations](#11-mitigations)
12. [Observability](#12-observability)
13. [Scaling Considerations](#13-scaling-considerations)
14. [Interview Questions](#14-interview-questions)

---

## 1. User Journey (Narrative)

### The Architecture

We trace a user request through this specific production VPC architecture:

```
VPC: 10.0.0.0/16 (us-east-1)

Public Subnets (AZ-a, AZ-b):
  us-east-1a: 10.0.1.0/24 (ALB, NAT Gateway)
  us-east-1b: 10.0.2.0/24 (ALB, NAT Gateway)

Private Subnets - App Tier (AZ-a, AZ-b):
  us-east-1a: 10.0.10.0/24 (EC2 app servers)
  us-east-1b: 10.0.11.0/24 (EC2 app servers)

Private Subnets - Data Tier (AZ-a, AZ-b):
  us-east-1a: 10.0.20.0/24 (RDS PostgreSQL primary)
  us-east-1b: 10.0.21.0/24 (RDS PostgreSQL replica)
```

### The Request: Alice Opens a Web App

**T+0ms — Alice types `https://app.example.com` in her browser**

Alice is sitting in New York. She types the URL and hits Enter. Nothing has happened yet — the browser is about to begin a series of network operations.

**T+1ms — Browser checks its own DNS cache**

The browser checks: "Have I resolved `app.example.com` recently?"
- Cache miss (first visit, or TTL expired)
- Browser passes the query to the OS resolver

**T+2ms — OS DNS resolution begins**

The OS stub resolver (on Alice's laptop) checks its cache, then sends a UDP packet to the configured DNS server (usually the router, which forwards to ISP DNS, or a configured resolver like 8.8.8.8).

The resolver walks the DNS hierarchy:
```
Root NS → .com NS → example.com NS → app.example.com

Answer: app.example.com. 60 IN A 54.89.XX.YY (ALB's public IP)
```

**T+50ms — DNS resolved. TCP begins.**

Alice's browser initiates a TCP connection to `54.89.XX.YY:443`. This IP belongs to the AWS Application Load Balancer sitting in the public subnet of the VPC.

**What the user sees:** Still the blank loading indicator.

**What's happening in AWS:** The TCP SYN packet arrives at the Internet Gateway (IGW). The IGW is not a single device — it's a redundant, horizontally scalable AWS service that performs Network Address Translation. It translates the public IP `54.89.XX.YY` to the ALB's private IP `10.0.1.100`. The packet traverses AWS's internal backbone to reach the ALB's network interface card.

**T+80ms — TCP established. TLS begins.**

TLS 1.3 handshake with the ALB. The ALB presents a certificate for `app.example.com` issued by ACM (AWS Certificate Manager). Alice's browser validates the certificate chain.

**T+120ms — HTTPS request sent**

Alice's browser sends the encrypted HTTP GET request. The ALB:
1. Terminates TLS (decrypts the request)
2. Evaluates its listener rules (which target group to forward to?)
3. Selects a healthy app server (10.0.10.5 in the private subnet)
4. Forwards the request over HTTP/1.1 or HTTP/2 to the app server
5. Adds headers: `X-Forwarded-For: Alice's IP`, `X-Forwarded-Proto: https`

**T+122ms — Request in the private subnet**

The packet is now in the private subnet `10.0.10.0/24`. It can ONLY reach:
- Other instances in the same VPC (via local routing)
- The internet indirectly via NAT Gateway (for outbound requests only)
- AWS services via VPC endpoints (S3, DynamoDB, etc. without internet)

The app server (10.0.10.5) receives the request. It processes the business logic and queries the database.

**T+123ms — App server queries RDS**

App server sends a TCP connection to RDS at `10.0.20.10:5432`. This connection:
- Stays entirely within the VPC (private subnet to data subnet routing)
- Never touches the internet
- Is encrypted with TLS (PostgreSQL SSL mode verify-full)

**T+150ms — Response assembled and returned**

The app server builds the HTTP response. The response travels back:
```
App server (10.0.10.5) → ALB (10.0.1.100) → [ALB terminates connection] 
→ Internet Gateway (NAT back to public IP) → Alice's browser
```

**What Alice sees:** The web page loads.

---

## 2. Network Layer Flow

### The VPC Network Stack Explained

Understanding AWS VPC requires understanding several overlapping network layers:

```
LAYER 1: Physical AWS Hardware (invisible to us)
  - AWS Nitro Cards: ASICs that enforce VPC isolation in hardware
  - Physical servers run multiple customers' VMs; Nitro ensures isolation
  - AWS Nitro Card intercepts all packets, applies VPC policy

LAYER 2: AWS Internal Backbone
  - Not the internet — AWS's private fiber network between data centers
  - Higher reliability, lower latency than public internet
  - Traffic between AZs in the same region uses this backbone

LAYER 3: VPC Virtual Network
  - Software-defined network, not physical cabling
  - Your CIDR block (10.0.0.0/16) exists only as a routing concept
  - The VPC router is a virtual device — every subnet has one at the .1 address

LAYER 4: Subnet Level
  - Resources in the same subnet can communicate without going through the VPC router
  - Still subject to Security Group and NACL rules

LAYER 5: Resource Level (EC2, RDS, ALB, Lambda ENI)
  - Elastic Network Interface (ENI): virtual NIC attached to a subnet
  - Has private IP, optionally public IP or Elastic IP
  - Security Groups attach to ENIs, not instances
```

---

### DNS Resolution — Deep Dive

When a resource inside the VPC (e.g., app server) needs to resolve `db.us-east-1.rds.amazonaws.com`:

```
EC2 Instance (10.0.10.5)
    |
    | DNS query to 169.254.169.253 (VPC DNS Resolver)
    | (This is the "VPC+2" address — always the VPC base + 2)
    | For VPC 10.0.0.0/16: resolver is at 10.0.0.2
    | Also accessible at 169.254.169.253 (link-local)
    v
AWS Route 53 Resolver
    |
    | For *.amazonaws.com: AWS's internal authoritative NS
    | Returns private IPs for VPC Endpoints (if configured)
    | OR returns public IPs for public endpoints
    v
Resolution: db-cluster.cxxxxxx.us-east-1.rds.amazonaws.com → 10.0.20.10 (private RDS IP)
```

**Why the VPC DNS resolver at 169.254.169.253 matters:**

AWS Route 53 Private Hosted Zones work because the VPC DNS resolver intercepts queries and answers from private DNS records. Without this, you'd need to use public DNS for everything inside your VPC, exposing internal service discovery to the internet.

**Example: Split-horizon DNS:**
```
External DNS (api.example.com): 54.89.XX.YY (ALB public IP)
  → Used by users on the internet
  → Traffic goes: Internet → IGW → ALB

Internal DNS (api.example.com): 10.0.1.100 (ALB private IP)
  → Used by EC2 instances inside the VPC via Route 53 Private Hosted Zone
  → Traffic goes: App server → ALB (stays internal, no IGW needed)
  → Faster AND doesn't unnecessarily expose traffic to the IGW
```

---

### The Internet Gateway (IGW) — Packet-Level Mechanics

The IGW is commonly misunderstood. It is NOT a NAT device in the traditional sense. Here's what actually happens:

**For inbound traffic (internet → VPC):**

```
Step 1: Alice's packet arrives at AWS edge
  Source IP: 203.0.113.5 (Alice's public IP)
  Destination IP: 54.89.XX.YY (ALB's Elastic IP)

Step 2: IGW performs 1:1 NAT (EIP → private IP mapping)
  The IGW has a mapping table:
    54.89.XX.YY (EIP) ↔ 10.0.1.100 (ALB private IP)
  
  It rewrites the destination:
  Source IP: 203.0.113.5
  Destination IP: 10.0.1.100  ← Changed from EIP to private IP

Step 3: AWS internal routing delivers to 10.0.1.100 (ALB's ENI)
```

**For outbound traffic (VPC → internet):**

```
Step 1: ALB sends a response
  Source IP: 10.0.1.100 (ALB private IP)
  Destination IP: 203.0.113.5 (Alice's IP)

Step 2: Routing table sends to IGW
  Route: 0.0.0.0/0 → igw-xxxxxx (Internet Gateway)

Step 3: IGW performs reverse NAT
  Source IP: 54.89.XX.YY (EIP) ← Changed from private to public
  Destination IP: 203.0.113.5

Step 4: Packet sent to Alice via internet
```

**Critical point:** The IGW only translates EIPs (Elastic IPs or auto-assigned public IPs). Private EC2 instances with NO public IP CANNOT send traffic through the IGW, even if the route table points to it. They must use a NAT Gateway.

---

### NAT Gateway — Outbound Internet for Private Resources

Private subnet resources (app servers, RDS) need internet access for things like:
- Downloading software updates from package repositories
- Calling external APIs (Stripe, Twilio, etc.)
- Sending data to monitoring services

But they should NOT be directly reachable from the internet.

**NAT Gateway mechanics:**

```
App server (10.0.10.5) initiates outbound connection:
  Source: 10.0.10.5:49821
  Destination: 54.84.1.1:443 (Stripe API)
  
  ↓ Route table: 0.0.0.0/0 → nat-gw-xxxxxx

NAT Gateway (10.0.1.254 private, 54.89.ZZ.AA Elastic IP):
  Creates a NAT translation table entry:
    (10.0.10.5:49821) ↔ (54.89.ZZ.AA:random_ephemeral_port)
  
  Rewrites packet:
    Source: 54.89.ZZ.AA:54321 (NAT Gateway's EIP + new port)
    Destination: 54.84.1.1:443

Response from Stripe:
  Source: 54.84.1.1:443
  Destination: 54.89.ZZ.AA:54321
  
  NAT Gateway translates back:
    Source: 54.84.1.1:443
    Destination: 10.0.10.5:49821  ← Restored to original private IP
```

**Why one NAT per AZ?** If the AZ with the NAT Gateway fails, instances in other AZs that route through it lose internet connectivity. Best practice: NAT Gateway in each AZ, with route tables for each AZ's private subnets pointing to their AZ's NAT Gateway.

---

### Route Tables — The Traffic Director

Route tables determine where packets go. Every subnet is associated with exactly one route table.

**Public subnet route table:**
```
Destination     Target          Description
10.0.0.0/16    local           VPC-internal traffic (stays in VPC)
0.0.0.0/0      igw-xxxxxx      All other traffic → Internet Gateway
```

**Private app subnet route table (us-east-1a):**
```
Destination     Target              Description
10.0.0.0/16    local               VPC-internal traffic
0.0.0.0/0      nat-gw-aaaa         Internet via NAT (in same AZ)
```

**Private data subnet route table:**
```
Destination     Target              Description  
10.0.0.0/16    local               VPC-internal only
0.0.0.0/0      NONE                NO internet access at all (no NAT route)
```

**The longest prefix match rule:**

When a packet has multiple matching routes, the most specific (longest prefix) wins:

```
Destination routes:
  10.0.0.0/16    → local
  10.0.10.0/24  → peering-connection-xxxxxx  (VPC peering to staging)
  0.0.0.0/0     → nat-gw-aaaa

Packet to 10.0.10.5:
  Matches: 10.0.0.0/16 AND 10.0.10.0/24
  Winner: 10.0.10.0/24 (/24 is more specific than /16)
  → Sent to VPC peering connection
```

---

### Full Network Flow Diagram

```
INTERNET (Alice, 203.0.113.5)
    |
    | TCP SYN to 54.89.XX.YY:443
    v
┌─────────────────────────────────────────────────────────────────────────────┐
│  AWS Region: us-east-1                                                     │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Internet Gateway (IGW)                                             │   │
│  │  NAT: 54.89.XX.YY → 10.0.1.100                                     │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                  │                                          │
│  ┌───────────────────────────────▼──────────────────────────────────────┐  │
│  │  VPC: 10.0.0.0/16                                                    │  │
│  │                                                                       │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │  PUBLIC SUBNETS                                                  │ │  │
│  │  │  Route: 0.0.0.0/0 → igw-xxx                                     │ │  │
│  │  │                                                                  │ │  │
│  │  │  ┌──────────────────┐   ┌──────────────────┐                    │ │  │
│  │  │  │  AZ-a: 10.0.1.0/24  │  AZ-b: 10.0.2.0/24  │                    │ │  │
│  │  │  │  ALB (10.0.1.100) │   │  ALB (10.0.2.100) │  ← Multi-AZ ALB   │ │  │
│  │  │  │  NAT GW (10.0.1.254) │   │  NAT GW (10.0.2.254) │                  │ │  │
│  │  │  └────────┬─────────┘   └────────┬─────────┘                    │ │  │
│  │  └───────────┼─────────────────────┼──────────────────────────────┘ │  │
│  │              │  ALB selects target  │                                │  │
│  │  ┌───────────▼─────────────────────▼──────────────────────────────┐ │  │
│  │  │  PRIVATE APP SUBNETS                                            │ │  │
│  │  │  Route: 0.0.0.0/0 → nat-gw (same AZ)                          │ │  │
│  │  │                                                                  │ │  │
│  │  │  ┌──────────────────────┐  ┌──────────────────────┐            │ │  │
│  │  │  │  AZ-a: 10.0.10.0/24 │  │  AZ-b: 10.0.11.0/24 │            │ │  │
│  │  │  │  EC2: 10.0.10.5     │  │  EC2: 10.0.11.7     │            │ │  │
│  │  │  │  EC2: 10.0.10.6     │  │  EC2: 10.0.11.8     │            │ │  │
│  │  │  │  SG: app-sg         │  │  SG: app-sg         │            │ │  │
│  │  │  └──────────┬──────────┘  └──────────┬──────────┘            │ │  │
│  │  └─────────────┼───────────────────────┼─────────────────────────┘ │  │
│  │                │  DB connection        │                            │  │
│  │  ┌─────────────▼───────────────────────▼──────────────────────────┐ │  │
│  │  │  PRIVATE DATA SUBNETS                                           │ │  │
│  │  │  Route: 10.0.0.0/16 → local ONLY (no internet)                 │ │  │
│  │  │                                                                  │ │  │
│  │  │  ┌──────────────────────┐  ┌──────────────────────┐            │ │  │
│  │  │  │  AZ-a: 10.0.20.0/24 │  │  AZ-b: 10.0.21.0/24 │            │ │  │
│  │  │  │  RDS Primary         │  │  RDS Replica         │            │ │  │
│  │  │  │  10.0.20.10:5432    │  │  10.0.21.10:5432    │            │ │  │
│  │  │  │  SG: db-sg          │  │  SG: db-sg          │            │ │  │
│  │  │  └──────────────────────┘  └──────────────────────┘            │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘

Traffic flow for Alice's request:
  [1] Alice → IGW (EIP 54.89.XX.YY → ALB 10.0.1.100)
  [2] ALB → App server (10.0.1.100 → 10.0.10.5)
  [3] App server → RDS (10.0.10.5 → 10.0.20.10)
  [4] RDS → App server (10.0.20.10 → 10.0.10.5)
  [5] App server → ALB (10.0.10.5 → 10.0.1.100)
  [6] ALB → IGW → Alice (10.0.1.100 → 54.89.XX.YY → 203.0.113.5)
```

### TCP 3-Way Handshake

**Between Alice and the ALB:**

```
Alice (203.0.113.5:49821)              ALB (54.89.XX.YY:443)
         |                                       |
         | SYN [seq=1000, MSS=1460, WS=256]      |
         |-------------------------------------->|
         |                                       | ALB's SG checks:
         |                                       | Inbound rule: Allow TCP 443 from 0.0.0.0/0 ✓
         | SYN-ACK [seq=5000, ack=1001]          |
         |<--------------------------------------|
         |                                       |
         | ACK [ack=5001]                        |
         |-------------------------------------->|
         | [TCP established — TLS begins]        |
```

**Between the ALB and the App Server (a NEW TCP connection):**

```
ALB (10.0.1.100)                       App Server (10.0.10.5:8080)
     |                                          |
     | SYN                                      | App SG checks:
     |----------------------------------------->| Inbound: Allow TCP 8080 from ALB SG ✓
     | SYN-ACK                                  |
     |<-----------------------------------------|
     | ACK                                      |
     |----------------------------------------->|
     | HTTP GET (plaintext from ALB to server)  |
     |----------------------------------------->|
```

**Important:** The ALB terminates the TLS connection from Alice. The connection from ALB to the app server is a SEPARATE TCP connection. By default, this connection can be HTTP (unencrypted). For production, enable HTTPS on the target group (the ALB re-encrypts before forwarding to the app server).

---

### TLS Handshake Details

The ALB presents its certificate to Alice:

```
Alice                                          AWS ALB
  |                                               |
  | ClientHello                                   |
  | - TLS 1.3                                     |
  | - key_share: X25519                          |
  | - SNI: "app.example.com"                     |
  |---------------------------------------------->|
  |                                               | ALB selects cert from ACM:
  |                                               | - Subject: app.example.com
  |                                               | - Issued by: Amazon RSA 2048 M01
  |                                               | - Valid: 2024-01-01 to 2025-01-01
  |                                               |
  | ServerHello + Certificate + CertVerify        |
  | + Finished                                    |
  |<----------------------------------------------|
  |                                               |
  | [Alice validates: chain → Amazon Root CA]    |
  |                                               |
  | Finished + [HTTP GET / (encrypted)]           |
  |---------------------------------------------->|
```

**AWS Certificate Manager (ACM) and the ALB:** ACM stores private keys in HSMs. The ALB never has direct access to the private key — instead, the TLS termination happens in a cryptographic offload path where the ALB can use the key for TLS without the key being in EC2 memory. This is managed by AWS and is part of why ACM certificates are locked to AWS services (can't export the private key).

---

### Security Groups — Stateful Firewall Mechanics

Security Groups are the most misunderstood VPC component. Key facts:

**They are STATEFUL:** If outbound port 80 is allowed and an EC2 instance makes an outbound connection, the RETURN traffic is automatically allowed even without an inbound rule.

**They operate at the ENI level:** Each EC2 instance has one or more ENIs. Security Groups attach to ENIs. An EC2 with multiple ENIs can have different Security Groups on each.

**The "allow from Security Group" feature:**

```python
# Instead of specifying an IP range, you can specify a Security Group ID:
ALB_SG.add_ingress_rule(
    peer=Peer.any_ipv4(),
    connection=Port.tcp(443),
    description="HTTPS from internet"
)

APP_SG.add_ingress_rule(
    peer=ALB_SG,  # Allow from ALB Security Group (not a specific IP!)
    connection=Port.tcp(8080),
    description="HTTP from ALB"
)

DB_SG.add_ingress_rule(
    peer=APP_SG,  # Allow from App Security Group
    connection=Port.tcp(5432),
    description="PostgreSQL from app servers"
)
```

**Why "allow from Security Group" is powerful:**

```
WITHOUT Security Group chaining:
  DB_SG allows: 10.0.10.0/24 → port 5432
  Problem: If you add an app server in 10.0.11.0/24, you must update DB_SG

WITH Security Group chaining:
  DB_SG allows: APP_SG → port 5432
  Now ANY resource in APP_SG can reach the DB, regardless of subnet
  Add a new app server, add APP_SG → automatically can reach DB
  No rule changes needed
```

**What Security Groups can't do:**
- Block outbound traffic in specific directions (the stateful nature means return traffic is always allowed)
- Filter by port range for return traffic (they track connections, not ports)
- Block traffic between instances in the SAME Security Group (unless you explicitly have no inbound self-referencing rule)

---

### Network ACLs (NACLs) — Stateless Subnet Firewall

NACLs operate at the subnet boundary. They're often misconfigured because they're stateless:

```
NACL for Private App Subnet:

Inbound rules:
  Rule 100: Allow TCP from 10.0.1.0/24 (public subnet) on port 8080
  Rule 110: Allow TCP from 10.0.2.0/24 (public subnet AZ-b) on port 8080
  Rule 32766: Deny ALL (implicit)

Outbound rules:
  Rule 100: Allow TCP to 10.0.1.0/24 on ports 1024-65535 (EPHEMERAL PORTS!)
  Rule 110: Allow TCP to 10.0.2.0/24 on ports 1024-65535
  Rule 200: Allow TCP to 10.0.20.0/24 (data subnet) on port 5432
  Rule 210: Allow TCP to 10.0.21.0/24 (data subnet AZ-b) on port 5432
  Rule 300: Allow TCP to 0.0.0.0/0 on port 443 (for outbound HTTPS via NAT)
  Rule 32766: Deny ALL (implicit)
```

**The ephemeral port gotcha:** When the ALB (in the public subnet) connects to the app server on port 8080, the ALB uses an ephemeral source port (say, 54321). The app server's RESPONSE goes back to the ALB on port 54321. The NACL on the public subnet must allow INBOUND on ports 1024-65535 (the entire ephemeral range), not just port 8080. 

This is why Security Groups are preferred over NACLs for most configurations — Security Groups are stateful and don't require ephemeral port rules.

---

## 3. Application Layer Flow

### ALB Listener Rules and Target Group Routing

The ALB processes the HTTP request through a rules engine:

```
Listener: 443 (HTTPS)
  Rule 1: Path /api/* → Target Group: api-servers (EC2 instances)
  Rule 2: Path /static/* → Target Group: S3 bucket (S3 as ALB target)
  Rule 3: Host app.example.com → Target Group: web-servers
  Rule 4: Default → Return 404 (catch-all for unknown hosts)
```

**Target Group health checks:**

The ALB continuously polls each registered target:
```
Health check:
  Protocol: HTTP
  Path: /health
  Port: 8080
  Interval: 30 seconds
  Threshold: 2 consecutive healthy checks
  Unhealthy threshold: 3 consecutive failures
  Timeout: 5 seconds

If a target fails 3 health checks:
  - Target marked "unhealthy" in ALB
  - No new connections routed to it
  - Existing connections allowed to drain (connection draining timeout: 300s)
  - Target deregistered from active pool
```

**Connection draining:** When an instance is being terminated (e.g., Auto Scaling scale-in), the ALB stops sending NEW requests to it but allows existing connections to complete. After the timeout, the instance is force-terminated. Without draining, in-flight requests would get connection resets (users see errors).

---

### HTTP Headers Added by the ALB

The ALB modifies the request before forwarding to the app server:

```http
GET / HTTP/1.1
Host: app.example.com
X-Forwarded-For: 203.0.113.5        ← Alice's original IP
X-Forwarded-Proto: https            ← Original protocol (HTTPS)
X-Forwarded-Port: 443               ← Original port
X-Amzn-Trace-Id: Root=1-xxxxxxxx-yyyy  ← AWS X-Ray trace ID
Connection: keep-alive              ← ALB keeps connection to backend alive
```

**X-Forwarded-For security issue:**

If the app server trusts `X-Forwarded-For` for IP-based access control, an attacker can spoof:
```
Request: X-Forwarded-For: 10.0.1.1, 203.0.113.5

If app reads the FIRST IP (10.0.1.1):
  App thinks request is from an internal IP
  May bypass IP-based access controls
  May grant elevated trust to the request
```

**Fix:** Always read the RIGHTMOST IP that your trusted proxy (ALB) adds, not the first. Or configure the ALB to drop and re-set the header with only Alice's IP.

---

### Application Layer for the App Server

The app server (a Node.js/Python/Go service) receives the forwarded request and:

1. **Validates the session/JWT** (covered in Section 5)
2. **Parses the request parameters**
3. **Executes business logic**
4. **Queries RDS** (via the connection pool to 10.0.20.10:5432)
5. **Returns the response**

The connection to RDS from the app server:
```
App server initiates TLS to RDS:
  - Connect to 10.0.20.10:5432
  - RDS presents its certificate (signed by Amazon's internal CA)
  - App verifies: is this cert for my RDS instance?
  - Connection: TLS 1.3, AES-256-GCM
  - Authentication: IAM database authentication (token-based, no password)
```

---

## 4. Backend Architecture

### VPC Endpoints — Accessing AWS Services Privately

Without VPC Endpoints, traffic from EC2 to S3 goes:

```
EC2 (10.0.10.5) → NAT Gateway → Internet → S3 endpoint (public IP)
```

Problems:
- Costs NAT Gateway data processing fees (~$0.045/GB)
- Traffic leaves AWS network (potentially)
- Need to allow outbound internet in Security Group

With S3 Gateway VPC Endpoint:

```
EC2 (10.0.10.5) → VPC Endpoint → S3 (stays entirely on AWS backbone)
```

**Two types of VPC Endpoints:**

**Gateway Endpoint (for S3 and DynamoDB — free):**
```
Route table entry:
  Destination: pl-63a5400a (S3's managed prefix list — all S3 IPs)
  Target: vpce-xxxxxx (the Gateway Endpoint)

When EC2 sends a packet to S3:
  DNS resolves S3 to S3's IP
  Route table sees: destination matches S3 prefix list → route to VPC Endpoint
  Packet never goes through NAT Gateway
```

**Interface Endpoint (for most other AWS services — costs ~$0.01/AZ/hour):**
```
Creates an ENI in your VPC with a private IP
DNS changes: logs.us-east-1.amazonaws.com → 10.0.10.250 (private endpoint IP)
Traffic goes through the ENI → AWS service (no internet)

Use for: CloudWatch Logs, SQS, SNS, Secrets Manager, SSM, ECR, etc.
```

**VPC Endpoint Policies (security layer):**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:role/app-server-role"
    },
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::my-company-bucket/*"
  }]
}
```

Even if an EC2 instance's IAM role has broad S3 access, the VPC Endpoint policy can restrict it to only specific buckets — defense in depth.

---

### Multi-AZ Architecture for Resilience

```
AZ Failure Scenario:
  AZ us-east-1a fails (power outage, network issue)
  
  Impact WITHOUT multi-AZ:
    ALB in AZ-a: unavailable
    App servers in 10.0.10.0/24: unavailable
    RDS primary in 10.0.20.0/24: unavailable
    COMPLETE OUTAGE
  
  Impact WITH multi-AZ (our architecture):
    ALB: still available (has nodes in AZ-b, Route 53 health checks fail AZ-a)
    App servers: Auto Scaling launches new instances in AZ-b (10.0.11.0/24)
    RDS: Automatic failover to replica in AZ-b (10.0.21.10)
      - DNS flips to replica: ~60-120 seconds downtime
    Overall: 1-2 minute disruption, then full recovery
```

**AZ routing preference:**

The ALB respects AZ affinity for cost optimization:
- ALB node in AZ-a preferentially sends traffic to targets in AZ-a
- This avoids cross-AZ data transfer fees (~$0.01/GB between AZs in same region)
- Cross-AZ load balancing can be enabled (routes to least-loaded, regardless of AZ)
- For most applications: enable cross-AZ LB for better distribution despite costs

---

### Sync vs Async Within the VPC

**Synchronous (user waits):**
```
HTTP request → ALB → App Server → RDS query → Response
Total: 50-200ms
All of this happens before the user sees a response
```

**Asynchronous (decoupled processing):**
```
HTTP request → ALB → App Server → Publish to SQS → 202 Accepted
                                         ↓
                              Worker EC2 reads from SQS
                              Worker processes job (30 seconds)
                              Worker updates RDS
                              Worker sends notification (SNS → email)

SQS traffic: App server → VPC Endpoint → SQS (private, no internet)
```

**Placement within the VPC for async components:**

```
SQS Workers: In private app subnet (10.0.10.0/24)
  - Same Security Group as web servers (or separate worker-sg)
  - No inbound traffic needed (they poll SQS, not wait for connections)
  - Outbound: SQS via VPC Endpoint, RDS via private route, S3 via Gateway Endpoint

Lambda Functions (event-driven):
  - Can run in VPC mode (slow cold start) or outside VPC (fast cold start)
  - VPC mode: creates ENIs in your private subnets
  - Use VPC mode ONLY if Lambda needs to reach VPC resources (RDS, ElastiCache)
  - Cold start with VPC: 5-15 seconds for ENI creation on first invocation
```

---

## 5. Authentication & Authorization Flow

### IAM Roles vs. Long-Term Credentials in the VPC

**The wrong way (unfortunately common):** SSH into an EC2 instance and configure `~/.aws/credentials` with an IAM user's access key and secret. This is a critical security failure:

```
~/.aws/credentials (on EC2 instance — WRONG):
  [default]
  aws_access_key_id = AKIAIOSFODNN7EXAMPLE
  aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Problems:
- Credentials can be extracted by anyone with OS access
- Credentials are long-lived (no automatic rotation)
- If the EC2 is compromised, the attacker has permanent credentials until manually rotated
- Credentials can be committed to git by accident

**The right way: EC2 Instance Profiles + IAM Roles**

```
1. Create IAM Role: app-server-role
   - Trust policy: allows EC2 service to assume this role
   - Permission policy: only what the app needs (S3 GetObject on specific bucket, 
     SQS SendMessage on specific queue, RDS IAM auth on specific cluster)

2. Attach role to EC2 instance (as Instance Profile)

3. AWS provides temporary credentials via the metadata service:
   EC2 instance queries: GET http://169.254.169.254/latest/meta-data/iam/security-credentials/app-server-role
   Returns:
     {
       "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",    ← Temporary
       "SecretAccessKey": "wJalrXUt...",          ← Temporary  
       "Token": "AQoDYXdz...",                    ← Session token (required with STS)
       "Expiration": "2024-11-15T11:30:00Z"       ← Expires in ~6 hours
     }

4. AWS SDKs automatically refresh these credentials before expiry
5. If the EC2 is compromised, credentials expire in <6 hours
   AND can be revoked immediately by detaching the instance profile
```

---

### Protecting the Instance Metadata Service (IMDS)

The metadata service at `169.254.169.254` is a major attack surface. An SSRF vulnerability in the app can be exploited to steal EC2 credentials:

```
Attacker finds SSRF in app:
  POST /api/fetch-url
  {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
  
  App fetches the URL on behalf of attacker
  Returns IAM role name: "app-server-role"
  
  Attacker follows up:
  {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-server-role"}
  
  Returns full temporary credentials!
  Attacker now has AWS API access as the EC2 role
```

**IMDSv2 — The fix:**

IMDSv2 requires a PUT request to get a session token first, then uses that token for subsequent requests. A standard SSRF exploit doesn't follow this two-step process.

```bash
# IMDSv1 (vulnerable — one GET):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role

# IMDSv2 (requires PUT first to get token):
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role
```

**Why SSRF can't exploit IMDSv2:**

An SSRF vulnerability typically makes the server do a GET request to an attacker-controlled URL. The `PUT` method with custom headers (`X-aws-ec2-metadata-token-ttl-seconds`) is much harder to trigger via SSRF — most server-side HTTP libraries default to GET and don't automatically send custom PUT headers.

**Enforce IMDSv2 on all instances:**
```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \          # Require the PUT token
  --http-endpoint enabled \
  --http-put-response-hop-limit 1   # Limit to 1 hop (prevents container-to-EC2 metadata access)
```

---

### VPC Peering and Transit Gateway Authentication

When connecting multiple VPCs (e.g., production VPC and shared services VPC):

**VPC Peering (point-to-point):**
```
VPC A (production): 10.0.0.0/16
VPC B (shared services): 10.1.0.0/16

Peering connection: pcx-xxxxxx
Route in VPC A: 10.1.0.0/16 → pcx-xxxxxx
Route in VPC B: 10.0.0.0/16 → pcx-xxxxxx

Security controls:
  - VPC A's Security Groups can reference VPC B's Security Group IDs
  - But traffic is NOT automatically trusted — Security Groups still apply
  - VPC A EC2's Security Group must explicitly allow inbound from VPC B's CIDR or SG
```

**Transit Gateway (hub-and-spoke for 3+ VPCs):**
```
Production VPC ─────┐
Staging VPC  ───────┤──→ Transit Gateway ──→ Shared Services VPC
Dev VPC      ───────┘

Transit Gateway Route Table:
  VPC attachment type controls routing
  Can implement network segmentation:
    Production → Shared Services: allowed
    Production → Dev: blocked (separate route table that doesn't include Dev routes)
    Dev → Production: blocked (asymmetrically)
```

---

## 6. Data Flow

### How Packets Are Processed at Each Hop

```
Packet journey for Alice's GET request:

[Alice's Browser]
  Creates TCP/IP packet:
    Source: 203.0.113.5:49821
    Destination: 54.89.XX.YY:443
    Data: HTTP GET / (encrypted with TLS)

[Internet → AWS Edge]
  Packet routes via BGP to AWS's edge router for us-east-1
  AWS's edge accepts the packet (routes announce 54.89.XX.YY belongs to AWS)

[Internet Gateway]
  Performs 1:1 NAT: 54.89.XX.YY → 10.0.1.100 (ALB private IP)
  Security Group not evaluated at IGW (evaluated at ENI)

[ALB ENI — Security Group Evaluation]
  ALB-SG inbound rule: TCP 443 from 0.0.0.0/0 ✓
  Packet accepted
  
[ALB Processing]
  TLS terminated
  HTTP request parsed
  Target selected: 10.0.10.5 (app server in AZ-a)
  New TCP connection opened to 10.0.10.5:8080
  HTTP request forwarded with X-Forwarded headers

[Routing through VPC to App Server]
  Source: 10.0.1.100 (ALB)
  Destination: 10.0.10.5 (app server)
  Route: local (both in 10.0.0.0/16, handled by VPC router)
  No NAT needed (both private IPs in same VPC)

[App Server ENI — Security Group Evaluation]
  App-SG inbound rule: TCP 8080 from ALB-SG ✓
  Packet accepted

[App Server Processing]
  HTTP request processed
  DB query initiated

[App Server → RDS Routing]
  Source: 10.0.10.5
  Destination: 10.0.20.10 (RDS, different subnet)
  Route: local (same VPC, local route)

[RDS ENI — Security Group Evaluation]
  DB-SG inbound rule: TCP 5432 from App-SG ✓
  TLS connection (verify-full mode)
  Database query executed

[Response path — symmetric]
```

### AWS Nitro System — The Enforcement Layer

The actual packet inspection and enforcement happens in the Nitro card (a dedicated network card with its own processor):

```
Physical Server:
  ┌─────────────────────────────────────────────────────┐
  │  EC2 Instance (your VMs run here)                   │
  │  - VM: VPC A, instance i-abc (10.0.10.5)           │
  │  - VM: VPC B, instance i-def (10.1.10.5)           │
  │                                                     │
  │  These VMs cannot see each other's traffic,        │
  │  even on the same physical NIC                     │
  └────────────────────┬────────────────────────────────┘
                       │ Physical NIC
                       ▼
  ┌─────────────────────────────────────────────────────┐
  │  AWS Nitro Card (separate ASIC)                    │
  │                                                     │
  │  For every packet from VPC A's VM:                 │
  │  1. Read VPC A's route table                       │
  │  2. Check Security Groups                           │
  │  3. Apply NACLs                                    │
  │  4. Encapsulate with VPC overlay headers           │
  │  5. Forward on AWS fabric                          │
  │                                                     │
  │  Packet cannot be intercepted by other VMs on     │
  │  this physical server — Nitro handles this         │
  └─────────────────────────────────────────────────────┘
```

The isolation is enforced in hardware, not just software. A guest VM kernel compromise cannot bypass VPC security groups because the enforcement is in the Nitro card, not in the guest.

---

### VPC Flow Logs — The Data Record

VPC Flow Logs capture metadata about network flows:

```
version  account-id  interface-id  srcaddr        dstaddr       srcport  dstport  protocol  packets  bytes  start       end         action  log-status
2        123456789   eni-abc123    203.0.113.5    10.0.1.100    49821    443      6         10       5000   1700000000  1700000060  ACCEPT  OK
2        123456789   eni-abc123    10.0.10.5      10.0.1.100    58291    443      6         8        4200   1700000001  1700000061  ACCEPT  OK
2        123456789   eni-def456    10.0.99.1      10.0.10.5     40000    22       6         2        120    1700000000  1700000002  REJECT  OK
```

The REJECT entry: Someone tried to SSH (port 22) from 10.0.99.1 to the app server. Security Group blocked it. This is logged but the connection was refused. Important for detecting unauthorized access attempts.

**Flow log destinations:**
- S3: Cheapest, highest latency for querying
- CloudWatch Logs: Moderate cost, queryable with Logs Insights
- Kinesis Data Firehose: Lowest latency, near-real-time to S3/Elasticsearch

---

## 7. Security Controls

### Security Group Best Practices

**The principle of least privilege applied to Security Groups:**

```python
# ALB Security Group
ALB_SG = SecurityGroup(
    id="alb-sg",
    ingress=[
        # Only allow HTTPS from internet
        Rule(port=443, source="0.0.0.0/0"),
        # HTTP redirect from internet (redirect to HTTPS)
        Rule(port=80, source="0.0.0.0/0"),
        # NO SSH, NO other ports
    ],
    egress=[
        # Allow to app servers only (NOT 0.0.0.0/0)
        Rule(port=8080, destination=APP_SG),
        Rule(port=8443, destination=APP_SG),  # If backend uses HTTPS
        # NO outbound internet (ALB doesn't need it)
    ]
)

# App Server Security Group
APP_SG = SecurityGroup(
    id="app-sg",
    ingress=[
        # Only from ALB (not from internet, not from 10.0.0.0/16 generically)
        Rule(port=8080, source=ALB_SG),
        # SSH only from Bastion/SSM (or just use SSM and skip SSH entirely)
        # Rule(port=22, source=BASTION_SG),  # If using bastion
        # NO SSH — use SSM Session Manager instead (no port 22 needed!)
    ],
    egress=[
        # DB access
        Rule(port=5432, destination=DB_SG),
        # Redis/ElastiCache
        Rule(port=6379, destination=REDIS_SG),
        # HTTPS for external API calls via NAT Gateway
        Rule(port=443, destination="0.0.0.0/0"),
        # SQS via VPC Endpoint (if not using endpoint, needs 443 to internet)
        Rule(port=443, destination=SQS_ENDPOINT_SG),
    ]
)

# DB Security Group
DB_SG = SecurityGroup(
    id="db-sg",
    ingress=[
        # ONLY from app servers
        Rule(port=5432, source=APP_SG),
        # NO other access — not from bastion, not from admin IPs
        # (Use RDS Proxy or direct app connections; admin via RDS Console/DMS)
    ],
    egress=[
        # NO outbound needed for RDS (it never initiates connections)
        # RDS replication handles itself internally within AWS
    ]
)
```

---

### AWS PrivateLink — Private Connectivity to SaaS

For connecting to third-party SaaS services without internet exposure:

```
WITHOUT PrivateLink:
  Your EC2 → NAT Gateway → Internet → Salesforce/Snowflake/etc.
  
  Problems:
  - Traffic traverses public internet
  - Need internet access in Security Group
  - Data transfer costs through NAT

WITH PrivateLink:
  Your EC2 → Interface VPC Endpoint (private IP in your VPC) → AWS backbone → SaaS VPC
  
  Benefits:
  - Traffic stays on AWS backbone (never hits internet)
  - Source IP is private VPC IP (not NAT Gateway public IP)
  - Better security posture
  - Endpoint policies restrict what you can access
```

---

### Encryption Controls

**Data in transit within the VPC:**

```
Despite being "private," traffic within VPC should be encrypted:

ALB to App Server:
  - Default: HTTP (cleartext within VPC)
  - SHOULD BE: HTTPS with ACM certificate on the app server
  - Or: Use ALB → NLB → App Server with passthrough TLS

App Server to RDS:
  - Default: SSL/TLS enforced by RDS parameter group
  - Parameter: rds.force_ssl = 1
  - Certificate: RDS uses Amazon-signed cert, app verifies with ssl_mode=verify-full
  - Why encrypt internal traffic? If an attacker gains access to the VPC
    (via a compromised EC2 in the same VPC), they cannot sniff DB traffic

App Server to Redis (ElastiCache):
  - ElastiCache Redis: Enable in-transit encryption
  - Requires Redis AUTH token (password)
  - TLS between app and Redis cluster

Within-AZ traffic:
  AWS encrypts traffic between instances in the same AZ by default
  (Nitro-based instances use hardware-level encryption for all traffic)
```

**Data at rest:**

```
RDS:
  - Storage encrypted with KMS (AES-256)
  - Option: Customer-managed KMS key (CMK) for regulatory compliance
  - Automated backups inherit encryption from the DB

EBS volumes (app server disks):
  - Encrypted by default (set at account level: enforce EBS encryption)
  - KMS-managed key

S3 buckets:
  - SSE-S3 (managed by AWS, no cost)
  - SSE-KMS (customer-managed key, $0.03/10,000 requests)
  - SSE-C (customer-provided key — app manages keys)
```

---

### Secrets Management Within the VPC

**AWS Secrets Manager (preferred):**
```
Process:
  1. Store database password in Secrets Manager
  2. Attach IAM policy to app-server-role:
     Action: secretsmanager:GetSecretValue
     Resource: arn:aws:secretsmanager:us-east-1:123456789:secret:prod/rds/password
  
  3. App server fetches secret at startup or on-demand:
     secret = boto3.client('secretsmanager').get_secret_value(
         SecretId='prod/rds/password'
     )
     db_password = secret['SecretString']
  
  4. Secrets Manager rotates the password automatically every 30 days
     - Rotation Lambda connects to RDS and updates the password
     - Old and new password are both valid during the rotation window
     - App SDK caches the secret for 5 minutes, then re-fetches
  
  5. Access via VPC Endpoint (no internet needed for this critical operation):
     Interface Endpoint for secretsmanager
     DNS: secretsmanager.us-east-1.amazonaws.com → 10.0.10.250 (private)
```

**AWS Systems Manager Parameter Store (for less sensitive config):**
```
Hierarchy:
  /app/prod/db/host  → rds-cluster.xxxxxx.us-east-1.rds.amazonaws.com
  /app/prod/db/port  → 5432
  /app/prod/feature-flag/new-ui → true

SecureString type for passwords (KMS-encrypted)
Standard Tier: Free
Advanced Tier: $0.05/parameter/month (needed for more than 10,000 parameters)
```

---

## 8. Attack Surface Mapping

### All Entry Points

```
EXTERNAL (Internet-Accessible):
════════════════════════════════════════════════════════════════

[E1] Internet Gateway → ALB
  - Every request from the internet enters via the IGW
  - ALB has Security Group: TCP 443, TCP 80 from 0.0.0.0/0
  - Attack surface: DDoS, web application attacks, TLS downgrade attempts

[E2] Bastion Host (if present)
  - SSH access point: TCP 22 from restricted IP ranges
  - High-value target: successful attack = VPC access
  - Alternative: AWS SSM Session Manager (no bastion needed)

[E3] Public EC2 Instances (if any)
  - Instances with Elastic IPs in public subnets
  - Reachable directly from internet
  - Should be minimized (ideally none except ALB/NAT)

[E4] VPN Endpoints
  - AWS Client VPN or Site-to-Site VPN
  - Attack surface: VPN credential theft, certificate abuse

INTERNAL (Within VPC or Peered VPCs):
════════════════════════════════════════════════════════════════

[I1] EC2 Metadata Service (169.254.169.254)
  - Accessible from any EC2 instance
  - Contains IAM credentials, instance configuration
  - SSRF vulnerability can expose credentials

[I2] Internal VPC DNS (10.0.0.2 or 169.254.169.253)
  - DNS queries from all EC2 instances
  - DNS poisoning via Route 53 private zone misconfiguration

[I3] Inter-Service Traffic (App → DB, App → Redis)
  - Lateral movement if one service is compromised
  - Network-level attack (if encryption disabled)

[I4] VPC Peering Connections
  - If peering is too permissive, a compromised VPC can pivot
  - Route tables and Security Groups must restrict access

[I5] Transit Gateway Attachments
  - Multiple VPCs connected via TGW
  - Route table misconfiguration = unintended VPC-to-VPC access

[I6] AWS Service Endpoints (from inside the VPC)
  - Lambda, SQS, SNS, S3 etc. via VPC Endpoints
  - If endpoint policy is too permissive: access to other accounts' resources
```

### Attack Surface Diagram

```
                    ┌────────────────────────────────────────────────────────┐
                    │                 EXTERNAL ATTACK SURFACE                │
                    │  [E1] IGW/ALB  [E2] Bastion  [E3] Public EC2          │
                    │  [E4] VPN Endpoint                                      │
                    └──────────────────────────┬─────────────────────────────┘
                                               │ Internet
                                               │
                    ┌──────────────────────────▼─────────────────────────────┐
                    │  Internet Gateway [TB-1]                               │
                    │  1:1 NAT for EIPs, No security policy of its own      │
                    │  Security enforced at the ENI level (Security Groups) │
                    └──────────────────────────┬─────────────────────────────┘
                                               │
                    ┌──────────────────────────▼─────────────────────────────┐
                    │  PUBLIC SUBNET [TB-2]                                  │
                    │  ALB (alb-sg: allow 443,80 from 0.0.0.0/0)           │
                    │  NAT Gateway (managed by AWS)                          │
                    │  Bastion (if present: ssh from office IPs only)       │
                    └──────────────────────────┬─────────────────────────────┘
                                               │ app-sg: allow 8080 from alb-sg
                    ┌──────────────────────────▼─────────────────────────────┐
                    │  PRIVATE APP SUBNET [TB-3]                            │
                    │  EC2 App Servers (app-sg)                             │
                    │  [I1] IMDS: 169.254.169.254 → IAM credentials         │
                    │  [I5] Outbound via NAT: external API calls            │
                    │  [I6] VPC Endpoints: S3, SQS, Secrets Manager        │
                    └──────────────────────────┬─────────────────────────────┘
                                               │ db-sg: allow 5432 from app-sg
                    ┌──────────────────────────▼─────────────────────────────┐
                    │  PRIVATE DATA SUBNET [TB-4]                           │
                    │  RDS (db-sg: allow 5432 from app-sg ONLY)            │
                    │  ElastiCache (redis-sg: allow 6379 from app-sg ONLY) │
                    │  NO internet access (no 0.0.0.0/0 route)            │
                    └─────────────────────────────────────────────────────────┘

TRUST BOUNDARIES:
  [TB-1] Internet → IGW: Zero trust. NAT only.
  [TB-2] IGW → Public Subnet: ALB accepts all internet, NAT for outbound.
  [TB-3] Public → Private App: Only ALB traffic allowed.
  [TB-4] Private App → Data: Only app servers allowed.
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — Security Group Misconfigurations — The "0.0.0.0/0" Problem

**Attacker Assumptions:**
- An engineer opened port 22 (SSH) from 0.0.0.0/0 on an app server's Security Group "temporarily" to debug a production issue
- The rule was never removed
- The EC2 instance has an associated Elastic IP (so it's internet-reachable)
- SSH is using password authentication (not key-only)

**Step-by-Step Execution:**

1. Attacker runs an internet-wide scanner (e.g., Shodan, Masscan) looking for port 22 on AWS IP ranges.

2. Attacker discovers `54.89.YY.ZZ:22` is open. SSH banner reveals `Ubuntu 22.04`.

3. Attacker runs a dictionary attack against common usernames (ubuntu, ec2-user, admin) with weak passwords or tries leaked credential lists.

4. If the EC2 uses password auth OR if the key pair was stored insecurely (e.g., in the repo), the attacker gains SSH access.

5. Now inside the EC2:
   ```bash
   # Enumerate the environment
   curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
   # Returns: app-server-role
   
   curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/app-server-role
   # Returns: AccessKeyId, SecretAccessKey, Token
   ```

6. Attacker now has AWS credentials with app-server-role permissions.

7. From these credentials, attacker can:
   - Read from S3 buckets the role can access
   - Send messages to SQS queues (potentially inject malicious jobs)
   - Query Secrets Manager for database passwords
   - Connect to RDS (since they're on the app server — DB Security Group allows app-sg)

**Where Detection Could Happen:**
- VPC Flow Logs: port 22 traffic from unusual internet IPs
- CloudTrail: `GetSecretValue` API call from an unusual source
- GuardDuty: "UnauthorizedAccess:IAMUser/MaliciousIPCaller" finding
- Failed SSH attempts: many authentication failures before success

**Why This Works:**
The Security Group was "temporarily" opened. The engineer meant to close it. But there's no automated enforcement. AWS doesn't expire Security Group rules. Without continuous monitoring or IaC enforcement (Security Groups defined in Terraform, any manual changes trigger alerts), temporary rules become permanent.

---

### 9.2 — SSRF to IAM Credential Theft

**Attacker Assumptions:**
- The application has an SSRF vulnerability (URL-fetching endpoint)
- The EC2 instance uses IMDSv1 (no token required)
- The IAM role has access to sensitive resources

**Step-by-Step Execution:**

1. Attacker discovers SSRF in the application's link preview feature:
   ```
   POST /api/preview
   {"url": "https://external-site.com/page"}
   → Server fetches this URL and returns page preview
   ```

2. Attacker substitutes the EC2 metadata URL:
   ```
   POST /api/preview
   {"url": "http://169.254.169.254/latest/meta-data/"}
   → Returns: ami-id\nhostname\niam\n...
   ```

3. Attacker navigates to IAM credentials:
   ```
   {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-server-role"}
   → Returns JSON with AccessKeyId, SecretAccessKey, Token
   ```

4. Attacker uses these credentials from outside AWS:
   ```bash
   AWS_ACCESS_KEY_ID=ASIA... \
   AWS_SECRET_ACCESS_KEY=... \
   AWS_SESSION_TOKEN=... \
   aws s3 ls s3://company-data-bucket/
   ```

5. Attacker can now exfiltrate data, read secrets, or pivot to other AWS services.

**Detection:**
- GuardDuty: Detects IAM credentials used from an IP outside AWS (if you normally only use from EC2)
- IMDS access logging (IMDSv2 with CloudTrail enabled)
- Application-level logging: unexpected URLs in the preview endpoint
- WAF rule: block requests to 169.254.169.254 in URL parameters

**Mitigation:**
```bash
# Enforce IMDSv2 — requires PUT token before credential access
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxx \
  --http-tokens required \
  --http-put-response-hop-limit 1

# With IMDSv2, the SSRF attack fails because:
# The attacker would need to make a PUT request first (not supported by most SSRF)
# Even if PUT is possible, the hop limit of 1 prevents container-to-host metadata access
```

---

### 9.3 — VPC Peering Lateral Movement

**Attacker Assumptions:**
- Company has two VPCs: Production (10.0.0.0/16) and Dev (10.2.0.0/16)
- A VPC peering connection exists between them
- Route tables allow FULL access between VPCs (10.2.0.0/16 → peering connection in Production routes)
- Dev VPC has weaker security (developer laptops can SSH in, test data, etc.)
- Production has the actual customer data

**Step-by-Step Execution:**

1. Attacker compromises a developer's laptop (phishing, or directly compromises a Dev EC2 instance).

2. From the compromised machine in Dev VPC (10.2.5.5):
   ```bash
   # Check routing — is Production VPC accessible?
   ip route show  # Shows 10.0.0.0/16 via 10.2.0.1 (VPC router via peering)
   ```

3. Scan Production VPC from Dev:
   ```bash
   nmap -p 5432 10.0.20.0/24  # Scan for databases in Production
   # Result: 10.0.20.10:5432 open
   ```

4. If the Production DB Security Group allows traffic from `10.2.0.0/16` (the Dev VPC CIDR):
   ```bash
   psql -h 10.0.20.10 -U app_user -d production_db
   # Prompt: password?
   ```

5. Attacker may already have credentials (from secrets stored in Dev environment, or can try credential stuffing).

**Why This Works:**
VPC peering allows routing between VPCs, but doesn't automatically restrict what traffic can flow. Engineers configure peering for convenience ("Dev needs to read from Production") but configure Security Groups too broadly (allow from entire Dev CIDR instead of specific Dev services).

**Detection:**
- VPC Flow Logs: unusual connections from 10.2.0.0/16 to 10.0.20.0/24 (dev → prod DB)
- GuardDuty: network scanning from internal IP ranges (Recon:EC2/PortProbeUnprotectedPort)
- Alert: any connection from Dev VPC IPs to Production DB Security Group

**Prevention:**
```
1. Restrict Security Group rules to specific IPs or Security Groups:
   DB-SG inbound: allow 5432 from APP_SG (not from 10.2.0.0/16)
   Since DEV VPC resources don't have APP_SG, they can't reach the DB

2. Use Transit Gateway route tables to block Dev → Production data subnet:
   TGW Route Table "production":
     10.0.0.0/16 → VPC A attachment (production)
     # No route for 10.0.20.0/24 from Dev VPC
     # Dev can only reach Production's 10.0.0.0/24 (public web tier) but not data tier

3. Separate AWS accounts for production and dev:
   Cannot peer across accounts without explicit cross-account peering
   Provides strongest isolation
```

---

### 9.4 — BGP Route Hijacking (External, Affects AWS)

**Background:** BGP (Border Gateway Protocol) is how the internet routes traffic. AWS advertises its IP ranges via BGP. A sophisticated attacker with access to a BGP-speaking router can advertise more-specific routes than AWS, attracting traffic to themselves.

**Attacker Assumptions:**
- Attacker has compromised a Tier-2 ISP or has illegitimate access to BGP routing infrastructure
- Target: intercept traffic to an AWS Elastic IP (the ALB's public IP)

**Step-by-Step Execution:**

1. AWS announces: `54.89.0.0/16` belongs to AWS us-east-1 (aggregate route)

2. Attacker announces (via compromised ISP): `54.89.XX.0/24` belongs to attacker (more specific route)

3. BGP longest-prefix match: `/24` beats `/16`. Traffic for `54.89.XX.YY` (the ALB) goes to the attacker.

4. Attacker now sees the TCP SYN packets from clients trying to connect to the ALB.

5. If TLS is NOT properly validated (certificate pinning or if users ignore cert warnings):
   Attacker can MITM the connection — present their own certificate and decrypt traffic.

6. With valid TLS (which it should be): 
   Attacker sees only encrypted TCP packets. Cannot decrypt (no private key for app.example.com).
   TLS certificate validation fails on the client (wrong certificate).
   Client sees: "Your connection is not private" warning.

**Why This Doesn't Fully Work Against Proper TLS:**
TLS protects the content even against BGP hijacking. The attacker sees encrypted bytes. Certificate validation alerts users that something is wrong. This attack is most effective against HTTP (no TLS) or when users ignore certificate warnings.

**Defensive Mitigations:**
1. HSTS (HTTP Strict Transport Security): Browser remembers to always use HTTPS for this domain
2. HSTS Preloading: Hardcoded into browsers — even a first connection knows to use HTTPS
3. Certificate Transparency: If an attacker gets a fraudulent cert issued, CT logs record it
4. RPKI (Resource Public Key Infrastructure): BGP route origin validation — AWS uses this to protect their prefixes

---

### 9.5 — Misconfigured S3 Bucket Accessible Within VPC

**Attacker Assumptions:**
- An S3 bucket is meant to be accessible ONLY from the VPC (VPC Endpoint Policy restricts access)
- However, the bucket policy was accidentally set to "public read"
- Sensitive company data is in the bucket

**Step-by-Step Execution:**

1. Security engineer set up a VPC Endpoint for S3 with a restrictive policy:
   ```json
   {
     "Statement": [{
       "Effect": "Allow",
       "Principal": "*",
       "Action": "s3:GetObject",
       "Resource": "arn:aws:s3:::company-data/*",
       "Condition": {
         "StringEquals": {"aws:sourceVpc": "vpc-12345678"}
       }
     }]
   }
   ```

2. BUT the bucket itself has this policy (a mistake by another engineer):
   ```json
   {
     "Statement": [{
       "Effect": "Allow",
       "Principal": "*",
       "Action": "s3:GetObject",
       "Resource": "arn:aws:s3:::company-data/*"
     }]
   }
   ```

3. The bucket policy wins. `Principal: *` with no conditions = anyone on the internet can read.

4. Attacker (outside the VPC, anywhere on internet) accesses:
   ```bash
   aws s3 ls s3://company-data/ --no-sign-request  # No credentials needed!
   aws s3 cp s3://company-data/customers.csv . --no-sign-request
   ```

**Why the VPC Endpoint Policy Didn't Help:**
VPC Endpoint Policies are "gateway" policies — they restrict what can flow through the endpoint. They don't make the S3 bucket more secure from other paths. The bucket was accessible via the public internet endpoint even though the VPC endpoint was restricted.

**Detection:**
- S3 Server Access Logs: requests from IPs not in your VPC CIDR
- CloudTrail: S3 GetObject calls with no AWS credentials (anonymous access)
- AWS Trusted Advisor: bucket with public access warning
- AWS Config Rule: `s3-bucket-public-access-prohibited`

**Prevention:**
```
1. S3 Block Public Access at the account level:
   aws s3control put-public-access-block \
     --account-id 123456789012 \
     --public-access-block-configuration \
     "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
   
   This overrides bucket policies that try to grant public access.
   If enabled: Even if bucket policy says "Principal: *", AWS blocks it.

2. Defense in depth: both bucket policy AND VPC endpoint policy should be restrictive.
   The bucket policy restricts who can access at the S3 layer.
   The VPC endpoint policy restricts what can flow through the endpoint.
```

---

## 10. Failure Points

### Under Load

**NAT Gateway bandwidth limits:**
```
NAT Gateway maximum throughput: 45 Gbps
NAT Gateway maximum connections: 55,000 simultaneous (per NAT GW)

At scale:
  1,000 EC2 instances each making 100 outbound connections = 100,000 connections
  This exceeds the 55,000 limit!
  
  Symptom: "Port allocation failed" errors in NAT Gateway metrics
  Fix: Multiple NAT Gateways per AZ, spread app servers across different subnets
       each with their own NAT Gateway

  Alternative: Use Private Link or VPC Endpoints to reduce NAT traffic
  (Internal AWS traffic doesn't count against NAT connection limits)
```

**Security Group rule limits:**
```
Default limits:
  - 5 Security Groups per ENI
  - 60 inbound rules per Security Group (60 outbound)
  - Total: 300 inbound rules across all Security Groups on one ENI

At scale:
  A shared service (RDS) needs to accept from 200 different Security Groups
  Solution: Use a "Security Group chain" — create an intermediate SG
            that all callers reference, then DB_SG allows from that intermediate SG
  Or: Use IP prefix lists with managed prefix lists
```

**VPC Endpoint scalability:**
```
Interface VPC Endpoints create ENIs in your subnet
Each ENI uses an IP from your subnet's CIDR range

/24 subnet = 256 IPs - 5 reserved = 251 usable
If you create 30 Interface Endpoints × 2 AZs = 60 ENIs
+ EC2 instances consuming IPs
= May run out of IP addresses in the subnet

Fix: Use /23 or larger subnets for endpoint-heavy deployments
     Or: Assign dedicated subnets for VPC Endpoints
```

---

### Under Attack

**DDoS against the ALB:**

```
Attack: SYN flood targeting 54.89.XX.YY:443

Without protection:
  ALB's connection table fills with half-open TCP connections
  Legitimate connections fail: "connection reset" or timeout
  ALB CPU/memory exhausted

With AWS Shield Standard (included):
  AWS absorbs volumetric DDoS at the internet edge
  SYN cookies prevent half-open connection table exhaustion
  Traffic scrubbing at AWS edge before reaching your ALB

With AWS Shield Advanced:
  Dedicated DDoS response team
  Cost protection (no billing for ALB/NAT data processing during attack)
  WAF integration for Layer 7 (application layer) attacks
  Real-time attack notification and diagnostics
```

**Security Group evaluation limits under port scan:**

```
Port scan: Attacker sends SYN to 65,535 ports on your EC2
  
Each packet:
  1. Arrives at EC2 ENI
  2. Security Group evaluated: Is this allowed?
  3. If not: Packet dropped (SG is stateless for drops — no RST sent)
  4. Attacker sees: no response = port closed or filtered
  
Performance impact:
  Security Group evaluation is in the Nitro card (hardware)
  No CPU impact on the EC2 instance
  But: creates noise in VPC Flow Logs (if capturing all rejected traffic)
```

---

### Common Misconfigurations

| Misconfiguration | Impact | Fix |
|---|---|---|
| `0.0.0.0/0` in Security Group for SSH/RDP | Internet-accessible admin ports | Use SSM Session Manager, remove port 22/3389 rules |
| VPC peering without subnet-level restrictions | Lateral movement between VPCs | Use Transit Gateway with route table restrictions |
| IMDSv1 enabled | SSRF → IAM credential theft | Enforce IMDSv2 on all instances |
| S3 public read with sensitive data | Data exposure | S3 Block Public Access at account level |
| No VPC Flow Logs | Can't investigate incidents | Enable Flow Logs to S3 or CloudWatch |
| DB Security Group allows from entire VPC CIDR | Any VPC resource can reach DB | Allow only specific app-sg, not 10.0.0.0/16 |
| Single NAT Gateway for all AZs | AZ failure = no internet for other AZs | One NAT Gateway per AZ |
| Default VPC in use | Insecure defaults, overlapping CIDR | Use custom VPC, delete default VPC |
| No egress filtering | Malware can call home freely | Firewall (AWS Network Firewall, proxy) for egress |
| VPC endpoint policy `Principal: *` | Any AWS account can use your endpoint | Restrict to your account ID or specific roles |
| Overly broad IAM role for EC2 | EC2 compromise = full AWS access | Least-privilege IAM, specific resource ARNs |

---

## 11. Mitigations

### Defense-in-Depth for VPC Security

**Layer 1: Account and Region Level**
```
- AWS Organizations SCP: Prevent deletion of VPC Flow Logs
- AWS Config: Continuous compliance monitoring
  Rule: restricted-ssh (alert if port 22 open to 0.0.0.0/0)
  Rule: vpc-default-security-group-closed (default SG has no rules)
  Rule: s3-bucket-public-access-prohibited
- AWS Security Hub: Aggregates findings from GuardDuty, Config, IAM Analyzer
- AWS CloudTrail: All API calls logged (who changed what Security Group, when)
- Control Tower: Landing zone with guardrails
```

**Layer 2: VPC Design**
```
- No default VPC (delete it or never use it)
- Custom VPC with non-overlapping CIDR (important for future peering)
- Multiple AZs for all tiers
- Private subnets for everything except ALB and NAT Gateway
- Data subnet has NO internet route (no 0.0.0.0/0 in route table)
- AWS Network Firewall for egress filtering (replaces complex SG rules for outbound)
```

**Layer 3: Security Groups (Zero Trust)**
```
- ALB: 443 from 0.0.0.0/0 ONLY
- App Tier: 8080 from ALB-SG ONLY
- DB Tier: 5432 from App-SG ONLY
- No Security Group allows SSH from 0.0.0.0/0
- All admin access via SSM Session Manager (no SSH key management)
- Use IaC (Terraform/CDK) for all Security Groups; manual changes trigger alerts
```

**Layer 4: Instance Level**
```
- IMDSv2 required on all EC2 instances
- No long-term IAM credentials on EC2 (use instance profiles)
- Least-privilege IAM roles (specific ARNs, not *)
- EBS encryption by default (AWS Config rule enforces)
- SSM Agent installed; no SSH keys (rotate IAM instead of key pairs)
- SELinux or AppArmor for additional OS-level isolation
```

**Layer 5: Monitoring and Response**
```
- VPC Flow Logs → Kinesis → Elasticsearch for real-time analysis
- GuardDuty enabled in all accounts/regions
  - Detects: unusual API calls, port scans, cryptocurrency mining
- AWS WAF on ALB:
  - Managed rule groups (OWASP Top 10, AWS managed rules)
  - Rate limiting rules (1000 req/5min per IP)
  - Geo-blocking if applicable
- CloudTrail + EventBridge:
  - Alert on: Security Group rule changes, new VPC peering connections
  - Alert on: IAM role policy changes, new IAM users with console access
```

---

### Engineering Tradeoffs

| Control | Security Benefit | Engineering Cost | Operational Impact |
|---|---|---|---|
| IMDSv2 required | SSRF→credential theft mitigated | Application code change to use token | Applications must handle token refresh |
| Delete default VPC | Prevents accidental deployment to it | One-time task | Engineers must use custom VPC |
| VPC Endpoints for all AWS services | No internet needed, cost savings | $0.01/hour per AZ per service | Setup complexity, multiple endpoints |
| Multi-AZ NAT Gateways | AZ failure resilience | 2x NAT Gateway cost (~$65/month) | None (transparent to apps) |
| AWS Network Firewall for egress | Centralized egress control, DLP | $0.395/hour + $0.065/GB | Latency for all egress traffic |
| GuardDuty | Automatic threat detection | ~$3-4/million VPC Flow events | Investigate alerts (false positive tuning) |
| SSM instead of SSH | No port 22 required, audited sessions | SSM agent install, IAM config | Slightly different workflow for ops |

---

## 12. Observability

### VPC Flow Logs — The Primary Data Source

VPC Flow Logs are essential for VPC security monitoring. Configure at the VPC level (captures all ENIs):

```bash
# Enable VPC Flow Logs to S3 (cheapest):
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-12345678 \
  --traffic-type ALL \  # Capture ACCEPT and REJECT (don't use ACCEPT-only!)
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::company-vpc-flowlogs/

# Custom format for richer data:
aws ec2 create-flow-logs \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${sublocation-id}'
```

**What to look for in flow logs:**

```python
# High-value queries on flow log data (AWS Athena):

-- Port scans: one source hitting many ports
SELECT srcaddr, COUNT(DISTINCT dstport) as ports_scanned
FROM vpc_flow_logs
WHERE action = 'REJECT' 
  AND start > UNIX_TIMESTAMP(NOW() - INTERVAL 1 HOUR)
GROUP BY srcaddr
HAVING ports_scanned > 100
ORDER BY ports_scanned DESC;

-- Unusual outbound connections from app servers
SELECT srcaddr, dstaddr, dstport, bytes
FROM vpc_flow_logs
WHERE srcaddr LIKE '10.0.10.%'  -- app subnet
  AND dstaddr NOT LIKE '10.0.%'  -- NOT going to internal
  AND dstaddr != '169.254.%'      -- NOT metadata
  AND dstport NOT IN (443, 80)    -- NOT expected HTTPS/HTTP
  AND action = 'ACCEPT';

-- Data exfiltration indicator: large outbound bytes to unusual destination
SELECT srcaddr, dstaddr, SUM(bytes) as total_bytes
FROM vpc_flow_logs  
WHERE srcaddr LIKE '10.0.%'
  AND bytes > 1000000  -- More than 1 MB per connection
  AND action = 'ACCEPT'
GROUP BY srcaddr, dstaddr
ORDER BY total_bytes DESC;
```

---

### CloudTrail — API Call Auditing

Every AWS API call within the VPC's account is logged in CloudTrail:

```json
{
  "eventTime": "2024-11-15T10:30:45Z",
  "eventName": "AuthorizeSecurityGroupIngress",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "john.engineer@example.com"
  },
  "sourceIPAddress": "203.0.113.10",  // Engineer's IP
  "requestParameters": {
    "groupId": "sg-12345678",         // Which Security Group
    "ipPermissions": {
      "items": [{
        "ipProtocol": "tcp",
        "fromPort": 22,
        "toPort": 22,
        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}  // THE BAD RULE
      }]
    }
  }
}
```

**EventBridge rule to alert on this:**
```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["AuthorizeSecurityGroupIngress"],
    "requestParameters": {
      "ipPermissions": {
        "items": {
          "ipRanges": {
            "items": {
              "cidrIp": ["0.0.0.0/0", "::/0"]
            }
          }
        }
      }
    }
  }
}
```

This rule fires whenever ANYONE adds a Security Group rule allowing all internet access. The EventBridge target sends a Slack alert + creates a ticket for immediate review.

---

### Metrics and Alerting

```
ALB Metrics (CloudWatch):
  HTTPCode_ELB_5XX_Count    → Alert if > 10 per minute (server errors)
  TargetResponseTime        → Alert if p99 > 2 seconds
  UnHealthyHostCount        → Alert if > 0 (any unhealthy targets)
  ActiveConnectionCount     → Monitor for DDoS (sudden spike)
  ProcessedBytes            → Monitor for data exfiltration (unusual spike)

NAT Gateway Metrics:
  BytesOutToDestination     → Alert if spike (unusual outbound traffic)
  ErrorPortAllocation       → Alert if > 0 (connection limits hit)
  ActiveConnectionCount     → Monitor for anomalies

VPC Flow Metrics (custom from Athena/CloudWatch Logs Insights):
  RejectedPackets by source    → Detect port scans
  Cross-AZ traffic bytes       → Cost monitoring
  Unusual port activity        → Security monitoring

RDS Metrics:
  DatabaseConnections        → Alert if near max_connections
  ReadLatency, WriteLatency  → Performance alerts
  FreeStorageSpace           → Alert at 20% remaining
```

---

### GuardDuty — Automatic Threat Detection

GuardDuty analyzes VPC Flow Logs, CloudTrail, and DNS logs automatically:

```
High-Priority GuardDuty Findings (should auto-respond):
  
  Backdoor:EC2/C&CActivity.B
    → Your EC2 is communicating with known C&C infrastructure
    → Auto-response: Isolate instance (update SG to deny all), snapshot for forensics
  
  CryptoCurrency:EC2/BitcoinTool.B
    → Cryptomining detected (outbound to mining pools)
    → Auto-response: Terminate instance, alert security team
  
  UnauthorizedAccess:IAMUser/MaliciousIPCaller
    → Your IAM credentials used from known malicious IP
    → Auto-response: Revoke all sessions for this role, rotate credentials

Medium-Priority (investigate within 24 hours):
  
  Recon:EC2/PortProbeUnprotectedPort
    → Port scanning detected against your instances
    → Review Flow Logs for scope, check if firewall is needed
  
  Stealth:IAMUser/CloudTrailLoggingDisabled
    → Someone disabled CloudTrail (hiding their tracks?)
    → Immediate investigation + re-enable CloudTrail
```

**Lambda for automated response:**
```python
def auto_isolate_ec2(instance_id):
    """Isolate a compromised EC2 instance by replacing its Security Groups."""
    
    # Create a "quarantine" Security Group with no rules
    quarantine_sg = ec2.create_security_group(
        GroupName=f'quarantine-{instance_id}-{int(time.time())}',
        Description=f'Quarantine SG for compromised instance {instance_id}',
        VpcId=get_instance_vpc_id(instance_id)
    )
    
    # Replace the instance's Security Groups with quarantine SG
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[quarantine_sg['GroupId']]
    )
    
    # Snapshot the instance for forensics
    ec2.create_snapshot(
        VolumeId=get_instance_volume_id(instance_id),
        Description=f'Forensic snapshot of compromised instance {instance_id}'
    )
    
    # Notify security team
    sns.publish(
        TopicArn=SECURITY_ALERTS_TOPIC,
        Subject=f'EC2 Instance Isolated: {instance_id}',
        Message=f'Instance {instance_id} has been isolated due to GuardDuty finding'
    )
```

---

## 13. Scaling Considerations

### VPC CIDR Planning

**The biggest mistake:** Choosing too small a CIDR block. You cannot shrink or easily expand a VPC CIDR after creation (you can add secondary CIDRs, but they're messy).

```
Bad: VPC CIDR 10.0.0.0/24 (254 hosts)
  /28 subnets: 16 IPs each (-5 reserved = 11 usable)
  Very quickly runs out of IP space for:
  - EC2 instances
  - VPC Interface Endpoints (each consumes an IP per AZ)
  - RDS instances
  - ElastiCache nodes
  - Lambda in VPC (each concurrent execution consumes an IP!)

Better: VPC CIDR 10.0.0.0/16 (65,534 hosts)
  Plenty of room for all resources
  Can create /24 subnets (251 usable IPs each)
  Room for expansion

Enterprise: VPC CIDR 10.0.0.0/8 (16 million hosts) across a Transit Gateway
  Different VPCs use different /16 ranges:
    Production:     10.0.0.0/16
    Staging:        10.1.0.0/16
    Dev:            10.2.0.0/16
    Shared Services: 10.3.0.0/16
  Non-overlapping = can peer any combination without conflicts
```

---

### Auto Scaling and the VPC

EC2 Auto Scaling groups respect AZ balance and subnet capacity:

```
Auto Scaling Group configuration:
  Subnets: [10.0.10.0/24 (AZ-a), 10.0.11.0/24 (AZ-b)]
  Min: 2, Desired: 4, Max: 20
  
  Scale-out: ASG launches instances, alternating between AZs for balance
    New instance in 10.0.10.0/24 (AZ-a): gets 10.0.10.22
    New instance in 10.0.11.0/24 (AZ-b): gets 10.0.11.15
  
  Scale-in: ASG terminates instances, rebalancing AZs
    ALB connection draining: existing connections complete before termination

Subnet IP address exhaustion scenario:
  10.0.10.0/24 has 251 usable IPs
  Auto Scaling launches 200 instances in AZ-a → 51 IPs left
  VPC Endpoint ENIs consume more IPs
  New instances fail to launch: "InsufficientFreeAddressesInSubnet"
  
  Fix: Use larger subnets (/23 = 507 usable IPs)
       Or: Configure ASG to use multiple subnets per AZ
```

---

### Transit Gateway for Scaling to Many VPCs

```
When VPC peering breaks down (N*(N-1)/2 connections for N VPCs):
  10 VPCs = 45 peering connections
  50 VPCs = 1225 peering connections
  This doesn't scale.

Transit Gateway solution:
  Each VPC has ONE attachment to the TGW
  TGW handles all routing between VPCs
  
  Scaling limits:
  - TGW max bandwidth: 50 Gbps per attachment
  - TGW max attachments: 5,000
  - TGW max route table entries: 10,000

  Segmentation:
  TGW Route Table "Production":
    10.0.0.0/16 → Production VPC attachment
    10.3.0.0/16 → Shared Services VPC attachment
    (No Dev routes → Dev cannot reach Production)
  
  TGW Route Table "Development":
    10.2.0.0/16 → Dev VPC attachment
    10.3.0.0/16 → Shared Services VPC attachment
    (No Production routes → Dev cannot reach Production)

  Cost: $0.05/attachment/hour + $0.02/GB processed
```

---

### Consistency Tradeoffs: Cross-Region Architectures

```
Single-Region VPC:
  ✓ Lowest latency for within-region communication
  ✓ Simple architecture
  ✗ Region failure = complete outage
  ✗ No geographic data residency

Multi-Region VPC:
  VPC in us-east-1 + VPC in eu-west-1
  Connected via: Global Accelerator, CloudFront, or Direct Connect
  
  Data replication:
  RDS Global Database: 
    Primary in us-east-1, replica in eu-west-1
    Failover time: <1 minute (automatic promotion)
    Replication lag: <1 second typically
    
  S3 Cross-Region Replication:
    Eventual consistency: objects replicated within 15 minutes typically
    Strong consistency at source region
    
  Route 53 Health Checks + Failover:
    Primary: api.example.com → us-east-1 ALB
    Secondary: api.example.com → eu-west-1 ALB (health check fails primary)
    Failover time: DNS TTL (60 seconds) + health check threshold
```

---

## 14. Interview Questions

### Q1: "Explain the difference between a Security Group and a NACL. Which would you use and when?"

**Answer:**

**Security Groups (SG):**
- Operate at the ENI (Elastic Network Interface) level — per instance, not per subnet
- **Stateful:** If you allow outbound port 443 and the connection is established, the return traffic is automatically allowed without an explicit inbound rule
- Can ONLY have ALLOW rules (no explicit deny — default is deny all)
- Can reference other Security Groups by ID (e.g., "allow from APP_SG") rather than IP ranges
- Rules evaluated collectively (all matching rules checked) — no rule priority/ordering

**Network ACLs (NACL):**
- Operate at the subnet boundary — all traffic entering or leaving a subnet is evaluated
- **Stateless:** Return traffic must be explicitly allowed. If you allow inbound TCP 80, you must also allow outbound ephemeral ports (1024-65535) for the response to return
- Can have both ALLOW and DENY rules
- Rules evaluated in order (lowest number wins — first match, not best match)
- Applied to ALL resources in the subnet, can't exempt specific instances

**When to use each:**

*Security Groups for almost everything:*
- Stateful behavior eliminates the need to think about return traffic
- Per-instance granularity (two EC2s in the same subnet can have different rules)
- Security Group chaining (reference SG IDs) is powerful and self-maintaining
- Default and preferred approach for all resource-level access control

*NACLs as a defense-in-depth layer:*
- **Explicit DENY use case:** SGs can't deny (only allow). If you want to block a specific IP range at the subnet boundary (e.g., block a known-malicious IP range), use a NACL with an explicit DENY rule
- **Subnet-level enforcement:** Some compliance frameworks require explicit subnet-level firewall rules. NACLs satisfy this
- **Wide-range protection:** Block entire CIDR ranges from reaching a subnet (e.g., block all from the dev VPC CIDR from reaching the data subnet, as an extra layer beyond SG rules)

**The ephemeral port gotcha for NACLs:** When you open a port inbound (e.g., 443), the response goes out on an ephemeral port (1024-65535). Your outbound NACL must allow this range. This is the most common NACL misconfiguration — allowing inbound on the application port but forgetting the outbound ephemeral port range, causing connections to timeout silently.

**What if → the NACL blocks traffic that the Security Group allows?** Both must allow the traffic. If either blocks it, the packet is dropped. NACL is evaluated first (at the subnet boundary), then the packet reaches the ENI where Security Groups are evaluated.

---

### Q2: "A developer reports that their new EC2 instance in the private subnet can't reach the internet to download software updates. Walk me through debugging this."

**Answer:**

This is a methodical elimination of each network component. I'd work from the packet's perspective outward:

**Step 1: Is there a route to the internet?**

Check the route table associated with the EC2's subnet:
```bash
aws ec2 describe-route-tables --filters "Name=association.subnet-id,Values=subnet-xxx"
```

Look for: `0.0.0.0/0 → nat-gw-xxxxxx`

If missing: Add a route to a NAT Gateway in the public subnet.

**Step 2: Does the NAT Gateway exist and is it in a public subnet?**

```bash
aws ec2 describe-nat-gateways --filter "Name=nat-gateway-id,Values=nat-gw-xxx"
```

Check: State is "available", Subnet is a PUBLIC subnet (not private). If the NAT GW is in a private subnet, it won't work because the NAT GW itself needs a route to the IGW.

**Step 3: Does the public subnet's route table have a route to the IGW?**

The NAT Gateway is in the public subnet. That public subnet must have `0.0.0.0/0 → igw-xxxxx`. If not, the NAT Gateway can't reach the internet either.

**Step 4: Check the Internet Gateway exists and is attached to the VPC.**

```bash
aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=vpc-xxx"
```

**Step 5: Check Security Group outbound rules.**

Does the EC2's Security Group allow outbound TCP 80/443 to `0.0.0.0/0`?

```bash
aws ec2 describe-security-groups --group-ids sg-xxx
```

Look at outbound rules. If only specific destinations are allowed, add a rule for the package repository IPs (or allow all outbound on 443).

**Step 6: Check NACLs on the private subnet.**

Is the private subnet's NACL blocking outbound to 0.0.0.0/0? Is it blocking inbound on ephemeral ports (response traffic on 1024-65535)?

**Step 7: Does the NAT Gateway have an Elastic IP?**

A NAT Gateway without an EIP can't route internet traffic.

**Step 8: Is the NAT Gateway in the same AZ as the EC2?**

Best practice: route table for AZ-a subnet → NAT Gateway in AZ-a. If the route points to AZ-b's NAT Gateway, it will still work but creates cross-AZ traffic (costs money and adds latency).

**The most common causes:**
1. No route to NAT Gateway in the subnet's route table (forgot to add the route)
2. NAT Gateway is in a private subnet (not public)
3. Security Group doesn't allow outbound 443/80
4. NACL blocks ephemeral port return traffic

---

### Q3: "What is VPC peering and what are its limitations compared to Transit Gateway?"

**Answer:**

**VPC Peering:**

A point-to-point private network connection between two VPCs. Traffic flows through AWS's internal network — not the internet.

Key properties:
- **Non-transitive:** If VPC A peers with VPC B, and VPC B peers with VPC C, VPC A cannot reach VPC C through VPC B. Each peer relationship is direct.
- **Cross-account and cross-region:** Can peer VPCs in different AWS accounts and different regions
- **No bandwidth limits:** Traffic limited only by EC2 instance bandwidth
- **Free data transfer** within the same AZ; $0.01/GB cross-AZ; $0.02/GB cross-region

**Limitations of VPC Peering:**
1. **Non-transitive routing:** 10 VPCs need 10×9/2 = 45 peering connections for full mesh. Unmanageable at scale.
2. **Overlapping CIDRs:** Can't peer VPCs with overlapping IP ranges. If both use 10.0.0.0/16, you can't peer them.
3. **No centralized management:** Each peering connection has its own route table entries. Managing 45 connections = managing 90+ route entries.
4. **No traffic inspection:** Can't insert a firewall or inspection device in the peering path.

**Transit Gateway:**

A regional hub that any number of VPCs (and on-premises networks) can attach to. Acts like a router in the center.

Key properties:
- **Transitive routing:** VPC A → TGW → VPC B → TGW → VPC C (transitive!)
- **Route table segmentation:** Different TGW route tables can isolate groups of VPCs
- **VPN and Direct Connect integration:** On-premises can connect to TGW and reach all attached VPCs
- **Cost:** $0.05/attachment/hour + $0.02/GB processed

**When to use each:**

*Use VPC Peering when:*
- You have 2-5 VPCs that need to communicate
- You want the cheapest option with no per-hour cost
- Traffic volumes are low
- Simple topology (no need for routing policy)

*Use Transit Gateway when:*
- 5+ VPCs (peering mesh becomes unmanageable)
- You need transitive routing
- You need centralized egress (all VPCs route outbound through a central VPC with firewalls)
- You're connecting on-premises networks (TGW integrates with VPN and Direct Connect)
- You need network segmentation policies (TGW route tables can isolate prod from dev)

**What if → you need to connect an on-premises data center AND 20 VPCs?**
Transit Gateway is the answer. You'd create one Site-to-Site VPN or Direct Connect attachment to the TGW, and all 20 VPCs can reach on-premises through it. Without TGW, you'd need 20 separate VPN connections (one per VPC) to on-premises.

---

### Q4: "What is the purpose of VPC Endpoints and how do Interface Endpoints differ from Gateway Endpoints?"

**Answer:**

**The problem VPC Endpoints solve:**

Without VPC Endpoints, your private EC2 instances need internet access to reach AWS services like S3 or SQS:

```
Private EC2 → NAT Gateway → Internet → S3 public endpoint
                         ^
                         This traffic traverses the internet!
                         Costs: NAT Gateway data processing ($0.045/GB)
                         Risk: Traffic could potentially be intercepted
                         Latency: Additional hops through internet
```

**VPC Endpoints solve this by providing private paths to AWS services that stay on AWS's backbone.**

---

**Gateway Endpoints (S3 and DynamoDB ONLY):**

- **FREE** — no per-hour charge, no data processing charge
- Works by adding a route to your route table
- The route destination is a managed prefix list (a list of S3/DynamoDB IP ranges)
- When EC2 sends a packet to S3, the route table diverts it to the endpoint instead of to the NAT Gateway

```
Route table with Gateway Endpoint:
  10.0.0.0/16  → local
  pl-63a5400a  → vpce-xxxxxx  ← S3 prefix list → Gateway Endpoint
  0.0.0.0/0    → nat-gw-xxx
```

**Limitations:** Only for S3 and DynamoDB. Can't apply Security Groups to them. Policy (bucket/table policies) provides access control.

---

**Interface Endpoints (everything else):**

- **Cost:** $0.01/AZ/hour + $0.01/GB processed
- Works by creating an ENI (Elastic Network Interface) in your subnet with a private IP
- DNS for the service points to this private IP
- Traffic goes from your EC2 → ENI in subnet → AWS backbone → Service

```
Without Interface Endpoint:
  cloudwatch.us-east-1.amazonaws.com → 52.94.X.X (public IP)
  
With Interface Endpoint:
  cloudwatch.us-east-1.amazonaws.com → 10.0.10.250 (your VPC ENI)
  (Route 53 Private Hosted Zone overrides the DNS automatically)
```

**Why have the ENI approach?** Interface Endpoints support:
- Security Groups on the ENI (restrict who can use the endpoint)
- Endpoint Policies (restrict what actions can be performed through the endpoint)
- Private DNS (seamless DNS override — no app code changes)

**When to use each:**
- **Gateway Endpoint:** Always use for S3 and DynamoDB — it's free and reduces NAT Gateway costs
- **Interface Endpoint:** For services where your private instances need access:
  - Secrets Manager (fetching DB passwords without internet)
  - SSM (for Session Manager — no SSH needed)
  - ECR (pulling container images)
  - CloudWatch Logs (centralized logging from private instances)
  - SQS/SNS (messaging between services)

**Cost analysis for interface endpoints:**
```
Without Interface Endpoint (using NAT Gateway for Secrets Manager):
  NAT processing: $0.045/GB
  For 1 GB/month of secrets fetches: $0.045/month

With Interface Endpoint (3 AZs):
  $0.01 × 3 AZs × 730 hours = $21.90/month

→ For low-volume API calls: NAT Gateway is cheaper
→ For high-volume (CloudWatch Logs, ECR pulls): Interface Endpoint is cheaper
→ Security requirement (must not traverse internet): Interface Endpoint regardless
```

---

### Q5: "How would you design a VPC for a financial services company that requires strict network segmentation between production, staging, and development?"

**Answer:**

Financial services typically have regulatory requirements (PCI DSS, SOX, GDPR) that mandate network isolation. Here's a design that satisfies these requirements:

**Approach: Separate AWS Accounts per environment (preferred)**

```
AWS Organization Structure:
  Root Management Account (no workloads)
  ├── Production Account (separate AWS account)
  │   └── VPC: 10.0.0.0/16
  ├── Staging Account (separate AWS account)
  │   └── VPC: 10.1.0.0/16
  ├── Development Account (separate AWS account)
  │   └── VPC: 10.2.0.0/16
  └── Shared Services Account (separate AWS account)
      └── VPC: 10.3.0.0/16 (logging, monitoring, CI/CD)
```

**Why separate accounts (not just separate VPCs)?**
- IAM errors in one account can't affect another (production credentials can't be used in dev)
- Service Quotas are per-account (dev experiments don't exhaust production quotas)
- Billing separation is clear
- Compliance audit scope: auditors review only the production account, not all accounts

**Connectivity design:**

```
Transit Gateway Hub (in each region):
  Production VPC → TGW
  Staging VPC → TGW
  Shared Services VPC → TGW
  
  TGW Route Table "production":
    10.0.0.0/16 → Production attachment
    10.3.0.0/16 → Shared Services attachment
    # NO staging or dev routes → production cannot reach them
  
  TGW Route Table "staging":
    10.1.0.0/16 → Staging attachment
    10.3.0.0/16 → Shared Services attachment
    # NO production routes → staging cannot reach production
  
  Development: Completely isolated from production network
    Developer access via Client VPN to their own account
    CI/CD deploys to staging → production via CodePipeline (API, not network)
```

**Within the production VPC:**

```
Subnet design:
  /24 for each layer per AZ (6 total subnets for 3 layers × 2 AZs):
    Public:     10.0.1.0/24, 10.0.2.0/24     (ALB, NAT GW)
    App:        10.0.10.0/24, 10.0.11.0/24   (EC2 app servers)
    Data:       10.0.20.0/24, 10.0.21.0/24   (RDS, ElastiCache)
    Endpoints:  10.0.30.0/24, 10.0.31.0/24   (Interface Endpoint ENIs)

Separate route tables per layer:
  Public route table: 0.0.0.0/0 → IGW
  App route table: 0.0.0.0/0 → NAT GW (same AZ)
  Data route table: NO 0.0.0.0/0 (data tier has ZERO internet access)
    Only: 10.0.0.0/16 → local
    Only: 10.3.0.0/16 → TGW (for centralized logging to Shared Services)
```

**For PCI DSS compliance specifically:**

```
Cardholder Data Environment (CDE) in a separate VPC:
  - Different CIDR: 10.100.0.0/16
  - Connected to production via PrivateLink (NOT peering)
    (PrivateLink exposes specific services, not the entire VPC)
  - AWS WAF on all ingress points
  - AWS Network Firewall for egress filtering (know exactly what CDE accesses)
  - VPC Flow Logs + CloudTrail: 12-month retention to S3 with Object Lock (WORM)
  - GuardDuty findings routed to Shared Services security team
  - All config managed in Terraform with change approval workflow
    (No manual Security Group changes allowed — automated enforcement via Config)
```

---

### Q6: "How does the Internet Gateway differ from a NAT Gateway? What happens if I put an EC2 in a public subnet but don't assign an Elastic IP?"

**Answer:**

**Internet Gateway (IGW):**

The IGW is a horizontally scalable, highly available VPC component that provides **bidirectional** connectivity between the internet and your VPC. It performs 1:1 NAT between public IPs (EIPs or auto-assigned public IPs) and private IPs.

Key properties:
- Bidirectional: Inbound traffic can reach your EC2 (if the EC2 has a public IP)
- No bandwidth limits (truly scales as needed)
- No per-hour cost, no data processing cost
- One per VPC (regional component)
- Does NOT provide connectivity for resources without public IPs

**NAT Gateway:**

A managed NAT service that provides **outbound-only** internet connectivity for private resources.

Key properties:
- Outbound only: Internet cannot initiate connections to private EC2 (by design)
- 45 Gbps bandwidth limit
- $0.045/GB data processing cost + $0.045/hour
- One per AZ (should be, for resilience)
- Has its own Elastic IP
- For private instances: routes through NAT GW → IGW → internet

**The "public subnet without Elastic IP" scenario:**

```
EC2 instance in public subnet (10.0.1.5):
  - The subnet's route table has: 0.0.0.0/0 → igw-xxxxxx
  - BUT the EC2 has no Elastic IP and no auto-assigned public IP

Inbound traffic (internet → EC2):
  - No public IP = no 1:1 NAT mapping in IGW
  - Internet has no way to reach 10.0.1.5
  - Inbound connections impossible from internet

Outbound traffic (EC2 → internet):
  - EC2 sends packet: Source=10.0.1.5, Dest=8.8.8.8
  - Route table: 0.0.0.0/0 → IGW
  - Packet arrives at IGW
  - IGW checks: does 10.0.1.5 have a public IP mapping?
  - NO mapping found → IGW DROPS the packet
  - Outbound connection FAILS

Result: EC2 in public subnet without Elastic IP has NO internet connectivity in EITHER direction
```

**This surprises many engineers:** Being in a "public subnet" doesn't make an instance internet-reachable. It means the subnet has a ROUTE to the IGW. But the IGW only performs NAT for instances with public IPs. Without a public IP, the route table has a route that points to the IGW, but the IGW silently drops the packets.

**Correct designs:**
- Want internet-reachable instance: Public subnet + Elastic IP (or auto-assign public IP enabled at subnet level)
- Want outbound internet but NOT inbound reachable: Private subnet + NAT Gateway route
- Want neither: Private subnet + no 0.0.0.0/0 route (data tier design)

---

*Document version: 1.0 | Classification: Internal Engineering | Author: Cloud Platform Engineering Team*  
*AWS VPC networking is fundamental to all AWS deployments. This document should be reviewed when onboarding cloud engineers and updated with new AWS networking features.*

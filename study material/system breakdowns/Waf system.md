# Web Application Firewall (WAF) — Engineering & Security Breakdown

**Classification:** Internal Engineering Reference  
**Audience:** Engineers, Security Analysts, Platform Architects  
**Assumed Reader:** Will be interviewed on this system. Every claim is mechanically precise and defensible.

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

### The Setup: Three Paths Through the WAF

A WAF sits inline between the internet and your origin application. Every single HTTP/HTTPS request — from legitimate users, bots, scanners, and attackers — passes through it. The WAF makes a per-request decision in milliseconds: Allow, Block, Challenge, or Count. Understanding what happens in those milliseconds is the entire purpose of this document.

Three personas capture the full behavioral range:

1. **Legitimate user**: Makes a normal web request. WAF inspects it, finds nothing suspicious, forwards it to the origin. User experience: invisible latency of 1–5ms.
2. **Attacker with known payload**: Sends an HTTP request containing an SQL injection string. WAF matches it against its rule set, blocks the request. User experience: an HTTP 403 or a custom block page. Attacker experience: frustrated.
3. **Sophisticated attacker using evasion**: Sends a crafted request that encodes the malicious payload in a way that bypasses signature matching. WAF misses it, forwards to origin. Origin is exploited. Detection happens later, in logs.

This document covers all three paths in full detail.

---

### Persona 1: Legitimate User Request

**T=0ms — User types URL or clicks a link**

The browser has a URL: `https://app.example.com/search?q=blue+shoes&page=1`. The user hits Enter.

**T=0–40ms — DNS Resolution**

The browser resolves `app.example.com`. For a CDN-integrated WAF (AWS WAF + CloudFront, Cloudflare, Fastly), the DNS record for `app.example.com` is a CNAME pointing to the WAF/CDN provider's infrastructure:

```
app.example.com  →  CNAME  d123.cloudfront.net
d123.cloudfront.net  →  A  13.35.12.45  (WAF/CDN edge node)
```

The user's traffic will go to the WAF node, not directly to the origin. The origin's real IP is never exposed in DNS.

**T=40–80ms — TCP + TLS to WAF Edge**

Standard TCP 3-way handshake followed by TLS 1.3 handshake. TLS is terminated at the WAF edge — the WAF decrypts the traffic to inspect it. This is fundamental: a WAF cannot inspect encrypted payloads without terminating TLS. The WAF re-encrypts traffic when forwarding to the origin (or uses an internal plaintext path if origin and WAF are co-located).

**T=80ms — HTTP Request Received by WAF**

The WAF receives the full HTTP request:
```
GET /search?q=blue+shoes&page=1 HTTP/2
Host: app.example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
Accept: text/html,application/xhtml+xml
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJhbGci...; _ga=GA1.2.123456789.1234567890
Referer: https://app.example.com/
```

**T=80–85ms — WAF Inspection Pipeline**

The WAF processes the request through its rule engine. For this legitimate request:

1. **IP reputation check**: Source IP `203.0.113.5` is not on any blocklist. Pass.
2. **Rate limiting**: This IP has made 3 requests in the last minute. Limit is 100/min. Pass.
3. **Geo-restriction**: Source is US. No geo-block. Pass.
4. **OWASP Core Rule Set (CRS) evaluation**:
   - SQL injection check on `q` parameter: `blue+shoes` — no SQL metacharacters. Pass.
   - XSS check: no `<script>`, no event handlers. Pass.
   - Path traversal check: `/search` — no `../` or encoded variants. Pass.
   - Header anomaly check: User-Agent present, valid format. Pass.
5. **Custom rules**: No business-specific rules match. Pass.
6. **Bot detection**: User-Agent is a real browser. No headless browser fingerprints. Cookies present (prior visit). Pass.

All rules pass. WAF action: **ALLOW**.

**T=85ms — Forward to Origin**

WAF forwards the request to the origin server (your application). The WAF adds headers:
- `X-Forwarded-For: 203.0.113.5` (real client IP)
- `X-Forwarded-Proto: https`
- Vendor-specific: `CF-Ray: 123abc`, `X-Amzn-Waf-Action: Allow`

**T=85–200ms — Origin Processing**

Origin receives the request, processes it (database query, template render), and responds with an HTML page.

**T=200ms — WAF Forwards Response to Client**

WAF may inspect the response (response inspection is less common but supported in some WAFs for data loss prevention — e.g., blocking responses containing credit card numbers). For this request, no response rules trigger. The HTML page is forwarded to the client.

**What the user sees**: The search results page loads in ~250ms. The WAF is completely invisible.

---

### Persona 2: Attacker with Known SQLi Payload

**T=0 — Attacker sends a crafted request**

```
GET /search?q=' OR '1'='1&page=1 HTTP/1.1
Host: app.example.com
User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
```

The attacker has tried to disguise as Googlebot (ineffective against good WAFs — more on this in attack scenarios).

**T=80–85ms — WAF Inspection**

1. **IP reputation**: Not on blocklist yet (fresh VPS). Pass.
2. **User-Agent validation**: Googlebot's IP doesn't match the request IP. Some WAFs perform reverse DNS verification of Googlebot — this fails. Flag.
3. **SQL injection check on `q` parameter**:
   - The WAF URL-decodes the parameter: `q = ' OR '1'='1`
   - Pattern match: `'` followed by SQL keywords (`OR`) and quoted comparison — matches SQLi signature.
   - Rule matched: `942100 - SQL Injection Attack Detected via libinjection`.
   - Anomaly score: +5 (critical).
4. **Anomaly scoring threshold**: Score of 5 meets the block threshold of 5. Action: **BLOCK**.

**T=85ms — Block Response**

WAF returns:
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
X-Correlation-ID: waf-block-abc123

<html>
<body>
<h1>Access Denied</h1>
<p>Your request has been blocked. Reference: waf-block-abc123</p>
</body>
</html>
```

Origin never sees this request. The block happens entirely within the WAF.

**What the attacker sees**: A 403 page. The reference ID is logged in WAF logs for investigation.

---

### Persona 3: Sophisticated Attacker with Evasion

**T=0 — Attacker sends encoded payload**

```
GET /search?q=%27%20OR%20%271%27%3D%271&page=1 HTTP/1.1
Host: app.example.com
```

The parameter `q` contains URL-encoded SQLi: `%27%20OR%20%271%27%3D%271` = `' OR '1'='1`.

**T=80–85ms — WAF Inspection (FAIL)**

If the WAF's rule engine doesn't normalize the input before matching:
- Raw value: `%27%20OR%20%271%27%3D%271`
- Regex pattern matching against raw string: no match (looks like URL-encoded data, not SQL).
- WAF ACTION: **ALLOW** (false negative).

This is a misconfigured WAF. A properly configured WAF with URL-decoding normalization would decode first, then match:
- Normalized: `' OR '1'='1` → matches SQLi rule → BLOCK.

**What the attacker sees**: The request succeeds. They've bypassed the WAF.

This is the central tension of WAF operation: rules must match across all encoding variants and transformation layers. Getting normalization wrong means your rule set is incomplete. This is detailed in the Attack Scenarios section.

---

## 2. Network Layer Flow

### DNS Resolution for WAF-Protected Applications

The DNS architecture for a WAF-protected application is deliberate: the WAF's IP is in DNS, the origin's IP is not. If the origin's IP leaks (via historical DNS records, TLS certificates in CT logs, email headers, error messages), the WAF can be bypassed entirely.

```
User Browser
    |
    | (1) Resolve: app.example.com
    v
OS DNS Cache (check: not found or TTL expired)
    |
    v
Stub Resolver → Recursive Resolver (8.8.8.8 or ISP)
    |
    | (2) Recursive resolution:
    |   . (root) → .com TLD → example.com authoritative NS
    |
    v
Authoritative NS for example.com
    |
    | Returns:
    |   app.example.com  IN CNAME  d123.cloudfront.net   TTL=300
    |   (Follow CNAME)
    |   d123.cloudfront.net  IN A  13.35.12.45           TTL=60
    |
    | NOTE: The actual origin IP (e.g., 10.0.1.5 or 52.x.x.x)
    |       is NEVER in public DNS. This is the WAF's first
    |       layer of protection: origin obscurity.
    v
Browser connects to 13.35.12.45:443 (WAF edge node)

WAF internally:
    app.example.com → origin: 10.0.1.5:8080 (private, internal routing)
    This mapping is in WAF config, not DNS.
```

**Short TTL rationale**: WAF providers use TTLs of 30–300 seconds. When a WAF edge node becomes unhealthy, DNS TTL controls how quickly clients switch to another node. Short TTL = faster failover but more DNS queries. Long TTL = fewer DNS queries but slower failover.

**GeoDNS / Anycast for WAF**:

Most major WAF/CDN providers use Anycast routing. The IP `13.35.12.45` is advertised from hundreds of PoPs globally via BGP. When a user in Mumbai resolves `app.example.com`, they get the same IP but their traffic is routed by BGP to the Mumbai PoP. When a user in London resolves the same name, BGP routes them to the London PoP. The DNS response is the same; the network path differs.

### TCP Handshake at the WAF Edge

```
Client (203.0.113.5:54321)           WAF Edge Node (13.35.12.45:443)
         |                                        |
         |  SYN (seq=X, flags=SYN)               |
         |--------------------------------------->|
         |                                        |  [WAF allocates TCP state]
         |  SYN-ACK (seq=Y, ack=X+1)             |  [SYN cookies if under SYN flood]
         |<---------------------------------------|
         |                                        |
         |  ACK (seq=X+1, ack=Y+1)               |
         |--------------------------------------->|
         |                                        |
         | [TCP established. WAF waits for TLS.]  |

WAF TCP-level controls at this stage:
  - SYN cookies: enabled by default in WAF infrastructure. Under SYN flood,
    the WAF embeds connection state into the SYN-ACK sequence number. No
    memory allocated until the ACK confirms the client is real (not spoofed).
  
  - Connection limits: Max simultaneous half-open connections per source IP
    (e.g., 100). Exceeding this → RST or silent drop.
  
  - TCP timeout: Half-open connections expire after 10–30 seconds.
    Completed connections idle timeout: 300–900 seconds.

WAF does NOT forward TCP connections to origin at this point.
WAF terminates the TCP connection itself. A SEPARATE TCP connection
exists between WAF and origin — persistent, pooled, already established.
```

**This is critical**: The WAF has two separate TCP connections:
1. **Client → WAF**: The client's TCP connection. WAF terminates this.
2. **WAF → Origin**: A separate, pre-established, pooled connection. WAF acts as a reverse proxy.

This means TCP-level DDoS attacks (SYN flood, RST flood, Slowloris) terminate at the WAF and never reach the origin. The origin only sees well-formed, fully established connections from the WAF's IP range.

### TLS Termination at the WAF

```
Client                                    WAF Edge Node
  |                                               |
  | ClientHello:                                  |
  |   TLS 1.3                                     |
  |   Cipher suites:                              |
  |     TLS_AES_256_GCM_SHA384                    |
  |     TLS_CHACHA20_POLY1305_SHA256              |
  |   Key share: X25519                           |
  |   SNI: app.example.com                        |
  |   ALPN: h2, http/1.1                          |
  |---------------------------------------------->|
  |                                               |
  | ServerHello + Certificate + CertVerify + Fin  |
  |   Cert: app.example.com                       |
  |         Issued by: Let's Encrypt or           |
  |                    DigiCert (WAF provider's   |
  |                    managed cert)              |
  |<----------------------------------------------|
  |                                               |
  | [ECDHE key exchange, keys derived]            |
  | [Finished]                                    |
  |---------------------------------------------->|
  |                                               |
  | [Application data — DECRYPTED at WAF]         |
  | HTTP/2 HEADERS + DATA frames                  |
  |---------------------------------------------->|  <-- WAF reads plaintext HERE
  |                                               |

WAF → Origin (separate TLS):
  WAF re-encrypts and forwards using a WAF-to-origin TLS connection.
  The origin presents its own certificate (internal CA or public CA).
  The WAF validates the origin's certificate (origin pinning).
  If not validated: WAF rejects the connection (prevents origin impersonation).
```

**Why TLS termination is mandatory for inspection**:

HTTP/2 and HTTP/3 use binary framing and header compression (HPACK, QPACK). Even if the WAF could see ciphertext (it can't), it would need to decrypt to understand the HTTP semantics. The WAF must be in the trust path for TLS — it is, by design, a Man-in-the-Middle, but a trusted one that you've explicitly placed in the request path.

**Certificate management at the WAF**:
- Cloudflare: Issues Cloudflare-signed certs for your domain. Stores private keys on their edge (distributed key management with HSMs).
- AWS WAF + ACM: TLS terminated at CloudFront or ALB. Certificate stored in AWS Certificate Manager (ACM), private key never extractable.
- Self-managed WAF (ModSecurity + nginx): You manage the certificate and private key. Key rotation is your responsibility.

### Full Packet Flow with WAF Inline

```
INTERNET
    |
    |  Client packet: src=203.0.113.5:54321, dst=13.35.12.45:443
    |  Payload: [TLS ClientHello]
    v
WAF EDGE NODE (13.35.12.45)
    |
    |  [Network layer]
    |  ├── DDoS scrubbing: volumetric floods absorbed here (Gbps scale)
    |  ├── IP reputation: check source IP against threat feeds
    |  ├── Connection rate limiting: per-IP, per-second
    |  └── Protocol validation: valid TCP, valid TLS version
    |
    |  [TLS termination]
    |  └── Decrypt → plaintext HTTP request
    |
    |  [HTTP parsing]
    |  ├── Method, URI, version
    |  ├── Header parsing (each header name and value)
    |  ├── Cookie parsing
    |  ├── Query string parsing (URL decode, parameter extraction)
    |  ├── Body parsing (JSON, XML, form data, multipart)
    |  └── Normalization (URL decode, HTML decode, Unicode normalization)
    |
    |  [WAF Rule Engine]
    |  ├── Managed rules (OWASP CRS, vendor managed rule groups)
    |  ├── Custom rules (business-specific logic)
    |  ├── Rate-based rules (count requests, trigger at threshold)
    |  └── Bot management rules (fingerprint, challenge, block)
    |
    |  Decision: ALLOW / BLOCK / CHALLENGE / COUNT
    |
    |  [If ALLOW: forward to origin]
    v
ORIGIN SERVER (10.0.1.5:8080) — separate TCP/TLS connection
    |
    v
ORIGIN RESPONSE → WAF → CLIENT
```

### Latency Budget and Failure Modes

| Phase | Normal | Under Load | Failure |
|---|---|---|---|
| DNS resolution | 5–50ms (cached: 0ms) | Same (DNS is stateless) | NXDOMAIN if zone misconfigured |
| TCP handshake to WAF | 10–40ms RTT | SYN queue saturation → timeout | DDoS absorbs capacity |
| TLS handshake | 10–40ms (TLS 1.3, 1 RTT) | CPU exhaustion on key exchange | Cert expiry → SSL error |
| WAF inspection | 1–5ms (simple rules) | 10–50ms (complex regex) | Rule engine OOM → fail-open or fail-closed |
| WAF → Origin TCP | 0ms (pooled) | Queue saturation | Origin unreachable → 502 |
| Origin processing | 50–500ms | DB saturation | Timeout → 504 |

**Critical failure mode — fail-open vs fail-closed**:

When the WAF rule engine crashes, overloads, or becomes unavailable:
- **Fail-open**: Traffic bypasses inspection and goes directly to origin. Availability is preserved; security is lost. Attackers can deliberately overload the WAF rule engine to trigger fail-open.
- **Fail-closed**: Traffic is blocked. Security is preserved; availability is lost. DoS against your own users.

This is a fundamental design decision with no universally correct answer. It depends on your threat model vs availability SLA.

---

## 3. Application Layer Flow

### HTTP Request Lifecycle Through the WAF

The WAF operates at Layer 7 — it must fully parse HTTP to make decisions. This is both its power (it understands application semantics) and its attack surface (malformed HTTP can exploit the parser itself).

**HTTP/2 specifics at the WAF**:

HTTP/2 uses binary framing with HPACK header compression. The WAF must decompress HPACK before it can read headers. A malicious sender could craft HPACK payloads designed to cause the decompressor to allocate excessive memory (HPACK bomb, analogous to an XML bomb). Good WAFs limit HPACK decompression memory.

```
HTTP/2 Frame received by WAF:
  [Frame Header: 9 bytes]
    Length: 0x000123    (number of bytes in frame payload)
    Type: 0x1           (HEADERS frame)
    Flags: 0x4          (END_HEADERS)
    Stream ID: 0x1      (stream 1)
  [Frame Payload: HPACK-compressed headers]
    :method: GET
    :path: /search?q=blue+shoes
    :authority: app.example.com
    :scheme: https
    ...

WAF decompresses HPACK → raw header list → inspection
```

### Method Handling

WAFs inspect HTTP methods and can:
- **Block non-standard methods**: TRACK, TRACE, DEBUG (information disclosure), CONNECT (proxy abuse).
- **Restrict methods per path**: `DELETE /users/123` might be allowed for API clients but blocked for frontend traffic.
- **Method override**: Some APIs use `X-HTTP-Method-Override: DELETE` with a POST. WAFs must inspect this header and apply the same method restrictions.

**Method override example — WAF bypass risk**:
```
POST /admin/delete-user HTTP/1.1
X-HTTP-Method-Override: GET

If the WAF only inspects the HTTP method (POST) and applies
rules for POST, but the application treats it as GET (because
it honors X-HTTP-Method-Override), the WAF's method-based
rules are bypassed for the actual operation.
```

### Header Parsing and Inspection

The WAF inspects every header name and value. Headers are a significant attack vector:

**Headers that WAFs inspect:**
- `User-Agent`: Bot detection, known scanner identification.
- `Referer`: Expected domain (no referrer on direct attacks), hotlinking prevention.
- `Cookie`: Session token validation, XSS via cookie value.
- `Content-Type`: Must match body format. `application/json` with XML body → parser confusion.
- `Accept`: Can be used to fingerprint clients.
- `X-Forwarded-For`: Attacker can forge this to spoof IP. WAF must know how many hops to trust.
- `Authorization`: Bearer tokens, Basic auth headers — WAF shouldn't log these in plaintext.
- Custom headers: `X-API-Key`, `X-Request-ID` — potential injection vectors.

**Header injection**:
```
GET /page HTTP/1.1
Host: app.example.com
X-Custom-Header: value\r\nInjected-Header: malicious

If the WAF or origin doesn't strip CR+LF from header values,
this injects a new HTTP header. The WAF should:
1. Reject requests with CR/LF in header values.
2. Normalize header values before forwarding.
```

### Cookie Parsing

Cookies are parsed as `name=value` pairs separated by `;`. Attack vectors:
- **Cookie injection**: `Cookie: session=abc; admin=true` — if the application reads `admin` cookie.
- **Cookie overflow**: Extremely long cookie value to trigger buffer overflow in parser.
- **Cookie-based XSS**: `Cookie: username=<script>alert(1)</script>` — if reflected in response.

WAF cookie inspection:
1. Parse cookie string into name/value pairs.
2. Apply SQLi, XSS, and injection checks to each value.
3. Optionally verify cookie signatures (if the WAF is configured with the application's cookie signing key — advanced integration).

### Query String and Body Parsing

**URL decoding**: `%27` → `'`, `%3C%73%63%72%69%70%74%3E` → `<script>`, `+` → ` `.

**HTML entity decoding**: `&#x27;` → `'`, `&lt;script&gt;` → `<script>`.

**Path normalization**:
- `/foo/../../../etc/passwd` → `/etc/passwd` (path traversal after normalization)
- `//foo` → `/foo`
- `/foo/./bar` → `/foo/bar`

A WAF that checks the raw path `/foo/../../../etc/passwd` might not find a matching pattern. After normalization, `/etc/passwd` clearly matches a path traversal rule. The WAF must normalize first.

**Multipart form data parsing** (file uploads):

```
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/pdf

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

WAF inspection of this request:
1. Detect multipart boundary.
2. Parse each part: extract `filename` field → `shell.php` → extension is `.php` → BLOCK (if PHP extension blocking is configured).
3. Inspect body content: `<?php system(` → PHP code execution pattern → BLOCK.
4. Content-Type mismatch: `application/pdf` declared but PHP content — can trigger content sniffing rules.

### Response Construction When Blocking

When a WAF blocks a request, it constructs the response without contacting the origin. The response includes:

- **HTTP status code**: 403 (default), 429 (rate limit), or a custom code.
- **Response headers**: `Content-Type`, `X-Correlation-ID` (for log correlation), optionally WAF vendor headers.
- **Response body**: Custom HTML block page, or a simple error message.
- **No sensitive headers**: The WAF response should NOT include `Server:`, `X-Powered-By:`, or other headers that reveal infrastructure details.

```
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Request-ID: waf-blk-550e8400-e29b-41d4-a716-446655440000
Cache-Control: no-store
X-Content-Type-Options: nosniff

<!DOCTYPE html>
<html>
<head><title>Request Blocked</title></head>
<body>
<h1>Access Denied</h1>
<p>Your request has been blocked by our security policy.</p>
<p>If you believe this is an error, contact support with reference: waf-blk-550e8400</p>
</body>
</html>
```

The reference ID maps to a CloudWatch/Splunk log entry. The support team can look up exactly which rule matched and why, without exposing that information to the requester.

---

## 4. Backend Architecture

### WAF Deployment Models

Understanding which deployment model you're using determines the trust model, latency profile, and failure modes.

```
MODEL 1: INLINE NETWORK APPLIANCE
════════════════════════════════════════════════════════════════════════

  Internet → [Firewall] → [WAF Appliance] → [Load Balancer] → [App Servers]

  WAF is a dedicated hardware or VM between the firewall and LB.
  All traffic passes through it physically.
  
  Pros: No DNS changes, works at network layer, can inspect all protocols.
  Cons: Single point of failure, hardware capacity limits, must scale vertically.
  Examples: F5 BIG-IP, Fortinet FortiWeb (on-premise).


MODEL 2: REVERSE PROXY (MOST COMMON)
════════════════════════════════════════════════════════════════════════

  Internet → [WAF Reverse Proxy] → [Origin Servers]
                    ↑
              DNS points here (WAF's IP)
              Origin's IP is private / not in DNS

  WAF terminates all connections. Forwards allowed requests to origin.
  
  Pros: Scales horizontally, origin protected, CDN integration.
  Cons: Requires DNS change, TLS termination at WAF, TLS between WAF and origin.
  Examples: Cloudflare, AWS WAF + CloudFront, nginx + ModSecurity.


MODEL 3: CLOUD-NATIVE / SIDECAR
════════════════════════════════════════════════════════════════════════

  Kubernetes Pod:
    [App Container] ↔ [WAF Sidecar (Envoy + OWASP CRS)] → [Network]

  WAF runs as a sidecar container in each pod.
  
  Pros: No single point of failure, scales with pods, mTLS native.
  Cons: CPU overhead per pod, rule updates require pod restart, complex.
  Examples: AWS App Mesh + WAF, Istio + custom filter.


MODEL 4: EMBEDDED MODULE
════════════════════════════════════════════════════════════════════════

  [nginx + ModSecurity module] → [Application]
  [Apache + mod_security] → [Application]

  WAF runs as a module inside the web server process.
  
  Pros: No network hop, low latency, direct access to request object.
  Cons: WAF crash = web server crash, updates require server restart.
  Examples: ModSecurity v3 (libmodsecurity), NAXSI.
```

### Internal WAF Architecture (Rule Engine Detail)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    WAF PROCESSING PIPELINE                           │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  PHASE 1: CONNECTION / IP LAYER                              │  │
│  │  - Source IP lookup in threat intelligence database          │  │
│  │  - IP allowlist (trusted scanners, monitoring IPs)           │  │
│  │  - IP blocklist (known malicious IPs, Tor exit nodes)        │  │
│  │  - Geo-blocking (country → action mapping)                   │  │
│  │  - ASN blocking (block entire cloud hosting ASNs)            │  │
│  │  Decision: ALLOW/BLOCK/CHALLENGE before HTTP is parsed       │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           ↓                                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  PHASE 2: HTTP PARSING + NORMALIZATION                       │  │
│  │  - HTTP method extraction                                    │  │
│  │  - URI parsing, path normalization, query string parsing     │  │
│  │  - Header parsing (name + value for each header)             │  │
│  │  - Cookie parsing                                            │  │
│  │  - Body parsing (based on Content-Type):                     │  │
│  │      JSON → parse JSON tree                                  │  │
│  │      XML → parse DOM (with XXE protection)                   │  │
│  │      form-urlencoded → key/value pairs                       │  │
│  │      multipart → parse parts, extract filenames              │  │
│  │  - Input normalization:                                      │  │
│  │      URL decode (%XX)                                        │  │
│  │      HTML entity decode (&amp; → &)                          │  │
│  │      Unicode normalization (NFC/NFKC)                        │  │
│  │      Path normalization (/../ collapse)                      │  │
│  │      Null byte removal (%00)                                 │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           ↓                                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  PHASE 3: RULE EVALUATION                                    │  │
│  │                                                              │  │
│  │  Rule types:                                                 │  │
│  │  ┌────────────────────────────────────────────────────────┐ │  │
│  │  │ SIGNATURE RULES (pattern matching)                      │ │  │
│  │  │   - Regex against normalized input                      │ │  │
│  │  │   - libinjection (ML-based SQLi/XSS detection)         │ │  │
│  │  │   - PCRE with limits (prevent ReDoS)                   │ │  │
│  │  │   Example: (?i)(\s*(union|select|insert|drop)\s+)      │ │  │
│  │  └────────────────────────────────────────────────────────┘ │  │
│  │  ┌────────────────────────────────────────────────────────┐ │  │
│  │  │ ANOMALY SCORING (OWASP CRS default mode)               │ │  │
│  │  │   - Each matching rule adds to a score                  │ │  │
│  │  │   - Score ≥ threshold → block                          │ │  │
│  │  │   - Multiple low-confidence matches → block            │ │  │
│  │  │   - Single high-confidence match → block               │ │  │
│  │  │   Paranoia levels: PL1 (low FP) to PL4 (high FP)      │ │  │
│  │  └────────────────────────────────────────────────────────┘ │  │
│  │  ┌────────────────────────────────────────────────────────┐ │  │
│  │  │ RATE-BASED RULES                                        │ │  │
│  │  │   - Count requests per key (IP, session, header value) │ │  │
│  │  │   - Sliding window (5min, 10min, etc.)                  │ │  │
│  │  │   - Trigger at threshold: block or challenge            │ │  │
│  │  │   - Stored in distributed counter (Redis/DynamoDB)     │ │  │
│  │  └────────────────────────────────────────────────────────┘ │  │
│  │  ┌────────────────────────────────────────────────────────┐ │  │
│  │  │ BOT MANAGEMENT                                          │ │  │
│  │  │   - JavaScript challenge (prove browser is real)        │ │  │
│  │  │   - CAPTCHA (human verification)                        │ │  │
│  │  │   - Device fingerprinting (canvas, WebGL, fonts)        │ │  │
│  │  │   - Behavioral analysis (mouse, keyboard, timing)       │ │  │
│  │  │   - TLS fingerprinting (JA3/JA3S hash)                 │ │  │
│  │  └────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           ↓                                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  PHASE 4: ACTION + LOGGING                                   │  │
│  │  - ALLOW: forward to origin with added headers               │  │
│  │  - BLOCK: return 403 (or custom block page)                  │  │
│  │  - CHALLENGE: return JS challenge or CAPTCHA page            │  │
│  │  - COUNT: allow but log the match (for tuning)               │  │
│  │  - Log: write event to SIEM/logging pipeline regardless      │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Caching Layers in WAF Architecture

```
CLOUDFLARE/CLOUDFRONT + WAF CACHING INTERACTION:
═══════════════════════════════════════════════════════════════════════

  Request arrives → WAF inspects → [ALLOW]
                                       ↓
                              Check CDN cache
                                       |
                          ┌────────────┴────────────┐
                      HIT │                         │ MISS
                          ▼                         ▼
                  Return cached response    Forward to origin
                  (No origin contact)      Cache response (if cacheable)

CRITICAL: WAF inspects ALL requests, even those served from cache.
          The WAF decision (allow/block) is made BEFORE cache lookup.
          This is correct: a cached response is still security-controlled.
          If WAF allowed caching of malicious requests, attacker could
          poison the cache.

RATE LIMITING + CACHE INTERACTION:
  - Rate limits apply to WAF-inspected requests, not just origin hits.
  - Cache HITs still count toward rate limits (correct behavior).
  - Some WAFs allow "rate limit bypass for cache hits" — dangerous:
    attacker could cache-bust to avoid rate limits.

REDIS IN WAF ARCHITECTURE:
  - Rate limit counters: Redis is the distributed counter store.
    Key: "ratelimit:{ip}:{window_start}" → Value: count
    TTL: window duration (e.g., 300 seconds for 5-min window)
  - Session tracking for bot management: challenges issued per session.
  - Challenge verification tokens: short-lived tokens issued with
    JS challenge, verified on next request.
```

### Threat Intelligence Integration

WAFs integrate with threat intelligence (TI) feeds to make IP reputation decisions. This is an asynchronous background process:

```
TI Feed Sources (async updates):
  - AWS Threat Intelligence (managed)
  - Cloudflare Radar (public + proprietary)
  - Commercial feeds: Recorded Future, Anomali, CrowdStrike
  - Community feeds: Spamhaus, SORBS, FireHOL
  - Your own: internal threat data from SIEM

Update cycle: every 1–60 minutes (varies by provider)
Storage: Trie (CIDR lookup), hash table (exact IP), or bloom filter (fast reject)

At request time (synchronous):
  Source IP → TI lookup (in-memory, <1ms)
  Result: {score: 85, categories: ["scanner", "tor_exit"], actions: ["challenge"]}
```

---

## 5. Authentication & Authorization Flow

### WAF's Role in Authentication

The WAF is not an authentication server — it does not validate passwords or issue tokens. However, it participates in authentication security in several specific ways.

**Pre-authentication protection:**

Before any login request reaches the origin's auth handler, the WAF applies:
1. **Rate limiting on auth endpoints**: `/login`, `/signin`, `/api/auth/token` get stricter rate limits than general endpoints. Typical: 10–20 requests per minute per IP (vs 100–1000 for general endpoints).
2. **Credential stuffing detection**: Pattern of POST requests to `/login` with changing `username` parameters from the same IP or IP range → bot behavior → CAPTCHA or block.
3. **IP reputation check**: Known credential-stuffing botnet IPs blocked before they attempt a single login.
4. **Request anomaly detection**: Login requests without expected headers (no `Cookie`, no `Referer`, no `Origin`) from direct HTTP clients → likely automated → challenge.

**Post-authentication session protection:**

After login, the origin issues a session token (cookie or JWT). The WAF can be configured to:
1. **Cookie validation**: If the WAF knows the expected format/prefix of session cookies, it can detect forged or absent cookies on requests to authenticated endpoints.
2. **Cookie encryption/signing at WAF edge**: Some WAFs can encrypt cookies before sending to the client and decrypt on return (transparent to the application). The origin never sees the raw cookie value — only the WAF can decrypt it. This prevents cookie theft and tampering.
3. **Session fixation prevention**: WAF can detect if a session cookie was set before authentication and if the same cookie continues after — session fixation pattern.

### Trust Boundaries in WAF Auth Context

```
TRUST BOUNDARY MAP FOR AUTH:
════════════════════════════════════════════════════════════════════════

[INTERNET — UNTRUSTED]
        |
        | (TLS: encrypted)
        |
[WAF EDGE — SEMI-TRUSTED]
   Trusts:  - Its own rule evaluation
            - TI feed data (as accurate as the feed)
            - Client IP (only if no X-Forwarded-For spoofing)
   Does NOT trust:
            - X-Forwarded-For header (client-controlled)
            - User-Agent header (client-controlled)
            - Cookie values (not validated by WAF in basic mode)
        |
        | (WAF adds X-Forwarded-For, X-WAF-Score, etc.)
        |
[LOAD BALANCER / API GATEWAY — TRUSTED]
   Trusts:  - WAF IP range (only WAF IPs should reach this)
            - X-Forwarded-For from WAF (WAF sets this correctly)
   Does NOT trust:
            - Requests from IPs NOT in the WAF's IP range
              (origin should have firewall rules blocking non-WAF traffic)
        |
[APPLICATION SERVER — TRUSTED INTERNAL]
   Trusts:  - Requests from LB (LB IP range)
            - X-Forwarded-For (as set by WAF)
            - Session tokens (application validates these itself)
   Does NOT rely on WAF for:
            - Authorization (WAF doesn't know user permissions)
            - Authentication validity (WAF doesn't validate session tokens)
        |
[DATABASE — FULLY TRUSTED INTERNAL]
   Trusts:  - Application server connection (authenticated DB user)
            - Parameterized queries (SQLi already blocked or safe)
```

### Session Token Handling

The WAF sees every request including the session cookie. This creates a sensitive data handling requirement:

**What the WAF does with tokens**:
- Reads the cookie/header to apply rules (e.g., check for SQLi in cookie values).
- Logs the request — should the session token be logged?

**Correct behavior**: WAF logs should **not** include full session tokens or API keys. These should be:
1. Masked in logs: `Cookie: session=eyJhbGci...***REDACTED***`
2. Hashed: log `SHA256(session_value)` for correlation without exposing the token.
3. Excluded: configure WAF log fields to exclude `Cookie` and `Authorization` header values.

**Token rotation and WAF**:
When a session token rotates (e.g., after privilege escalation or on each request), the WAF's rate-limiting and session-tracking logic must track the new token. If rate limiting is keyed on the session token, token rotation resets the rate limit — attackers can rotate tokens to bypass rate limiting.

Better rate limit key: IP + User-Agent + TLS fingerprint (JA3), not session token.

---

## 6. Data Flow

### Request Data Transformations

```
RAW TCP BYTES (from client)
    |
    | TLS decryption → raw HTTP/2 or HTTP/1.1 bytes
    v
HTTP FRAMING PARSE
    | HTTP/2: HEADERS + DATA frames, HPACK decompression
    | HTTP/1.1: header section + body
    v
HEADER EXTRACTION
    | Name-value pairs
    | Cookie parsing (name=value; name=value pairs)
    v
URI PARSING
    | Scheme, host, path, query string (raw)
    v
NORMALIZATION (applied to each field):
    | URL decode:       %27 → '   %3D → =   %20 → space
    | Double URL decode:%2527 → %27 → '  (for double-encoded attacks)
    | HTML entity:      &lt; → <  &amp; → &  &#x27; → '
    | Unicode:          \u003c → <  (JS unicode escape)
    | Null byte:        %00 → removed
    | Path:             /a/../b → /b   /a//b → /a/b
    | Case:             some rules are case-insensitive
    v
BODY PARSING (if body present):
    | Content-Type: application/json → JSON parse → field extraction
    | Content-Type: application/xml  → XML parse → DOM traversal
    | Content-Type: application/x-www-form-urlencoded → key/value parse
    | Content-Type: multipart/form-data → boundary parse → part extraction
    v
RULE EVALUATION TARGETS:
    | Each rule specifies WHICH fields to inspect:
    | - REQUEST_URI (raw URI)
    | - REQUEST_URI_RAW (before normalization)
    | - ARGS (all query + body parameters)
    | - ARGS_GET (query string only)
    | - ARGS_POST (body only)
    | - REQUEST_HEADERS (all header values)
    | - REQUEST_COOKIES (all cookie values)
    | - REQUEST_BODY (raw body)
    | - FILES_TMPNAMES (uploaded file paths)
    v
MATCH RESULT → ACTION → LOG EVENT
```

### WAF Log Event Structure

```json
{
  "timestamp": "2025-05-15T10:23:45.123Z",
  "action": "BLOCK",
  "httpRequest": {
    "clientIp": "203.0.113.5",
    "country": "US",
    "headers": [
      {"name": "Host", "value": "app.example.com"},
      {"name": "User-Agent", "value": "Mozilla/5.0..."},
      {"name": "Cookie", "value": "***REDACTED***"}
    ],
    "uri": "/search",
    "args": "q=%27+OR+%271%27%3D%271&page=1",
    "httpMethod": "GET",
    "httpVersion": "HTTP/2.0"
  },
  "ruleGroupList": [
    {
      "ruleGroupId": "AWSManagedRulesSQLiRuleSet",
      "terminatingRule": {
        "ruleId": "SQLi_QUERYARGUMENTS",
        "action": "BLOCK",
        "ruleMatchDetails": [
          {
            "conditionType": "SQL_INJECTION",
            "sensitivityLevel": "HIGH",
            "location": "QUERY_STRING",
            "matchedData": ["' OR '1'='1"]
          }
        ]
      }
    }
  ],
  "webaclId": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/MyWebACL/abc123",
  "terminatingRuleId": "SQLi_QUERYARGUMENTS",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "responseCodeSent": "403",
  "requestId": "waf-req-550e8400-e29b-41d4-a716-446655440000",
  "ja3Fingerprint": "a0e9f5d64349fb13191bc781f81f42e1",
  "ja3sFingerprint": "771,49200-49196-49192-...,0-23-65281-10-11-16"
}
```

### Serialization Formats in WAF Context

**Rule format serialization**:

OWASP CRS rules are written in ModSecurity rule language:
```
SecRule ARGS "@detectSQLi" \
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,t:removeWhitespace,\
    msg:'SQL Injection Attack Detected via libinjection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    ver:'OWASP_CRS/3.3.4',\
    severity:'CRITICAL',\
    setvar:'tx.sqli_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
```

This rule:
1. Inspects `ARGS` (all query + body parameters).
2. Applies `@detectSQLi` operator (libinjection library — ML-based SQL/XSS detection).
3. Before matching, applies transformations: `utf8toUnicode`, `urlDecodeUni` (decode URL encoding), `removeNulls`, `removeWhitespace`.
4. If match: increment anomaly score by `critical_anomaly_score` (default: 5).
5. At the end of Phase 2: if `tx.anomaly_score >= tx.inbound_anomaly_score_threshold` (default: 5) → BLOCK.

**AWS WAF uses JSON rule format**:
```json
{
  "Name": "SQLiRule",
  "Priority": 10,
  "Statement": {
    "SqliMatchStatement": {
      "FieldToMatch": {"QueryString": {}},
      "TextTransformations": [
        {"Priority": 0, "Type": "URL_DECODE"},
        {"Priority": 1, "Type": "HTML_ENTITY_DECODE"}
      ],
      "SensitivityLevel": "HIGH"
    }
  },
  "Action": {"Block": {}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "SQLiRule"
  }
}
```

---

## 7. Security Controls

### Encryption In Transit

**Client ↔ WAF**: TLS 1.3 mandatory. TLS 1.0/1.1 disabled (PCI DSS 4.0 requires this by March 2025). Cipher suites: AEAD only (no CBC-mode suites — no POODLE/BEAST exposure). HSTS with preload ensures browsers only use HTTPS:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

**WAF ↔ Origin**: TLS required (not optional). Origin certificate validation enforced (WAF doesn't forward to self-signed certs without explicit pinning). Prevents substitution attacks where a compromised internal service presents a fake cert.

**WAF internal state**: Rate limit counters in Redis are not sensitive (just IP + count), but session tokens in the challenge verification cache are. Redis should have authentication (`requirepass`) and TLS. In-memory state in WAF processes: protected by process isolation, not encrypted (key material should never be in WAF memory beyond the TLS session duration).

### Input Validation as a WAF Control

The WAF's entire purpose is input validation at the perimeter. Layers:

1. **Structural validation**: Is this valid HTTP? Valid JSON/XML? Are headers well-formed?
2. **Size limits**: Max URI length (4096 bytes), max header size (8192 bytes), max body size (configured per endpoint — API: 1MB, file upload: 100MB, JSON API: 64KB).
3. **Character set validation**: URLs should contain only printable ASCII. Non-ASCII in URIs requires encoding. Null bytes in any field → reject.
4. **Pattern matching**: Signature-based rules for known attack patterns.
5. **Semantic validation**: Is the `page` parameter a positive integer? Can the WAF enforce this? (Custom rules can.)

**Defense-in-depth rationale**: WAF input validation is NOT a replacement for application-level input validation. It's a perimeter defense. The application must still parameterize SQL queries, HTML-encode output, validate file types, etc. WAF is the first line; application security is the last.

### Access Control at the WAF

WAFs implement access control that precedes application-level auth:

- **IP-based allowlisting**: Admin panels (`/admin/*`) accessible only from office IP ranges. WAF blocks all other IPs before the request reaches the app.
- **Geo-blocking**: If the business only operates in North America, block all other countries at the WAF. Reduces attack surface from international actors.
- **Rate limiting as access control**: Effectively limits the rate of API calls, functioning as coarse-grained quotas.
- **Authentication endpoint protection**: `/login` and `/register` protected by CAPTCHA or JS challenge for non-browser clients.

### Secrets Handling in WAF Configuration

WAF configurations contain sensitive data:
- **Origin server address**: Never expose in public documentation.
- **API keys for TI feed access**: Stored in secrets manager, injected at deployment.
- **Cookie signing keys** (if WAF does cookie encryption): Rotated regularly, stored in HSM or secrets manager.
- **WAF API keys/tokens** (for WAF management API): Used by automation to update rules. Must be rotated and have minimal permissions.

**WAF rule as a secret**: Custom rules may contain information about your application's internal structure (e.g., "block paths matching `/internal/v2/admin/*`"). This reveals internal path structure if the rules are leaked. Treat WAF rule configurations as sensitive.

---

## 8. Attack Surface Mapping

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                    WEB APPLICATION FIREWALL — ATTACK SURFACE MAP                 ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║  EXTERNAL ATTACK SURFACE (Internet-facing)                                        ║
║                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐    ║
║  │  WAF RULE BYPASS SURFACE                                                 │    ║
║  │                                                                           │    ║
║  │  Entry: Any HTTP/HTTPS request to the WAF's IP                           │    ║
║  │                                                                           │    ║
║  │  Attack vectors:                                                         │    ║
║  │  • Encoding evasion (multi-layer URL encoding, unicode tricks)           │    ║
║  │  • HTTP protocol abuse (chunked encoding, pipelining)                   │    ║
║  │  • Parser confusion (inconsistent parsing between WAF and origin)       │    ║
║  │  • Rule gaps (payload types not covered by ruleset)                     │    ║
║  │  • Rate limit bypass (distribute across IPs, rotate sessions)           │    ║
║  │  • Threshold gaming (stay just under anomaly score threshold)           │    ║
║  │  • WAF fingerprinting (determine WAF vendor, find known bypasses)       │    ║
║  └─────────────────────────────────────────────────────────────────────────┘    ║
║                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐    ║
║  │  DENIAL OF SERVICE SURFACE                                               │    ║
║  │                                                                           │    ║
║  │  • Volumetric DDoS: absorb WAF capacity (Gbps attack vs WAF capacity)   │    ║
║  │  • Rule engine DoS: ReDoS (regex exhaustion via crafted input)          │    ║
║  │  • State exhaustion: max out WAF session/connection tables              │    ║
║  │  • CAPTCHA bypass at scale: CAPTCHA-solving services                   │    ║
║  │  • Distributed rate limit evasion: millions of IPs, each under limit   │    ║
║  └─────────────────────────────────────────────────────────────────────────┘    ║
║                                                                                   ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 1: Internet → WAF Edge (TLS terminated here)                     ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐    ║
║  │  ORIGIN BYPASS SURFACE                                                   │    ║
║  │                                                                           │    ║
║  │  The biggest WAF risk: attackers discover origin IP and bypass WAF.     │    ║
║  │                                                                           │    ║
║  │  Discovery vectors:                                                      │    ║
║  │  • Historical DNS records (SecurityTrails, Shodan)                      │    ║
║  │  • SSL certificates (Certificate Transparency logs → origin's cert     │    ║
║  │    may have SANs with internal hostnames or the real IP)               │    ║
║  │  • Email headers (SMTP server IP in Received: header)                  │    ║
║  │  • Application error messages (stack traces with IP)                   │    ║
║  │  • Subdomains without WAF (api.example.com → direct origin)           │    ║
║  │  • SSRF from another compromised service                               │    ║
║  │  • Cloud metadata (S3 bucket names, Lambda URLs expose region)        │    ║
║  └─────────────────────────────────────────────────────────────────────────┘    ║
║                                                                                   ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 2: WAF → Origin (WAF IP range allowlisted at origin)             ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐    ║
║  │  WAF MANAGEMENT / CONTROL PLANE SURFACE                                  │    ║
║  │                                                                           │    ║
║  │  Entry: WAF management console/API (AWS Console, Cloudflare Dashboard)  │    ║
║  │                                                                           │    ║
║  │  Attack vectors:                                                         │    ║
║  │  • WAF management credential compromise → attacker modifies rules      │    ║
║  │  • Rule deletion/weakening → removes protection                        │    ║
║  │  • Adding attacker's IP to allowlist → bypass                          │    ║
║  │  • Disabling logging → removes detection capability                    │    ║
║  │  • WAF API key leakage (in code repos, CI/CD logs)                    │    ║
║  └─────────────────────────────────────────────────────────────────────────┘    ║
║                                                                                   ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 3: Management Plane (requires separate auth)                      ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐    ║
║  │  INTERNAL SURFACE                                                         │    ║
║  │                                                                           │    ║
║  │  • WAF log pipeline (CloudWatch, S3) — integrity of logs               │    ║
║  │  • Redis (rate limit state) — cache poisoning, state manipulation      │    ║
║  │  • TI feed update pipeline — feed poisoning (false allowlisting)       │    ║
║  │  • WAF config as code (Terraform/CDK) — SCM compromise                │    ║
║  │  • WAF software supply chain — WAF software vulnerabilities            │    ║
║  └─────────────────────────────────────────────────────────────────────────┘    ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 9. Attack Scenarios

### Scenario 1: SQL Injection with Multi-Layer Encoding Bypass

**Attacker Assumptions:**
- Target runs a WAF (identified via `Server: cloudflare` header, or WAF-specific block page).
- WAF uses signature-based SQLi detection.
- WAF normalizes one layer of URL encoding before matching.
- The origin application uses string concatenation for SQL queries (vulnerable to SQLi).

**Step-by-Step Execution:**

1. **WAF fingerprinting**: Attacker sends: `GET /search?q=' HTTP/1.1` → Gets a 403 with Cloudflare/AWS WAF block page. Confirms WAF type.

2. **Baseline payload**: `GET /search?q='%20OR%20'1'='1` → 403. Single URL-encoded SQLi is blocked.

3. **Double URL encoding**:
   The attacker encodes the already-encoded string:
   - Raw: `' OR '1'='1`
   - URL encoded: `%27%20OR%20%271%27%3D%271`
   - Double URL encoded: `%2527%2520OR%2520%25271%2527%253D%25271`
   
   Sends: `GET /search?q=%2527%2520OR%2520%25271%2527%253D%25271`

4. **WAF evaluation** (if misconfigured to only decode once):
   - WAF URL-decodes once: `%2527` → `%27`, `%2520` → `%20`
   - WAF sees: `%27%20OR%20%271%27%3D%271` (still encoded — no SQL pattern match)
   - WAF: **ALLOW**

5. **Origin evaluation**:
   - Origin web framework URL-decodes: `%27%20OR%20%271%27%3D%271` → `' OR '1'='1`
   - SQL query: `SELECT * FROM products WHERE name = '' OR '1'='1'`
   - Result: all rows returned → SQLi successful.

**Where Detection Could Happen:**
- Application logs: unusual `%25`-encoded query strings (double-encoded is a red flag).
- Database monitoring: `WHERE 1=1` clauses in queries (via database activity monitoring tool like Imperva DAM or AWS RDS audit logging).
- WAF count mode: if WAF has a "count" rule that matches even patterns it doesn't block — these alerts surface the attempt even when action is ALLOW.
- SIEM anomaly: unusual number of rows returned from a query that normally returns a few results.

**Why This Works:**
The gap between WAF normalization depth (1 decode pass) and origin normalization depth (2 decode passes due to framework + application logic) creates the bypass. This is the "parser differential" attack class.

**Fix:**
Configure WAF with multiple transformation passes: `URL_DECODE` → match, then `URL_DECODE` again → match. Or use `URL_DECODE_UNI` (full unicode-aware URL decoding, handles nested encoding). AWS WAF's `TextTransformations` can chain multiple transforms in priority order.

---

### Scenario 2: WAF Bypass via HTTP Request Smuggling

**Attacker Assumptions:**
- WAF and origin are connected via HTTP/1.1 (not HTTP/2, which has unambiguous framing).
- WAF uses `Content-Length` to determine request body length.
- Origin uses `Transfer-Encoding: chunked` if present.

**Step-by-Step Execution:**

1. Attacker sends a CL.TE smuggling request:

```
POST /search HTTP/1.1
Host: app.example.com
Content-Length: 49
Transfer-Encoding: chunked

e
q=blue+shoes
0

POST /admin HTTP/1.1
X-Forwarded-For: 127.0.0.1
Content-Length: 0

```

2. **WAF evaluation**:
   - WAF reads `Content-Length: 49`.
   - Reads 49 bytes of body: `e\r\nq=blue+shoes\r\n0\r\n\r\nPOST /admin HTTP/1.1\r\n...`
   - WAF sees this as one request with a chunked-looking body.
   - WAF inspects the body for injection patterns: `q=blue+shoes` looks clean.
   - WAF: **ALLOW** (forwarded to origin).

3. **Origin evaluation**:
   - Origin sees `Transfer-Encoding: chunked` (and may prefer it over `Content-Length`).
   - Reads chunk: `e` bytes (14 bytes) = `q=blue+shoes`, then `0` = end of body.
   - Origin treats the remaining data as a **new request**:
     `POST /admin HTTP/1.1\r\nX-Forwarded-For: 127.0.0.1\r\nContent-Length: 0\r\n\r\n`
   - This second request is prepended to the next legitimate user's request.
   - The combined request hits `/admin` with `X-Forwarded-For: 127.0.0.1`.
   - If the application trusts `X-Forwarded-For` for admin access (localhost bypass): **admin access granted**.

4. **Why WAF missed it**: WAF and origin parsed the same request body with different rules (CL vs TE priority). The WAF never saw the smuggled `/admin` request — it was hidden inside the body from WAF's perspective.

**Where Detection Could Happen:**
- Origin logs: unexpected `/admin` requests with `X-Forwarded-For: 127.0.0.1` that don't appear in WAF logs (log correlation gap).
- HTTP request smuggling detection tools (run periodically against your endpoints).
- HTTP/2 between WAF and origin: eliminates the attack entirely (HTTP/2 has unambiguous framing, no CL vs TE ambiguity).

**Why This Works:**
RFC 7230 says: if both `Content-Length` and `Transfer-Encoding` are present, `Transfer-Encoding` takes precedence. Different implementations handle this differently, creating the parsing differential.

---

### Scenario 3: ReDoS Attack Against WAF Rule Engine

**Attacker Assumptions:**
- WAF uses regex-based rules (OWASP CRS ModSecurity, or vendor-built rules).
- Attacker can identify which regex patterns are applied (via public CRS source code, or trial and error).
- WAF rule engine CPU is shared across all requests.

**Step-by-Step Execution:**

1. Attacker identifies a vulnerable regex in the rule engine. Example — a CRS rule checking for SQL `UNION SELECT`:

```
(?i:(?:[\s(]|^)union(?:\s+(?:all|distinct))?[\s(]+select(?:[\s(]+|\*))
```

This regex has catastrophic backtracking when given input like:
```
(((((((((((((((((((((((((((((((((((((((((((UNION
```

2. Attacker sends a flood of requests with this input:
```
GET /search?q=%28%28%28%28%28%28%28%28%28%28%28%28%28%28%28%28%28%28%28%28UNION HTTP/1.1
```

3. **WAF evaluation**:
   - WAF URL-decodes: `((((((((((((((((((((UNION`
   - Applies the UNION SELECT regex.
   - Regex engine backtracks exponentially: O(2^n) time where n = number of `(` characters.
   - WAF rule evaluation takes seconds instead of microseconds.
   - WAF CPU at 100%.

4. **Effect**:
   - If WAF rule engine uses limited CPU per request: this request is terminated (but CPU was still consumed for a window).
   - With hundreds of concurrent ReDoS requests: WAF CPU is fully consumed.
   - Legitimate requests queue up → timeout → WAF fails.
   - If WAF fails open: origin is exposed without WAF protection.
   - If WAF fails closed: DoS against your own application.

**Where Detection Could Happen:**
- WAF CPU metrics: sudden spike in rule evaluation time.
- Request latency: WAF inspection time > 1000ms (normal: 1–5ms).
- Rate limiting: these requests come from one IP in rapid succession — rate limiting fires before ReDoS impact is catastrophic.

**Why This Works:**
PCRE regex patterns without backtracking protection are vulnerable to catastrophic backtracking. The attacker's input is specifically crafted to maximize backtracking steps.

**Fix:**
Use `PCRE_STUDY` (optimization) and set `pcre_match_limit` and `pcre_match_limit_recursion` in ModSecurity. Use RE2 or Hyperscan regex engines (linear time, no backtracking — used by Cloudflare). AWS WAF uses a proprietary engine with backtracking protection. Never write custom WAF rules with nested quantifiers.

---

### Scenario 4: WAF Fingerprinting and Targeted Bypass

**Attacker Assumptions:**
- Attacker wants to know which WAF vendor and version is deployed.
- Different WAF vendors have different rule sets and known bypasses.

**Step-by-Step Execution:**

1. **Active fingerprinting**:
   - Send a known attack payload and observe the block page format.
   - AWS WAF block pages: minimal, no server header.
   - Cloudflare block pages: include `CF-RAY` header, distinctive HTML format.
   - ModSecurity: includes `ModSecurity` in the `Server` header (if misconfigured).
   - F5 ASM: specific error codes in the block page body.

2. **Passive fingerprinting**:
   - Observe response headers: `CF-Cache-Status`, `X-Cache`, `X-Amz-Cf-Id`, `Strict-Transport-Security` format.
   - TLS fingerprint of the WAF's TLS stack (JA3S): each WAF vendor has characteristic JA3S values.
   - HTTP/2 settings frame: WAF vendors have characteristic initial SETTINGS values (MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, etc.).

3. **Look up known bypasses**:
   - GitHub: "Cloudflare WAF bypass 2025", "AWS WAF XSS bypass".
   - Known bypass for Cloudflare XSS rule (example, not current):
     ```
     <svg/onload=alert(1)//
     ```
     Versus standard `<script>alert(1)</script>` which is blocked.

4. **Exploit identified bypass**:
   - Test the bypass in COUNT mode (attacker doesn't know count mode is configured, but can test if the payload succeeds at the origin without triggering a block page).
   - If bypass works: proceed with actual attack payload.

**Where Detection Could Happen:**
- Fingerprinting attempts generate characteristic patterns in logs: many different payloads from one IP, all blocked, in rapid succession.
- WAF sampling: log sampled requests even when allowed — fingerprinting requests may appear.
- GuardDuty / threat detection: "Port scanning equivalent" at HTTP layer.

**Why This Works:**
WAF vendors publish their rule sets (OWASP CRS is open-source). Researchers (and attackers) continuously test WAF rules and publish bypasses. WAF vendors patch, attackers find new bypasses. It's a cat-and-mouse game.

---

### Scenario 5: Origin IP Discovery and Direct Attack

**Attacker Assumptions:**
- The target uses Cloudflare WAF.
- Attacker wants to attack the origin directly (bypassing WAF entirely).

**Step-by-Step Execution:**

1. **Historical DNS lookup**: Using SecurityTrails or ViewDNS, look up historical A records for `app.example.com`. Before Cloudflare was added, the A record pointed directly to `52.1.2.3` (the origin's EIP). This IP is still active.

2. **Verification**: `curl -H "Host: app.example.com" https://52.1.2.3/` → The origin responds! It doesn't check whether the request came through Cloudflare.

3. **Direct attack**: Attacker now sends attack payloads directly to `52.1.2.3` with `Host: app.example.com`. The WAF is completely bypassed.

4. **SQLi directly to origin**:
   ```
   GET /search?q=' OR '1'='1 HTTP/1.1
   Host: app.example.com
   ```
   Sent to `52.1.2.3:443`. No WAF. SQLi succeeds.

**Where Detection Could Happen:**
- Origin access logs: requests from non-Cloudflare IPs. If origin is configured to only accept Cloudflare IPs (firewall rule / SG rule), this attack doesn't work.
- Monitoring: traffic to origin IP from non-WAF sources (CloudWatch metric filter on access logs).

**Why This Works:**
The WAF is only effective if the origin is inaccessible without going through the WAF. If the origin accepts connections from anywhere, the WAF is decorative. This is the most common WAF deployment error.

**Fix:**
- AWS: Security Group on EC2/ALB allows inbound 443 only from CloudFront's managed prefix list (`com.amazonaws.global.cloudfront.origin-facing`) or from Cloudflare's published IP ranges.
- Cloudflare Tunnel (Argo Tunnel): Origin makes an outbound tunnel to Cloudflare. No inbound port open at all on the origin. No IP to discover.
- Secret shared header: WAF adds `X-CDN-Secret: <rotating-secret>` to all forwarded requests. Origin validates this header and rejects requests without it. Attackers don't know the secret.

---

### Scenario 6: Rate Limit Evasion via Distributed Botnet

**Attacker Assumptions:**
- WAF has rate limiting: 100 requests/minute per IP.
- Attacker has access to a botnet of 100,000 IPs.
- Attacker wants to perform credential stuffing: test 1,000,000 username/password pairs.

**Step-by-Step Execution:**

1. **Botnet coordination**: Attacker's C2 server distributes the credential list across 100,000 bots. Each bot is responsible for testing 10 pairs.

2. **Rate-compliant requests**: Each bot sends 10 POST requests to `/login` spread over 10 minutes = 1 request per minute per IP. This is well under the 100/min rate limit.

3. **WAF evaluation**: Each individual IP is under the rate limit. No rate limit rule triggers. Requests are allowed.

4. **At origin**: 100,000 individual login attempts arrive over 10 minutes = ~167 per second. This may or may not trigger application-level rate limiting.

5. **Successful logins**: If 0.5% of credentials are valid: 5,000 accounts compromised.

**Where Detection Could Happen:**
- Application-level: total login failure rate (global across all IPs) spikes dramatically.
- WAF anomaly: same password used across thousands of different usernames/IPs (velocity on credential patterns, not just IPs).
- User notification: failed login email alerts trigger for accounts being tested.
- ML-based WAF features: behavioral clustering identifies coordinated traffic even without per-IP rate limit violation.

**Why This Works:**
Rate limiting by IP is a necessary but insufficient control against distributed attacks. The attacker scales horizontally to stay under per-IP limits while exceeding the origin's safe total capacity.

**Fix:**
- Device fingerprinting: TLS fingerprint (JA3), HTTP/2 fingerprint, canvas/font fingerprinting. Bots often share fingerprints even across different IPs.
- Global rate limiting: limit total failed login rate across ALL IPs (e.g., 1,000 failed logins/minute globally → trigger CAPTCHA for all login attempts).
- Credential-stuffing-specific detection: alert when the same password appears in multiple failed login attempts.
- CAPTCHA or JS challenge on the login endpoint for all requests (not just rate-limited ones).
- Account lockout + notification at the application level.

---

## 10. Failure Points

### Under Load

**Rule engine CPU saturation**:
Complex regex rules are CPU-intensive. Under high traffic, rule evaluation time increases from 1–2ms to 50–500ms. This increases overall request latency. If the WAF is inline and can't process fast enough, it either queues requests (increasing latency) or drops them (dropping legitimate traffic).

**Mitigation**: WAF horizontal scaling (more nodes behind an Anycast load balancer). Per-request CPU budgets for rule evaluation (terminate evaluation after X milliseconds, use the accumulated score so far).

**Memory exhaustion from large body parsing**:
JSON or XML bodies up to 64KB are common. Malicious actors send 10MB JSON blobs (`Content-Length: 10485760`). If the WAF buffers the entire body before evaluation (necessary for some rules), 1,000 simultaneous large body requests = 10GB memory consumed.

**Mitigation**: Stream-based inspection (inspect body as it arrives, don't buffer entirely). Size limits enforced before buffering (`Content-Length` checked before reading body — if too large, reject immediately with 413).

**State table exhaustion**:
Rate limiting state (Redis/in-memory counters) grows with unique IP count. A large DDoS with millions of unique IPs can exhaust the rate limiting state table.

**Mitigation**: Probabilistic data structures (Count-Min Sketch) for rate limiting — O(1) memory regardless of unique IP count, with small error rate.

**TLS session cache exhaustion**:
TLS session resumption requires maintaining session state. Under millions of connections, the session cache fills. New connections fall back to full TLS handshakes (higher CPU).

### Under Attack

**Slowloris against WAF**:
Attacker opens many connections and sends headers very slowly (1 byte per 15 seconds). WAF holds connections open waiting for the complete request. Thousands of slow connections exhaust the WAF's concurrent connection limit.

WAF defense: connection timeout (reject connections that don't complete a request within N seconds), max concurrent connections per IP.

**SSL/TLS exhaustion (THC-SSL-DOS style)**:
TLS handshakes are asymmetrically expensive: server computation (RSA key exchange or ECDHE) is more expensive than client computation. Attacker initiates and renegotiates TLS handshakes rapidly, exhausting WAF TLS processing capacity.

WAF defense: Disable TLS renegotiation. Use TLS 1.3 (no renegotiation in 1.3). Rate limit TLS handshakes per IP.

**Logic bomb in rules**:
If an attacker can modify WAF rules (via compromised management credentials), they can insert a rule that:
- Allowlists their attack IP: `IP matches 203.0.113.5 → ALLOW all`
- Disables specific protection rules.
- Fails open under specific conditions.

WAF defense: Require MFA for WAF management access. Immutable rule audit trail. Automated compliance check (WAF rules as code in version control, drift detection).

### Common Misconfigurations

| Misconfiguration | Impact | Detection |
|---|---|---|
| All rules in COUNT mode | WAF logs but never blocks — security theater | Verify rule actions via WAF console; test with known attack payloads |
| High anomaly score threshold | SQLi/XSS patterns allowed through (score 5 allowed when threshold is 10) | Run WAF test suite; penetration test |
| Missing body inspection | POST body attacks bypass WAF (only URI/headers inspected) | Check WAF config for body inspection rules |
| No origin IP protection | WAF bypassed by direct origin access | Verify origin security groups/firewall rules |
| Logging disabled | No visibility into attacks or false positives | Check WAF logging configuration |
| No response inspection | Data exfiltration in responses undetected | Review if DLP rules are configured |
| WAF only on production | Dev/staging endpoints directly accessible | Apply WAF to all environments |
| Overly permissive geo rules | All countries allowed when only one is needed | Review geo-blocking configuration |
| Default rule set only | No custom rules for application-specific attacks | Check for custom rules tailored to the application |
| X-Forwarded-For trusted blindly | Attacker spoofs their IP to bypass IP-based rules | Configure WAF to use the actual connection IP, not XFF |
| Content-Length not validated | Large body DoS | Check max body size configuration |
| No rate limiting on auth endpoints | Credential stuffing unrestricted | Check rate limit rules on /login, /api/auth/* |

---

## 11. Mitigations

### Defense-in-Depth WAF Strategy

The WAF is ONE layer. Every layer below it must be independently secure. A request that bypasses the WAF must still be stopped by the application.

```
Layer 1: Network / CDN DDoS Protection
   - Absorb volumetric attacks (Gbps scale)
   - Anycast routing to nearest PoP
   - BGP-level traffic scrubbing

Layer 2: WAF Perimeter (this document)
   - IP reputation, geo-blocking
   - Signature-based detection (SQLi, XSS, SSRF, etc.)
   - Rate limiting, bot management
   - Protocol validation

Layer 3: Application Gateway / Load Balancer
   - TLS termination (if not at WAF)
   - Health checking, circuit breaking
   - Connection limits

Layer 4: Application Authentication
   - MFA enforcement
   - Session management (secure cookies, rotation)
   - JWT validation

Layer 5: Application Input Validation
   - Parameterized queries (SQL injection defense)
   - Output encoding (XSS defense)
   - File type validation (upload defense)
   - Size limits

Layer 6: Data Layer
   - Database access controls (least privilege)
   - Encryption at rest
   - Audit logging

Layer 7: Detection & Response
   - SIEM integration
   - Anomaly detection
   - Incident response playbooks
```

### Concrete Fixes

**Fix 1: Multi-pass normalization in WAF rules**

Configure transformation chains that apply multiple decoding passes:
```json
"TextTransformations": [
  {"Priority": 0, "Type": "URL_DECODE"},
  {"Priority": 1, "Type": "HTML_ENTITY_DECODE"},
  {"Priority": 2, "Type": "URL_DECODE"},
  {"Priority": 3, "Type": "LOWERCASE"}
]
```

**Fix 2: Origin IP protection**

```
Option A (AWS): 
  Security Group on ALB → Inbound 443 from:
    aws_managed_prefix_list.cloudfront.id only
  
Option B (Cloudflare Tunnel):
  Origin runs cloudflared daemon
  Outbound-only connection to Cloudflare
  No inbound port open on origin

Option C (Shared Secret Header):
  WAF config: Add header X-Origin-Verify: {secret}
  Origin: Middleware checks header, returns 403 if missing
  Secret rotated monthly, stored in Secrets Manager
```

**Fix 3: Rate limiting architecture**

```
Layered rate limits (AWS WAF):

Rule 1: IP-based coarse limit
  - Rate: 2000 requests / 5 minutes per IP
  - Action: Block (DDoS protection)

Rule 2: Auth endpoint strict limit  
  - URI matches /login, /signin, /api/token
  - Rate: 20 requests / 5 minutes per IP
  - Action: Block

Rule 3: API key rate limit
  - Header X-API-Key present
  - Rate: 1000 requests / minute per API key value
  - Action: Block (sends 429)

Rule 4: Global login failure rate (Lambda-triggered)
  - CloudWatch metric: login failures > 500/minute (across all IPs)
  - Action: Enable CAPTCHA requirement on /login endpoint
            via WAF rule toggle (automation)
```

**Fix 4: WAF rule testing and CI/CD integration**

```bash
# WAF test suite (run in pre-deploy pipeline)
# Tests that attack payloads are BLOCKED:

tests_blocked=(
  "?q=' OR '1'='1"                         # SQLi
  "?q=<script>alert(1)</script>"            # XSS
  "?path=../../../etc/passwd"              # Path traversal
  "?url=http://169.254.169.254/meta-data/" # SSRF
  "?q=%27%20OR%20%271%27%3D%271"          # Encoded SQLi
)

for payload in "${tests_blocked[@]}"; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://app.example.com/search${payload}")
  if [ "$response" != "403" ]; then
    echo "FAIL: ${payload} returned ${response}, expected 403"
    exit 1
  fi
done

# Tests that legitimate requests are ALLOWED:
tests_allowed=(
  "?q=blue+shoes&page=1"
  "?q=SELECT+YOUR+SIZE&category=shirts"   # "SELECT" is a word, not SQLi
  "?q=<winter+sale>&type=promotion"       # < in legit context
)
```

**Fix 5: ReDoS prevention in custom rules**

```
WRONG (catastrophic backtracking):
  Pattern: (a+)+b
  Input: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  → Exponential backtracking

CORRECT (possessive quantifiers / atomic groups):
  Pattern: (?>a+)+b  (possessive: no backtracking into the group)
  Or use RE2/Hyperscan engine (linear time guarantee)

AWS WAF: Uses a proprietary linear-time engine — safe.
ModSecurity: Uses PCRE. Must set:
  SecPcreMatchLimit 100000
  SecPcreMatchLimitRecursion 100000
  → These cap backtracking, causing rule evaluation to fail
    (not match) rather than hang.
```

**Engineering Tradeoffs Table:**

| Decision | Pros | Cons |
|---|---|---|
| High paranoia level (PL4) | Catches more attacks | High false positive rate, blocks legitimate traffic |
| Low paranoia level (PL1) | Low false positives | Misses some attack variants |
| Anomaly scoring (OWASP default) | Reduces FP vs per-rule blocking | Complex to tune, harder to reason about |
| Per-rule blocking | Simple, deterministic | More FP — one rule fires on legitimate request → block |
| Block mode | Actually protects | Risk of blocking legitimate users (FP) |
| Count/detect-only mode | No disruption | No actual protection |
| Custom rules only | Tailored to app | Miss zero-days not in custom rules |
| Managed rules only | Vendor maintains | May not cover app-specific logic |

---

## 12. Observability

### WAF Logs: What to Capture, What to Avoid

**Enable full WAF logging with these fields:**

```json
{
  "loggingConfiguration": {
    "resourceArn": "arn:aws:wafv2:...",
    "logDestinationConfigs": ["arn:aws:kinesis:..."],
    "redactedFields": [
      {"singleHeader": {"name": "authorization"}},
      {"singleHeader": {"name": "cookie"}},
      {"queryString": {}}
    ],
    "filteringConfiguration": {
      "defaultBehavior": "KEEP",
      "filters": [
        {
          "behavior": "DROP",
          "conditions": [
            {"actionCondition": {"action": "ALLOW"}},
            {"labelNameCondition": {"labelName": "awswaf:managed:bot:verified"}}
          ]
        }
      ]
    }
  }
}
```

Note: Redacting `authorization`, `cookie`, and `queryString` removes sensitive data from logs. This is a tradeoff — you lose the ability to see what credential was used, but you protect session tokens from log theft.

**Log fields that MUST be present:**

| Field | Value | Why |
|---|---|---|
| `timestamp` | ISO8601 with ms | Precise timing for incident reconstruction |
| `action` | ALLOW/BLOCK/CHALLENGE/COUNT | Know what the WAF decided |
| `terminatingRuleId` | Rule that caused the decision | Debug which rule matched |
| `httpRequest.clientIp` | Source IP | Attacker identification |
| `httpRequest.uri` | Path + query | What was requested |
| `httpRequest.httpMethod` | GET/POST/etc. | Method used |
| `requestId` | UUID | Correlate with origin access logs |
| `ja3Fingerprint` | TLS fingerprint | Bot identification across IP changes |
| `httpRequest.country` | Geo code | Geographic analysis |
| `ruleGroupList` | All matched rules | Understand full evaluation |

### Metrics

**CloudWatch Metrics for WAF (AWS WAF):**

```
AllowedRequests          — Total requests allowed. Baseline then alert on anomalies.
BlockedRequests          — Total blocked. Alert on sudden spikes (attack) or drops (rules disabled).
CountedRequests          — Rules in count mode matched. Monitor to tune before enabling block.
PassedRequests           — Requests that didn't match any rule.

Per-rule metrics:
  {WebACLName}/{RuleName}/AllowedRequests
  {WebACLName}/{RuleName}/BlockedRequests

Rate-based:
  BlockedRequests where RuleId = "RateLimitRule" — tells you how often rate limiting fires.

Custom metrics:
  WAF inspection latency (p50, p95, p99) — if p99 > 10ms, investigate rule complexity.
  False positive rate — (legitimate user reports / total allowed requests) × 100
```

**Metrics that SHOULD alert:**

| Metric | Condition | Severity | Action |
|---|---|---|---|
| BlockedRequests | Spike > 5x baseline in 5min | HIGH | Investigate active attack |
| BlockedRequests | Drop to 0 (rules disabled?) | CRITICAL | Check WAF config |
| AllowedRequests | Sudden drop | HIGH | WAF may be blocking all traffic (false positive surge) |
| 5xx from origin | Spike > 1% of requests | HIGH | Origin overwhelmed despite WAF |
| WAF rule count | Rule deleted | CRITICAL | Unauthorized rule modification |
| Auth endpoint block rate | > 100 blocks/min | MEDIUM | Credential stuffing in progress |
| ReDoS indicator (eval time) | P99 > 50ms | HIGH | ReDoS attack or complex regex |

**Metrics that SHOULD NOT alert (to avoid alert fatigue):**

- Normal BlockedRequests within baseline range (scanners hit your site every day).
- Individual 403 responses from known scanner IPs (already blocked by IP reputation).
- Rate limit blocks from known CI/CD IPs (add to allowlist).
- Bot traffic blocks (legitimate — expected to be high).

### Traces

**Distributed tracing across WAF + origin**:

The WAF adds a request ID to every forwarded request:
```
X-Request-ID: waf-550e8400-e29b-41d4-a716-446655440000
```

The origin logs this ID in its access log. When investigating an incident:
1. Find the WAF log entry by `requestId`.
2. Find the origin log entry by `requestId` (X-Request-ID).
3. Correlate: WAF allowed it (or didn't — if only in WAF log, it was blocked before origin).
4. Find downstream traces (database query, external API calls) by the same request ID.

**WAF inspection timing as a trace**:

```
Total request time: 250ms
  WAF Phase 1 (IP/connection): 0.5ms
  WAF Phase 2 (HTTP parsing): 0.8ms
  WAF Phase 3 (rule eval): 2.1ms   ← if this is > 10ms, rule complexity issue
  Network WAF→Origin: 5ms
  Origin processing: 241ms
  Network Origin→WAF: 0.6ms
```

This decomposition requires either WAF vendor APM support or custom logging with timestamps at each phase.

### What to Alert On (Summary)

```
CRITICAL (page immediately):
  • WAF completely unavailable (health check fails)
  • BlockedRequests = 0 for > 5 minutes (rules possibly disabled)
  • WAF management credentials used from unusual location
  • CloudTrail: WAF rule deleted or modified

HIGH (alert, investigate within 1 hour):
  • BlockedRequests spike > 10x baseline (large attack)
  • Auth endpoint blocks > 1000/minute (credential stuffing)
  • 5xx error rate from origin > 5% (WAF passing through too much)
  • New IP range appearing in BlockedRequests at high rate (new attack campaign)

MEDIUM (investigate next business day):
  • Repeated blocks from same IP range (persistent attacker)
  • False positive report from a specific IP (customer complaint)
  • WAF rule in COUNT mode matching > 1000 times/hour (review for block mode)
  • New country appearing in traffic (geo expansion or proxy)

LOW (log, no alert):
  • Normal bot scanning blocked
  • Standard rate limit blocks
  • Single request blocks (one-off scanner)
```

---

## 13. Scaling Considerations

### How WAFs Scale (and Where They Don't)

**Cloudflare / AWS CloudFront + WAF (Managed SaaS WAF)**:

These scale automatically. The WAF runs on thousands of nodes globally. You don't provision capacity. The constraint is your account-level quotas (max rules, max rule size, max rate limit rules).

Practically: the bottleneck is not WAF throughput — it's rule evaluation complexity. Adding 1,000 custom regex rules multiplies CPU per request by 1,000. With SaaS WAFs, this is absorbed by their infrastructure, but it increases latency (and cost, since many charge per million WAF requests × rule count).

**Self-managed WAF (nginx + ModSecurity)**:

You manage capacity. The scaling model:

```
Vertical scaling (bigger instances):
  - WAF is single-process per nginx worker.
  - More CPU cores → more nginx workers → more parallel request evaluation.
  - Memory: needed for TLS session cache, rule sets (CRS is ~5MB RAM).
  - Effective up to ~64 vCPUs, then returns diminish.

Horizontal scaling (more WAF instances):
  - Add WAF nodes behind a TCP/UDP load balancer (NLB in AWS).
  - Each node is stateless for request inspection (stateless scale-out).
  - Rate limiting state (Redis) must be shared: centralized Redis cluster.
    - Redis becomes the bottleneck at very high scale.
    - Redis Cluster (sharded): partition rate limit counters by IP hash.
  - TLS session resumption: session tickets (stateless) work across nodes.
    Session IDs (stateful) require sticky routing or shared session store.
```

### Rate Limiting at Scale — Consistency Tradeoffs

Rate limiting is a distributed counting problem. The tradeoff: accuracy vs scalability.

**Exact counting (centralized Redis)**:
- All WAF nodes → single Redis cluster → exact counts.
- Problem: Redis becomes a single bottleneck. At 100,000 req/sec with 50-byte write per request → 5MB/sec write to Redis. Feasible at small scale, painful at large.
- Redis latency: 1ms per lookup/increment. For WAF at 10,000 req/sec per node: 10,000 Redis calls/sec per node.

**Approximate counting (local + sync)**:
- Each WAF node maintains local counters.
- Periodically (every 100ms) sync local counts to Redis.
- Other nodes read from Redis at the same interval.
- Accuracy: within 100ms window, a request might be allowed even after the limit is hit (during the sync gap).
- For a rate limit of 100 req/min: 100ms sync gap allows ~0.17 extra requests. Acceptable error.
- At high scale: dramatically reduces Redis pressure.

**Probabilistic rate limiting (Count-Min Sketch)**:
- Fixed memory, O(1) update and query.
- Slight overestimate (never underestimates — safe for rate limiting).
- Shared sketch across nodes via Redis using HyperLogLog or custom bitmap.
- Used by Cloudflare and other large-scale WAF providers internally.

### Rule Deployment and Consistency

When you update WAF rules (add a new rule, change a threshold), the update must propagate to all WAF nodes:

```
Rule update committed to WAF config store
    |
    | Propagation: seconds to minutes depending on WAF
    v
All WAF edge nodes receive updated rules

During propagation window:
  - Some nodes have old rules, some have new.
  - This is normal and acceptable for most rule changes.
  - For security-critical changes (blocking an active attack):
    Propagation latency matters. Managed SaaS WAFs typically
    propagate in < 30 seconds globally.
    Self-managed WAFs: depends on your config management pipeline
    (Ansible/Terraform may take minutes).

Blue/green rule deployment:
  - To test new rules without disruption:
    1. Deploy new rules in COUNT mode (logs only, no blocking).
    2. Monitor false positive rate for 24–48 hours.
    3. Switch to BLOCK mode if FP rate is acceptable.
  - AWS WAF supports this via rule action overrides.
```

---

## 14. Interview Questions

### Q1: Explain what happens when a WAF is in "count mode" vs "block mode." Are there scenarios where count mode actually reduces security without the operator knowing?

**Why asked**: Tests understanding of WAF operational modes and subtle security gaps.

**Answer direction**:

Count mode means the WAF evaluates the rule and logs the match but takes no blocking action — the request is allowed to proceed to origin. Block mode means the WAF stops the request and returns a 403.

**Scenarios where count mode reduces security without awareness**:

1. **All managed rules deployed in count mode** (this is the default on AWS WAF when you first add a managed rule group — operators don't always notice). The WAF is logging attacks that are successfully reaching the origin.

2. **Anomaly scoring with count mode**: In OWASP CRS with anomaly scoring, count mode rules still increment the anomaly score but the blocking rule (which checks if score ≥ threshold) is also in count mode. So even if a request scores 10 (way above threshold of 5), nothing is blocked.

3. **Rule A in count mode overrides rule B in block mode**: In some WAF configurations, rules are evaluated in priority order and the first matching rule wins. If a broad "allow" rule in count mode (lower priority number = evaluated first) matches a request, the more specific "block" rule is never reached.

4. **Testing misunderstanding**: "We tested with the attack payload and it logged correctly in count mode" — this is not a security test. The test should use block mode and verify the 403.

The correct use of count mode: initial deployment for tuning (monitoring FPs before enabling blocking), not as a permanent state.

---

### Q2: A WAF rule is blocking a legitimate request. A developer says "Just add an exception for our IP." Why might this be dangerous, and what's a better approach?

**Why asked**: Tests understanding of exception management and exception bloat.

**Answer direction**:

IP-based exceptions are dangerous for several reasons:

1. **IP spoofing in some contexts**: `X-Forwarded-For` can be forged. If the WAF trusts XFF for IP-based exceptions, an attacker can forge `X-Forwarded-For: <office_IP>` and bypass the rule. The WAF must use the actual TCP connection IP for exception matching, not XFF.

2. **Office IP changes**: DHCP, ISP changes, and VPN configurations change IP ranges. Exception breaks when IP changes; development team asks to add new IP; exceptions accumulate.

3. **Exception scope creep**: An exception for "our IP" typically uses a wildcard rule: "allow all traffic from 203.0.113.0/24." This disables WAF protection for everyone in that IP range, not just the specific developer. An attacker in the same network, coffee shop with the same public IP, or who compromises one machine in the range gets through.

4. **False root cause**: The rule triggered because the legitimate request looked malicious. Adding an exception hides the root cause. Better fix: understand WHY the rule triggered and either fix the application request (remove injection-like characters from legitimate parameters), tune the specific rule (narrow the match condition), or accept the risk with a documented exception that expires.

**Better approaches**:
- Fix the application to not send injection-like patterns in legitimate requests.
- Add a narrowly scoped exception: specific URI + specific parameter combination, not a broad IP exception.
- Use COUNT mode for the specific rule temporarily while investigating.
- If IP exception is necessary: scope it to the specific rule, specific IP, and set an expiry.

---

### Q3: What is JA3 fingerprinting, and how does a WAF use it for bot detection? Can it be evaded, and how?

**Why asked**: Tests knowledge of advanced bot detection techniques.

**Answer direction**:

**JA3** is a fingerprinting technique that hashes the parameters of a TLS ClientHello message:
- TLS version
- List of cipher suites offered (in order)
- List of TLS extensions (in order)
- Supported elliptic curve groups
- Elliptic curve point formats

These parameters differ between TLS implementations. A Java application, a Python `requests` library, a Chrome browser, and a curl command all have different characteristic JA3 hashes. The hash is computed as `MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)` = a 32-character hex string.

**WAF usage**:
- A request claiming to be a Chrome browser but with a Python/requests JA3 hash → User-Agent spoofing → bot.
- A request with a known malicious tool's JA3 hash (sqlmap, Nikto, curl with default config) → block or challenge.
- Rate limit by JA3 hash: a bot that rotates IPs but keeps the same JA3 hash (same tool) is still identifiable.

**Evasion**:
1. **JA3 randomization**: Some HTTP clients and bot frameworks randomize cipher suite order on each connection. Randomization produces different JA3 hashes. Detection is harder.
2. **Using a real browser for requests**: Playwright/Puppeteer with a headless Chrome has Chrome's actual JA3 hash. JA3-based detection fails for these.
3. **Proxy services**: Residential proxies with real browser stacks.

**JA3S** (server-side fingerprint): Hash the server's ServerHello parameters. Different WAF vendors have different JA3S values — useful for fingerprinting the WAF, not for blocking.

**Countermeasure**: JA3 alone is weak. Combine with HTTP/2 fingerprinting (SETTINGS frame values, window sizes, priority frames), canvas fingerprinting, and behavioral analysis for robust bot detection.

---

### Q4: Describe the mechanics of how an anomaly scoring WAF works. What is the paranoia level, and what is the tradeoff between paranoia level 1 and paranoia level 4?

**Why asked**: Tests deep understanding of OWASP CRS rule organization and tuning strategy.

**Answer direction**:

**Anomaly scoring mechanics**:
Each OWASP CRS rule has a severity level that maps to an anomaly score increment:
- CRITICAL: +5
- ERROR: +4
- WARNING: +3
- NOTICE: +2

Rules add to two score variables:
- `tx.anomaly_score`: inbound anomaly total
- `tx.inbound_anomaly_score_threshold`: the threshold (default: 5 for blocking)

At the end of Phase 2 (request body inspection), a blocking rule checks:
```
SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}"
    "id:949110,phase:2,deny,status:403,..."
```

If the score meets or exceeds the threshold, the request is blocked.

**Why anomaly scoring reduces false positives**: A single low-severity match (score +2) doesn't block the request. Multiple medium-severity matches that together hit the threshold do. This means a single benign request that happens to contain an unusual word doesn't get blocked, but a request with multiple indicators of attack does.

**Paranoia levels**:

Rules in OWASP CRS are tagged with a paranoia level (PL1–PL4). Each level adds more rules:

- **PL1** (default): High-confidence rules. Catches obvious, clearly malicious patterns. Very low false positive rate. Misses sophisticated, evasive attacks.
- **PL2**: More patterns, some legitimate inputs may match. Catches more attacks. Small FP increase. Suitable for most applications.
- **PL3**: Aggressive rules. Legitimate requests with SQL-like patterns (e.g., search query for "SELECT your favorite color") may trigger rules. Significant FP risk. Requires application-specific tuning.
- **PL4**: Extremely aggressive. Almost any unusual input triggers rules. Suitable only for highly locked-down APIs with very controlled input. High false positive rate. Requires extensive exception configuration.

**Practical guidance**: Start at PL1 in production. Deploy PL2–3 in COUNT mode, monitor false positives for 2–4 weeks. Enable block mode for PL2 if FP rate is acceptable. Evaluate PL3 only if your application has controlled, predictable inputs (API with schema-validated JSON, not free-text search).

---

### Q5: What is HTTP request smuggling? Give a concrete example of how it bypasses a WAF and what the fix is at the WAF and origin level.

**Why asked**: Tests understanding of a sophisticated HTTP protocol-level attack that specifically targets the WAF/origin gap.

**Answer direction**:

Already covered in Attack Scenario 2. Key extension points for interview:

**Why it specifically bypasses WAFs**: WAF and origin parse the request body boundary differently. The WAF "sees" one request; the origin "sees" two. The second, smuggled request was never inspected by the WAF.

**TE.CL variant** (the reverse — origin prefers Content-Length):
```
POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

96
q=shoes
0

GET /malicious HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
```
- WAF reads chunked: sees 0x96 bytes of body (the second request is the body).
- Origin reads Content-Length: 4 → `96\r\n` is the body (4 bytes). Remainder is new request.

**Fixes**:

1. **Use HTTP/2 between WAF and origin**: HTTP/2 has unambiguous framing — no CL vs TE ambiguity. Request smuggling in its classic form is impossible with HTTP/2.

2. **Normalize requests at WAF**: WAF strips one of the conflicting headers before forwarding. AWS ALB does this — if both CL and TE are present, it normalizes. If WAF is in front of ALB, the WAF should also normalize.

3. **Reject ambiguous requests**: If a request has both Content-Length and Transfer-Encoding: chunked, reject it with 400. This prevents the smuggling but may break some legitimate clients.

4. **Verify no gap in logs**: If a request appears in origin logs but NOT in WAF logs, it was smuggled. Log correlation tool should alert on this.

---

### Q6: What is the "confused deputy" problem in WAF context? Give a specific example of how an attacker exploits it.

**Why asked**: Tests creative application of a security concept (confused deputy) to WAF architecture.

**Answer direction**:

The confused deputy in WAF context is the **origin IP exposure problem**: The WAF (the deputy) is trusted by the origin to have already inspected requests. But if an attacker can send requests directly to the origin (by discovering its IP), they bypass the WAF. The WAF was supposed to act as the gatekeeper, but the origin doesn't verify that requests actually came through the WAF — it trusts anyone who knows its address.

**Specific example**:

The origin uses `X-Forwarded-For` to log the client's IP (for analytics). The WAF sets `X-Forwarded-For: <real_client_ip>` on forwarded requests.

An attacker discovers the origin IP (from Certificate Transparency logs) and sends directly:
```
POST /api/admin/user/delete HTTP/1.1
Host: app.example.com
X-Forwarded-For: 127.0.0.1
Content-Type: application/json

{"user_id": "victim_id"}
```

The application checks `X-Forwarded-For` to determine if the request is "local" and, if so, skips authentication (a bad pattern, but it happens). Attacker's forged XFF = `127.0.0.1`. Application thinks it's a local request. Deletes user. No WAF inspection happened.

**The double confused deputy**: The origin is confused (trusts the XFF header from anyone, not just the WAF). The application is confused (uses XFF for authentication decisions).

**Fix**:
1. Origin only accepts connections from WAF IP ranges (removes confused deputy at network level).
2. Application NEVER uses XFF for authentication decisions.
3. Use a shared secret header (WAF adds `X-Origin-Secret: <value>`; origin validates).

---

### Q7: Why do WAFs have false positives, and how do you systematically reduce them without weakening security?

**Why asked**: Tests practical WAF operations knowledge — the most common real-world WAF challenge.

**Answer direction**:

**Why false positives occur**:

1. **Regex overmatch**: A SQLi pattern like `\bOR\b` matches the word "OR" in legitimate text: "small OR medium size."
2. **URL structure mismatch**: Path-based rules designed for REST APIs firing on RPC-style URLs.
3. **Application-specific legitimacy**: A medical application legitimately sends body content like `patient has condition AND requires medication LIKE X.` The word `AND` and `LIKE` match SQL patterns.
4. **Rich text editors**: HTML editors send content with `<script>` tags legitimately (when editing blog content, for example).
5. **API payloads**: A JSON body with nested quotes: `{"query": "color = 'blue'"}` triggers SQLi rules on the `'blue'` value.

**Systematic reduction**:

1. **Deploy new rules in COUNT mode first** — measure FP rate before blocking.

2. **Parse false positive patterns** — group FP logs by:
   - Which rule triggered
   - Which URI triggered it
   - Which parameter triggered it
   Pattern: "SQLi rule 942100 triggers on /api/search for parameter `q` when it contains single quotes."

3. **Add targeted exceptions** (not broad IP exceptions):
   ```json
   {
     "ExcludedRules": [{
       "Name": "942100"
     }],
     "ScopeDownStatement": {
       "ByteMatchStatement": {
         "FieldToMatch": {"UriPath": {}},
         "SearchString": "/api/search",
         "PositionalConstraint": "STARTS_WITH"
       }
     }
   }
   ```
   This excludes rule 942100 only for requests to `/api/search`, not globally.

4. **Fix the application**: If `/api/search` receives raw SQL fragments in user input because the frontend sends them, fix the frontend to encode them differently.

5. **Tune the rule threshold**: Lower the anomaly score for a specific rule (change severity from CRITICAL to NOTICE), so it contributes less to the block threshold.

6. **Track FP rate over time**: Plot FP rate after each rule change. Downward trend = improving. Flat = stable. Upward = regression.

---

### Q8: What is the difference between a WAF and a Next-Generation Firewall (NGFW)? When would you use each, and when do you need both?

**Why asked**: Tests ability to distinguish overlapping security tools.

**Answer direction**:

| | WAF | NGFW |
|---|---|---|
| **Layer** | Layer 7 (HTTP/HTTPS) | Layer 3–7 (all protocols) |
| **Protocol awareness** | HTTP, WebSocket, some gRPC | TCP/UDP/IP + app identification |
| **Primary attacks blocked** | SQLi, XSS, SSRF, Path traversal, HTTP floods | Port scanning, network intrusion, protocol abuse |
| **TLS inspection** | Yes, by design (terminates TLS) | Optionally (expensive, separate config) |
| **Granularity** | HTTP method, URI, header, cookie, body field | Source/dest IP, port, protocol, app |
| **Deployment** | Inline HTTP reverse proxy | Network-level inline device |

**WAF doesn't protect against**:
- Network-level attacks (port scanning, ARP spoofing, ICMP flood on non-HTTP protocols).
- Non-HTTP services (SMTP, FTP, DNS abuse).
- Lateral movement between internal systems (it's only at the perimeter for HTTP).

**NGFW doesn't protect against**:
- Application-level attacks in valid HTTP traffic (it might see `SELECT` in a URL but doesn't understand SQL injection semantics).
- HTTP header manipulation.
- Business logic flaws.
- Fine-grained HTTP routing decisions.

**When you need both**:
In most enterprise environments:
- **NGFW** at the network perimeter: controls which services are reachable, blocks non-HTTP attack traffic, does URL filtering for outbound.
- **WAF** in front of web applications: inspects HTTP semantics, detects application attacks.

They're complementary. A request must pass NGFW (network level) AND WAF (application level) before reaching the application. Each layer defends against what the other can't see.

---

### Q9: Walk me through how TLS fingerprinting (JA3) can be used to detect that an attacker changed their IP but is using the same attack tool. What are the limits of this?

**Answer direction**: (Covered in Q3 above — extend with the following)

**Concrete detection scenario**:
An attacker using sqlmap has JA3 hash `a7a4dc87b7d71d85e06bdece60bc131d` (Python/urllib3 default JA3). They run sqlmap from IP A, which gets blocked (rate limit). They switch to IP B. But sqlmap still makes TLS connections with the same JA3 hash (same tool, same configuration).

WAF rule: `Block if JA3 = a7a4dc87b7d71d85e06bdece60bc131d AND Block requests > 10 from this JA3 in 5 minutes.`

Result: IP rotation doesn't help the attacker — JA3 identifies the tool.

**Limits**:
1. Tool authors can randomize cipher suite order per connection. sqlmap has this feature (`--random-agent` + transport randomization).
2. Residential proxies provide real browser TLS stacks.
3. JA3 databases need constant updates as tools update their TLS stacks.
4. Very high-volume legitimate services (corporate proxies, Akamai, Cloudflare itself) have well-known JA3 hashes that can't be blocked.

---

### Q10: A security team says "We're going to put our WAF in monitor-only mode during peak traffic hours so we don't risk false positives affecting users." What's wrong with this thinking, and what should they do instead?

**Why asked**: Tests operational judgment and WAF tuning philosophy.

**Answer direction**:

**Why this is exactly backwards**:

1. **Peak hours = highest attack risk**: Attackers specifically time attacks during high traffic periods because:
   - Anomalous requests are harder to detect in high-volume noise.
   - Security teams are focused on performance, not security.
   - Incident response is slower.
   - If the WAF is disabled, the timing is known and exploitable.

2. **False positive risk during peak hours is lower, not higher**: If your WAF has good false positive tuning, it should perform consistently regardless of traffic volume. If false positive rate is unacceptable, the problem is rule tuning, not traffic volume.

3. **Monitor-only during attacks is useless**: The entire value of a WAF is in its ability to block. A WAF that monitors but doesn't block is an expensive logging tool.

**What they should actually do**:

1. **Fix the false positive problem now** (outside peak hours): Deploy problem rules in COUNT mode, analyze which legitimate requests are being blocked, add targeted exceptions.

2. **Pre-compute high-confidence allow rules**: If `/api/v1/products` with only numeric query parameters never triggers false positives, add an explicit allow rule for that URI pattern. This pre-approves known-good traffic without disabling protection.

3. **Enable sampling**: Log 1% of allowed requests during peak hours (reduces log volume) but keep blocking active.

4. **Chaos-engineer the WAF**: Run known attack payloads against your staging environment during simulated peak load. Verify blocking still works and latency is acceptable.

5. **Progressive roll-out**: New rules go COUNT mode for 1 week → block mode for 10% of traffic → 100% if FP rate acceptable. Never disable existing rules for fear of false positives.

---

### Q11: What happens to the WAF when the origin is down? What does the user see, and what security implications does this have?

**Why asked**: Tests understanding of WAF behavior in failure modes and the interaction between availability and security.

**Answer direction**:

**If origin is down**:
- WAF receives the request, passes rule inspection (ALLOW action).
- WAF attempts to connect to origin (TCP connect to origin IP).
- Origin TCP connection fails (refused or timeout) or origin returns 5xx.
- WAF returns a 502 Bad Gateway or 504 Gateway Timeout to the client.

**Security implications of origin down**:

1. **WAF blocking still works**: Requests that would be blocked (BLOCK action) are still blocked before the origin connection attempt. The WAF blocks malicious requests even when the origin is down.

2. **DoS reveals WAF limits**: Attackers can deliberately take down the origin (if it's reachable directly — another reason for origin IP protection). With origin down, the WAF returns errors for all requests. From an attacker's perspective: they've achieved DoS against your users. From a security perspective: WAF is still blocking — the DoS didn't bypass the WAF.

3. **Custom error page security**: When the WAF returns 502/504, make sure the error page doesn't reveal:
   - Origin IP address
   - Internal hostnames
   - Technology stack (nginx, Apache, etc.)
   - Debug information

4. **Circuit breaker pattern**: WAF should detect that origin is down and return cached error responses quickly instead of waiting for each connection to timeout (5–30 seconds). Proper timeout configuration: WAF origin connection timeout: 10 seconds. WAF origin read timeout: 30 seconds.

5. **Failover origin**: WAF configured with multiple origin servers (primary and secondary). If primary is down, WAF fails over to secondary. The failover decision happens within the WAF — transparent to clients.

---

### Q12: If you were building a WAF from scratch, what are the five most important design decisions you'd make, and what would you trade off with each?

**Why asked**: Tests architectural thinking and understanding of core WAF design principles.

**Answer direction**:

**Decision 1: Rule engine: regex (PCRE) vs linear-time engine (RE2/Hyperscan)**

- PCRE: Flexible, supports backreferences (needed for some complex patterns). Vulnerable to ReDoS. Default for ModSecurity.
- RE2/Hyperscan: Linear time guarantee, no ReDoS possible. Can't do backreferences. Much faster at scale.
- **Choice**: RE2/Hyperscan for the core engine + PCRE with strict limits for complex patterns that require backreferences (isolate in a sandboxed process).

**Decision 2: Fail mode: open vs closed**

- Fail-open: WAF crash → traffic passes uninspected. Availability preserved.
- Fail-closed: WAF crash → all traffic blocked. Security preserved.
- **Choice**: Fail-open for public consumer websites (availability > security for a crashed WAF). Fail-closed for financial, healthcare, internal admin tools (security > availability). Make this configurable per protected application.

**Decision 3: Normalization depth**

- Single-pass: Fast, but misses multi-encoded payloads.
- Multi-pass: Slower, catches encoding evasion.
- **Choice**: Multi-pass with a maximum depth limit (e.g., 3 decoding passes). Track when additional decoding changed the input — if the request required 3 encoding layers to decode, that's anomalous and should add to the anomaly score.

**Decision 4: Inspection scope (request only vs response inspection)**

- Request only: Less CPU, lower latency. Misses data exfiltration in responses.
- Request + response: Higher CPU. Can detect sensitive data in responses (credit card numbers, SSNs, private keys in error messages).
- **Choice**: Request inspection always. Response inspection for high-value endpoints (payment flows, user data APIs) with a configurable set of DLP patterns (not all endpoints — the CPU cost is too high at scale).

**Decision 5: State management for rate limiting (exact vs approximate)**

- Exact (centralized Redis): Perfect accuracy, Redis bottleneck at scale.
- Approximate (Count-Min Sketch, local + async sync): Near-accurate, highly scalable.
- **Choice**: Exact for low-volume high-value endpoints (login, payment). Approximate for general traffic rate limiting where near-accuracy is sufficient. Threshold: below 10,000 req/sec per node → exact. Above → approximate.

---

*Document Version: 1.0 | Last Updated: May 2026 | Classification: Internal Engineering*  
*All WAF behaviors described reflect commonly deployed configurations. Specific implementations (AWS WAF, Cloudflare, ModSecurity) may differ — consult vendor documentation for exact behavior.*

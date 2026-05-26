# DNS Security (DNSSEC, DoH, DoT) — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference
**Audience:** Security Engineers, Network Engineers, Platform Architects, SRE Teams
**Scope:** Complete breakdown of DNS security mechanisms — from raw packet anatomy through cryptographic chain-of-trust, protocol-over-TLS/HTTPS implementations, attack mechanics, and operational failure modes
**System Context:** Production DNS infrastructure supporting a global SaaS platform — authoritative DNS, recursive resolvers, stub resolvers in client devices, and the cryptographic infrastructure connecting them

---

## A Beginner's Orientation: Why DNS Security Is Hard

**What DNS does:** DNS (Domain Name System) is the internet's phone book. When you type `api.example.com`, your computer asks a DNS resolver "what is the IP address for this name?" The resolver traverses a hierarchy of DNS servers to find the answer.

**Why DNS is a security target:**

```
The original DNS protocol (RFC 1034/1035, 1987) was designed with ZERO security:
  - Responses are not authenticated (anyone can forge a DNS response)
  - Transport is UDP (connectionless, easy to spoof)
  - Caching is distributed (poison one cache, affect many users)
  - Queries are in plaintext (ISPs can see every domain you look up)

Three fundamental threats this creates:
  1. Spoofing/Poisoning: Attacker injects false DNS responses
     Result: Users sent to attacker-controlled servers (phishing, MITM)

  2. Surveillance: ISP/attacker sees all DNS queries in plaintext
     Result: User browsing history exposed without HTTPS protecting domains

  3. Manipulation: ISP modifies DNS responses (censorship, ad injection, captive portals)
     Result: Users receive tampered data without knowing it

Three security mechanisms address these:
  DNSSEC:  Cryptographic signatures on DNS records (addresses spoofing/poisoning)
  DoT:     DNS-over-TLS on port 853 (addresses surveillance and manipulation)
  DoH:     DNS-over-HTTPS on port 443 (addresses surveillance, harder to block)
```

---

## Table of Contents

1. [Protocol Lifecycle Narrative](#1-protocol-lifecycle-narrative)
2. [Header & Packet Anatomy](#2-header--packet-anatomy)
3. [Cryptographic & Trust Mechanics](#3-cryptographic--trust-mechanics)
4. [Core Implementation Architecture](#4-core-implementation-architecture)
5. [Bypass & Attack Mechanics](#5-bypass--attack-mechanics)
6. [Security Controls & Defensive Mechanics](#6-security-controls--defensive-mechanics)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Failure Points & Misconfigurations](#8-failure-points--misconfigurations)
9. [Mitigations & Observability](#9-mitigations--observability)
10. [Interview Questions](#10-interview-questions)

---

## 1. Protocol Lifecycle Narrative

### Scenario: Browser resolves `api.example.com` with full DNSSEC + DoH

**T+0ms — Application triggers DNS resolution**

A user navigates to `https://api.example.com/v1/data`. The operating system's network stack detects no cached entry for `api.example.com` and invokes the stub resolver.

**T+0ms to T+2ms — Stub resolver checks local cache**

```
Stub resolver cache lookup:
  Key: "api.example.com" + record type A
  Result: MISS (TTL expired or first lookup)
  
  Stub resolver checks /etc/hosts first (Unix/Linux/macOS):
  No entry found.
  
  Check OS DNS cache (nscd, systemd-resolved, or similar):
  No entry found.
  
  Prepare to query upstream resolver.
```

**T+2ms — Stub resolver selects and contacts recursive resolver**

Modern devices with DoH configured (e.g., Chrome's Secure DNS, Firefox's Trusted Recursive Resolver):

```
Stub resolver configuration:
  Resolver: 1.1.1.1 (Cloudflare) via DoH
  Endpoint: https://cloudflare-dns.com/dns-query

Construct DoH query:
  HTTP method: POST (or GET with base64url-encoded query)
  URL: https://cloudflare-dns.com/dns-query
  Headers:
    Content-Type: application/dns-message
    Accept: application/dns-message
  Body: [raw DNS wire format message, encoded]
```

**T+2ms to T+30ms — TLS handshake to DoH resolver**

If no existing TLS session to `cloudflare-dns.com`:
- Full TLS 1.3 handshake occurs (1 RTT)
- Certificate validated for `cloudflare-dns.com`
- Session established

If TLS session already cached (most common):
- TLS session resumption (0-RTT or 1-RTT)
- DoH query sent immediately

**T+30ms to T+80ms — Recursive resolver iterates the DNS hierarchy**

The recursive resolver at Cloudflare processes the query. It doesn't know the answer, so it iterates:

```
Step 1: Query root nameservers for "." (cached — refreshed every 48h)
  Recursive resolver already knows 13 root nameserver IPs (hardcoded/precached)
  Query to a.root-servers.net:53 (plain UDP/TCP):
    Question: api.example.com. IN A
  Response (referral): 
    No answer, but here are the .com nameservers:
    a.gtld-servers.net → 192.5.6.30
    b.gtld-servers.net → 192.33.14.30
    [and 11 more TLD servers]
    PLUS RRSIG records for DNSSEC validation

Step 2: Query .com TLD nameservers
  Query to a.gtld-servers.net:53:
    Question: api.example.com. IN A
  Response (referral):
    No answer, but here are example.com's nameservers:
    ns1.example.com → 205.251.196.1
    ns2.example.com → 205.251.197.1
    PLUS DS record for example.com (DNSSEC delegation)
    PLUS RRSIG for the DS record

Step 3: Query example.com authoritative nameservers
  Query to ns1.example.com:53:
    Question: api.example.com. IN A
  Response (authoritative answer):
    api.example.com. 300 IN A 198.51.100.1
    api.example.com. 300 IN RRSIG A 13 3 300 [signature data]
    PLUS: DNSKEY records for example.com zone
```

**T+80ms to T+85ms — DNSSEC validation at recursive resolver**

```
Recursive resolver validates the chain of trust:
  1. Validate root zone DNSKEY (trusted via built-in root trust anchor)
  2. Validate .com DS record signature (signed by root)
  3. Validate example.com DNSKEY using DS hash comparison
  4. Validate api.example.com A record RRSIG using example.com DNSKEY
  
  All valid → DNSSEC OK → mark response as "AD" (Authenticated Data)
```

**T+85ms — DoH response returned to stub resolver**

```
Recursive resolver sends DoH response:
  HTTP 200 OK
  Content-Type: application/dns-message
  Body: [DNS wire format response with AD bit set]
  
  DNS response contains:
    api.example.com. 300 IN A 198.51.100.1
    AD bit = 1 (DNSSEC authenticated)
```

**T+85ms to T+90ms — Browser connects to the IP**

Stub resolver returns `198.51.100.1` to the browser. Browser initiates TCP + TLS to that IP. DNS resolution is complete.

---

## 2. Header & Packet Anatomy

### DNS Wire Format — Complete Packet Structure

Every DNS message (query and response) uses the same wire format:

```
DNS MESSAGE FORMAT (RFC 1035):
═══════════════════════════════════════════════════════════

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌─────────────────────────────────────────────────────────────────┐
│                          ID (16 bits)                           │
│  Transaction ID: random number, matches query to response       │
├───────┬─┬─┬─┬─┬─┬──────┬─┬──────────────────────────────────┤
│  QR   │  Opcode  │AA│TC│RD│RA│  Z  │AD│CD│      RCODE        │
│(1bit) │ (4 bits) │  │  │  │  │(1b) │  │  │    (4 bits)       │
├─────────────────────────────────────────────────────────────────┤
│                     QDCOUNT (16 bits)                           │
│                     Number of questions                         │
├─────────────────────────────────────────────────────────────────┤
│                     ANCOUNT (16 bits)                           │
│                     Number of answer records                    │
├─────────────────────────────────────────────────────────────────┤
│                     NSCOUNT (16 bits)                           │
│                     Number of authority records                 │
├─────────────────────────────────────────────────────────────────┤
│                     ARCOUNT (16 bits)                           │
│                     Number of additional records                │
├─────────────────────────────────────────────────────────────────┤
│                    QUESTION SECTION                              │
│  QNAME: domain encoded as length-prefixed labels               │
│  Example: "api.example.com" →                                   │
│    \x03api\x07example\x03com\x00                               │
│    (3)api (7)example (3)com (0=end)                            │
│  QTYPE: 1=A, 28=AAAA, 2=NS, 5=CNAME, 15=MX, 16=TXT, 6=SOA    │
│  QCLASS: 1=IN (Internet)                                        │
├─────────────────────────────────────────────────────────────────┤
│                    ANSWER SECTION                                │
│  Resource Records (RRs):                                        │
│    NAME: domain (may use pointer compression)                   │
│    TYPE: record type (same as QTYPE values)                     │
│    CLASS: 1=IN                                                   │
│    TTL: 32-bit unsigned integer (seconds to cache)              │
│    RDLENGTH: length of RDATA field                              │
│    RDATA: record-specific data                                   │
│           For A record: 4-byte IPv4 address                     │
│           For AAAA: 16-byte IPv6 address                        │
│           For MX: 2-byte preference + domain name              │
└─────────────────────────────────────────────────────────────────┘

KEY FLAGS:
  QR:  0=Query, 1=Response
  AA:  Authoritative Answer (set by authoritative nameserver)
  TC:  TrunCated (message exceeded UDP size limit, use TCP)
  RD:  Recursion Desired (client wants recursive resolution)
  RA:  Recursion Available (server supports recursion)
  AD:  Authenticated Data (DNSSEC validation succeeded)
  CD:  Checking Disabled (client says: don't validate DNSSEC)

  RCODE:
    0 = NOERROR (success)
    1 = FORMERR (malformed query)
    2 = SERVFAIL (server error, also used for DNSSEC failure)
    3 = NXDOMAIN (name does not exist)
    5 = REFUSED
```

### DNSSEC Record Types — Anatomy

**RRSIG (Resource Record Signature):**

```
RRSIG RECORD ANATOMY:
═══════════════════════════════════════════════

NAME:        api.example.com.
TYPE:        RRSIG
CLASS:       IN
TTL:         300

RDATA fields:
┌─────────────────────────────────────────────────────────────┐
│ Type Covered  (16 bits): 1 (covers A records)               │
│ Algorithm     (8 bits):  13 (ECDSA P-256 SHA-256)           │
│                          8 = RSA SHA-256                     │
│                          13 = ECDSA P-256                    │
│                          15 = Ed25519 (modern, recommended)  │
│ Labels        (8 bits):  3 (api.example.com has 3 labels)   │
│ Original TTL  (32 bits): 300                                 │
│ Signature Expiration (32 bits): timestamp                    │
│ Signature Inception  (32 bits): timestamp                    │
│ Key Tag       (16 bits): 12345 (identifies which DNSKEY)     │
│ Signer's Name: example.com. (zone that signed this)         │
│ Signature    (variable): [cryptographic signature bytes]     │
└─────────────────────────────────────────────────────────────┘

WHAT IS SIGNED:
  The signature covers:
    - All RRs of the same name+type (the entire RRset)
    - The RRSIG fields above (algorithm, TTL, expiration, etc.)
    - The owner name
  
  NOT covered: TTL field during transit (can decrease as time passes)
  COVERED: Original TTL (ensures TTL was not artificially inflated)
```

**DNSKEY Record:**

```
DNSKEY RECORD ANATOMY:
═══════════════════════════════════════════════

NAME:        example.com.
TYPE:        DNSKEY
CLASS:       IN
TTL:         3600

RDATA fields:
┌─────────────────────────────────────────────────────────────┐
│ Flags        (16 bits):                                      │
│   Bit 7 (Zone Key): must be set for DNSSEC keys             │
│   Bit 8 (Revocation): set to indicate key is revoked        │
│   Bit 15 (SEP - Secure Entry Point): set for KSK           │
│   Example: 257 = Zone Key + SEP = KSK                       │
│            256 = Zone Key only = ZSK                        │
│                                                              │
│ Protocol     (8 bits):  3 (must always be 3)                │
│ Algorithm    (8 bits):  13 (ECDSA P-256)                    │
│ Public Key   (variable): [raw public key bytes, base64]     │
└─────────────────────────────────────────────────────────────┘

TWO KEY TYPES:
  ZSK (Zone Signing Key, flags=256):
    - Used to sign all other records in the zone
    - Rotated frequently (30-90 days typical)
    - Can be rotated without parent zone involvement
  
  KSK (Key Signing Key, flags=257):
    - Used ONLY to sign the DNSKEY RRset
    - Its hash (DS record) is stored in the parent zone
    - Rotated infrequently (1-2 years typical)
    - Rotation requires coordination with parent zone registrar
```

**DS (Delegation Signer) Record:**

```
DS RECORD ANATOMY (stored in PARENT zone, e.g., .com for example.com):
═══════════════════════════════════════════════════════════════════════

NAME:        example.com.  (stored in .com zone)
TYPE:        DS
CLASS:       IN
TTL:         86400

RDATA fields:
┌─────────────────────────────────────────────────────────────┐
│ Key Tag      (16 bits): 12345 (matches DNSKEY key tag)      │
│ Algorithm    (8 bits):  13 (same as DNSKEY algorithm)       │
│ Digest Type  (8 bits):  2 = SHA-256                         │
│                         4 = SHA-384                         │
│ Digest       (variable): SHA-256(DNSKEY wire format)        │
│   = hash of the zone's KSK public key                       │
└─────────────────────────────────────────────────────────────┘

HOW THE DS LINKS CHILD TO PARENT:
  The .com zone stores a hash of example.com's KSK.
  When a resolver validates example.com records:
    1. Gets example.com's DNSKEY records
    2. Computes SHA-256 of the KSK
    3. Compares to DS record in .com zone
    4. If match: DNSKEY is authenticated
    5. Uses DNSKEY to verify RRSIGs on actual records
```

### DoH Request/Response Format

```
DoH QUERY (POST method):
═══════════════════════════════════════════════

HTTP Request:
  POST /dns-query HTTP/2
  Host: cloudflare-dns.com
  Content-Type: application/dns-message
  Accept: application/dns-message
  Content-Length: 29

  [DNS wire format message, binary]
  
  Wire format bytes (example, query for api.example.com A):
  00 01         - ID: 1
  01 00         - Flags: QR=0 (query), RD=1 (recursion desired)
  00 01         - QDCOUNT: 1 question
  00 00         - ANCOUNT: 0
  00 00         - NSCOUNT: 0
  00 00         - ARCOUNT: 0
  03 61 70 69   - \x03"api"
  07 65 78 61   - \x07"example"
  6d 70 6c 65
  03 63 6f 6d   - \x03"com"
  00            - Root label (end of name)
  00 01         - QTYPE: A (1)
  00 01         - QCLASS: IN (1)

DoH GET Alternative:
  GET /dns-query?dns=AAABAAABAAAAAAAAA3FwaQdleGFtcGxlA2NvbQAAAQAB HTTP/2
  Host: cloudflare-dns.com
  Accept: application/dns-message
  
  (Query is base64url-encoded and passed as 'dns' parameter)

HTTP Response:
  HTTP/2 200 OK
  Content-Type: application/dns-message
  Cache-Control: max-age=300  ← TTL of the DNS record, used by HTTP caching
  Content-Length: [length]

  [DNS wire format response, binary]
```

### DoT Connection Format

```
DoT (DNS-over-TLS) PROTOCOL:
═══════════════════════════════════════════════

Connection: TCP to port 853, then TLS handshake

After TLS established, DNS messages use RFC 1035 TCP framing:
  2-byte length prefix (big-endian) followed by DNS message:
  
  ┌─────────────┬──────────────────────────────────────┐
  │  Length (2B)│        DNS Message (variable)         │
  └─────────────┴──────────────────────────────────────┘
  
  This is identical to DNS-over-TCP (port 53), just wrapped in TLS.
  The length prefix is needed because TCP is a stream protocol
  (no message boundaries), unlike UDP which is packet-based.

  OPPORTUNISTIC vs STRICT mode:
  Opportunistic: Try DoT, fall back to cleartext if connection fails
                 No certificate verification
                 Provides privacy against passive observers
                 Does NOT protect against active MITM

  Strict: Require DoT with validated certificate
          Configure specific resolver hostname to validate
          Certificate MUST match configured hostname
          Provides both privacy AND authentication
          Never falls back to cleartext
```

---

## 3. Cryptographic & Trust Mechanics

### DNSSEC Chain of Trust — Complete Mechanics

```
DNSSEC CHAIN OF TRUST
═══════════════════════════════════════════════════════════════════════

TRUST ANCHOR (hardcoded in every validator)
  Root Zone KSK Public Key:
  Algorithm: ECDSA P-256 or RSA-2048
  This is published by IANA and hardcoded in DNS software
  Validators TRUST this key without any cryptographic proof
  (It's the "root of trust" — must be trusted a priori)
  
  ↓ ROOT KSK signs ROOT ZSK (DNSKEY RRSIG at root)
  ↓ ROOT ZSK signs DS records for .com (RRSIG in root zone)
  ↓
  
  .COM ZONE
  .com KSK: public key stored in .com DNSKEY record
             DS record in root zone = SHA-256(.com KSK) ← LINKS TO ROOT
  .com ZSK: signs all .com zone records
  .com ZSK signs DS record for example.com ← DELEGATION LINK
  
  ↓ .com ZSK signs DS record for example.com
  ↓
  
  EXAMPLE.COM ZONE
  example.com KSK: public key in example.com DNSKEY record
                   DS record in .com zone = SHA-256(example.com KSK)
  example.com ZSK: signs api.example.com A record
  
  ↓ example.com ZSK signs api.example.com RRSIG
  ↓
  
  api.example.com. 300 IN A 198.51.100.1
  api.example.com. 300 IN RRSIG A [signed by example.com ZSK]

ASCII CHAIN OF TRUST:

┌─────────────────────────────────────────────────────────────────────┐
│           ROOT ZONE (trust anchor)                                  │
│  ┌──────────────────┐                                               │
│  │  Root KSK        │ ← Hardcoded trust in validator               │
│  │  (flags=257)     │                                               │
│  └────────┬─────────┘                                               │
│           │ signs (RRSIG over DNSKEY RRset)                        │
│  ┌────────▼─────────┐                                               │
│  │  Root ZSK        │                                               │
│  │  (flags=256)     │                                               │
│  └────────┬─────────┘                                               │
│           │ signs DS record for .com in root zone                  │
└───────────┼─────────────────────────────────────────────────────────┘
            │
┌───────────▼─────────────────────────────────────────────────────────┐
│           .COM TLD ZONE                                             │
│  ┌──────────────────┐                                               │
│  │  DS record for   │ = SHA-256(.com KSK public key)               │
│  │  .com            │ ← validated using Root ZSK signature          │
│  └────────┬─────────┘                                               │
│           │ validates                                               │
│  ┌────────▼─────────┐                                               │
│  │  .com KSK        │                                               │
│  │  (flags=257)     │                                               │
│  └────────┬─────────┘                                               │
│           │ signs                                                   │
│  ┌────────▼─────────┐                                               │
│  │  .com ZSK        │                                               │
│  │  (flags=256)     │                                               │
│  └────────┬─────────┘                                               │
│           │ signs DS record for example.com                        │
└───────────┼─────────────────────────────────────────────────────────┘
            │
┌───────────▼─────────────────────────────────────────────────────────┐
│           EXAMPLE.COM ZONE                                          │
│  ┌──────────────────┐                                               │
│  │  DS record for   │ = SHA-256(example.com KSK)                   │
│  │  example.com     │ ← validated using .com ZSK signature          │
│  └────────┬─────────┘                                               │
│           │ validates                                               │
│  ┌────────▼─────────┐                                               │
│  │  example.com KSK │                                               │
│  │  (flags=257)     │                                               │
│  └────────┬─────────┘                                               │
│           │ signs                                                   │
│  ┌────────▼─────────┐                                               │
│  │  example.com ZSK │                                               │
│  │  (flags=256)     │                                               │
│  └────────┬─────────┘                                               │
│           │ signs                                                   │
│  ┌────────▼─────────────────────────────────────────────────────┐  │
│  │  RRSIG for api.example.com A record                          │  │
│  │  Covers: api.example.com. 300 IN A 198.51.100.1             │  │
│  │  Signature: ECDSA-P256(ZSK_private_key, hash_of_RRset)      │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Signature Generation and Verification — The Math

**Signature generation (at authoritative nameserver/signing system):**

```python
"""
DNSSEC Signature Generation (ECDSA P-256 / Algorithm 13):

Input:
  RRset: all records of same name+type
  ZSK private key: d (256-bit integer)
  ZSK public key: Q = d × G (point on P-256 curve)

Step 1: Construct the "to-be-signed" data
  wire_to_sign = (
    RRSIG_rdata_without_signature  +  # Algorithm, expiry, etc.
    canonical_rr_name               +  # Lowercase owner name
    sorted_canonical_rdata             # All RRs, sorted, wire format
  )

Step 2: Hash the data
  digest = SHA-256(wire_to_sign)

Step 3: ECDSA sign
  k = cryptographically_secure_random()  # CRITICAL: must be unique per signature
  r = (k × G).x mod n                    # x-coordinate of kG
  s = k^(-1) × (digest + r × d) mod n   # Signature component
  signature = encode(r, s)               # 64 bytes for P-256

Output RRSIG: algorithm=13, signature=signature_bytes

CRITICAL SECURITY NOTE:
  If k is reused for two different signatures, the private key d can be computed:
  d = (s1 × k - hash1) / r1 = (s2 × k - hash2) / r2 → solve for k, then d
  This is the Sony PS3 private key leak scenario.
  Modern implementations use deterministic ECDSA (RFC 6979) to derive k deterministically
  from the private key and message, eliminating randomness failures.
"""
```

**Signature verification (at recursive resolver):**

```python
"""
DNSSEC Signature Verification:

Input:
  RRSIG record (from DNS response)
  DNSKEY record (zone's public key)
  RRset being validated

Step 1: Extract parameters from RRSIG
  algorithm = RRSIG.algorithm      # e.g., 13 (ECDSA P-256)
  key_tag = RRSIG.key_tag          # identifies which DNSKEY
  signer = RRSIG.signer_name       # zone that signed
  expiry = RRSIG.sig_expiration
  inception = RRSIG.sig_inception
  signature = RRSIG.signature

Step 2: Validate temporal validity
  current_time = now()
  if current_time > expiry:
    FAIL: Signature expired
  if current_time < inception:
    FAIL: Signature not yet valid

Step 3: Find matching DNSKEY
  For each DNSKEY in zone:
    if compute_key_tag(DNSKEY) == key_tag:
      public_key = DNSKEY.public_key
      break
  if not found:
    FAIL: No matching key

Step 4: Reconstruct signed data (identical to how signer built it)
  wire_to_verify = (
    RRSIG_rdata_without_signature +
    canonical_rr_name +
    sorted_canonical_rdata
  )

Step 5: ECDSA verify
  Q = parse_public_key(public_key)  # Point on P-256 curve
  digest = SHA-256(wire_to_verify)
  r, s = parse_signature(signature)
  
  # Verify: is (r, s) a valid signature over digest with public key Q?
  w = s^(-1) mod n
  u1 = digest × w mod n
  u2 = r × w mod n
  point = u1 × G + u2 × Q
  
  if point.x mod n == r:
    VALID
  else:
    FAIL: Invalid signature

Step 6: Validate DNSKEY itself
  Compute SHA-256(DNSKEY wire format)
  Compare to DS record from parent zone
  If match: DNSKEY is authenticated → signature is authenticated
"""
```

### DNSSEC Key Rotation — The Real Operational Challenge

```
ZSK ROTATION (frequent, every 30-90 days):
  
  Phase 1: Pre-publish new ZSK
    Publish new ZSK in DNSKEY RRset alongside old ZSK
    Wait: at least the maximum TTL of cached DNSKEY records (e.g., 1 hour)
    Why: Resolvers with cached old DNSKEY must see new ZSK before we use it
  
  Phase 2: Switch signing
    Start signing all new records with new ZSK
    Old signatures (signed with old ZSK) are still valid until they expire
    Why: Cached records signed by old ZSK are still valid if old ZSK still published
  
  Phase 3: Remove old ZSK
    Wait: at least the maximum TTL of any signed record (e.g., 1 day)
    Then remove old ZSK from DNSKEY RRset
    Why: All cached records have either expired or been re-signed with new ZSK

KSK ROTATION (infrequent, requires registrar coordination):
  
  Phase 1: Generate new KSK
    Publish new KSK in DNSKEY RRset alongside old KSK
  
  Phase 2: Submit DS to parent zone
    Operator submits new DS record (hash of new KSK) to registrar
    Registrar publishes new DS in parent zone (.com)
    Wait: DS record must propagate globally (TTL typically 24-48 hours)
    CRITICAL POINT: Both old AND new DS must be in parent zone simultaneously
    If only new DS before old KSK expires: validation fails for resolvers
    with old DS cached
  
  Phase 3: Switch signing DNSKEY RRset with new KSK
    Start signing DNSKEY RRset with new KSK
    Old KSK still present (old DS still cached at some resolvers)
  
  Phase 4: Remove old KSK
    Wait: at least one TTL of the DS record (e.g., 24 hours)
    Remove old KSK from DNSKEY RRset
    Contact registrar to remove old DS record
  
  EMERGENCY KSK ROLLOVER (key compromise):
    No waiting periods
    Immediately publish new KSK and DS
    Remove old KSK
    Accept: brief validation failures as resolvers catch up
    Alert: All zone operators, CERT/CC, resolver operators

ROOT KSK ROLLOVER (IANA, affects entire internet):
  The 2018 root KSK rollover:
    Announced: 2017
    Executed: October 11, 2018
    Delay: Multiple postponements (millions of resolvers had old trust anchor)
    Risk: If resolvers didn't update trust anchor, ALL DNSSEC validation fails globally
    Lesson: Trust anchor management is the hardest problem in DNSSEC deployment
```

---

## 4. Core Implementation Architecture

### Recursive Resolver — Internal State Machine

```
BIND/Unbound RECURSIVE RESOLVER ARCHITECTURE:

For each incoming query:
  1. Parse query packet
  2. Cache lookup (positive and negative cache)
  3. If cache hit and TTL valid: return cached response
  4. If cache miss or TTL expired: begin iterative resolution

CACHE TYPES:
  Positive cache: Stores actual answers (A, AAAA, MX records, etc.)
  Negative cache: Stores NXDOMAIN responses (RFC 2308)
    - NXDOMAIN TTL: taken from SOA minimum TTL field (often 300-3600s)
    - Prevents repeated queries for non-existent domains

  DNSSEC cache additions:
    DNSKEY cache: Cached zone public keys (used for validation)
    DS cache: Cached delegation signer records
    Validated response cache: Marks which entries have been DNSSEC-validated
    Bogus cache: Marks responses that FAILED DNSSEC validation
      (prevents re-querying and re-validating repeatedly)

IMPLEMENTATION DETAILS (Unbound):

  Iterator module: Handles iterative resolution
    Maintains query state machine:
      STATE_INIT → STATE_QUERYTARGETS → STATE_QUERY →
      STATE_PRIME → STATE_INIT_2 → STATE_DONE
    
    Primes root hints (gets current root server IPs and DNSKEY)
    Follows referrals (NS records pointing to child zone nameservers)
    Handles CNAME chains (follows aliases to final answer)

  Validator module: Handles DNSSEC validation
    Receives answer from iterator
    Fetches DNSKEY records if not cached
    Validates each RRset signature
    Validates chain of trust up to trust anchor
    Returns: SECURE, INSECURE, BOGUS, INDETERMINATE

  Cache module: Thread-safe LRU cache
    Key: (name, type, class)
    Value: RRset + TTL + validation state
    Thread locking: per-slab (sharded for performance)
```

### DoH Server Implementation

```python
"""
DoH SERVER IMPLEMENTATION (FastAPI/Python example showing the flow):

A DoH server is simply an HTTP/2 server that:
1. Accepts POST requests with Content-Type: application/dns-message
2. Decodes the binary DNS query from the body
3. Passes it to a recursive resolver backend
4. Returns the binary DNS response with appropriate HTTP headers
"""

from fastapi import FastAPI, Request, Response
import dns.message  # dnspython library
import asyncio

app = FastAPI()

@app.post("/dns-query")
async def doh_post(request: Request):
    # Validate content type
    if request.headers.get("content-type") != "application/dns-message":
        return Response(status_code=415)  # Unsupported Media Type
    
    # Read binary DNS query
    query_bytes = await request.body()
    
    # Parse DNS query (validates wire format, rejects malformed)
    try:
        dns_query = dns.message.from_wire(query_bytes)
    except Exception:
        return Response(status_code=400)  # Bad Request
    
    # Forward to recursive resolver backend (plain DNS on 127.0.0.1)
    response_bytes = await forward_to_resolver(dns_query)
    
    # Parse response to extract TTL for HTTP cache headers
    dns_response = dns.message.from_wire(response_bytes)
    min_ttl = get_minimum_ttl(dns_response)
    
    return Response(
        content=response_bytes,
        media_type="application/dns-message",
        headers={
            "Cache-Control": f"max-age={min_ttl}",
            # Allows HTTP caches to cache DNS responses
            # Client-side: browser can cache DoH response like any HTTP response
        }
    )

@app.get("/dns-query")
async def doh_get(request: Request):
    # GET method: query in base64url-encoded 'dns' parameter
    dns_param = request.query_params.get("dns")
    if not dns_param:
        return Response(status_code=400)
    
    # Decode base64url (no padding) to binary DNS message
    import base64
    query_bytes = base64.urlsafe_b64decode(dns_param + "==")  # Add padding
    
    # Same processing as POST
    # ... (same code as above)
```

### Negative Trust Anchors (NTA) — Operational Safety Valve

```
PROBLEM: A zone breaks DNSSEC (misconfiguration, key rotation failure).
  All resolvers enforcing DNSSEC return SERVFAIL for ALL queries in that zone.
  The zone's DNS is effectively unreachable despite having correct records.
  
  Example: company.example.com forgets to update their DS record.
  Resolvers: "DS in .com says key fingerprint X, but DNSKEY in company.example.com
              is fingerprint Y → BOGUS → return SERVFAIL"
  
  Users cannot reach company.example.com until the zone is fixed.
  Time to fix: could be hours or days (requires registrar coordination).

SOLUTION: Negative Trust Anchor (RFC 7646)
  A resolver operator can configure: "Do NOT validate DNSSEC for company.example.com"
  The zone is treated as unsigned (INSECURE) rather than BOGUS.
  Users can resolve the zone (with no DNSSEC protection) while the zone is fixed.
  
  Configuration (Unbound):
    negative-trust-anchor: company.example.com
  
  SECURITY IMPLICATION:
    NTA disables DNSSEC protection for the named zone.
    Cache poisoning attacks become possible again for that zone.
    NTAs should be time-limited and require justification.
    This is an explicit security downgrade with documented justification.
```

---

## 5. Bypass & Attack Mechanics

### Attack 1: DNS Cache Poisoning — Kaminsky Attack

**Background and why original DNS was vulnerable:**

```
ORIGINAL DNS (pre-Kaminsky, pre-2008):
  Transaction ID: 16-bit random number (65,536 possibilities)
  Source port: Fixed or low-entropy (often fixed port 53)
  
  To poison a cache entry:
    1. Send a query to the resolver: "What is evil.example.com?"
    2. Race: Send forged responses with all 65,536 possible IDs
    3. If one forged response arrives before the legitimate response:
       Resolver caches the forged answer
       
  Success probability per attempt: 1/65536 ≈ 0.0015%
  With fast flooding: 1,000 guesses/second → poisoned in ~65 seconds
  Not practical but theoretically possible.
```

**The Kaminsky Attack (2008) — Why it was devastating:**

```
DAN KAMINSKY'S INSIGHT (2008):

Instead of querying for a record and racing to inject a forged response,
attack the NS delegation records:

Attack:
  Query: "What is {random}.example.com?" (e.g., "a.example.com", "b.example.com")
  Since {random}.example.com doesn't exist: resolver queries example.com's nameservers
  This happens every single time with a NEW random subdomain
  → Attacker gets UNLIMITED ATTEMPTS to inject a forged response
  
  Forged response contains:
    Answer section: {random}.example.com IN A 198.51.100.1  (attacker's IP)
    Authority section: example.com IN NS ns1.attacker.com  ← POISON THIS
    Additional section: ns1.attacker.com IN A [attacker's IP]
  
  If the forged NS record is accepted:
  ALL future queries for *.example.com → attacker's nameserver
  Resolver caches attacker-controlled NS for example.com

ATTACK MATHEMATICS:
  Guessing the transaction ID: 1/65536 per attempt
  Source port randomization (PRNG): adds ~16 bits → 1/(65536 × 65536) per attempt
  But: one attempt per millisecond → 65,536 attempts in 65 seconds
  With unlimited subdomain queries: attacker tries indefinitely until they win
  
  BIRTHDAY PARADOX application:
  Attack sends N forged responses per real query
  Probability of at least one match: 1 - (1 - 1/65536)^N
  At N=1000 guesses/response: probability = 1.5% per query attempt
  With 1000 query attempts: probability of eventual success ≈ 99.99%

CRITICAL MITIGATION: DNSSEC
  If the resolver validates DNSSEC, a forged NS record without a valid RRSIG fails.
  The RRSIG requires the zone's private key to produce → attacker cannot forge it.
  DNSSEC completely defeats Kaminsky-style attacks.
  
  But: DNSSEC adoption (especially signing of zones) remains low (~20-30% of domains).
```

**Step-by-step modern cache poisoning attempt:**

```
STEP 1: Attacker identifies target resolver (e.g., a corporate internal DNS server)

STEP 2: Attacker triggers recursive query
  Option A: Direct: Attacker controls a machine that uses target resolver
  Option B: Indirect: Trick a website served by the target into loading a resource
             that triggers DNS lookup via target resolver (DNS rebinding setup)

STEP 3: Query for random subdomains
  attacker → resolver: "What is [uuid].vulnerable-zone.example.com?"
  resolver → authoritative NS: "What is [uuid].vulnerable-zone.example.com?"
  
  [uuid] is different each time → fresh query → fresh transaction ID to guess

STEP 4: Flood forged responses
  attacker → resolver (spoofed source: authoritative NS IP): 
  DNS Response:
    ID: [try all 65,536 values in rapid succession]
    QR=1 (response)
    AA=1 (authoritative)
    Answer: [uuid].vulnerable-zone.example.com IN A [attacker IP]
    Authority: vulnerable-zone.example.com IN NS ns1.attacker.com
    Additional: ns1.attacker.com IN A [attacker controlled IP]

STEP 5: If one guessed ID matches:
  Resolver caches: vulnerable-zone.example.com NS → ns1.attacker.com
  All future queries for *.vulnerable-zone.example.com → attacker's nameserver
  
STEP 6: Attacker's nameserver responds with attacker-controlled IPs
  Users accessing vulnerable-zone.example.com get sent to attacker's servers

WHY DEFAULT CONFIG FAILS:
  - No DNSSEC on vulnerable-zone.example.com (no signature to validate)
  - Resolver accepts the NS delegation from the additional/authority section
    without verifying the source (legitimate behavior per RFC 1035)
  - Transaction IDs are predictable if PRNG is weak (CVE exists for multiple implementations)
```

### Attack 2: DNS Rebinding Attack

```
DNS REBINDING — BYPASSING SAME-ORIGIN POLICY:

PROBLEM: Same-Origin Policy (SOP) prevents malicious websites from accessing
         resources on other origins. But DNS rebinding exploits TTL.

SETUP:
  Attacker controls:
    - evil.attacker.com (their website)
    - The authoritative DNS for attacker.com
  
  evil.attacker.com initial DNS response:
    evil.attacker.com. 1 IN A 1.2.3.4  ← Short TTL of 1 second!

ATTACK SEQUENCE:
  Step 1: Victim visits evil.attacker.com (in their browser)
    Browser: resolves evil.attacker.com → 1.2.3.4 (attacker's server)
    Browser: loads attacker's JavaScript from 1.2.3.4
    SOP: JavaScript can make requests to evil.attacker.com (same origin)

  Step 2: JavaScript waits 1+ seconds for TTL to expire

  Step 3: DNS rebind — attacker changes DNS response
    evil.attacker.com. 1 IN A 192.168.1.1  ← Now resolves to victim's router!
    (Or 169.254.x.x for cloud metadata, or any internal IP)

  Step 4: JavaScript makes fetch() to evil.attacker.com
    Browser: "evil.attacker.com is in my origin, so SOP allows this"
    Browser: resolves evil.attacker.com again (TTL expired) → 192.168.1.1
    Browser: sends HTTP request to 192.168.1.1 (victim's router)
    HTTP response: router admin interface HTML
    JavaScript: reads the response (same origin!) → sends to attacker server

WHAT ATTACKER CAN DO:
  - Access internal services (router admin, internal APIs, dev servers)
  - Cloud metadata (169.254.169.254 AWS, 169.254.169.254 GCP)
    → Steal IAM credentials if metadata service is accessible
  - Internal Kubernetes API server, etcd
  - Anything accessible from the victim's machine via HTTP

DEFENSES:
  - DNS Rebinding Protection in resolvers:
      Block responses that resolve public domains to private IPs (RFC1918)
      Resolver detects: "evil.attacker.com resolved to 192.168.1.1 → suspicious → block"
      Limitation: Only works if resolver is the victim's resolver (not DoH to Cloudflare)
  
  - HTTP Host header validation at internal services:
      Internal router: only accept requests with Host: 192.168.1.1 or Host: router.local
      Reject: Host: evil.attacker.com (won't match) → attack fails
      Many IoT devices and internal services don't validate Host headers → vulnerable
  
  - Browser-level protection: Chrome has rebinding protection since 2022
      Blocks responses from public IPs to private IPs (CORS-like)
```

### Attack 3: DoH as a Covert Channel

```
CONCERN: DoH can be used for data exfiltration via DNS

MECHANISM:
  Traditional DNS tunneling (e.g., iodine, dnscat2):
    Encodes data in DNS query names:
    base32(payload).c2.attacker.com → TXT response contains encoded data
    Detection: Unusual query patterns, high NXDOMAINs, long subdomains
    Blocking: Block UDP/53 and TCP/53 outbound (common in enterprise)

  DoH tunneling:
    All DNS queries go to 1.1.1.1:443 or 8.8.8.8:443 via HTTPS
    From network perspective: looks like normal HTTPS to Google/Cloudflare
    Enterprise firewalls: cannot inspect (TLS) or block (blocks all HTTPS)
    Detection: MUCH harder (blends with legitimate DoH traffic)
    
  Practical tunneling via DoH:
    Malware sends DNS queries for encoded.data.c2.attacker.com via DoH
    Attacker's authoritative DNS server receives query, decodes payload
    Response TXT record contains encoded command
    Malware decodes command from response
    
  ALL DNS TUNNELING has these limitations:
    Low bandwidth (~1-5 kbps for DNS tunnel, higher overhead than HTTPS)
    High latency (multiple DNS round-trips per payload)
    Rate limiting by DoH providers (Cloudflare, Google rate-limit unusual patterns)
    Attacker must control authoritative DNS for their domain

ENTERPRISE DEFENSE:
  Option A: Proxy all DoH via corporate DNS that can inspect queries
    Force all DoH traffic through corporate proxy
    Inspect DNS query names for tunneling patterns (long subdomains, high entropy)
    Block non-corporate approved resolvers

  Option B: DNS RPZ (Response Policy Zones)
    Block queries to known C2 domains regardless of transport protocol
    Requires threat intelligence integration

  Option C: TLS inspection (controversial, privacy implications)
    Decrypt DoH traffic at the proxy
    Inspect DNS query names
    Re-encrypt to endpoint
    Requires deploying corporate CA cert to endpoints
```

### Attack 4: DNSSEC Amplification (DNSSECKill)

```
DNSSEC CREATES LARGER RESPONSES → USEFUL FOR AMPLIFICATION ATTACKS

Normal DNS A record response: 60-100 bytes
DNSSEC-signed response: 400-4000 bytes (RRSIG + DNSKEY + DS records)
Amplification factor: 40-400x

ATTACK:
  Attacker sends: Small DNS query (60 bytes) with spoofed source = victim's IP
                  Query type: DNSKEY (returns multiple large records)
  DNS resolver sends: Large DNSSEC response (2000 bytes) to victim
  Amplification: 33x
  
  At 10 Gbps of spoofed queries: victim receives 330 Gbps of DNSSEC responses

DEFENSE AGAINST DNSSEC AMPLIFICATION:
  DNS Response Rate Limiting (RRL):
    Rate limit responses to any single IP
    Standard: limit to 100 responses/second per IP
    Configured on authoritative and recursive nameservers
  
  Response Truncation:
    If DNSSEC response would be large: set TC=1 (truncated)
    Client must retry over TCP (TCP requires 3-way handshake → no spoofing)
  
  BCP38 (network ingress filtering):
    Blocks spoofed source IPs at network edge
    Prevents amplification by preventing IP spoofing
```

---

## 6. Security Controls & Defensive Mechanics

### DNSSEC Deployment — Strict Enforcement

```
DNSSEC VALIDATION MODES:

Strict (recommended):
  Process: Validate all responses
  On failure (BOGUS): Return SERVFAIL to client
  Configuration (Unbound):
    dnssec-mode: yes  # Enable validation
    trust-anchor: ". 20326 IN DS 19036 8 2 [hash]"  # Root trust anchor
  
  Effect:
    Correctly signed zones: Transparent to users
    Incorrectly signed zones: SERVFAIL (zone is broken, fix it or use NTA)
    Unsigned zones (INSECURE): Passed through without validation
    Maliciously modified responses: SERVFAIL (attacker's forgery rejected)

Permissive (not recommended for security):
  Process: Validate but don't fail on BOGUS
  Log validation failures but pass responses through
  Use for: Monitoring and debugging before strict deployment
  Risk: Provides no actual security benefit (forged responses passed through)

Common deployment mistake:
  Setting CD=1 (Checking Disabled) bit in queries
  This tells the resolver: "I'll do my own validation, please skip yours"
  If the client doesn't actually validate: DNSSEC provides no protection
  
  Correct behavior: Only set CD=1 if you are the DNSSEC validator
  (Most stub resolvers are NOT validators — they rely on the recursive resolver)

FULL VALIDATION STACK CONFIGURATION (ISP/Enterprise resolver):
  # Unbound configuration for strict DNSSEC validation
  server:
    module-config: "validator iterator"  # Load validator module
    
    # Root trust anchor (must be kept current)
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    # auto-trust-anchor-file uses RFC 5011 automatic trust anchor management
    # Automatically updates trust anchor when IANA announces KSK rollover
    
    # What to do with BOGUS responses
    val-bogus-ttl: 60  # Cache bogus status for 60 seconds (prevent DoS)
    
    # Deny DNSSEC-signed NXDOMAIN for existing names (prevents amplification)
    val-clean-additional: yes
```

### DoT/DoH — Strict Mode Configuration

```
STUB RESOLVER (CLIENT) CONFIGURATION:

Linux/systemd-resolved (strict DoT):
  # /etc/systemd/resolved.conf
  [Resolve]
  DNS=1.1.1.1#cloudflare-dns.com  # IP and hostname (for cert validation)
  DNSOverTLS=yes                   # Opportunistic (yes) or enforce
  # Use DNSOverTLS=opportunistic for fallback to cleartext
  # Use DNSOverTLS=yes for strict (never fall back)
  DNSSEC=yes                       # Also validate DNSSEC
  
  # The hostname after # is used for TLS certificate validation:
  # TLS to 1.1.1.1 must present cert for cloudflare-dns.com
  # Without hostname: opportunistic mode only (no cert validation)

Firefox DoH configuration:
  about:config:
    network.trr.mode = 2   # DoH with fallback to system DNS
    network.trr.mode = 3   # DoH ONLY, no fallback (strict)
    network.trr.mode = 5   # DoH disabled
    network.trr.uri = "https://cloudflare-dns.com/dns-query"
    
  Mode 3 (strict):
    If DoH fails for any reason: DNS resolution fails entirely
    Benefit: No cleartext DNS leakage
    Risk: If DoH resolver is unreachable, all DNS fails

macOS configuration (DoH/DoT):
  Uses Configuration Profiles (MDM) or manual settings in Network preferences
  Enterprise: Deploy via MDM profile with forced DoH to corporate resolver

Android Private DNS (DoT):
  Settings → Network → Private DNS → Private DNS provider hostname
  Enter: dns.cloudflare.com (or corporate DoT resolver)
  Mode: Always on (strict) — never falls back to cleartext
```

### Response Policy Zones (RPZ) — Blocklisting at DNS Level

```
RPZ (RESPONSE POLICY ZONES) — DNS FIREWALL:

What it does:
  Overrides DNS responses based on policy rules
  "When anyone queries for malware.example.com, return NXDOMAIN instead"
  Applied at the recursive resolver level

RPZ policy types:
  NXDOMAIN: Return "name doesn't exist" for blocked domain
  DROP: No response at all (connection times out)
  NODATA: Return NOERROR but empty answer (no A/AAAA records)
  Local Data: Return a specific IP (redirect to block page)
  PASSTHRU: Allow through (override broader blocks)

Use cases:
  - Block malware C2 domains
  - Block phishing domains
  - Block ad tracking (pihole-style)
  - Enforce safe search (redirect google.com to forcesafesearch.google.com)

Configuration (BIND):
  # Load RPZ zone from threat intelligence feed
  response-policy {
    zone "rpz.threatintel.example.com" policy NXDOMAIN;
  };

  # In the rpz zone file:
  malware.badsite.com.  CNAME  .  ; NXDOMAIN
  *.badsite.com.        CNAME  .  ; NXDOMAIN for all subdomains

  # Redirect to block page:
  phishing.example.com. CNAME rpz-passthru. ; Passes through (whitelist)
  
LIMITATIONS:
  RPZ only works for DNS-based filtering:
    If attacker hardcodes IP addresses: bypasses DNS entirely
    If attacker uses DoH to external resolver: bypasses corporate DNS
    
  DNSSEC conflict:
    RPZ modifies DNS responses → breaks DNSSEC validation
    RPZ must be applied carefully alongside DNSSEC
    Typically: RPZ overrides happen BEFORE DNSSEC validation
    Or: RPZ configured to only apply to unsigned (insecure) zones
```

---

## 7. Attack Surface Mapping

### Complete Attack Surface

```
DNS SECURITY ATTACK SURFACE
══════════════════════════════════════════════════════════════════════════

EXTERNAL ATTACK SURFACE (Internet-accessible):
═══════════════════════════════════════════════
[E1] Authoritative DNS servers (port 53 UDP/TCP, public)
  Threats:
    Zone transfer exploitation (AXFR — leaks all DNS records)
    Amplification attack source (your DNS used to attack others)
    Direct DDoS to take DNS offline
    DNS cache poisoning via forged referrals (if no DNSSEC)

[E2] Domain registrar account
  Threats:
    Account takeover → change NS records → redirect all traffic
    Unauthorized DS record modification → break DNSSEC
    Domain hijacking → complete loss of domain control
  This is the highest-value target — compromise here bypasses all other controls

[E3] DNS-over-HTTPS endpoint (port 443)
  Threats:
    DDoS to disable DoH resolver
    TLS certificate theft → MITM DoH traffic
    Covert channel exploitation (tunneling)

[E4] DNS-over-TLS endpoint (port 853)
  Threats:
    Port 853 often blocked by enterprise firewalls
    If blocked: client falls back to cleartext (if not strict mode)
    Certificate mismatch → connection failure (strict mode) or fallback (opportunistic)

INTERNAL ATTACK SURFACE (within infrastructure):
═══════════════════════════════════════════════
[I1] Recursive resolver
  Threats:
    Cache poisoning (inject false records)
    DNS amplification (using resolver as reflector)
    Configuration exploitation (zone transfer, NOTIFY flood)

[I2] DNSSEC signing infrastructure (HSM/signing server)
  Threats:
    Private key exfiltration → forge any DNS record in the zone
    Signing server compromise → inject malicious records at signing time
    HSM PIN disclosure → unlock hardware key storage

[I3] Zone file management systems
  Threats:
    Unauthorized zone file modification
    Injection of malicious records before signing
    Supply chain: DNS management software vulnerability

[I4] DNS client (stub resolver on endpoint)
  Threats:
    Malware modifying /etc/resolv.conf → redirect to attacker DNS
    DHCP spoofing → push attacker DNS server to clients
    Hosts file modification → bypass DNS entirely

NETWORK ATTACK SURFACE:
═══════════════════════
[N1] UDP/53 DNS queries (cleartext)
  Threats:
    Passive surveillance (ISP, network observer)
    Active MITM (forge responses)
    Replay attacks (reuse captured responses)

[N2] TCP/53 DNS queries (cleartext)
  Threats:
    Same as UDP, plus TCP session hijacking
    RST injection to terminate legitimate queries

[N3] BGP routing (affects DNS server reachability)
  Threats:
    BGP hijacking of DNS server prefixes
    Route injection to redirect DNS traffic
```

### Trust Boundaries Diagram

```
DNS SECURITY TRUST BOUNDARIES
═══════════════════════════════════════════════════════════════════════════

INTERNET (Zero Trust — anyone can send anything)
      |
      | UDP/53 or TCP/53 (cleartext)
      | No authentication, no encryption
      v
┌─────────────────────────────────────────────────────────────────────┐
│  RECURSIVE RESOLVER [TB-1]                                         │
│  Trust boundary: Validates DNSSEC signatures against trust anchor  │
│  Attack surface: Cache poisoning if DNSSEC absent                  │
│  Protections: DNSSEC validation, DNS cookies, source port rand.    │
│                                                                     │
│  TRUSTS: Root trust anchor (hardcoded)                             │
│  DOES NOT TRUST: Any individual response (validates signatures)    │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                    ┌─────────▼──────────┐       ┌─────────────────────┐
                    │ DNSSEC VALIDATION  │       │ CACHE POISONING     │
                    │ [Trust Boundary]   │       │ If DNSSEC absent    │
                    │ Chain verified vs  │       │ or validation       │
                    │ root trust anchor  │       │ disabled: attacker  │
                    └─────────┬──────────┘       │ can inject records  │
                              │                  └─────────────────────┘
                              │ TLS (DoH/DoT) or cleartext
                              v
┌─────────────────────────────────────────────────────────────────────┐
│  STUB RESOLVER ON CLIENT [TB-2]                                    │
│  Trust boundary: Trusts recursive resolver's responses             │
│  If DoH (strict): validates TLS cert of resolver                   │
│  If cleartext: trusts any response (completely vulnerable)         │
│                                                                     │
│  TRUSTS: Recursive resolver (if DoH/DoT with cert validation)      │
│  DOES NOT TRUST: Without DoH/DoT: trusts any response!            │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              v
┌─────────────────────────────────────────────────────────────────────┐
│  APPLICATION (Browser, OS) [TB-3]                                  │
│  Uses resolved IP to connect via TLS                               │
│  TLS certificate validates server identity                          │
│  (Last line of defense if DNS was poisoned — cert won't match)    │
│  HSTS: Forces HTTPS even if DNS returns different IP               │
└─────────────────────────────────────────────────────────────────────┘

AUTHORITATIVE DNS HIERARCHY:
┌────────────────────────────────────────────────────────────────────┐
│  ROOT ZONE [Highest trust — must be CORRECTLY configured]         │
│  Trust: Established by IANA/ICANN, hardcoded in software          │
│  Attack: If root is compromised, ENTIRE DNS is compromised         │
└────────────────────┬───────────────────────────────────────────────┘
                     │ DS record (signed by root)
┌────────────────────▼───────────────────────────────────────────────┐
│  TLD ZONES (.com, .net, .org)                                     │
│  Trust: DS record validates their KSK                             │
│  Managed by: Verisign (.com/.net), PIR (.org), etc.               │
└────────────────────┬───────────────────────────────────────────────┘
                     │ DS record (signed by TLD)
┌────────────────────▼───────────────────────────────────────────────┐
│  DOMAIN ZONES (example.com, yourdomain.org)                       │
│  Trust: DS record validates their KSK                             │
│  Managed by: Zone operator (you or your DNS provider)             │
│  MOST VULNERABLE: Operator errors, misconfiguration, poor security │
└────────────────────────────────────────────────────────────────────┘
```

---

## 8. Failure Points & Misconfigurations

### DNSSEC Failures — Operational Disasters

```
FAILURE 1: RRSIG EXPIRATION

  Scenario: Zone is DNSSEC-signed. Automated signer fails for 3 days.
  RRSIG records have TTL=86400 (24h) and signature validity of 7 days.
  After 7 days: RRSIGs expire.
  
  What happens to resolvers:
    Resolver checks: Is this RRSIG still valid? Expiration timestamp: PASSED
    Result: BOGUS → SERVFAIL
    All queries for this zone: SERVFAIL
    
  User experience:
    "DNS_PROBE_FINISHED_NXDOMAIN" or similar browser error
    Service completely unreachable for DNSSEC-validating resolvers
    Non-validating resolvers: still work (no DNSSEC validation, no failure)
    
  Detection:
    Monitor: RRSIG expiration timestamps (alert when < 48h from expiry)
    Tool: check_dnssec.py, Nagios DNSSEC plugin, Zabbix DNSSEC monitoring
    
  Recovery:
    Re-sign zone immediately (fix signing infrastructure)
    New RRSIGs propagate based on record TTLs (minutes to hours)
    Old SERVFAIL responses cached for: bogus-ttl in resolver config (often 60s)

FAILURE 2: KSK/DS MISMATCH

  Scenario: Zone operator rotates KSK, publishes new DNSKEY, but forgets
            to update DS record in parent zone (.com).
  
  What happens:
    Resolver: fetches example.com DNSKEY → gets new KSK
    Resolver: fetches DS record from .com zone → still has old KSK hash
    Resolver: computes SHA-256(new KSK) ≠ old DS hash → BOGUS
    Result: SERVFAIL for all example.com queries
    
  Recovery:
    Submit new DS to registrar (can take hours to process)
    Registrar publishes DS in .com zone
    .com zone propagation: up to 48 hours
    Full recovery: could take 2-48 hours depending on registrar speed
    
  Prevention:
    ALWAYS publish new DS before removing old KSK
    Wait for DS to propagate (query public resolvers to confirm)
    Keep both old and new DNSKEY/DS in zone during transition

FAILURE 3: NEGATIVE TRUST ANCHOR MISUSE

  Scenario: Admin adds NTA for "example.com" to work around a DNSSEC issue.
  Forgets to remove it. DNSSEC issue is fixed months later.
  
  What happens:
    DNSSEC validation disabled for example.com for months
    Zone is actually DNSSEC-signed and valid
    But resolver treats it as unsigned (INSECURE)
    Cache poisoning attacks possible for this zone
    
  Detection:
    Audit NTAs regularly: "unbound-control list_stubs; unbound-control list_negtus"
    Alert if NTA is active for > 24 hours
    Document: Every NTA must have associated ticket with expiry date

FAILURE 4: DoT/DoH FAILURE AND FALLBACK BEHAVIOR

  Scenario: Corporate DoT resolver is unreachable.
  Client configured: DoT strict mode (no fallback).
  
  What happens (strict mode):
    All DNS resolution fails
    No fallback to cleartext
    Browser errors on all domain accesses
    
  What happens (opportunistic mode):
    Client falls back to cleartext DNS
    ISP can now see/modify all DNS queries
    If fallback was attacker-triggered: MITM enabled
    
  Correct deployment:
    Strict mode: Only for high-security environments where cleartext is unacceptable
    Opportunistic: Better availability but weaker security (still prevents passive surveillance)
    Enterprise: Deploy internal DoT resolver as primary, with monitoring and automatic failover
```

### DNS Propagation Delays — The Operational Reality

```
TTL MECHANICS AND PROPAGATION:

When you change an A record from 198.51.100.1 to 203.0.113.1:
  1. You update the authoritative nameserver
  2. Cached copies throughout the internet: still serve OLD IP
  3. Old IP is served until TTL expires on each cached copy
  
  If TTL was 3600 (1 hour): complete propagation takes up to 1 hour
  If TTL was 86400 (1 day): propagation takes up to 1 day
  
  "DNS propagation" is a misnomer:
  DNS doesn't "propagate" — caches simply expire at their own pace
  
DNSSEC AND TTL INTERACTIONS:

  RRSIG TTL and signature validity are separate:
    RRSIG record TTL: How long the resolver caches the RRSIG record
    Signature validity: When the cryptographic signature expires (in the RRSIG RDATA)
    
  Resolver behavior:
    Caches RRSIG based on TTL (same as any other record)
    If TTL expires but signature is still valid: re-fetches and re-validates
    If signature expiry passes: BOGUS (even if cached RRSIG hasn't expired by TTL)
    
  TRAP: Setting very long TTLs on RRSIG:
    Long TTL = resolvers cache for a long time = signing infrastructure can be offline longer
    But: If you revoke a ZSK (compromise), cached RRSIGs with old ZSK still validated
    Even though you've revoked the ZSK from the DNSKEY RRset

NEGATIVE CACHING (NXDOMAIN caching):
  If a domain doesn't exist: resolvers cache NXDOMAIN for up to SOA minimum TTL
  This is used by attackers:
    Pre-poison the cache with NXDOMAIN for a domain before it's created
    When the domain is legitimately created: resolver still returns NXDOMAIN
    Legitimate traffic unable to resolve the new domain for TTL duration
    
  Mitigation: Low SOA minimum TTL (300-600 seconds) for domains under active deployment
```

### Strict Mode Breaking Legitimate Traffic

```
DNSSEC STRICT MODE FALSE POSITIVES:

Scenario: Email provider uses a DNSSEC-signed zone with common misconfigurations.
  Your recursive resolver: strict DNSSEC validation enabled.
  
  Result: SERVFAIL for legitimate email domains → emails bounce → business impact.

Real-world DNSSEC failures that caused outages:
  - Microsoft Azure (2021): DNSSEC misconfiguration caused azure.com SERVFAIL
  - Various .gov domains: Regular RRSIG expiration incidents
  - Akamai Edge (2021): DNSSEC outage affected multiple large websites
  
  The operational risk of DNSSEC enforcement is real:
  Domains with DNSSEC problems become completely unreachable.
  For email: SERVFAIL on MX lookup → email delivery failure (bounce, not delay)

HOW TO IDENTIFY IF DNSSEC IS BREAKING LEGITIMATE TRAFFIC:
  Check: dig +dnssec domain.com @your_resolver
    If SERVFAIL: check dig +dnssec domain.com @8.8.8.8 (uses different resolver)
    If 8.8.8.8 also SERVFAIL: domain's DNSSEC is broken
    If 8.8.8.8 returns answer: your resolver's validation differs → investigate
    
  Check: dig +cd domain.com @your_resolver (CD=Checking Disabled)
    If +cd works but without +cd fails: DNSSEC validation is the issue
    Confirms: domain's DNSSEC configuration is broken, not a server issue

OPERATIONAL DECISION: When to add NTA vs when to refuse access
  NTA for high-importance domains (business-critical partner): acceptable
  NTA for unknown/untrusted domains: unacceptable (defeats security purpose)
  NTA should always have: time limit, documented justification, ticket reference
```

---

## 9. Mitigations & Observability

### Concrete Deployment Strategies

```bash
# DNSSEC Zone Signing (BIND9 example):

# Generate ZSK (Zone Signing Key)
dnssec-keygen -a ECDSAP256SHA256 -b 256 -n ZONE example.com

# Generate KSK (Key Signing Key)  
dnssec-keygen -a ECDSAP256SHA256 -b 256 -n ZONE -f KSK example.com

# Sign the zone
dnssec-signzone -A -3 $(head -c 1000 /dev/random | sha1sum | cut -b 1-16) \
    -N INCREMENT -o example.com -t example.com.zone

# Enable automatic signing in BIND9 (recommended over manual):
zone "example.com" {
    type master;
    key-directory "/etc/bind/keys";
    auto-dnssec maintain;  # Automatically sign and resign
    inline-signing yes;    # Sign inline, serve signed zone
    file "/etc/bind/zones/example.com";
};

# Monitor RRSIG expiration:
#!/bin/bash
DOMAIN=$1
EXPIRY=$(dig +dnssec @8.8.8.8 $DOMAIN A | grep RRSIG | awk '{print $9}')
# Parse expiry timestamp and alert if < 48 hours remaining
```

```
# Unbound recursive resolver configuration for maximum security:
server:
    # DNSSEC validation
    module-config: "validator iterator"
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    
    # DoT upstream (Unbound queries upstreams via DoT)
    # Note: This is resolver-to-authoritative, not client-to-resolver
    # Authoritative servers generally don't support DoT
    
    # DNS-over-TLS for stub-to-resolver queries (Unbound serves DoT)
    interface: 0.0.0.0@853        # Listen on port 853
    tls-service-key: "/etc/unbound/unbound_server.key"
    tls-service-pem: "/etc/unbound/unbound_server.pem"
    
    # Access control (only local clients can use this resolver)
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    
    # Rate limiting (prevent amplification)
    ratelimit: 1000  # Limit answers to 1000/second per IP
    
    # Harden against various attacks
    harden-glue: yes           # Only allow glue from delegation
    harden-dnssec-stripped: yes # Fail if signed zone loses signatures
    harden-below-nxdomain: yes  # NXDOMAIN for subdomains of NXDOMAIN
    harden-referral-path: yes   # Validate referral paths
    use-caps-for-id: yes        # DNS 0x20 bit randomization (anti-poisoning)
    hide-identity: yes          # Don't reveal server version
    hide-version: yes
    
    # QNAME minimization (privacy — don't send full name to each NS)
    qname-minimisation: yes
```

### Key Metrics to Monitor

```
METRICS AND LOGGING CHECKLIST:

DNSSEC HEALTH METRICS:
  dnssec_validation_success_rate     → Target: > 99%
  dnssec_bogus_response_count        → Any bogus = misconfiguration or attack
  dnssec_rrsig_remaining_days        → Alert: < 7 days, Critical: < 2 days
  dnssec_key_tag_active              → Track which ZSK/KSK is currently active
  dnssec_nta_active_count            → Alert: any NTA active > 24 hours

DNS QUERY METRICS:
  dns_query_rate_by_type             → Spike in DNSKEY/ANY = amplification attack
  dns_nxdomain_rate                  → High NXDOMAIN = DNS tunneling or attack
  dns_servfail_rate                  → DNSSEC failures, resolver issues
  dns_response_time_p99              → High latency = resolver under load
  dns_cache_hit_rate                 → Low hit rate = cache thrashing or flood

DoH/DoT METRICS:
  doh_connection_count               → Track DoH adoption
  doh_error_rate                     → TLS failures, HTTP errors
  dot_tls_handshake_duration         → Latency added by TLS
  dot_certificate_expiry_days        → Alert: < 30 days to cert expiry

SECURITY METRICS:
  dns_amplification_blocked          → Responses dropped due to rate limiting
  rpz_block_count_by_policy         → Domains blocked by DNS firewall
  zone_transfer_attempts             → Unauthorized AXFR attempts
  unusual_query_pattern_score        → ML/heuristic anomaly detection

LOG FORMATS:

# Unbound query log format:
# [timestamp] unbound[pid]: info: [thread] [query]: [response]
1700000001.123 unbound[1234]: info: 10.0.0.5 api.example.com. A IN NOERROR
  0.001254 secure 198.51.100.1 ttl=300

# Fields: client_ip, qname, qtype, qclass, rcode, latency, sec_status, answer, ttl

# DNSSEC validation log (on failure):
1700000002.456 unbound[1234]: error: validator: response has an invalid signature:
  malware.example.com. A IN RRSIG [key_tag=12345] signature failed

# Parse these logs for:
# sec_status="bogus" → DNSSEC validation failures
# rcode=SERVFAIL → resolution failures (include reason parsing)
# sec_status="secure" → successfully validated queries

DoH ACCESS LOG:
# Apache/Nginx format:
# [timestamp] POST /dns-query - client_ip - 200 - "application/dns-message" - latency
1700000003.789 POST /dns-query 203.0.113.5 200 29 "application/dns-message" 0.012

# Monitor:
# Non-200 status codes (400=malformed query, 429=rate limited)
# Unusually long query names (base64 encoded data = tunneling)
# High request rates from single IPs
```

### Monitoring DNSSEC Infrastructure

```python
"""
DNSSEC Health Monitoring Script:
Checks RRSIG validity, DNSKEY presence, and chain of trust
"""
import dns.resolver
import dns.dnssec
import datetime

def check_dnssec_health(domain):
    results = {}
    
    # Check 1: Can the zone be resolved?
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        answer = resolver.resolve(domain, 'A', raise_on_no_answer=False)
        results['resolution'] = 'OK'
        results['ad_bit'] = bool(answer.response.flags & dns.flags.AD)
    except dns.resolver.SERVFAIL:
        results['resolution'] = 'SERVFAIL — possible DNSSEC failure'
        results['ad_bit'] = False
    
    # Check 2: RRSIG records present?
    try:
        rrsig_answer = resolver.resolve(domain, dns.rdatatype.RRSIG)
        for rrsig in rrsig_answer:
            expiry = datetime.datetime.fromtimestamp(rrsig.expiration)
            days_until_expiry = (expiry - datetime.datetime.now()).days
            results['rrsig_expiry_days'] = days_until_expiry
            
            if days_until_expiry < 7:
                results['rrsig_status'] = f'WARNING: Expires in {days_until_expiry} days'
            elif days_until_expiry < 2:
                results['rrsig_status'] = f'CRITICAL: Expires in {days_until_expiry} days'
            else:
                results['rrsig_status'] = 'OK'
    except Exception as e:
        results['rrsig_status'] = f'ERROR: {e}'
    
    # Check 3: DS record in parent zone?
    try:
        parent_domain = '.'.join(domain.split('.')[1:])  # example.com → .com
        ds_answer = resolver.resolve(domain, dns.rdatatype.DS)
        results['ds_record'] = f'Present: {len(ds_answer)} DS records'
    except dns.resolver.NoAnswer:
        results['ds_record'] = 'MISSING — zone not connected to parent'
    except Exception as e:
        results['ds_record'] = f'ERROR: {e}'
    
    return results

# Run checks every 5 minutes, alert on any WARNING or CRITICAL
for domain in ['api.example.com', 'mail.example.com', 'example.com']:
    health = check_dnssec_health(domain)
    print(f"{domain}: {health}")
```

---

## 10. Interview Questions

### Q1: "Explain the DNSSEC chain of trust from the root zone to a specific record. Why is the root KSK the 'trust anchor' and what happens if it needs to be rotated?"

**Answer:**

The chain of trust is a linked sequence of cryptographic validations. At each level, a parent zone contains a hash (DS record) of the child zone's Key Signing Key (KSK). Since the parent's signature is itself validated by its parent's key, validation chains all the way up to the root zone.

The root KSK is the "trust anchor" because it is the starting point of this chain that has NO parent to validate it. There is no parent zone above the root ("." zone). Instead, the root KSK's public key (or its fingerprint) is hardcoded into every DNSSEC-validating resolver. This is a deliberate design choice: since the chain cannot extend infinitely upward, it must terminate at an a priori trusted key. Resolvers ship with this key baked in, identical to how browsers ship with CA root certificates.

Root KSK rotation (which happened in 2018) is the hardest operation in all of DNS. The challenge: every resolver on the internet has the old KSK hardcoded or cached via RFC 5011 rollover. If a resolver has only the old KSK and you begin signing with the new KSK, that resolver will fail to validate EVERYTHING on the internet. The 2018 rotation required IANA to:
1. Publish both old and new KSK (pre-publish phase lasting months)
2. Sign the root DNSKEY RRset with BOTH keys simultaneously
3. Monitor resolver populations to determine what fraction had the new KSK
4. Only complete the transition when enough resolvers had updated

The real operational lesson: trust anchors must never be changed without extremely long transition periods. Any rotation failure would make the entire DNSSEC-secured internet unreachable for resolvers with the old trust anchor.

**What-if:** "What if the root KSK private key was compromised?" This would be catastrophic — an attacker with the root KSK could forge DS records for any TLD, and those forged DS records would validate any fraudulent delegation. The only recovery is for IANA to generate a new root KSK through an emergency key ceremony, and for all resolver operators to update their trust anchors manually (RFC 5011 automation would itself be compromised if the attacker can forge root zone records). This is why the root KSK is managed through extremely controlled key ceremonies with multiple Hardware Security Modules in air-gapped facilities.

---

### Q2: "Explain the Kaminsky DNS cache poisoning attack. How does DNSSEC prevent it? What about resolvers that don't validate DNSSEC?"

**Answer:**

The Kaminsky attack exploits two properties of DNS: source port randomization that was inadequate in 2008, and the ability to inject authority records (NS delegations) in a forged response.

The attack works by querying a target recursive resolver for random subdomains of a target zone (e.g., random-uuid.example.com). Since these subdomains don't exist, the resolver queries the authoritative nameservers. For each such query, the resolver generates a transaction ID (16 bits, ~65,000 values). The attacker races to send forged responses with all possible transaction IDs, each containing a fraudulent NS delegation (e.g., claiming that example.com's nameserver is ns.attacker.com). Because the attacker can generate unlimited random subdomain queries, they get unlimited races. Eventually, one forged response arrives before the legitimate response with the correct transaction ID, and the forged NS delegation is cached.

DNSSEC prevents this because a forged response would need to include a valid RRSIG for the authority records. The RRSIG is an ECDSA or RSA signature over the record set using the zone's private ZSK. Without the private key, the attacker cannot produce a valid RRSIG. A validating resolver receiving the forged response would compute the signature verification and get a mismatch → BOGUS → SERVFAIL. The forged record is never cached.

For resolvers not validating DNSSEC: the Kaminsky attack remains viable. The defenses that partially mitigate it (but don't fully prevent it) are: source port randomization (adds ~16 bits of entropy beyond the 16-bit transaction ID), 0x20 bit randomization (randomizes case in the query name, forged response must match), and DNS cookies (RFC 7873, adds a shared secret to each session). None of these is as robust as DNSSEC — they increase the work factor for attackers but don't make the attack impossible.

---

### Q3: "What is the difference between DoT and DoH? Which is better for privacy and why do enterprises prefer one over the other?"

**Answer:**

Both DoT (DNS-over-TLS, port 853) and DoH (DNS-over-HTTPS, port 443) encrypt DNS queries, preventing passive surveillance. The differences are architectural:

DoT uses a dedicated port (853) for DNS queries wrapped in TLS. The transport is a standard TLS connection with a 2-byte length-prefixed DNS message format. The protocol is distinct and identifiable at the network layer (even if content is encrypted, the port and TLS fingerprint identify it as DNS).

DoH uses standard HTTPS on port 443. DNS queries are sent as HTTP/2 POST requests with `Content-Type: application/dns-message`. From a network perspective, DoH traffic is completely indistinguishable from ordinary HTTPS traffic to a web API.

**Privacy comparison:** Both provide confidentiality against passive eavesdroppers. DoH provides stronger resistance to censorship and blocking because port 853 can be trivially blocked by firewalls without affecting web traffic, while blocking port 443 would break essentially all HTTPS — not a viable option for censors. DoH also hides which resolver you're using (the resolver hostname is the TLS SNI, but it could be a CDN shared by many services).

**Enterprise perspective:** Enterprises strongly prefer DoT. The reason is visibility and control. Enterprise security teams need to inspect DNS queries for threat detection (malware C2 domains, data exfiltration, RPZ filtering). DoT uses a dedicated port (853) that enterprises can:
1. Block at the firewall, forcing clients to use corporate DNS
2. Intercept with TLS inspection (decrypt and inspect DNS queries for threat hunting)
3. Monitor for policy compliance

DoH is a nightmare for enterprise control because it uses port 443 alongside all other HTTPS traffic. Blocking port 443 to 8.8.8.8 or 1.1.1.1 would break legitimate HTTPS to Google and Cloudflare services. Enterprises often deploy internal DoH resolvers and use MDM policies to force clients to use the corporate DoH server rather than external providers.

---

### Q4: "Walk me through what happens to DNS resolution if DNSSEC validation fails. Why does it return SERVFAIL instead of the incorrect answer?"

**Answer:**

When DNSSEC validation fails, a properly configured validating resolver returns SERVFAIL (RCODE=2) with no answer. This is not a coincidence of naming — it's a deliberate security design decision.

The reasoning: if a DNSSEC-signed zone returns a response that fails signature verification, there are only two possibilities. Either the response has been tampered with (cache poisoning, MITM attack), or the zone's DNSSEC configuration is broken. In either case, returning the answer would be providing data the resolver cannot vouch for.

The alternatives would both be worse. If the resolver returned the record with a flag saying "DNSSEC validation failed," applications rarely inspect this flag and would use the record anyway — providing no security benefit and potentially serving poisoned data. If the resolver returned the record silently anyway, DNSSEC would provide no security protection (attackers would simply forge records knowing the forged response would be served).

SERVFAIL communicates "I received a response but I cannot verify it is authentic." This forces the application to either refuse to use the result or seek another resolution path. For users, this manifests as "DNS_PROBE_FINISHED_NXDOMAIN" or similar browser errors — the site appears unreachable.

The AD bit (Authenticated Data, bit 5 in the DNS flags) is the positive signal: a response with AD=1 means the resolver verified DNSSEC signatures and the data is authentic. Absence of AD doesn't mean failure — it means the zone is unsigned (INSECURE) and no validation was possible. Only an explicit SERVFAIL with RCODE=2 and a BOGUS extended error code (RFC 8914) indicates a validation failure.

**What-if:** "What if the stub resolver tells the recursive resolver to skip validation with CD=1?" The CD (Checking Disabled) bit instructs the recursive resolver to return responses even if DNSSEC validation fails. The recursive resolver will then return the data (marked with AD=0). This is intended for use by local validating resolvers that want raw data to validate themselves — but if the stub resolver sets CD=1 without actually doing its own validation, DNSSEC provides zero protection. Audit your stub resolvers: CD=1 without local validation is a security misconfiguration.

---

### Q5: "Explain DNS rebinding. What does it bypass, and why is it hard to fully prevent?"

**Answer:**

DNS rebinding attacks exploit the Same-Origin Policy (SOP) in browsers combined with DNS caching TTLs. SOP prevents JavaScript loaded from evil.attacker.com from making requests to other origins (like internal network services). DNS rebinding makes the browser believe that evil.attacker.com and an internal service are the same origin.

The attack sequence: The attacker serves a website from evil.attacker.com with an extremely short DNS TTL (1 second). The initial DNS response resolves to the attacker's real server IP, which serves malicious JavaScript. After the TTL expires, the attacker changes the DNS response to resolve to an internal IP (e.g., 192.168.1.1, or 169.254.169.254 for cloud metadata). When the JavaScript makes a subsequent fetch() to evil.attacker.com, the browser re-resolves the domain (TTL has expired) and gets the internal IP. The browser sends the HTTP request to the internal service, believing it's still communicating with evil.attacker.com (same origin). The response — perhaps the router admin interface or cloud IAM credentials — comes back and the JavaScript reads it, because SOP allows reading responses from the same origin.

**Why it's hard to fully prevent:**

First, browsers traditionally implement SOP based on hostname, not IP address. Changing the IP while keeping the hostname is the core of the attack, and until recently browsers didn't detect this change.

Second, TTL enforcement in browsers is inconsistent. Browsers sometimes ignore TTLs and cache DNS results longer (performance optimization), but they may also re-resolve earlier than expected, making the attack timing unpredictable.

Third, the most robust defense — internal services validating the HTTP Host header and rejecting requests where Host doesn't match expected values — is widely unimplemented in embedded devices, routers, and internal services designed for local use only. These devices assume they'll only be accessed by users on the local network, not through DNS rebinding.

Modern mitigations include Chrome's Private Network Access (formerly CORS for private networks), which requires a preflight request before cross-origin-to-private-network requests, and resolver-side blocking of public domains resolving to private IPs. But these are newer and not universally deployed.

---

### Q6: "What is DNSSEC NSEC3 and why is it needed? What does it protect against?"

**Answer:**

NSEC3 (Next Secure 3, RFC 5155) addresses a privacy problem with the original NSEC (Next Secure) record, while maintaining DNSSEC's ability to cryptographically prove that a domain name does not exist.

**The problem NSEC creates:** When you query for a non-existent domain (e.g., xyz.example.com) in a DNSSEC-signed zone, the nameserver cannot just say "NXDOMAIN" — an attacker could forge that NXDOMAIN. The nameserver needs to prove cryptographically that the name doesn't exist. It does this with an NSEC record that says "there are no names between alpha.example.com and gamma.example.com" (in canonical alphabetical order). This NSEC record is signed, so it's authenticated.

The problem: NSEC records reveal the COMPLETE enumeration of a zone. By sending NXDOMAIN queries and following the NSEC chain (alpha → beta → delta → gamma → ...), an attacker can walk the entire zone and discover every DNS record. Zone walking defeats any security through obscurity (though DNS was never designed for obscurity) and enables targeted attacks against specific internal services.

**How NSEC3 solves it:** Instead of listing actual domain names in the NSEC chain, NSEC3 lists hashed values of domain names. The hash is SHA-1 with a salt and iteration count. Zone walking now only reveals SHA-1 hashes, not actual domain names. An attacker trying to enumerate would need to reverse SHA-1 hashes (computationally expensive) or brute-force using rainbow tables (mitigated by the salt).

NSEC3 provides authenticated denial of existence (an attacker cannot forge an NXDOMAIN response) while protecting zone contents from enumeration. It's the recommended mode for DNSSEC-signed zones that contain sensitive internal service names.

The remaining weakness: NSEC3 with very low iteration counts (iteration=0 is now recommended per RFC 9276 to avoid DoS via expensive hashing) means an attacker with significant compute can still enumerate if they know the approximate zone contents. For truly sensitive zones, the answer is split-horizon DNS (different views for internal vs external) rather than relying on NSEC3 alone.

---

*Document version: 1.0 | Classification: Internal Engineering*
*Author: Network Security Engineering Team*
*This document covers production DNS security architecture, protocol mechanics, and operational best practices.*
*All attack descriptions are for defensive engineering purposes, consistent with IETF RFC documentation and security curricula.*
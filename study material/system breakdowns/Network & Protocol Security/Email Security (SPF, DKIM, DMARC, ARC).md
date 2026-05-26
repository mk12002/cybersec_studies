# Email Security (SPF, DKIM, DMARC, ARC) — Deep Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Reference
> **Audience:** Security Engineers, Email Administrators, Protocol Architects, Interview Candidates
> **Scope:** Complete mechanics of SPF, DKIM, DMARC, and ARC — from DNS record structure through cryptographic verification, attack vectors, and operational deployment
> **Systems Covered:** Postfix/Exim/Exchange MTAs, OpenDKIM, Rspamd, public DNS (BIND/Unbound), DNSSEC chain of trust, Google/Microsoft email gateway behavior

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

### Scenario: Legitimate Email from `ceo@corp.com` to `recipient@gmail.com`

This narrative traces the exact sequence of operations from SMTP submission through final delivery, showing how each authentication protocol is invoked, in order.

---

### T=0 — SMTP Submission (Mail User Agent → Mail Submission Agent)

The CEO's mail client submits the email to `mail.corp.com:587`:

```
SMTP Submission Session (port 587, STARTTLS upgraded):
  C: EHLO laptop.corp.com
  S: 250-mail.corp.com Hello
     250-SIZE 52428800
     250-AUTH LOGIN PLAIN
     250-STARTTLS
     250 OK
  C: STARTTLS
  S: 220 Ready to start TLS
  [TLS handshake — encrypts session]
  C: AUTH LOGIN
  [Credentials exchanged]
  C: MAIL FROM:<ceo@corp.com>
  S: 250 OK
  C: RCPT TO:<recipient@gmail.com>
  S: 250 OK
  C: DATA
  S: 354 End data with <CR><LF>.<CR><LF>
  C: [email headers and body]
  C: .
  S: 250 OK: queued as abc123
```

---

### T=100ms — Outbound MTA Processing (corp.com's mail server)

The outbound MTA (`mail.corp.com`) receives the queued message and prepares it for delivery:

**Step 1: DKIM Signing**

The MTA (or a signing daemon like OpenDKIM) computes a DKIM signature over specified headers and the body:

1. Canonicalizes the email body (normalizes whitespace)
2. Canonicalizes specified headers (From, Subject, To, Date, MIME-Version)
3. Computes SHA-256 hash of the canonicalized body → `bh=` tag
4. Computes RSA or Ed25519 signature over the specified headers + the `bh=` value
5. Adds a `DKIM-Signature:` header to the email with the signature and metadata

**Step 2: Message Transfer**

The MTA performs a DNS MX lookup for `gmail.com` to find where to deliver:
```
DNS Query: MX gmail.com
Response:  10 alt1.gmail-smtp-in.l.google.com
           20 alt2.gmail-smtp-in.l.google.com
           5  gmail-smtp-in.l.google.com
```

The MTA connects to `gmail-smtp-in.l.google.com:25`:
```
SMTP Delivery Session (port 25, STARTTLS):
  C: EHLO mail.corp.com
  S: 250-gmail-smtp-in.l.google.com Hello
     250-SIZE 157286400
     250-STARTTLS
     250 OK
  C: STARTTLS
  [TLS handshake]
  C: MAIL FROM:<ceo@corp.com>
  S: 250 OK
  C: RCPT TO:<recipient@gmail.com>
  S: 250 OK
  C: DATA
  S: 354 Ready
  C: [full message with DKIM-Signature header]
  C: .
  S: 250 OK: message delivered
```

---

### T=200ms — Receiving MTA Authentication Checks (Gmail)

Gmail's inbound gateway performs all authentication checks **before** accepting the message for delivery to the inbox:

**Check 1: SPF**

Gmail looks up `corp.com`'s SPF record:
```
DNS Query: TXT corp.com
Response: "v=spf1 ip4:203.0.113.0/24 include:_spf.google.com ~all"
```

Gmail checks: Does the connecting IP (`mail.corp.com`'s IP, say `203.0.113.5`) fall within `203.0.113.0/24`? **YES.** SPF result: `pass`.

**Check 2: DKIM**

Gmail extracts the `DKIM-Signature:` header and finds:
```
d=corp.com, s=mail2024
```
It queries: `mail2024._domainkey.corp.com` TXT record → gets the public key. Verifies the signature. **PASS.**

**Check 3: DMARC**

Gmail looks up `corp.com`'s DMARC policy:
```
DNS Query: TXT _dmarc.corp.com
Response: "v=DMARC1; p=reject; rua=mailto:dmarc@corp.com; ruf=mailto:dmarc-forensic@corp.com; pct=100"
```

Gmail evaluates:
- Does SPF identifier align with the `From:` domain? `MAIL FROM` was `ceo@corp.com`, `From:` is `ceo@corp.com`. **Aligned.**
- Does DKIM identifier align? `d=corp.com` in the DKIM signature matches `From:` domain. **Aligned.**
- Policy: `p=reject` — would reject if both fail, but both passed.
- DMARC result: **PASS**

**Check 4: Outcome**

Message is delivered to the recipient's inbox with authentication headers added by Gmail.

---

## 2. Header & Packet Anatomy

### 2.1 SPF — TXT Record Structure

SPF is published as a DNS TXT record at the domain's apex (or subdomain):

```
DNS TXT Record for corp.com:
  "v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 include:_spf.sendgrid.net a:mail.corp.com mx -all"
```

**Parsing SPF mechanisms (evaluated left-to-right, first match wins):**

| Mechanism | Example | Meaning |
|-----------|---------|---------|
| `ip4:` | `ip4:203.0.113.0/24` | Match if sending IP is in this IPv4 range |
| `ip6:` | `ip6:2001:db8::/32` | Match if sending IP is in this IPv6 range |
| `include:` | `include:_spf.sendgrid.net` | Recursively evaluate the included domain's SPF record |
| `a:` | `a:mail.corp.com` | Match if sending IP is in the A/AAAA records of this hostname |
| `mx:` | `mx:corp.com` | Match if sending IP is one of the domain's MX records' IPs |
| `ptr:` | `ptr:corp.com` | Match if PTR record of sending IP resolves back to corp.com (slow, deprecated) |
| `exists:` | `exists:%{i}._spf.corp.com` | Match if DNS lookup returns any result (used for macros) |
| `all` | Always the last mechanism | Match everything (used with qualifier) |

**Qualifiers (prepend to any mechanism):**

| Qualifier | Meaning |
|-----------|---------|
| `+` (default) | PASS — this source is authorized |
| `-` | FAIL — this source is explicitly unauthorized |
| `~` | SOFTFAIL — this source is probably unauthorized (still deliver, but mark) |
| `?` | NEUTRAL — no assertion about authorization |

**So `-all` at the end means:** Any sender IP that didn't match a previous mechanism is explicitly FAIL.

**The `MAIL FROM` vs `From:` distinction (critical):**

SPF checks the **`MAIL FROM`** address (the RFC 5321 envelope sender — also called the "bounce address" or "return path"), **NOT** the `From:` header that users see in their email client. This is fundamental to understanding why SPF alone doesn't prevent spoofing of the visible `From:` address.

```
SMTP Envelope (what SPF checks):
  MAIL FROM: <ceo@corp.com>   ← SPF looks up corp.com TXT record
  RCPT TO: <victim@gmail.com>

Email Headers (what user sees — NOT what SPF checks):
  From: CEO <ceo@corp.com>    ← SPF does NOT check this
  Subject: Urgent wire transfer
```

An attacker can set `MAIL FROM: <attacker@legitimate-spf-domain.com>` (passes SPF) while setting `From: <ceo@corp.com>` (the address the user sees). DMARC alignment is what closes this gap.

---

### 2.2 DKIM — Signature Header Structure

A DKIM-Signature header looks like this:

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=corp.com; s=mail2024;
    t=1705358400; x=1705444800;
    h=from:to:subject:date:message-id:mime-version:content-type;
    bh=2jUSOH9NhtIH1/MnvLiFKkHqxc8Yz1T4tCzSxY5fks=;
    b=AuUoFEfDxTVo6FpsFRfjy+pxKQQAb8nXnpz6xm3Vp5RrQv4jkwLBKSMJX...
```

**Field-by-field breakdown:**

| Tag | Value | Meaning |
|-----|-------|---------|
| `v=1` | 1 | DKIM version (always 1) |
| `a=rsa-sha256` | algorithm | Signing algorithm: RSA with SHA-256 (or `ed25519-sha256`) |
| `c=relaxed/relaxed` | canonicalization | Header/body canonicalization method |
| `d=corp.com` | signing domain | The domain whose DNS holds the public key |
| `s=mail2024` | selector | Which specific key to look up under the domain |
| `t=1705358400` | timestamp | Unix timestamp when the signature was created |
| `x=1705444800` | expiry | Unix timestamp when the signature expires (optional) |
| `h=from:to:...` | signed headers | Colon-separated list of header fields included in the signature |
| `bh=...` | body hash | Base64-encoded hash of the canonicalized body |
| `b=...` | signature | Base64-encoded cryptographic signature |

**The DNS public key record:**

```
DNS TXT record at: mail2024._domainkey.corp.com
  "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC..."
  
  v=DKIM1: DKIM key record version
  k=rsa:   Key type (rsa or ed25519)
  p=...:   Base64-encoded public key (DER-encoded SubjectPublicKeyInfo)
  
  Optional tags:
  t=y:     Testing mode — receivers should not reject failures
  t=s:     Strict mode — subdomains may NOT use this key
  s=email: Service type (email, or * for any)
```

**DKIM Canonicalization — why it exists:**

Email messages often have headers and body modified in transit (whitespace normalization, line wrapping, added headers by forwarding servers). Canonicalization defines exactly which modifications are "acceptable" before the signature is verified.

**`simple` canonicalization:** Almost no transformations allowed. Line endings normalized to CRLF. Very strict — any modification breaks the signature.

**`relaxed` canonicalization (almost always used in practice):**

*Header relaxed:*
- Header field names converted to lowercase
- Runs of whitespace (spaces, tabs) in header values replaced with a single space
- Leading and trailing whitespace in header values stripped
- The header field itself retains its content

*Body relaxed:*
- Runs of whitespace replaced with single space within lines
- Trailing whitespace removed from each line
- Multiple trailing empty lines reduced to a single trailing CRLF

```
ORIGINAL BODY:
  "Hello  World  \r\n\r\n\r\n"

AFTER RELAXED CANONICALIZATION:
  "Hello World\r\n"
  
SHA-256 of canonicalized body = bh= value
```

---

### 2.3 DMARC — Policy Record Structure

```
DNS TXT record at: _dmarc.corp.com
  "v=DMARC1; p=reject; sp=quarantine; pct=100;
   rua=mailto:dmarc-agg@corp.com;
   ruf=mailto:dmarc-forensic@corp.com;
   adkim=s; aspf=s; fo=1"
```

**Field breakdown:**

| Tag | Example | Meaning |
|-----|---------|---------|
| `v=DMARC1` | Required | Version tag, must be first |
| `p=` | reject/quarantine/none | Policy for the domain itself |
| `sp=` | reject/quarantine/none | Policy for subdomains (if different from `p=`) |
| `pct=` | 0-100 | Percentage of messages subject to filtering policy |
| `rua=` | mailto:... | Where to send aggregate (XML) reports |
| `ruf=` | mailto:... | Where to send failure/forensic reports |
| `adkim=` | r (relaxed) or s (strict) | DKIM alignment mode |
| `aspf=` | r (relaxed) or s (strict) | SPF alignment mode |
| `fo=` | 0/1/d/s | Failure reporting options |
| `ri=` | 86400 | Reporting interval in seconds (default 24h) |

**DMARC Alignment — the critical concept:**

DMARC passes only if at least one of SPF or DKIM "aligns" with the `From:` header domain:

**SPF Alignment:**
- *Relaxed (`aspf=r`, default):* The `MAIL FROM` domain and `From:` domain share an Organizational Domain (eTLD+1). `mail.corp.com` aligns with `corp.com`.
- *Strict (`aspf=s`):* The `MAIL FROM` domain must EXACTLY match the `From:` domain.

**DKIM Alignment:**
- *Relaxed (`adkim=r`, default):* The `d=` value in the DKIM signature and the `From:` domain share an Organizational Domain.
- *Strict (`adkim=s`):* The `d=` value in the DKIM signature must EXACTLY match the `From:` domain.

**DMARC evaluation logic:**
```
DMARC_PASS if:
  (SPF result is 'pass' AND SPF identifier aligns with From: domain)
  OR
  (DKIM result is 'pass' AND DKIM d= aligns with From: domain)

DMARC_FAIL if:
  Both of the above conditions are false.
  (Note: SPF or DKIM can individually pass, but if neither ALIGNS with From:, DMARC still fails)
```

---

### 2.4 ARC — Authenticated Received Chain Headers

ARC addresses a fundamental problem: legitimate email forwarding (mailing lists, auto-forwarders) breaks DKIM and SPF because the forwarder modifies the message or sends from a different IP.

ARC adds three headers per hop, forming a chain of authentication state preservation:

```
ARC-Authentication-Results: i=1; mx.google.com;
    dkim=pass header.i=@corp.com header.s=mail2024;
    spf=pass smtp.mailfrom=ceo@corp.com;
    dmarc=pass (p=REJECT) header.from=corp.com

ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
    d=google.com; s=arc-20240116;
    h=from:to:subject:date:dkim-signature:message-id;
    bh=2jUSOH9NhtIH1/MnvLiFKkHqxc8Yz1T4tCzSxY5fks=;
    b=FhFLPTu...

ARC-Seal: i=1; a=rsa-sha256;
    d=google.com; s=arc-20240116;
    cv=none;
    b=QpJOT7...
```

**The three ARC headers:**

1. **`ARC-Authentication-Results` (AAR):** Records the authentication status at this hop. What did the current receiver see when it authenticated the message?

2. **`ARC-Message-Signature` (AMS):** A DKIM-like signature over the current state of the message (headers + body). This preserves the integrity of the message at this point in the chain.

3. **`ARC-Seal` (AS):** Seals all ARC headers from this hop and previous hops. The `cv=` tag indicates chain validation status: `none` (first hop), `pass` (prior chain valid), or `fail` (prior chain invalid).

**ARC `i=` counter:** Each intermediary increments `i=`. A message forwarded through Google Mail then through a corporate gateway would have `i=1` headers from Google and `i=2` headers from the corporate gateway.

---

## 3. Cryptographic & Trust Mechanics

### 3.1 DKIM Signature Generation

```
SIGNING PROCESS (at sending MTA):

1. SELECT HEADERS TO SIGN
   Headers: from, to, subject, date, message-id, mime-version, content-type
   (Always include From: — it's what users see)

2. CANONICALIZE HEADERS
   For each header in the h= list (in order specified in h=):
     "from:CEO <ceo@corp.com>\r\n"   (after relaxed canonicalization)
     "to:recipient@gmail.com\r\n"
     "subject:Q4 Results\r\n"
     ...
   
   Append the DKIM-Signature header itself (without the b= value):
     "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp.com; ..."

3. CANONICALIZE BODY
   Apply relaxed canonicalization to the message body
   Compute: body_hash = SHA-256(canonicalized_body)
   Encode: bh = base64(body_hash)

4. CONSTRUCT SIGNING INPUT
   data_to_sign = concatenation of all canonicalized headers
   (The bh= value is included in the DKIM-Signature header being signed)

5. SIGN
   RSA-SHA256:
     signature = RSA_sign(
       private_key,
       SHA-256(data_to_sign),
       padding=PKCS1v1.5  (or PSS for newer implementations)
     )
   
   Ed25519:
     signature = Ed25519_sign(private_key, data_to_sign)
     (Ed25519 includes its own hashing internally)
   
   b = base64(signature)
```

### 3.2 DKIM Signature Verification

```
VERIFICATION PROCESS (at receiving MTA):

1. EXTRACT DKIM-SIGNATURE HEADER
   Parse all tags: d=, s=, h=, bh=, b=, a=, c=

2. FETCH PUBLIC KEY
   Query: <selector>._domainkey.<signing_domain> TXT
   e.g., mail2024._domainkey.corp.com
   Extract: p= tag (base64-encoded public key)
   Decode: DER-encoded RSA/Ed25519 public key

3. VERIFY BODY HASH
   Canonicalize the message body using method in c= (right side)
   computed_bh = base64(SHA-256(canonicalized_body))
   If computed_bh != bh= value: FAIL (body was modified in transit)

4. RECONSTRUCT SIGNING INPUT
   For each header name in h= (in order listed):
     Fetch the MOST RECENT occurrence of that header from the email
     Canonicalize it using method in c= (left side)
   
   Reconstruct the DKIM-Signature header (with b= value as empty string)
   Append to the data

5. VERIFY SIGNATURE
   RSA-SHA256:
     RSA_verify(
       public_key,
       SHA-256(reconstructed_data),
       base64_decode(b=),
       padding=PKCS1v1.5
     )
   
   If verification succeeds: DKIM=PASS for d= domain
   If fails: DKIM=FAIL

6. CHECK ALIGNMENT WITH FROM: HEADER
   (For DMARC purposes)
   Compare d= value with the domain in From: header
   Apply relaxed or strict alignment rules
```

---

### 3.3 DNSSEC Chain of Trust for DKIM Key Distribution

DKIM public keys are published in DNS. Without DNSSEC, an attacker who can poison DNS can substitute their own public key and sign malicious emails with the corresponding private key.

```
DNSSEC TRUST CHAIN:

Root Zone (.)
  └── DNSKEY (KSK): signed by ICANN's Hardware Security Module
       └── Signs DS records in root zone for TLD delegations
  
.com TLD Zone
  ├── DNSKEY (ZSK): signed by root zone's DS record
  └── Signs DS records for registered domains

corp.com Zone
  ├── DNSKEY (ZSK): signed by .com zone's DS record
  │    Key type: Zone Signing Key (rotated frequently, e.g., monthly)
  │
  └── TXT record: mail2024._domainkey.corp.com
       └── RRSIG: cryptographic signature over this TXT record
            Signed by corp.com's ZSK
            → Proof: this key record was published by the legitimate corp.com zone owner

VALIDATION PROCESS (at resolver):
  1. Fetch TXT record for mail2024._domainkey.corp.com
  2. Fetch RRSIG for that TXT record
  3. Fetch DNSKEY for corp.com (the ZSK that signed the TXT record)
  4. Fetch DS record from .com zone (hash of corp.com's KSK)
  5. Verify chain up to the trust anchor (root KSK, pre-installed in resolver)
  
If DNSSEC validation fails: resolver returns SERVFAIL
This prevents substitution of fraudulent DKIM public keys
```

---

### 3.4 Trust Chain ASCII Diagram

```
╔══════════════════════════════════════════════════════════════════════════╗
║  EMAIL AUTHENTICATION TRUST CHAIN                                        ║
╚══════════════════════════════════════════════════════════════════════════╝

SENDER (corp.com)                     RECEIVER (Gmail)
┌────────────────────────────┐        ┌────────────────────────────────────┐
│  DOMAIN OWNER              │        │  INBOUND MTA                        │
│                            │        │                                    │
│  DNS zone: corp.com        │        │  1. SPF CHECK                      │
│  ┌──────────────────────┐  │        │     Query: TXT corp.com            │
│  │ TXT: v=spf1 ...      │──┼──DNS──►│     Compare: MAIL FROM IP vs SPF  │
│  │ TXT: v=DMARC1 p=rej  │  │        │     Result: pass/fail/softfail     │
│  │ TXT (selector._dk..) │  │        │                                    │
│  └──────────────────────┘  │        │  2. DKIM CHECK                     │
│                            │        │     Extract: d=, s= from header    │
│  Signing Key (private):    │        │     Query: s._domainkey.d DNS      │
│  ┌──────────────────────┐  │        │     Verify: RSA/Ed25519 signature  │
│  │  HSM / Key Store     │  │        │     Result: pass/fail/none         │
│  │  Private Key         │──┼──sign─►│                                    │
│  │  (never leaves)      │  │        │  3. DMARC CHECK                    │
│  └──────────────────────┘  │        │     Query: TXT _dmarc.corp.com     │
│                            │        │     Evaluate: alignment + policy   │
│  Message:                  │        │     Apply: none/quarantine/reject  │
│  From: ceo@corp.com        │        │                                    │
│  DKIM-Signature: ...  ─────┼──SMTP─►│  4. ARC (if forwarded):            │
│                            │        │     Validate chain: cv=pass?       │
└────────────────────────────┘        │     Override DMARC if chain valid  │
                                      └────────────────────────────────────┘
                                                 │
              ┌──────────────────────────────────▼─────────────────────┐
              │  DNS (authoritative for corp.com)                        │
              │                                                          │
              │  mail2024._domainkey.corp.com  TXT  "v=DKIM1; k=rsa;   │
              │                                       p=MIGf..."        │
              │  corp.com                      TXT  "v=spf1 ip4:..."    │
              │  _dmarc.corp.com               TXT  "v=DMARC1; p=rej..." │
              │                                                          │
              │  DNSSEC CHAIN:                                          │
              │  . (root) → .com → corp.com → RRSIGs on all records    │
              └─────────────────────────────────────────────────────────┘

TRUST PROPERTIES:
  SPF:  Trust is in DNS zone control (can I forge DNS? → DNSSEC prevents this)
  DKIM: Trust is in private key possession + DNS zone control for public key
  DMARC: Trust is in alignment between envelope/DKIM identity and From: header
  ARC:  Trust is in chain of intermediaries (each one must be trusted)
```

---

### 3.5 Key Rotation Reality

**DKIM key rotation** is operationally critical but often neglected. The standard recommendation is to rotate DKIM keys every 6-12 months, but the mechanics require careful sequencing:

```
DKIM KEY ROTATION SEQUENCE:

Step 1: Generate new key pair
  openssl genrsa -out dkim_new.pem 2048
  # Extract public key for DNS
  openssl rsa -in dkim_new.pem -pubout -out dkim_new.pub

Step 2: Publish NEW selector in DNS (DO NOT remove old yet)
  Add TXT record: mail2025._domainkey.corp.com "v=DKIM1; k=rsa; p=<new_pubkey>"
  Wait for DNS propagation (TTL expiry — can be minutes to 48 hours)
  DO NOT switch signing to the new key yet

Step 3: Wait for old-key-signed messages to clear the mail system
  Messages already in transit (queued, deferred) are signed with the old key
  Receiving servers will try to validate them for up to 5-7 days (RFC recommendation)
  If you revoke the old key before these messages are delivered: they fail DKIM

Step 4: Switch signing to the new selector
  Update MTA configuration: signing_selector = "mail2025"
  Restart signing service
  Verify: send test email, check headers for s=mail2025

Step 5: Retain old selector in DNS for 1-2 weeks
  Allows any messages signed with the old key but still in transit to validate
  
Step 6: Remove old selector
  Delete TXT record: mail2024._domainkey.corp.com
  
COMMON FAILURE: Steps 2 and 3 are reversed — new selector added and old one
removed simultaneously. Any messages in queues signed with the old key fail.
```

---

## 4. Core Implementation Architecture

### 4.1 Postfix + OpenDKIM Integration

```
POSTFIX MTA WITH OPENDKIM:

postfix/smtpd (receives incoming)
  └── milter protocol → opendkim (signing daemon)
       └── Queries DNS for public key
       └── Verifies received signatures
       └── Adds Authentication-Results header

postfix/smtp (sends outgoing)
  └── milter protocol → opendkim (signing daemon)
       └── Reads private key from filesystem/HSM
       └── Computes DKIM signature
       └── Inserts DKIM-Signature header

OPENDKIM CONFIGURATION:
  # /etc/opendkim.conf
  Mode                sv           # s=sign, v=verify
  Canonicalization    relaxed/relaxed
  Domain              corp.com
  Selector            mail2024
  KeyFile             /etc/dkim/mail2024.private
  
  # Key table maps selector to key file:
  mail2024._domainkey.corp.com    corp.com:mail2024:/etc/dkim/mail2024.private
  
  # Signing table maps from addresses to key entries:
  *@corp.com    mail2024._domainkey.corp.com
  *@sub.corp.com    mail2024._domainkey.corp.com

IPC MECHANISM (milter protocol):
  Postfix communicates with OpenDKIM via Unix socket or TCP:
  smtpd_milters = unix:/run/opendkim/opendkim.sock
  
  Protocol flow:
  Postfix → [CONNECT] → OpenDKIM (send connection metadata)
  Postfix → [HELO] → OpenDKIM (send EHLO domain)
  Postfix → [MAIL] → OpenDKIM (send MAIL FROM)
  Postfix → [RCPT] → OpenDKIM (send RCPT TO, multiple)
  Postfix → [HEADER] → OpenDKIM (send each header, one at a time)
  Postfix → [EOH] → OpenDKIM (end of headers)
  Postfix → [BODY] → OpenDKIM (send body in chunks)
  Postfix → [EOM] → OpenDKIM (end of message)
              ↓
         OpenDKIM computes signature
         Returns: INSHEADER action (add DKIM-Signature header)
              ↓
  Postfix inserts the header and delivers the message
```

### 4.2 SPF DNS Caching Behavior

```
SPF EVALUATION WITH DNS CACHING:

Receiving MTA caches DNS results to avoid repeated lookups for the same domain.

IMPORTANT: SPF evaluation can require multiple DNS lookups:
  - The primary SPF record: 1 lookup
  - Each "include:" mechanism: 1 lookup per include
  - Each "a:" mechanism: 1+ lookup (A/AAAA records)
  - Each "mx:" mechanism: 1 lookup for MX + 1 per MX host (A/AAAA)
  
RFC 7208 LIMIT: Maximum 10 DNS lookups during SPF evaluation.
  "include:", "a:", "mx:", "ptr:", "exists:" all count toward the 10-lookup limit
  "ip4:", "ip6:", "all" do NOT require DNS lookups

SPF PERMERROR: If the 10-lookup limit is exceeded, the result is "permerror"
  (permanent error — neither pass nor fail).
  For DMARC: permerror counts as a FAIL in SPF alignment evaluation.
  Many large organizations exceed this limit unintentionally due to many "include:" records
  for different email service providers.

CACHING CONSIDERATION:
  TTL=300 (5 min): SPF record for corp.com
  If an include: points to _spf.sendgrid.net, that record may have different TTL
  A change to a third-party email provider's SPF record won't be reflected
  until the TTL expires in the receiver's cache.
  
  Security implication: After removing an email provider, their IPs remain
  "authorized" in SPF from the perspective of cached DNS for up to TTL seconds.
```

### 4.3 DMARC Report Generation and Consumption

```
DMARC AGGREGATE REPORTS (RUA):

Sent daily by each receiving system (Google, Microsoft, Yahoo) to rua= address.
Format: XML, gzip-compressed, sent as email attachment.

Report structure:
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>8120238938</report_id>
    <date_range>
      <begin>1705276800</begin>   <!-- 2024-01-15 00:00:00 UTC -->
      <end>1705363199</end>       <!-- 2024-01-15 23:59:59 UTC -->
    </date_range>
  </report_metadata>
  
  <policy_published>
    <domain>corp.com</domain>
    <p>reject</p>
    <sp>quarantine</sp>
    <adkim>s</adkim>
    <aspf>s</aspf>
  </policy_published>
  
  <record>
    <row>
      <source_ip>203.0.113.5</source_ip>    <!-- Sending IP -->
      <count>1247</count>                     <!-- Messages from this IP today -->
      <policy_evaluated>
        <disposition>none</disposition>       <!-- Action taken: none/quarantine/reject -->
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_from>corp.com</envelope_from>
      <header_from>corp.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>corp.com</domain>
        <selector>mail2024</selector>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>corp.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  
  <!-- Additional records for other source IPs -->
</feedback>

FORENSIC REPORTS (RUF):
  Sent per-failure, contains the actual message headers (sometimes body)
  Privacy concern: RUF reports can contain sensitive email content
  Many receiving systems don't send RUF reports for this reason
  Google: sends RUF to ruf= address only if sender has published DMARC p=reject
```

---

## 5. Bypass & Attack Mechanics

### Attack 1: SPF Pass + DMARC Bypass via Subdomain

**Attacker goal:** Send phishing email appearing to be from `ceo@corp.com` that passes SPF.

**Setup:** `corp.com` has `p=reject` in DMARC. But `newsletters.corp.com` has no DMARC record (many organizations forget subdomains).

```
ATTACK EXECUTION:

1. Check DMARC for subdomains:
   Query: _dmarc.newsletters.corp.com → NXDOMAIN (no record)
   Query: _dmarc.corp.com → "v=DMARC1; p=reject" (no sp= tag)
   
   If sp= is not specified, the default is the same as p= (reject).
   BUT: Many older DMARC implementations treated unspecified sp= as "none".
   Modern receivers use p= value for subdomains if sp= is not set.
   
   ACTUAL BYPASS: Some receivers + p= without sp= = sp=none behavior.

2. Register/control a domain that passes SPF for corp.com's infrastructure:
   If corp.com's SPF includes "include:mailchimp.net" (third-party sender):
   Attacker creates a Mailchimp account with corp.com as a sending domain
   (if corp.com doesn't use DKIM alignment checks properly)
   
3. Send email with:
   MAIL FROM: <bounce@sub.corp.com>  (SPF passes if sub.corp.com has SPF)
   From: CEO <ceo@corp.com>          (user-visible header — potentially DMARC bypass)
   
   SPF checks MAIL FROM → sub.corp.com → passes
   DMARC alignment: Does sub.corp.com align with corp.com? YES (relaxed alignment)
   BUT: only if the SPF-aligned domain (sub.corp.com) is an organizational match
        for the From: domain (corp.com) — which it IS under relaxed alignment.
   
   RESULT: DMARC PASSES if aspf=r (relaxed) — sub.corp.com aligns with corp.com!
   
4. DEFENSE: Use strict DMARC alignment: aspf=s
   Strict requires EXACT domain match between MAIL FROM and From:
   sub.corp.com ≠ corp.com → DMARC FAILS → message rejected
```

---

### Attack 2: Display Name Spoofing (Bypasses All Authentication)

**Attacker goal:** Make email appear to come from the CEO without needing to bypass SPF/DKIM/DMARC.

```
ATTACK EXECUTION:

Attacker registers: corp-security@gmail.com

Sends email:
  From: "CEO Corp.com" <corp-security@gmail.com>
  
The From: header is technically:
  "CEO Corp.com" <corp-security@gmail.com>
  
Gmail's authentication results:
  SPF: pass (gmail.com SPF passes for Gmail's IPs)
  DKIM: pass (Gmail signs with @gmail.com DKIM key)
  DMARC: pass (d=gmail.com aligns with From: domain gmail.com)
  
ALL THREE PASS.

WHY THIS WORKS:
  The display name ("CEO Corp.com") is free text — not authenticated by any protocol.
  Email clients display the display name prominently.
  Many users only see "CEO Corp.com" not the actual email address.
  The email address is legitimate (gmail.com), so all checks pass.

VARIANTS:
  "Ceo <ceo@corp.com>" <attacker@evil.com>
  └── Some parsers will show "Ceo <ceo@corp.com>" as the display name
       (treating the outer angle brackets as the actual address)
       This is a header parsing attack — RFC 5322 is complex to parse correctly
  
  Unicode lookalike attacks:
  "CEO Corp.com" <cе0@corp.com>  ← The 'е' is Cyrillic, '0' is zero
  Domain: corp.com vs c0rp.com (zero not O)
  
DEFENSES:
  - Display name impersonation detection (ML-based in Gmail/O365)
  - BIMI (Brand Indicators for Message Identification): verified logo next to sender
  - User training
  - No pure protocol defense — this is a user interface problem
```

---

### Attack 3: DKIM Replay Attack

**Attacker goal:** Reuse a valid DKIM signature to give legitimacy to attacker-controlled content.

```
MATHEMATICAL BASIS:
  DKIM signs specific NAMED HEADERS in a specific ORDER.
  The h= tag lists which headers are signed.
  If Subject: is NOT in h=, the attacker can replace the subject.
  
EXPLOIT (if From: is signed but To: is not):

Original legitimate email:
  DKIM-Signature: ... h=from:subject:date:message-id; b=VALID_SIG ...
  From: ceo@corp.com
  To: trusted-colleague@corp.com
  Subject: Q4 results attached

Attacker intercepts, changes To: header:
  DKIM-Signature: ... h=from:subject:date:message-id; b=VALID_SIG ...  (UNCHANGED)
  From: ceo@corp.com
  To: victim@corp.com    ← CHANGED (not in h=, doesn't break signature!)
  Subject: Q4 results attached

DKIM validation: PASS (From:, Subject:, Date:, Message-ID all unchanged)
DMARC: PASS (DKIM passes with alignment to corp.com)

The victim receives an email that appears to be from the real CEO,
with a valid DKIM signature, but was never actually sent to them.

STRONGER VARIANT — Full Replay:
  Attacker obtains a legitimately-signed email (e.g., from a mailing list)
  Replays it to different recipients
  DKIM signature is still valid because the signed content hasn't changed
  
  Protection: t= (timestamp) and x= (expiry) tags in DKIM
  If x= is set and the signature is past expiry: FAIL
  But many implementations set no expiry (x= is optional)
  
  Also: message-id: should be unique per message
  Replay detection: if the receiver logs message-ids and rejects duplicates,
  this attack is defeated operationally (but not by DKIM itself)

MITIGATION:
  Always include From:, To:, Subject:, Date:, Message-ID: in h= at minimum
  Set x= expiry (e.g., 604800 = 7 days)
  Receive side: log and deduplicate Message-ID values
```

---

### Attack 4: SMTP Header Injection / Multiple From Headers

**Attacker goal:** Confuse the receiver's parser into accepting a different `From:` address than what DMARC evaluates.

```
RFC 5322 AMBIGUITY ATTACK:

The RFC says there should be exactly one From: header.
But parsing is implementation-defined when multiple exist.

SMTP DATA:
  MAIL FROM: <legit@corp.com>     ← SPF checks this (passes)
  ...
  From: legit@corp.com            ← DMARC checks this for alignment
  From: ceo@corp.com              ← Duplicate From: header
  Subject: Urgent
  ...

PARSING BEHAVIOR DISCREPANCY:
  MTA (DMARC evaluator): takes the FIRST From: header → legit@corp.com
    SPF: legit@corp.com aligns with corp.com → PASS (if corp.com SPF valid)
    DKIM: if d=corp.com → PASS
    DMARC: PASS
  
  Mail client (what user sees): MAY take the LAST From: header → ceo@corp.com
    User sees: email from ceo@corp.com with DMARC PASS authentication badge

WHY THIS WORKS:
  Different software parses ambiguous messages differently.
  The security check and the user display are performed by different code.
  The gap between "what DMARC evaluated" and "what the user sees" is the attack.

RFC COMPLIANCE DEFENSES:
  Receiving MTA should reject messages with multiple From: headers (strict mode)
  Or: DMARC evaluator and user-facing display must use IDENTICAL parser
  Many systems now check for and reject duplicate From: headers
  Google/Microsoft have largely closed this attack vector in their own parsing
  
NULL ORIGIN / ENCODING ATTACKS:
  From: =?utf-8?b?Q0VPIDxjZW9AY29ycC5jb20+?= <legit@corp.com>
  Base64-decodes to: "CEO <ceo@corp.com>" as display name
  Actual address: legit@corp.com
  User might see: CEO <ceo@corp.com>
```

---

### Attack 5: DNS Cache Poisoning Against DKIM Key Records

**Attacker goal:** Replace the legitimate DKIM public key in DNS with an attacker-controlled public key.

```
MATHEMATICAL BASIS (Kaminsky Attack variant for DKIM):

Without DNSSEC:
  The resolver caches DNS results. To poison it:
  
  1. Attacker triggers a DNS lookup from the target resolver:
     (e.g., by sending an email to victim@target.com, causing target.com's
      MTA to look up mail2024._domainkey.corp.com)
  
  2. While the resolver is waiting for the authoritative response from
     corp.com's nameservers, attacker floods the resolver with spoofed
     DNS responses:
     
     Spoofed response:
       QID: (random, guessing 16-bit space = 65536 possibilities)
       Answer: mail2024._domainkey.corp.com TXT "v=DKIM1; k=rsa; p=<ATTACKER_KEY>"
     
     The attacker needs to guess:
       - The 16-bit Query ID
       - The source port (random, 16-bit)
       Total: 2^32 combinations, but with fast machines: feasible
  
  3. If the attacker wins the race (their spoofed response arrives before the
     real response and has the correct QID):
     The resolver caches the attacker's public key for the TTL period
  
  4. Attacker signs malicious emails with their PRIVATE KEY
     Receivers query the poisoned cache, get the attacker's PUBLIC KEY
     Signature verifies: DKIM PASS
  
WITH DNSSEC:
  The spoofed response would need a valid RRSIG (cryptographic signature from
  corp.com's zone signing key). The attacker cannot forge this without the
  private signing key.
  
  DNSSEC completely defeats DNS-based DKIM key substitution attacks.
  This is why DNSSEC is critical for domains that use DKIM.
```

---

## 6. Security Controls & Defensive Mechanics

### 6.1 Progressive DMARC Deployment (Monitoring → Enforcement)

```
DEPLOYMENT PHASES:

PHASE 1: Monitor Mode (minimum 30 days)
  DNS: _dmarc.corp.com "v=DMARC1; p=none; rua=mailto:dmarc@corp.com; pct=100"
  
  Effect: No messages blocked. Aggregate reports show what would fail.
  Purpose: Discover all legitimate sending sources.
  
  What to check in reports:
  - Source IPs sending as corp.com (are they all authorized?)
  - SPF failures (misconfigured or unauthorized senders)
  - DKIM failures (services that send as corp.com but aren't signing)
  - Third-party senders: Salesforce, Mailchimp, Zendesk — all must be authorized

PHASE 2: Quarantine with Low Percentage
  DNS: "v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc@corp.com"
  
  Effect: 10% of failing messages go to spam/junk. 90% still delivered normally.
  Purpose: Validate no legitimate traffic breaks at small scale.
  pct= allows gradual rollout.

PHASE 3: Quarantine at Full Scale
  DNS: "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@corp.com"
  
  Duration: 2-4 weeks minimum. Watch for user complaints about missing email.

PHASE 4: Reject
  DNS: "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@corp.com; ruf=mailto:dmarc-forensic@corp.com"
  
  Effect: Receiving servers REJECT (not deliver, not quarantine) failing messages.
  This is the target state for security.
  
  IMPORTANT: After reaching p=reject, discovery of a legitimate service
  that wasn't configured properly = that service's emails are being silently
  rejected. Monitor reports continuously even at p=reject.
```

### 6.2 SPF Record Hardening

```
WRONG (soft fail — still delivers, just marks):
  v=spf1 ... ~all

WRONG (neutral — makes no assertion):
  v=spf1 ... ?all

WRONG (no enforcement):
  v=spf1 ... +all  ← allows ANYONE to send as your domain

CORRECT (hard fail — instructs receivers to reject):
  v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all

COMBINED WITH DMARC:
  SPF -all without DMARC p=reject: receiving servers may still deliver (SPF -all
  is just a hint; many receivers deliver softfail and fail equally)
  
  DMARC p=reject: this is the actual enforcement mechanism
  SPF is most useful as a data source for DMARC alignment, not standalone enforcement

AVOIDING SPF PERMERROR (lookup limit):
  WRONG:
  v=spf1 include:sendgrid.net include:mailchimp.net include:salesforce.com
         include:zendesk.net include:hubspot.com include:marketo.com
         include:intercom.io include:twilio.com include:constant-contact.net
         include:mailjet.com -all
  ← This easily exceeds 10 lookups

  CORRECT: Use SPF flattening
  Tool: dmarcian.com/spf-flattener or similar
  Flattening: resolve all include: chains to their final IP ranges
  Result: v=spf1 ip4:149.72.0.0/16 ip4:167.89.0.0/17 ip6:2a06:98c0::/29 ... -all
  
  DOWNSIDE of flattening: Third-party providers change their IP ranges.
  Flattened SPF record becomes stale. Must be re-flattened periodically.
  Best practice: Automate SPF flattening with scheduled DNS updates.
```

---

## 7. Attack Surface Mapping

### 7.1 Complete Entry Points

```
╔══════════════════════════════════════════════════════════════════════════╗
║  EMAIL AUTHENTICATION ATTACK SURFACE                                     ║
╚══════════════════════════════════════════════════════════════════════════╝

SENDING SIDE ATTACK SURFACE:
  ┌──────────────────────────────────────────────────────────────────────┐
  │  DNS Zone (corp.com)                                                  │
  │  - SPF TXT record: if modified → unauthorized senders pass           │
  │  - DKIM public key TXT: if substituted → attacker's key validates    │
  │  - DMARC TXT record: if deleted → no enforcement fallback to none    │
  │  - Without DNSSEC: all DNS records are spoofable via cache poisoning  │
  │  TRUST: Domain owner has full control. Registrar account = target.   │
  └──────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │  DKIM Private Keys                                                    │
  │  - Stored on MTA server or HSM                                       │
  │  - If stolen: can sign arbitrary emails that pass DKIM validation    │
  │  - No revocation mechanism in DKIM itself (must remove DNS record)   │
  │  - Key compromise is silent: no CRL, no OCSP, just delete the record │
  │  TRUST: Must be hardware-protected (HSM) or secrets manager.         │
  └──────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │  Third-Party Email Senders (Mailchimp, Salesforce, Sendgrid)         │
  │  - Included in SPF: if their infrastructure is compromised,          │
  │    attacker can send as your domain and SPF passes                   │
  │  - If they support DKIM signing for your domain: same risk           │
  │  - Supply chain: each third-party is a trust delegation              │
  │  TRUST: Third-party has physical control of their infrastructure.    │
  └──────────────────────────────────────────────────────────────────────┘

RECEIVING SIDE ATTACK SURFACE:
  ┌──────────────────────────────────────────────────────────────────────┐
  │  MTA DMARC Policy Enforcement                                         │
  │  - Receiving MTA may not enforce DMARC (especially older systems)    │
  │  - Per-receiver behavior differs (Gmail vs Yahoo vs on-prem Exchange) │
  │  - p=reject: relies on EACH receiver implementing correctly           │
  │  TRUST: Sender cannot guarantee receiver behavior.                   │
  └──────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │  Header Parsing Inconsistencies                                       │
  │  - Multiple From: headers: evaluator vs display may parse differently │
  │  - MIME encoding attacks: encoded headers may display unexpectedly   │
  │  - Internationalized domain names: homograph attacks                  │
  │  TRUST: Parser implementations are the trust boundary.               │
  └──────────────────────────────────────────────────────────────────────┘

EMAIL FORWARDING / ARC SURFACE:
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Mailing List Servers / Auto-Forwarders                               │
  │  - Modify message: break DKIM body hash                              │
  │  - Forward from new IP: break SPF                                    │
  │  - Without ARC: legitimate forwarded email fails DMARC               │
  │  - With ARC: receiving server must TRUST the ARC chain intermediaries│
  │  TRUST: ARC trust is configurable per-receiver (trusted intermediary │
  │          lists maintained by each receiving organization)            │
  └──────────────────────────────────────────────────────────────────────┘
```

### 7.2 Trust Boundary Diagram

```
═══════════════════════════════════════════════════════════════════════════
TRUST ZONE: SENDER'S DOMAIN OWNER
  ┌──────────────────────────────────────────────────────────────────┐
  │  Controls: DNS zone, DKIM private keys, MTA configuration        │
  │  Trusts: Their own infrastructure (and third parties they include) │
  │  Risk: Domain registrar account compromise → full zone takeover  │
  └──────────────────────────────────────────────────────────────────┘

TRUST BOUNDARY 1: DNS resolution
  (DNSSEC provides cryptographic integrity; without it, DNS is untrusted)

═══════════════════════════════════════════════════════════════════════════
TRUST ZONE: PUBLIC DNS INFRASTRUCTURE
  ┌──────────────────────────────────────────────────────────────────┐
  │  Resolvers, authoritative servers, root trust anchors            │
  │  With DNSSEC: cryptographically secured chain of trust           │
  │  Without DNSSEC: susceptible to cache poisoning                  │
  └──────────────────────────────────────────────────────────────────┘

TRUST BOUNDARY 2: SMTP + TLS
  (Opportunistic TLS: encrypted in transit, but no sender authentication)
  (STARTTLS is not authentication; the receiving server authenticates with a cert
   but there's no verification the cert belongs to who the sender claims to be)

═══════════════════════════════════════════════════════════════════════════
TRUST ZONE: RECEIVING MTA (Google, Microsoft, etc.)
  ┌──────────────────────────────────────────────────────────────────┐
  │  Independently fetches DNS records and evaluates SPF/DKIM/DMARC  │
  │  Applies sender's published policy (or local override policy)    │
  │  Trust: Sender trusts receiver to correctly implement the checks  │
  │         Receiver trusts sender's DNS records (DNSSEC-protected)  │
  └──────────────────────────────────────────────────────────────────┘

TRUST BOUNDARY 3: User's Mail Client
  (Mail client renders the From: display name — no protocol authentication here)
  (This is where display name attacks live; no email auth protocol addresses this)

═══════════════════════════════════════════════════════════════════════════
TRUST ZONE: USER
  ┌──────────────────────────────────────────────────────────────────┐
  │  Sees: Display name, email address (if client shows it)          │
  │  Does NOT see: DMARC result, SPF result, DKIM result (usually)   │
  │  Risk: Trained to trust padlock/shield icons without understanding│
  └──────────────────────────────────────────────────────────────────┘
```

---

## 8. Failure Points & Misconfigurations

### 8.1 DNS Propagation During SPF/DMARC Changes

```
SCENARIO: Corp.com migrates from on-premises email to Microsoft 365.

NAIVE MIGRATION SEQUENCE (DANGEROUS):
  Day 0: Remove old MTA's IP from SPF record
  Day 0: Add Microsoft 365 IPs to SPF
  Day 0: Switch MX records to Microsoft
  
  PROBLEM:
  - Old MX records (TTL=3600) are still cached
  - Emails sent during the TTL window still go to old server
  - Old server's IP no longer in SPF → SPF fails for old server
  - If DMARC is p=reject: legitimate email in transit gets rejected

CORRECT MIGRATION SEQUENCE:
  Day -7: Add Microsoft 365 IPs to SPF (before switching MX)
           Keep old IPs in SPF too
           Deploy DKIM signing on Microsoft 365 for corp.com
           Test DKIM by sending test emails
  
  Day 0: Switch MX records to Microsoft 365
          Lower TTL on MX records to 300 (5 minutes) a few days before
  
  Day +7: Remove old MTA's IPs from SPF (after old TTLs expire and
           no legitimate traffic is using the old path)
  
  Day +14: Remove old DKIM selector
            (Keep old selector live for 7+ days to allow in-transit messages to validate)

SPF TTL STRATEGY:
  During stable operation: TTL=3600 (1 hour) — reduces DNS query load
  Before any SPF change: Lower TTL to 300 (5 min) — allows fast propagation
  After change stabilizes: Raise TTL back to 3600
  
  The window of inconsistency = the old TTL before you lowered it
  Always lower TTL BEFORE making the change, not at the same time
```

### 8.2 DKIM Key Compromise — The Silent Revocation Problem

```
CRISIS SCENARIO: Private DKIM key for corp.com (selector mail2024) is leaked.

THE PROBLEM WITH DKIM REVOCATION:
  There is no DKIM CRL (Certificate Revocation List).
  There is no DKIM OCSP (Online Certificate Status Protocol).
  The only "revocation" mechanism is:
  
  Option A: Remove the DNS TXT record mail2024._domainkey.corp.com
    Effect: Any in-transit messages signed with this key now fail DKIM
    Effect: Attacker can no longer use the key (their signed emails fail)
    Problem: Legitimate messages in transit ALSO fail
    Risk window: Messages stay in queues for up to 5 days (RFC recommendation)
    
  Option B: Update the DNS record to an empty p= tag
    "v=DKIM1; p="   ← Empty p= means KEY REVOKED
    Effect: Any signature validated against this selector returns FAIL
    This is cleaner than deleting (prevents caching of NXDOMAIN)
    Still breaks in-transit legitimate messages
    
  Option C: Rotate to a new key (add new selector, keep old)
    mail2025._domainkey.corp.com (new, legitimate)
    mail2024._domainkey.corp.com (old, compromised — leave for a few days)
    Switch signing to mail2025 IMMEDIATELY
    Revoke mail2024 after 7-10 days (in-transit window clears)
    
  DURING THE REVOCATION WINDOW:
    The attacker with the stolen key can continue to send emails that
    pass DKIM for mail2024 until you remove/empty that DNS record.
    This is a fundamental architectural weakness of DKIM.
    
  MINIMIZING DAMAGE:
    Short key validity via x= (expiry) tag: set x= to 7 days in future
    Attackers who steal the key only have a 7-day window of usability
    (Assuming receivers honor the x= tag — not all do)
    
    DMARC aggregate reports: will show unusual volume from unknown IPs
    using your domain during the attack — detection mechanism
```

### 8.3 Mailing Lists Breaking DKIM

```
MAILING LIST PROBLEM:

  Original message: From: author@example.com
                   DKIM-Signature: d=example.com, b=VALID
  
  Mailing list (mailman.corp.com) receives and forwards:
  
  MODIFICATIONS MADE BY THE LIST:
  1. Adds "[Corp List]" to Subject: line
     → Subject: header is in h=, and its value changed
     → DKIM signature BREAKS
  
  2. Adds a footer to the message body:
     → Body hash (bh=) changes
     → DKIM signature BREAKS
  
  3. Changes the From: to the list address:
     From: Corp List <corplist@corp.com>
     → Original DKIM d=example.com doesn't align with new From:
     → DMARC FAILS (even if DKIM still valid)
  
  4. Sends from mailman.corp.com's IP:
     → SPF check: corp.com's SPF doesn't list mailman.corp.com's IP
     → Wait — the From: now says corp.com, so MAIL FROM is corp.com
     → SPF checks corp.com's record vs mailman.corp.com's IP
     → SPF might FAIL depending on configuration
  
  RESULT: A legitimate mailing list delivery fails DMARC with p=reject.
          The message gets rejected even though it's legitimate.

ARC SOLUTION:
  When the mailing list receives the message:
  1. Authenticate it: SPF pass (for example.com), DKIM pass
  2. Record the authentication state in ARC-Authentication-Results
  3. Sign the current message state with ARC-Message-Signature
  4. Add ARC-Seal (cv=none for the first hop)
  5. Forward the modified message
  
  When the recipient's MTA receives it:
  1. Standard SPF/DKIM/DMARC checks FAIL (as expected — list modified it)
  2. But ARC chain exists: cv=none, i=1, d=mailman.corp.com
  3. Receiver checks: is mailman.corp.com in our trusted ARC intermediary list?
  4. If YES: validates the ARC-Message-Signature (was the message unchanged
     from what the trusted intermediary received?)
  5. If valid: override the DMARC failure, deliver the message
  
  CRITICAL: ARC only works if:
  - The intermediary (mailing list server) adds ARC headers
  - The receiving MTA trusts the intermediary (explicit whitelist)
  - The ARC chain hasn't been broken (cv=fail at any hop → chain invalid)
```

---

## 9. Mitigations & Observability

### 9.1 DMARC Aggregate Report Analysis

```
KEY METRICS FROM DMARC REPORTS:

1. UNAUTHORIZED SENDERS (most important):
   In the XML report: records where source_ip is NOT your infrastructure
   AND disposition is NOT "none" (would have been rejected/quarantined)
   
   Significance: Someone is actively trying to send as your domain
   Action: Investigate source IP, check for brand abuse, report to abuse@isp
   
   SQL query against parsed reports:
   SELECT source_ip, count, disposition, dkim_result, spf_result
   FROM dmarc_records
   WHERE header_from = 'corp.com'
     AND source_ip NOT IN (SELECT ip FROM authorized_senders)
   ORDER BY count DESC;

2. BROKEN LEGITIMATE SENDERS:
   Records where:
   - source_ip IS your infrastructure
   - But dkim or spf FAIL
   
   Significance: A legitimate service is misconfigured
   Action: Fix SPF/DKIM for that service before upgrading to p=reject
   
3. FORWARDING FAILURES (ARC opportunities):
   Records where dkim FAILS but the IP appears to be a major forwarder
   (e.g., Google Workspace forwarding, Microsoft Exchange forwarding)
   
   Significance: Forwarding chains are breaking authentication
   Action: Ensure ARC is implemented on your forwarding infrastructure

4. VOLUME BASELINE:
   Total legitimate volume vs failing volume
   Calculate: legitimate_rate = passing_count / total_count
   Target: > 99.9% legitimate pass rate before enabling p=reject

AUTOMATION:
  Tools: Valimail, Dmarcian, EasyDMARC, Proofpoint Email Fraud Defense
  All parse DMARC XML reports and provide dashboards
  
  Self-hosted: Postmaster-tools parsers, rua2db (open source)
  
  Alert thresholds:
  - New source IP appearing sending as your domain: IMMEDIATE ALERT
  - Legitimate source IP DKIM failure spike: ALERT within 1 hour
  - Overall DMARC pass rate drop > 5%: ALERT
```

### 9.2 Complete Defense-in-Depth Configuration

```
STEP 1: DNS CONFIGURATION
  # SPF (hard fail, minimal includes)
  corp.com. 3600 TXT "v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.0/24 -all"
  
  # DKIM (multiple selectors for redundancy)
  mail2024._domainkey.corp.com. 3600 TXT "v=DKIM1; k=ed25519; p=<key>; t=s"
  # Note: t=s (strict) means subdomains CANNOT use this selector
  
  # DMARC (full enforcement)
  _dmarc.corp.com. 3600 TXT "v=DMARC1; p=reject; sp=reject; pct=100;
    adkim=s; aspf=s; rua=mailto:dmarc@corp.com; ruf=mailto:dmarc-forensic@corp.com;
    fo=1; ri=86400"
  # adkim=s, aspf=s: strict alignment (subdomains must exactly match)
  # fo=1: send forensic report for ANY failure (not just all-fail)
  
  # DNSSEC on all the above records (essential)
  # Enable at registrar level + zone signing

STEP 2: MTA HARDENING
  # Postfix: reject SPF failures explicitly
  /etc/postfix/main.cf:
  smtpd_recipient_restrictions =
    permit_mynetworks,
    reject_unauth_destination,
    check_policy_service unix:private/policy-spf,   # SPF check
    permit
  
  policy_time_limit = 3600
  
  # OpenDKIM: sign all outbound email
  # With Ed25519 keys (smaller, faster, equally secure)
  
  # Rspamd: full DMARC enforcement
  /etc/rspamd/local.d/dmarc.conf:
  actions = {
    quarantine = "add_header",
    reject = "reject"
  }
  
  spf_cache_size = 512;
  spf_cache_expire = 1d;

STEP 3: MONITORING
  # Parse DMARC aggregate reports daily
  # Metrics to export to your monitoring system:
  
  dmarc_messages_total{domain="corp.com",result="pass"} 125000
  dmarc_messages_total{domain="corp.com",result="fail"} 43
  dmarc_unauthorized_sources_total{domain="corp.com"} 7
  dkim_signing_failures_total{selector="mail2024"} 0
  spf_permerror_total{domain="corp.com"} 0  # Alert if > 0 (lookup limit exceeded)

STEP 4: BIMI (Brand Indicators for Message Identification)
  # After achieving p=quarantine or p=reject:
  default._bimi.corp.com. TXT "v=BIMI1; l=https://corp.com/logo.svg; a=https://corp.com/cert.pem"
  
  # This enables a verified logo to appear next to sender in Gmail/Yahoo/Apple Mail
  # Requires: VMC (Verified Mark Certificate) from Entrust/DigiCert
  # Cost: ~$1500/year but provides visible trust signal to users
  # Closes the display name attack surface (users see the verified logo)
```

---

## 10. Interview Questions

### Q1: What is the difference between the `MAIL FROM` address and the `From:` header? Why does SPF checking the wrong one enable spoofing?

**Answer:**

The `MAIL FROM` address (also called the envelope sender, return path, or RFC 5321 `MAIL FROM`) is the address transmitted during the SMTP session:
```
MAIL FROM: <bounce@provider.com>
```

This address serves as the bounce destination — where non-delivery reports (NDRs) are sent. It is NOT what appears in the user's email client.

The `From:` header (RFC 5322) is part of the email message content:
```
From: CEO <ceo@corp.com>
```
This IS what users see in their mail client as the sender.

SPF validates the `MAIL FROM` domain's DNS record against the connecting IP. An attacker can set `MAIL FROM: <bounce@attacker-domain.com>` (which passes SPF because attacker-domain.com's SPF record lists their IP), while setting `From: CEO <ceo@corp.com>` in the message headers (which is what the victim sees).

**Why this enables spoofing:** The user's experience is entirely determined by the `From:` header, which SPF doesn't check at all. SPF was designed to protect the bounce address path, not the display address.

**How DMARC closes this gap:** DMARC requires alignment — the domain in `MAIL FROM` (or `d=` in DKIM) must match the domain in `From:`. So even if SPF passes on `attacker-domain.com`, DMARC alignment fails because `attacker-domain.com` ≠ `corp.com`.

---

### Q2: Explain exactly how DKIM signing works. What specific bytes are hashed and signed, and how does the receiving server reconstruct the signed content?

**Answer:**

DKIM signing has two distinct hashing operations:

**Body hash (`bh=`):**
1. The message body is canonicalized (using the method in the right side of `c=`, typically `relaxed`)
2. Canonicalization normalizes whitespace and trailing lines
3. SHA-256 is computed over the entire canonicalized body
4. Result is base64-encoded → stored as `bh=`

**Signature over headers (`b=`):**
1. Each header named in `h=` is canonicalized (using the left side of `c=`)
2. They are concatenated in the order listed in `h=` (NOT the order they appear in the email)
3. The DKIM-Signature header itself is canonicalized and appended LAST (with `b=` set to empty string)
4. RSA-SHA256 (or Ed25519) signature is computed over this concatenation
5. Result is base64-encoded → stored as `b=`

**Receiver reconstruction:**
The receiver re-does exactly these steps:
1. Fetches the public key from `<selector>._domainkey.<d=domain>` DNS TXT record
2. Canonicalizes the message body, computes SHA-256, compares to `bh=` — if different, the body was modified
3. Fetches each header named in `h=`, canonicalizes them in the same order
4. Reconstructs the DKIM-Signature header with empty `b=`
5. Verifies the signature: `RSA_verify(public_key, SHA256(data), b=)`

**What if:** What if the same header appears multiple times? RFC 6376 says the receiver takes the MOST RECENT occurrence (last in message) for each header in `h=`, but the signer takes the first occurrence. Some implementations get this wrong, causing spurious DKIM failures for messages with duplicate headers.

---

### Q3: Why does DMARC alignment matter? Give a concrete example where SPF passes but DMARC fails.

**Answer:**

DMARC alignment is the mechanism that connects SPF/DKIM results to the visible `From:` address. Without alignment, an attacker could construct an email where all authentication checks pass but the displayed sender is completely different from any authenticated domain.

**Concrete example:**

An attacker wants to send phishing email as `ceo@corp.com`.

They control `evil.com` which has a perfectly valid SPF record listing their IP.

```
SMTP Envelope:
  MAIL FROM: <bounce@evil.com>    ← Their own domain, SPF will PASS

Email Headers:
  From: CEO <ceo@corp.com>       ← What the victim sees
  Subject: Urgent wire transfer needed
```

**Authentication results (without DMARC alignment checking):**
- SPF: PASS — `evil.com` lists this IP, check passes
- DKIM: Not signed (or signed by `evil.com`)

**With DMARC alignment:**
- SPF passed for `evil.com`, but `From:` says `corp.com`
- `evil.com` ≠ `corp.com` (different organizational domains)
- SPF alignment: FAIL
- DKIM alignment: FAIL (no DKIM, or DKIM `d=evil.com` ≠ `corp.com`)
- DMARC overall: FAIL
- If `corp.com` has `p=reject`: the message is rejected

**The mathematical basis:** DMARC alignment enforces that at least one of the authenticated identifiers (SPF domain or DKIM signing domain) organizationally matches the visible `From:` header domain. This closes the gap between "who technically sent it" and "who the user thinks sent it."

---

### Q4: How does ARC enable legitimate forwarded email to pass DMARC, and what trust assumptions does it require?

**Answer:**

**The problem ARC solves:**

When an email is forwarded through a mailing list, the list server:
- Changes the message body (adds footer → breaks DKIM `bh=`)
- Changes Subject: (adds "[List Name]" → breaks DKIM `h=` signature)
- Sends from the list server's IP (breaks SPF for original domain)
- Result: All authentication fails at the final destination, even though the original was legitimate

**How ARC works:**

At each intermediary hop, ARC captures and preserves the authentication state:

1. The list server receives the original email and authenticates it: sees DKIM=pass, SPF=pass, DMARC=pass
2. It adds three headers before forwarding:
   - **ARC-Authentication-Results (i=1):** Records "at this hop, DKIM=pass for corp.com, DMARC=pass"
   - **ARC-Message-Signature (i=1):** Signs the current message (like a new DKIM signature, capturing the message state at this point including the AAR header)
   - **ARC-Seal (i=1, cv=none):** Signs all three ARC headers from this hop; `cv=none` means no prior ARC chain to validate

3. The list server modifies the message (adds footer, etc.) and forwards it

4. At the final destination:
   - SPF fails (list server IP not in corp.com SPF)
   - DKIM fails (message body was modified)
   - DMARC would fail — but ARC chain exists

5. The receiver evaluates the ARC chain:
   - Was the ARC-Seal from a trusted intermediary? (Is `d=mailman.corp.com` in our trusted list?)
   - Is the ARC-Message-Signature valid? (Was the message unchanged from what the intermediary received and what it says it received in ARC-Authentication-Results?)
   - Did the ARC chain say the original had valid authentication?

6. If all checks pass: DMARC override — deliver the message

**Critical trust assumptions:**
- The receiving MTA must explicitly trust the intermediary that added the ARC headers (trust is not automatic)
- ARC chains with `cv=fail` are invalid (a broken link invalidates the entire chain)
- A malicious intermediary that's trusted could forge ARC headers — trust must be carefully granted
- Most receiving systems (Gmail, Microsoft) maintain their own internal trusted forwarder lists

---

### Q5: What is the DKIM replay attack and what protocol limitations make it possible?

**Answer:**

**The attack:** An attacker obtains a copy of a legitimately DKIM-signed email (by being a recipient of a mailing list, intercepting an email, or receiving a phishing defense analysis of a legit message). They then send this message — with the original valid DKIM signature — to different recipients it was never intended for.

**Why DKIM allows it:**

DKIM signs headers and body. The `To:` header can be in `h=` or not. If `To:` is NOT in `h=`, the attacker can simply change the `To:` header to redirect the email to new victims — the DKIM signature doesn't cover `To:` so it remains valid.

Even if `To:` IS in `h=`, the message-as-signed (with the original `To:`) can still be replayed to additional recipients by adding a BCC or sending it as-is to new addresses via a different SMTP session. The recipient's MTA doesn't know the message was originally sent to someone else.

**Protocol limitations exploited:**

1. DKIM has no concept of "authorized recipient" — it authenticates the sender, not the intended delivery path
2. DKIM `x=` (expiry) is optional; many systems don't set it; many receivers don't enforce it even when set
3. Message-ID uniqueness is a convention, not enforced by DKIM
4. There's no database of "this message was already delivered to these recipients"

**What DKIM is designed to do:** Verify that the signing domain authorized the message contents. It explicitly does NOT guarantee that the message is being delivered to the originally intended recipient.

**Defenses:**
- Always include `To:` in `h=` (makes header-swapping harder)
- Set `x=` expiry to 7 days
- Implement receiver-side Message-ID deduplication (doesn't require DKIM changes)
- For high-security scenarios: include a recipient-specific token in the message body and verify it at delivery

---

### Q6: Explain the SPF `permerror` condition. How can exceeding 10 DNS lookups silently break email delivery, and how do you diagnose and fix it?

**Answer:**

**What `permerror` is:** RFC 7208 mandates that SPF evaluation MUST NOT perform more than 10 DNS lookups. Each `include:`, `a:`, `mx:`, `ptr:`, and `exists:` mechanism counts as one lookup. If this limit is exceeded, the result is `permerror` — a permanent error indicating the SPF record is invalid.

**Why it's dangerous:**

For DMARC: `permerror` is treated as an SPF authentication failure. If DKIM also fails to align, the message fails DMARC. With `p=reject`, legitimate email from your domain gets rejected — not because it's spoofed, but because your SPF record is too complex.

**The silent failure pattern:**

Many organizations accumulate `include:` references over years:
```
v=spf1 
  include:sendgrid.net      (1)
  include:mailchimp.net     (2)
    → includes _spf1.mailchimp.net (3)
  include:salesforce.com    (4)
    → includes _spf.salesforce.com (5)
    → includes _spfmatch.salesforce.com (6)
  include:zendesk.net       (7)
  include:hubspot.com       (8)
  include:intercom.io       (9)
  include:marketo.net       (10)
    → includes _spf.marketo.net (11) ← PERMERROR
  -all
```

The count includes recursive lookups. `include:sendgrid.net` fetches their SPF record, which may itself have `include:` references, each counting toward the limit.

**Diagnosis:**
```bash
# Use mxtoolbox, dmarcian, or check.spf.foundation
# Command-line check:
python3 -c "
import dns.resolver, sys
def count_lookups(domain, count=0):
    answers = dns.resolver.resolve(domain, 'TXT')
    for r in answers:
        spf = r.to_text().strip('\"')
        if spf.startswith('v=spf1'):
            for mech in spf.split():
                if mech.startswith('include:'):
                    count += 1
                    count = count_lookups(mech[8:], count)
                elif mech.startswith(('a:', 'mx:', 'exists:', 'ptr:')):
                    count += 1
    return count
print(f'Lookups: {count_lookups(\"corp.com\")}')
"
```

**Fix: SPF Flattening**

Resolve all `include:` chains to their final IP ranges:
```bash
# Use a flattening tool or service
# Result:
v=spf1 
  ip4:149.72.0.0/16    # was include:sendgrid.net
  ip4:198.241.128.0/17 # was include:mailchimp.net
  ip4:204.14.232.0/21  # was include:salesforce.com
  ip4:185.12.80.0/22   # was include:zendesk.net
  # ... etc ...
  -all
```

This has zero DNS lookups for `ip4:` and `ip6:` mechanisms, so the limit is not hit.

**Maintenance burden:** Third parties change their IP ranges. Flattened SPF becomes stale. You must automate re-flattening (monthly automated check) or use a DNS service that auto-updates flattened SPF records.

---

### Q7: Why is Ed25519 preferred over RSA-2048 for DKIM signing, and what are the practical deployment differences?

**Answer:**

**Cryptographic properties:**

Ed25519 uses Edwards-curve digital signature algorithm with Curve25519. Compared to RSA-2048 for DKIM:

| Property | RSA-2048 | Ed25519 |
|----------|----------|---------|
| Key size (private) | 1,700+ bytes | 32 bytes |
| Public key size | 294 bytes | 32 bytes |
| DNS TXT record size | ~400 chars for `p=` | ~44 chars for `p=` |
| Signature size | 256 bytes | 64 bytes |
| Signing speed | ~1,000/sec (software) | ~100,000+/sec |
| Verification speed | ~10,000/sec (software) | ~50,000/sec |
| Security level | ~112 bits | ~128 bits |
| Side-channel resistance | Requires careful implementation | Inherently resistant (constant time) |

**Practical DNS benefit:** RSA-2048 public keys in DNS TXT records approach the 255-character limit per string (requiring multi-string TXT records). Ed25519 keys fit comfortably in a single string.

**Deployment differences:**

```dns
# RSA-2048 DKIM key record (often needs multi-string TXT):
mail2024._domainkey.corp.com. TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUA"
                                   "A4GNADCBiQKBgQC3kFrxHN+Cbx..."
# Split across multiple strings because of 255-char limit

# Ed25519 DKIM key record (single string, much simpler):
mail2024._domainkey.corp.com. TXT "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
```

**Compatibility concern:** Ed25519 is specified in RFC 8463 (2018). Most modern MTAs (Postfix 3.1+, Exim 4.90+, OpenDKIM 2.11+) support it. Some older systems may not recognize `k=ed25519` and treat it as an unknown key type (resulting in a DKIM verification failure).

**Recommendation:** Deploy DUAL SIGNING — sign with both RSA-2048 (for compatibility) and Ed25519 (for modern receivers). The DKIM-Signature headers stack; receivers try each one and pass if any validates.

---

*End of document. This breakdown represents a production-grade email security engineering reference at the level expected of a senior security engineer or email infrastructure architect.*
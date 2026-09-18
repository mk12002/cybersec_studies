# Burp Suite — The Complete Reference (Beginner → Advanced)

> A ground-up reference for web application penetration testing with Burp Suite.
> Every tool, every concept, and — most importantly — **why** each discovery technique works.
>
> Ordered so you can read top-to-bottom as a course, or jump to any section.

---

## Table of Contents

1. [What Burp Suite Is and Why It Exists](#1-what-burp-suite-is-and-why-it-exists)
2. [Prerequisite Concepts: HTTP, TLS, and the Browser](#2-prerequisite-concepts-http-tls-and-the-browser)
3. [The Core Idea: An Intercepting Proxy (Self-MITM)](#3-the-core-idea-an-intercepting-proxy-self-mitm)
4. [Editions: Community vs Professional vs Enterprise](#4-editions-community-vs-professional-vs-enterprise)
5. [First-Time Setup (Step by Step)](#5-first-time-setup-step-by-step)
6. [Scope and the Target Tool](#6-scope-and-the-target-tool)
7. [Proxy — The Heart of Burp](#7-proxy--the-heart-of-burp)
8. [Repeater — The Manual Workhorse](#8-repeater--the-manual-workhorse)
9. [Intruder — Automated Custom Attacks](#9-intruder--automated-custom-attacks)
10. [Decoder, Inspector, and Comparer](#10-decoder-inspector-and-comparer)
11. [Sequencer — Testing Randomness of Tokens](#11-sequencer--testing-randomness-of-tokens)
12. [Scanner — Automated Vulnerability Discovery (Pro)](#12-scanner--automated-vulnerability-discovery-pro)
13. [Burp Collaborator — Out-of-Band Detection (The Big Concept)](#13-burp-collaborator--out-of-band-detection-the-big-concept)
14. [The Concepts Behind the Discoveries (Vuln-by-Vuln)](#14-the-concepts-behind-the-discoveries-vuln-by-vuln)
15. [Advanced Workflows: Match/Replace, Macros, Session Handling](#15-advanced-workflows-matchreplace-macros-session-handling)
16. [Extensions and the BApp Store](#16-extensions-and-the-bapp-store)
17. [Turbo Intruder and the Single-Packet Attack](#17-turbo-intruder-and-the-single-packet-attack)
18. [HTTP Request Smuggling with Burp](#18-http-request-smuggling-with-burp)
19. [Command-Line, Headless, and REST API](#19-command-line-headless-and-rest-api)
20. [Keyboard Shortcuts and Efficiency](#20-keyboard-shortcuts-and-efficiency)
21. [Pitfalls, Evasion, and Good Practice](#21-pitfalls-evasion-and-good-practice)
22. [Legal and Ethical Note](#22-legal-and-ethical-note)

---

## 1. What Burp Suite Is and Why It Exists

**Burp Suite** is an integrated platform for testing the security of web applications. Think of it as a workbench: a collection of interconnected tools that all sit on top of one central capability — the ability to **see and modify every HTTP message** flowing between a browser and a web server.

### The problem it solves

When you use a website, an enormous amount happens that you never see:

- The browser builds HTTP requests, adds headers, handles cookies, follows redirects.
- JavaScript fires background requests (AJAX/`fetch`/XHR) you never clicked for.
- The server enforces (or fails to enforce) rules about who can access what.

Security bugs live in exactly this invisible layer. A "Buy" button might be disabled in the UI, but the server might still accept the purchase request if you send it manually. A price field of `100` might be changeable to `1`. A user ID of `1005` in a URL might be changeable to `1006` to read someone else's data.

To find these bugs you need to **step between the browser and the server** and take manual control of the raw traffic. That is precisely what Burp gives you. Everything else in Burp is built around that one superpower.

### Where it fits in a pentest

A typical web app test flows roughly like this:

1. **Recon / mapping** — browse the app through Burp so it records everything (Proxy + Target site map).
2. **Analysis** — look at the requests, understand parameters, spot interesting inputs.
3. **Probing** — replay and tamper individual requests (Repeater), automate variations (Intruder), or run the Scanner (Pro).
4. **Exploitation & proof** — confirm and demonstrate impact.
5. **Reporting** — export findings.

Burp touches every one of those stages.

---

## 2. Prerequisite Concepts: HTTP, TLS, and the Browser

You cannot use Burp well without a mental model of HTTP. Here is the minimum, explained.

### An HTTP request

```
POST /login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123
Content-Length: 29

username=admin&password=hunter2
```

Anatomy:

- **Request line**: `METHOD path HTTP/version`. Method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, etc.) says *what kind of action*. The path is the resource.
- **Headers**: metadata as `Name: value` pairs. `Host` says which site (crucial for shared servers). `Cookie` carries session state. `Content-Type` says how the body is encoded. `Content-Length` says how many bytes the body is.
- **Blank line**: separates headers from body. (Its exact bytes — `\r\n\r\n` — matter a lot for request smuggling later.)
- **Body**: the payload. Here it's URL-encoded form data.

### An HTTP response

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=xyz789; HttpOnly; Secure
Content-Length: 1274

<html>...</html>
```

- **Status line**: `HTTP/version code reason`. Codes you must know:
  - `2xx` success (`200 OK`, `201 Created`).
  - `3xx` redirect (`301`, `302 Found`, `304 Not Modified`).
  - `4xx` client error (`400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `429 Too Many Requests`).
  - `5xx` server error (`500 Internal Server Error`, `502`, `503`). A `500` triggered by your input is often a sign you broke a parser — a lead.
- **Headers**, then blank line, then **body**.

**Why this matters for Burp:** almost every discovery you make is you noticing that a *changed request* produced a *meaningfully different response* — a different status code, a different length, a different message, a time delay, or an interaction with a server you control. Train your eyes on those four numbers/signals: **status, length, timing, out-of-band interaction.**

### TLS / HTTPS in one paragraph

HTTPS is HTTP wrapped in **TLS** encryption. The browser and server perform a handshake, verify the server's certificate against a chain of trusted **Certificate Authorities (CAs)**, and then encrypt everything. This is great for privacy but it directly blocks a man-in-the-middle — which is exactly what Burp is. Section 3 explains how Burp gets around this *for your own traffic, with your permission*.

---

## 3. The Core Idea: An Intercepting Proxy (Self-MITM)

Burp works by being a **proxy** — software that sits in the middle of a network conversation. You configure your browser to send all its traffic to Burp (usually `127.0.0.1:8080`) instead of directly to the internet. Burp receives each request, optionally lets you view/pause/edit it, then forwards it to the real server. The response comes back through Burp the same way.

This is a **Man-in-the-Middle (MITM)** position — but a *consensual* one, on your own machine, against traffic you are authorized to test.

### The TLS problem and how Burp solves it

If Burp just tried to sit in the middle of an HTTPS connection, the browser would scream: the certificate Burp presents wouldn't be signed by a CA the browser trusts, so you'd get a certificate error. That's TLS doing its job.

Burp's solution is elegant:

1. On first run, Burp generates its **own unique CA certificate** (a private root cert, unique to your installation).
2. You **install Burp's CA certificate** into your browser's / operating system's trust store, telling *your* machine "trust certificates signed by this CA."
3. Now, when your browser connects to `https://example.com` through Burp, Burp **generates a certificate for `example.com` on the fly**, signs it with its own CA, and presents it to the browser. Because you trust Burp's CA, the browser accepts it. Burp separately makes a *real* TLS connection to the actual server.

The result: two TLS connections (browser↔Burp and Burp↔server), with Burp decrypting, showing you plaintext, and re-encrypting. This is the whole trick.

> **Security caution:** Burp's CA is powerful — anything that trusts it can be silently intercepted. Each Burp install generates a *unique* CA (older shared CAs were a real vulnerability). Only install it on machines you control, and understand that it stays in your trust store until removed.

---

## 4. Editions: Community vs Professional vs Enterprise

| Capability | Community (free) | Professional (paid) | Enterprise |
|---|---|---|---|
| Proxy, Repeater, Decoder, Comparer, Sequencer | Yes | Yes | — |
| Intruder | **Throttled** (rate-limited, no saved custom payload sets) | Full speed | — |
| Automated Scanner | **No** | Yes (crawl + audit) | Yes (at scale) |
| Burp Collaborator (private OOB testing) | No | Yes | Yes |
| Project files (save/resume work) | No (memory only) | Yes | — |
| Extensions (BApp Store) | Yes (most) | Yes (all, incl. Pro-API ones) | — |
| CI/CD automated scanning, multi-user | No | No | Yes |

**Practical takeaway for a learner:** Community is genuinely enough to learn 90% of manual technique — Proxy, Repeater, Decoder, Sequencer, and a slow-but-working Intruder. The two things you truly lose are the **Scanner** and **Collaborator**, both of which matter for advanced/blind bugs. Many people learn on Community and move to Pro when doing real engagements.

---

## 5. First-Time Setup (Step by Step)

1. **Start Burp** and choose a project. Community only offers a *temporary* in-memory project; Pro lets you save to a `.burp` file.
2. **Confirm the Proxy listener.** Go to `Proxy → Proxy settings → Proxy listeners`. Default is `127.0.0.1:8080`. This is the address your browser will point at.
3. **Choose how to browse:**
   - **Easiest:** use Burp's **built-in browser** (`Proxy → Intercept → Open browser`). It's a Chromium instance pre-configured to route through Burp with the CA already trusted. Zero setup.
   - **External browser:** configure your browser (or an extension like FoxyProxy) to use `127.0.0.1:8080` as its HTTP/HTTPS proxy, then install the CA cert.
4. **Install the CA certificate (external browser only):** with the proxy set, visit **`http://burp`** in that browser → **CA Certificate** → download `cacert.der` → import it into the browser/OS trust store as a trusted root. Now HTTPS works cleanly through Burp.
5. **Set Intercept to off initially** (`Proxy → Intercept → Intercept is off`). This lets traffic flow freely while still being *recorded* in HTTP history. Turn intercept on only when you want to catch and edit a specific request.
6. **Browse the target** normally. Watch `Proxy → HTTP history` fill up. You're now capturing everything.

If HTTP history stays empty: your browser isn't actually routing through Burp, or the listener port is wrong/taken. If HTTPS pages show cert errors: the CA isn't installed/trusted in *that* browser.

---

## 6. Scope and the Target Tool

**Scope** is the set of hosts/URLs you are allowed and intend to test. Setting it early is not bureaucracy — it changes Burp's behavior and protects you.

- `Target → Site map`: a tree of every host, folder, and endpoint Burp has seen, built passively as you browse. This is your map of the application's attack surface.
- `Target → Scope settings`: define include/exclude rules (by host, port, protocol, path — literal or regex).
- Enable **"And in-scope items only"** filters across Proxy history, and set Burp to **drop out-of-scope traffic**. This stops Burp from recording (or worse, scanning) `google.com`, analytics, ad networks, and third-party CDNs — dramatically cutting noise and preventing you from accidentally probing systems you're not authorized to touch.

**Why it matters technically:** the Scanner, Collaborator interactions, and session-handling rules can all be scoped. A tight scope means automation only fires where you intend. A sloppy scope means you might actively scan a payment provider's API — a legal and operational problem.

`Target → Issue definitions` (Pro) is a built-in encyclopedia of every vulnerability class Burp knows, with remediation text — useful for learning and for reports.

---

## 7. Proxy — The Heart of Burp

Everything starts here. The Proxy has several sub-tabs.

### 7.1 Intercept

When **Intercept is on**, Burp pauses each request (and optionally response) and waits for you. You can:

- **Edit** any part — path, headers, body — then **Forward** it.
- **Drop** it (never reaches the server).
- Toggle **response interception** to also catch and edit what the server sends back before the browser renders it (great for un-hiding disabled buttons or bypassing client-side checks).

Beginners often leave intercept **on** and get confused when the browser "hangs" — it's just waiting on a paused request. Rule of thumb: **intercept off by default**, flip it on only to grab a specific request.

### 7.2 HTTP history

A chronological log of every request/response that passed through, even with intercept off. This is where you spend a lot of time:

- Filter by scope, status code, MIME type, search term.
- Click any entry to see the full request and response.
- **Right-click → Send to Repeater / Intruder / Comparer / Decoder**, or "Do passive scan" (Pro).

Columns to watch: **Status**, **Length**, **MIME type**, **Method**. Sorting or eyeballing these reveals patterns (e.g., one request out of fifty returns a different length).

### 7.3 WebSockets history

WebSockets (`ws://` / `wss://`) are persistent bidirectional channels used by chat, live dashboards, trading apps. Burp logs the message stream and lets you intercept/edit individual WebSocket messages — an area many testers forget to check.

### 7.4 Match and replace (Proxy settings)

Automatic find-and-replace rules applied to every request or response on the fly. Examples:

- Replace your `User-Agent` on every request.
- Add a custom header (e.g., `X-Forwarded-For: 127.0.0.1`) to every request to test header-based access bypasses.
- Rewrite a response body to change `disabled` buttons to enabled, or flip a feature flag `"isAdmin":false` → `"isAdmin":true` in what the browser receives (client-side control bypass testing).

This is your first taste of automation-without-Intruder and is genuinely powerful.

---

## 8. Repeater — The Manual Workhorse

If Proxy is Burp's heart, **Repeater** is its right hand. Repeater lets you take a single request and send it **over and over, editing it freely each time**, watching how the response changes. This tight *edit → send → observe* loop is the core motion of manual web testing.

### How you use it

1. In HTTP history or Proxy, right-click a request → **Send to Repeater** (`Ctrl+R`).
2. In the Repeater tab, modify anything: change a parameter value, add a header, swap the method, tamper with JSON.
3. Click **Send** (`Ctrl+Space`). Read the response on the right.
4. Repeat, changing one thing at a time.

### What you're actually doing (the concept)

Manual testing is a **hypothesis loop**. You form a guess ("maybe the server doesn't check that this `user_id` belongs to me"), craft the minimal request change that would test it, send, and read the response for confirmation or refutation. Repeater is the instrument for that loop because it removes the browser, JavaScript, and UI entirely — you talk straight to the server.

**Worked example — Insecure Direct Object Reference (IDOR):**

Original request (yours, user 1005):
```
GET /api/account?id=1005 HTTP/1.1
Host: bank.example.com
Cookie: session=YOURS
```
Response: `200 OK`, your account details.

In Repeater, change `id=1005` → `id=1006`, resend. If you get:
```
HTTP/1.1 200 OK
...
{"id":1006,"name":"Someone Else","balance":9421.55}
```
…the server returned **another user's data** to *your* session. That is a broken access control (IDOR) — discovered purely by changing one number and reading the response. No exploit code, just Repeater and a hypothesis.

Repeater also supports tabs (one per request under test), history (undo your edits), and "Send group in parallel/sequence" for advanced timing attacks (see §17).

---

## 9. Intruder — Automated Custom Attacks

**Intruder** automates sending many variations of a request by inserting **payloads** into **positions** you mark. It is Burp's fuzzer, brute-forcer, and enumerator. Understanding its four **attack types** is essential — most Intruder confusion comes from picking the wrong one.

### 9.1 Positions and payloads

You send a request to Intruder (`Ctrl+I`), then mark **positions** — the spots where payloads get inserted — using the `§` markers. Example (two positions marked):

```
POST /login HTTP/1.1
Host: example.com

username=§admin§&password=§pass§
```

A **payload set** is the list of values to try in a position. **Payload processing** rules can transform each payload (e.g., URL-encode it, hash it, prepend text, skip if it matches a regex).

### 9.2 The four attack types — with the math

**Sniper** — *one* payload set, **one position at a time**. It cycles the payload through each marked position individually, leaving the others at their original value.
- Requests = (number of positions) × (payloads in set).
- Use for: testing each parameter separately, single-field fuzzing, single-field brute force.

**Battering ram** — *one* payload set, but the **same payload placed in ALL positions simultaneously**.
- Requests = (payloads in set).
- Use for: when the same value must appear in multiple places at once (e.g., a token repeated in header and body).

**Pitchfork** — *multiple* payload sets (one per position), iterated **in parallel like a zip**: 1st of set A with 1st of set B, 2nd with 2nd, etc.
- Requests = length of the **smallest** set.
- Use for: **correlated** pairs — e.g., a list of known username→password combos you want to try as pairs, not all combinations.

**Cluster bomb** — *multiple* payload sets, tries **every combination** (Cartesian product).
- Requests = (set A size) × (set B size) × …
- Use for: **credential brute force** — every username against every password. This grows fast: 100 usernames × 1000 passwords = 100,000 requests.

> Mnemonic: **Sniper** = one bullet, one spot at a time. **Battering ram** = one big value smashing all spots. **Pitchfork** = parallel forks moving together. **Cluster bomb** = everything explodes against everything.

### 9.3 Reading results — how you spot the finding

Intruder shows a results table: one row per request, with **Status**, **Length**, **Response received (time)**, and any **Grep-Match** columns you configured. **The finding is almost always the outlier.** You sort or scan for the row that differs.

**Worked example — username enumeration (Sniper):**

Many login forms leak which usernames exist by responding differently. Suppose failed logins return `"Invalid username"` (length 3521) but a *valid* username with wrong password returns `"Invalid password"` (length 3547). Run Sniper over a username wordlist against the username position with a fixed dummy password:

```
 Payload        Status   Length
 admin          200      3521
 root           200      3521
 jsmith         200      3547   <-- outlier: valid username
 test           200      3521
 support        200      3547   <-- outlier: valid username
```

The length difference (or a Grep-Match on the string `Invalid password`) reveals valid usernames — you never saw the "secret," you *inferred* it from a response difference. This inference-from-difference is the beating heart of most discovery.

**Worked example — credential brute force (Cluster bomb):**

Two positions (username, password), two payload sets. A successful login often changes the response: a `302` redirect to `/dashboard`, a new `Set-Cookie`, or a length jump.

```
 user     pass        Status   Length
 admin    123456      200      3521
 admin    password    200      3521
 admin    Summer2024  302      182     <-- success: redirect + short body
```

Configure a **Grep-Match** for `Set-Cookie` or filter for `302` and the winner pops out.

### 9.4 Grep-Match, Grep-Extract, and options

- **Grep-Match**: flag responses containing a given string (adds a true/false column). Great for "success"/"error" markers.
- **Grep-Extract**: pull a value *out* of each response into a column (e.g., extract a CSRF token, a balance, an error detail). Essential for multi-step attacks.
- **Resource pool / throttling**: controls concurrency and delay between requests — to avoid rate limits, lockouts, or DoS. (Community throttles you here automatically.)
- **Payload processing / encoding**: transform payloads (base64, URL-encode, add prefix/suffix, hash, match/replace) before sending.

### 9.5 What Intruder is really for

Any time the answer is "send this same request but vary one or two things and watch for the odd one out," Intruder is the tool: fuzzing parameters for injection, brute-forcing credentials/PINs/tokens, enumerating IDs or usernames, testing many payloads for XSS/SQLi/path traversal, or harvesting values across a range.

---

## 10. Decoder, Inspector, and Comparer

### 10.1 Decoder

A manual **encode/decode/hash** workbench. Web apps constantly wrap data in encodings; to tamper intelligently you must decode, edit, and re-encode. Decoder handles:

- **URL** encoding (`%20` ↔ space) — how data travels in URLs and form bodies.
- **HTML** entities (`&lt;` ↔ `<`) — relevant to XSS.
- **Base64** — ubiquitous for tokens, Basic auth, and binary-in-text. (Base64 is *encoding, not encryption* — trivially reversible.)
- **ASCII hex**, **octal**, **binary**, **Gzip**.
- **Hashing**: MD5, SHA family, etc.
- **Smart decode**: Burp guesses the encoding and unwraps layered encodings automatically.

**Example:** a cookie `dXNlcj1hZG1pbg==` looks random. Paste into Decoder → Base64 decode → `user=admin`. Now you understand it, can tamper it (`user=root`), re-encode, and test. What looked opaque was just Base64.

### 10.2 Inspector

Modern Burp embeds an **Inspector** side-panel in Proxy/Repeater that auto-parses a request into its components — query params, cookies, headers, body params — and **auto-decodes** them, letting you edit each as a clean key/value and having Burp re-encode correctly. It's Decoder's convenience baked into the request editor, so you rarely mangle encoding by hand.

### 10.3 Comparer

A **visual diff** tool. Send two requests or two responses to Comparer and it highlights byte- or word-level differences. Uses:

- Compare a "valid username" response vs an "invalid username" response to find the exact leak (the enumeration signal from §9.3).
- Compare an authorized vs unauthorized response to see what access control actually changes.
- Compare two tokens to see which bytes vary (a lead into predictability).

Comparer turns "these look kind of different" into "these differ in exactly these bytes," which is what you need for precise reporting.

---

## 11. Sequencer — Testing Randomness of Tokens

**Sequencer** analyzes the **randomness (entropy)** of tokens the application issues — session IDs, anti-CSRF tokens, password-reset tokens, API keys. This answers a critical security question: *can an attacker predict or guess these?*

### The concept

Session tokens are the keys to accounts. If a token is predictable (sequential, timestamp-based, weakly random), an attacker can forge a valid one and hijack a session without ever knowing the password. "Looks random to a human" is worthless — humans are terrible at judging randomness. You need **statistical** analysis.

### How Sequencer works

1. Point it at a request whose response sets a token (e.g., a login that returns `Set-Cookie: session=...`). Tell Burp which token to capture.
2. Sequencer **live-captures** the token repeatedly — hundreds to thousands of samples (≥100 to start, ideally 20,000+ for confidence).
3. It runs a battery of **statistical randomness tests**, many derived from the **FIPS 140-2** standard, at both **bit level** and **character level**:
   - **Monobit test** — are 0s and 1s roughly balanced?
   - **Poker test** — do fixed-size groups appear with expected frequency?
   - **Runs test** — are runs of identical bits distributed as randomness predicts?
   - **Long runs test** — any improbably long streak?
   - Plus **FIPS spectral**, **correlation**, and **compression** analyses.
4. It reports **effective entropy** in **bits** at a given significance level.

### Reading the output

Sequencer reports something like *"effective entropy: 118 bits"* with per-bit charts. Interpretation:

- **High entropy** (e.g., >100+ bits, near the token's full length): the token is effectively unpredictable — good.
- **Low entropy** (e.g., a 128-bit token showing only ~20 bits effective): most of the token is predictable/static; only a small part actually varies. An attacker's search space is far smaller than it looks — potentially brute-forceable or predictable. **This is the finding.**

The insight: a long token is not automatically strong. Sequencer measures how much of it is *genuinely* unpredictable. Discovering that a "random-looking" 32-char session ID has only ~24 bits of real entropy is a serious, statistically-backed vulnerability.

---

## 12. Scanner — Automated Vulnerability Discovery (Pro)

The **Scanner** (Professional/Enterprise only) automates discovery of many vulnerability classes. It has two phases: **Crawl** and **Audit**.

### 12.1 Crawl vs Audit

- **Crawl**: Burp navigates the app like a user — following links, submitting forms, executing some JavaScript — to **discover content** and build a complete site map. It's asking *"what endpoints and parameters exist?"*
- **Audit**: for each discovered location, Burp **sends crafted test requests** to find vulnerabilities. It's asking *"is this endpoint exploitable?"*

You can run "Crawl only," "Crawl and audit," or audit a specific selection.

### 12.2 Passive vs Active scanning — the key distinction

**Passive scanning** analyzes traffic that *already flowed* — it sends **no extra requests**. It can only spot things visible in existing request/response pairs:

- Missing security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`).
- Cookies missing `HttpOnly`/`Secure`/`SameSite`.
- Reflected input (input echoed into the response — a *candidate* for XSS).
- Information disclosure (stack traces, server versions, comments, internal IPs).
- Insecure form actions, cacheable sensitive content.

Passive is **safe and silent** — you can leave it on all the time. It never changes app state.

**Active scanning** *sends new, crafted probe requests* to confirm vulnerabilities by observing how the app reacts. It's what actually detects SQLi, XSS, command injection, etc. Active is **intrusive**: it can submit forms, trigger emails, create records, or cause errors. Never point it at production without authorization and care.

### 12.3 How active scanning "discovers" — the underlying logic

Burp's Scanner is essentially an automated version of the hypothesis loop, per vulnerability class:

1. **Identify insertion points** — every parameter, header, cookie, JSON field, path segment where attacker input enters.
2. **Send probes** — inject class-specific payloads.
3. **Analyze the reaction** — status change, error signature, reflected payload, time delay, or out-of-band interaction (via Collaborator).
4. **Confirm and reduce false positives** — often by sending a *pair* of probes (e.g., a "true" and a "false" condition) and checking the responses differ as predicted.

The detailed per-vuln logic is in §14 — that's the "concepts behind the discoveries" you asked for.

---

## 13. Burp Collaborator — Out-of-Band Detection (The Big Concept)

This is one of the most important advanced ideas in the whole tool, so read slowly.

### The problem: blind vulnerabilities

Many serious bugs produce **no visible change in the HTTP response**. If you inject a command and the output never comes back to you, how do you know it ran? If a server is tricked into making a request, but the result isn't shown to you, how do you detect it? These are **blind** / **out-of-band (OOB)** vulnerabilities, and response-watching alone can't find them.

### The idea: make the target phone home to a server you control

**Burp Collaborator** is a dedicated external server (run by PortSwigger by default at `oastify.com`; you can self-host) that provides **DNS, HTTP, and SMTP** services. The workflow:

1. Burp generates a **unique subdomain**, e.g. `abc123xyz.oastify.com`, and embeds it in a payload.
2. You deliver that payload to the target (in a parameter, header, XML entity, hostname, email field, etc.).
3. **If the target is vulnerable**, it will *interact* with that subdomain — do a **DNS lookup** for it, make an **HTTP request** to it, or send it an **email**.
4. Burp **polls the Collaborator server**, sees the interaction, and correlates the unique subdomain back to the exact payload/insertion point that caused it.

An interaction arriving = **proof the injection executed**, even though the app's own response told you nothing. The target quite literally reaches out and rings a bell only you can hear.

### What it unlocks

- **Blind SSRF** — server fetches your Collaborator URL → HTTP interaction appears.
- **Blind OS command injection** — inject `nslookup abc123.oastify.com` → DNS interaction appears.
- **Blind XXE** — external entity points at your Collaborator → HTTP/DNS interaction appears.
- **Blind SQL injection** — DB triggers a DNS lookup to your subdomain → interaction appears.
- **Email/SMTP** injection and asynchronous processing bugs.

### Why the DNS layer is gold

Even in locked-down networks that block outbound HTTP, **DNS resolution often still works** (it's needed for basic operation). So a payload that triggers merely a DNS *lookup* of your subdomain can reveal a vulnerability in an environment where a full HTTP callback would be firewalled. Collaborator captures DNS-only interactions, which is why it's so powerful.

> Collaborator is Pro-only. Without it, blind bugs must be confirmed with your own external listener (e.g., a VPS running a DNS/HTTP logger, or a public OOB service) — the same concept, more manual.

---

## 14. The Concepts Behind the Discoveries (Vuln-by-Vuln)

This section explains *how* Burp (and you, manually) actually detect each major web vulnerability — the reasoning, not just the payload. This is where tool knowledge becomes real understanding.

### 14.1 SQL Injection (SQLi)

**What it is:** user input is concatenated into a database query, letting an attacker alter the query's logic.

**How it's discovered — three signal channels:**

- **Error-based:** inject a `'` (single quote) to break the SQL string. If the app returns a database error (`You have an error in your SQL syntax...`), the input reaches the query unsanitized. The *error message itself* is the signal. Burp's passive/active scan flags these signatures.
- **Boolean-based blind:** no errors shown, but the page differs for true vs false conditions. Send `id=1 AND 1=1` (true) → normal page; `id=1 AND 1=2` (false) → different/empty page. **The difference between the two responses is the proof.** You're extracting one bit of information per request (Comparer helps see the difference; Intruder + Grep-Match automates it).
- **Time-based blind:** no visible difference at all. Inject `id=1; IF(1=1, SLEEP(5), 0)` (syntax varies by DB). If the response takes ~5 seconds *only when the condition is true*, you've confirmed injection **by timing**. Burp measures response time per request — that's the signal.
- **Out-of-band (OOB):** force the DB to do a DNS lookup to your Collaborator subdomain. An interaction confirms injection even with no response difference *and* no measurable delay.

**The core concept:** SQLi detection is about finding a **channel** — an error string, a response difference, a time delay, or an OOB interaction — that leaks whether your injected condition was true. Each channel is a fallback for when the previous one is unavailable.

### 14.2 Cross-Site Scripting (XSS)

**What it is:** attacker-controlled input is rendered in a victim's browser as executable HTML/JavaScript.

**How it's discovered:**

1. **Reflection tracking:** Burp inserts a unique, harmless marker (e.g., `burpXYZ123`) into each input and checks whether it appears in the response. If it does, that input is *reflected* — a candidate.
2. **Context analysis:** *where* does it land? Inside an HTML tag body? An attribute value? A `<script>` block? A URL? The context dictates which characters must be "escaped" to break out (`<`, `>`, `"`, `'`, backtick).
3. **Payload confirmation:** Burp sends context-appropriate payloads and checks whether the special characters survive **unescaped** in the response. If `<` comes back as `<` (not `&lt;`), you can inject tags → likely XSS.

**Types:**
- **Reflected:** payload in the request is echoed straight back in that response.
- **Stored:** payload is saved (comment, profile) and served to other users later — higher impact.
- **DOM-based:** the vulnerability is entirely in client-side JavaScript reading a source (e.g., `location.hash`) and writing it to a dangerous sink (e.g., `innerHTML`). No server round-trip changes — Burp's DOM/JS analysis and browser-driven scanning are needed here.

**The core concept:** XSS detection = **reflection + failure to encode dangerous characters in the specific output context.** Encoding is the defense; the discovery is proving the encoding is absent or bypassable.

### 14.3 Server-Side Request Forgery (SSRF)

**What it is:** the server can be tricked into making HTTP requests to a destination the attacker chooses (internal services, cloud metadata endpoints).

**How it's discovered:** find a parameter that takes a URL/host (image fetchers, webhooks, PDF generators, URL previews). Point it at:
- Something you control (**Collaborator**) → an interaction confirms the server made the request (works even when the response is hidden = **blind SSRF**).
- Internal targets (`http://169.254.169.254/` cloud metadata, `http://localhost/admin`) → differences in response reveal internal reachability.

**The core concept:** you're testing whether *the server's* network position can be borrowed. The OOB interaction is the clean proof.

### 14.4 XML External Entity (XXE)

**What it is:** an XML parser processes attacker-defined external entities, enabling file reads or SSRF.

**How it's discovered:** in XML input, define an external entity pointing at a local file (`file:///etc/passwd`) or a URL. If file contents appear in the response → **in-band XXE**. If nothing appears but the entity points at **Collaborator** and an interaction fires → **blind XXE** confirmed out-of-band.

**The core concept:** XXE detection leans heavily on OOB because responses are often blind — the parser fetches your entity URL and Collaborator catches it.

### 14.5 OS Command Injection

**What it is:** user input is passed into a system shell command.

**How it's discovered:**
- **In-band:** inject `; whoami` or `| id` and look for command output in the response.
- **Blind time-based:** inject `& ping -c 10 127.0.0.1 &` or `; sleep 10` — a delayed response proves execution.
- **Blind OOB:** inject `; nslookup abc123.oastify.com` — a DNS interaction at Collaborator proves execution with no output and no timing needed.

**The core concept:** identical to blind SQLi — find a channel (output, timing, OOB) that betrays that your command ran.

### 14.6 Path / Directory Traversal

**What it is:** manipulating a file-path parameter to escape the intended directory (`../../../../etc/passwd`).

**How it's discovered:** feed `../` sequences (and encoded variants: `%2e%2e%2f`, double-encoding, `....//`) into file parameters; a response containing `root:x:0:0:` (the shape of `/etc/passwd`) confirms it. Intruder is ideal for spraying encoding variants to defeat naive filters.

### 14.7 Broken Access Control / IDOR

**What it is:** the server fails to verify that the authenticated user is *allowed* to perform the action or view the object.

**How it's discovered — the concept:** this is **logic**, not a payload, so scanners struggle and *you* shine. The method: take an authenticated request and **replay it as a different (or no) user**, or **change an object identifier**, and check whether access is still granted.
- **Horizontal:** change `id=1005` → `1006` (another peer's data). (The Repeater IDOR example in §8.)
- **Vertical:** take an admin-only request and resend it with a low-privilege user's session — if it still works, privilege boundaries are broken.
- **Tooling:** extensions like **Autorize** automate this by replaying every request with a low-priv session and flagging any that *still* succeed. The concept: **compare the same action across privilege levels; any success that shouldn't happen is the bug.**

### 14.8 Cross-Site Request Forgery (CSRF)

**What it is:** a malicious site causes a victim's browser to submit a state-changing request to a site where they're authenticated, abusing automatic cookie attachment.

**How it's discovered:** find a state-changing request (change email, transfer funds) and check whether it's protected by an **unpredictable anti-CSRF token** and/or `SameSite` cookies. If not, Burp Pro's **"Generate CSRF PoC"** builds an HTML page that auto-submits the forged request — proof of exploitability. The concept: **does the server rely only on the cookie (which browsers send automatically) to authorize a change?** If yes, it's forgeable.

### 14.9 Insecure Deserialization

**What it is:** the app deserializes attacker-controlled serialized objects (Java, PHP, .NET, Python pickle), enabling logic abuse or remote code execution via "gadget chains."

**How it's discovered:** spot serialized blobs (Java `rO0AB...` Base64, PHP `O:4:...`). Tamper them; use the **Java Deserialization Scanner** / **Hackvertor** extensions and tools like `ysoserial` to generate gadget payloads, often confirmed via Collaborator (OOB). Concept: **untrusted bytes become live objects** — control the bytes, influence execution.

### 14.10 Race Conditions

**What it is:** sending requests so close together that they hit a "window" between a check and an action (e.g., redeem a one-time coupon twice, overdraw a balance).

**How it's discovered:** fire many identical requests **simultaneously** and check for anomalous outcomes (coupon applied twice). Timing jitter used to make this unreliable; the **single-packet attack** (see §17) removes jitter and makes race testing precise. Concept: **exploit the gap between validation and state change by removing the time between requests.**

### 14.11 HTTP Request Smuggling

Covered in depth in §18 — it exploits disagreement between two servers about where one request ends and the next begins.

---

## 15. Advanced Workflows: Match/Replace, Macros, Session Handling

These features solve a very real problem: **automation breaks authentication.** When Intruder or Scanner fires hundreds of requests, your session may expire, or each request may need a fresh anti-CSRF token. Session handling rules and macros keep automation authenticated.

### 15.1 Macros

A **macro** is a saved sequence of one or more requests that Burp can replay automatically. Two classic uses:

- **Re-login:** a macro that submits credentials to `/login`, capturing the new session cookie.
- **Fetch-then-use a token:** a macro that GETs a page, **extracts** the anti-CSRF token from the response, so it can be injected into the next real request.

### 15.2 Session handling rules

A **session handling rule** defines actions Burp performs **around** requests made by chosen tools (Scanner, Intruder, Repeater), scoped to chosen URLs. Typical rule:

1. **Run a macro** before each request (e.g., ensure logged in / grab a fresh CSRF token).
2. **Check session validity** — if a response looks logged-out, run the login macro and retry.
3. **Use cookies from Burp's cookie jar** so fresh cookies propagate.

**Worked scenario — scanning a CSRF-protected app:** every POST needs a one-time `csrf_token` that changes per request. Without help, Intruder's second request fails (stale token). Solution: a macro that GETs the form page and **Grep-Extracts** the fresh `csrf_token`; a session-handling rule that runs this macro before each Intruder request and substitutes the extracted token into the outgoing request. Now automation stays valid across hundreds of requests. This is one of the most powerful — and most misunderstood — features in Burp.

### 15.3 Match and replace (recap as workflow)

Covered in §7.4 — combine it with the above to, e.g., strip caching headers, inject test headers globally, or normalize requests before they hit Scanner.

---

## 16. Extensions and the BApp Store

Burp is extensible via the **BApp Store** (`Extensions → BApp Store`) and custom extensions written against the **Montoya API** (modern Java API; older ones used the "Extender" API, plus Python via Jython and Ruby via JRuby).

**Extensions every tester should know:**

- **Autorize** — automated access-control/IDOR testing: replays each request with a low-priv session and flags anything that still succeeds.
- **Logger++** — advanced, filterable logging across all Burp tools.
- **Turbo Intruder** — extremely fast, scriptable request sending; enables the single-packet attack (§17).
- **HTTP Request Smuggler** — automated smuggling detection (§18).
- **Param Miner** — brute-forces hidden/unlinked parameters and headers (guessing param names the app secretly honors) and finds web cache poisoning vectors.
- **Hackvertor** — inline tag-based encoding/encryption/transformation of payloads.
- **JSON Web Tokens (JWT)** / **JWT Editor** — inspect and attack JWTs (alg confusion, `none` alg, weak-key cracking).
- **Active Scan++**, **Java Deserialization Scanner**, **Collaborator Everywhere**, **Retire.js** (vulnerable JS libs), **Software Vulnerability Scanner**.

**Why extend:** the Montoya API lets you hook into request/response processing, add scanner checks, build custom tabs, and automate bespoke workflows — turning Burp from a tool into a platform tailored to a specific target.

---

## 17. Turbo Intruder and the Single-Packet Attack

**Turbo Intruder** is an extension for sending huge numbers of requests very fast, driven by a small **Python script** you write — giving precise control over concurrency, connection reuse, and timing that the standard Intruder can't match.

### The single-packet attack (advanced race conditions)

Discovered by PortSwigger's James Kettle, this technique defeats network **jitter** — the tiny, variable delays that used to make race-condition testing unreliable. The idea:

- Using **HTTP/2**, you can place **many requests inside a single TCP packet**, so the server receives them essentially **simultaneously**, eliminating the timing differences between them.
- This makes the "window" between check and action exploitable with high reliability.

It's implemented in **Turbo Intruder** and, more accessibly, in Repeater via **"Send group in parallel"** (add requests to a group, choose parallel send). Concept recap: to win a race you must remove *all* time between the competing requests — the single-packet attack does exactly that.

---

## 18. HTTP Request Smuggling with Burp

**What it is:** front-end and back-end servers (e.g., a proxy/CDN in front of an app server) can **disagree about where one HTTP request ends and the next begins**. An attacker exploits this to "smuggle" part of a request so it prepends to the *next* user's request — enabling request hijacking, cache poisoning, and auth bypass.

### The mechanism

Two headers can define body length: **`Content-Length` (CL)** and **`Transfer-Encoding: chunked` (TE)**. If the front-end uses one and the back-end uses the other, their boundaries diverge. Classic variants:

- **CL.TE** — front-end honors `Content-Length`, back-end honors `Transfer-Encoding`.
- **TE.CL** — the reverse.
- **TE.TE** — both support TE, but one can be tricked into ignoring it via an obfuscated header.
- **H2.CL / H2.TE** — downgrade issues when HTTP/2 is translated to HTTP/1.1 downstream.

The smuggled bytes sit in the back-end's buffer and get glued to the front of the **next** request that arrives — which may belong to another user.

### How Burp discovers it

The **HTTP Request Smuggler** extension automates detection by sending crafted CL/TE-conflicting requests and measuring **timing** and **response** differences that indicate desync. Because a successful desync often produces a **delay** (the back-end waits for bytes that never come) or a **captured** subsequent request, those are the signals. Burp Repeater's ability to send raw, non-normalized requests (disable "update Content-Length," control exact `\r\n`) is essential for crafting these by hand.

**The core concept:** the vulnerability is an **ambiguity in parsing** between two machines. You exploit the seam where they disagree.

---

## 19. Command-Line, Headless, and REST API

Burp is GUI-first, but supports automation:

- **Launch with a bigger heap** (Burp is Java; large scans need memory):
  ```bash
  java -jar -Xmx4g burpsuite_pro.jar
  ```
- **Open a project / config at start:**
  ```bash
  java -jar burpsuite_pro.jar --project-file=engagement.burp --config-file=myconfig.json
  ```
- **Headless / unattended (CI):** run without the UI for pipeline scans:
  ```bash
  java -jar -Djava.awt.headless=true burpsuite_pro.jar
  ```
- **Disable extensions on launch** (troubleshooting): `--disable-extensions`.
- **REST API (Pro):** Burp exposes a local REST API (enable under `Settings → Suite → REST API`) to start scans and pull results programmatically — the basis for lightweight CI integration. **Enterprise** is the proper product for large-scale automated/scheduled scanning across many sites with a web dashboard.

> Config files (`.json`) let you save and share scan configurations, scope, and session-handling setups across a team — important for repeatable engagements.

---

## 20. Keyboard Shortcuts and Efficiency

| Action | Shortcut |
|---|---|
| Send to Repeater | `Ctrl + R` |
| Send to Intruder | `Ctrl + I` |
| Send request (in Repeater) | `Ctrl + Space` |
| Forward intercepted request | `Ctrl + F` |
| Toggle intercept on/off | `Ctrl + T` |
| URL-encode selection | `Ctrl + U` |
| Base64-encode selection | `Ctrl + B` |
| Cut / Copy / Paste | `Ctrl + X/C/V` |
| Search within message | `Ctrl + S` (or the search bar) |

Efficiency habits: keep intercept **off**, work primarily from **HTTP history → Repeater**, tighten **scope** immediately, name your Repeater tabs, and use the **Inspector** panel to edit params without breaking encoding.

---

## 21. Pitfalls, Evasion, and Good Practice

**Common beginner pitfalls**
- **"The browser froze."** Intercept is on and a request is paused. Turn intercept off or forward it.
- **HTTPS cert errors.** Burp CA not installed/trusted in that browser. Reinstall from `http://burp`.
- **Empty HTTP history.** Browser isn't routed through Burp, or wrong port.
- **Broke a request by hand-editing.** You changed the body but not `Content-Length` (or mangled encoding). Let Burp update `Content-Length` automatically, or use Inspector.
- **Active-scanning out of scope.** Set scope *first*; restrict Scanner/Intruder to it.
- **Account lockouts during brute force.** Throttle Intruder via resource pools; watch for lockout thresholds.

**Evasion / WAF considerations (authorized testing only)**
- **Encoding variants** to slip past filters: URL-encode, double-encode, mixed case, HTML entities, unicode. Intruder payload-processing + Hackvertor automate generating these.
- **Header tricks** (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`) to test access-control and routing bypasses.
- **Rate/pacing control** to avoid tripping WAF rate rules.
- **Null bytes, comment injection, alternate content-types** where parsers disagree.

**Good practice**
- Save projects (Pro) frequently; scans and history live in the project file.
- Keep passive scanning on always; be deliberate with active scanning.
- Document as you go — Burp Pro's **Organizer** lets you shelve requests-of-interest; annotate history rows with colors/notes.
- Remove Burp's CA from trust stores when you're done on a shared/temporary machine.

---

## 22. Legal and Ethical Note

Burp Suite is a powerful offensive tool. Everything above is for **authorized** security testing only:

- Only test systems you **own** or have **explicit written permission** to test (a signed scope/rules-of-engagement, a bug bounty program's scope, or your own lab).
- Practice safely and legally on intentionally vulnerable targets: **PortSwigger Web Security Academy** (free, made by Burp's authors — the single best place to learn these concepts hands-on), **OWASP Juice Shop**, **DVWA**, **bWAPP**, and deliberately vulnerable VMs.
- Unauthorized testing — even "just looking" — can be a criminal offense. Scope discipline isn't just tidiness; it's what keeps testing lawful.

---

### Where to go next

- Work through the **PortSwigger Web Security Academy** labs *while* re-reading §14 — each vulnerability class there maps directly to the concepts above, and the labs force you to use Repeater, Intruder, and Collaborator for real.
- Rebuild each discovery **manually in Repeater** before trusting the Scanner. The Scanner is fast; understanding is durable.

*End of reference.*

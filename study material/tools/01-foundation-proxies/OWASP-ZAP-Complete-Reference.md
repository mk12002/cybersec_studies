# ZAP (Zed Attack Proxy) — The Complete Reference (Beginner → Advanced)

> A ground-up reference for web application penetration testing with **ZAP** (formerly *OWASP ZAP*, now *ZAP by Checkmarx*).
> Structured to parallel the Burp Suite reference so you can map concepts between the two tools.
> Every module, every concept, and **why** each discovery technique works.

---

## Table of Contents

1. [What ZAP Is and Why It Exists](#1-what-zap-is-and-why-it-exists)
2. [A Note on Naming and Governance (OWASP → Checkmarx)](#2-a-note-on-naming-and-governance-owasp--checkmarx)
3. [Prerequisite Concepts (HTTP, TLS) — Quick Recap](#3-prerequisite-concepts-http-tls--quick-recap)
4. [The Core Idea: Intercepting Proxy + ZAP's Dynamic SSL CA](#4-the-core-idea-intercepting-proxy--zaps-dynamic-ssl-ca)
5. [ZAP vs Burp — The Mental Mapping](#5-zap-vs-burp--the-mental-mapping)
6. [Installing ZAP and the UI Layout](#6-installing-zap-and-the-ui-layout)
7. [ZAP Modes: Safe, Protected, Standard, ATTACK](#7-zap-modes-safe-protected-standard-attack)
8. [First-Time Setup (Proxy, CA, Browser, HUD)](#8-first-time-setup-proxy-ca-browser-hud)
9. [Contexts, Sessions, and Scope](#9-contexts-sessions-and-scope)
10. [Sites Tree, History, and Search](#10-sites-tree-history-and-search)
11. [Crawling: The Spider and the AJAX Spider](#11-crawling-the-spider-and-the-ajax-spider)
12. [Passive Scanning](#12-passive-scanning)
13. [Active Scanning: Policies, Thresholds, Attack Strength](#13-active-scanning-policies-thresholds-attack-strength)
14. [Alerts: Risk and Confidence](#14-alerts-risk-and-confidence)
15. [Manual Request Editor, Requester, and Breakpoints](#15-manual-request-editor-requester-and-breakpoints)
16. [The Fuzzer (ZAP's Intruder)](#16-the-fuzzer-zaps-intruder)
17. [Encode/Decode/Hash and Compare](#17-encodedecodehash-and-compare)
18. [The HUD (Heads-Up Display)](#18-the-hud-heads-up-display)
19. [Authentication Handling (Contexts, Users, Session Management)](#19-authentication-handling-contexts-users-session-management)
20. [OAST — Out-of-Band Detection (ZAP's Collaborator)](#20-oast--out-of-band-detection-zaps-collaborator)
21. [The Concepts Behind the Discoveries (Vuln-by-Vuln)](#21-the-concepts-behind-the-discoveries-vuln-by-vuln)
22. [The Add-on Marketplace](#22-the-add-on-marketplace)
23. [The Scripting Engine](#23-the-scripting-engine)
24. [The Automation Framework (YAML)](#24-the-automation-framework-yaml)
25. [API, Daemon Mode, and CLI Options](#25-api-daemon-mode-and-cli-options)
26. [Docker Packaged Scans (Baseline / Full / API)](#26-docker-packaged-scans-baseline--full--api)
27. [Pitfalls, Evasion, and Good Practice](#27-pitfalls-evasion-and-good-practice)
28. [Legal and Ethical Note](#28-legal-and-ethical-note)

---

## 1. What ZAP Is and Why It Exists

**ZAP (Zed Attack Proxy)** is a free, open-source **DAST** tool — a **Dynamic Application Security Testing** scanner. "Dynamic" means it tests a **running** application from the outside (like a real attacker), as opposed to **SAST** (static analysis), which reads source code. ZAP finds vulnerabilities by sending real HTTP traffic to a live app and analyzing the responses.

At its core, ZAP is the same kind of tool as Burp Suite: an **intercepting proxy** that sits between your browser and the target so you can see, modify, replay, and automatically attack the traffic. The problem it solves is identical to Burp's — the security-relevant action happens in the invisible HTTP layer, and you need to get in the middle of it.

**Why ZAP specifically:**

- **Completely free and open-source** (Apache License 2.0), with **no paid tier and no feature gating**. The full active scanner, fuzzer, and automation are all free — unlike Burp, where the Scanner and Collaborator require Professional.
- **Automation-first heritage.** ZAP was built with CI/CD in mind: a YAML **Automation Framework**, official **Docker images**, **GitHub Actions**, and a full **REST API**. It's the default choice for "shift-left" automated security testing in pipelines.
- **Extensible** via a large **Marketplace** of add-ons and a built-in **scripting engine**.
- **Cross-platform** (Java-based: Windows, macOS, Linux).

**Where it fits in a pentest** is the same five-stage flow as any web test: map → analyze → probe → exploit/prove → report. ZAP covers all five, and is especially strong at the "run it automatically in a pipeline" use case.

---

## 2. A Note on Naming and Governance (OWASP → Checkmarx)

You called it "OWASP ZAP" — that name is now historical, and it's worth knowing why:

- ZAP began as an OWASP **flagship project**.
- In **2023** the project **left OWASP** (moving under the Linux Foundation's Software Security Project) to secure sustainable funding.
- In **2024**, the core maintainers (Simon Bennetts, Rick Mitchell, Ricardo Pereira) joined **Checkmarx**, and the project was rebranded **"ZAP by Checkmarx."**
- It **remains free, open-source, community-driven, and Apache 2.0 licensed.** Governance and funding changed; the tool's openness did not.

**Practical implications:**
- Prefer the name **"ZAP"** (or "ZAP by Checkmarx"); "OWASP ZAP" can wrongly imply OWASP still governs it.
- **Old Docker image paths changed.** Legacy tutorials reference `owasp/zap2docker-stable` — those are deprecated. Current images live under the ZAP/Checkmarx org (e.g., `ghcr.io/zaproxy/...` / `zaproxy/zap-stable`). If a Docker example fails, an outdated image path is a likely cause.
- The latest stable release line as of early 2026 is **ZAP 2.17.x**.

---

## 3. Prerequisite Concepts (HTTP, TLS) — Quick Recap

Everything from the Burp reference's HTTP/TLS section applies unchanged — ZAP manipulates the exact same HTTP requests and responses. In brief:

- A **request** = request line (`METHOD path HTTP/version`) + headers + blank line + body.
- A **response** = status line (`HTTP/version code reason`) + headers + blank line + body.
- The four signals you hunt for in *any* proxy tool: **status code, response length, timing, and out-of-band interaction.** A discovery is almost always "my changed request produced a meaningfully different response."
- **HTTPS** is HTTP inside TLS. TLS verifies the server's certificate against trusted CAs, which blocks a man-in-the-middle — the exact problem ZAP must solve to read encrypted traffic (§4).

If you haven't internalized HTTP structure yet, do that first — it's the substrate both tools operate on.

---

## 4. The Core Idea: Intercepting Proxy + ZAP's Dynamic SSL CA

ZAP works exactly like Burp's proxy: you route your browser through ZAP (default **`localhost:8080`**), and every request/response passes through it to be inspected, logged, modified, and probed.

### TLS interception in ZAP

The mechanism is the same MITM-with-consent trick as Burp:

1. ZAP generates its own **Dynamic SSL Root CA certificate** (unique to your install).
2. You **install/trust that CA** in your browser or OS trust store.
3. When your browser makes an HTTPS request through ZAP, ZAP **mints a per-site certificate on the fly**, signs it with its own root CA, and presents it. Because you trust ZAP's root, the browser accepts it. ZAP makes its own real TLS connection to the actual server.

The result: two TLS legs (browser↔ZAP, ZAP↔server) with ZAP decrypting in the middle so you see plaintext. In ZAP this is configured under **Options → Dynamic SSL Certificates**, where you **generate**, **save/export**, and **import** the root CA.

> **Same security caution as Burp:** the ZAP root CA can silently intercept anything that trusts it. Keep it to machines you control and remove it when you're done on shared/temporary systems.

---

## 5. ZAP vs Burp — The Mental Mapping

Since you just learned Burp, this table is the fastest way to become productive in ZAP. The *concepts* are identical; the names and workflow differ.

| Concept / task | Burp Suite | ZAP |
|---|---|---|
| Intercepting proxy | Proxy | Proxy (built in) |
| Traffic log | HTTP history | **History** tab |
| Site structure | Target → Site map | **Sites** tree |
| Replay/edit one request | **Repeater** | **Manual Request Editor / Requester** |
| Intercept & edit live | Intercept (global toggle) | **Breakpoints** (set specifically, or break-all) |
| Automated custom attack / fuzzing | **Intruder** (Sniper/Cluster bomb…) | **Fuzzer** (fuzz locations + payloads) |
| Automated vuln scan | **Scanner** (Pro only) | **Active Scan** (free) |
| Passive analysis | Passive scan (Pro) | **Passive Scan** (free, always on) |
| Token randomness | Sequencer | *(no direct equivalent; add-ons/scripts)* |
| Encode/decode | Decoder / Inspector | **Encode/Decode/Hash** dialog |
| Diff | Comparer | **Compare** (via add-on/right-click) |
| Out-of-band detection | **Collaborator** (Pro) | **OAST** add-on (interactsh/BOAST/callback) |
| Scope | Target scope | **Contexts** + "in scope" |
| Auth persistence for automation | Session handling rules + macros | **Context authentication + users + session management** |
| Extensions | BApp Store (Montoya API) | **Marketplace** add-ons + **Scripts** |
| Automation/CI | REST API (Pro) / Enterprise | **Automation Framework (YAML)** + API + Docker |
| In-browser control overlay | *(none)* | **HUD** (unique to ZAP) |

**The single biggest philosophical difference:** ZAP's full scanner and fuzzer are **free**, and ZAP is **built for automation** (YAML/Docker/API). Burp's manual tooling (Repeater/Intruder ergonomics) is often considered smoother for **hands-on** testing, and its Pro Scanner + Collaborator are best-in-class. Many testers use **both**.

---

## 6. Installing ZAP and the UI Layout

**Install options:** native installers (Windows/macOS/Linux), a cross-platform Java package, a Linux package, or **Docker**. ZAP requires a **Java runtime** (bundled in most installers). It's also pre-installed in **Kali Linux**.

**The desktop UI has three main regions:**

1. **Tree window (left):** the **Sites** tree (a hierarchical map of everything ZAP has seen) and the **Scripts** tree.
2. **Workspace window (top-right):** the **Request** and **Response** editors, plus the **Quick Start** tab (a beginner-friendly "enter a URL and attack" launcher).
3. **Information window (bottom):** tabbed panels — **History**, **Search**, **Alerts**, **Output**, **Active Scan**, **Spider**, **Fuzzer**, **AJAX Spider**, **Automation**, etc. This is where results stream in.

**Footer:** shows counts of **alerts by risk level** (red/orange/yellow/blue flags) and current proxy status.

The **Quick Start** tab is the gentlest on-ramp: paste a URL, click **Attack**, and ZAP spiders + passively + actively scans automatically. Great for a first look; graduate to manual control quickly for real testing.

---

## 7. ZAP Modes: Safe, Protected, Standard, ATTACK

ZAP has a **mode selector** (top-left dropdown) with no Burp equivalent. It's a safety governor that constrains what ZAP is allowed to do:

- **Safe mode** — **all potentially dangerous operations are disabled.** No active scan, no fuzzing, no spider attacks. You can only proxy and inspect. Use when you must be certain ZAP won't alter the target.
- **Protected mode** — dangerous operations (active scan, fuzz) are **only allowed against URLs that are in a Context and in scope.** This is the recommended default for real engagements: it makes it *impossible* to accidentally attack out-of-scope hosts.
- **Standard mode** — the default. You can do anything, but attacks must be **manually started**. Nothing aggressive happens on its own.
- **ATTACK mode** — ZAP **automatically active-scans nodes as soon as they're discovered** within scope. Aggressive and noisy; useful for a fast pass on a target you fully control, dangerous elsewhere.

**Why this matters:** the mode is your seatbelt. Combined with Contexts (§9), **Protected mode** is the clean way to guarantee you only attack authorized targets — the ZAP equivalent of Burp's "restrict to scope" discipline, but enforced at the engine level.

---

## 8. First-Time Setup (Proxy, CA, Browser, HUD)

1. **Confirm the proxy listener:** `Options → Network → Local Servers/Proxies` (older builds: `Options → Local Proxies`). Default `localhost:8080`.
2. **Generate/trust the root CA:** `Options → Dynamic SSL Certificates` → **Generate** (if needed) → **Save** the cert → import it into your browser/OS trust store as a trusted root. Without this, HTTPS pages throw certificate errors.
3. **Launch a pre-configured browser:** ZAP's Quick Start has a **"Launch Browser"** button (Firefox/Chrome) that opens a browser **already proxied through ZAP with the CA trusted** — zero manual config, exactly like Burp's embedded browser. Use this to avoid fiddling with proxy settings.
4. **Enable the HUD** (optional but great for beginners): toggle it on the Quick Start / toolbar before launching the browser (§18).
5. **Browse the target** — watch the **History** tab and **Sites** tree populate. You're now capturing traffic.

If History stays empty, the browser isn't routed through ZAP or the port is wrong. If HTTPS breaks, the CA isn't trusted in that browser.

---

## 9. Contexts, Sessions, and Scope

A **Context** is ZAP's central organizing concept — roughly Burp's "scope," but richer. A Context is a **named grouping of URLs that belong to one application**, together with everything ZAP needs to know to test it intelligently:

- **Include/Exclude rules** (regex) defining which URLs are part of this app.
- **In scope** flag — mark the Context in scope so Protected mode and "in-scope only" filters apply.
- **Authentication** method (how to log in).
- **Users** (credentials) and **Session Management** (how the session is tracked).
- **Technology** hints (tell ZAP it's MySQL/Apache/etc. so it skips irrelevant attacks and runs relevant ones).
- **Structure** rules (how to treat data-driven URLs, custom parameters).

**Sessions** (the ZAP `.session` file) store *all* your work — the Sites tree, History, alerts, Contexts. Save a session to resume an engagement later (this is free in ZAP; Burp gates project saving behind Pro).

**Why Contexts matter technically:** by declaring "this is the app, here's how to authenticate, here's the tech stack," you let ZAP's spider, scanner, and auth handling operate as an informed insider rather than a blind outsider — dramatically improving coverage and reducing wasted/irrelevant requests.

---

## 10. Sites Tree, History, and Search

- **Sites tree (left):** a hierarchical map of every host/folder/endpoint ZAP has observed, built passively as you browse (Burp's site map). Right-click any node for the full menu: Attack → Spider/Active Scan, Open in Requester, Include/Exclude from Context, Fuzz, etc.
- **History tab (bottom):** the chronological log of every request/response (Burp's HTTP history). Click a row to load it into the Request/Response editors. Columns: method, URL, status code, response time, size — your signal columns.
- **Search tab:** regex search across requests, responses, headers, bodies, URLs, or fuzz results. Invaluable for finding where a parameter is reflected, or which responses contain a marker string.

Right-clicking in History/Sites is where most manual workflows begin — everything routes out from there to Requester, Fuzzer, Active Scan, or a Context.

---

## 11. Crawling: The Spider and the AJAX Spider

To test an app you must first **discover its content**. ZAP has two crawlers, and knowing when to use each is important.

### The (traditional) Spider

The Spider requests a start URL, **parses the HTML response for links and forms**, requests those, and recurses — building out the Sites tree. It's **fast** and finds anything reachable via static HTML links.

**Its limitation:** it does **not execute JavaScript.** Modern single-page apps (React/Angular/Vue) build their links and content client-side, so a pure HTML spider sees almost nothing — often just an empty shell page.

### The AJAX Spider

The AJAX Spider drives a **real headless browser** (via Selenium) — it actually *loads the page, runs the JavaScript, and clicks around* like a user, capturing the requests the app makes dynamically. It's **much slower** but essential for **JavaScript-heavy / SPA** applications.

**The concept:** crawling coverage depends on whether the app's links exist in the initial HTML (traditional spider suffices) or are generated by JavaScript at runtime (you need the AJAX spider). **Best practice: run the traditional Spider first (fast, broad), then the AJAX Spider to catch what JavaScript reveals.** More discovered endpoints = more attack surface for the scanner to test.

---

## 12. Passive Scanning

**Passive scanning is always on and completely safe.** As traffic flows through ZAP (from your browsing or from the spider), passive scan rules **analyze existing requests/responses without sending a single extra request.** Because it never touches the server beyond what already happened, you can leave it running everywhere, including lightly against production.

What passive rules find (visible in existing traffic only):

- Missing/weak security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`).
- Cookies lacking `HttpOnly` / `Secure` / `SameSite`.
- Information disclosure (stack traces, server/version banners, private IPs, comments).
- Reflected parameters (input echoed in the response — a *candidate* for XSS, to be confirmed actively).
- Insecure form/autocomplete settings, cacheable sensitive responses.

Passive scanning **cannot** confirm SQLi, XSS execution, command injection, etc. — those require *sending crafted probes*, which is the active scanner's job (§13).

---

## 13. Active Scanning: Policies, Thresholds, Attack Strength

**Active scanning** is where ZAP *sends crafted attack payloads* to discovered endpoints and analyzes the reactions to find real vulnerabilities. It is **intrusive**: it submits forms, injects payloads, and can create/modify data or trigger errors. **Only run it against targets you're authorized to attack.** ZAP's full active scanner is **free** — a major advantage over Burp.

### Scan Policy: two dials per rule

Each active scan rule (SQLi, XSS, path traversal, etc.) has two independent settings:

- **Threshold** (Off / Low / Medium / High) — the **false-positive tolerance**. *Low* threshold = ZAP raises an alert on weaker evidence (more findings, more false positives). *High* = only strong evidence (fewer, more reliable). *Off* disables that rule.
- **Attack Strength** (Low / Medium / High / **Insane**) — **how many payload variations** ZAP tries per insertion point. Higher strength = more thorough but far more requests and time. *Insane* can be enormous.

A **Scan Policy** is a saved bundle of these settings across all rules. You tune policies per engagement — e.g., a fast smoke-test policy vs a deep thorough policy.

### How ZAP chooses what to attack

ZAP identifies **insertion points** — URL query params, body params, headers, cookies, JSON fields, path segments — and applies each enabled rule's payloads to each point. Technology hints from the Context prune irrelevant attacks (no need to fire Oracle payloads at a MySQL app). Then it watches responses for each rule's tell-tale signal (§21).

### Running it

Right-click a node/Context → **Attack → Active Scan**, choose a policy and scope, and watch the **Active Scan** tab for progress and the **Alerts** tab for findings. In **ATTACK mode**, this happens automatically as nodes are discovered.

---

## 14. Alerts: Risk and Confidence

Findings appear in the **Alerts** tree, each with two orthogonal ratings you must not conflate:

- **Risk** — how serious *if real*: **High**, **Medium**, **Low**, **Informational**.
- **Confidence** — how sure ZAP is it's real: **Confirmed**, **High**, **Medium**, **Low**, **False Positive**.

A **High-risk / Low-confidence** alert means "would be bad, but ZAP isn't certain — verify manually." A **High-risk / High-confidence** alert is a priority. Each alert includes the affected URL, the parameter, the attack payload, evidence (the matched string), a CWE/WASC reference, description, and remediation guidance.

**The workflow:** treat alerts as *leads*, not conclusions. Reproduce each in the **Requester** (§15) or a browser, confirm impact, and mark false positives. Automated scanners on both ZAP and Burp produce false positives; the human confirmation step is the actual pentest.

---

## 15. Manual Request Editor, Requester, and Breakpoints

### Requester / Manual Request Editor (Repeater equivalent)

Right-click any request → **Open/Resend with Request Editor** (or use the **Requester** add-on's dedicated tabbed panel, which behaves very much like Burp Repeater). You get an editable request and a **Send** button; edit anything — params, headers, method, body — resend, and read the response. This is the manual **hypothesis loop**: change one thing, send, observe. The IDOR example from the Burp reference (change `id=1005`→`1006`, resend, see another user's data) works identically here.

### Breakpoints (intercept equivalent — but different model)

ZAP does **not** use a single global "intercept on/off" toggle like Burp. Instead it uses **breakpoints**:

- **Break on a specific request/response** — right-click → *Break* to catch just the matching messages.
- **Break on ALL requests/responses** — the green/red circle buttons in the toolbar toggle a catch-everything breakpoint (this is the closest analog to Burp's global intercept).
- **Custom breakpoints** — break only when a URL/header/body matches conditions you specify (e.g., only when the body contains `password`).

When a breakpoint hits, traffic pauses in the **Break** tab; you **edit** the message, then **Step** / **Continue** / **Drop**. The custom/conditional breakpoints are actually more surgical than Burp's global intercept — you can catch exactly the request you care about without wading through everything.

---

## 16. The Fuzzer (ZAP's Intruder)

The **Fuzzer** is ZAP's equivalent of Burp Intruder: it sends many variations of a request by substituting **payloads** into **locations** you highlight. It's how you brute-force, enumerate, and fuzz for injection in ZAP.

### Setting up a fuzz attack

1. In History or the Request editor, **highlight the exact bytes** you want to replace (e.g., the value of `username=`), right-click → **Fuzz**.
2. In the Fuzzer dialog, the highlighted region becomes a **fuzz location**. You can add **multiple locations**.
3. For each location, add one or more **payload generators**:
   - **File** / **File Fuzzers** — built-in wordlists (from **fuzzdb** and **jbrofuzz**: common usernames, passwords, SQLi strings, XSS vectors, path-traversal sequences, etc.).
   - **Strings** — a manual list.
   - **Numberzz** — numeric ranges (great for ID enumeration).
   - **Script** — payloads generated by a custom script.
   - **Regex**, etc.
4. Add **Payload Processors** if needed — transform each payload before sending (URL-encode, Base64, MD5/SHA hash, prefix/suffix, custom script). This mirrors Burp's payload processing.
5. Set concurrency/delay (to avoid lockouts/rate limits), then **Start Fuzzer**.

### Reading results — spot the outlier

The **Fuzzer results** tab lists every request with **payload, status code, response size (bytes), response time, and State/reason**. **The finding is the outlier** — exactly as in Burp Intruder:

```
 Payload        Code   Size    Time(ms)
 admin          200    3521    88
 root           200    3521    91
 jsmith         200    3547    90     <-- larger response: valid username
 support        200    3547    92     <-- larger response: valid username
```

Here a differing **Size** reveals valid usernames (the app leaks "Invalid password" vs "Invalid username"). For brute force, watch for a `302` redirect or a size jump indicating a successful login. Add a **regex highlight** to flag responses containing a success/error marker.

### Difference from Burp Intruder

ZAP's Fuzzer does **not** have named attack types (Sniper / Cluster bomb / Pitchfork / Battering ram). Instead:

- **One fuzz location, one payload set** ≈ Sniper on a single position.
- **Multiple fuzz locations, each with its own payload set** ≈ ZAP iterates combinations, closer to **Cluster bomb** behavior (all combinations), depending on payload configuration.

So you get the same outcomes, but you compose them by choosing locations and payload sets rather than picking a preset attack mode. In practice: for single-field fuzzing/brute force ZAP's Fuzzer is very comparable; for elaborate multi-position correlated attacks, Burp Intruder's explicit modes are more ergonomic.

---

## 17. Encode/Decode/Hash and Compare

### Encode/Decode/Hash dialog (Decoder equivalent)

`Tools → Encode/Decode/Hash` opens a workbench that simultaneously shows a value in many encodings: **URL**, **Base64**, **HTML entity**, **ASCII hex**, plus **hashes** (MD5, SHA variants). Paste an opaque cookie like `dXNlcj1hZG1pbg==`, and the Base64 pane reveals `user=admin` — now you can tamper it, re-encode, and test. Same purpose as Burp's Decoder; you can add custom tabs/scripts for bespoke transforms.

### Compare (Comparer equivalent)

ZAP can **diff two requests or two responses** (via right-click compare / the Compare add-on), highlighting what changed byte- or line-wise. Uses are identical to Burp Comparer: pinpoint the exact difference between a "valid" and "invalid" response (the enumeration signal), or between an authorized and unauthorized response (what access control actually changes).

---

## 18. The HUD (Heads-Up Display)

The **HUD** is ZAP's most distinctive feature, with **no Burp equivalent.** It injects an interactive overlay **directly into the target website in your browser** — semi-transparent controls down the left and right edges of the page. From the page itself you can:

- See **alerts for the current page** as colored icons, and click them for detail.
- **Trigger the Spider, AJAX Spider, and Active Scan** on the current page.
- **Toggle break/intercept** and step through requests.
- Enable/disable attack mode, view the history, and more — **without switching to the ZAP desktop UI.**

**Why it exists / the concept:** it lowers the barrier for developers and beginners by keeping security testing *in the browser where you're already working*. You browse the app normally and see security information and controls layered on top of the real site. It runs by ZAP injecting the HUD's JavaScript into responses as they pass through the proxy — a neat, self-demonstrating use of the very interception capability the whole tool is built on.

---

## 19. Authentication Handling (Contexts, Users, Session Management)

This is ZAP's answer to the same hard problem Burp solves with session-handling rules and macros: **keeping automated scans authenticated.** When the spider and active scanner fire thousands of requests, they must stay logged in, or they'll only test the public surface.

You configure this **inside a Context**:

1. **Authentication method** — choose one:
   - **Form-based** — ZAP submits credentials to a login URL with specified username/password fields.
   - **JSON-based** — for APIs that take JSON login bodies.
   - **HTTP/NTLM** — for Basic/NTLM auth.
   - **Script-based** — a custom script for complex/multi-step logins (CSRF-token-in-login, OAuth-ish flows, custom headers).
   - **Auto-detect / Browser-based** — newer ZAP can drive a real browser to log in, handling JavaScript-heavy login flows.
2. **Users** — define one or more sets of credentials tied to the Context. The scanner/spider can then run **as a specific user**.
3. **Session Management** — how the session is tracked after login: **cookie-based**, **HTTP header** (e.g., a bearer token), or **script-based**. ZAP replays the right session token on every request.
4. **Logged-in / Logged-out indicators** — you give ZAP a regex that identifies an authenticated response (e.g., presence of a "Logout" link) or an unauthenticated one. ZAP uses this to **detect when it's been logged out and re-authenticate automatically** — the same concept as Burp's session-validity check + re-login macro.

**Why this is advanced and essential:** without it, an "authenticated scan" silently degrades into an unauthenticated one and you miss most of the app. The logged-in/out indicator + re-auth loop is what makes long automated scans survive session expiry. Getting authentication right is often the difference between a scan that finds real bugs and one that finds nothing.

---

## 20. OAST — Out-of-Band Detection (ZAP's Collaborator)

ZAP addresses **blind / out-of-band** vulnerabilities — the ones that produce **no visible response change** — with the **OAST** add-on (Out-of-band Application Security Testing). It's the conceptual equivalent of Burp Collaborator.

**The idea is identical to Collaborator:** generate a unique external address, embed it in a payload, deliver it to the target, and if the target **interacts** with that address (DNS lookup or HTTP request), you've proven the injection fired — even though the app's own response revealed nothing.

ZAP's OAST add-on supports multiple back-ends:

- **interactsh** — a popular open-source OAST server (from ProjectDiscovery); you can use public instances or self-host.
- **BOAST** — another open OAST server you can self-host.
- **Callback Address** — ZAP itself listens on an address the target can reach, and logs any callbacks (simplest when the target can reach your ZAP host directly).

Some active scan rules (and many community/custom scripts) use OAST automatically to detect **blind SSRF, blind OS command injection, blind XXE, and blind SQLi** via DNS/HTTP callbacks. As with Burp, the **DNS channel is especially valuable** because DNS resolution often works even in networks that block outbound HTTP.

> Because ZAP is free and OAST can be **self-hosted**, you get Collaborator-style out-of-band testing without a paid license — you just supply (or point at) the OAST server.

---

## 21. The Concepts Behind the Discoveries (Vuln-by-Vuln)

The *underlying* detection logic for each vulnerability class is the **same physics** as in the Burp reference — ZAP just implements each as an **active scan rule** (plus passive rules for candidates). What follows focuses on how ZAP specifically surfaces each one; the deeper conceptual explanations in the Burp reference's §14 apply verbatim.

### SQL Injection
ZAP's SQLi active scan rule probes each insertion point across the same channels:
- **Error-based:** inject `'` and match database error signatures in the response.
- **Boolean-based blind:** send a true condition (`' AND '1'='1`) and a false one (`' AND '1'='2`), then **compare the two responses** — a reliable difference means the input alters the query. (ZAP automates the pair-and-compare that you'd do manually with Compare.)
- **Time-based blind:** inject a conditional `SLEEP`/`WAITFOR DELAY` and **measure response time** — a delay only under the true condition confirms injection.
- **OOB:** via OAST, force a DB-driven DNS callback.
The concept is unchanged: find a **channel** (error / response-diff / timing / OOB) that leaks whether the injected condition was true.

### Cross-Site Scripting (XSS)
- **Passive** rules flag **reflected input** (a candidate).
- **Active** rules then inject context-aware payloads and check whether the special characters (`< > " '`) survive **unencoded** in the specific output context (HTML body, attribute, script, URL). Survival = injectable.
- ZAP detects **reflected** and **stored** XSS by tracking where inputs re-appear (including on *other* pages for stored). DOM-based XSS needs browser-driven analysis. Concept: **reflection + failure to encode in context.**

### SSRF, XXE, Command Injection (the blind family)
These lean on **OAST** exactly as Burp leans on Collaborator:
- **SSRF:** point a URL parameter at your OAST address; an interaction proves the server made the request (blind SSRF confirmed).
- **XXE:** define an external entity pointing at your OAST address (or a local file for in-band); interaction or file contents confirm it.
- **OS command injection:** inject a command that triggers a DNS lookup / sleep; OOB interaction or timing confirms execution.
Concept: when the response is blind, **make the target phone home** or **measure a delay.**

### Path Traversal
Active rule sprays `../` sequences and encoded variants (`%2e%2e%2f`, double-encoding, `....//`) into file parameters and matches file-content signatures (`root:x:0:0:`). The Fuzzer with a fuzzdb traversal list does the same manually.

### Broken Access Control / IDOR
This is **logic**, so — as with Burp — automated scanners are weak here and **you** do the work: replay a request as a different/no user, or change an object ID, and check whether access is still granted. ZAP add-ons and scripts (and the **Access Control Testing** add-on, which compares what each Context *user* can reach against defined rules) help systematize horizontal/vertical access-control testing. Concept: **compare the same action across privilege levels; any success that shouldn't happen is the bug.**

### CSRF
Passive rules flag forms **lacking anti-CSRF tokens**; ZAP tracks known token parameter names per Context. Concept: **does the server rely only on the auto-sent cookie to authorize a state change?** If yes, it's forgeable.

### Others
Insecure deserialization, request smuggling, and race conditions are addressed via **add-ons, scripts, and manual technique** (the Fuzzer + Requester + parallel sending), with the same conceptual foundations described in the Burp reference. ZAP's strength is that all of this is free and scriptable; Burp's strength is polished dedicated tooling (e.g., the HTTP Request Smuggler extension).

---

## 22. The Add-on Marketplace

ZAP is extended through the **Marketplace** (`Manage Add-ons` → **Marketplace** tab). Add-ons are grouped by maturity:

- **Release** — stable, well-tested.
- **Beta** — usable, still maturing.
- **Alpha** — experimental, may be rough.

Many capabilities described above (AJAX Spider, Fuzzer, HUD, OAST, Requester, Automation Framework, additional active/passive scan rules) ship **as add-ons**, some bundled by default. Notable ones:

- **Active scanner rules (alpha/beta)** — expand vulnerability coverage beyond the defaults.
- **SOAP / OpenAPI / GraphQL** add-ons — import API definitions so ZAP can scan APIs directly (no browsing required).
- **Access Control Testing** — systematic authorization testing across users.
- **Retire.js** — flags known-vulnerable JavaScript libraries.
- **Report Generation** — HTML/XML/JSON/Markdown/**SARIF** reports (SARIF integrates with GitHub code scanning).
- **Selenium / Ajax Spider** — browser automation for crawling.
- **Community scripts** — a large library of ready-made scripts.

Install add-ons in the GUI, or headlessly with `-addoninstall <id>` / via the Automation Framework — important for reproducible CI environments.

---

## 23. The Scripting Engine

ZAP has a **built-in scripting engine** (Burp needs an extension/Montoya API for equivalent power). Scripts let you customize almost every stage of ZAP's operation. **Languages:** ECMAScript/JavaScript (via GraalVM/Nashorn), and — via add-ons — **Python (Jython)**, **Ruby (JRuby)**, **Kotlin**, and others.

**Script types** (each hooks a different point):

- **Standalone** — a script you run on demand (custom tooling, bulk operations).
- **Active Rules** — add your own active scan checks (custom payloads + response analysis).
- **Passive Rules** — add your own passive checks against traffic.
- **Proxy** — modify requests/responses as they pass through the proxy (like Burp match/replace, but programmable).
- **HTTP Sender** — modify every request ZAP sends (from any tool) — e.g., add a header, sign requests, inject a fresh token.
- **Authentication** — implement complex/custom login flows.
- **Session Management** — implement custom session tracking.
- **Payload Generator / Payload Processor** — feed or transform Fuzzer payloads.
- **Targeted** — run against a specific message you select.

**Why it's powerful:** anything ZAP does, you can bend. Need to sign every request with an HMAC before it's sent? An HTTP Sender script. Need a bespoke SQLi check for a weird parameter format? An Active Rule script. Need to handle a five-step SSO login? An Authentication script. The scripting engine turns ZAP from a scanner into a programmable testing platform — and because it's free and open, there are no API-tier restrictions.

---

## 24. The Automation Framework (YAML)

The **Automation Framework** is ZAP's modern, declarative way to define an entire testing workflow as a **single YAML file** — "scan as code." This is ZAP's flagship automation feature and a big reason it dominates CI/CD security testing.

A plan is a list of **jobs** run in order. Common jobs:

- `env` / **context** definitions — target URLs, include/exclude, authentication, users.
- `spider` — traditional crawl.
- `spiderAjax` — browser-based crawl.
- `passiveScan-config` and `passiveScan-wait` — configure and wait for passive scanning.
- `activeScan` — run the active scanner with a chosen policy.
- `report` — generate HTML/JSON/SARIF/etc.
- `requestor`, `delay`, `exitStatus`, `alertFilter` (to suppress known false positives), and more.

**Minimal example (conceptual):**

```yaml
env:
  contexts:
    - name: "target-app"
      urls: ["https://target.example.com"]
      includePaths: ["https://target.example.com.*"]
jobs:
  - type: spider
    parameters:
      context: "target-app"
      maxDuration: 5
  - type: passiveScan-wait
  - type: activeScan
    parameters:
      context: "target-app"
      policy: "Default Policy"
  - type: report
    parameters:
      template: "traditional-html"
      reportDir: "/zap/reports"
```

Run it: `zap.sh -cmd -autorun plan.yaml` (or inside the Docker image). You can **generate a starter plan from the GUI** (`Automation` tab) after configuring things interactively, then commit the YAML to your repo. This is how teams get a **repeatable, version-controlled** scan that runs on every build.

---

## 25. API, Daemon Mode, and CLI Options

ZAP is fully controllable **headlessly** — essential for automation and the reason ZAP is a CI staple.

### Daemon mode + REST API

Run ZAP with no GUI, exposing its **REST API**:

```bash
zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.key=YOUR_SECRET_KEY
```

Then drive it over HTTP (start spider, start active scan, pull alerts, generate reports) from any language, or via the official **client libraries** (Python `zaproxy`, Java, Node, etc.). The **API key** protects the local API from misuse — keep it secret. The API is also browsable at `http://zap/` (or the proxy address) when ZAP is running.

### Useful command-line options

| Option | Purpose |
|---|---|
| `-daemon` | Run headless (no GUI). |
| `-cmd` | Run in inline command mode (run tasks and exit). |
| `-autorun <plan.yaml>` | Run an Automation Framework plan. |
| `-quickurl <url>` | Quick attack a single URL. |
| `-quickout <file>` | Write quick-scan results to a report file. |
| `-config <key=value>` | Override any config (e.g., `api.key`, proxy port). |
| `-port <n>` / `-host <h>` | Set proxy/daemon listener. |
| `-newsession <name>` | Start with a fresh named session. |
| `-session <file>` | Load an existing session. |
| `-dir <path>` | Use a custom home directory. |
| `-addoninstall <id>` | Install an add-on non-interactively. |
| `-addonupdate` | Update installed add-ons. |

Increase Java heap for large scans by editing the launcher or setting JVM options (ZAP is Java; big crawls/scans need memory — the same consideration as Burp).

---

## 26. Docker Packaged Scans (Baseline / Full / API)

ZAP ships **Docker images** with three ready-made "packaged scan" scripts — the fastest way to run ZAP in a pipeline. (Use current images under the ZAP/Checkmarx org, e.g. `ghcr.io/zaproxy/zaproxy:stable` / `zaproxy/zap-stable`; the old `owasp/zap2docker-*` images are deprecated after the OWASP split.)

- **`zap-baseline.py`** — spiders the target and runs **passive scanning only** (no active attacks). Fast, safe, ideal to run on every build/PR. Fails the build if new alerts appear above a threshold. This is the most-used CI scan.
  ```bash
  docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
    -t https://target.example.com -r baseline-report.html
  ```
- **`zap-full-scan.py`** — spiders (traditional + AJAX) and runs the **active scanner** too. Thorough and intrusive; run against staging/authorized targets, not blindly on every commit.
  ```bash
  docker run -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
    -t https://target.example.com -r full-report.html
  ```
- **`zap-api-scan.py`** — scans an **API** from its definition file (**OpenAPI/Swagger, SOAP, or GraphQL**). Because APIs have no browsable UI, you feed the spec and ZAP derives the endpoints/parameters to test.
  ```bash
  docker run -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
    -t https://target.example.com/openapi.json -f openapi -r api-report.html
  ```

Common flags: `-t` target, `-r` HTML report, `-J` JSON report, `-w` Markdown, `-x` XML, `-a` include alpha rules, `-j` use AJAX spider, `-z` pass ZAP options, `-c`/`-u` supply a config file to ignore known false positives. Official **GitHub Actions** wrap these scripts for one-line pipeline integration.

---

## 27. Pitfalls, Evasion, and Good Practice

**Common beginner pitfalls**
- **HTTPS certificate errors** — the ZAP root CA isn't trusted in that browser. Re-export from `Options → Dynamic SSL Certificates` and import it.
- **Empty History / Sites** — the browser isn't routed through ZAP, or the port clashes. Use Quick Start's **Launch Browser** to avoid manual proxy config.
- **Spider finds nothing on a modern app** — it's a JavaScript SPA; the traditional spider can't see JS-generated links. Run the **AJAX Spider**.
- **"Authenticated" scan finds nothing sensitive** — auth actually failed; the scan ran logged-out. Fix the **Context authentication + logged-in indicator** so ZAP stays authenticated (§19).
- **Accidentally attacking out of scope** — use **Protected mode** + a Context so aggressive actions are impossible outside scope.
- **Scan too slow / too aggressive** — tune **Attack Strength** and **Threshold** in the Scan Policy; adjust threads.
- **Deprecated Docker image** — old `owasp/zap2docker-*` paths no longer maintained; switch to current ZAP/Checkmarx images.

**Evasion / WAF considerations (authorized testing only)**
- Use **payload processors** / **Encode-Decode** to generate encoding variants (URL, double-encoding, mixed case, HTML entities) that slip past naive filters.
- Add or spoof headers (`X-Forwarded-For`, `X-Original-URL`) via **HTTP Sender scripts** or proxy scripts to test header-based access/routing bypasses.
- Pace requests (threads/delay) to avoid tripping rate limits and lockouts.

**Good practice**
- **Save your session** early and often (free in ZAP) so you can resume.
- Leave **passive scanning on** always; be deliberate about **active scanning** scope.
- Confirm every alert manually in the **Requester**/browser before reporting; watch **confidence** ratings and mark false positives.
- Codify repeatable scans in the **Automation Framework** YAML and commit it.
- Combine ZAP with other tools — it plays well alongside Burp, and its free scanner/OAST make it a strong CI companion even if you do manual work elsewhere.

---

## 28. Legal and Ethical Note

ZAP is an offensive security tool; everything above is for **authorized testing only**:

- Only test systems you **own** or have **explicit written permission** to test (signed rules of engagement, an in-scope bug-bounty program, or your own lab).
- **Active scanning and fuzzing send real attacks** that can alter data or disrupt service — never point them at production or third-party systems without authorization.
- Practice legally and safely on intentionally vulnerable targets: **OWASP Juice Shop**, **DVWA**, **bWAPP**, **WebGoat**, and deliberately vulnerable VMs. (ZAP also has a built-in tutorial via the HUD.)
- Unauthorized testing — even passive-looking probing — can be a criminal offense. **Contexts + Protected mode** aren't just tidiness; they're how you keep testing lawful and contained.

---

### Where to go next

- Practice on **OWASP Juice Shop** or **DVWA**: browse through ZAP with the **HUD** on, run the **Spider → AJAX Spider → Active Scan** sequence, then reproduce each alert manually in the **Requester** to understand *why* it fired (map each back to §21).
- Once comfortable, write a small **Automation Framework** YAML for the same target and run it via Docker — that's the workflow that makes ZAP shine in the real world.
- Since you already know Burp: keep the §5 mapping table handy, and try solving the same lab in both tools — you'll cement the concepts by seeing how each expresses them.

*End of reference.*

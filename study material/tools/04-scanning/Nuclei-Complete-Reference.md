# Nuclei — The Complete Reference (Beginner → Advanced)

> A ground-up reference for **Nuclei**, ProjectDiscovery's template-driven vulnerability scanner: how the template model works, how to read and **write** a template, matchers/extractors/DSL, out-of-band detection, workflows, the fuzzing/DAST mode, and how to run it safely at scale.

---

## Table of Contents

1. [What Nuclei Is and Why It Exists](#1-what-nuclei-is-and-why-it-exists)
2. [Status and Key Facts](#2-status-and-key-facts)
3. [The Core Concept: Template-Based Scanning](#3-the-core-concept-template-based-scanning)
4. [Anatomy of a Template (Annotated)](#4-anatomy-of-a-template-annotated)
5. [Matchers Explained](#5-matchers-explained)
6. [Extractors Explained](#6-extractors-explained)
7. [The DSL and Helper Functions](#7-the-dsl-and-helper-functions)
8. [Protocols Supported](#8-protocols-supported)
9. [OAST / Interactsh — Out-of-Band Detection](#9-oast--interactsh--out-of-band-detection)
10. [Severity, Tags, and Classification](#10-severity-tags-and-classification)
11. [Workflows (Conditional Chaining)](#11-workflows-conditional-chaining)
12. [Fuzzing / DAST Mode (Unknown Vulnerabilities)](#12-fuzzing--dast-mode-unknown-vulnerabilities)
13. [Automatic Scan and Tech Detection](#13-automatic-scan-and-tech-detection)
14. [The nuclei-templates Repo and Template Signing](#14-the-nuclei-templates-repo-and-template-signing)
15. [Installation and Template Setup](#15-installation-and-template-setup)
16. [Command-Line Options (Full Breakdown)](#16-command-line-options-full-breakdown)
17. [Worked Examples with Output, Explained](#17-worked-examples-with-output-explained)
18. [Writing Your Own Template (Walkthrough)](#18-writing-your-own-template-walkthrough)
19. [Reading the Output](#19-reading-the-output)
20. [Performance, Rate Limiting, and Safety](#20-performance-rate-limiting-and-safety)
21. [Where It Fits: Workflow and Chaining](#21-where-it-fits-workflow-and-chaining)
22. [Limitations and Pitfalls](#22-limitations-and-pitfalls)
23. [Legal and Ethical Note](#23-legal-and-ethical-note)

---

## 1. What Nuclei Is and Why It Exists

**Nuclei** is a fast, template-driven **vulnerability scanner**. You point it at a target (or thousands), and it runs a library of **YAML templates** — each describing *a request to send* and *how to recognize a specific vulnerability, misconfiguration, or exposure in the response*. If a response matches, Nuclei reports the finding with its severity and references.

The defining idea: **the detection logic lives in data (YAML templates), not in the code.** The Nuclei binary is a generic engine that reads templates and executes them; the *knowledge* of what to check for lives in the **community-maintained `nuclei-templates` repository** — thousands of checks for CVEs, default logins, exposed panels, misconfigurations, information leaks, subdomain takeovers, and more, updated continuously.

Written in **Go** by **ProjectDiscovery**, Nuclei is prized for **speed** (massive concurrency + request clustering), **breadth** (thousands of up-to-date checks), **low false positives** (templates simulate real verification steps), and **customizability** (you can write your own templates in minutes).

**Why it exists / the problem it solves:** you've seen signature scanners already — Nikto has a database of known-bad paths; WPScan maps WordPress components to CVEs. Both are valuable but **hard-coded and narrow** (Nikto's checks are baked into the tool; WPScan only does WordPress). Nuclei generalizes that idea into an **open, community-driven format**: anyone can write a check as a YAML template, the community ships thousands, and the same engine runs them all across HTTP/DNS/TCP/SSL and more. That model means Nuclei gets a template for a new critical CVE **within hours of disclosure**, contributed by the community — coverage no single-team tool can match. It's the modern standard for the "fast pass for known issues" stage of every engagement and for continuous/CI security testing.

**A crucial framing:** Nuclei (in its default mode) finds **known** issues — things someone has written a template for. It is not a crawler and not primarily a discoverer of novel bugs (though its newer **fuzzing/DAST mode** extends toward that, §12). Think of it as *"run every known check against this target, fast."*

---

## 2. Status and Key Facts

- **Actively developed**, very fast-moving. Current is the **v3.x series** (v3.3+/v3.4+; check `nuclei -version`). By ProjectDiscovery.
- **Language:** Go — compiled, highly concurrent; install via Go, Homebrew, Docker, or a release binary.
- **Repo/templates:** engine at `github.com/projectdiscovery/nuclei`; checks at `github.com/projectdiscovery/nuclei-templates` (auto-downloaded on first run). Docs at `docs.projectdiscovery.io`.
- **Protocols:** HTTP, DNS, TCP, SSL, WHOIS, File, Headless (browser), WebSocket, **Code** (execute code), **JavaScript**, plus **multi-protocol** templates and **flow** (JS-based logic) for complex multi-step checks.
- **v3 highlights:** multi-protocol templates, JavaScript-based `flow` logic, built-in **interactsh** (OAST), **template signing** (security), and a full **fuzzing/DAST** engine (v3.2+).
- **Design goals:** ultra-fast parallel scanning, **request clustering** (dedupe identical base requests across templates), CI/CD integration, and "zero false positives" via templates that verify real-world conditions.
- **Two template libraries:** `nuclei-templates` (**known** vulnerabilities — the default) and the DAST/fuzzing templates now under `nuclei-templates/dast` (**unknown** vulnerabilities via fuzzing, §12).

---

## 3. The Core Concept: Template-Based Scanning

The single idea to internalize: **Nuclei separates the *engine* from the *checks*.**

- **The engine** (the Go binary) knows how to speak HTTP/DNS/TCP/etc., send requests concurrently, and evaluate matchers/extractors against responses. It changes rarely.
- **The templates** (YAML files) describe *what* to check: which request(s) to send and what response pattern indicates the vulnerability. They change constantly, contributed by thousands of people.

**Why this architecture is powerful:**

1. **Community scale.** Because a check is just a YAML file, *anyone* can write one, and the community ships thousands. When a new critical CVE drops (say, a widely-exploited RCE), a template often appears within **hours** — far faster than any single vendor could ship a scanner update. You get the collective output of the whole security community.
2. **Transparency.** Every check is human-readable YAML you can open, audit, and understand — unlike a black-box scanner. You can see *exactly* what a template sends and how it decides "vulnerable," which builds trust and teaches you.
3. **Customization.** You can write a template for *your* specific need (a custom app's login page, an internal misconfiguration) in minutes, and run it with the same engine. Your checks and the community's run side by side.
4. **Precision & low false positives.** Good templates don't just match a banner — they **simulate the real verification step** (send the actual exploit request and confirm the specific proof), which is why Nuclei's findings are more trustworthy than pure version-guessing.

**Compared to the signature scanners you've studied:**
- **Nikto** — a *fixed* database of known-bad paths, baked into the tool; general web server checks only.
- **WPScan** — a curated vuln DB, but **WordPress-only**.
- **Nuclei** — an *open, extensible, multi-protocol* template format with a huge community library, covering everything from CVEs to takeovers to misconfigs, updatable by anyone.

That openness is why Nuclei has largely become the default "known-issues" scanner, and why many workflows now **lead with Nuclei** and use Nikto/WPScan for their specialties.

---

## 4. Anatomy of a Template (Annotated)

Understanding one template teaches you the whole tool. Here's a complete HTTP template, annotated:

```yaml
id: example-panel-exposure                 # (1) unique template ID (filename-safe)

info:                                        # (2) metadata about the check
  name: Example Admin Panel Exposure         #     human-readable name
  author: yourname                           #     who wrote it
  severity: medium                           #     info | low | medium | high | critical
  description: Detects an exposed Example admin login panel.
  reference:                                 #     links (advisory, CVE, blog)
    - https://example.com/advisory
  classification:                            #     standardized identifiers
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
    cvss-score: 5.3
    cwe-id: CWE-200
  tags: panel,exposure,example               #     filter labels (see §10)

http:                                        # (3) the protocol block (HTTP here)
  - method: GET                              #     request definition
    path:
      - "{{BaseURL}}/admin/login"            #     {{BaseURL}} = the target you pass in

    matchers-condition: and                  # (4) how multiple matchers combine (and/or)
    matchers:
      - type: word                           #     match #1: body contains a string
        part: body
        words:
          - "Example Admin Login"
      - type: status                         #     match #2: status code is 200
        status:
          - 200

    extractors:                              # (5) pull data out of the response
      - type: regex
        part: body
        regex:
          - 'version ([0-9.]+)'              #     capture the version string
```

**How Nuclei executes it:**
1. Reads the `info` for severity/tags (used for filtering and reporting).
2. Sends `GET {{BaseURL}}/admin/login` — `{{BaseURL}}` is replaced with each target you provide.
3. Evaluates the **matchers**: with `matchers-condition: and`, the finding fires **only if** the body contains "Example Admin Login" **and** the status is 200. (`or` would fire on either.)
4. If it fires, runs **extractors** to pull useful data (here, the version) into the output.
5. Reports the hit with the template's name, severity, and the matched URL.

**The key sections you'll always see:**
- **`id`** — unique identifier.
- **`info`** — name, author, **severity**, description, references, **classification** (CVE/CWE/CVSS), **tags**. This is what you filter and report on.
- **A protocol block** (`http:`, `dns:`, `tcp:`, `ssl:`, etc.) — the request(s) to send.
- **`matchers`** — the conditions that define "vulnerable/present" (§5).
- **`extractors`** (optional) — data to pull out (§6).

Once you can read this, you can read *any* Nuclei template — and writing your own is just filling in these blocks (§18).

---

## 5. Matchers Explained

**Matchers are the heart of a template** — they define *what in the response means the check succeeded.* A template can have several, combined with `matchers-condition: and | or`.

**Matcher types:**

| Type | Matches when the response… |
|---|---|
| `word` | contains one or more **literal strings** (fast, common). |
| `regex` | matches a **regular expression**. |
| `status` | has one of the given **HTTP status codes**. |
| `size` | body is a specific **byte size**. |
| `binary` | contains specific **binary/hex** bytes (for binary protocols/files). |
| `dsl` | satisfies a **DSL expression** — arbitrary logic (§7), the most powerful. |

**Key matcher options:**

- **`part`** — *which part* of the response to inspect: `body` (default), `header`, `all` (raw response), `interactsh_protocol` (for OAST, §9), or a named extracted variable.
- **`condition`** (within a single matcher) — `and`/`or` across the listed words/regexes (e.g., all words must appear vs any).
- **`matchers-condition`** (across matchers) — `and`/`or` across the whole matcher list.
- **`negative: true`** — invert the match (fires when the pattern is **absent**) — e.g., "vulnerable if the response does *not* contain the patched marker."
- **`internal: true`** — the match is used internally (e.g., to gate a later step in a workflow/multi-step template) but not reported on its own.
- **`case-insensitive: true`** — ignore case for word matching.

**Example — a precise, low-false-positive matcher:**
```yaml
matchers-condition: and
matchers:
  - type: word
    part: body
    words:
      - "root:x:0:0"          # the shape of /etc/passwd
  - type: status
    status:
      - 200
  - type: word
    part: header
    words:
      - "text/plain"          # served as raw text, not an HTML error page
```
This fires only when the body looks like `/etc/passwd`, the status is 200, **and** it's served as plain text — three conditions together, dramatically reducing false positives compared to matching `root:x:0:0` alone. **This "verify multiple real conditions" approach is why Nuclei findings are trustworthy** — good templates prove the vuln, they don't guess from a banner.

---

## 6. Extractors Explained

**Extractors pull specific data out of a matched response** — a version number, a token, a username, an internal path — for two purposes: (1) enriching the **output** (so your report shows the actual leaked value), and (2) feeding **later requests** in multi-step templates (use an extracted value in the next request).

**Extractor types:**

| Type | Pulls data via… |
|---|---|
| `regex` | a regular expression (with a capture group). |
| `kval` | a **key-value** lookup (e.g., a response header by name, like `Server`). |
| `json` | a **JSONPath**-style expression into a JSON body. |
| `xpath` | an **XPath** expression into HTML/XML. |
| `dsl` | a **DSL expression** result. |

**Example:**
```yaml
extractors:
  - type: regex
    part: body
    group: 1                       # which capture group to return
    regex:
      - '"version":"([0-9.]+)"'    # capture the version from JSON-ish body
  - type: kval
    part: header
    kval:
      - server                     # extract the Server header value
```

**`internal: true`** on an extractor makes the value available to **subsequent requests** in the same template (chaining) without printing it — the mechanism for multi-step checks (extract a CSRF token / session ID from request 1, use it in request 2). Extractors turn "yes it's vulnerable" into "yes, and here's the proof/data," which is what makes a finding actionable.

---

## 7. The DSL and Helper Functions

Nuclei's **DSL (Domain-Specific Language)** lets templates express logic beyond simple string/status matching — arithmetic, string manipulation, hashing, encoding, comparisons, and access to response variables. It's used in `dsl` matchers, `dsl` extractors, and fuzzing pre-conditions.

**Available response variables** include `status_code`, `content_length`, `body`, `header`, `all_headers`, `duration` (response time), `content_type`, and protocol-specific ones (`dns_cname`, `http_body`, etc.).

**Helper functions** (100+) cover common needs:
- **Encoding:** `base64()`, `base64_decode()`, `url_encode()`, `hex_encode()`.
- **Hashing:** `md5()`, `sha1()`, `sha256()`.
- **Strings:** `contains()`, `startswith()`, `regex()`, `len()`, `to_lower()`, `trim()`, `replace()`.
- **Randomness:** `rand_base()`, `rand_int()`, `rand_text_alpha()` — generate unique markers to avoid caching/collisions.
- **Time/logic:** comparisons, `compare_versions()`.

**Example DSL matchers:**
```yaml
matchers:
  - type: dsl
    dsl:
      - 'status_code == 200'
      - 'contains(body, "admin")'
      - 'len(body) > 1000'
      - 'duration >= 5'                    # response took ≥5s → time-based signal
    condition: and
```
```yaml
# Reflection check: does our random marker appear in the response? (XSS-style)
- type: dsl
  dsl:
    - 'contains(body, "{{randstr}}")'
```

The DSL is what elevates Nuclei from "match a string" to "express a real vulnerability condition" — e.g., time-based blind detection via `duration`, or confirming a reflected marker for XSS. Use `-svd` (show DSL variables) with `-v` when writing templates to see every variable available for a given response.

---

## 8. Protocols Supported

Nuclei isn't HTTP-only. Each protocol is its own template block, and **multi-protocol** templates combine them.

| Protocol | Use |
|---|---|
| `http` | The main one — web requests, matchers/extractors, fuzzing. |
| `dns` | Query DNS records (detect misconfig, subdomain takeover CNAMEs). |
| `tcp` | Raw TCP — banner grabbing, non-HTTP services. |
| `ssl` | Inspect TLS certificates/config (expiry, weak ciphers, SANs). |
| `whois` | WHOIS lookups. |
| `file` | Scan **local files** (search codebases/configs for secrets/patterns). |
| `headless` | Drive a **real browser** (Chromium) — for JS-heavy checks, DOM XSS, and things that only manifest after rendering. Enable with `-headless`. |
| `websocket` | Test WebSocket endpoints. |
| `code` | **Execute code** (e.g., a script) as part of a check — powerful and gated behind `-code` + signing (see §14). |
| `javascript` | Run JavaScript logic (network protocols, complex steps). |

**Multi-protocol example** (subdomain-takeover-style check combining DNS + HTTP):
```yaml
id: multi-protocol-takeover
info:
  name: Multi Protocol Example
  author: pdteam
  severity: info
dns:
  - name: "{{FQDN}}"
    type: cname
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: dsl
        dsl:
          - contains(dns_cname, 'myshopify.com')
          - contains(http_body, 'Sorry, this shop is currently unavailable.')
        condition: and
```
This checks a **DNS CNAME** and an **HTTP body** together — the exact fingerprint of a Shopify subdomain takeover. For logic too complex for YAML (multi-step exploits with loops/conditionals), v3's **`flow`** field lets you write the orchestration in **JavaScript**.

---

## 9. OAST / Interactsh — Out-of-Band Detection

This is one of Nuclei's most important capabilities, and it directly uses the **OAST** concept from your glossary (and mirrors Burp Collaborator).

**The problem (recap):** many severe vulnerabilities are **blind** — the response shows nothing. Blind SSRF, blind command injection, blind XXE, Log4Shell-style JNDI injection: the app never returns the result, so matching the response can't detect them.

**Nuclei's built-in solution — interactsh:** Nuclei ships with an integrated **OAST client (interactsh)**. A template can insert a unique callback URL via the **`{{interactsh-url}}`** placeholder into its payload. If the target is vulnerable and **interacts** with that URL (DNS lookup or HTTP request), Nuclei's interactsh client **catches the interaction** and correlates it back to the template — confirming the blind vulnerability.

**Example (blind detection):**
```yaml
http:
  - raw:
      - |
        GET /vulnerable?url=https://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        part: interactsh_protocol       # fires when a callback is received
        words:
          - "dns"                        # a DNS interaction proves the injection ran
      - type: word
        part: interactsh_protocol
        words:
          - "http"
        condition: or
```
Here the template injects a Collaborator-style URL and matches on **`interactsh_protocol`** — if a **DNS or HTTP** callback arrives at Nuclei's interaction server, the blind vuln is confirmed. The **DNS channel** is especially valuable (as with Burp Collaborator) because DNS resolves even where outbound HTTP is firewalled.

**Options:** `-interactsh-url` to use a **self-hosted** interactsh server (better privacy/reliability), `-interactions-cache-size`, `-no-interactsh` to disable OOB testing. This built-in OAST is a big reason Nuclei can reliably find critical blind bugs like Log4Shell at scale.

---

## 10. Severity, Tags, and Classification

Templates are labeled so you can **filter** which ones run and **prioritize** findings.

**Severity** (in `info.severity`): `info`, `low`, `medium`, `high`, `critical`. Filter with:
- `-severity critical,high` — run only these.
- `-exclude-severity info` — skip the noisy informational ones.

**Tags** (in `info.tags`): free-form labels like `cve`, `rce`, `sqli`, `xss`, `wordpress`, `exposure`, `panel`, `takeover`, `log4j`, `misconfig`, `tech`. Filter with:
- `-tags cve,rce` — run templates with these tags.
- `-exclude-tags dos,fuzz` — skip these (e.g., avoid DoS templates).

**Classification** (in `info.classification`): standardized identifiers — **CVE ID**, **CWE ID**, **CVSS score/vector**, EPSS. These power reporting and let you filter by, e.g., a specific CVE:
- `-id CVE-2021-44228` — run one template by ID.
- `-template-condition` / `-tc` — complex expressions (e.g., `contains(tags,'cve') && severity=='critical'`).

**Why this matters:** the template library is enormous (thousands). You rarely run *all* of them — you scope by severity/tags/tech to keep scans fast, relevant, and quiet. A common first pass: `-severity critical,high -exclude-tags dos`. A targeted pass: `-tags wordpress` or `-id <specific-CVE>` when you already know the stack.

---

## 11. Workflows (Conditional Chaining)

**Workflows** let templates run **conditionally**: *"if template A detects technology X, then run the X-specific templates."* This is an efficiency and accuracy feature — instead of blasting every template at every host, you detect first, then run only what's relevant.

**Example workflow:**
```yaml
id: wordpress-workflow
info:
  name: WordPress Security Checks
  author: yourname
workflows:
  - template: technologies/wordpress-detect.yaml   # first, detect WordPress
    subtemplates:                                   # only if detected…
      - tags: wordpress                             # …run all WordPress templates
      - template: cves/wordpress/                   # …and WordPress CVEs
```

**Why it matters:** running 500 WordPress templates against a non-WordPress site is wasted noise and time. A workflow detects the tech once, then fires only the applicable checks — **faster, quieter, and fewer false positives.** Workflows can chain multiple levels (detect CMS → detect plugin → run plugin-specific CVE). This is Nuclei's answer to "scan intelligently, not indiscriminately," conceptually similar to WPScan's technology-aware scanning but generalized to any stack.

---

## 12. Fuzzing / DAST Mode (Unknown Vulnerabilities)

By default, Nuclei finds **known** issues (a template exists for each). Since **v3.2**, Nuclei also has a full **fuzzing engine** for finding **unknown** vulnerabilities — turning it into a true **DAST** tool that injects payloads into request parts and detects flaws generically (SQLi, XSS, SSTI, command injection, OOB template injection) rather than by known signature.

**How it differs:** a normal template checks one specific known thing. A **fuzzing (DAST) template** defines *where* to inject (query params, headers, body, path), *what* payloads to try, and *how* to detect success (reflection, error, time delay, or OAST callback) — applied to **whatever parameters the target actually has.** These live in `nuclei-templates/dast`.

**Key pieces of a fuzzing template:**
- **`fuzzing:`** block — declares the injection points and payloads.
- **`part`** — which request component to fuzz (`query`, `header`, `body`, `path`).
- **`pre-condition`** — a matcher-like gate deciding **whether** to fuzz a given request (e.g., only fuzz `POST` requests with a body). This controls **noise/volume** — indiscriminate fuzzing behind a WAF gets you IP-banned, so pre-conditions keep it targeted.
- **`fuzz`** — the payloads/DSL to substitute.

**Running DAST mode:**
```bash
# Enable fuzzing/DAST templates
nuclei -u "https://target.com/search?q=test" -dast

# Fuzz from imported real traffic (Burp/proxy export) or an API schema
nuclei -l burp-export.txt -dast
nuclei -im openapi -l openapi.yaml -dast     # generate requests from an OpenAPI spec
```

**Why this is significant:** it bridges Nuclei and tools like **ffuf/Burp Scanner** — you can import real HTTP traffic (from Burp, httpx, or Proxify) or an OpenAPI/Swagger schema, and Nuclei fuzzes every parameter for injection flaws, confirming blind ones via interactsh. It's Nuclei moving from "known-CVE scanner" toward "generic vulnerability discovery." (Still maturing — query-parameter fuzzing is most mature; body/header fuzzing is expanding.)

> **Volume warning:** fuzzing multiplies requests enormously (payloads × parameters × endpoints). Use `pre-condition`, rate limiting (§20), and scope carefully — DAST mode is much louder than template mode.

---

## 13. Automatic Scan and Tech Detection

**`-as` (automatic scan)** makes Nuclei **fingerprint the target's technology first** (wappalyzer-style — detect WordPress, nginx, Jira, etc.), then **run only the templates relevant to that stack.** It's the "smart, don't-scan-everything" mode built in, so you don't manually pick tags.

```bash
nuclei -u https://target.com -as
```

**Why use it:** against an unknown target, `-as` avoids firing thousands of irrelevant templates (all the Oracle/Citrix/WordPress checks at a plain nginx site), giving a faster, quieter, more relevant scan. It's the same principle as workflows (§11), automated for you. For a known stack, manual `-tags`/`-id` is more precise; for triage of an unknown host, `-as` is a great default.

---

## 14. The nuclei-templates Repo and Template Signing

**The `nuclei-templates` repository** is where Nuclei's power lives — thousands of community + official templates, organized by directory: `cves/`, `vulnerabilities/`, `misconfiguration/`, `exposures/`, `default-logins/`, `takeovers/`, `technologies/`, `dast/` (fuzzing), and more. On first run, Nuclei downloads them to a local directory (e.g., `~/.local/nuclei-templates` or `~/nuclei-templates`). Update with `-update-templates` (`-ut`).

**Template signing (a v3 security feature you must understand):** templates are **code** — they send requests, and the `code`/`javascript` protocols can literally **execute commands**. A malicious template could therefore harm *your* machine or attack unintended targets. To prevent this, ProjectDiscovery **cryptographically signs official templates**, and Nuclei **verifies signatures**:

- **Official (signed) templates** run normally — you can trust they're vetted.
- **Custom/unsigned templates** run too, but Nuclei **warns** that they're unverified. **Code-protocol** templates specifically require the `-code` flag *and* proper signing/trust, because they execute code.
- **Only run untrusted templates you've read.** Treat a random template from the internet like any script — audit it before running, especially anything using `code`/`javascript`/`headless`.

**Why this matters:** the same openness that makes Nuclei powerful (anyone can write a template) is a supply-chain risk (a malicious template). Signing + your own review is the mitigation. Stick to the official repo plus templates you've audited.

---

## 15. Installation and Template Setup

Nuclei is a single Go binary; templates download automatically.

```bash
# Go (recommended — latest)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Homebrew
brew install nuclei

# Docker
docker run projectdiscovery/nuclei:latest -u https://target.com

# Kali (apt)
sudo apt install nuclei

# Verify + fetch/update templates
nuclei -version
nuclei -update-templates      # (-ut) download/update the template library
nuclei -update                # update the engine itself
```

On first scan, Nuclei fetches the template repo automatically. Keep both engine and templates current (`-update`, `-ut`) — new CVEs get templates constantly, and stale templates = missed (or falsely-flagged) findings. Optionally sign in to **ProjectDiscovery Cloud (PDCP)** for a results dashboard and private templates (`-auth`, `-cloud-upload`/`-dashboard`).

---

## 16. Command-Line Options (Full Breakdown)

Grouped by purpose.

### Target
| Option | Purpose |
|---|---|
| `-u, -target <url>` | Target URL(s) (comma-separated or repeated). |
| `-l, -list <file>` | File of targets (one per line) — the usual way at scale. |
| `-im, -input-mode <mode>` | Input format (e.g., `list`, `burp`, `openapi`, `jsonl`) — import traffic/schemas. |
| `-resume <file>` | Resume a previous scan. |


### Template selection
| Option | Purpose |
|---|---|
| `-t, -templates <path>` | Run specific template(s)/dir. |
| `-tags <tags>` | Run templates with these tags. |
| `-etags, -exclude-tags <tags>` | Exclude these tags. |
| `-id <id>` | Run template(s) by ID (e.g., a CVE). |
| `-a, -author <name>` | Run templates by author. |
| `-s, -severity <levels>` | Run only these severities. |
| `-es, -exclude-severity <levels>` | Exclude severities. |
| `-tc, -template-condition <expr>` | Complex filter expression. |
| `-it` / `-et` | Force-include / exclude specific templates. |
| `-nt, -new-templates` | Only templates added since last update. |
| `-as, -automatic-scan` | Tech-detect, then run relevant templates. |
| `-w, -workflows <path>` | Run a workflow. |
| `-dast` | Enable fuzzing/DAST templates. |
| `-headless` | Enable headless (browser) templates. |
| `-code` | Enable code-protocol templates (requires trust/signing). |

### Interactsh / OAST
| Option | Purpose |
|---|---|
| `-iserver, -interactsh-server <url>` | Use a self-hosted interactsh server. |
| `-ni, -no-interactsh` | Disable OOB testing. |

### Output
| Option | Purpose |
|---|---|
| `-o <file>` | Write findings to a file. |
| `-j, -jsonl` | JSONL output (for tooling). |
| `-me, -markdown-export <dir>` | Markdown report per finding. |
| `-se, -sarif-export <file>` | SARIF (for GitHub code scanning). |
| `-silent` | Only print findings (clean, pipeable). |
| `-nc, -no-color` | Disable color. |
| `-v` / `-debug` | Verbose / debug (see requests & responses). |
| `-stats` | Live scan statistics. |
| `-sresp, -store-resp` | Save all responses to disk (evidence). |

### Rate / performance / network
| Option | Purpose |
|---|---|
| `-rl, -rate-limit <n>` | Max requests/second (default 150). |
| `-c, -concurrency <n>` | Templates run in parallel (default 25). |
| `-bs, -bulk-size <n>` | Hosts per template in parallel. |
| `-timeout <s>` / `-retries <n>` | Per-request timeout / retries. |
| `-proxy <url>` | Route via a proxy (e.g., Burp). |
| `-H, -header <header>` | Custom header(s). |
| `-V, -var <k=v>` | Template variables. |
| `-project` | Avoid duplicate requests across templates (caching). |

### Maintenance
| Option | Purpose |
|---|---|
| `-update` / `-ut, -update-templates` | Update engine / templates. |
| `-tl, -template-list` | List available templates. |
| `-validate` | Validate template syntax (when writing your own). |

Run `nuclei -h` for the full, version-accurate list.

---

## 17. Worked Examples with Output, Explained

> Output is **representative**.

### 17.1 Basic scan (all default templates)
```bash
nuclei -u https://target.com
```
```
[INF] Templates loaded for current scan: 8500
[INF] Executing 8500 signed templates from projectdiscovery/nuclei-templates

[tech-detect:nginx] [http] [info] https://target.com
[http-missing-security-headers] [http] [info] https://target.com
[waf-detect:cloudflare] [http] [info] https://target.com
[CVE-2021-XXXX] [http] [high] https://target.com/vuln/path
[exposed-git] [http] [medium] https://target.com/.git/config
[INF] Scan completed in 2m14s. 5 findings.
```
**Reading a finding line:** `[template-id] [protocol] [severity] matched-URL`. So `[CVE-2021-XXXX] [http] [high] ...` = that CVE template fired at high severity on that URL. `[exposed-git]` found a readable `.git/config` (source-code leak — a real lead). The `[info]` lines (tech-detect, missing headers, WAF-detect) are context, not vulnerabilities.

### 17.2 Scoped, fast, safe first pass
```bash
nuclei -u https://target.com -severity critical,high -exclude-tags dos -stats
```
Only critical/high templates, no DoS checks, with live stats — a sensible triage: high signal, lower noise/risk.

### 17.3 Scan a list of hosts (from recon)
```bash
nuclei -l live-hosts.txt -tags cve,exposure -o findings.txt -jsonl
```
Run CVE + exposure templates across every discovered host; save text + JSONL.

### 17.4 One specific CVE across many hosts
```bash
nuclei -l hosts.txt -id CVE-2021-44228 -stats     # hunt Log4Shell specifically
```
When a big CVE drops, check your whole estate in one command (interactsh confirms the blind callback automatically).

### 17.5 Through Burp, with a custom template
```bash
nuclei -u https://target.com -t ./my-templates/custom-check.yaml \
       -proxy http://127.0.0.1:8080 -v
```
Run your own template, routed through Burp so you can inspect exactly what Nuclei sends/receives.

### 17.6 DAST fuzzing from imported traffic
```bash
nuclei -l burp-requests.txt -im burp -dast -rl 50
```
Import real requests exported from Burp and fuzz their parameters for injection flaws, rate-limited to 50 req/s.

---

## 18. Writing Your Own Template (Walkthrough)

The best way to *understand* Nuclei is to write a template. Here's a complete beginner example — detecting an exposed `.env` file (which often leaks credentials).

**Goal:** flag any target serving a readable `.env` file containing environment-variable-style secrets.

```yaml
id: exposed-env-file

info:
  name: Exposed .env File
  author: yourname
  severity: high
  description: Detects a publicly accessible .env file leaking secrets.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/
  tags: exposure,config,env

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:                      # typical .env keys
          - "DB_PASSWORD"
          - "APP_KEY"
          - "SECRET"
        condition: or               # any one is enough
      - type: status
        status:
          - 200
      - type: word                  # avoid HTML error pages that echo the words
        part: header
        words:
          - "text/plain"

    extractors:
      - type: regex
        part: body
        regex:
          - 'DB_PASSWORD=([^\n]+)'  # pull the leaked password into the output
```

**Why each part is there:**
- **`matchers-condition: and`** with three matchers = high precision: the body must contain a secret key, **and** return 200, **and** be served as plain text (not an HTML "not found" page that happens to contain the word "SECRET"). This "verify multiple real conditions" pattern is what keeps false positives near zero.
- **`condition: or`** inside the word matcher = any one of the common keys triggers it.
- **The extractor** surfaces the actual leaked value in your report — proof of impact.

**Validate and run it:**
```bash
nuclei -validate -t exposed-env-file.yaml                       # check syntax
nuclei -u https://your-lab-target -t exposed-env-file.yaml -v   # run it (verbose)
```

**Iterate:** run against a lab target, use `-v -debug` to see the exact request/response, and tighten matchers until it fires only on real hits. Then read the official templates for advanced patterns (raw requests, DSL, interactsh, multi-step) — reading them is the fastest way to learn. You now understand the whole tool: *fill in `id` + `info` + a protocol block + matchers (+ extractors), and the engine does the rest.*

---

## 19. Reading the Output

Default finding format:
```
[template-id] [protocol] [severity] matched-url [extracted-data]
```
- **`template-id`** — which check fired (often a CVE ID or descriptive name); look it up in the repo to see exactly what it tested.
- **`protocol`** — `http`, `dns`, `tcp`, etc.
- **`severity`** — `info`/`low`/`medium`/`high`/`critical` — your triage priority.
- **matched-url** — where it fired.
- **extracted-data** (if any) — the leaked value/version the extractor pulled.

**Triage discipline:**
- **`critical`/`high`** — investigate first; verify and (in scope) confirm exploitability. Nuclei's templates are precise, but **still verify criticals** before reporting.
- **`info`** — context (tech detected, WAF present, missing headers) — useful for the report and next steps, not vulnerabilities themselves.
- Use **`-jsonl`/`-sarif-export`/`-markdown-export`** for tooling, CI gating, or reports; **`-store-resp`** to keep raw responses as evidence.

Because templates are transparent YAML, when a finding is unclear, **open the template** and read exactly what it sent and matched — a big advantage over black-box scanners for validating results.

---

## 20. Performance, Rate Limiting, and Safety

Nuclei can run thousands of templates against thousands of hosts — powerful, and unthrottled, abusive.

- **`-rate-limit <n>`** — cap requests/second (default 150). The primary throttle.
- **`-concurrency <n>`** (`-c`, default 25) — templates run in parallel.
- **`-bulk-size <n>`** — hosts scanned per template in parallel.
- **`-timeout` / `-retries`** — tune for slow/flaky targets.
- **`-project`** — cache and **de-duplicate** identical requests across templates (request clustering) — big speedup, less load.
- **`-exclude-tags dos`** — skip Denial-of-Service templates on fragile/production targets.
- **`-as` / workflows / tag scoping** — run fewer, more relevant templates to cut time and noise.

**Reading the signs:** if the target starts erroring or a WAF begins blocking, lower `-rate-limit`/`-c`, scope tighter, or stop. Nuclei's speed is borrowed from the target's capacity — and be especially careful with **`-dast`** (fuzzing multiplies volume) and **`-headless`** (heavy browser requests).

---

## 21. Where It Fits: Workflow and Chaining

Nuclei is the **"fast pass for known issues"** stage — after discovery, feeding manual/deep testing.

```
[ subdomain enum ] → [ port scan ] → [ httpx: live hosts + tech ]
                                             │
                                             ▼
                                       [ NUCLEI ]  ← known-issue templates at scale
                                             │      (CVEs, exposures, misconfigs, takeovers, default logins)
                                             │      + interactsh confirms blind vulns
                                             │      + -dast fuzzes params for unknown vulns
                                             ▼
         findings → verify + [ Burp / ZAP ]   deep manual testing
                  → [ sqlmap ]                 exploit confirmed SQLi
                  → [ WPScan / Nikto ]         specialist follow-up
```

**Relationship to the tools you've studied:**
- **httpx feeds it** — `httpx -l hosts.txt -silent | nuclei` is a classic one-liner.
- **complements Nikto/WPScan** — Nuclei is broader and community-updated; lead with Nuclei, use Nikto (server config) and WPScan (WordPress depth) for their specialties. Running all catches more.
- **feeds Burp/sqlmap** — a Nuclei finding is the lead you confirm/exploit manually in Burp or sqlmap. Route Nuclei through Burp (`-proxy`) to capture its traffic.
- **imports from Burp** — `-im burp -dast` fuzzes real requests you captured in Burp.
- **shares the OAST concept** — interactsh is Nuclei's Burp-Collaborator for blind bugs.

**The discipline:** *discover hosts → Nuclei for a fast, broad known-issue sweep (+ OAST, + optional DAST) → triage by severity → verify and deep-test the interesting findings manually.*

---

## 22. Limitations and Pitfalls

- **Finds mostly *known* issues.** Default templates detect things someone wrote a check for; it won't find a novel logic flaw (DAST mode helps for generic injection but isn't a substitute for manual testing or a crawler).
- **Not a crawler.** It tests the URLs/hosts you give it (plus template paths); pair with a crawler/httpx/content discovery for coverage.
- **Template quality varies.** Community templates range from excellent to sloppy; a weak matcher = false positives. Official/signed templates are vetted; **verify criticals** regardless.
- **Template trust is a real risk.** Templates are code (esp. `code`/`javascript`/`headless`). Only run signed official templates or ones you've audited (§14).
- **Loud at scale/DAST.** Thousands of templates or fuzzing = lots of traffic; WAFs/IDS notice. Throttle and scope.
- **Keep it updated.** Stale templates miss new CVEs and may misfire; `-update`/`-ut` regularly.
- **Info-severity noise.** Default runs surface many `info` findings; scope with severity/tags for signal.

---

## 23. Legal and Ethical Note

- **Nuclei is active, high-volume testing** — it sends attack-flavored requests (and, with `-dast`, injects payloads) across potentially many hosts. Intrusive and easily disruptive.
- **Only scan systems you own or are explicitly authorized to test** — signed rules of engagement, an in-scope bug-bounty target that permits automated scanning (some restrict rate or forbid certain template categories — **read the rules**), or your own lab. Mass-scanning arbitrary internet hosts is a legal and ethical line.
- **Mind DoS and code templates.** Exclude `dos` tags on fragile/production targets; treat `-code`/`-headless`/unsigned templates with caution — they can execute code or generate heavy load.
- **Interactsh callbacks leave your marker on external infrastructure** — use a self-hosted interactsh server where privacy matters, and stay in scope.
- **Verify before reporting.** A Nuclei hit is a strong lead, not always a confirmed, exploitable finding — reproduce criticals before claiming them.
- **Practice legally:** run Nuclei against intentionally vulnerable targets — **OWASP Juice Shop**, **DVWA**, **VAmPI**, vulnerable VMs, or HTB/THM boxes — and **write your own templates** against them to learn the format safely.

---

### Where to go next

- Install Nuclei, `-ut` the templates, and run `nuclei -u <lab-target> -as` — watch it fingerprint the tech and fire only relevant checks. Then open one template it ran and trace exactly what it sent and matched (§4) — reading templates is the fastest way to *get* Nuclei.
- **Write the `.env` template** from §18 against a lab target, break it and fix it with `-v -debug`, and tighten the matchers. Writing one template teaches more than running a thousand.
- Wire the recon chain: `httpx -l hosts.txt -silent | nuclei -severity critical,high -stats`, then take any lead into **Burp/sqlmap** — connecting Nuclei to the tools you've already learned into one real workflow.

*End of reference.*

# Nikto — The Complete Reference (Beginner → Advanced)

> A ground-up reference for the **Nikto** web server scanner: what it finds, exactly **how** it finds it, every option and tuning/evasion class, and how to read (and distrust) its output.

---

## Table of Contents

1. [What Nikto Is and Why It Exists](#1-what-nikto-is-and-why-it-exists)
2. [Status and Key Facts](#2-status-and-key-facts)
3. [What Nikto Is NOT (Set Expectations)](#3-what-nikto-is-not-set-expectations)
4. [How Nikto Works Internally](#4-how-nikto-works-internally)
5. [The 404 / False-Positive Baseline Problem (Core Concept)](#5-the-404--false-positive-baseline-problem-core-concept)
6. [The Check Databases and What "Signature-Based" Means](#6-the-check-databases-and-what-signature-based-means)
7. [The Concepts Behind the Discoveries (Category by Category)](#7-the-concepts-behind-the-discoveries-category-by-category)
8. [Installation](#8-installation)
9. [Command-Line Options (Full Breakdown)](#9-command-line-options-full-breakdown)
10. [Tuning: Selecting Test Categories (-Tuning)](#10-tuning-selecting-test-categories--tuning)
11. [Evasion: LibWhisker IDS-Evasion Techniques (-evasion)](#11-evasion-libwhisker-ids-evasion-techniques--evasion)
12. [Plugins](#12-plugins)
13. [Output Formats and Reporting](#13-output-formats-and-reporting)
14. [Worked Examples with Output, Explained](#14-worked-examples-with-output-explained)
15. [Interactive Scan Controls](#15-interactive-scan-controls)
16. [Updating the Databases](#16-updating-the-databases)
17. [Interpreting Results and Handling False Positives](#17-interpreting-results-and-handling-false-positives)
18. [Where It Fits: Workflow and Chaining](#18-where-it-fits-workflow-and-chaining)
19. [Noise, WAF/IDS, and When Not to Use It](#19-noise-wafids-and-when-not-to-use-it)
20. [Legal and Ethical Note](#20-legal-and-ethical-note)

---

## 1. What Nikto Is and Why It Exists

**Nikto** is a free, open-source **web server scanner**. You point it at a web server and it fires thousands of HTTP requests to check for **known dangerous files, default/backup files, outdated server software, insecure configurations, and other well-known problems** — then reports what it found with references.

Created by **Chris Sullo** in 2001 and co-maintained for years by **David Lodge**, it's written in **Perl**, built on the **LibWhisker2 (LW2)** HTTP library, and comes pre-installed on Kali, Parrot, and BlackArch. It's one of the oldest and most recognizable tools in the field.

**Why it exists / the problem it solves:** once you've found a live web server, you want a fast answer to *"is this box running anything obviously old, misconfigured, or leaving well-known dangerous files exposed?"* Manually requesting hundreds of known-bad paths (`/phpinfo.php`, `/admin/`, `/.git/`, `/backup.zip`, default install files) and checking version banners against known-vulnerable releases would take hours. Nikto automates that entire "known-bad checklist" in one command. It's a **reconnaissance/triage** tool: a quick, broad first pass that flags leads for deeper investigation.

Think of it as running down a giant checklist of *"things that are commonly wrong with web servers,"* very fast and very loudly.

---

## 2. Status and Key Facts

- **Actively maintained.** The current stable release is **Nikto 2.6.0 (February 2026)**, with ongoing commits and database updates from Sullo and Lodge. (The prior milestone, 2.5.0, folded in hundreds of updates over several years — IPv6 support, updated DB formats, new flags like `-usecookies`, `-followredirects`, `-noslash`, and removal of old false-positive-prone tests.)
- **Language/engine:** Perl, on **LibWhisker2** (by Rain Forest Puppy) — which also provides its IDS-evasion features. Runs anywhere Perl runs.
- **License nuance worth knowing:** the **Nikto code is GPL**, but the **data files** (the check databases) historically are **not** fully free — their development has been supported via commercial partnership (Invicti/Netsparker). The engine is open; the "intelligence" (checks) is curated.
- **Scale of checks:** on the order of **6,700–8,000+** potentially dangerous/interesting files and programs, outdated-version checks for **1,250+** servers, and version-specific problems on **270+** servers — continually updated.
- **Repo/site:** `github.com/sullo/nikto` and `cirt.net/Nikto2`. Official Docker images exist (`ghcr.io/sullo/nikto`, `hackllc/nikto`).
- **UA behavior (recent):** newer versions use a **static Chrome User-Agent by default** (they stopped rotating the UA on every request) for more stable responses.

---

## 3. What Nikto Is NOT (Set Expectations)

This is the most important framing to get right, and where beginners misjudge the tool:

**Nikto tests the web *server*, not the web *application*.** It does **not**:

- **Crawl/spider** the application to discover its real pages and parameters.
- **Log in** or handle complex authentication to forms.
- **Execute JavaScript** or understand single-page apps (React/Angular/Vue).
- **Submit forms** or follow the app's own workflows.
- **Test business logic**, access control, or app-specific injection in a deep, context-aware way.

Contrast with a **DAST** tool (Burp Scanner, ZAP Active Scan): those crawl and probe the *application's* inputs for SQLi/XSS/logic flaws. Nikto instead checks the *server's* surface — known files, version banners, methods, headers, misconfigurations — against a **signature database** of known issues.

**The correct mental model:** Nikto is a **fast, broad, signature-based reconnaissance pass** over a web server. It surfaces *leads* ("this looks old," "this default file exists," "this method is enabled") that you then verify and pursue with Burp/ZAP/Nuclei and manual testing. It is **not** a final vulnerability list, and it is **not** a replacement for an application scanner. Used with those expectations, it's excellent; used as a one-shot "am I secure?" button, it will mislead you (both false positives and false negatives).

---

## 4. How Nikto Works Internally

Nikto's scan is a fairly linear pipeline. Understanding it makes every option and output line click.

1. **Target setup.** Parse the host, port, and protocol (HTTP/HTTPS). Establish the connection (LibWhisker handles the HTTP/SSL).
2. **Server fingerprinting.** Send baseline requests and read the `Server` header, response headers, error pages, favicon, and content to **identify the web server and technologies** (Apache/nginx/IIS, versions, frameworks). Many later checks are **conditional on this fingerprint** — Nikto runs IIS checks against IIS, Apache checks against Apache, etc.
3. **404 / "not found" baselining.** Before hunting for files, Nikto learns **what "this resource doesn't exist" looks like** on *this* server (see §5 — this is the key concept). Without it, every check would false-positive.
4. **Database-driven checks.** Nikto iterates its **check databases** (`db_tests` and friends). Each check is essentially *"request path X (optionally with method M); if the response matches condition C, report issue Y with reference R."* It sends the requests, compares responses against the 404 baseline and each check's match condition, and records hits.
5. **Category/tuning filter.** Only checks whose **tuning category** is enabled (see §10) actually run — this scopes the scan.
6. **Specialized checks & plugins.** Additional logic runs via plugins: HTTP methods/OPTIONS, headers, `robots.txt`, directory indexing, SSL details, cookies, apache user enumeration, etc. (§12).
7. **Evasion (optional).** If `-evasion` is set, LibWhisker mangles the outgoing requests to try to slip past IDS/WAF signatures (§11).
8. **Reporting.** Print findings live and write reports in the requested format(s) (§13).

**Key properties:**

- **It's request-heavy and linear** — a full scan can be **thousands to tens of thousands of requests**, which is why it's slow-ish and *loud* (§19).
- **Checks are largely independent** — Nikto isn't reasoning about the app; it's running a checklist where each item is a request+match rule.
- **Fingerprint gates checks** — accurate server identification improves relevance; behind a CDN/reverse proxy (which changes the `Server` header and 404 behavior), accuracy drops and false positives rise.

---

## 5. The 404 / False-Positive Baseline Problem (Core Concept)

This is the single most important concept for trusting Nikto's output, so understand it well.

Nikto's core activity is **requesting known-bad paths and seeing if they exist.** The naive logic is: *"if `GET /phpinfo.php` returns `200 OK`, the file exists."* But that logic breaks on real servers because of **soft 404s**:

- Many apps/servers return **`200 OK` for everything**, serving a friendly "page not found" HTML page instead of a real `404` status. A framework catch-all route, a SPA that returns `index.html` for any path, or a custom error page all do this.
- Reverse proxies, WAFs, and CDNs often return **consistent `200`/`302`** responses regardless of path.

If Nikto trusted status codes alone, it would report **every** path in its database as "found" — thousands of false positives.

**How Nikto defends against this (baselining):** before running file checks, Nikto **requests a random, guaranteed-nonexistent path** (e.g., `/nikto-1234567890random.html`). Whatever comes back is the server's **"this doesn't exist" fingerprint** — its status code, its content length, and characteristic strings in the body. Nikto then treats a check as a **hit only if the response *differs* from that baseline** in a meaningful way (different length, different content, different status). So a "found file" means *"this response looks materially different from a known-nonexistent one,"* not merely *"status was 200."*

**Why you still see false positives:** the baseline heuristic is imperfect. Dynamic pages whose length varies, personalized content, A/B testing, rotating banners, and aggressive CDNs can all make legitimate-nonexistent responses vary enough to fool the comparison. That's why **Nikto output is leads, not conclusions** — every "interesting" finding must be **manually verified** (open the URL yourself; §17).

You can help Nikto here with `-404code` (treat specific codes as "not found") and `-404string` (treat responses containing a given string as "not found"), which is invaluable against servers with weird soft-404 behavior.

---

## 6. The Check Databases and What "Signature-Based" Means

Nikto is **signature/database-driven.** Its "knowledge" lives in plain-text database files (in the `databases/` directory), not in the code. This is why it can be updated without changing the program.

**Notable databases:**

- **`db_tests`** — the main check list. Each row encodes: a **test id**, the **tuning category**, the **HTTP method**, the **URI/path** to request, a **match string / condition**, and the **message + references** to report on a hit. This file *is* the bulk of what Nikto looks for.
- **`db_variables`** — reusable variables (e.g., lists of CGI directories, default admin paths) expanded into many concrete requests.
- **`db_404_strings`** / **`db_content_search`** — strings used for soft-404 detection and content-based matching.
- **`db_server_msgs`** — maps server banners/versions to known issues.
- **`db_outdated`** — known "current" versions so Nikto can flag **outdated** software.
- **`db_httpoptions`**, **`db_realms`**, **`db_favicon`** — HTTP method checks, auth realms, favicon fingerprints (identify software by its favicon hash), etc.

**What "signature-based" means in practice:** Nikto finds **what it has a signature for**. It will not discover a novel vulnerability, a custom app's logic flaw, or an unknown file. It excels at the **known-bad checklist**: default files that ship with software, historically dangerous CGIs, well-known admin paths, backup-file naming conventions, version-to-known-vuln mappings. Its power and its ceiling are both defined by that database. Keep the database updated (§16) or you're scanning with a stale checklist.

---

## 7. The Concepts Behind the Discoveries (Category by Category)

Here's *how* Nikto actually detects each class of finding — the reasoning behind the report line.

### 7.1 Server and software fingerprinting
**Concept:** identify the server/tech so checks are relevant and version-based flags are possible. **How:** read the `Server` header and other response headers (`X-Powered-By`, `X-AspNet-Version`), analyze error-page wording, and hash the **favicon** to match known software. **Report:** `+ Server: nginx/1.18.0`. This underpins everything else — and is easily spoofed or hidden behind proxies, so treat the fingerprint as a hint.

### 7.2 Outdated version detection
**Concept:** old software = known CVEs. **How:** compare the fingerprinted version against Nikto's `db_outdated` "known current" data; if the target's version is older, flag it and cite references. **Report:** `+ Apache/2.4.29 appears to be outdated (current is at least 2.4.x).` **Caveat — the big false-positive source here:** many distros **backport security fixes** without changing the version string (e.g., Debian's `2.4.29` may be fully patched). So "outdated" from a banner is a *lead to check*, not proof of vulnerability. Also, banners are trivially edited/removed.

### 7.3 Dangerous/known files, CGIs, default and backup files
**Concept:** software ships with sample/admin/test files, and admins leave backups; many are dangerous or leak info. **How:** request each known path from the database and compare against the 404 baseline (§5). Targets include default install files (`/icons/README`, IIS sample apps), admin panels (`/admin/`, `/manager/html`), info leaks (`/phpinfo.php`, `/server-status`, `/.git/`, `/.env`), and backups (`index.php.bak`, `backup.zip`, `.old`, `~` files). **Report:** `+ /icons/README: Apache default file found.` / `+ /phpinfo.php: Output from phpinfo() found.`

### 7.4 Directory indexing and multiple index files
**Concept:** a directory with no index file may **list its contents** (directory listing), exposing files not meant to be browsed; multiple index files can indicate misconfig. **How:** request directories and detect listing markers ("Index of /") in the response. **Report:** `+ /backup/: Directory indexing found.`

### 7.5 Dangerous HTTP methods
**Concept:** methods beyond GET/POST can be abused. **How:** send `OPTIONS` to read the `Allow` header, and probe methods directly. Nikto flags:
- **PUT / DELETE** — if enabled and unauthenticated, may allow **uploading or deleting files** (potential webshell upload).
- **TRACE** — enables **Cross-Site Tracing (XST)**, a way to read otherwise-protected headers/cookies via reflected TRACE.
- **CONNECT** — may allow the server to be used as a proxy.
**Report:** `+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE` and a specific note if TRACE/PUT is dangerous.

### 7.6 Insecure and interesting headers / missing security headers
**Concept:** headers reveal info or, when missing, leave client-side protections off. **How:** inspect response headers. Nikto flags **missing** `X-Frame-Options` (clickjacking), `X-Content-Type-Options` (MIME sniffing), `Strict-Transport-Security`, `Content-Security-Policy`, and **present-but-leaky** headers (server/version banners, `X-Powered-By`, uncommon custom headers). **Report:** `+ /: The X-Frame-Options header is not present.` These are low-severity, high-frequency findings — useful hygiene notes, rarely the "win."

### 7.7 Information disclosure
**Concept:** servers leak paths, versions, internal IPs, emails, stack traces, and config in error pages, comments, and specific files. **How:** request known info-leak files and pattern-match responses for tell-tale strings. **Report:** e.g., `robots.txt` entries worth reviewing (they often *name* sensitive paths the admin wanted hidden), `server-status`/`server-info` exposure, verbose errors.

### 7.8 SSL/TLS checks
**Concept:** certificate and TLS details matter. **How:** on HTTPS, Nikto reads and reports the **certificate subject/issuer, ciphers**, and basic TLS info, and can note weak configurations. **Report:** an `SSL Info` block. (For deep TLS analysis, pair with `sslscan`/`testssl.sh` — Nikto's SSL checks are basic.)

### 7.9 Cookies
**Concept:** cookie flags and content matter for session security. **How:** capture `Set-Cookie` headers and report cookies received (and can decode some known cookie formats, e.g., Netscaler). **Report:** cookies with a note to review flags (`HttpOnly`, `Secure`, `SameSite`).

**The unifying idea:** every Nikto discovery is **request a known thing → compare the response against a baseline/pattern → map to a database entry with a reference.** It's a fast, broad pattern-matcher over well-known web-server problems — powerful for coverage of the *known*, blind to the *novel*, and prone to false positives that you must verify.

---

## 8. Installation

Nikto needs a **Perl** environment (present on most Unix-like systems). Dependencies are minimal; SSL support needs `Net::SSLeay`.

**Git (recommended — newest checks):**
```bash
git clone https://github.com/sullo/nikto.git
cd nikto/program
./nikto.pl -h http://www.example.com
# or, if not executable:
perl nikto.pl -h http://www.example.com
```

**Kali/Parrot (pre-installed or via apt):**
```bash
sudo apt install nikto
nikto -h http://www.example.com
```

**Docker (no local Perl needed):**
```bash
docker pull ghcr.io/sullo/nikto:latest
docker run --rm ghcr.io/sullo/nikto -h http://www.example.com
# Save a report by mounting a volume:
docker run --rm -v $(pwd):/tmp ghcr.io/sullo/nikto -h http://www.example.com -o /tmp/out.json
```

The main script lives in `program/nikto.pl`; the databases and config (`nikto.conf`) live alongside it. `nikto.conf` lets you set defaults (proxy, default plugins, `RFIURL`, etc.).

---

## 9. Command-Line Options (Full Breakdown)

Grouped by purpose. (Nikto options are **case-sensitive** — `-p` port vs `-P`; `-t` timeout vs `-T` tuning-ish; mind the case.)

### Target
| Option | Purpose |
|---|---|
| `-h, -host <host/IP/URL/file>` | Target host, URL, or a **file of hosts**. Accepts full URLs. |
| `-p, -port <n[,n...]>` | Port(s) to scan (default 80). Can be a list/range. |
| `-ssl` | Force SSL/HTTPS on the port. |
| `-nossl` | Force plain HTTP (disable SSL). |
| `-vhost <name>` | Set the `Host:` header (virtual host) independent of the IP — essential for name-based vhosts and CDNs. |
| `-root <path>` | Prepend a base path to all requests (scan an app in a subdirectory). |
| `-noslash` | Don't add a trailing slash to directory requests. |

### Scan control
| Option | Purpose |
|---|---|
| `-Tuning <x>` | **Select which test categories run** (see §10). Big lever for speed/scope. |
| `-Plugins <list>` | Choose which plugins run (see §12). |
| `-mutate <n>` | **Mutation** techniques: aggressively generate guesses (brute directories/files, username enum, subdomains, etc.). Much slower/louder. |
| `-maxtime <time>` | Cap total scan time (e.g., `-maxtime 300s` or `1h`). |
| `-Pause <n>` | Seconds to pause **between requests** (throttle to be gentler/stealthier). |
| `-timeout <n>` | Per-request timeout (default 10s). |
| `-followredirects` | Fetch and test the targets of 3xx redirects. |
| `-usecookies` | Send cookies received back on later requests (stateful-ish behavior). |
| `-404code <codes>` | Treat these status codes as "not found" (fix soft-404s). |
| `-404string <str>` | Treat responses containing this string as "not found." |
| `-until <time>` | Run until a clock time. |

### Evasion & network
| Option | Purpose |
|---|---|
| `-evasion <ids>` | Apply LibWhisker **IDS-evasion** techniques (see §11). |
| `-useproxy <url>` | Route through an HTTP proxy (e.g., through Burp: `-useproxy http://127.0.0.1:8080`). |
| `-useragent <str>` | Set a custom User-Agent. |
| `-nolookup` | Skip reverse DNS lookups. |

### Authentication
| Option | Purpose |
|---|---|
| `-id <user:pass[:realm]>` | HTTP Basic/NTLM auth credentials for protected areas. |

### Output & reporting
| Option | Purpose |
|---|---|
| `-o, -output <file>` | Write results to a file (format inferred from extension or `-Format`). |
| `-Format <fmt>` | Report format: `csv, json, htm, nbe, sql, txt, xml`. |
| `-Save <dir>` | Save **actual response** files to a directory (for evidence/analysis). |
| `-Display <flags>` | Control what's shown live (verbose `V`, redirects `2`/`3`, cookies `C`, etc.). |

### Maintenance & info
| Option | Purpose |
|---|---|
| `-update` | Update the plugins and databases from the source. |
| `-dbcheck` | Sanity-check the databases for syntax errors. |
| `-list-plugins` | List available plugins and exit. |
| `-Version` | Show version of Nikto, plugins, and databases. |
| `-config <file>` | Use an alternate config file. |
| `-H, -Help` | Full help. |

**Common ergonomics:** `-h` target, `-p` port(s), `-ssl` if HTTPS, `-o report.html` to save, `-Tuning` to scope, `-useproxy` to watch/replay traffic in Burp, `-Display V` for verbosity.

---

## 10. Tuning: Selecting Test Categories (-Tuning)

`-Tuning` controls **which classes of tests run**, by category id. This is your main lever to make a scan **faster, quieter, or targeted** at a specific concern. Combine ids (e.g., `-Tuning 123b`).

| Id | Category |
|---|---|
| `0` | File Upload |
| `1` | Interesting File / Seen in Logs |
| `2` | Misconfiguration / Default File |
| `3` | Information Disclosure |
| `4` | Injection (XSS/Script/HTML) |
| `5` | Remote File Retrieval — Inside Web Root |
| `6` | Denial of Service |
| `7` | Remote File Retrieval — Server-Wide |
| `8` | Command Execution / Remote Shell |
| `9` | SQL Injection |
| `a` | Authentication Bypass |
| `b` | Software Identification |
| `c` | Remote Source Inclusion |
| `x` | **Reverse** — treat the given ids as the ones to **exclude** (run everything else) |

**Examples:**
```bash
# Only misconfig + info disclosure + software id (fast, low-risk recon)
nikto -h https://target -Tuning 23b

# Everything EXCEPT Denial of Service (avoid the risky category)
nikto -h https://target -Tuning x6
```

**Why it matters:** the DoS category (`6`) can actually disrupt a fragile target — often excluded with `-Tuning x6`. Scoping to `2,3,b` gives a quick, safe fingerprint/misconfig pass. Enabling the injection/RCE categories makes Nikto noisier and more intrusive. (Note: some builds add categories like `d` WebService and `g` Generic — check `-H` on your version.)

---

## 11. Evasion: LibWhisker IDS-Evasion Techniques (-evasion)

Because Nikto rides on **LibWhisker (LW2)**, it inherits Rain Forest Puppy's classic **anti-IDS request-mangling** techniques. These rewrite the *form* of a request so it still means the same thing to the web server but **doesn't match signature-based IDS/WAF rules** looking for literal strings. Combine multiple with `-evasion` (e.g., `-evasion 1237`).

| Id | Technique | Idea |
|---|---|---|
| `1` | Random URI (non-UTF8) encoding | Percent-encode characters so `/etc/passwd` doesn't appear literally. |
| `2` | Directory self-reference `/./` | Insert `/./` — same path, different bytes (`/cgi-bin/./test`). |
| `3` | Premature URL ending | Trick some parsers with an early apparent end of the URL. |
| `4` | Prepend long random string | Pad the request to disrupt signature offsets. |
| `5` | Fake parameter | Add a bogus query parameter to change the request shape. |
| `6` | TAB as request spacer | Use a TAB instead of space between method/URI/version. |
| `7` | Change case of URL | `/CGI-BIN/` vs `/cgi-bin/` — bypasses case-sensitive signatures. |
| `8` | Windows directory separator `\` | Use `\` instead of `/` where the server accepts it. |
| `A` | Carriage return (0x0d) as spacer | Use `\r` as a separator. |
| `B` | Binary 0x0b as spacer | Use a vertical-tab byte as a separator. |

**The concept:** signature-based defenses often match **exact byte patterns** (e.g., an alert for the literal string `/etc/passwd` or `cmd.exe`). By **encoding, re-casing, or inserting semantically-neutral characters**, the request evades the literal match while the target still processes it normally. This is a foundational lesson in **why input normalization matters** on the defensive side.

**Honest limitations:** these are **1999-era tricks against signature IDS.** Modern WAFs normalize/decode requests before matching, so evasion `1`/`2`/`7` etc. often won't fool them. And evasion does nothing about Nikto's **volume** — thousands of requests to known-bad paths from a static UA is itself a glaring signal (§19). Treat `-evasion` as educational and situationally useful, not a cloak of invisibility.

---

## 12. Plugins

Nikto's functionality is modular; many checks are **plugins**. List them with:
```bash
nikto -list-plugins
```
Select specific ones with `-Plugins`. Notable plugins:

- **`headers`** — analyze HTTP response headers (security headers, leaks).
- **`httpoptions`** — enumerate allowed HTTP methods (OPTIONS/PUT/DELETE/TRACE).
- **`cookies`** — capture and analyze cookies.
- **`robots`** — fetch and report `robots.txt` entries (often names sensitive paths).
- **`apacheusers`** — attempt to enumerate Apache usernames.
- **`sitefiles`** / **`paths`** — check for common interesting files/directories.
- **`favicon`** — identify software by favicon hash.
- **`report_*`** — the reporting plugins for each output format (`report_html`, `report_json`, `report_xml`, `report_csv`, etc.).
- **`ms10_070`** and other **version/CVE-specific** checks.

(Note: the old **dictionary/brute** plugin was removed in recent versions to reduce noise/false positives — use dedicated tools like `ffuf`/`gobuster` for directory brute-forcing instead.)

---

## 13. Output Formats and Reporting

Nikto writes reports in several formats via `-o <file>` (extension auto-detected) or explicit `-Format`:

| Format | Use |
|---|---|
| `txt` | Plain text (default, human-readable). |
| `htm` | Styled HTML report (nice for sharing). |
| `csv` | Spreadsheet-friendly rows. |
| `json` | Structured — pipe into other tooling/dashboards. |
| `xml` | Structured XML. |
| `nbe` | Nessus format (import alongside Nessus data). |
| `sql` | SQL insert statements for a database. |

```bash
nikto -h https://target -o report.html            # HTML (inferred)
nikto -h https://target -o report.json -Format json
```

Newer Nikto supports **multiple report formats from a single scan**. Use `-Save <dir>` to also dump the **raw responses** Nikto received for findings — useful as evidence and for manual re-examination. (Note: 2.5+ introduced breaking changes to JSON/XML schemas — if you parse these programmatically, re-verify against your Nikto version.)

---

## 14. Worked Examples with Output, Explained

> Output below is **representative** of Nikto's format. Real findings vary by target.

### 14.1 Basic scan

```bash
nikto -h https://www.example.com
```

Representative output:
```
- Nikto v2.6.0
---------------------------------------------------------------------------
+ Target IP:          93.184.216.34
+ Target Hostname:    www.example.com
+ Target Port:        443
+ SSL Info:        Subject:  /CN=www.example.com
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=US/O=DigiCert Inc/CN=DigiCert TLS RSA SHA256 2020 CA1
+ Start Time:         2026-09-14 10:22:31 (GMT0)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render content differently (MIME sniffing).
+ /robots.txt: contains 12 entries which should be manually viewed.
+ /admin/: This might be interesting.
+ /icons/README: Apache default file found.
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
+ nginx/1.18.0 appears to be outdated (current is at least 1.25.x).
+ 7834 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2026-09-14 10:29:02 (GMT0) (391 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

**Reading it, line by line:**
- **Header block** — resolved IP, hostname, port, and (for HTTPS) an **SSL Info** block with cert subject/issuer/ciphers.
- **`+ Server: nginx/1.18.0`** — the fingerprint (§7.1); everything version-based depends on it.
- **`X-Frame-Options` / `X-Content-Type-Options` not present** — missing security headers (§7.6). Low severity, very common; hygiene notes.
- **`/robots.txt: contains 12 entries…`** — Nikto is telling you `robots.txt` lists paths the admin tried to hide — **go read them manually**, they often name admin/backup/staging paths.
- **`/admin/: This might be interesting.`** — a known-interesting path that responded differently from the 404 baseline. A **lead** — verify by opening it.
- **`/icons/README: Apache default file found.`** — a shipped default file (note it says Apache while Server says nginx → possible proxy in front; a hint the fingerprint is muddled).
- **`OPTIONS: Allowed HTTP Methods: …`** — method enumeration (§7.5). Here no dangerous methods; if `PUT`/`TRACE` appeared, that'd be flagged.
- **`nginx/1.18.0 appears to be outdated…`** — banner-based outdated flag (§7.2). **Verify** — could be backported/patched despite the version string.
- **Footer** — request count, errors, items reported, duration. `7834 requests` shows how *loud* even a basic scan is.

**Format of each finding:** `+ <path>: <message>` — path tested, then the human-readable issue (older versions appended `OSVDB-xxxx` references; newer ones use updated reference links).

### 14.2 Scoped, safer, saved report
```bash
nikto -h https://target.example.com -p 443 -Tuning x6 -o nikto_target.html -Display V
```
- `-Tuning x6` runs everything **except** Denial of Service (§10) — safer on fragile targets.
- `-o nikto_target.html` writes an HTML report.
- `-Display V` shows verbose live progress.

### 14.3 Through Burp, with vhost and throttling
```bash
nikto -h 203.0.113.10 -vhost app.example.com \
      -useproxy http://127.0.0.1:8080 \
      -Pause 1 -evasion 1 -o out.json
```
- `-vhost app.example.com` sets the `Host:` header so name-based virtual hosting resolves to the right app even though you gave an IP.
- `-useproxy …:8080` routes every request **through Burp**, so you can watch, log, and replay Nikto's traffic and manually investigate hits.
- `-Pause 1` adds a 1-second gap between requests (gentler, slightly stealthier).
- `-evasion 1` applies URI encoding evasion (§11).

### 14.4 Multiple hosts + specific port list
```bash
nikto -h hosts.txt -p 80,443,8080,8443 -o scan.csv -Format csv
```
Scan every host in `hosts.txt` across several common web ports, output CSV — a natural fit after a port scan (§18).

---

## 15. Interactive Scan Controls

While a scan runs, Nikto accepts **single-keypresses** to change behavior on the fly — handy on long scans:

| Key | Action |
|---|---|
| `Spacebar` | Report the **current scan status/progress**. |
| `v` | Toggle **verbose** mode. |
| `d` | Toggle **debug** mode. |
| `e` | Toggle **error** display. |
| `r` | Toggle **redirect** display. |
| `c` | Toggle **cookie** display. |
| `a` | Toggle **auth** display. |
| `n` / `N` | Skip to the **next host/target**. |
| `q` | **Quit** (writes the report so far). |

Press **Spacebar** any time you're wondering "is it stuck or just slow?" — it'll print how far along it is.

---

## 16. Updating the Databases

Nikto's usefulness depends on **fresh check databases** (§6). Update and sanity-check them:

```bash
nikto -update      # pull latest plugins and databases
nikto -dbcheck     # verify database files parse correctly (no syntax errors)
nikto -Version     # show versions of Nikto, plugins, and databases
```

Run `-update` periodically (or `git pull` if you installed from source, which is often the freshest path). **Licensing note (from §2):** while the engine is GPL, the check data is curated with commercial backing — so keep in mind the "intelligence" is maintained on its own cadence. Stale databases = you're checking against an old list of known-bad, missing newer defaults/CVEs.

---

## 17. Interpreting Results and Handling False Positives

**Golden rule: Nikto output is a list of *leads*, not confirmed vulnerabilities.** It is pattern-based and baseline-heuristic (§5–6), so false positives are routine — especially against **custom 404 pages, reverse proxies, CDNs, and WAFs**. Work findings like this:

1. **Manually open every "interesting"/"found" URL.** Confirm the file/path really exists and really matters. Half of Nikto's `This might be interesting` lines evaporate on inspection.
2. **Verify "outdated" flags out-of-band.** Check whether the version is genuinely vulnerable (CVE lookup) and whether the distro backported fixes. Don't report "outdated banner" as a vulnerability by itself.
3. **Watch for proxy/CDN confusion.** Mismatched signals (nginx `Server` header but "Apache default file found") mean something sits in front — recalibrate with `-vhost`, `-404code`, `-404string`.
4. **Tame soft-404s.** If Nikto reports hundreds of "found" files, the server likely returns `200` for everything. Set `-404code`/`-404string` to the real not-found signature and rescan.
5. **Cross-check with other tools.** Confirm methods with `curl -X OPTIONS`, TLS with `testssl.sh`, directories with `ffuf`, and app-level issues with Burp/ZAP.
6. **Prioritize by real impact:** exposed `.git`/`.env`/backup files, directory listings of sensitive dirs, dangerous methods (PUT), and genuinely vulnerable outdated software are the leads worth chasing; missing security headers are hygiene notes.

---

## 18. Where It Fits: Workflow and Chaining

Nikto is an **early, fast, broad pass** on a **known web server** — after you've found the server, before deep manual/app testing.

```
[ subdomain enum ]  →  [ port scan: nmap/naabu ]  →  find live web servers (httpx)
                                                              │
                                                              ▼
                                                    [ NIKTO ]  ← fast server-config triage
                                                              │  (known files, versions, methods, misconfig)
                                                              ▼
                        leads → verify manually + [ Burp / ZAP ]  ← deep app testing (crawl, auth, logic, injection)
                                                     [ Nuclei ]    ← templated CVE/exposure checks
                                                     [ ffuf/gobuster ] ← content discovery
                                                     [ testssl.sh ]   ← deep TLS analysis
```

**Why this order:** Nikto quickly tells you *"this server has obvious known issues / default files / old software / risky methods"* so you know where to dig, and it complements DAST tools that test the **application** rather than the **server**. Route Nikto through Burp (`-useproxy`) so its hits land in your Burp history for immediate follow-up. Nikto and Nuclei overlap somewhat (both signature-based); many workflows now lead with **Nuclei** for CVE/exposure templates and use Nikto for its broad classic checklist — running both catches more.

---

## 19. Noise, WAF/IDS, and When Not to Use It

**Nikto is loud by design — it makes no attempt to be stealthy in volume.**

- A scan is **thousands to tens of thousands of requests** to known-suspicious paths, from a recognizable pattern of behavior. Any IDS/WAF/log review will light up immediately, and Nikto's requests are themselves a well-known signature (defenders literally have "Nikto detected" rules).
- `-evasion` mangles request *form* but not *volume*, and modern WAFs normalize around most of those tricks (§11). `-Pause` and `-maxtime` reduce rate but not the fundamental footprint.
- On **fragile targets**, the DoS tuning category (`6`) or heavy `-mutate` runs can actually **disrupt service** — exclude DoS (`-Tuning x6`) and avoid aggressive mutation on production.

**When not to reach for Nikto:**
- When you need **stealth** — it will be detected.
- When the target is a **JavaScript SPA / API** — Nikto won't understand it; use Burp/ZAP and API-aware tools.
- When you need **application-logic / auth / injection depth** — that's DAST + manual testing territory.
- On **production systems you're worried about stability of**, without excluding DoS and throttling.

Use it for what it's great at: a **fast, authorized, broad server-config triage** where noise is acceptable.

---

## 20. Legal and Ethical Note

- **Nikto is actively intrusive.** It sends thousands of attack-flavored requests, probes for files, and (with some tuning categories) attempts injection/RCE-style checks. This is unambiguously **active testing**, not passive recon.
- **Only scan systems you own or are explicitly authorized to test** — a signed scope/rules of engagement, an in-scope bug-bounty target that permits automated scanning (many programs **forbid** noisy scanners like Nikto — check the rules), or your own lab.
- **It can disrupt fragile targets.** Exclude the DoS category and throttle on anything you care about; never point aggressive scans at production without permission and coordination.
- **Detection is likely and expected.** Because it's so loud, unauthorized use is easily traced. Keep it inside authorized scope.
- **Practice legally:** run Nikto against intentionally vulnerable targets — **OWASP Juice Shop**, **DVWA**, **Metasploitable**, or your own VMs — to learn its output and false-positive patterns safely.

---

### Where to go next

- Spin up **Metasploitable** or **DVWA** locally and run `nikto -h http://<lab-ip>` — a deliberately old/misconfigured target lights up with findings, so you can practice **verifying each lead manually** (the real skill).
- Re-run with `-useproxy http://127.0.0.1:8080` so every Nikto request lands in **Burp**, then investigate the interesting hits there — this bridges Nikto (server triage) into Burp (deep testing), exactly as in a real workflow.
- Experiment with `-Tuning` and `-404string` against a soft-404 server to *feel* how the baseline problem (§5) drives false positives — the single most useful intuition for reading Nikto output.

*End of reference.*

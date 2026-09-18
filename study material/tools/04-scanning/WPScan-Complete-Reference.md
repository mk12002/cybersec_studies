# WPScan — The Complete Reference (Beginner → Advanced)

> A ground-up reference for **WPScan**, the WordPress security scanner: the WordPress attack surface it targets, exactly **how** it fingerprints core/plugins/themes/users, how it maps them to known vulnerabilities, its brute-force capabilities, and how to read (and trust) its output.

---

## Table of Contents

1. [What WPScan Is and Why It Exists](#1-what-wpscan-is-and-why-it-exists)
2. [Status and Key Facts](#2-status-and-key-facts)
3. [Why WordPress Is Such a Big Target](#3-why-wordpress-is-such-a-big-target)
4. [WordPress Anatomy You Must Know](#4-wordpress-anatomy-you-must-know)
5. [How WPScan Works Internally](#5-how-wpscan-works-internally)
6. [The API Token and Vulnerability Database](#6-the-api-token-and-vulnerability-database)
7. [Detection Modes: Passive, Mixed, Aggressive](#7-detection-modes-passive-mixed-aggressive)
8. [The Concepts Behind the Discoveries](#8-the-concepts-behind-the-discoveries)
9. [Password Brute-Forcing (wp-login vs XML-RPC)](#9-password-brute-forcing-wp-login-vs-xml-rpc)
10. [Installation and API Token Setup](#10-installation-and-api-token-setup)
11. [Command-Line Options (Full Breakdown)](#11-command-line-options-full-breakdown)
12. [The --enumerate (-e) Options](#12-the---enumerate--e-options)
13. [Worked Examples with Output, Explained](#13-worked-examples-with-output-explained)
14. [Reading the Output](#14-reading-the-output)
15. [Evasion and Being Gentle](#15-evasion-and-being-gentle)
16. [Where It Fits: Workflow and Chaining](#16-where-it-fits-workflow-and-chaining)
17. [Limitations and Pitfalls](#17-limitations-and-pitfalls)
18. [Legal and Ethical Note](#18-legal-and-ethical-note)

---

## 1. What WPScan Is and Why It Exists

**WPScan** is a **black-box WordPress security scanner** written in Ruby. You point it at a WordPress site and it **fingerprints** what's running — the WordPress core version, installed plugins, installed themes, and user accounts — then **checks each of those against a curated database of known vulnerabilities** to tell you what's exploitable. It can also **brute-force login credentials** and flag common misconfigurations (exposed config backups, database dumps, enabled XML-RPC, etc.).

"Black-box" means it tests from the **outside**, like an attacker with no special access — it doesn't read the site's source code or need admin login; it infers everything from HTTP responses.

**Why it exists / the problem it solves:** WordPress powers **over 40% of all websites**, which makes it the single most attacked CMS on the internet. Its core is well-maintained and patched quickly — but its **ecosystem of 60,000+ plugins and thousands of themes** is a sprawling, uneven attack surface where most real-world WordPress compromises originate (an outdated plugin with a known CVE that the admin never updated). Manually determining "which of this site's 22 plugins are outdated and vulnerable" would mean fingerprinting each plugin's version and cross-referencing a vulnerability database by hand. WPScan automates exactly that: **enumerate everything, then map it to known vulnerabilities.** It's the de-facto standard tool for WordPress penetration testing.

---

## 2. Status and Key Facts

- **Actively maintained** and **owned by Automattic** (WordPress's parent company) since its **2021 acquisition** of the WPScan team. First released June 2011.
- **Language:** Ruby (distributed as a gem; the old `ruby ./wpscan.rb` era is gone). Current is the **v3.8.x** line. Pre-installed on **Kali/Parrot**; also via Ruby gem or **Docker**.
- **Licensing nuance:** WPScan's own docs state it is **"free for non-commercial use"** and **not Open Source** — commercial use requires a paid plan. The CLI code is on GitHub, but the **vulnerability database data is proprietary.**
- **Requires an API token for vulnerability data.** Register free at wpscan.com for a token; the **free plan allows 25 API requests/day** (non-commercial). WPScan makes **one API request for the WP version, one per plugin, and one per theme** — so an average site (~22 plugins) can consume most of your daily quota in a single scan. Without a token (or when quota is exhausted), WPScan **still enumerates and runs** — it just won't attach vulnerability data.
- **Token supply methods:** `--api-token <token>`, the `WPSCAN_API_TOKEN` environment variable, or a config file (`~/.config/wpscan/scan.yml`).

---

## 3. Why WordPress Is Such a Big Target

Understanding *why* WordPress deserves its own scanner explains what WPScan looks for.

- **Ubiquity → attacker ROI.** WordPress runs ~40%+ of the web. A single exploit for a popular plugin can be sprayed across **millions** of sites automatically. Attackers invest heavily here because scale makes it worthwhile.
- **Core is strong; the ecosystem is the weak point.** The WordPress *core* team patches quickly and auto-updates minor releases. But the security burden shifts to **third-party plugins and themes**, written by tens of thousands of independent developers of wildly varying skill, on their own (or no) update schedule. **Most WordPress breaches trace to an outdated, vulnerable plugin/theme**, not core.
- **Admins under-maintain.** Sites accumulate plugins over years; owners fear updates will break the site, so they don't. A plugin with a public CVE and a released fix may sit unpatched indefinitely — a standing, known, exploitable hole.
- **Predictable structure.** Every WordPress site has the same layout (`wp-admin`, `wp-content/plugins/`, `wp-login.php`, `xmlrpc.php`, etc.), so tooling can reliably fingerprint and attack it. That predictability is exactly what WPScan exploits to enumerate.
- **Weak credentials + exposed login.** `wp-login.php` and `xmlrpc.php` are public by default, and `admin`/weak passwords remain common → brute-forcing is viable.

**The takeaway:** the highest-value WordPress finding is usually *"this specific plugin is version X, and version X has a known CVE fixed in version Y."* WPScan's whole design is built to produce that sentence, at scale, reliably.

---

## 4. WordPress Anatomy You Must Know

WPScan navigates a **standard directory/URL structure** that's identical across WordPress sites. Knowing it makes every fingerprinting technique obvious.

| Path | What it is / why it matters |
|---|---|
| `/wp-login.php` | The **login page**. Target for credential brute force; its error messages can leak valid usernames. |
| `/wp-admin/` | The **admin dashboard** (requires auth). Its presence confirms WordPress. |
| `/wp-content/` | User content root. Contains: |
| `/wp-content/plugins/<slug>/` | **Installed plugins**, each in its own folder. Front-end pages reference these (CSS/JS), which leaks plugin presence. Each plugin ships a **`readme.txt`** with a `Stable tag:` line → **version disclosure**. |
| `/wp-content/themes/<slug>/` | **Installed themes**, similarly referenced and versioned (`style.css` header). |
| `/wp-content/uploads/` | Media uploads; may expose files, backups, or the site's date structure. |
| `/wp-includes/` | Core files (JS/CSS with `?ver=` query strings) → **core version fingerprinting**. |
| `/xmlrpc.php` | Legacy **remote API**. Enables `system.multicall` (brute-force amplification) and pingback (SSRF/DDoS) — a notable attack surface. |
| `/wp-json/` (REST API) | The **REST API**. `/wp-json/wp/v2/users` historically **enumerates usernames**. |
| `/readme.html` | Ships with core; often reveals the **major WordPress version**. |
| `/?author=1`, `/author/<name>/` | **Author archives** — requesting `?author=N` redirects to `/author/<username>/`, leaking usernames. |
| RSS/Atom feeds (`/feed/`) | Contain a **generator** tag and author names → version + usernames. |
| `<meta name="generator" content="WordPress X.Y">` | HTML meta tag → direct **core version** (often removed by hardening, but many other leaks remain). |

**The core insight:** WordPress leaks its version and components through *many* redundant channels — meta tags, feeds, readme files, asset version strings, static file checksums, plugin `readme.txt` files, REST API. Hardening can close *some* (remove the generator tag), but rarely *all*. WPScan checks them all and takes the most confident answer.

---

## 5. How WPScan Works Internally

The scan pipeline:

1. **Confirm it's WordPress** (unless `--force`) — check for the tell-tale paths/markers above.
2. **Fingerprint the core version** — from the generator meta tag, `readme.html`, RSS generator, `/wp-includes/` asset `?ver=` strings, and static-file checksums. Multiple sources → a confidence-rated version.
3. **Enumerate plugins** — **passively** (parse the HTML for `/wp-content/plugins/<slug>/` references) and/or **aggressively** (request known plugin slugs from a large wordlist and infer existence from responses). Detect each plugin's **version** (often from its `readme.txt` `Stable tag:` or static-file hashes).
4. **Enumerate themes** — same idea (references + slug brute force; version from `style.css`).
5. **Enumerate users** — via author-archive redirects, the REST API, RSS, login errors, oEmbed (§8.4).
6. **Detect misconfigurations** — XML-RPC enabled, config backups, DB exports, directory listings, TimThumbs, exposed media.
7. **Query the vulnerability database (API)** — for the core version and **each** identified plugin/theme, ask the WPScan API "any known vulnerabilities for this component at this version?" Map results to CVEs with **"fixed in"** versions.
8. **(Optional) brute force** — if `--passwords`/`--usernames` given, attempt logins via `wp-login.php` or `xmlrpc.php` (§9).
9. **Report** — print findings with **confidence**, **"found by"** method, references, and remediation ("fixed in") — in CLI or JSON.

**Key properties:**
- **Fingerprint accuracy is everything.** The vuln mapping is only as good as the detected version. Wrong/undetected version → missing or false vulnerabilities. This is why `-v` (verbose, shows detected versions) matters.
- **The API is the intelligence.** WPScan's code enumerates; the **database** turns "plugin X v5.4.1" into "vulnerable to CVE-xxxx." No token/quota → enumeration only, no vuln verdicts.
- **Enumeration depth vs noise** is a dial you control (detection modes, §7).

---

## 6. The API Token and Vulnerability Database

WPScan's discovery power comes from the **WordPress Vulnerability Database (WPVulnDB)** — a curated, continuously-updated feed of known vulnerabilities in WordPress core, plugins, and themes, maintained by the WPScan team (now under Automattic).

**How the token works:**
- Get a **free token** by registering at wpscan.com.
- Supply it via `--api-token`, the `WPSCAN_API_TOKEN` env var, or the config file.
- During a scan, WPScan makes **one API call per component**: 1 for the WP version + 1 per plugin + 1 per theme.
- **Free plan = 25 requests/day.** Because an average site has ~22 plugins, one thorough scan can nearly exhaust the free quota — the free tier realistically covers ~50% of sites once/day. Paid/Enterprise plans raise or remove the limit; Enterprise can use a **local database dump** (no request limit, and better privacy).

**Without a token (or after quota):** WPScan **keeps working** — it still fingerprints core, plugins, themes, users, and misconfigs — but it **won't tell you which are vulnerable**, because that judgment lives in the database. You'll get an inventory, not a vulnerability verdict.

**Config file example** (`~/.config/wpscan/scan.yml`) — keep the token out of your command history:
```yaml
cli_options:
  api_token: YOUR_TOKEN_HERE
  random_user_agent: true
  throttle: 500
```

**Why this matters conceptually:** WPScan splits **"what's installed"** (its own enumeration) from **"what's vulnerable"** (the external database). Both must be current: an accurate fingerprint against a **stale** database, or a **fresh** database against a **wrong** fingerprint, both give bad answers. Keep the tool updated (`wpscan --update`) and your fingerprints verified.

---

## 7. Detection Modes: Passive, Mixed, Aggressive

The central tradeoff in WPScan is **coverage vs noise**, controlled by detection modes. You can set an overall `--detection-mode` and finer-grained `--plugins-detection` / `--plugins-version-detection` (and theme equivalents).

- **Passive** — WPScan only **reads what the site volunteers**: it parses the HTML of pages it fetches for references to plugins/themes (their CSS/JS URLs). **Quiet and fast**, but **only finds components that emit front-end assets** on the pages it sees. A plugin that runs purely in the admin or emits nothing on the homepage is **invisible** to passive detection.
- **Aggressive** — WPScan **actively probes**: it requests **known plugin/theme slugs from a large wordlist** (thousands of paths) and infers existence from the responses (200 vs 404, redirect behavior, presence of `readme.txt`). **Finds "silent" components passive misses**, but sends **thousands of requests** — slow, very loud, and obvious in logs/WAF.
- **Mixed** — a blend: passive first, then targeted active probing. A reasonable default balance.

**When to use which:**
- **Passive/`--stealthy`** — when you must stay quiet, or for a fast first look.
- **Aggressive** — when thoroughness matters and noise is acceptable (authorized, robust target), especially to catch a vulnerable plugin that isn't referenced on the front end. **This is often necessary** — the vulnerable plugin is frequently one that *doesn't* advertise itself in the HTML, so passive-only scans give a false sense of safety.

**The concept:** passive detection answers "what does the site show me?"; aggressive answers "what does the site have, even if hidden?" The most dangerous plugin is often the hidden one, so real assessments usually need an aggressive plugin pass — at the cost of a lot of noise.

---

## 8. The Concepts Behind the Discoveries

How WPScan actually detects each thing — the reasoning behind every finding.

### 8.1 Core version fingerprinting
**Concept:** WordPress leaks its version through many redundant channels; hardening rarely closes them all. **How WPScan detects it:**
- **Meta generator tag** — `<meta name="generator" content="WordPress 6.4.2">` (often removed by hardening).
- **RSS/Atom feed generator** — feeds include a `<generator>` WordPress URL with version.
- **`readme.html`** — ships with core, reveals the major version.
- **Static asset version strings** — `/wp-includes/js/*.js?ver=6.4.2` query params.
- **File checksums** — hashes of known core files map to specific releases even when banners are stripped.
WPScan reports the version with a **confidence %** and the **"found by"** method. **Why it matters:** the version drives the entire vuln lookup — a stripped generator tag doesn't hide you if the asset versions or file hashes still leak it.

### 8.2 Plugin enumeration and version detection
**Concept (enumeration):** plugins live at `/wp-content/plugins/<slug>/`.
- **Passive:** front-end pages reference plugin CSS/JS (`/wp-content/plugins/contact-form-7/...`), revealing the slug.
- **Aggressive:** WPScan requests thousands of **known slugs** and infers presence from responses (a `200`/redirect on `/wp-content/plugins/<slug>/`, or a retrievable `readme.txt`).
**Concept (version):** WordPress plugins ship a **`readme.txt`** with a `Stable tag: 5.4.1` line — a reliable version source. WPScan also uses **changelogs** and **static-file hashes**. **Why it matters:** plugin+version is the highest-yield finding; the version determines whether a known CVE applies.

### 8.3 Theme enumeration and version detection
Same logic as plugins: themes at `/wp-content/themes/<slug>/`, referenced in HTML, version from **`style.css`** (which has a `Version:` header). Vulnerable themes are less common than plugins but do appear.

### 8.4 User enumeration
**Concept:** you can't attack an account without its username, and WordPress historically leaks usernames several ways. **How WPScan detects them:**
- **Author archive redirect** — requesting `/?author=1` **redirects to `/author/<username>/`**, disclosing the login name for user ID 1. Iterate IDs (`u1-10`) to map them.
- **REST API** — `/wp-json/wp/v2/users` returns a JSON list of users (unless disabled).
- **RSS feeds** — author names in post feeds.
- **Login error messages** — some configs say "invalid password for <user>" (confirming the user exists) vs "invalid username."
- **oEmbed** and other endpoints.
**Why it matters:** enumerated usernames feed directly into brute force (§9). `admin`, the author of most posts, and predictable names are prime spray targets.

### 8.5 Vulnerability mapping
**Concept:** this is the payoff. For the core version and **each** enumerated plugin/theme+version, WPScan queries the WPVulnDB API: *"known vulns for this component at this version?"* The DB returns entries with a **"Fixed in"** version. If the **detected version < fixed-in version**, the target is **vulnerable**, and WPScan reports the CVE(s) and references. **The whole result quality = fingerprint accuracy × database freshness.**

### 8.6 Misconfigurations and exposed files
WPScan also checks for classic WordPress exposures:
- **XML-RPC enabled** (`/xmlrpc.php`) — brute-force amplification + pingback abuse (§9).
- **Config backups** (`wp-config.php.bak`, `wp-config.php~`, `.wp-config.php.swp`) — **database credentials in cleartext** if exposed (critical).
- **Database exports** (`.sql` dumps) — full data leak.
- **TimThumb** scripts — historically RCE-prone image resizer.
- **Directory listing** enabled on `wp-content/`.
- **Full-path disclosure**, debug logs, backup archives.
These are found by requesting the known paths and checking responses (the same forced-browsing logic as feroxbuster, scoped to WordPress conventions).

---

## 9. Password Brute-Forcing (wp-login vs XML-RPC)

WPScan can brute-force WordPress logins given a **username list** and a **password wordlist**. This is where user enumeration (§8.4) and a targeted wordlist (e.g., from **CeWL**) pay off.

```bash
wpscan --url https://target --usernames admin,editor --passwords cewl_words.txt
```

**Two attack channels — and why XML-RPC is faster:**

- **`wp-login`** — submits each guess to the **`wp-login.php` form**, one HTTP request per attempt. Simple, but **slow** and very visible (one login POST per password).
- **`xmlrpc`** (the important one) — uses **`/xmlrpc.php`**, WordPress's legacy remote API. Its **`system.multicall`** method lets you bundle **many authentication attempts into a single HTTP request**. So instead of 1 password per request, you can try **hundreds per request** — an **amplification** that makes brute-forcing **orders of magnitude faster** and generates far fewer HTTP requests (quieter per-guess). WPScan picks this automatically when XML-RPC is enabled, or force it:

```bash
wpscan --url https://target -U users.txt -P passwords.txt --password-attack xmlrpc --max-threads 5
```

- **`--multicall-max-passwords`** tunes how many passwords per multicall request.

**Why XML-RPC matters conceptually:** it's a legacy feature enabled by default on many sites, and `system.multicall` was designed for efficiency, not abuse — but that efficiency is exactly what makes credential attacks (and pingback SSRF/DDoS) practical. Disabling XML-RPC is a common WordPress hardening step for this reason.

**The full credential-attack chain:** enumerate users (§8.4) → build a **targeted wordlist with CeWL** from the site's content → brute-force via XML-RPC. This connects three tools you've now studied into one attack.

> **Lockout & noise warning:** brute force can lock accounts and is loud. Know the lockout/security-plugin policy, throttle (`--throttle`), keep username/password lists focused, and only do this with authorization. Offline is impossible here (no hashes) — this is online, so caution is essential.

---

## 10. Installation and API Token Setup

WPScan needs **Ruby**. On Kali it's pre-installed.

```bash
# Kali / Parrot (pre-installed or apt)
sudo apt install wpscan

# Ruby gem
sudo gem install wpscan

# Docker
docker pull wpscanteam/wpscan
docker run -it --rm wpscanteam/wpscan --url https://target --api-token YOUR_TOKEN

# Update the local metadata/database references
wpscan --update
```

**Get and configure the API token:**
1. Register free at **wpscan.com** → copy your API token (free plan: 25 requests/day).
2. Supply it one of three ways:
```bash
# a) on the command line
wpscan --url https://target --api-token YOUR_TOKEN

# b) environment variable
export WPSCAN_API_TOKEN=YOUR_TOKEN
wpscan --url https://target

# c) config file (best) — ~/.config/wpscan/scan.yml
#    cli_options:
#      api_token: YOUR_TOKEN
```
The config-file approach keeps the token out of your shell history and applies it to every scan.

---

## 11. Command-Line Options (Full Breakdown)

Grouped by purpose.

### Target & core
| Option | Purpose |
|---|---|
| `--url, -u <URL>` | Target WordPress URL. |
| `--force` | Skip the "is this WordPress?" check and scan anyway. |
| `--update` | Update WPScan's local database/metadata. |
| `--api-token <token>` | WPVulnDB API token for vulnerability data. |

### Enumeration & detection
| Option | Purpose |
|---|---|
| `--enumerate, -e [opts]` | What to enumerate (see §12). |
| `--detection-mode <mode>` | Overall mode: `passive`, `mixed`, `aggressive`. |
| `--plugins-detection <mode>` | Plugin detection mode. |
| `--plugins-version-detection <mode>` | How hard to work to detect plugin versions. |
| `--themes-detection` / `--themes-version-detection` | Same for themes. |
| `--exclude-content-based <regex>` | Exclude responses matching a pattern during enumeration. |
| `--plugins-list <list>` | Restrict plugin brute force to a specific list. |
| `--stealthy` | Convenience: random UA + passive detection. |

### Brute force
| Option | Purpose |
|---|---|
| `--passwords, -P <file>` | Password wordlist for login brute force. |
| `--usernames, -U <list/file>` | Usernames to try. |
| `--password-attack <method>` | `wp-login`, `xmlrpc`, or `xmlrpc-multicall`. |
| `--multicall-max-passwords <n>` | Passwords per XML-RPC multicall request. |
| `--login-uri <uri>` | Custom login URL if non-default. |

### Network, stealth & auth
| Option | Purpose |
|---|---|
| `--random-user-agent, --rua` | Randomize the User-Agent per scan. |
| `--user-agent, -a <UA>` | Fixed custom User-Agent. |
| `--throttle <ms>` | Delay (ms) between requests — be gentle/stealthier. |
| `--max-threads <n>` | Concurrency (default 5). |
| `--request-timeout` / `--connect-timeout` | Timeouts. |
| `--proxy <proto://host:port>` | Route through a proxy (e.g., Burp, SOCKS). |
| `--proxy-auth <user:pass>` | Proxy credentials. |
| `--http-auth <user:pass>` | HTTP Basic/Digest auth on the target. |
| `--cookie-string <cookies>` / `--cookie-jar <file>` | Send cookies (authenticated scans). |
| `--headers <headers>` | Custom headers. |
| `--disable-tls-checks` | Ignore TLS/cert errors. |

### Output
| Option | Purpose |
|---|---|
| `--output, -o <file>` | Write results to a file. |
| `--format, -f <fmt>` | `cli`, `cli-no-color`, `json`. |
| `--verbose, -v` | Verbose (shows detected versions & methods). |
| `--no-banner` | Suppress the banner. |

Run `wpscan --help` (short) or `--hh` (full help) for the exact, version-accurate list.

---

## 12. The --enumerate (-e) Options

`-e/--enumerate` controls what WPScan hunts for. Combine codes (e.g., `-e vp,vt,u`).

| Code | Enumerates |
|---|---|
| `vp` | **Vulnerable Plugins** only (needs API token to know which are vulnerable). |
| `ap` | **All Plugins** (aggressive; big plugin slug brute force). |
| `p` | **Popular Plugins**. |
| `vt` | **Vulnerable Themes** only. |
| `at` | **All Themes**. |
| `t` | **Popular Themes**. |
| `tt` | **TimThumbs** (vulnerable image-resizer scripts). |
| `cb` | **Config Backups** (`wp-config.php.bak`, etc.). |
| `dbe` | **Db Exports** (`.sql` dumps). |
| `u[range]` | **Users** by ID range, e.g. `u1-10`. |
| `m[range]` | **Media** IDs, e.g. `m1-100`. |

**Default** (bare `-e` / `--enumerate` with no codes) runs: **`vp, vt, tt, cb, dbe, u, m`** — a sensible "find the dangerous stuff" set. For a *thorough* plugin hunt (catching hidden vulnerable plugins), use **`ap`** (all plugins, aggressive) despite the noise:

```bash
wpscan --url https://target -e ap --plugins-detection aggressive --api-token TOKEN
```

---

## 13. Worked Examples with Output, Explained

> Output is **representative** and trimmed.

### 13.1 Standard scan with vulnerability data
```bash
wpscan --url https://example.com --api-token YOUR_TOKEN
```
```
_______________________________________________________________
        WordPress Security Scanner by the WPScan Team
                        Version 3.8.x
       Sponsored by Automattic - https://automattic.com/
_______________________________________________________________

[+] URL: https://example.com/ [93.184.216.34]
[+] Started: Mon Sep 14 10:30:00 2026

Interesting Finding(s):
[+] XML-RPC seems to be enabled: https://example.com/xmlrpc.php
[+] WordPress readme found: https://example.com/readme.html
[+] The external WP-Cron seems to be enabled

[+] WordPress version 5.8.1 identified (Insecure, released 2021-09-09).
 | Found By: Rss Generator (Passive Detection)
 | Confidence: 100%

[+] WordPress theme in use: twentytwentyone
 | Version: 1.4 (80% confidence)

[i] Plugin(s) Identified:
[+] contact-form-7
 | Location: https://example.com/wp-content/plugins/contact-form-7/
 | Version: 5.4.1 (100% confidence)
 | Found By: Comment (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 | [!] Title: Contact Form 7 5.3.2 - Reflected Cross-Site Scripting (XSS)
 |     Fixed in: 5.4.2
 |     References:
 |      - cve: 2021-XXXXX
 |      - wpvulndb: https://wpscan.com/vulnerability/...

[i] User(s) Identified:
[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
[+] editor
 | Found By: Wp Json Api (Aggressive Detection)

[+] Finished: ... [Requests Done: 168] [API Calls: 4]
```

**Reading it:**
- **Interesting Findings** — XML-RPC enabled (brute-force surface), readme present (version leak). Leads/hygiene.
- **WordPress version 5.8.1 (Insecure)** — fingerprinted at 100% confidence via the RSS generator; flagged insecure. This drives the core vuln lookup.
- **Plugin `contact-form-7` v5.4.1** — found passively (referenced in an HTML comment), version at 100% from its readme. The **`[!] vulnerability … Fixed in: 5.4.2`** is the payoff: 5.4.1 < 5.4.2, so it's vulnerable to the listed XSS (CVE + WPVulnDB reference). **This is the finding you act on.**
- **Users** — `admin` (author pattern) and `editor` (REST API) enumerated → brute-force candidates.
- **Footer** — `Requests Done` (how loud it was) and `API Calls: 4` (WP version + theme + plugin + …, counting against your 25/day).

### 13.2 Thorough, aggressive plugin hunt
```bash
wpscan --url https://target -e ap --plugins-detection aggressive \
       --api-token TOKEN --random-user-agent --throttle 300
```
Catches hidden plugins (thousands of slug probes), randomizes UA, and paces requests (300 ms) to be less abusive/obvious.

### 13.3 Enumerate users, then brute force via XML-RPC with a CeWL list
```bash
# 1) find usernames
wpscan --url https://target -e u --api-token TOKEN
# 2) brute force those users with a target-specific wordlist
wpscan --url https://target -U admin,editor -P cewl_words.txt \
       --password-attack xmlrpc --max-threads 5 --throttle 500
```
Ties user enumeration + CeWL + XML-RPC amplification into one credential attack (authorized only).

### 13.4 Through Burp, JSON output
```bash
wpscan --url https://target --proxy http://127.0.0.1:8080 \
       -f json -o wpscan.json --api-token TOKEN
```
Route via Burp for visibility/replay; emit JSON for reporting/automation.

---

## 14. Reading the Output

WPScan findings are annotated so you can judge how much to trust them. Learn these annotations:

- **Confidence %** — how sure WPScan is about a detected version/component. `100%` (e.g., version pulled from a plugin's `readme.txt`) is reliable; `80%` or lower means the guess is softer. **Low-confidence versions can produce wrong vuln verdicts** — verify before reporting.
- **Found By** — the detection method, which tells you the evidence quality:
  - *Passive Detection* (e.g., "Comment", "Rss Generator", "Author Pattern") — read from what the site volunteered; low noise, generally trustworthy.
  - *Aggressive Detection* (e.g., "Known Locations", "Wp Json Api") — WPScan actively probed; found more, but confirm it's not a false positive from a soft-404.
- **`[+]`** — a confirmed finding. **`[!]`** — a **vulnerability** (the important lines). **`[i]`** — informational. **`[e]`** — error.
- **Fixed in** — the version that patched the vuln. Compare to the detected version: *detected < fixed-in → vulnerable*. This is also your remediation instruction ("update to ≥ fixed-in").
- **References** — `cve:`, `wpvulndb:`, sometimes `exploitdb:`/`url:`/`metasploit:`. Follow these to understand impact and whether a public exploit exists.
- **Requests Done / API Calls** (footer) — how loud the scan was, and how much of your 25/day quota it used.

**The discipline:** treat **`[!]` lines with high-confidence versions** as real leads, then **verify** — confirm the version independently (`-v`), read the CVE, and (in scope) test whether the vuln is actually exploitable on this target. A reported vuln based on an 80%-confidence version guess is a hypothesis, not a fact. And remember: **no API token = no `[!]` lines at all**, only the inventory.

---

## 15. Evasion and Being Gentle

WPScan (especially aggressive enumeration and brute force) is **loud** — thousands of requests to predictable WordPress paths, which security plugins (Wordfence, etc.) and WAFs are specifically tuned to detect.

**Reducing noise / footprint:**
- **`--throttle <ms>`** — put a delay between requests; the cleanest way to be gentle on a fragile or monitored target.
- **`--random-user-agent` / `--rua`** — vary the UA so requests don't all look identical (default UA screams "WPScan").
- **`--stealthy`** — convenience mode: random UA + passive detection (quiet first pass).
- **`--max-threads`** — lower concurrency to reduce load.
- **Passive detection modes** — when you must stay quiet, accept the reduced coverage.

**The hard reality — WAFs and Cloudflare:** modern bot protection (Cloudflare, etc.) is *designed* to stop automated scanners like WPScan, and the built-in evasion often won't get through. For **authorized** tests, the correct move isn't clever evasion — it's to have the site owner **allowlist your scanning IP** (or a temporary Cloudflare bypass rule) so the scan runs cleanly and legally. Trying to defeat a WAF you're authorized to test around is wasted effort; ask for the allowlist.

**Honest note:** evasion changes the *shape* of requests, not the *fact* that you're hitting `wp-login.php`, `xmlrpc.php`, and thousands of plugin paths. WPScan is best used where noise is acceptable (authorized engagements, your own sites), not for stealth operations.

---

## 16. Where It Fits: Workflow and Chaining

WPScan runs **once you've identified a WordPress target** (from recon/fingerprinting) and drives **verification and exploitation** of the WordPress-specific findings.

```
[ subdomain enum ] → [ port scan ] → [ httpx / whatweb: identify WordPress ]
                                                   │
                                                   ▼
                                            [ WPScan ]  ← fingerprint core/plugins/themes/users
                                                   │      + map to known CVEs (via API)
                                                   │      + enumerate users, find misconfigs
                                                   ▼
         ┌──────────────────────────┬─────────────────────────────┐
         ▼                          ▼                             ▼
[ verify each CVE ]        [ CeWL → wordlist ]            [ feroxbuster/ffuf ]
 searchsploit / PoC /       + enumerated users →           content discovery for
 metasploit modules         XML-RPC brute force            backups/uploads/config
         │                          │                             │
         └──────────────► [ Burp / manual exploitation ] ◄────────┘
```

**Relationship to the tools you've studied:**
- **After a crawler/fingerprinter** identifies "this is WordPress," WPScan specializes the assessment.
- **feeds/uses CeWL** — enumerated usernames + a CeWL wordlist → XML-RPC brute force (§9).
- **complements feroxbuster** — feroxbuster finds generic hidden files; WPScan finds WordPress-specific ones (config backups, plugin paths) using WordPress conventions.
- **hands off to Burp** — route WPScan through Burp (`--proxy`) so findings land in your history, then exploit confirmed vulns manually.

The discipline: **identify WordPress → WPScan to inventory + map to CVEs → verify each finding → exploit in scope (vuln PoC or credential attack).**

---

## 17. Limitations and Pitfalls

- **Fingerprint accuracy is everything.** A wrong or undetected version yields wrong/missing vulnerabilities. Always run `-v` and sanity-check detected versions; low-confidence detections are hypotheses.
- **No token = no vulnerability data.** Without an API token (or after the 25/day quota), you get an inventory only, not vuln verdicts. Budget the quota; consider a config-file token.
- **Database freshness.** The vuln DB is curated and updated, but a brand-new (0-day) plugin vuln won't be there yet, and a mis-catalogued one can be missed. WPScan reports *known* vulns only.
- **False positives/negatives.** Passive detection misses hidden plugins (false sense of safety → use aggressive); aggressive detection can misfire on soft-404 servers (false positives → verify). Version detection from cached/CDN'd assets can be stale.
- **WAF/Cloudflare blocks scans.** Built-in evasion often fails against modern bot protection; use an authorized IP allowlist instead.
- **Loud and active.** Aggressive enumeration and brute force generate huge, obvious traffic and can trigger lockouts/alerts. It's active testing, not recon.
- **Not open source / commercial restrictions.** Free for non-commercial use only; commercial engagements need a paid plan. The vuln data is proprietary.
- **WordPress-only.** It's a specialist tool — useless against non-WordPress targets (it'll tell you it's not WordPress unless `--force`).

---

## 18. Legal and Ethical Note

- **WPScan is active, intrusive testing.** Enumeration hits predictable endpoints hard, and brute force attempts real logins — unambiguously an attack from the target's perspective, and easily logged.
- **Only scan sites you own or have explicit written permission to test.** Scanning third-party WordPress sites without consent can violate the **Computer Fraud and Abuse Act (US)** and equivalent computer-misuse laws elsewhere. WPScan's own terms restrict it to your own sites or authorized testing.
- **Brute force can lock accounts and disrupt users.** Know the lockout/security-plugin policy, throttle, keep lists focused, and get authorization; many programs restrict or forbid online brute forcing.
- **Enumerated usernames/emails are personal data** — handle per engagement rules and privacy law; use only within scope.
- **Respect the API terms** — the free plan is non-commercial; don't exceed or abuse the quota.
- **Practice legally:** run WPScan against **your own WordPress install** or intentionally vulnerable targets — a local WordPress in Docker, **OWASP-style vulnerable WordPress VMs**, or lab boxes (HTB/THM WordPress machines) — to learn enumeration, output, and the CeWL→XML-RPC chain safely.

---

### Where to go next

- Spin up a **local WordPress** (Docker: `wordpress` + `mysql`) with an old plugin installed, get a **free API token**, and run `wpscan --url http://localhost -e ap --api-token TOKEN -v`. Watching it fingerprint the plugin and print a real **`[!] Fixed in: …`** line is the "aha" that makes the tool click (§8.2, §8.5).
- Enumerate users (`-e u`), then practice the full **credential chain** on your lab site: **CeWL** the site → feed the wordlist + enumerated users into `--password-attack xmlrpc`. Feeling XML-RPC's multicall amplification (§9) connects three of your tools into one attack.
- Route a scan through **Burp** (`--proxy`) and inspect how WPScan fingerprints — seeing the actual `?author=1` redirects and `readme.txt` fetches turns the concepts in §8 from abstract to concrete.

*End of reference.*

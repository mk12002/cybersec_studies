# httpx & Amass — The Complete Reference (Beginner → Advanced)

> A ground-up reference for the recon "glue": **Amass** (in-depth attack-surface mapping / subdomain & asset enumeration) and **httpx** (fast HTTP probing that turns a list of names into live, enriched web targets). How each works, how they chain into everything else — and the critical Amass v5 output change that silently breaks old pipelines.

---

## Table of Contents

1. [What These Tools Are and Why](#1-what-these-tools-are-and-why)
2. [The Recon Pipeline: Where Each Fits](#2-the-recon-pipeline-where-each-fits)
3. [Passive vs Active Recon (Recap)](#3-passive-vs-active-recon-recap)

**— AMASS (enumerate / map) —**
4. [Amass: Status and Key Facts](#4-amass-status-and-key-facts)
5. [How Amass Works: Sources and Techniques](#5-how-amass-works-sources-and-techniques)
6. [The Open Asset Model and Asset Database](#6-the-open-asset-model-and-asset-database)
7. [Amass Subcommands and the v5 Output Gotcha](#7-amass-subcommands-and-the-v5-output-gotcha)
8. [Passive vs Active, API Keys, and Config](#8-passive-vs-active-api-keys-and-config)
9. [Amass Options and Examples](#9-amass-options-and-examples)

**— HTTPX (probe / enrich) —**
10. [httpx: Status and Key Facts](#10-httpx-status-and-key-facts)
11. [How httpx Works and What It Tells You](#11-how-httpx-works-and-what-it-tells-you)
12. [httpx Matchers, Filters, and Extraction](#12-httpx-matchers-filters-and-extraction)
13. [httpx Options and Examples](#13-httpx-options-and-examples)

**— SHARED —**
14. [Installation](#14-installation)
15. [The Full Pipeline in Practice](#15-the-full-pipeline-in-practice)
16. [Reading the Output](#16-reading-the-output)
17. [Limitations and Pitfalls](#17-limitations-and-pitfalls)
18. [Legal and Ethical Note](#18-legal-and-ethical-note)

---

## 1. What These Tools Are and Why

These two tools own the **front of the recon pipeline** — the stage that turns "here's a target domain" into "here's a categorized list of live web servers to attack." They do complementary jobs:

- **Amass** (OWASP) is an **in-depth attack-surface mapping and asset-discovery** framework. Give it a domain and it enumerates **subdomains and related assets** (IPs, netblocks, ASNs, organizations) using dozens of data sources and multiple techniques — the comprehensive, thorough successor to lighter tools like Sublist3r. Its output is a big list of **names/assets that might exist.**

- **httpx** (ProjectDiscovery) is a **fast HTTP prober.** Feed it that list of names, and it rapidly determines **which are actually live web servers** and enriches each with metadata — status code, page title, technology stack, IP, CDN, and more. Its output is a **live, categorized target list.**

**Why they matter — the "glue" role:** enumeration (Amass) produces *thousands* of candidate hostnames, but most are **dead, parked, or non-web**. You can't feed a raw name list straight into Nuclei/feroxbuster/Burp — you'd waste enormous effort on hosts that don't respond. **httpx is the filter and enricher in between:** it probes the whole list in seconds, keeps only the live web hosts, and tags each with status/title/tech so you know *what* you're looking at and *what to prioritize*. Amass finds the surface; httpx makes it actionable. Together they're the standard opening of nearly every modern web/bug-bounty recon workflow, and the bridge into every tool you've already studied.

---

## 2. The Recon Pipeline: Where Each Fits

Seeing the whole pipeline first makes each tool's role obvious:

```
[ target domain(s) ]
        │
        ▼
┌─────────────────────────────────────────────┐
│ ENUMERATE — find what exists                 │
│   amass enum   (deep, many sources + active) │
│   subfinder    (fast, passive)               │  → thousands of candidate hostnames
└─────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│ PROBE / ENRICH — which are live? what are they?│
│   httpx  (status, title, tech, ip, cdn, …)   │  → live, categorized web targets
└─────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│ ATTACK — the tools you already know          │
│   nuclei      (known-issue templates)        │
│   feroxbuster/ffuf (content discovery)       │
│   nmap        (ports/services on the IPs)    │
│   nikto/wpscan (server/CMS specifics)        │
│   Burp/ZAP    (deep manual testing)          │
│   dalfox/sqlmap (XSS/SQLi on found params)   │
└─────────────────────────────────────────────┘
```

**The division of labor:**
- **Amass/subfinder** answer *"what hostnames belong to this target?"* (breadth of attack surface).
- **httpx** answers *"which of those are live web servers, and what's running on them?"* (filter + enrich).
- Everything downstream **operates on httpx's clean output** — you point Nuclei/feroxbuster/Burp at *live* hosts, not a raw name dump.

This is why "recon glue" fits: httpx connects the enumeration stage to the attack stage, and Amass provides the raw material. Get this front end right and the rest of the engagement has a rich, accurate target list; get it wrong (or skip it) and you test only the handful of hosts you already knew about.

---

## 3. Passive vs Active Recon (Recap)

(From the glossary and Sublist3r reference — it governs how both tools behave.)

- **Passive** — gather information **without sending traffic to the target's own infrastructure** (query third parties: search engines, certificate transparency logs, passive-DNS providers, APIs). Stealthy, low-risk, but only finds what someone else already recorded.
- **Active** — **interact directly with the target** (resolve DNS against it, brute-force subdomains, pull certificates, attempt zone transfers, probe web ports). Finds more (including unpublished assets) but is noisier and higher-footprint.

**Amass** does **both**, and lets you choose: `-passive` mode uses only OSINT sources (quiet); the default/active modes also resolve names and can brute-force, permute, and attempt zone transfers. **httpx** is inherently **active** — it *must* send HTTP requests to the target hosts to probe them (that's its whole job), so it's never "passive," though it's lightweight. Know which mode you're in for stealth and authorization reasons (§18).

---

## 4. Amass: Status and Key Facts

- **OWASP flagship project**, by **Jeff Foley (caffix)**. Go. **Apache 2.0** licensed. Pre-installed on **Kali/Parrot** (though possibly an older version — check).
- **Major versions matter a lot here** (Amass changes architecture between them):
  - **v3** — the classic subdomain-list era (`amass enum -o list.txt` → a flat file).
  - **v4** — introduced the **Open Asset Model (OAM)** and an **Asset Database (graph DB)**: Amass stopped being just a subdomain lister and became an **asset-graph mapper** (FQDNs, IPs, netblocks, ASNs, orgs, and their relationships).
  - **v5** (2025, current) — an **evolution of v4**: a **client/engine split** (a launcher/client talks to a standalone collection **engine**, enabling detached/distributed/collaborative scanning), a matured OAM, and schema/caching/performance changes.
- **⚠️ The v5 output change you must know (details in §7):** v5 writes results into the **asset database**, not to a text file. The old `amass enum -d example.com -o subs.txt` now produces an **empty `subs.txt`** — the scan runs and stores data, but `-o` gives you nothing, so any `httpx | nuclei` pipeline reading that file **silently does nothing**. You extract names with **`amass subs -names`** instead. This breaks most older tutorials.
- **Comprehensive but heavier/slower** than the fast passive tools (subfinder). Common practice: **subfinder for speed, Amass for depth** — run both, merge, dedupe.
- **Documentation churn** is a known pain point — subcommands and output have moved across v4→v5, so verify against `amass --help` on *your* installed version rather than trusting old blog posts.

---

## 5. How Amass Works: Sources and Techniques

Amass's strength is combining **many data sources** with **many techniques** to find subdomains/assets that any single method would miss.

**Data sources (80+),** grouped:
- **Scraping** — search engines and DNS aggregators (Bing, DNSDumpster, Netcraft, etc.).
- **Certificates** — Certificate Transparency logs (crt.sh, Censys, CertSpotter, Google CT) and optional active cert pulls.
- **APIs** — passive-DNS and intel providers: SecurityTrails, Shodan, Censys, VirusTotal, AlienVault, PassiveTotal, GitHub, HackerTarget, and many more (**most need API keys** in config to unlock — §8).

**Techniques:**
- **DNS enumeration** — resolve discovered names to confirm they exist.
- **Certificate Transparency** — extract hostnames from logged certificates (the high-value passive source you learned in Sublist3r).
- **Passive DNS** — historical resolution data from providers.
- **DNS brute-forcing** (`-brute`, optional) — guess subdomain labels from a wordlist and resolve them (active — finds unpublished names).
- **Name alterations / permutations** — generate variations of found names (`api-dev`, `dev-api`, `api2`) and resolve them — catches related hosts near known ones.
- **Reverse DNS sweeping** — map IP ranges back to names.
- **Zone transfers (AXFR)** (optional, active) — attempt to dump a whole DNS zone from misconfigured servers.
- **ASN / netblock expansion** — from an org, find its IP ranges, then the hosts in them (attack-surface expansion beyond one domain).

**The concept:** each source/technique catches a different slice of the attack surface — CT logs reveal certificated names, passive DNS reveals historically-resolved names, brute force reveals unpublished common names, permutations reveal siblings of known names, ASN expansion reveals whole netblocks. Amass **runs them together and correlates the results into one asset graph** (§6), which is why it finds more than lighter tools — at the cost of being slower and, in active mode, noisier. This is the "depth" you reach for when thoroughness matters more than speed.

---

## 6. The Open Asset Model and Asset Database

Since v4, Amass is built around the **Open Asset Model (OAM)** — a shift from "a list of subdomains" to **"a graph of assets and their relationships."** This is the conceptual leap that distinguishes modern Amass from Sublist3r-style tools.

**What the OAM captures:** not just FQDNs (hostnames), but the whole interconnected surface — **IP addresses, netblocks/CIDRs, ASNs, organizations, TLS certificates, DNS records** — and, crucially, the **relationships** between them (this FQDN resolves to that IP, which sits in that netblock, which belongs to that ASN, owned by that org). Instead of a flat name list, you get a **map of how the target's assets connect.**

**Why relationships matter:** attack paths often hide in the connections. Knowing that `dev.example.com` and an unrelated-looking `internal-tool.acquired-co.net` both resolve into the same netblock owned by the same org reveals scope you'd never find from one domain's subdomains alone. The graph lets you **pivot** — from a domain to its ASN to all its netblocks to every host in them — expanding the attack surface systematically.

**The Asset Database:** Amass v4/v5 stores everything it collects in a local **graph database** (SQLite by default; Postgres/Neo4j possible for larger/collaborative setups). Benefits: results **persist** across runs, you can **query** the accumulated data, track how the surface **changes over time**, and feed it into visualization. The tradeoff (and the v5 gotcha) is that results now live **in the database**, not automatically in a text file — you must **query/extract** them (§7).

**v5's client/engine split** layers onto this: a standalone **engine** does the collecting and populates the database; **clients** (the `amass` command) submit work and read results. This enables running the engine as a service and connecting multiple clients — good for teams and distributed scanning, but it's why the mental model is now "collect into a DB, then query the DB" rather than "run a command, get a file."

---

## 7. Amass Subcommands and the v5 Output Gotcha

Amass is driven by **subcommands.** These have shifted across versions, so here's the practical map plus the critical output change.

**Core subcommands:**
| Subcommand | Purpose |
|---|---|
| `amass enum` | **The workhorse** — enumerate subdomains/assets for a domain (into the asset DB). |
| `amass subs` | **(v5) Extract subdomain names** from the asset DB — `amass subs -names -d example.com` gives the flat hostname list. |
| `amass intel` | **Intelligence gathering** — discover *root domains* and org info via whois, reverse-whois, ASN, and OSINT (find *what* to enumerate, before `enum`). |
| `amass assoc` / `oam_assoc` | Analyze the collected data to find assets **associated** with your seeds (pivot via the graph). |
| `amass db` / `oam` tools | Query/manage the asset database. |
| `amass viz` | Visualization output (e.g., for Maltego/graph viewers) — availability varies by version. |
| `amass track` | (older) Compare enumerations over time to see what changed. |

**⚠️ THE v5 OUTPUT GOTCHA — read this or lose hours:**

The universal recon one-liner from years of tutorials is:
```bash
amass enum -passive -d example.com -o subs.txt
httpx -l subs.txt -silent | nuclei -severity high,critical
```
**In Amass v5, `subs.txt` comes out EMPTY.** v5 moved results into the **asset database** and **stopped populating the `-o` text output** during `enum`. The scan *works*, the data *is stored* — but `-o` produces nothing, so httpx probes nothing, nuclei finds nothing, and **the pipeline exits 0 (success) while doing nothing.** It fails silently, possibly for months on a schedule.

**The v5-correct way to get a usable name list:**
```bash
# 1) collect into the asset DB
amass enum -passive -d example.com
# 2) EXTRACT the names from the DB
amass subs -names -d example.com -o subs.txt
# 3) now the pipeline works
httpx -l subs.txt -silent | nuclei -severity high,critical
```
Or query the DB with a helper like **`oamx`** (a third-party reader that works across v4/v5 and outputs plain values/JSONL). **Always verify your `subs.txt` actually has content** before trusting a downstream pipeline. On **v3/v4**, `amass enum -o` still gives you names directly — which is exactly why old tutorials mislead on v5. Check `amass --version` and confirm output is non-empty.

---

## 8. Passive vs Active, API Keys, and Config

**Passive vs active mode:**
- **`-passive`** — OSINT sources only; Amass does **not** resolve names against the target or brute-force. Stealthy and fast(er). Good default for quiet recon or when you only need known names.
- **Default / active** — Amass **resolves** discovered names (confirming they exist) and, with flags, does more aggressive active work:
  - **`-active`** — enables active techniques like certificate pulls and **zone-transfer** attempts (touches the target directly).
  - **`-brute`** — DNS brute-forcing with a wordlist (`-w`), finding unpublished names.
- Active finds more but sends traffic to the target's DNS/servers — mind stealth and authorization.

**API keys — the single biggest factor in how much Amass finds.** Many of the best data sources (SecurityTrails, Shodan, Censys, VirusTotal, etc.) require **API keys**. Without them, Amass silently skips those sources and finds far less. Adding keys (many have free tiers) dramatically improves results. Keys go in Amass's **config**:
- **v3:** `config.ini`.
- **v4/v5:** YAML config (`config.yaml`) with a **datasources** file listing each provider and its key(s).
- Default config locations vary by OS (e.g., `~/.config/amass/`). Use `-config <file>` to point at yours.

**The takeaway:** run Amass **with API keys configured** for real work — an un-keyed Amass is a fraction of its potential. And choose passive vs active deliberately based on stealth needs and scope.

---

## 9. Amass Options and Examples

Common `amass enum` options (verify against your version's `--help`):

| Option | Purpose |
|---|---|
| `-d <domain>` | Target domain (repeatable). |
| `-df <file>` | File of domains. |
| `-passive` | Passive (OSINT-only) mode. |
| `-active` | Enable active techniques (cert pulls, zone transfers). |
| `-brute` | DNS brute-force. |
| `-w <wordlist>` | Wordlist for brute-forcing. |
| `-o <file>` | Output file (**⚠️ empty on v5 enum — use `amass subs`**). |
| `-json <file>` | JSON output. |
| `-config <file>` | Config file (API keys). |
| `-dir <path>` | Asset-database/output directory. |
| `-timeout <min>` | Stop after N minutes. |
| `-min-for-recursive <n>` | Threshold before recursive brute-forcing a subdomain. |
| `-ip` / `-src` | Show IPs / the data source per finding. |

**Examples:**

```bash
# Passive enumeration (quiet), then extract names (v5-correct)
amass enum -passive -d example.com
amass subs -names -d example.com -o subs.txt

# Active + brute force for depth (louder, more thorough)
amass enum -active -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -d example.com -config ~/.config/amass/config.yaml

# Intel first: find the org's root domains, then enumerate them
amass intel -org "Example Corp"
amass intel -d example.com -whois          # related domains via reverse-whois

# JSON output for tooling
amass enum -passive -d example.com -json out.json

# (v3/v4 legacy) direct name list
amass enum -passive -d example.com -o subs.txt   # works pre-v5
```

**Practical guidance:** start **passive** to map the known surface cheaply, then go **active/brute** for depth if scope allows. Always run with **API keys** configured. On **v5**, extract with `amass subs -names` and **confirm the file isn't empty** before piping onward.

---

## 10. httpx: Status and Key Facts

- **Actively maintained** by **ProjectDiscovery** (the Nuclei/subfinder team). Go. **v1.x series** (check `httpx -version`). Pre-installed on **Kali/Parrot**; install via Go/Homebrew/Docker/binary.
- **⚠️ Two different tools are called "httpx"** — don't confuse them:
  - **ProjectDiscovery httpx** — the **recon HTTP prober** (this document). A Go **binary**.
  - **Python `httpx`** — a popular **HTTP client library** for Python (like `requests`). A different thing entirely.
  - `pip install httpx` gets the **Python library**, not the recon tool. Install the PD tool via Go (`go install github.com/projectdiscovery/httpx/cmd/httpx@latest`) or your package manager, and run the binary. If `httpx` errors with Python import stuff or lacks `-title`/`-status-code`, you installed the wrong one.
- **Purpose:** take a list of hosts/domains/IPs/URLs and **probe them over HTTP(S)** to find which are live web servers, enriching each with a rich set of metadata (status, title, tech, IP, CDN, TLS info, screenshots, and more).
- **Fast and pipeline-native** — built to consume the output of subfinder/amass and feed nuclei/other tools, with `-silent` clean output and JSON/JSONL for tooling. Also does **built-in screenshots** (replacing aquatone/gowitness for many workflows).

---

## 11. How httpx Works and What It Tells You

**How it works:** httpx takes each input (a hostname, IP, URL, or CIDR), tries HTTP and HTTPS (on default or specified ports), follows the logic to determine if a **live web server** responds, and collects **metadata** from the response. It's massively concurrent, so it probes thousands of hosts in seconds.

**What it can tell you about each live host** (each is a flag you enable):

| Flag | Tells you |
|---|---|
| `-status-code` / `-sc` | HTTP **status code** (200/301/403/…). |
| `-title` | The page **`<title>`** — instantly says what the site is ("Admin Login", "Jenkins", "Default nginx page"). |
| `-tech-detect` / `-td` | **Technology stack** (Wappalyzer-based): nginx, WordPress, Tomcat, PHP, Cloudflare, etc. — tells you which specialist tool to use next. |
| `-web-server` / `-server` | The `Server` header. |
| `-content-length` / `-cl` | Response size. |
| `-content-type` / `-ct` | MIME type. |
| `-location` | Redirect target (for 3xx). |
| `-ip` | Resolved **IP** address. |
| `-cname` | CNAME record (a lead for **subdomain takeover**). |
| `-cdn` | Whether it's behind a **CDN/WAF** (Cloudflare, Akamai…). |
| `-asn` | The **ASN** (owning network). |
| `-favicon` | **Favicon hash** (mmh3) — pivot to find other hosts with the same favicon via Shodan/Censys. |
| `-jarm` | **JARM** TLS fingerprint — identify/cluster servers by their TLS stack. |
| `-hash <algo>` | Hash of the response body (dedupe identical pages). |
| `-response-time` / `-rt` | Latency. |
| `-word-count` / `-line-count` | Body word/line counts (filtering fingerprints). |
| `-screenshot` / `-ss` | **Headless screenshot** of each page (visual triage at scale). |
| `-probe` | Show `[SUCCESS]`/`[FAILED]` per host (see what's live vs dead). |

**Why this enrichment is the whole point:** a raw name list is undifferentiated. httpx turns each name into a **profile**: *"`admin.example.com` → 200, title 'Login', tech: PHP + nginx, IP x, not behind CDN."* Now you can **prioritize** (the Jenkins box, the admin panel, the outdated CMS) and **route** (WordPress → WPScan; a plain web app → feroxbuster + Burp; an IP → nmap). The `-title` and `-tech-detect` fields alone transform hours of manual clicking into a scannable table. And features like `-favicon` (hash-pivot) and `-cname` (takeover leads) turn httpx into a light discovery tool in its own right.

---

## 12. httpx Matchers, Filters, and Extraction

Because you often probe **huge** lists, httpx has **matchers** and **filters** (same idea as ffuf/nuclei) to keep only what's interesting:

**Matchers (keep only these):**
- `-mc <codes>` — match status codes (`-mc 200,301,403`).
- `-ms <string>` — match a response string.
- `-mr <regex>` — match a regex.
- `-ml <n>` / `-mlc` / `-mwc` — match line/word counts.

**Filters (drop these):**
- `-fc <codes>` — filter out status codes (`-fc 404,502`).
- `-fs <string>` / `-fr <regex>` — filter by string/regex.
- `-fl <n>` — filter by line count.

**Extraction:**
- `-extract-regex <regex>` — **pull data out** of responses (e.g., emails, API keys, version strings, endpoints) across every probed host — useful for finding secrets/leads at scale.
- `-json` / `-jsonl` — structured output with all fields, for `jq` and downstream tooling.
- `-csv` — spreadsheet output.

**Common patterns:**
```bash
# Keep only live pages, hide 404s
httpx -l subs.txt -mc 200,301,302,403 -silent

# Find admin-ish titles across the estate
httpx -l subs.txt -title -mr "(?i)(admin|login|dashboard|jenkins)"
```

The workflow mirrors your other tools: probe broadly, then **match/filter to the signal** (live, interesting hosts) so downstream tools aren't buried in dead names.

---

## 13. httpx Options and Examples

Key options grouped:

**Input:** `-u` (single), `-l` (list/stdin), `-ports`/`-p` (probe extra ports, e.g. `-p 80,443,8080,8443`), `-path`/`-paths` (probe a path), `-x` (methods), `-body` (POST body), `-H` (headers).

**Probes/enrichment:** `-sc -title -td -server -cl -ct -location -ip -cname -cdn -asn -favicon -jarm -hash -rt -wc -lc -ss` (as in §11), `-probe`, `-vhost` (detect virtual hosts), `-follow-redirects`/`-fr`, `-random-agent`, `-http2`, `-pipeline`.

**Output:** `-o` (file), `-json`/`-jsonl`, `-csv`, `-silent`, `-nc` (no color), `-sr` (store full responses), `-srd <dir>` (response dir), `-stream` (stream mode for massive inputs), `-extract-regex`.

**Performance:** `-t` (threads, default 50), `-rl` (rate limit), `-timeout`, `-retries`, `-delay`, `-proxy` (route via Burp).

**Examples:**

```bash
# 1) The canonical probe: live hosts with key metadata
httpx -l subs.txt -sc -title -td -ip -silent

# 2) Probe extra web ports too (catch apps on 8080/8443)
httpx -l subs.txt -p 80,443,8080,8443,3000 -sc -title -silent

# 3) Screenshot every live host for visual triage
httpx -l subs.txt -ss -srd screenshots/ -silent

# 4) Pipe straight from enumeration into the attack stage
subfinder -d example.com -silent | httpx -silent | nuclei -severity high,critical

# 5) Through Burp, JSON output for tooling
httpx -l subs.txt -sc -title -td -json -o probe.json -proxy http://127.0.0.1:8080

# 6) Favicon-hash pivot (find related hosts via Shodan later)
httpx -l subs.txt -favicon -silent
```

Example 4 is the recon workhorse — **enumerate → probe → scan** in one line. (With **Amass v5**, remember to source names via `amass subs -names` first, not a possibly-empty `amass enum -o`.)

---

## 14. Installation

**httpx (ProjectDiscovery):**
```bash
# Go (recommended)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Homebrew
brew install httpx

# Kali / Parrot
sudo apt install httpx-toolkit     # note the package name (avoids the python httpx clash)

# Docker
docker run projectdiscovery/httpx:latest -u https://example.com

httpx -version
```
> On Kali the binary may be `httpx-toolkit` to avoid colliding with the Python `httpx`. If `httpx` runs the wrong tool, use the full path to the PD binary or the `httpx-toolkit` name.

**Amass (OWASP):**
```bash
# Homebrew
brew install amass

# Go
go install -v github.com/owasp-amass/amass/v5/...@master     # v5 (check current module path)

# Kali / Parrot (may be older)
sudo apt install amass

# Docker (avoids build hassles; DB persists via a mounted volume)
docker run -v "$(pwd):/data" caffix/amass enum -passive -d example.com

amass --version
```
> Configure **API keys** (§8) after install for real results, and know your **major version** (v4 vs v5) because output/subcommands differ. Also grab **subfinder** (`go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`) — the fast passive companion you'll often run alongside Amass.

---

## 15. The Full Pipeline in Practice

Putting the recon front end together, feeding everything you've learned:

```bash
# ── 1. ENUMERATE (breadth: fast passive + deep Amass) ─────────────
subfinder -d example.com -all -silent > subs_sf.txt
amass enum -passive -d example.com                 # collects into asset DB
amass subs -names -d example.com > subs_amass.txt  # v5: EXTRACT names (not -o!)
cat subs_sf.txt subs_amass.txt | sort -u > all_subs.txt

# ── 2. PROBE / ENRICH (which are live? what are they?) ────────────
httpx -l all_subs.txt -p 80,443,8080,8443 \
      -sc -title -td -ip -cname -cdn -silent -o live.txt
#   → live.txt: categorized live web hosts with status/title/tech
httpx -l all_subs.txt -json -o live.json           # structured for tooling
httpx -l all_subs.txt -ss -srd shots/ -silent      # screenshots for triage

# ── 3. ATTACK (route by what httpx revealed) ──────────────────────
# extract just the live URLs for downstream tools:
cut -d' ' -f1 live.txt > live_urls.txt

nuclei -l live_urls.txt -severity critical,high -stats     # known issues
#   WordPress hosts (from -td) → wpscan; plain apps → feroxbuster + Burp
feroxbuster --stdin -w raft-medium-directories.txt < live_urls.txt
#   resolve to IPs → nmap the services
httpx -l all_subs.txt -ip -silent | awk '{print $2}' | sort -u | nmap -iL - -sV
```

**The logic:** breadth from enumeration → filtered/enriched to live targets by httpx → routed to the right attack tool by what httpx (and Amass's graph) revealed. This is the opening moves of essentially every modern web engagement, and it connects Amass/subfinder/httpx to **Nuclei, feroxbuster, WPScan, nmap, Burp, sqlmap, dalfox** — the entire toolkit you've built.

---

## 16. Reading the Output

**httpx** default (with probes) is a compact, colorized line per live host:
```
https://admin.example.com [200] [Admin Login] [PHP,nginx,Bootstrap] [93.184.216.34]
https://dev.example.com   [403] [Forbidden]   [nginx]               [93.184.216.35]
https://blog.example.com  [200] [Example Blog] [WordPress,PHP]      [93.184.216.36] [cloudflare]
   │                        │      │             │                     │              │
   URL                    status  title       tech stack             IP            CDN
```
**Reading it:** each line is a **live web target profiled**. `admin.example.com [200] [Admin Login]` → a login panel to test. `[403]` → exists but protected (a lead). `[WordPress]` → route to **WPScan**. `[cloudflare]` → behind a CDN/WAF (adjust expectations). `-json` gives every field for filtering/reporting. This table *is* your prioritized attack list.

**Amass** output is a name/asset list (via `amass subs -names`) or a relationship graph (via `-json`/the DB/`viz`). The names feed httpx; the graph/JSON (with IPs, ASNs, sources) supports pivoting and scope expansion. Always **confirm the extracted name list is non-empty** (the v5 trap) before piping onward.

**Triage habit:** scan httpx output for interesting **titles** (admin/login/dashboard/jenkins/default pages), notable **tech** (old CMS, dev frameworks), **403s** (protected = interesting), and **CNAMEs** (takeover leads) — then route each to the right tool.

---

## 17. Limitations and Pitfalls

**Amass:**
- **⚠️ v5 empty-output trap** — `amass enum -o` no longer writes names; use `amass subs -names` and verify the file has content (§7). The #1 way people silently break their pipeline.
- **Version/subcommand churn** — v3 vs v4 vs v5 differ significantly; documentation lags. Check `amass --version` and `--help`; don't trust old tutorials blindly.
- **Un-keyed = shallow** — without API keys, Amass skips its best sources and finds a fraction. Configure keys.
- **Slow/heavy** — thorough but resource-intensive; for speed pair with/precede by subfinder.
- **Active modes touch the target** — `-active`/`-brute`/zone transfers send traffic to the target's DNS/servers (authorization + noise).

**httpx:**
- **Wrong httpx** — the Python library vs the PD tool (§10). Install the PD binary.
- **It's active** — it sends HTTP requests to every host; against large lists that's real traffic (rate-limit, throttle).
- **Probes only what you point it at** — it's a prober, not an enumerator or crawler; feed it good input.
- **Tech/title detection isn't perfect** — CDNs/WAFs and custom stacks can mask or mislead; treat as strong hints.
- **Default ports only unless told otherwise** — add `-p` to catch apps on 8080/8443/3000, or you'll miss them.
- **Screenshots/verification need headless Chromium** — ensure it's available.

**Both:** recon output is a **starting map, not ground truth** — validate before acting, and remember more/newer sources and tools (subfinder, other PD tools) complement rather than replace these.

---

## 18. Legal and Ethical Note

- **Scope discipline is paramount in recon** — enumeration expands your view of the attack surface, and it's easy to wander **out of scope** (Amass ASN/permutation expansion can surface assets you're *not* authorized to test; a domain resolving into a shared cloud netblock doesn't make the neighbors in-scope). **Only probe/enumerate assets explicitly in your authorization.**
- **Passive vs active matters legally.** Passive OSINT (querying third parties) is low-risk; **active** techniques — Amass `-brute`/`-active`/zone transfers and **all** of httpx (which sends requests to the target) — interact with the target directly and require authorization. Confirm your engagement permits active recon.
- **Amass ASN/org expansion can pull in third-party assets** — verify ownership/scope before touching anything it surfaces; being *findable* doesn't make it *in-scope*.
- **httpx is active testing at scale** — thousands of probes are real traffic that's logged and rate-limitable; throttle (`-rl`, `-t`, `-delay`) and stay in scope.
- **Handle discovered data responsibly** — asset inventories, screenshots, and extracted secrets are sensitive; use only within scope and per your rules of engagement/privacy law.
- **Practice legally:** enumerate/probe domains you **own**, authorized bug-bounty targets **within their stated scope**, or lab environments. Public CT/passive-DNS lookups on any domain are public info and fine to study.

---

### Where to go next

- Run the **full pipeline** on a domain you own or an in-scope bug-bounty target: `subfinder` + `amass subs -names` → `httpx -sc -title -td` → eyeball the profiled list. Seeing a raw name dump become a categorized target table is the "aha" that shows why httpx is the glue (§11).
- On **Amass v5**, deliberately run `amass enum -o subs.txt`, note it's **empty**, then fix it with `amass subs -names` — internalizing that trap now saves you a silent-failure headache later (§7).
- Configure a couple of **free API keys** (e.g., VirusTotal, SecurityTrails) in Amass and re-run — watch the result count jump, proving why keys matter (§8).
- Route httpx output onward: WordPress titles → **WPScan**, `403`s/admin panels → **Burp**, everything → **Nuclei**, IPs → **nmap**. That connects this recon front end to the entire toolkit you've built.

*End of reference.*

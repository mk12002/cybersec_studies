# Sublist3r — The Complete Reference (Beginner → Advanced)

> A ground-up reference for subdomain enumeration with **Sublist3r**, and — just as importantly — the **recon concepts** behind it (DNS, OSINT, certificate transparency, passive DNS, DNS brute-forcing).
> Includes an honest assessment of the tool's current state and the modern alternatives that have largely replaced it.

---

## Table of Contents

1. [What Sublist3r Is and Why It Exists](#1-what-sublist3r-is-and-why-it-exists)
2. [Honest Status Check (Read This First)](#2-honest-status-check-read-this-first)
3. [Prerequisite: DNS and Subdomains Explained](#3-prerequisite-dns-and-subdomains-explained)
4. [Why Subdomain Enumeration Matters (The Recon Rationale)](#4-why-subdomain-enumeration-matters-the-recon-rationale)
5. [Passive vs Active Enumeration — The Core Taxonomy](#5-passive-vs-active-enumeration--the-core-taxonomy)
6. [How Sublist3r Works Internally](#6-how-sublist3r-works-internally)
7. [The Data Sources — The Concepts Behind Each Discovery](#7-the-data-sources--the-concepts-behind-each-discovery)
8. [Installation](#8-installation)
9. [Command-Line Options (Full Breakdown)](#9-command-line-options-full-breakdown)
10. [Worked Examples with Output, Explained](#10-worked-examples-with-output-explained)
11. [Using Sublist3r as a Python Module](#11-using-sublist3r-as-a-python-module)
12. [Interpreting and Validating Results](#12-interpreting-and-validating-results)
13. [Where It Fits: Chaining Into a Recon Workflow](#13-where-it-fits-chaining-into-a-recon-workflow)
14. [Limitations and Pitfalls](#14-limitations-and-pitfalls)
15. [Modern Alternatives (What People Use Now)](#15-modern-alternatives-what-people-use-now)
16. [Legal and Ethical Note](#16-legal-and-ethical-note)

---

## 1. What Sublist3r Is and Why It Exists

**Sublist3r** is a Python command-line tool that **enumerates the subdomains of a target domain using OSINT** (Open-Source Intelligence). Written by Ahmed Aboul-Ela and released in 2015, it became one of the most-referenced beginner recon tools because it did one thing simply: give it `example.com` and it tries to discover `mail.example.com`, `dev.example.com`, `vpn.example.com`, `admin.example.com`, and so on.

Its approach is to **query many public sources** that happen to know about subdomains — search engines, DNS aggregators, threat-intel databases, certificate records — collect the names they return, de-duplicate them, and optionally **brute-force** more names using a wordlist (via the bundled `subbrute` module). It performs no exploitation; it's a **reconnaissance / information-gathering** tool that runs at the very start of an engagement.

**Why it exists:** the first question in almost any external web assessment is *"what does this organization actually expose to the internet?"* Companies rarely have just `www`. They have dozens or hundreds of subdomains — many forgotten, misconfigured, or running old software. Sublist3r automates the tedious work of finding them from public data, without ever sending a packet to the target's own servers (in passive mode).

---

## 2. Honest Status Check (Read This First)

Because you're learning, you need to know this up front or you'll be confused when the tool returns almost nothing:

**The original Sublist3r (aboul3la/Sublist3r) is essentially frozen and partially broken as of 2026.** Specifically:

- **Search-engine scraping is largely defeated.** Google, Bing, Yahoo, Baidu, and Ask now deploy aggressive bot detection, IP rate-limiting, and CAPTCHAs. Sublist3r's Google module — historically its biggest source — is frequently non-functional. You'll often see it return a handful of results (sometimes just `www`) where it once returned dozens.
- **Several API sources have changed or expired.** Some aggregators it queries have altered their endpoints, added auth requirements, or shut down, so those modules silently return nothing.
- **No active development.** Bugs and broken modules aren't being fixed, and no new data sources are added, while the ecosystem has moved on.
- **The DNS brute-force can behave like a self-DoS** at high thread counts (hammering resolvers).

**So why learn it at all?** Two good reasons:

1. **It's a perfect teaching tool.** It's small and readable, and each of its data sources maps to a *fundamental recon concept* (search dorking, certificate transparency, passive DNS, DNS brute force). Understanding *how Sublist3r tries to find subdomains* teaches you how **all** subdomain tools work.
2. **You'll see it everywhere** — in old tutorials, "top 10 recon tools" lists, and existing scripts. Knowing its real capabilities (and limits) keeps you from trusting stale output.

**What to actually use for real work:** modern tools like **subfinder** and **amass** (covered in §15) query 40+ current sources and produce clean, pipeable output. Treat Sublist3r as a concept teacher and a historical reference, and reach for those in practice. Several community forks (Sublist3r2, "modernized" rewrites, v3.0 forks) also attempt to fix the broken modules with varying success.

---

## 3. Prerequisite: DNS and Subdomains Explained

You cannot understand subdomain enumeration without understanding **DNS**. Here's the minimum, built up cleanly.

### The domain name hierarchy

Domain names are read **right to left**, most-general to most-specific:

```
        mail   .   example   .   com   .
         |          |            |      |
     subdomain    domain       TLD    root (usually implicit)
   (3rd level)  (2nd level)  (top level)
```

- **Root** — the invisible `.` at the very top.
- **TLD (Top-Level Domain)** — `.com`, `.org`, `.io`, `.co.uk`.
- **Registrable/second-level domain** — `example.com` — the part an organization registers.
- **Subdomain** — anything to the left: `mail.example.com`, `dev.api.example.com`. An organization can create unlimited subdomains under a domain it controls, at no marginal cost and often with no central inventory — which is exactly why they proliferate and get forgotten.

### DNS resolution in one paragraph

**DNS (Domain Name System)** translates human names into IP addresses. When something needs to reach `mail.example.com`, a **resolver** walks the hierarchy — asks the root servers who handles `.com`, asks the `.com` servers who handles `example.com`, then asks `example.com`'s **authoritative name server** for the record for `mail`. The answer is cached along the way. This is why enumeration is possible: subdomains leave traces in many systems (resolvers, logs, certificates, third-party databases) during their normal existence.

### DNS record types you'll meet

- **A** — maps a name to an IPv4 address. **AAAA** — to an IPv6 address.
- **CNAME** — an alias pointing one name at another name (`shop.example.com` → `example.myshopify.com`). **CNAMEs are central to subdomain takeover** (§4).
- **MX** — mail servers for the domain.
- **NS** — the authoritative name servers.
- **TXT** — arbitrary text (SPF, domain verification, DKIM) — often leaks internal hostnames and third-party services.
- **SOA** — administrative "start of authority" info for the zone.

### A zone and why "just ask for the list" usually fails

A **zone** is the portion of the DNS namespace an organization administers. There's a DNS feature called a **zone transfer (AXFR)** that dumps *every* record in a zone at once — the enumerator's dream. But it's meant only for replication between an organization's own name servers, so **properly configured servers refuse AXFR from strangers.** Occasionally a misconfigured server allows it and hands you the entire subdomain list instantly (always worth a quick `dig AXFR`), but you can't rely on it. Because the easy path is usually closed, tools like Sublist3r instead **piece the list together from indirect public sources** — which is what the rest of this document is about.

---

## 4. Why Subdomain Enumeration Matters (The Recon Rationale)

Subdomain enumeration is foundational because **you cannot test what you haven't found.** The size and quality of your subdomain list often determines the entire outcome of an assessment.

### Attack surface expansion

Each subdomain is a potential entry point — a distinct application, API, admin panel, or service, each with its own code, configuration, and vulnerabilities. `www.example.com` might be a hardened marketing site, while `jenkins-old.example.com` is an unpatched CI server with default credentials. **The main site is rarely where the breach happens; the forgotten subdomain is.**

### Shadow IT and forgotten assets

Large organizations spin up subdomains for demos, staging, marketing campaigns, acquisitions, and one-off projects — then forget them. These "orphaned" assets:

- run **outdated software** no one patches,
- expose **staging/dev environments** with weaker controls, verbose errors, or real data,
- host **undocumented APIs** and internal tools that were never meant to be public.

Enumeration surfaces exactly this shadow IT.

### Subdomain takeover (a whole vuln class enabled by enumeration)

This is the most important concept to connect to enumeration. A **subdomain takeover** happens when a subdomain has a **dangling DNS record** — typically a **CNAME pointing at a third-party service that's no longer claimed.** Example:

1. The company set `blog.example.com` → CNAME → `example.github.io` (or a Heroku/S3/Azure endpoint).
2. They later deleted the GitHub Pages site but **left the CNAME in DNS.**
3. Now `blog.example.com` points at an unclaimed target. An attacker registers that GitHub Pages name, and suddenly **serves their own content on the company's subdomain** — enabling convincing phishing, cookie theft (if cookies are scoped to `*.example.com`), and OAuth/redirect abuse.

You can only find these by **enumerating subdomains and then checking each one's DNS record for a dangling third-party pointer.** Enumeration is step one; the takeover is the payoff. (Tools like `subjack`, `nuclei`'s takeover templates, and `dnsReaper` automate the checking step once you have the list.)

### The bottom line

More discovered subdomains → more attack surface → more chances to find the one weak asset. That's why recon-heavy disciplines like bug bounty treat subdomain enumeration as a continuous, high-value activity.

---

## 5. Passive vs Active Enumeration — The Core Taxonomy

Every subdomain discovery technique is either **passive** or **active**. Understanding the split is essential — it governs how stealthy you are, how legal/safe the activity is, and what you'll find.

### Passive enumeration

You gather subdomains **from third-party sources without ever sending traffic to the target's own infrastructure.** You're querying Google, certificate logs, threat-intel databases, passive-DNS providers — all of which already collected this data. The target's servers never see you.

- **Pros:** stealthy (no logs on the target), low legal risk, fast, no direct interaction.
- **Cons:** only finds subdomains that some third party already knows about; misses names that exist but were never indexed, logged, or certificated.

Most of Sublist3r's sources are **passive** (search engines, Netcraft, VirusTotal, DNSdumpster, certificate/SSL sources, passive DNS).

### Active enumeration

You **interact with the target's DNS directly** — most commonly by **brute-forcing**: guessing candidate names (`admin`, `dev`, `vpn`, `test`…) and asking DNS whether each resolves. Also includes zone-transfer attempts and DNS "permutation/alteration" scanning.

- **Pros:** finds subdomains **no public source knows about** — the internal-sounding, never-indexed names — which are often the juiciest.
- **Cons:** generates DNS queries that can be logged/rate-limited; noisier; the guessing is only as good as your wordlist.

Sublist3r's `subbrute` integration (the `-b` flag) is the **active** part of the tool.

**Best practice: do both.** Passive gives you the known surface cheaply and quietly; active brute-forcing then digs up the hidden names. Serious recon layers many passive sources *and* brute-forcing *and* permutation scanning.

---

## 6. How Sublist3r Works Internally

Understanding the architecture makes every option and every output line make sense.

**The pipeline, end to end:**

1. **Parse arguments** — the target domain and options.
2. **Spin up one enumeration thread per source.** Sublist3r runs its search-engine and aggregator modules **concurrently** (each is a subclass of a common `enumratorBase` class). Each module knows how to query its source and parse subdomains out of the response.
3. **Each module queries its source repeatedly, paging through results**, extracting hostnames that end in the target domain, and applying a **subdomain regex** to pull valid names from raw HTML/JSON/text.
4. **A module stops** when it stops finding *new* subdomains across pages (or hits an internal page limit / gets blocked).
5. **Results are merged and de-duplicated** into a single unique set (case-normalized, wildcard/junk filtered).
6. **(Optional) subbrute brute-force** runs if `-b` is set: it resolves a large wordlist of candidate names against the domain using many threads and its own resolver list, adding any that resolve.
7. **(Optional) port check** if `-p` is set: a simple TCP connect test against each found subdomain for the specified ports.
8. **Output** — print to screen (colored, optionally real-time with `-v`) and/or save to a file with `-o`.

**Key design points:**

- **Threading model:** the passive engines run in parallel with each other; the `-t` (threads) option controls **only the subbrute brute-force** concurrency, not the passive engines.
- **Deduplication:** the whole point of using many sources is coverage; the same subdomain will be reported by several sources, so Sublist3r keeps a set and reports each unique name once.
- **Validation is minimal by default.** The passive modules report names *as the sources present them*. Sublist3r doesn't necessarily confirm each name still resolves (brute-force names do resolve, because that's how they're found). This is why you should **re-resolve results yourself** before trusting them (§12).

---

## 7. The Data Sources — The Concepts Behind Each Discovery

This is the heart of the tool and the most transferable knowledge: **each source represents a different way that subdomains leak into the public record.** Learn these and you understand subdomain enumeration in general, not just Sublist3r. (Reliability notes reflect the tool's current degraded state.)

### 7.1 Search engines: Google, Bing, Yahoo, Baidu, Ask

**Concept — search dorking.** Search engines crawl and index the web. If a page on `dev.example.com` was ever linked and crawled, the engine knows that hostname. Sublist3r queries the engine for pages under the target domain and **extracts subdomains from the result URLs**, using the search operator idea behind a *dork* like:

```
site:example.com -site:www.example.com
```

The `-site:www...` exclusion is the clever trick: it tells the engine "show me pages on the domain **that aren't** on `www`," progressively pushing new subdomains into the results as you exclude the ones already found. Sublist3r automates this exclusion loop, harvesting `mail`, `blog`, `shop`, etc.

**Reliability today: poor.** This is precisely what modern bot-detection breaks — the engines serve CAPTCHAs or block the scraper. Google especially is often dead. This was Sublist3r's flagship source, and its decline is the main reason the tool underperforms now.

### 7.2 Netcraft

**Concept.** Netcraft runs long-standing internet surveys and holds historical data about sites and the servers/subdomains associated with a domain. Sublist3r queries Netcraft's search and parses subdomains from the response. It's a passive third-party database — no target contact. Reliability varies as Netcraft's pages change.

### 7.3 VirusTotal

**Concept — threat-intel aggregation.** VirusTotal analyzes huge volumes of URLs and files and, as a side effect, records **subdomains it has observed** for a domain (from submitted URLs, passive DNS, etc.). Its "relations/subdomains" data is a genuinely useful passive source. **Caveat:** VirusTotal now generally **requires an API key** and rate-limits, so the un-keyed legacy module may return little or nothing.

### 7.4 ThreatCrowd

**Concept.** ThreatCrowd was a threat-intelligence search engine correlating domains, IPs, and subdomains from security telemetry. Its API returned known subdomains for a domain. **Caveat:** ThreatCrowd's service has been unreliable/limited for years, so this module frequently returns nothing today.

### 7.5 DNSdumpster

**Concept — DNS reconnaissance aggregation.** DNSdumpster (by Hacker Target) builds a map of a domain's DNS: hosts, MX, and discovered subdomains, drawing on its own data collection. It's a good passive source when it works, but it uses CSRF tokens/anti-scraping that can break automated queries.

### 7.6 SSL/TLS certificates — Certificate Transparency (the crown jewel)

**This is the single most valuable passive concept in modern subdomain enumeration, so understand it well.**

**Certificate Transparency (CT)** is a public-accountability system (RFC 6962). To combat mis-issued certificates, Certificate Authorities are required to submit every TLS certificate they issue to **public, append-only CT logs.** Anyone can search these logs.

Why this is gold: to serve HTTPS on `internal-admin.example.com`, the organization needed a certificate for that name, and **that certificate's issuance is now permanently, publicly logged** — including the hostnames in its **Subject** and **Subject Alternative Name (SAN)** fields. So CT logs reveal subdomains that:

- were **never linked or indexed** (so search engines can't find them),
- **sound internal** (`vpn`, `jenkins`, `staging`, `vault`) — exactly the high-value ones,
- existed at **any point in history** (logs are append-only; old certs remain).

You query CT via services like **`crt.sh`** (or Censys). A simple manual query:

```
https://crt.sh/?q=%25.example.com&output=json
```

(`%25` is a URL-encoded `%` wildcard → "all certs for `*.example.com`".)

**Limitation:** **wildcard certificates.** If the org uses one cert for `*.example.com`, CT shows only the wildcard, not the specific names behind it — so CT complements, but doesn't replace, brute-forcing. Sublist3r includes an SSL/certificate module (engine name `ssl`) built on this idea; modern tools lean on CT heavily because it's reliable and rich.

### 7.7 Reverse DNS and Passive DNS

**Reverse DNS (PTR concept):** given an IP, ask DNS what name it maps to (`PTR` record). If you know the target's IP ranges, reverse lookups across those ranges can reveal hostnames. Useful but limited (PTR records are often unset or generic).

**Passive DNS:** specialized providers (sensors on resolvers worldwide) record **historical DNS resolutions** — "over time, these names resolved to these IPs." Querying passive DNS for a domain yields subdomains that were actually resolved in the wild, even if never indexed or currently offline. It's one of the most powerful passive techniques; Sublist3r's `passivedns` engine taps this idea, and modern tools query many passive-DNS sources.

### 7.8 subbrute — active DNS brute-forcing

**Concept.** Everything above is passive (someone else already knew the name). **Brute-forcing finds names nobody published** by *guessing* them and asking DNS directly. `subbrute` (by TheRook, integrated via the `-b` flag) does this:

1. Take a **wordlist** of likely subdomain labels (`admin`, `dev`, `test`, `mail`, `vpn`, `api`, `portal`, `git`, `staging`, …). Sublist3r's list derives from **Bitquark's dnspop** research — labels ranked by how often they actually occur in the wild, so common names are tried first.
2. For each candidate `label`, resolve `label.example.com` using a pool of DNS **resolvers**, across many **threads** (`-t`).
3. If it **resolves to an IP**, the subdomain exists → add it.

**Wildcard DNS detection (critical to avoid false positives).** Some domains use **wildcard DNS**: `*.example.com` resolves *everything* to a catch-all IP. Naive brute-forcing would then report `asdfqwerty.example.com`, `doesnotexist.example.com`, and every other guess as "found." subbrute defends against this by first resolving a **random, definitely-nonexistent** name; if that resolves, a wildcard is in play, and the tool accounts for it (e.g., treating the wildcard IP as a "not a real finding" baseline) rather than reporting garbage.

**The "self-DoS" caveat.** Brute-forcing fires enormous numbers of DNS queries. Too many threads (`-t`) can overwhelm your own resolver, your network, or trip target/resolver rate limits — sometimes producing *worse* results (timeouts read as "doesn't exist"). Tune threads sensibly; more is not always better.

**Coverage vs wordlist.** Brute-force only finds what's **in your wordlist**. `zzqxje.example.com` will never be guessed. That's the inherent limit of active enumeration — and why passive sources (which find arbitrary real names) and active brute-force (which finds unpublished common names) are complementary.

---

## 8. Installation

Sublist3r is a Python tool. It supports Python 3 (and historically Python 2.7). Dependencies: **`requests`**, **`dnspython`**, **`argparse`**.

**Clone from GitHub (most common):**
```bash
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
python sublist3r.py -d example.com
```

**Via pip:**
```bash
pip install sublist3r
sublist3r -d example.com
```

**Kali Linux (often pre-packaged):**
```bash
sudo apt install sublist3r
sublist3r -d example.com
```

**Isolated (recommended to avoid dependency clashes):**
```bash
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python sublist3r.py -d example.com
```

> If results look empty/broken, it's usually not your install — it's the degraded sources (§2). Verify your setup works by confirming at least the certificate (`ssl`) source returns data, which is the most reliable one remaining.

---

## 9. Command-Line Options (Full Breakdown)

```
Usage: python sublist3r.py -d DOMAIN [options]
```

| Short | Long | Argument | Purpose |
|---|---|---|---|
| `-d` | `--domain` | domain | **(Required)** The domain to enumerate subdomains for, e.g. `example.com`. |
| `-b` | `--bruteforce` | *(flag)* | Enable the **subbrute** DNS brute-force module (active enumeration). |
| `-p` | `--ports` | e.g. `80,443` | After enumeration, TCP-connect-scan each found subdomain for these ports; report which have them open. |
| `-v` | `--verbose` | *(flag)* | **Verbose**: display each discovered subdomain **in real time** as it's found (colored by source). Without it, you get a summary at the end. |
| `-t` | `--threads` | integer | Number of threads for the **brute-force** module only (default is a moderate value). Higher = faster but riskier (see self-DoS, §7.8). |
| `-e` | `--engines` | comma list | Restrict to **specific sources**, e.g. `-e google,bing,ssl`. Valid names include: `baidu, yahoo, google, bing, ask, netcraft, dnsdumpster, virustotal, threatcrowd, ssl, passivedns`. |
| `-o` | `--output` | filename | Save unique subdomains (one per line, plain text) to a file. |
| `-n` | `--no-color` | *(flag)* | Disable colored output (useful when piping/logging). |
| `-h` | `--help` | *(flag)* | Show help and exit. |

**Notes:**
- `-t` affects **only** brute-forcing; it does nothing without `-b`.
- `-e` is your friend today: skip the broken/slow engines and run the reliable ones (e.g., `-e ssl,passivedns,dnsdumpster`).
- `-o` output is deliberately plain (one name per line) so you can pipe it into other tools — the intended way to use recon output.

---

## 10. Worked Examples with Output, Explained

> Outputs below are **representative** of Sublist3r's format (banner + per-source progress + summary list). Real counts today are often much lower than historical examples because of the broken sources.

### 10.1 Basic passive enumeration

```bash
python sublist3r.py -d example.com
```

Representative output:
```
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|

                # Coded By Ahmed Aboul-Ela

[-] Enumerating subdomains now for example.com
[-] Searching now in Baidu..
[-] Searching now in Yahoo..
[-] Searching now in Google..
[-] Searching now in Bing..
[-] Searching now in Ask..
[-] Searching now in Netcraft..
[-] Searching now in DNSdumpster..
[-] Searching now in Virustotal..
[-] Searching now in ThreatCrowd..
[-] Searching now in SSL Certificates..
[-] Searching now in PassiveDNS..
[-] Total Unique Subdomains Found: 7
www.example.com
mail.example.com
blog.example.com
dev.example.com
api.example.com
vpn.example.com
support.example.com
```

**Reading it:**
- The **banner** confirms the tool/author.
- Each `[-] Searching now in <Source>..` line is **one module starting** (they run concurrently, so ordering is roughly launch order). A source that returns nothing still prints its line — silence isn't necessarily an error; the source may be blocked or empty for this domain.
- `Total Unique Subdomains Found: 7` is the **de-duplicated** count across all sources.
- The list is your result. Note it's **unvalidated** — some names might be stale (no longer resolve). Validate before acting (§12).

### 10.2 Verbose, real-time, saved to file

```bash
python sublist3r.py -d example.com -v -o example_subs.txt
```

With `-v`, each subdomain prints the instant a source finds it, tagged by source and colored:
```
[-] Searching now in Google..
Google: api.example.com
Google: blog.example.com
[-] Searching now in SSL Certificates..
SSL Certificates: jenkins.example.com
SSL Certificates: staging.example.com
SSL Certificates: vault.example.com
...
```
`-o example_subs.txt` writes the final unique list (one per line) for piping into the next tool. Notice how the **SSL Certificates** source surfaces internal-sounding names (`jenkins`, `staging`, `vault`) that search engines never would — that's certificate transparency (§7.6) doing the heavy lifting.

### 10.3 Passive + active brute-force

```bash
python sublist3r.py -d example.com -b -t 50 -v
```
- `-b` enables subbrute, so after the passive sources finish, it brute-forces the wordlist.
- `-t 50` uses 50 threads for that brute-force (tune down if you see timeouts/instability).
- You'll see a `[-] Starting bruteforce module now using subbrute..` phase, then newly-resolved names appear. This is where you catch unpublished internal names — at the cost of noise and DNS queries hitting the target's authoritative servers (active!).

### 10.4 Targeted, reliable sources only + port check

```bash
python sublist3r.py -d example.com -e ssl,passivedns,dnsdumpster -p 80,443 -o live.txt
```
- `-e ssl,passivedns,dnsdumpster` skips the flaky search-engine scrapers and runs the sources most likely to work today.
- `-p 80,443` then does a quick TCP check on each found subdomain and flags those with 80/443 open — a first cut at "which of these are live web servers." (It's a basic connect test, not a substitute for `nmap`/`httpx`.)

---

## 11. Using Sublist3r as a Python Module

Sublist3r can be imported and driven programmatically, which is how you'd fold it into a larger recon script:

```python
import sublist3r

subdomains = sublist3r.main(
    domain='example.com',
    no_threads=40,          # threads for the bruteforce module
    savefile='subs.txt',    # output file (or None)
    ports=None,             # e.g. '80,443' or None
    silent=False,           # suppress console noise if True
    verbose=False,          # real-time printing
    enable_bruteforce=False,# set True to run subbrute
    engines=None            # None = all; or 'ssl,passivedns'
)

print(f"Found {len(subdomains)} subdomains")
for s in subdomains:
    print(s)
```

`main()` returns the **list of unique subdomains**, so you can feed it straight into resolution, HTTP probing, or takeover checks in the same script. The parameter order matters — match the signature above.

---

## 12. Interpreting and Validating Results

Sublist3r's passive output is a list of **candidate** names from third parties. Before you act on them, validate — otherwise you'll waste time on dead hosts and report false positives.

**1. Re-resolve every name.** A name in a CT log or old index may no longer exist. Resolve each and keep the ones that answer:
```bash
# quick DNS resolution check with dnsx (ProjectDiscovery)
cat example_subs.txt | dnsx -silent -a -resp
```

**2. Watch for wildcard DNS.** If *everything* resolves to the same IP, you may be seeing a wildcard, not real hosts. Resolve a guaranteed-fake name (`zzq-nope-123.example.com`); if it answers, treat identical-IP results skeptically.

**3. Probe for live web services.** Resolving ≠ serving HTTP. Find which are actually live:
```bash
cat example_subs.txt | httpx -silent -status-code -title -tech-detect
```

**4. De-duplicate and normalize** (lowercase, strip trailing dots) if you merged multiple tools' outputs.

**5. Remember what's missing.** Passive misses unpublished names (run brute-force/permutations); brute-force misses names not in the wordlist. A "complete" list rarely exists — enumeration is best-effort and worth repeating over time.

---

## 13. Where It Fits: Chaining Into a Recon Workflow

Subdomain enumeration is **step one**. Its plain-text output is designed to pipe into the rest of the pipeline:

```
[ Sublist3r / subfinder / amass ]   → raw subdomain list
            │
            ▼
[ dnsx ]        resolve & filter to names that actually exist
            │
            ▼
[ httpx ]       probe for live HTTP(S); grab status, title, tech
            │
            ├──► [ subjack / nuclei takeover templates ]  → subdomain takeover checks
            ├──► [ aquatone / gowitness ]                 → screenshot every live host at scale
            ├──► [ naabu / nmap ]                         → port/service scanning
            └──► [ nuclei / Burp / ZAP ]                  → vulnerability scanning & manual testing
```

The discipline: **enumerate → resolve → probe → triage → attack.** Sublist3r (or better, subfinder/amass) owns the first box; everything downstream depends on the quality of that list, which is why recon experts obsess over enumeration breadth.

---

## 14. Limitations and Pitfalls

- **Degraded sources (the big one).** Search-engine scraping is largely broken; several APIs need keys or are defunct. Expect thin results and don't mistake that for "the target has few subdomains."
- **No output for a source ≠ error.** Blocked/empty sources still print their "Searching now in…" line. Absence of results isn't a crash.
- **Unvalidated passive results.** Names may be stale; always re-resolve (§12).
- **Wildcard DNS false positives** during brute-force if not handled — verify.
- **Brute-force self-DoS / rate-limiting.** Too many threads degrade results and generate noise.
- **Only finds wordlist names** in active mode; only finds published names in passive mode.
- **No permutation/alteration scanning.** Modern tools generate variations (`api-dev`, `dev-api`, `api2`) from found names; Sublist3r doesn't. (See `altdns`/`gotator`.)
- **Plain-text only output.** No JSON/structured formats for easy tooling — a real friction point today.
- **Active steps (brute-force, port check) touch the target** — that's no longer pure passive recon; treat accordingly (§16).

---

## 15. Modern Alternatives (What People Use Now)

For real work, these have largely replaced Sublist3r. Knowing them is part of knowing Sublist3r's place.

- **subfinder** (ProjectDiscovery) — the de-facto **CLI replacement**. Queries **40+ current passive sources**, supports API keys for premium sources, is fast, and outputs clean/JSON data that pipes natively into `dnsx`/`httpx`/`nuclei`. If you take one thing from this section: **learn subfinder.**
- **amass** (OWASP) — the most **comprehensive** framework: many passive sources, brute-forcing, permutations/alterations, and DNS/graph features. Heavier and slower, but deep. Great for thorough or long-running recon.
- **assetfinder** (tomnomnom) — tiny, fast, scriptable passive finder; popular in one-liner pipelines.
- **findomain** — fast Rust-based enumerator with monitoring features.
- **crt.sh directly** — for pure certificate-transparency queries you can just hit `crt.sh` (web or JSON API); it's the reliable core that many tools wrap.
- **Community Sublist3r forks** — "modernized" rewrites and v2/v3 forks that fix broken modules and add sources like `crt`, `hackertarget`, `anubis`; useful if you specifically want the Sublist3r interface with working sources.

**How to think about it:** the *concepts* in §7 are permanent; the *tools* that implement them best change over time. Sublist3r taught a generation those concepts. Today, run **subfinder** (breadth) + **amass** (depth) + **CT/crt.sh**, brute-force with a good wordlist, then validate and probe.

---

## 16. Legal and Ethical Note

- **Passive enumeration is low-risk but not zero.** You're querying third parties, not the target — generally acceptable for authorized recon and OSINT. Still, respect those third parties' terms (automated search-engine scraping can violate ToS), and confirm your engagement permits OSINT recon.
- **Active steps are different.** Brute-forcing subdomains sends DNS queries that hit the target's authoritative name servers, and the `-p` port check connects to the target's hosts. These are **active interactions** — only do them against domains you **own or are explicitly authorized to test** (signed scope, in-scope bug-bounty program, or your own lab).
- **Finding a subdomain is not permission to attack it.** Enumeration produces a map; testing what you find requires it to be in scope. A discovered `admin.example.com` outside your authorization is off-limits.
- **Practice legally:** enumerate domains you own, use bug-bounty programs with explicit subdomain scope, or lab environments. Certificate-transparency lookups on any domain are public information and fine to study.

---

### Where to go next

- **Cement the concepts, not the tool:** for a domain you own, run Sublist3r with `-e ssl` and separately query `crt.sh` — compare results and watch certificate transparency in action (§7.6).
- Then run **subfinder** and **amass** on the same domain and compare coverage; you'll immediately see why they replaced Sublist3r, while recognizing every technique they use from §7.
- Finally, pipe your list through `dnsx → httpx` and try a **subdomain-takeover** check (§4) — that's where enumeration turns into a real finding.

*End of reference.*

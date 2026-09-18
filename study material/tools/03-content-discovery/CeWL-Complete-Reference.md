# CeWL — The Complete Reference (Beginner → Advanced)

> A ground-up reference for **CeWL** (Custom Word List generator): why a wordlist built from the *target itself* beats a generic one, how CeWL spiders and extracts it, the metadata/email OSINT it also gathers, and — crucially — how its output plugs into the password-cracking pipeline.

---

## Table of Contents

1. [What CeWL Is and Why It Exists](#1-what-cewl-is-and-why-it-exists)
2. [Status and Key Facts](#2-status-and-key-facts)
3. [The Core Concept: Why Targeted Wordlists Beat Generic Ones](#3-the-core-concept-why-targeted-wordlists-beat-generic-ones)
4. [Where CeWL Fits in the Password-Cracking Pipeline](#4-where-cewl-fits-in-the-password-cracking-pipeline)
5. [How CeWL Works Internally](#5-how-cewl-works-internally)
6. [The Spider and Its Limits](#6-the-spider-and-its-limits)
7. [Beyond Words: Metadata and Email Extraction (OSINT)](#7-beyond-words-metadata-and-email-extraction-osint)
8. [FAB — Files Already Bagged](#8-fab--files-already-bagged)
9. [URL Structure Capture](#9-url-structure-capture)
10. [Installation](#10-installation)
11. [Command-Line Options (Full Breakdown)](#11-command-line-options-full-breakdown)
12. [Worked Examples with Output, Explained](#12-worked-examples-with-output-explained)
13. [Using CeWL Output: Rules, Cracking, Spraying, Discovery](#13-using-cewl-output-rules-cracking-spraying-discovery)
14. [Tuning for Quality Wordlists](#14-tuning-for-quality-wordlists)
15. [Limitations and Pitfalls](#15-limitations-and-pitfalls)
16. [Alternatives and Related Tools](#16-alternatives-and-related-tools)
17. [Where It Fits: Workflow and Chaining](#17-where-it-fits-workflow-and-chaining)
18. [Legal and Ethical Note](#18-legal-and-ethical-note)

---

## 1. What CeWL Is and Why It Exists

**CeWL** (Custom Word List generator, pronounced *"cool"*) is a Ruby tool that **spiders a target website and builds a wordlist from the words actually found on it.** Instead of handing a password cracker a giant generic list, you give it a list of terms drawn from the target's own site — company jargon, product names, project codenames, local terminology, people's names — the vocabulary a real user at that organization is likely to have baked into a password.

Written by **Robin Wood (DigiNinja)**, CeWL was inspired by a discussion about creating custom word lists by crawling a target's website and collecting unique words. Point it at a URL and it crawls to a set depth, extracts the visible text, and outputs the unique words (by default, everything 3+ characters, sorted by frequency). It can *also* harvest **document metadata** (to build username lists) and **email addresses** along the way.

**Why it exists / the problem it solves:** password cracking succeeds or fails on the quality of your **candidate words**. Generic lists like `rockyou.txt` contain common global passwords but **know nothing about your specific target** — they don't contain "Volganeer2024" derived from a company called Volganeer, or "RedFalconVPN" from an internal project. Humans overwhelmingly base passwords on **words that are meaningful to them**, and a company's own website is a concentrated source of exactly those meaningful words. CeWL automates turning that site into a **target-specific dictionary** — dramatically improving your odds against organization-flavored passwords that generic lists will never guess.

---

## 2. Status and Key Facts

- **Actively maintained** by Robin Wood; current is the **CeWL 6.x** line, with the latest always on GitHub (`github.com/digininja/CeWL`) and tagged releases packaged in **Kali** and other distros.
- **Language:** Ruby. Depends on gems including **nokogiri** (HTML parsing), **mime-types**, **spider**, and **mini_exiftool** — the last of which requires the **`exiftool`** application installed for metadata extraction.
- **Official Docker image:** `ghcr.io/digininja/cewl`.
- **Defaults you must know:**
  - **Depth 2** (follows links two hops from the start URL).
  - **Minimum word length 3.**
  - **Stays on the target site** (won't follow off-site links unless `-o`).
  - **Preserves case** deliberately (so `Product` and `product` are treated as different) — because passwords are case-sensitive; you can lowercase with `--lowercase`.
  - **Sorts words by frequency**; add `--count` to show the counts.
  - **Outputs to stdout** unless you `-w` to a file.
- **Bundled companion:** **FAB** (Files Already Bagged) — extracts author/creator metadata from already-downloaded files to build username lists (§8).

---

## 3. The Core Concept: Why Targeted Wordlists Beat Generic Ones

This is *the* idea behind CeWL, and it's rooted in **how humans actually choose passwords.**

When forced to invent and remember a password, people reach for words that are **familiar and meaningful** to them:

- The **company / product / brand** name (`Acme`, `Volganeer`, `RedFalcon`).
- **Internal project or team names**, office locations, building names.
- **Industry jargon** and technical terms specific to what the company does.
- **Local** sports teams, landmarks, and slang.
- Then they apply predictable **mangling**: capitalize the first letter, append a year or `123`, add a `!`, swap letters for leetspeak (`o`→`0`, `a`→`@`, `s`→`$`).

A generic wordlist (`rockyou.txt`, 14M common leaked passwords) captures the *global* common choices (`password`, `qwerty`, `iloveyou`) but **contains none of the target-specific vocabulary**. If an admin's password is `Volganeer2024!`, no generic list will ever produce the base word `Volganeer` — but that word is almost certainly **all over the company's homepage**, so CeWL grabs it in seconds.

**The insight:** the target's own public content is a **high-density source of the exact words its people are likely to embed in passwords.** CeWL converts "the words this organization talks about" into "the base words most likely to crack this organization's passwords." That relevance is why a few thousand CeWL words often outperform millions of generic ones **for a specific target** — you're guessing from *their* dictionary, not the world's.

**Important nuance:** CeWL gives you **base words**, not finished passwords. `Volganeer` alone won't match `Volganeer2024!`. The next section explains how mangling rules bridge that gap — and why "CeWL + rules" is the real technique, not "CeWL alone."

---

## 4. Where CeWL Fits in the Password-Cracking Pipeline

Understanding this pipeline is what turns CeWL from "a word scraper" into a genuine cracking capability.

```
[ CeWL ]  →  base words   →  [ mangling rules ]  →  candidate passwords  →  [ cracker ]  →  hits
 (spider    (Volganeer,       (append 123/2024,       (Volganeer2024!,        (hashcat/     (cracked
  the site)  RedFalcon,        capitalize, leet,        RedFalcon!,             john/hydra)   creds)
             Products…)        add symbols…)            Pr0ducts123…)
```

1. **CeWL produces base words** — the raw target vocabulary.
2. **Mangling rules transform each base word** into many realistic variants. This is where the magic happens. Crackers apply **rule sets** that mimic human habits:
   - **Case rules:** capitalize first letter (`c`), uppercase all (`u`), toggle case.
   - **Append/prepend:** add digits and symbols (`$1$2$3` → append `123`; append `2024`, `!`, `@123`).
   - **Leetspeak substitutions:** `sa@` (swap `a`→`@`), `so0` (swap `o`→`0`), `se3`.
   - **Combinations** of the above.
   Popular rule files: **`best64.rule`**, **`rockyou-30000.rule`**, **`OneRuleToRuleThemAll.rule`** (hashcat); John's `--rules` (Single, Jumbo, KoreLogic).
3. **The cracker** hashes each candidate and compares against captured hashes (offline) or submits them to a login (online spraying).

**Why this matters:** `Volganeer` (a CeWL base word) + `best64.rule` automatically generates `Volganeer1`, `Volganeer!`, `Volganeer2024`, `Volganeer123`, `volganeer`, `VOLGANEER`, `V0lganeer`, and hundreds more — one of which is the real password. **CeWL supplies the target-specific stems; rules supply the human-predictable decorations.** Neither is enough alone; together they're potent. Keep this mental model whenever you use CeWL.

---

## 5. How CeWL Works Internally

CeWL's pipeline is straightforward:

1. **Start at the given URL** and act as a **spider/crawler**.
2. **Fetch each page**, follow links, and recurse up to the **depth** limit (default 2), by default **staying on the same site**.
3. **Parse the HTML** (via nokogiri) and extract the **visible text** (stripping tags, scripts, styles).
4. **Tokenize** the text into words.
5. **Filter** by minimum length (default 3) and by character rules (letters only by default; `--with-numbers` to allow digits within words).
6. **Count occurrences** of each unique word, keeping original case by default.
7. **Sort by frequency** (most common first) and **output** — to stdout or a file (`-w`), optionally with counts (`--count`).
8. **(Optional) side channels:** if enabled, also extract **document metadata** (`-a`, via exiftool) and **email addresses** (`-e`) encountered while spidering, writing them to their own files.

**Key properties:**
- **Frequency sorting is deliberate** — the words the site emphasizes most are surfaced first, and those are often the most password-relevant (brand/product terms).
- **Case is preserved on purpose** — because a password cracker may need the exact case; the user can normalize later.
- **It's a text miner, not a vulnerability scanner** — CeWL doesn't attack anything; it reads public content. The "attack" happens later, when you crack with the wordlist. (That said, spidering is still active interaction with the target — §18.)

---

## 6. The Spider and Its Limits

CeWL's crawler behaves like the traditional spiders you met in ZAP/Burp, and shares their **main limitation.**

**Controls:**
- **`-d/--depth <n>`** — how many link-hops from the start URL to follow (default 2). Higher depth = more pages = more words, but slower and more likely to wander.
- **`-o/--offsite`** — allow following links to *other* domains. **Use with caution:** combined with high depth, the spider can **drift across the whole internet**, collecting irrelevant words (and hitting sites you're not authorized to touch). Usually leave off.
- **`--allowed <regex>`** — only spider URLs matching a pattern (keep it scoped).
- **`--exclude <file>`** — skip URLs matching regexes (avoid logout links, huge archives, calendars).
- **`-H/--header`, `-u/--ua`** — custom headers / User-Agent.
- **Auth & proxy** — spider authenticated areas (`--auth_type`, `--auth_user`, `--auth_pass`) or route through a proxy (`--proxy_host`, etc.). Authenticated spidering reaches internal vocabulary (product internals, member content) that yields richer wordlists.

**The big limitation — no JavaScript execution.** CeWL parses the HTML it receives; it **does not run JavaScript.** On a modern **single-page app** (React/Angular/Vue) where content is rendered client-side, CeWL sees a near-empty shell and returns a thin wordlist. Workarounds:
- Crawl the site first with a **JS-capable crawler** (or Burp/ZAP with the browser/AJAX spider), then build the wordlist from that content.
- Use a **Burp-based reimplementation** (Whey CeWLer / the CO2 CeWLer, §16) that reads Burp's already-crawled sitemap — no separate crawl, and it benefits from Burp having rendered the app.
- Point CeWL at **content-rich static pages** (blog, about, product docs, PDFs) which hold most of the useful vocabulary anyway.

**Depth vs quality tradeoff:** deeper isn't always better. Depth 2 on a content-rich site often gives an excellent list; going deep can flood the list with boilerplate (navigation, footers, legal text) that dilutes the useful terms. Tune depth to the site.

---

## 7. Beyond Words: Metadata and Email Extraction (OSINT)

CeWL isn't only a word scraper — while spidering it can harvest two other high-value OSINT artifacts.

### 7.1 Document metadata → usernames (`-a/--meta`)

Every document a site hosts — **PDF, DOCX, XLSX, PPTX, images** — carries embedded **metadata**: the **author/creator name**, the **company**, the **software and version** used to create it, sometimes the **username** of the person who saved it. CeWL (with `-a`, using **exiftool** under the hood) downloads such files and extracts this metadata to a file (`--meta_file`).

**Why this is gold:**
- **Real names and usernames** from document authors → a **username list** for spraying/brute-forcing (you can't crack a password if you don't know the account name). If PDFs list author `jsmith` or `John Smith`, you've learned both a username and the org's **naming convention**.
- **Software/version fingerprints** (e.g., "Microsoft Office Word 2016", specific PDF library versions) → hints for other attacks.

This is a classic OSINT technique: organizations leak internal usernames through the metadata of documents they publish without thinking.

### 7.2 Email addresses (`-e/--email`)

CeWL can scrape **email addresses** it finds while spidering, writing them to a file (`--email_file`).

**Why this matters:**
- **Usernames & spray targets** — emails give you valid account identifiers.
- **Naming convention discovery** — seeing `john.smith@corp.com` tells you the format is `first.last`, so you can *derive* likely usernames/emails for other employees found elsewhere (LinkedIn, metadata).
- **Phishing target lists** (in authorized social-engineering engagements).

### 7.3 Words-off / metadata-only (`-n/--no-words`)

If you only want the metadata/emails and not the wordlist, `-n` suppresses word output — CeWL becomes a pure OSINT harvester for usernames/emails.

**The combined picture:** in a single spider run, CeWL can hand you (a) a **target-specific password wordlist**, (b) a **username list** from document metadata, and (c) **email addresses / naming convention** — i.e., both halves of a credential attack (usernames *and* candidate passwords) plus the format to combine them.

---

## 8. FAB — Files Already Bagged

**FAB** is a small companion tool that ships with CeWL. It performs the **same metadata extraction** as CeWL's `-a` option, but on **files you've *already* downloaded** rather than spidering for them.

**Use case:** you (or another tool) have already collected a batch of the target's documents — from the website, from Google dorking (`site:target.com filetype:pdf`), from a data dump — and you want to mine them for **author/creator names** to build a **username list**. Point FAB at the local files and it extracts the metadata, no crawling required.

**Why it's separate:** decoupling "download files" from "extract metadata" lets you gather documents however you like (search engines often surface more documents than an on-site spider will) and then process them in bulk. FAB + a `filetype:` dork harvest is a compact recipe for enumerating an organization's usernames from published documents.

---

## 9. URL Structure Capture

Newer CeWL versions can add **components of the URLs themselves** to the wordlist — not just page text. URLs frequently encode meaningful tokens (product names, technologies, internal terms, environment names) that make excellent wordlist entries *and* content-discovery seeds.

| Option | Adds to the wordlist |
|---|---|
| `--capture-paths` | URL **path** components (e.g., `products`, `legacy-portal`, `v2`, `internal`). |
| `--capture-subdomains` | **Subdomain** components (e.g., `dev`, `staging`, `vpn`). |
| `--capture-domain` | The **main domain** label. |
| `--capture-url-structure` | **All** of the above (domain + paths + subdomains). |

**Why it's useful:** a path like `/products/redfalcon/admin/` contributes `redfalcon` and `admin` — both plausible password stems *and* useful directory-brute-force words. This ties CeWL neatly to content discovery (§13/§17): the structure of the site becomes both cracking fuel and a target-specific discovery wordlist.

---

## 10. Installation

CeWL needs **Ruby** and the **exiftool** application (for metadata).

```bash
# Kali / Parrot (pre-installed, or via apt)
sudo apt install cewl

# From source
git clone https://github.com/digininja/CeWL.git
cd CeWL
sudo gem install bundler
bundle install                 # installs nokogiri, mini_exiftool, etc.
sudo apt install libimage-exiftool-perl   # the exiftool binary (for -a/FAB)
ruby cewl.rb --help

# Docker (no local Ruby needed)
docker run -it --rm -v "${PWD}:/host" ghcr.io/digininja/cewl [OPTIONS] <url>
```

If metadata extraction (`-a`) errors out, it's almost always because **`exiftool` isn't installed** — install it separately from the Ruby gem.

---

## 11. Command-Line Options (Full Breakdown)

Basic form: `cewl [OPTIONS] <url>`

### Spidering & scope
| Option | Purpose |
|---|---|
| `-d, --depth <n>` | Spider depth (default 2). |
| `-o, --offsite` | Allow following off-site links (use carefully). |
| `--allowed <regex>` | Only spider URLs matching this regex. |
| `--exclude <file>` | Skip URLs matching regexes listed in the file. |
| `-u, --ua <agent>` | Set the User-Agent. |
| `-H, --header <name:value>` | Add a custom header (repeatable). |

### Word extraction & formatting
| Option | Purpose |
|---|---|
| `-m, --min_word_length <n>` | Minimum word length (default 3). |
| `-c, --count` | Show the frequency count next to each word. |
| `--lowercase` | Lowercase all words. |
| `--with-numbers` | Accept words that contain numbers. |
| `--convert-umlauts` | Convert accented/umlaut characters to ASCII. |
| `-g, --groups <n>` | Also output **groups** of `n` adjacent words (phrases). |

### Other harvests
| Option | Purpose |
|---|---|
| `-a, --meta` | Extract **document metadata** (needs exiftool). |
| `--meta_file <file>` | Output file for metadata. |
| `-e, --email` | Extract **email addresses**. |
| `--email_file <file>` | Output file for emails. |
| `--meta-temp-dir <dir>` | Temp dir for files downloaded for metadata (default `/tmp`). |
| `-n, --no-words` | Don't output the wordlist (metadata/email only). |
| `-k, --keep` | Keep the downloaded files (for metadata). |

### URL structure capture
| Option | Purpose |
|---|---|
| `--capture-paths` | Add URL path components to the wordlist. |
| `--capture-subdomains` | Add subdomain components. |
| `--capture-domain` | Add the main domain. |
| `--capture-url-structure` | Capture all URL structure (domain + paths + subdomains). |

### Output, auth, proxy, debug
| Option | Purpose |
|---|---|
| `-w, --write <file>` | Write the wordlist to a file (instead of stdout). |
| `-v` | Verbose. |
| `--debug` | Extra debug output. |
| `--auth_type <basic\|digest>` | HTTP auth type. |
| `--auth_user <user>` / `--auth_pass <pass>` | Auth credentials. |
| `--proxy_host <h>` / `--proxy_port <p>` | Proxy host/port (default port 8080). |
| `--proxy_username` / `--proxy_password` | Proxy credentials. |

Run `cewl --help` for the exact, version-accurate list.

---

## 12. Worked Examples with Output, Explained

> Output is **representative**.

### 12.1 Basic wordlist

```bash
cewl https://www.example-corp.com
```
```
CeWL 6.1 Robin Wood (robin@digi.ninja) (https://digi.ninja/)

Volganeer
Products
Services
Solutions
Enterprise
Cloud
Support
Careers
RedFalcon
...
```
Words 3+ chars, sorted by frequency (most-emphasized site terms first), case preserved. This is your raw base-word list. Note target-specific stems like `Volganeer` and `RedFalcon` — exactly what a generic list lacks.

### 12.2 Deeper, longer words, with counts, saved
```bash
cewl -d 3 -m 5 -c -w corp_words.txt https://www.example-corp.com
```
- `-d 3` — spider one hop deeper (more pages, more words).
- `-m 5` — only words 5+ chars (drops noise like `the`, `and`, `you`; longer words make better password stems).
- `-c` — include counts.
- `-w corp_words.txt` — save to file.

With `-c`, the file looks like:
```
Volganeer, 148
Products, 96
Enterprise, 73
RedFalcon, 41
Kubernetes, 28
...
```
The counts help you judge relevance — the top terms are the brand/product vocabulary most likely reused in passwords.

### 12.3 Harvest usernames and emails too
```bash
cewl -d 2 -a --meta_file meta.txt -e --email_file emails.txt -w words.txt https://www.example-corp.com
```
- `-a --meta_file meta.txt` — pull document metadata (authors) → username leads.
- `-e --email_file emails.txt` — scrape emails → usernames + naming convention.
- Produces three artifacts in one run:

`meta.txt` (authors/creators):
```
John Smith
jsmith
Marketing Team
Microsoft Office Word
Adobe PDF Library 15.0
```
`emails.txt`:
```
info@example-corp.com
john.smith@example-corp.com
hr@example-corp.com
```
From these you learn the username convention (`first.last` and/or `jsmith`) and get real account identifiers — the *username* half of a credential attack, alongside the *password* half in `words.txt`.

### 12.4 Metadata-only OSINT pass
```bash
cewl -n -a --meta_file authors.txt -d 2 https://www.example-corp.com
```
`-n` suppresses the wordlist; CeWL becomes a pure author/username harvester.

### 12.5 Authenticated, scoped, through a proxy
```bash
cewl -d 2 --auth_type basic --auth_user analyst --auth_pass 's3cr3t' \
     --allowed '.*example-corp\.com.*' \
     --proxy_host 127.0.0.1 --proxy_port 8080 \
     -w internal_words.txt https://portal.example-corp.com
```
Spider an authenticated portal (richer internal vocabulary), stay strictly in scope with `--allowed`, and route through Burp for visibility.

---

## 13. Using CeWL Output: Rules, Cracking, Spraying, Discovery

CeWL's output is an ingredient, not a finished attack. Here's how to actually use it.

### 13.1 Offline cracking with mangling rules (the main event)

**Hashcat** — apply a rule set to expand each base word into realistic variants:
```bash
# -a 0 = straight/wordlist attack; -m 0 = MD5 (set to your hash type); -r = rules
hashcat -a 0 -m 0 hashes.txt cewl_words.txt -r /usr/share/hashcat/rules/best64.rule
# Bigger coverage:
hashcat -a 0 -m 1000 ntlm_hashes.txt cewl_words.txt -r rules/OneRuleToRuleThemAll.rule
```
**John the Ripper** — same idea with `--rules`:
```bash
john --wordlist=cewl_words.txt --rules=Jumbo hashes.txt
```
Rules turn `Volganeer` into `Volganeer1`, `Volganeer!`, `Volganeer2024`, `V0lganeer`, etc. — this is where CeWL words become cracked passwords (§4).

### 13.2 Online password spraying / brute force

With a **username list** (from CeWL's metadata/emails, §7) and the **wordlist**, spray carefully against a login (respecting lockout policy):
```bash
hydra -L usernames.txt -P cewl_words.txt example-corp.com https-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid"
```
> **Lockout warning:** online spraying can lock accounts. Prefer a *few* high-probability passwords across *many* users (spraying), throttle, and know the lockout policy. Offline cracking (§13.1) has no lockout risk — always prefer it when you have hashes.

### 13.3 Seeding content discovery

A CeWL wordlist (especially with `--capture-url-structure`) is a **target-specific directory/file wordlist** — feed it to the discovery tools:
```bash
feroxbuster -u https://example-corp.com -w cewl_words.txt -x php,bak
ffuf -u https://example-corp.com/FUZZ -w cewl_words.txt
```
Because the words come from the target, they hit target-specific paths (`/redfalcon/`, `/volganeer/`) a generic list would miss — a direct tie-in to the content-discovery tools.

### 13.4 Combine and refine
```bash
# Merge with a generic list, dedupe, sort
cat cewl_words.txt rockyou.txt | sort -u > combined.txt
# Or generate case/leet permutations of CeWL stems before cracking (e.g., with a rules pass)
```

---

## 14. Tuning for Quality Wordlists

A bigger list isn't a better list. Aim for **signal, not volume.**

- **Depth (`-d`):** start at 2. Increase only if the site is large and content-rich; too deep floods the list with boilerplate (nav/footer/legal) that dilutes useful stems.
- **Minimum length (`-m`):** raise to 5–6 to drop short filler (`the`, `and`, `for`). Longer words are better password stems and better discovery paths.
- **Case:** keep default case for cracking (case matters), or `--lowercase` if you'll let rules handle capitalization (often cleaner — one stem, rules add case).
- **Numbers (`--with-numbers`):** include when the site uses alphanumeric product names/versions (`redfalcon2`, `v4portal`).
- **Count threshold:** CeWL sorts by frequency; you can post-filter with `--count` output to keep only words seen ≥N times (drop one-off noise): e.g., parse the `word, N` output and keep high-N terms.
- **Scope tightly:** `--allowed` / `--exclude` to avoid drift and boilerplate-heavy sections.
- **Feed the right pages:** product pages, docs, blogs, and PDFs carry the richest vocabulary; login pages and image galleries carry little.
- **Then let rules do the decoration** — don't try to make CeWL output finished passwords; that's the cracker's job.

---

## 15. Limitations and Pitfalls

- **No JavaScript rendering.** SPA/JS-heavy sites yield thin lists; crawl with a JS-capable tool first or use a Burp-sitemap approach (§6, §16).
- **Base words only.** CeWL words aren't passwords; without mangling rules they'll crack little. "CeWL + rules" is the technique.
- **Boilerplate dilution.** Deep crawls pull in navigation/legal text repeated site-wide — raise `-m`, filter by count, scope tightly.
- **Offsite drift.** `-o` with high depth can wander onto unrelated (and unauthorized) domains — usually leave offsite off and scope with `--allowed`.
- **Case explosion.** Preserving case multiplies entries (`Product`/`product`/`PRODUCT`); decide whether to keep case or lowercase + rules.
- **exiftool dependency.** `-a`/FAB silently underperform if `exiftool` isn't installed.
- **Spidering is active.** Even though it "just reads," CeWL sends real requests to the target and can be noticeable/heavy at depth — it's not zero-footprint (§18).
- **Not a vulnerability scanner.** CeWL finds *words*, not vulns. The value is entirely downstream (cracking/discovery).

---

## 16. Alternatives and Related Tools

- **Whey CeWLer / CeWLer (CO2 Burp extension):** a Burp-based reimplementation that builds a wordlist from Burp's **already-crawled sitemap** — no separate crawl, and it benefits from Burp having rendered JS-heavy apps. Lacks CeWL's metadata parsing but is very convenient. Good answer to CeWL's no-JS limitation.
- **goCeWL:** a Go clone that crawls concurrently (faster, static binary, lower memory) — experimental but handy for large sites.
- **crunch:** generates wordlists from **character sets/patterns** (not from a site) — complementary when you know a password *format* (e.g., 8 chars, specific mask).
- **CUPP / Mentalist:** build wordlists from **personal info** (names, dates, pet names) with profile-based mangling — pairs well with CeWL org-words for targeting individuals.
- **Wordlist rule sets:** `best64.rule`, `rockyou-30000.rule`, `OneRuleToRuleThemAll.rule` (hashcat); John Jumbo/KoreLogic rules — the mangling layer that makes CeWL output effective.

Most workflows use **CeWL for org vocabulary + rules for mangling**, optionally blended with CUPP (personal info) and generic lists.

---

## 17. Where It Fits: Workflow and Chaining

CeWL sits in the **recon/OSINT** phase and feeds **credential attacks** and **content discovery**.

```
[ recon: find the target's website + documents ]
                 │
                 ▼
            [ CeWL ] ──► wordlist (org vocabulary)
                 ├──► metadata → usernames  (─a / FAB)
                 └──► emails → usernames + naming convention  (─e)
                 │
     ┌───────────┼────────────────────────────┐
     ▼           ▼                             ▼
[ hashcat/john ]  [ hydra/spray ]        [ feroxbuster/ffuf ]
 offline crack     online (careful)       target-specific
 with rules        with usernames         content discovery
```

**Relationship to the tools you've studied:**
- **vs generic wordlists:** CeWL supplies *target-specific* stems those lack.
- **feeds feroxbuster/ffuf:** a CeWL list (esp. with `--capture-url-structure`) is a bespoke discovery wordlist that finds target-specific paths.
- **complements crawlers (Burp/ZAP):** those map the app; CeWL mines its vocabulary (and a Burp sitemap can even be the source via CeWLer).

The discipline: **mine the target's words and usernames → mangle with rules → crack offline (or spray carefully) → also reuse the list for discovery.**

---

## 18. Legal and Ethical Note

- **Spidering is active interaction.** CeWL sends real requests and, at depth, can be heavy/noticeable — treat it as reconnaissance against the target, not a passive lookup. Scan only sites you **own or are authorized to test**.
- **The downstream use is where the real risk sits.** Cracking hashes and spraying logins are serious actions:
  - **Offline cracking** requires you to have lawfully obtained the hashes (in scope).
  - **Online spraying can lock accounts and disrupt users** — know the lockout policy, throttle, and get explicit authorization; many programs restrict or forbid it.
- **Harvested usernames/emails are personal data** — handle per your engagement's rules and applicable privacy law; don't use them beyond scope.
- **Off-site spidering (`-o`) can stray onto systems you're not authorized to touch** — keep it off and scope with `--allowed`.
- **Practice legally:** run CeWL against your own site or authorized lab targets; practice the CeWL→rules→hashcat pipeline on **hashes you generated yourself** or lab hashes (e.g., from intentionally vulnerable VMs).

---

### Where to go next

- Build a list from a site you control, then run the full payoff pipeline on **your own test hashes**: `cewl … -w words.txt` → `hashcat -a 0 -m 0 your_hashes.txt words.txt -r best64.rule`. Watching a CeWL stem + a rule crack a realistic password is the "aha" that makes the tool click (§4, §13).
- Add `-a`/`-e` and see how metadata and emails hand you the **username** side — then combine usernames + wordlist for a (lab-only) spray to feel the full credential-attack shape.
- Feed a `--capture-url-structure` CeWL list into **feroxbuster/ffuf** against the same lab target and compare hits to a generic list — the target-specific words earn their keep.

*End of reference.*

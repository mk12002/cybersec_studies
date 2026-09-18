# ffuf — The Complete Reference (Beginner → Advanced)

> A ground-up reference for **ffuf** ("Fuzz Faster U Fool"), the fast, general-purpose web fuzzer: the `FUZZ`-anywhere model that makes it far more than a directory brute-forcer, its matcher/filter engine, the three attack modes, and how to point it at any part of an HTTP request.

---

## Table of Contents

1. [What ffuf Is and Why It Exists](#1-what-ffuf-is-and-why-it-exists)
2. [Status and Key Facts](#2-status-and-key-facts)
3. [The Core Concept: The FUZZ Keyword](#3-the-core-concept-the-fuzz-keyword)
4. ["Fuzzing" Here vs Content Discovery (ffuf vs feroxbuster)](#4-fuzzing-here-vs-content-discovery-ffuf-vs-feroxbuster)
5. [The Many Use Cases (Where You Put FUZZ)](#5-the-many-use-cases-where-you-put-fuzz)
6. [Matchers and Filters (The Core Skill)](#6-matchers-and-filters-the-core-skill)
7. [Auto-Calibration (The Soft-404 Solution)](#7-auto-calibration-the-soft-404-solution)
8. [Attack Modes: Clusterbomb, Pitchfork, Sniper](#8-attack-modes-clusterbomb-pitchfork-sniper)
9. [How ffuf Works Internally](#9-how-ffuf-works-internally)
10. [Installation](#10-installation)
11. [Command-Line Options (Full Breakdown)](#11-command-line-options-full-breakdown)
12. [Worked Examples with Output, Explained](#12-worked-examples-with-output-explained)
13. [Reading the Output](#13-reading-the-output)
14. [Input From a Command (Mutation Fuzzing)](#14-input-from-a-command-mutation-fuzzing)
15. [Recursion, Encoders, and Interactive Mode](#15-recursion-encoders-and-interactive-mode)
16. [Performance, Rate Limiting, and WAF Stops](#16-performance-rate-limiting-and-waf-stops)
17. [Raw Requests and Burp Integration](#17-raw-requests-and-burp-integration)
18. [Where It Fits: Workflow and Chaining](#18-where-it-fits-workflow-and-chaining)
19. [Pitfalls and Good Practice](#19-pitfalls-and-good-practice)
20. [Legal and Ethical Note](#20-legal-and-ethical-note)

---

## 1. What ffuf Is and Why It Exists

**ffuf** (Fuzz Faster U Fool) is a fast, general-purpose **web fuzzer** written in Go. "Fuzzing" here means **sending many different inputs into a chosen spot in an HTTP request and watching the responses for anomalies** that reveal something interesting — a hidden directory, a valid parameter, a working credential, an unlisted virtual host.

Its defining feature is the **`FUZZ` keyword**: a placeholder you drop **anywhere** in a request, which ffuf replaces with each entry from your wordlist. That one idea makes ffuf a Swiss-army tool — the *same* engine does directory discovery, parameter discovery, virtual-host discovery, credential brute-forcing, header fuzzing, and injection payload testing, just by moving where you put `FUZZ`.

Written by **Joona Hoikkala (joohoi)**, ffuf is prized for **speed** (Go concurrency), **flexibility** (fuzz any part of the request), and a powerful **matcher/filter** system for turning a flood of responses into a clean list of findings.

**Why it exists / the problem it solves:** older tools were often single-purpose (dirb/gobuster for directories, a different tool for parameters, another for vhosts). ffuf **generalizes** all of that into "put `FUZZ` where you want to test, give it a wordlist, define what a 'hit' looks like." It's fast enough to make large wordlists practical and flexible enough to cover fuzzing tasks that previously needed several tools or Burp Intruder. In practice it's the go-to CLI fuzzer for content discovery *and* everything-else fuzzing.

---

## 2. Status and Key Facts

- **Actively maintained.** Current is **v2.1.0** (the v2.x line). By Joona Hoikkala (joohoi). Pre-installed on **Kali/Parrot**.
- **Language:** Go — compiled, fast, highly concurrent; install via `go install github.com/ffuf/ffuf/v2@latest`, Homebrew, or a release binary.
- **Repo:** `github.com/ffuf/ffuf`.
- **Three attack modes:** `clusterbomb` (default), `pitchfork`, `sniper` (§8).
- **Defaults you must know:**
  - **Threads: 40**, **timeout: 10s**, method **GET**.
  - **Default matcher: status codes.** Historically `200,204,301,302,307,401,403,405,500`; **v2.1.0 changed the default toward matching 2XX responses.** Because the default can hide interesting codes (like `401`/`403`) or vary by version, experienced users often run **`-mc all`** and then *filter* noise out (§6).
  - **Auto-calibration is OFF by default** (`-ac` to enable) — unlike feroxbuster's always-on auto-filter (§7).
  - **Recursion is OFF by default** (`-recursion` to enable) — also unlike feroxbuster.
- **Recent niceties:** raw-request fuzzing (`-request`), payload encoders (`-enc`/pencode), response scraping, automatic brotli/deflate decompression, extensible auto-calibration strategies, audit logging.

---

## 3. The Core Concept: The FUZZ Keyword

Everything in ffuf revolves around **`FUZZ`** — a literal placeholder marking **where in the request the wordlist entries go.** ffuf takes your request template, and for each word in the wordlist, substitutes it in place of `FUZZ` and sends the request.

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ
```
For the word `admin`, ffuf requests `https://target.com/admin`; for `login`, `https://target.com/login`; and so on.

**The placeholder can go anywhere:**
- In the **URL path**: `-u https://target.com/FUZZ`
- In a **query parameter name**: `-u "https://target.com/page?FUZZ=1"`
- In a **query parameter value**: `-u "https://target.com/page?id=FUZZ"`
- In a **header**: `-H "Host: FUZZ.target.com"` or `-H "X-Api-Key: FUZZ"`
- In **POST data**: `-d "user=admin&pass=FUZZ" -X POST`
- Anywhere in a **raw request file** (§17).

**Custom keywords for multiple positions.** When you fuzz more than one spot, name each wordlist's keyword with `-w file:KEYWORD` and use that keyword instead of `FUZZ`:
```bash
ffuf -w users.txt:USER -w pass.txt:PASS -X POST \
     -d "username=USER&password=PASS" -u https://target.com/login
```
Here `USER` and `PASS` are two independent fuzz positions fed by two wordlists.

**The mental model:** ffuf is *"take this HTTP request, mark the variable spot(s) with a keyword, iterate a wordlist through them, and show me the responses that stand out."* Once that clicks, every use case in §5 is just a different placement of the keyword.

---

## 4. "Fuzzing" Here vs Content Discovery (ffuf vs feroxbuster)

You've already met **feroxbuster** (recursive content discovery). ffuf overlaps with it but is **broader and more manual**. Knowing the distinction helps you pick.

| Aspect | feroxbuster | ffuf |
|---|---|---|
| Primary job | **Content discovery** (dirs/files), recursive | **General fuzzing** — any request position |
| `FUZZ` anywhere | No (path-focused) | **Yes** — the whole point |
| Recursion | **On by default** | Off by default (`-recursion`) |
| Soft-404 handling | Auto-filter **on by default** | Auto-calibration **opt-in** (`-ac`) |
| Multi-position combinatorics | No | **Yes** (clusterbomb/pitchfork/sniper) |
| Vibe | Point-and-go discovery | Precise, composable fuzzing |

**When to use which:**
- **feroxbuster** — you want fast, recursive *directory/file discovery* with smart defaults and minimal fuss.
- **ffuf** — you want to fuzz **something other than a path** (parameters, vhosts, headers, POST fields, injection payloads), fuzz **multiple positions** with combinatorics, or drive fuzzing from a **raw Burp request**. It's also excellent for directory discovery — just more hands-on (you set matchers/filters yourself).

They're complementary, and many testers use both. Think: **feroxbuster for "what files/dirs exist,"** and **ffuf for "fuzz this specific thing however I want."** (ffuf is essentially a fast CLI cousin of **Burp Intruder** — same combinatoric modes, same "mark a position and iterate payloads" idea.)

---

## 5. The Many Use Cases (Where You Put FUZZ)

The single skill of "move the keyword" unlocks all of these:

### 5.1 Directory / file discovery
```bash
ffuf -w raft-medium-directories.txt -u https://target.com/FUZZ
ffuf -w raft-medium-files.txt -u https://target.com/FUZZ -e .php,.html,.bak,.txt
```
`-e` appends extensions to each word (like feroxbuster's `-x`). This is the "classic" use.

### 5.2 GET parameter **name** discovery
```bash
ffuf -w burp-parameter-names.txt -u "https://target.com/script.php?FUZZ=test" -fs 4242
```
Apps often honor **hidden parameters** (`debug=1`, `admin=true`, `id=`) that aren't linked anywhere. Fuzz the **name** and watch for a response that differs from the "unknown param" baseline (filter the constant size with `-fs`). This is the CLI equivalent of Burp's **Param Miner** concept.

### 5.3 GET parameter **value** fuzzing
```bash
ffuf -w values.txt -u "https://target.com/user?id=FUZZ" -fc 401
```
Enumerate IDs (IDOR), test injection payloads, brute-force tokens — anything where the *value* varies.

### 5.4 POST data / credential fuzzing
```bash
ffuf -w passwords.txt -X POST \
     -d "username=admin&password=FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -u https://target.com/login -fc 200
```
Brute-force a login (filter the "wrong password" response). Fuzz JSON bodies similarly (`-d '{"user":"admin","pass":"FUZZ"}' -H "Content-Type: application/json"`).

### 5.5 Virtual host (vhost) discovery
```bash
ffuf -w subdomains.txt -u https://target.com/ \
     -H "Host: FUZZ.target.com" -fs 4242
```
**Concept:** one server IP can host **many sites**, distinguished by the `Host` header. Some vhosts aren't in public DNS (so subdomain enumeration misses them) but *are* served if you send the right `Host`. Fuzz the `Host` header against the same IP; a **valid vhost returns a different response size** than the default site — filter the default size (`-fs`) and the real vhosts pop out. This finds hidden internal sites DNS won't reveal.

### 5.6 Header / auth fuzzing
```bash
ffuf -w tokens.txt -u https://target.com/api -H "Authorization: Bearer FUZZ"
```
Fuzz API keys, custom headers, or bypass headers (`X-Forwarded-For: FUZZ`).

### 5.7 Subdomain fuzzing (DNS)
Point `FUZZ` at the hostname and match resolvable/served hosts:
```bash
ffuf -w subdomains.txt -u https://FUZZ.target.com/
```
(For pure passive subdomain enumeration, dedicated tools like subfinder are better — but ffuf can brute-force DNS-fronted vhosts.)

**The takeaway:** you don't learn seven tools; you learn **one keyword** and where to place it. That generality is ffuf's superpower.

---

## 6. Matchers and Filters (The Core Skill)

Because *everything* you fuzz returns *some* response, the essential skill is **defining what counts as a hit.** ffuf does this with **matchers** (show responses that match) and **filters** (hide responses that match). Master these or drown in noise.

### Matchers (allow-list: only show these)
| Option | Matches on |
|---|---|
| `-mc <codes>` | HTTP **status codes** (e.g., `-mc 200,301,403`; `-mc all`). |
| `-ml <n>` | Number of **lines** in the response. |
| `-mw <n>` | Number of **words**. |
| `-ms <n>` | Response **size** in bytes. |
| `-mr <regex>` | Response **matches a regex**. |
| `-mt <time>` | Response **time** (e.g., `>100`) — useful for time-based injection. |

### Filters (deny-list: hide these)
| Option | Filters out |
|---|---|
| `-fc <codes>` | Status codes (e.g., `-fc 404,400`). |
| `-fl <n>` | Line count. |
| `-fw <n>` | Word count. |
| `-fs <n>` | Size in bytes. |
| `-fr <regex>` | Regex match. |
| `-ft <time>` | Response time. |

`-mmode`/`-fmode` set whether multiple matchers/filters combine with **and** or **or**.

### The workflow (identical in spirit to feroxbuster §12)
1. Run with **`-mc all`** so you see everything first.
2. Spot the **noise pattern** — usually a flood of responses with the **same size/words/lines** (the soft-404/wildcard).
3. **Filter that pattern out**: e.g., `-fs 4242` (hide the 4242-byte not-found page) or `-fw 312`.
4. Iterate until only real, distinct responses remain.

**Golden rule (same as feroxbuster):** **don't blindly filter `401`/`403`** — "exists but protected" is a lead, not noise. Filter the *not-found* fingerprint, not the *interesting* codes.

**Why size/words/lines matter:** the not-found page is usually a fixed template, so its **byte size / word count / line count is constant**. That constant is your filter target. When you see `Size: 4242` on hundreds of results, that's the app saying "not found" 200 in disguise — filter `-fs 4242`.

---

## 7. Auto-Calibration (The Soft-404 Solution)

You've met this problem three times now (Nikto's 404 baseline, feroxbuster's auto-filter): many servers return **`200` for everything** (soft-404/wildcard), which would make every wordlist entry look like a hit. ffuf's built-in answer is **auto-calibration**, enabled with **`-ac`** (it's **off by default** — a key difference from feroxbuster).

**How it works:** before fuzzing, ffuf sends a few **dummy requests for content that definitely shouldn't exist**, learns the "not found" response fingerprint (size/words/lines), and **automatically creates filters** to hide anything matching it. You then see only responses that genuinely differ.

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac
```

**Finer control:**
- **`-acc <string>`** — add your own custom auto-calibration probe strings (calibrate against specific known-bad inputs).
- **`-ach`** — auto-calibrate **per host** (important when fuzzing multiple hosts/vhosts with different not-found pages).
- **Auto-calibration strategies** (v2.1.0) — extensible strategies for trickier soft-404 behavior.

**When `-ac` isn't enough:** if the not-found page **varies** (timestamps, tokens, personalization) so its size wobbles, static filters and calibration can miss it — fall back to a **regex filter** (`-fr "not found"`) or match on a stable **word/line count** instead of size. This is the same soft-404 arms race as the other tools; ffuf gives you `-ac` plus the full matcher/filter toolkit to win it.

**Practical habit:** for directory discovery, `-ac` is almost always worth adding. For precise single-position fuzzing where you already know the baseline, a manual `-fs`/`-fw` filter is often cleaner.

---

## 8. Attack Modes: Clusterbomb, Pitchfork, Sniper

When you fuzz **multiple positions**, the **mode** decides how ffuf combines the wordlists. These map directly onto **Burp Intruder's** modes (§9 of the Burp reference) — same combinatorics.

### Clusterbomb (default) — every combination
Tries **all combinations** of the wordlists (Cartesian product). For lists of size a and b → **a × b** requests.
```bash
ffuf -mode clusterbomb -w users.txt:USER -w pass.txt:PASS \
     -X POST -d "username=USER&password=PASS" -u https://target.com/login
```
**Use for:** credential brute force (every username × every password), or any case where positions are independent. Grows fast — 1,000 users × 1,000 passwords = 1,000,000 requests.

### Pitchfork — lockstep parallel
Reads the wordlists **in parallel**: 1st of each list together, 2nd of each together, etc. Requests = length of the **shortest** list.
```bash
ffuf -mode pitchfork -w users.txt:USER -w ids.txt:UID \
     -u "https://target.com/u/UID/profile/USER"
```
**Use for:** **correlated** pairs — e.g., a list of known `username`→`user_id` pairs you want tried together, not in all combinations.

### Sniper — one position at a time
Takes a **single wordlist** and **multiple positions marked with `§...§`**, and fuzzes **each marked position in turn** (as separate queued jobs), leaving the others at their base value.
```bash
ffuf -mode sniper -w payloads.txt \
     -u "https://target.com/user/§id§" -X POST -d "name=§name§"
```
**Use for:** testing **specific injection points** you have in mind (e.g., spray an XSS/SQLi payload list against `id`, then against `name`), rather than brute-forcing a whole path.

**Mnemonic (same as Burp Intruder):** **clusterbomb** = everything × everything; **pitchfork** = lists move together in lockstep; **sniper** = one payload list, each marked spot in turn. Knowing Intruder, you already know these.

---

## 9. How ffuf Works Internally

The pipeline is simple, which is part of ffuf's appeal:

1. **Build the request template** — from `-u`, `-X`, `-H`, `-d` (or a raw `-request` file), with keyword(s) marking the fuzz position(s).
2. **(Optional) auto-calibrate** — send dummy requests to learn the not-found fingerprint and install filters (`-ac`).
3. **Load wordlist(s)** and, per the **mode**, generate the sequence of payload combinations.
4. **Fire requests concurrently** — a pool of goroutines (default 40 threads), respecting `-rate`/`-p` limits.
5. **Evaluate each response** against **matchers** and **filters** — decide keep or drop.
6. **Print kept results** live (status/size/words/lines/duration) and update the progress line.
7. **(Optional) recurse** into discovered directories (`-recursion`), queueing new jobs.
8. **Output** — write results (`-o`/`-of`), dump matched responses (`-od`), replay matches to a proxy (`-replay-proxy`).

**Key properties:**
- **It's a request generator + response classifier.** ffuf doesn't "understand" the app; it substitutes payloads and classifies responses by your matcher/filter rules. Your rules *are* the intelligence.
- **Speed comes from Go concurrency** — large wordlists are practical, but that speed is borrowed from the target's capacity (tune `-rate`/`-t`).
- **Everything hinges on distinguishing signal from the not-found baseline** — hence auto-calibration and the matcher/filter system are where you spend your attention.

---

## 10. Installation

```bash
# Kali / Parrot (pre-installed or apt)
sudo apt install ffuf

# Go (latest)
go install github.com/ffuf/ffuf/v2@latest

# Homebrew (macOS/Linux)
brew install ffuf

# Binary: download from github.com/ffuf/ffuf/releases/latest

ffuf -V   # verify version
```

Grab good wordlists too: **SecLists** (`sudo apt install seclists`) and **OneListForAll** (six2dez) are the standard sources.

---

## 11. Command-Line Options (Full Breakdown)

Grouped by purpose.

### Input
| Option | Purpose |
|---|---|
| `-w <file[:KEYWORD]>` | Wordlist (repeatable; name the keyword for multi-position). |
| `-mode <mode>` | `clusterbomb` (default), `pitchfork`, `sniper`. |
| `-input-cmd <cmd>` | Generate payloads from a command's output (§14). |
| `-input-num <n>` | Number of inputs to generate with `-input-cmd`. |
| `-e <exts>` | Extensions to append (dir/file mode), e.g. `.php,.bak`. |

### Request
| Option | Purpose |
|---|---|
| `-u <URL>` | Target URL (put `FUZZ` where you want to fuzz). |
| `-X <method>` | HTTP method (default GET). |
| `-H <header>` | Custom header (repeatable; can contain `FUZZ`). |
| `-d <data>` | POST/PUT body (can contain `FUZZ`). |
| `-b <cookies>` | Cookies. |
| `-request <file>` | **Raw HTTP request file** (from Burp); put `FUZZ` inside (§17). |
| `-request-proto <proto>` | Protocol for the raw request (default https). |
| `-x <proxy>` | Proxy all requests (e.g., Burp). |
| `-replay-proxy <proxy>` | Send **only matched** requests to a proxy (§17). |
| `-enc <KEYWORD:encoder>` | Encode payloads (e.g., `FUZZ:urlencode`, `b64encode`). |
| `-timeout <s>` | Per-request timeout (default 10). |

### Matchers (show)
`-mc` (status), `-ml` (lines), `-mw` (words), `-ms` (size), `-mr` (regex), `-mt` (time), `-mmode` (and/or).

### Filters (hide)
`-fc` (status), `-fl` (lines), `-fw` (words), `-fs` (size), `-fr` (regex), `-ft` (time), `-fmode` (and/or).

### Calibration & recursion
| Option | Purpose |
|---|---|
| `-ac` | Auto-calibrate filters (learn the not-found baseline). |
| `-acc <str>` | Custom auto-calibration probe string. |
| `-ach` | Auto-calibrate per host. |
| `-recursion` | Recurse into found directories. |
| `-recursion-depth <n>` | Max recursion depth. |
| `-recursion-strategy <s>` | Recursion strategy. |

### Performance & control
| Option | Purpose |
|---|---|
| `-t <n>` | Threads (default 40). |
| `-rate <n>` | Requests per second cap. |
| `-p <delay>` | Delay between requests (e.g., `0.1` or `0.1-2.0`). |
| `-maxtime <s>` / `-maxtime-job <s>` | Cap total / per-job runtime. |
| `-se` | Stop on spurious errors. |
| `-sf` | Stop when **>95% of responses are 403** (WAF block detection). |
| `-sa` | Stop on all errors. |

### Output
| Option | Purpose |
|---|---|
| `-o <file>` | Output file. |
| `-of <fmt>` | Format: `json, ejson, html, md, csv, ecsv, all`. |
| `-od <dir>` | Dump matched **responses** to a directory. |
| `-or` | Don't create output file if no results. |
| `-debug-log` / `-audit-log` | Internal logging / full request-response audit log. |
| `-s` | Silent (results only — for piping). |
| `-v` | Verbose (full URL, redirect location, payload position). |
| `-c` | Colorize. |

Run `ffuf -h` for the exact, version-accurate list; keep a `.ffufrc` config for your defaults.

---

## 12. Worked Examples with Output, Explained

> Output is **representative**.

### 12.1 Directory discovery with auto-calibration
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u https://target.com/FUZZ -ac -c -v
```
```
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/  v2.1.0
________________________________________________
 :: Method     : GET
 :: URL        : https://target.com/FUZZ
 :: Wordlist   : FUZZ: raft-medium-directories.txt
 :: Calibration: true
 :: Matcher    : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin        [Status: 301, Size: 178,  Words: 6,   Lines: 8,   Duration: 42ms]
login.php    [Status: 200, Size: 4523, Words: 340, Lines: 120, Duration: 55ms]
.htaccess    [Status: 403, Size: 277,  Words: 20,  Lines: 10,  Duration: 40ms]
server-status[Status: 403, Size: 299,  Words: 22,  Lines: 10,  Duration: 39ms]
:: Progress: [30000/30000] :: Job [1/1] :: 890 req/sec :: Duration: [0:00:34] :: Errors: 0 ::
```
**Reading it:** `-ac` learned the not-found page and filtered it, so only distinct responses show. `admin` (301 → a directory), `login.php` (200 → a page), and two `403`s (**exist but forbidden** — leads, not noise). The footer shows rate and total requests.

### 12.2 Hidden GET parameter discovery
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "https://target.com/api/item?FUZZ=1" -mc all -fs 27
```
Every unknown param returns the same 27-byte "missing/invalid" JSON, so `-fs 27` hides them; a param that changes the response (`debug`, `admin`, `id`) survives the filter → a discovered hidden parameter.

### 12.3 Virtual host discovery
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u https://target.com/ -H "Host: FUZZ.target.com" -fs 10918
```
The default site returns 10,918 bytes for any bogus vhost; filter it (`-fs 10918`). Any `Host` value returning a **different size** is a real vhost served by that IP — including internal ones **not in DNS**.

### 12.4 Login brute force (clusterbomb)
```bash
ffuf -mode clusterbomb -w users.txt:U -w rockyou-small.txt:P \
     -X POST -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=U&password=P" -u https://target.com/login \
     -fc 200 -mc all -rate 50
```
`-fc 200` hides the "login failed" 200 page; a **302 redirect** (successful login) survives → the winning pair. `-rate 50` throttles to avoid lockout/DoS.

### 12.5 Fuzz from a raw Burp request
```bash
# In Burp: save the request to req.txt, replace the value to test with FUZZ
ffuf -request req.txt -request-proto https -w payloads.txt -mc all -ac
```
ffuf parses the file and reproduces the exact method, headers, cookies, and body — ideal for authenticated/complex requests (§17).

---

## 13. Reading the Output

Each result line has a consistent, filterable shape:

```
admin   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 42ms]
  │        │            │          │         │          │
payload   status code   bytes      words     lines      response time
```

- **Payload** — the wordlist entry that produced this response (the finding).
- **Status** — HTTP code. `200` served; `301/302` redirect (often a directory); **`401/403` exists-but-protected (a lead)**; `405` wrong method for an existing path; `500` your input broke something (strong lead).
- **Size / Words / Lines** — the response's byte/word/line counts. **These are your filtering fingerprints:** identical triples across many results = the soft-404 to filter (`-fs`/`-fw`/`-fl`); an outlier triple = a genuinely distinct, interesting response.
- **Duration** — response time; spikes can indicate time-based injection or a heavy endpoint (match with `-mt`).

The **header block** at the top echoes your effective config (matcher, calibration, threads) — sanity-check it matches your intent. The **footer** shows progress, request rate, and error count (rising errors → the target is struggling or blocking you; consider `-sf`/`-rate`).

**The core reading skill:** scan the Size/Words/Lines columns for the constant (noise) vs the outliers (findings), and treat status codes as leads by category — exactly the instinct you built with feroxbuster.

---

## 14. Input From a Command (Mutation Fuzzing)

Beyond static wordlists, ffuf can take payloads from a **command's output** with `-input-cmd`, enabling **mutation/generative fuzzing**:

```bash
ffuf -input-cmd 'radamsa --seed $FFUF_NUM seed.txt' -input-num 10000 \
     -u https://target.com/api -X POST -d 'FUZZ' -mc all -mt '>3000'
```
- **`radamsa`** is a mutation fuzzer that takes a valid sample (`seed.txt`) and produces malformed variations — great for finding crashes/edge cases in parsers and APIs.
- `-input-num` sets how many payloads to generate; `$FFUF_NUM` is the current iteration (used as the mutation seed for reproducibility).
- Matching on `-mt '>3000'` (slow responses) or `-mc 500` helps catch the inputs that break the server.

**Concept:** static wordlists find *known* names; **mutation fuzzing** finds *unexpected* input-handling bugs (crashes, exceptions, injection) by throwing structured-but-broken data at an endpoint. This turns ffuf from a discovery tool into a lightweight **input fuzzer** for APIs.

---

## 15. Recursion, Encoders, and Interactive Mode

**Recursion (`-recursion`, off by default):** when ffuf finds a directory, it can queue a new job to fuzz inside it, up to `-recursion-depth`. Unlike feroxbuster (recursion-first), ffuf makes you opt in:
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2 -ac
```
Mind the request explosion (same math as feroxbuster) — scope depth deliberately.

**Encoders (`-enc`):** transform payloads before sending, per keyword:
```bash
ffuf -w payloads.txt:FUZZ -enc FUZZ:urlencode -u "https://target.com/q?s=FUZZ"
```
Chainable encoders (URL-encode, base64, etc.) help when the app expects encoded input or to slip past naive filters — the ffuf analog of Burp Intruder's payload processing / sqlmap tampers.

**Interactive mode:** press **[ENTER]** during a running scan to **pause** and drop into an interactive prompt where you can, among other things, **add filters on the fly**, view current results, adjust, and resume — invaluable when you spot the soft-404 pattern mid-run and want to filter it without restarting.

---

## 16. Performance, Rate Limiting, and WAF Stops

ffuf is fast; that speed must be governed on real targets.

- **`-t <n>`** — threads (default 40). More = faster, heavier on target.
- **`-rate <n>`** — hard cap on **requests/second** (the cleanest way to be gentle/stealthier; `-rate 50` is civilized).
- **`-p <delay>`** — fixed or random delay between requests (e.g., `-p 0.1-1.0`).
- **`-maxtime` / `-maxtime-job`** — cap total or per-directory runtime (bounds recursion/huge lists).
- **`-sf`** — **stop when >95% of responses are `403`**: a strong signal a **WAF has started blocking you**, so continuing is pointless (and noisy). Great safety valve.
- **`-se` / `-sa`** — stop on spurious/all errors (bail when the target is failing).

**Reading the signs:** a sudden wall of `403`s or rising `Errors:` in the footer means you've been detected/blocked or the target is overloaded — throttle (`-rate`), back off, or stop (`-sf`). Speed is borrowed from the target; tune it to the engagement.

---

## 17. Raw Requests and Burp Integration

Two features make ffuf fit cleanly into a Burp-centric workflow:

**`-request` (raw request file) — the pro input method.** Save a request from Burp (or write one), drop `FUZZ` where you want to test, and ffuf reproduces the **exact** method, headers, cookies, and body:
```bash
ffuf -request req.txt -request-proto https -w wordlist.txt -ac -mc all
```
This is the ffuf equivalent of sqlmap's `-r`: it effortlessly handles **authenticated**, **POST/JSON**, and **complex-header** requests without you re-specifying anything. The typical flow: intercept in Burp → save request → insert `FUZZ` → fuzz.

**`-replay-proxy` — send only the hits to Burp.** ffuf does the noisy fuzzing itself, but **replays only matched responses** through your proxy, so Burp's history stays clean and every entry is a real finding ready for Repeater:
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -replay-proxy http://127.0.0.1:8080
```
(Use `-x` instead to route *all* traffic through a proxy — usually you want `-replay-proxy` for discovery, exactly as with feroxbuster.)

---

## 18. Where It Fits: Workflow and Chaining

ffuf lives in **content discovery + targeted fuzzing**, feeding deeper testing.

```
[ subdomain enum ] → [ port scan ] → [ httpx: live web servers ]
                                             │
                                             ▼
                                        [ ffuf ]  ← fuzz: dirs/files, params, vhosts, creds
                                             │       (FUZZ anywhere; matchers/filters; -ac)
                                             ▼
        findings → [ Burp / ZAP ]  deep testing of discovered endpoints/params
                 → [ sqlmap ]      test discovered parameters for SQLi
                 → [ nuclei ]      templated checks on discovered paths
```

**Relationship to the tools you've studied:**
- **vs feroxbuster** — feroxbuster for fast recursive *discovery*; ffuf for *flexible fuzzing* of any request position and multi-position combinatorics (§4).
- **like Burp Intruder** — same clusterbomb/pitchfork/sniper modes, but faster and scriptable from the CLI.
- **feeds sqlmap** — ffuf discovers a hidden parameter → confirm it's injectable → hand the request to sqlmap.
- **feeds Burp** — `-request` in, `-replay-proxy` out: fuzz on the CLI, investigate hits in Burp.
- **uses CeWL/SecLists** — target-specific or curated wordlists sharpen every fuzz.

**The discipline:** *decide what to fuzz → place FUZZ → pick a wordlist → define matchers/filters (or `-ac`) → read Size/Words/Lines for outliers → verify hits and hand them downstream.*

---

## 19. Pitfalls and Good Practice

- **Soft-404 floods.** If you see hundreds of same-size results, add `-ac` or a `-fs`/`-fw`/`-fr` filter. ffuf's calibration is **opt-in** — remember to turn it on for discovery.
- **Default matcher surprises.** The default `-mc` can hide interesting codes and changed in v2.1.0. When in doubt, `-mc all` + filters so nothing interesting is silently dropped.
- **Don't filter `401`/`403`.** Exists-but-protected is a lead.
- **Recursion & clusterbomb explosions.** Depth × wordlist, or list-A × list-B, can be millions of requests. Bound with `-recursion-depth`, `-maxtime`, `-rate`.
- **Wrong wordlist = wrong results.** The wordlist is your guesses; match it to the task (dir list vs param list vs subdomain list vs value list) and the tech stack.
- **Getting blocked.** A wall of `403`s or rising errors = WAF/rate-limit. Use `-sf`, throttle `-rate`, back off.
- **vhost/host calibration.** When fuzzing multiple hosts, use `-ach` (per-host calibration) or filters per target — one global filter won't fit different not-found pages.
- **It's loud.** Fuzzing is high-volume active testing; expect detection and tune accordingly.
- **Verify hits.** A surviving response means "distinct from baseline," not "exploitable" — open it and confirm.

---

## 20. Legal and Ethical Note

- **ffuf is active, high-volume testing.** It sends thousands to millions of requests probing paths, parameters, hosts, and credentials — intrusive and easily disruptive.
- **Only fuzz systems you own or are explicitly authorized to test** — signed rules of engagement, an in-scope bug-bounty target that permits automated fuzzing (some restrict request rates or forbid credential brute-forcing — **read the rules**), or your own lab.
- **Credential brute-forcing can lock accounts** and is loud; throttle (`-rate`), keep lists focused, know the lockout policy, and get authorization.
- **Rate-limit on anything fragile/production** (`-rate`, `-p`, `-maxtime`); never unleash default speed on a system you're unsure about.
- **Finding something is not permission to attack it.** Discovery yields a map; testing what you find must be in scope.
- **Practice legally:** run ffuf against intentionally vulnerable targets — **OWASP Juice Shop**, **DVWA**, HTB/THM lab boxes, or your own VMs — to learn matchers/filters, calibration, and the modes safely.

---

### Where to go next

- On a lab target, run a directory scan **without** `-ac`, watch the soft-404 flood, then add `-ac` (or a `-fs` filter) and see the noise vanish — that filtering intuition (§6, §7) is the whole skill.
- Do the **same task three ways** — directory discovery, hidden-parameter discovery, and vhost discovery — moving only where `FUZZ` sits. Feeling one keyword cover three jobs is ffuf's core lesson (§5).
- Practice the **Burp handoff**: save a request, insert `FUZZ`, run with `-request` and `-replay-proxy http://127.0.0.1:8080`, then investigate hits in Burp — and when you discover a parameter, hand it to **sqlmap**. That chains ffuf into the tools you've already learned.

*End of reference.*

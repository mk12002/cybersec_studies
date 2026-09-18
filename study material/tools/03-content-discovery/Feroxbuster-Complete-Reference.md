# Feroxbuster — The Complete Reference (Beginner → Advanced)

> A ground-up reference for **feroxbuster**, the fast, recursive **content discovery** (forced browsing) tool written in Rust — what it finds, exactly **how** it finds it, how to read its output, and how to tune it without drowning in noise.

---

## Table of Contents

1. [What Feroxbuster Is and Why It Exists](#1-what-feroxbuster-is-and-why-it-exists)
2. [Status and Key Facts](#2-status-and-key-facts)
3. [The Core Concept: Forced Browsing / Content Discovery](#3-the-core-concept-forced-browsing--content-discovery)
4. [How It Differs From the Alternatives](#4-how-it-differs-from-the-alternatives)
5. [How Feroxbuster Works Internally](#5-how-feroxbuster-works-internally)
6. [The Wildcard / Soft-404 Auto-Filter (Core Concept)](#6-the-wildcard--soft-404-auto-filter-core-concept)
7. [Recursion Explained](#7-recursion-explained)
8. [Link Extraction and the "Collect" Family (Smart Discovery)](#8-link-extraction-and-the-collect-family-smart-discovery)
9. [Wordlists and Extensions (The Fuel)](#9-wordlists-and-extensions-the-fuel)
10. [Installation](#10-installation)
11. [Command-Line Options (Full Breakdown)](#11-command-line-options-full-breakdown)
12. [Filtering Deep-Dive](#12-filtering-deep-dive)
13. [Understanding the Output Line Format](#13-understanding-the-output-line-format)
14. [Worked Examples with Output, Explained](#14-worked-examples-with-output-explained)
15. [The Scan Management Menu and Interactive Control](#15-the-scan-management-menu-and-interactive-control)
16. [Performance and Safety Tuning](#16-performance-and-safety-tuning)
17. [Sending Matches to Burp (Replay Proxy) and Integrations](#17-sending-matches-to-burp-replay-proxy-and-integrations)
18. [Resume, State, Output Formats, and Piping](#18-resume-state-output-formats-and-piping)
19. [The Config File (ferox-config.toml)](#19-the-config-file-ferox-configtoml)
20. [Where It Fits: Workflow and Chaining](#20-where-it-fits-workflow-and-chaining)
21. [Pitfalls and Good Practice](#21-pitfalls-and-good-practice)
22. [Legal and Ethical Note](#22-legal-and-ethical-note)

---

## 1. What Feroxbuster Is and Why It Exists

**Feroxbuster** is a fast, recursive **content discovery** tool — also called a **forced browsing** or **directory/file brute-forcing** tool. You give it a target URL and a wordlist, and it requests `target/word` for every word, watching the responses to discover **files and directories that exist on the server but aren't linked anywhere you can see** — hidden admin panels, backup files, config files, API endpoints, old pages, dev directories.

Written in **Rust** by **Ben "epi" Risher (epi052)**, it's built for **speed** (async, highly concurrent), **recursion by default** (it automatically dives into directories it finds), and a **pleasant real-time UI** with progress bars and an interactive scan-management menu.

**Why it exists / the problem it solves:** web servers host far more than what's linked from the homepage. Developers leave behind `/backup/`, `/admin/`, `/.git/`, `/api/v1/`, `/old/`, `/test.php`, `/config.php.bak` — content that's reachable if you know the URL but invisible to a normal crawler because nothing links to it. A spider (like Burp's or ZAP's) can only find **linked** content; it will never discover `/admin_backup_2019/` because no page points to it. **Content discovery brute-forces the guesses a crawler can't make.** That unlinked content is often exactly where the interesting bugs live.

This is the natural complement to Nikto: **Nikto checks a curated list of *known* dangerous paths; feroxbuster brute-forces a *wordlist* to find *unknown* paths specific to this target.**

---

## 2. Status and Key Facts

- **Actively maintained.** Current is the **2.x series (2.11.x as of late 2025)**, with ongoing releases and fixes. (Versions move; check `feroxbuster --version`.)
- **Language:** Rust — compiled, memory-safe, and fast; a big reason it out-paces older Perl/Python/Go tools on large wordlists.
- **Repo:** `github.com/epi052/feroxbuster`. Pre-packaged on Kali/Parrot; also via Homebrew, Cargo, or a static binary.
- **Defaults you must know (they shape every scan):**
  - **Threads: 50**, **timeout: 7s**, **User-Agent: `feroxbuster/<version>`**, **method: GET**.
  - **Status codes: ALL are reported by default** — you *filter down*, rather than allow-list up (§12).
  - **Link extraction: ON by default** — it parses HTML/JS/robots.txt in responses for more paths (§8).
  - **Recursion: ON by default, depth 4** (§7).
  - **Wildcard/soft-404 auto-filtering: ON by default** (§6).

These "smart defaults" make feroxbuster find a lot with little configuration — but also mean you should understand what it's doing automatically, or the output will surprise you.

---

## 3. The Core Concept: Forced Browsing / Content Discovery

**Forced browsing** (OWASP's term) means **directly requesting resources by URL to find ones that aren't linked or advertised.** The technique rests on a simple truth about the web:

> **A resource exists if the server serves it — whether or not anything links to it.**

So if you can *guess* the URL, you can reach the resource. Content discovery automates the guessing with a **wordlist** of likely names.

### Linked vs unlinked content

- **Linked content** — reachable by following links from the homepage. A crawler/spider finds this.
- **Unlinked content** — exists on the server but nothing links to it: leftover files, admin tools, backups, dev/staging paths, API routes, disabled features. **Only brute-forcing (or an information leak) finds this.**

### Why unlinked content is high-value

The stuff nobody linked is often the stuff nobody secured or remembered:

- **Backup/source files** — `index.php.bak`, `config.php~`, `.git/`, `site.zip` → source code and secrets.
- **Admin/management interfaces** — `/admin/`, `/manager/html`, `/phpmyadmin/`.
- **Config/environment files** — `.env`, `web.config`, `application.yml` → credentials, keys.
- **Old/dev/test artifacts** — `/old/`, `/dev/`, `/test/`, `/v1/` → weaker security, debug modes.
- **Hidden API endpoints** — `/api/internal/`, `/actuator/` → unauthenticated data/actions.

### The mechanism in one line

For each `word` in the wordlist: request `http://target/word` (and optionally `word.ext` for each extension), then decide from the **response** whether it "exists." That decision — distinguishing a real hit from the server's "not found" behavior — is the whole game (§6, §12).

---

## 4. How It Differs From the Alternatives

Content discovery is a crowded space: **gobuster, ffuf, dirb, dirbuster, dirsearch, wfuzz**. Knowing feroxbuster's niche helps you choose.

| Tool | Language | Recursion | Notable |
|---|---|---|---|
| **feroxbuster** | Rust | **Automatic, by default** | Fast, recursive-first, link extraction on by default, smart "collect" features, great live UI + scan menu |
| **ffuf** | Go | Manual (via config/scripting) | Extremely fast, ultra-flexible **fuzzing** (any position via `FUZZ`), great for parameter/vhost fuzzing |
| **gobuster** | Go | Not by default (needs re-runs) | Simple, fast, mode-based (dir/dns/vhost/fuzz); no recursion in `dir` mode historically |
| **dirsearch** | Python | Yes | Feature-rich, good defaults, slower |
| **dirb/dirbuster** | C/Java | dirbuster yes | Older, slower; classic teaching tools |

**Feroxbuster's distinguishing strengths:**

1. **Recursion is the default behavior**, not an afterthought — find `/api/`, and it immediately brute-forces *inside* `/api/`, then inside whatever it finds there, down to depth 4. This mirrors how a human would explore and is its signature feature.
2. **Speed** from Rust + async concurrency, so recursion doesn't become painfully slow.
3. **Link extraction on by default** — it's a *hybrid* discoverer, finding both **linked** (parsed from responses) and **unlinked** (brute-forced) content in one pass.
4. **"Smart" collectors** — auto-collect extensions, request backup variants of found files, and build wordlists from response bodies (§8).
5. **Polished UX** — real-time progress bars, and an interactive **Scan Management Menu** to cancel/add scans mid-run.

**When to pick something else:** for arbitrary-position **fuzzing** (parameters, headers, vhosts, POST bodies with the `FUZZ` keyword anywhere), **ffuf** is more flexible. Many testers use **both** — feroxbuster for recursive directory/file discovery, ffuf for targeted fuzzing.

---

## 5. How Feroxbuster Works Internally

The scan pipeline:

1. **Parse config** — merge command-line args, the `ferox-config.toml` file, and built-in defaults.
2. **Wildcard/soft-404 baseline** — before brute-forcing a directory, request a random nonexistent path to learn the "not found" behavior and **auto-create a filter** for it (§6).
3. **Wordlist expansion** — for each word, build the candidate URL(s): `dir/word`, plus `dir/word.ext` for each `-x` extension (and combinations from collected extensions).
4. **Concurrent requests** — an async engine (Rust/tokio) fires many requests at once (default 50 threads), respecting rate/scan limits.
5. **Response evaluation** — each response is checked against the **filters**: is its status/size/word-count/line-count/regex/similarity filtered out? If not, it's a **match** and gets printed.
6. **Link extraction** — matched responses' bodies (HTML, JS) and `robots.txt` are parsed for more paths, which are fed back into the scan (default on).
7. **Recursion queueing** — when a match looks like a directory (or with `--force-recursion`, any found asset), a **new scan is queued** for that directory, up to the depth limit.
8. **Collectors (optional)** — auto-collect extensions, request backup variants, and/or build a wordlist from bodies (§8).
9. **Live reporting + state** — print matches in real time with progress bars; write a **state file** so a Ctrl-C'd scan can be resumed.

**Key properties:**
- **It's a tree crawl by brute force.** Each discovered directory spawns its own sub-scan; the whole thing fans out concurrently — which is why it's both powerful and potentially very loud/heavy.
- **Filters are central.** Because it reports *everything* by default, your filter configuration is what turns raw noise into a clean findings list.
- **Auto-filtering protects you from wildcard chaos** (§6) — without it, a soft-404 server would report every single word as "found."

---

## 6. The Wildcard / Soft-404 Auto-Filter (Core Concept)

This is the same fundamental problem you met with Nikto's 404 baseline, and it's *the* concept that makes content discovery trustworthy — so internalize it.

**The problem:** you decide "the resource exists" from the response. But many servers **don't return a clean `404`** for missing paths:

- A **soft-404**: the server returns **`200 OK`** with a friendly "page not found" page for *any* path.
- A **wildcard**: `/anything` returns the same `200` content (SPA catch-all, custom error handler, some frameworks).
- A **catch-all redirect**: everything `302`s to `/login` or `/`.

Naively, feroxbuster would then report **every word in the wordlist as a hit** — thousands of false positives.

**How feroxbuster solves it (auto-filtering, on by default):** before scanning a directory, it **requests a random, guaranteed-nonexistent path**. Whatever comes back is the directory's "this doesn't exist" fingerprint. Feroxbuster then **auto-creates a filter** matching that fingerprint (by size/content), so all the real not-found responses are silently filtered out and only *genuinely different* responses surface as matches. You'll see it announce this live:

```
404      GET  4l  34w  232c  Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
```

**Manual reinforcement when auto-filter isn't enough:**

- **`--filter-similar-to <URL>`** — point at a known soft-404 page; feroxbuster **fuzzy-hashes** it and filters out responses that are *similar* (not just identical). This defeats soft-404s whose length varies slightly (timestamps, CSRF tokens, personalization) and would otherwise slip past a size filter.
- **`-S/--filter-size`, `-W/--filter-words`, `-N/--filter-lines`, `-X/--filter-regex`, `-C/--filter-status`** — filter out the noise pattern explicitly once you've spotted it (§12).
- **`-D/--dont-filter`** — disable auto-filtering entirely (rarely wanted; useful when debugging why something's missing).

**The takeaway:** a "match" in feroxbuster means *"this response differs from the server's not-found behavior,"* not *"status was 200."* When you see a flood of same-size results, the server has a wildcard/soft-404 and you need to add a filter — the tool tries automatically, but you finish the job.

---

## 7. Recursion Explained

Recursion is feroxbuster's headline feature. **When it finds a directory, it automatically starts a new scan inside that directory** — and inside whatever *that* scan finds — building out the tree without you re-running the tool.

**How it decides to recurse:** by default, feroxbuster recurses into responses that indicate a **directory** (e.g., a `301/302` redirect appending a trailing slash, or a `200` on a path ending in `/`). Each such find **queues a new sub-scan** using the same wordlist and settings.

**Controls:**

- **`--depth <n>`** — maximum recursion depth (**default 4**). `dir/a/b/c/d` is depth 4. `--depth 0` = unlimited (dangerous — can run effectively forever on large sites).
- **`-n/--no-recursion`** — disable recursion; scan only the given directory (one level). Faster, quieter, predictable — good for a first quick pass.
- **`--force-recursion`** — recurse into **any 'found' asset**, not just things that look like directories (still respects the depth limit). Useful when a server serves directory-like content without the usual signals, but it **massively increases requests** — use with care.
- **`--dont-scan <url/regex>`** — exclude URLs/patterns from recursion (e.g., skip `/logout`, huge static dirs, or anything that would cause a self-DoS or log you out).
- **`--scope <domain/url>`** — add extra in-scope domains/URLs so extracted links to those are scanned too (otherwise off-domain links are ignored).

**Why recursion is powerful and dangerous:** it mirrors human exploration and finds deeply-nested content a single-level scan misses. But **request volume multiplies** — a 30,000-word wordlist over many discovered directories at depth 4 can become **millions of requests**. Combine sensible depth, `--dont-scan`, `--scan-limit`, and `--rate-limit` (§16) to keep it controlled. On a big target, start with `-n` to map the top level, then let recursion loose selectively.

---

## 8. Link Extraction and the "Collect" Family (Smart Discovery)

Feroxbuster is a **hybrid** discoverer: it brute-forces *and* harvests. These "smart" features (several on by default) dramatically improve coverage over plain brute force.

### `-e/--extract-links` (default: ON)
For every matched response, feroxbuster parses the **body (HTML, JavaScript)** and **robots.txt** for absolute and relative links, then **feeds those paths back into the scan**. Example: a JS file references `/homepage/assets/img/icons/handshake.svg` → feroxbuster adds `/homepage/`, `/homepage/assets/`, `/homepage/assets/img/`, `/homepage/assets/img/icons/` as directories to scan, and requests the file itself. This catches **linked-but-unguessable** content (weird directory names no wordlist contains) — a huge win, especially for modern apps that embed API endpoints in JavaScript bundles. Disable with `--dont-extract-links` if you need a pure wordlist scan.

### `-E/--collect-extensions`
As it scans, feroxbuster **notices file extensions in play** on the target (e.g., it sees `.php` responses) and **automatically adds them to `--extensions`**, so subsequent requests try `word.php` too. It adapts the scan to the target's tech stack without you specifying extensions up front. (`--dont-collect` excludes specific extensions like `.js`/`.html` you don't want appended.)

### `--collect-backups`
For each **found file**, feroxbuster requests common **backup variants** — `file.bak`, `file~`, `file.old`, `file.1`, `.file.swp`, etc. This directly targets one of the highest-value finds: **source-code and config backups** left next to live files (`config.php` → try `config.php.bak`, which often serves the *source* instead of executing it). One of the most productive features for real findings.

### `--collect-words`
Feroxbuster **builds a wordlist from the words in response bodies** and uses them as additional scan candidates — a lightweight, target-specific wordlist generated on the fly, surfacing names that generic wordlists lack.

**Together**, these turn a static wordlist scan into an **adaptive** one that learns the target's structure, extensions, vocabulary, and backup conventions as it goes. That adaptivity is a major reason feroxbuster finds things other tools miss — at the cost of more requests, so mind the volume.

---

## 9. Wordlists and Extensions (The Fuel)

**A content-discovery tool is only as good as its wordlist.** The wordlist *is* your set of guesses; no word, no discovery.

### Wordlists
- Supply with **`-w/--wordlist`**. The common default points into **SecLists** (e.g., `Discovery/Web-Content/raft-medium-directories.txt`). Install SecLists (`apt install seclists` on Kali, or clone `danielmiessler/SecLists`).
- **Popular choices** (trade coverage vs speed):
  - `raft-*-directories.txt` / `raft-*-files.txt` — ranked by real-world frequency (great general choice).
  - `directory-list-2.3-medium.txt` (DirBuster) — classic, large.
  - `common.txt` — small/fast first pass.
  - Technology-specific lists (e.g., API, PHP, IIS wordlists) when you know the stack.
- **Strategy:** start with a **small/common** list for a fast first pass, then a **medium/large** list (with recursion) for depth. Pick lists matching the detected tech.

### Extensions
- **`-x/--extensions php,html,txt,bak`** appends each extension to every word: `admin` → `admin`, `admin.php`, `admin.html`, `admin.txt`, `admin.bak`. Multiplies requests by (1 + number of extensions), so choose extensions relevant to the target (PHP app → `php`; .NET → `aspx`; always consider `bak,old,txt,zip` for leaks).
- `--collect-extensions` (§8) can discover these automatically.

### The math (mind the volume)
Requests ≈ **wordlist size × (1 + extensions) × directories discovered (recursion)**. A 30k list × 4 extensions × 20 discovered dirs = **~2.4 million requests**. This is why wordlist choice, extensions, depth, and rate limits must be deliberate.

---

## 10. Installation

Feroxbuster ships as a static binary and via package managers.

```bash
# Kali / Parrot (apt)
sudo apt install feroxbuster

# Homebrew (macOS/Linux)
brew install feroxbuster

# Cargo (Rust)
cargo install feroxbuster

# Official install script (latest static binary)
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# Verify
feroxbuster --version
```

Also grab **SecLists** for wordlists: `sudo apt install seclists` (Kali) or clone `github.com/danielmiessler/SecLists`.

---

## 11. Command-Line Options (Full Breakdown)

Grouped by purpose. (Feroxbuster has a lot of options; these are the ones that matter.)

### Target & input
| Option | Purpose |
|---|---|
| `-u, --url <URL>` | Target URL (repeatable for multiple targets). |
| `--stdin` | Read target URL(s) from stdin (pipe from `httpx`, etc.). |
| `--resume-from <state.json>` | Resume a previous scan from its state file. |
| `-w, --wordlist <FILE>` | Wordlist to use (default: a SecLists raft list). |
| `-x, --extensions <e1,e2>` | Append file extensions to each word (e.g., `php,html,bak`). |
| `--scope <domain/url>` | Additional in-scope domains/URLs for extracted links. |
| `--dont-scan <url/regex>` | Exclude URLs/patterns from recursion/scanning. |

### Recursion
| Option | Purpose |
|---|---|
| `--depth <n>` | Max recursion depth (default 4; `0` = unlimited). |
| `-n, --no-recursion` | Don't recurse; single-level scan. |
| `--force-recursion` | Recurse into any found asset (respects depth). |

### Discovery smarts
| Option | Purpose |
|---|---|
| `-e, --extract-links` | Parse responses for links to scan (default ON). |
| `--dont-extract-links` | Disable link extraction. |
| `-E, --collect-extensions` | Auto-discover and add extensions. |
| `--collect-backups` | Request backup variants of found files. |
| `--collect-words` | Build a wordlist from response bodies. |
| `--dont-collect <exts>` | Exclude extensions from auto-collection. |

### Filtering (turn noise into findings — see §12)
| Option | Purpose |
|---|---|
| `-s, --status-codes <codes>` | **Allow-list** of status codes to keep (mutually exclusive with `-C`). |
| `-C, --filter-status <codes>` | **Deny-list** of status codes to filter out. |
| `-S, --filter-size <bytes>` | Filter out responses of these byte sizes. |
| `-W, --filter-words <n>` | Filter out by word count. |
| `-N, --filter-lines <n>` | Filter out by line count. |
| `-X, --filter-regex <regex>` | Filter out responses matching regex (body **and headers**). |
| `--filter-similar-to <URL>` | Filter out responses fuzzy-similar to this page (soft-404 killer). |
| `-D, --dont-filter` | Disable wildcard/soft-404 auto-filtering. |

### Requests
| Option | Purpose |
|---|---|
| `-H, --headers <H>` | Custom header(s), e.g. `-H "Authorization: Bearer X"`. |
| `-b, --cookies <C>` | Cookies to send. |
| `-Q, --query <k=v>` | Add query parameters. |
| `--data <DATA>` | Request body (for POST etc.). |
| `-m, --methods <M>` | HTTP method(s) to scan with (e.g., `GET,POST`). |
| `-a, --user-agent <UA>` | Custom User-Agent. |
| `-A, --random-agent` | Randomize the User-Agent. |
| `-r, --redirects` | Follow redirects. |
| `-k, --insecure` | Ignore TLS certificate errors. |

### Performance & safety (see §16)
| Option | Purpose |
|---|---|
| `-t, --threads <n>` | Concurrent threads (default 50). |
| `--rate-limit <n>` | Cap requests per second (per directory scan). |
| `--scan-limit <n>` | Max number of concurrent directory scans. |
| `-T, --timeout <secs>` | Per-request timeout (default 7). |
| `--auto-tune` | Automatically lower scan rate when errors spike. |
| `--auto-bail` | Automatically stop a scan throwing excessive errors. |

### Proxy, output & logging (see §17–18)
| Option | Purpose |
|---|---|
| `-p, --proxy <URL>` | Send **all** traffic through a proxy. |
| `--replay-proxy <URL>` | Send **only matched** responses through a proxy (e.g., Burp). |
| `--replay-codes <codes>` | Which status codes to replay to the replay proxy. |
| `-o, --output <FILE>` | Save results to a file. |
| `--json` | Output newline-delimited JSON. |
| `-q, --quiet` | Suppress progress bars (keep findings). |
| `--silent` | Machine-readable: only URLs, no banner/bars (for piping). |
| `-v, --verbosity` | Increase verbosity (`-vv`, etc.). |
| `--no-state` | Don't write a state file. |

Run `feroxbuster -h` (short help) or `--help` (long help) for the full, version-accurate list.

---

## 12. Filtering Deep-Dive

Because feroxbuster **reports all status codes by default**, **filtering is how you get a clean result set.** There are two philosophies, and (since v2.7.0) the status-code ones are **mutually exclusive**:

### Status-code filtering (pick one approach)
- **Allow-list with `-s/--status-codes`:** keep only these codes; everything else is filtered out. Example — only "found/redirect/auth" signals:
  ```bash
  feroxbuster -u https://target -w list.txt -s 200,204,301,302,307,308,401,403,405
  ```
- **Deny-list with `-C/--filter-status`:** keep everything **except** these. Example — hide 404s and 400s:
  ```bash
  feroxbuster -u https://target -w list.txt -C 404,400
  ```
You can't use both at once. Allow-list when you know exactly what "interesting" looks like; deny-list when you mostly want to strip a couple of noise codes.

> **Don't blanket-filter 403/401.** A `403 Forbidden` or `401 Unauthorized` means *the resource exists but is protected* — often a lead (an admin panel, a protected API). Filtering them out hides real attack surface. Keep them; investigate them.

### Content-based filtering (defeat soft-404 noise)
When a wildcard/soft-404 slips past auto-filtering, you'll see many results with the **same size/word/line count**. Filter that pattern out:

- **`-S 5174`** — filter out all responses of 5174 bytes (the soft-404's size). Combine multiples: `-S 5174,1287`.
- **`-W 312`** — filter by word count (better than size when size wobbles slightly).
- **`-N 36`** — filter by line count.
- **`-X '^Not Found$'`** or **`-X 'error-token'`** — regex filter on body **and headers** (great for a signature string in soft-404 pages).
- **`--filter-similar-to https://target/known-404`** — fuzzy-hash a known soft-404 and drop *similar* responses; the most robust option when the soft-404 page varies per request.

### The workflow
1. Run once, watch for a **flood of identical-sized results** → that's the wildcard/soft-404.
2. Note its size/word/line count or a unique string.
3. Re-run adding the matching filter (`-S`/`-W`/`-N`/`-X`/`--filter-similar-to`).
4. Keep `401/403` visible; strip `404`/noise.

Good filtering is the difference between a 5-line findings list and 30,000 lines of garbage.

---

## 13. Understanding the Output Line Format

Each match prints as a compact, aligned line. Learn to read it at a glance:

```
200      GET      5l      42w      1256c   http://target/admin/login.php
│         │        │       │        │       │
status    method   lines   words   bytes   discovered URL
```

- **Status** — HTTP status code (`200`, `301`, `403`, …).
- **Method** — HTTP method used (`GET` by default).
- **`Nl`** — **line** count of the response body.
- **`Nw`** — **word** count of the response body.
- **`Nc`** — **byte/character** count (content length).
- **URL** — the resource found.

**Why the l/w/c numbers matter:** they're your **filtering fingerprint**. Scanning the list, identical `l/w/c` triples across many URLs scream "soft-404 / wildcard" — copy those numbers into `-N`/`-W`/`-S` to filter them. Conversely, a result whose size differs from its neighbors is a real, distinct page worth opening.

**Reading status codes as leads:**
- `200` — exists and served. Open it.
- `301`/`302` — redirect; often a **directory** (feroxbuster will recurse). Note *where* it redirects (to `/login`? then it's protected).
- `401`/`403` — **exists but protected** — high-interest (bypass attempts, different methods, etc.).
- `405` — method not allowed → the path exists but not for this method; try others (`-m`).
- `500` — the path exists and **your request broke something** — a strong lead (error handling, injection).

The header block at the start also confirms your effective settings (threads, wordlist, status-code handling, extract-links, recursion depth) — always sanity-check it matches your intent before the scan runs.

---

## 14. Worked Examples with Output, Explained

> Output is **representative** of feroxbuster's format (banner + live matches + progress bar).

### 14.1 Basic scan

```bash
feroxbuster -u https://target.example.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

Representative output:
```
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `  /\ \_/ |  |  /__` |   |__/
|    |___ |  \ |  \ | \__, /~~\ / \ \__/ .__/ |   |  \
                        by Ben "epi" Risher 🤓         ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://target.example.com
 🚀  Threads               │ 50
 📖  Wordlist              │ raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET  9l  31w  278c  Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET  9l  28w  313c  https://target.example.com/admin => /admin/
200      GET  120l 340w 4823c https://target.example.com/login
403      GET  9l  28w  277c  https://target.example.com/server-status
301      GET  9l  28w  313c  https://target.example.com/api => /api/
200      GET  15l  40w  512c  https://target.example.com/robots.txt
[####################] - 2m  30000/30000 0s   found:5  errors:0
[####################] - 1m  30000/30000 0s   found:3  https://target.example.com/admin/
[####################] - 1m  30000/30000 0s   found:2  https://target.example.com/api/
```

**Reading it:**
- **Banner** confirms settings — note `Status Codes: All`, `Extract Links: true`, `Recursion Depth: 4` (the defaults).
- The **`404 … Auto-filtering …`** line is feroxbuster detecting the soft-404 and installing a filter automatically (§6). Everything below is post-filter.
- **`301 … /admin => /admin/`** — a redirect that's really a **directory**; feroxbuster will **recurse into it** (note the separate `/admin/` progress bar at the bottom — a sub-scan spawned by recursion).
- **`200 … /login`** — a real page (distinct size 4823c). Open it.
- **`403 … /server-status`** — **exists but forbidden** — a lead (Apache status page, worth a bypass attempt).
- **Multiple progress bars** — one per active directory scan; recursion is fanning out. `found:N` per scan.

### 14.2 Filtered, extensions, keep protected paths
```bash
feroxbuster -u https://target -w raft-medium-files.txt \
  -x php,bak,old,txt,zip \
  -C 404 \
  --collect-backups
```
- `-x php,bak,old,txt,zip` — hunt files and their **backups/leaks**.
- `-C 404` — strip 404s (keep 200/301/403/401/500 as leads).
- `--collect-backups` — for every found file, auto-request backup variants (catches `config.php.bak` source leaks).

### 14.3 Kill a stubborn soft-404 with similarity
```bash
feroxbuster -u https://spa.example.com -w list.txt \
  --filter-similar-to https://spa.example.com/definitely-not-real-xyz
```
The SPA returns a `200` app shell for everything; sizes vary slightly per request so `-S` won't catch them. `--filter-similar-to` fuzzy-hashes the shell and drops *similar* responses, leaving only genuinely different pages.

### 14.4 Authenticated scan through Burp, controlled rate
```bash
feroxbuster -u https://app.example.com -w list.txt \
  -H "Cookie: session=abc123" \
  --replay-proxy http://127.0.0.1:8080 \
  --rate-limit 100 --scan-limit 4 --depth 3
```
- `-H "Cookie: …"` — scan **as a logged-in user** (finds authenticated-only content).
- `--replay-proxy …:8080` — send **only the matches** into Burp for immediate follow-up (§17).
- `--rate-limit 100 --scan-limit 4 --depth 3` — keep it civilized: ≤100 req/s, ≤4 concurrent dir scans, depth 3.

### 14.5 Piped recon (many hosts, machine-readable)
```bash
cat live-hosts.txt | feroxbuster --stdin -w common.txt --silent -o ferox.txt
```
Feed live hosts from `httpx`, scan each, `--silent` for clean pipe-able URL output, save to file.

---

## 15. The Scan Management Menu and Interactive Control

Feroxbuster is **interactive during a scan.** Press **[ENTER]** at any time to open the **Scan Management Menu™**, which lets you:

- **View all active scans** (each recursive directory scan is listed with its progress).
- **Cancel specific scans** — kill a runaway recursion (e.g., a huge `/static/` tree or an accidental self-DoS) *without stopping the whole run*.
- **Add new scan targets** on the fly.

This is a genuine advantage over fire-and-forget tools: when recursion wanders into a giant, low-value directory, you don't have to abort everything — open the menu, cancel just that branch, and let the useful scans continue.

**Stopping and resuming:** `Ctrl-C` stops the scan and writes a **state file** (`ferox-<timestamp>.state`). Resume later with `--resume-from <file>` (§18) — invaluable for long scans you must pause.

---

## 16. Performance and Safety Tuning

Feroxbuster is fast, and with recursion + extensions + collectors it can generate **enormous** request volume. Tuning keeps it effective without hammering the target (or yourself).

**Speed vs stealth vs stability dials:**
- **`-t/--threads <n>`** — concurrency (default 50). More = faster but heavier on target and network.
- **`--rate-limit <n>`** — hard cap on **requests/second** (per scan). The cleanest way to be gentle on a fragile or monitored target.
- **`--scan-limit <n>`** — cap **concurrent directory scans**. Recursion can spawn dozens; limiting them controls total load and keeps output readable.
- **`--depth <n>`** — shallower depth = far fewer requests. Start shallow, go deeper deliberately.
- **`-T/--timeout <secs>`** — lower to fail-fast on dead hosts; raise on slow targets.

**Automatic guardrails:**
- **`--auto-tune`** — when errors spike (server struggling / rate-limiting you), feroxbuster **automatically slows down** to a sustainable rate, then recovers. Great default for unknown targets.
- **`--auto-bail`** — when errors become excessive, **abandon the failing scan** rather than pointlessly hammering. Protects the target and your results.

**Avoiding self-inflicted problems:**
- **`--dont-scan`** logout/delete endpoints and giant static trees (prevents getting logged out mid-scan or wasting hours on `/images/`).
- On production/fragile targets: **`--rate-limit` + `--scan-limit` + `--auto-tune`** and a moderate `--depth`. Fast defaults are for labs and robust targets.

**Rule of thumb:** the tool's *speed* is not free — it's borrowed from the target's capacity and your visibility. Tune it to the engagement.

---

## 17. Sending Matches to Burp (Replay Proxy) and Integrations

A standout feature: **`--replay-proxy`** sends **only the matched (interesting) responses** through a proxy, unlike `-p/--proxy` which floods the proxy with *every* request.

```bash
feroxbuster -u https://target -w list.txt --replay-proxy http://127.0.0.1:8080 --replay-codes 200,301,302,401,403
```

- Feroxbuster does the noisy brute-forcing itself, but **only the finds land in Burp's history** — so your Burp stays clean and every entry is a real discovery ready to send to Repeater/Scanner.
- `--replay-codes` controls which status codes get replayed (default matches the found set).

**Why this is better than `--proxy` for discovery:** routing 30,000 brute-force requests through Burp would bury you and bog Burp down. Replay proxy gives you the best of both: feroxbuster's speed for discovery, Burp's depth for the handful of hits.

**Other integrations:**
- **`--stdin`** — accept targets piped from `httpx`/`subfinder` (chain recon).
- **`--json` / `--silent`** — machine-readable output to pipe into `jq`, other tools, or a report pipeline.
- **`-o`** — save findings for later processing or as evidence.

---

## 18. Resume, State, Output Formats, and Piping

**State & resume:**
- On `Ctrl-C`, feroxbuster writes a **state file** (`ferox-<timestamp>.state`, JSON) capturing progress.
- Resume with **`--resume-from ferox-<timestamp>.state`** — it picks up where it left off. Essential for long scans, flaky networks, or scheduled windows.
- **`--no-state`** disables writing the state file if you don't want it.

**Output & piping modes:**
- **`-o report.txt`** — save the human-readable results.
- **`--json`** — newline-delimited JSON (one object per result) → perfect for `jq` and tooling.
- **`--silent`** — only the discovered URLs, no banner/bars/colors → ideal for `| tool` pipelines and scripting.
- **`-q/--quiet`** — drop the progress bars but keep readable findings (good for logging to a terminal you're watching).

```bash
# Pipe clean URLs into the next tool
feroxbuster -u https://target -w list.txt --silent | httpx -silent -title -tech-detect

# Structured output for processing
feroxbuster -u https://target -w list.txt --json -o ferox.json
```

---

## 19. The Config File (ferox-config.toml)

For persistent defaults, feroxbuster reads **`ferox-config.toml`** (in the binary's directory, or `~/.config/feroxbuster/`). Any CLI option has a config equivalent; CLI args override the file. Example:

```toml
# ferox-config.toml
wordlist       = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
threads        = 40
timeout        = 7
filter_status  = [404]
extract_links  = true
collect_backups = true
auto_tune      = true
scan_limit     = 6
rate_limit     = 200
replay_proxy   = "http://127.0.0.1:8080"
replay_codes   = [200, 301, 302, 401, 403]
extensions     = ["php", "bak", "old", "txt"]
depth          = 3
```

This lets you encode your **house defaults** — sensible rate/scan limits, your preferred wordlist, always-on backup collection, auto-tune, and Burp replay — so every scan starts safe and productive without a wall of flags. Keep separate config files per engagement style (fast-lab vs careful-prod) and select with `--config` where supported.

---

## 20. Where It Fits: Workflow and Chaining

Content discovery runs **after** you've found live web servers and **alongside/before** deep application testing.

```
[ subdomain enum ] → [ port scan ] → [ httpx: live web servers + tech ]
                                              │
                                              ▼
                                    [ FEROXBUSTER ]  ← discover unlinked files/dirs (recursive)
                                              │   (admin panels, backups, .git, .env, APIs, old apps)
                                              ▼
                    findings → [ Burp / ZAP ] (deep testing of discovered endpoints)
                             → [ nuclei ]     (templated checks against discovered paths)
                             → manual review  (open every 200/403/500 lead)
```

**Relationship to the other tools you've studied:**
- **vs a crawler (Burp/ZAP spider):** the spider finds *linked* content; feroxbuster finds *unlinked* content. **Run both** — they're complementary halves of "what's on this server?"
- **vs Nikto:** Nikto checks a curated list of *known-bad* paths and versions; feroxbuster brute-forces a *wordlist* to find *this target's* hidden paths. Different jobs; use both.
- **Feeding Burp:** use `--replay-proxy` so discovered endpoints land in Burp, then test them with Repeater/Intruder/Scanner.

The discipline: **discover → filter to real hits → open every lead → test the interesting ones deeply.** Feroxbuster owns the discovery step; its output quality (driven by wordlist + filters) sets up everything downstream.

---

## 21. Pitfalls and Good Practice

- **Wildcard/soft-404 floods.** If you get thousands of same-size hits, add a filter (`-S`/`-W`/`-N`/`-X`/`--filter-similar-to`). Auto-filter helps but isn't perfect (§6).
- **Don't filter out `401`/`403`.** "Exists but protected" is a lead, not noise.
- **Recursion explosion.** Depth 4 × big wordlist × extensions × many dirs = millions of requests. Use `--depth`, `--scan-limit`, `--rate-limit`, `--dont-scan`, and the scan menu to stay in control.
- **Weak wordlist = weak results.** The list is your guesses; pick good ones (SecLists raft/dirsearch lists) and match the tech stack. No word, no find.
- **Extensions matter.** Add stack-relevant extensions (`php`/`aspx`/`jsp`) and leak extensions (`bak`,`old`,`zip`,`txt`); consider `--collect-extensions`.
- **Getting logged out / self-DoS.** `--dont-scan` logout/delete/expensive endpoints; scan authenticated with `-H`/`-b` but exclude session-killers.
- **Loud by nature.** Brute-forcing thousands of paths is very visible in logs/WAF. It's active testing — expect detection; throttle where needed.
- **Verify every finding.** A `200` from feroxbuster means "distinct from not-found," not "exploitable." Open it, confirm it's real and interesting.

---

## 22. Legal and Ethical Note

- **Feroxbuster is active, high-volume testing.** It sends thousands to millions of requests, probing for hidden resources — unambiguously intrusive, and easily disruptive to fragile targets.
- **Only scan systems you own or are explicitly authorized to test** — signed scope/rules of engagement, an in-scope bug-bounty target that permits automated content discovery (some programs restrict request rates or forbid noisy brute-forcing — **read the rules**), or your own lab.
- **Rate-limit and coordinate on anything fragile or production.** Use `--rate-limit`, `--scan-limit`, `--auto-tune`, and moderate depth; never unleash default speed on a system you're unsure about.
- **Finding a resource is not permission to attack it.** Discovery yields a map; testing what you find must be in scope. A discovered `/admin/` outside authorization is off-limits.
- **Practice legally:** run feroxbuster against intentionally vulnerable targets — **OWASP Juice Shop**, **DVWA**, **Metasploitable**, HTB/THM lab boxes, or your own VMs — to learn its output, filtering, and recursion behavior safely.

---

### Where to go next

- On a lab box (DVWA/Juice Shop), run a **plain scan**, watch the **auto-filter** line appear, then deliberately trigger a soft-404 flood and practice killing it with `-S`/`--filter-similar-to` — that filtering intuition (§6, §12) is the core skill.
- Turn on **`--collect-backups`** and add `-x bak,old,txt` against a target with source files — finding a `.bak` that serves raw source is one of the most satisfying (and common) real wins.
- Wire up **`--replay-proxy http://127.0.0.1:8080`** so discoveries flow straight into Burp, then test the juicy `200`/`403` hits — that hand-off from discovery to deep testing is the whole point.

*End of reference.*

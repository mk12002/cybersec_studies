# LinkFinder & SecretFinder — The Complete Reference (Beginner → Advanced)

> A ground-up reference for mining JavaScript: **LinkFinder** (extract hidden **endpoints/paths** from JS) and **SecretFinder** (extract **API keys/tokens/secrets** from JS). Why the real attack surface hides in JavaScript, how these regex tools work, their limits, the modern alternatives (jsluice, xnLinkFinder), and how they feed your workflow.

---

## Table of Contents

1. [What These Tools Are and Why](#1-what-these-tools-are-and-why)
2. [Why JavaScript Analysis Matters (The Hidden Attack Surface)](#2-why-javascript-analysis-matters-the-hidden-attack-surface)
3. [Status and Key Facts](#3-status-and-key-facts)
4. [LinkFinder: What It Finds and How](#4-linkfinder-what-it-finds-and-how)
5. [LinkFinder Options and Examples](#5-linkfinder-options-and-examples)
6. [SecretFinder: What It Finds and How](#6-secretfinder-what-it-finds-and-how)
7. [Secrets in Client-Side Code (The Concept)](#7-secrets-in-client-side-code-the-concept)
8. [SecretFinder Options and Examples](#8-secretfinder-options-and-examples)
9. [Gathering JavaScript Files (The Input Problem)](#9-gathering-javascript-files-the-input-problem)
10. [Installation](#10-installation)
11. [Regex Mining vs AST Parsing: Strengths and Limits](#11-regex-mining-vs-ast-parsing-strengths-and-limits)
12. [Reading and Validating Results](#12-reading-and-validating-results)
13. [Modern Alternatives](#13-modern-alternatives)
14. [Where It Fits: Workflow and Chaining](#14-where-it-fits-workflow-and-chaining)
15. [Limitations and Pitfalls](#15-limitations-and-pitfalls)
16. [Legal and Ethical Note](#16-legal-and-ethical-note)

---

## 1. What These Tools Are and Why

**LinkFinder** and **SecretFinder** are Python tools that **mine JavaScript files for hidden treasure** — the things developers put in client-side code that expand your attack surface but that a normal crawler never surfaces:

- **LinkFinder** (by Gerben Javado) extracts **endpoints and paths** from JavaScript — API routes (`/api/v1/users`), internal paths, admin endpoints, and parameters referenced in the JS but not linked anywhere in the rendered HTML.
- **SecretFinder** (by m4ll0k, built on LinkFinder) extracts **secrets** from JavaScript — hardcoded API keys, access tokens, AWS keys, Google API keys, authorization headers, JWTs, and private keys that developers accidentally left in client-side code.

They're **sibling tools using the same technique** (regex-matching over JavaScript content) aimed at two different prizes: LinkFinder hunts **endpoints**, SecretFinder hunts **secrets**. Both are staples of the recon/discovery phase, especially in bug bounty.

**Why they exist / the problem they solve:** modern web apps are **JavaScript-heavy single-page applications (SPAs)** — a thin HTML shell plus large JS bundles that define the entire application, including which API endpoints it calls and how. That means **the real map of the API lives inside the JavaScript**, not in HTML links. A crawler (or content-discovery tool like feroxbuster) can only find what's *linked* or *guessable* — it will never see `/api/internal/admin/users` if that route only appears as a string inside `app.min.js`. Reading the JS is the only way to find it. Likewise, developers frequently (and mistakenly) leave **secrets in client-side code** — thinking it's "hidden" when it's actually served to every visitor. LinkFinder and SecretFinder automate reading through big, minified JS bundles to pull out exactly these hidden endpoints and leaked secrets.

**The mental model:** *the JavaScript is a treasure map the app hands to every visitor.* These tools read that map so you don't have to manually scroll through thousands of lines of minified JS.

---

## 2. Why JavaScript Analysis Matters (The Hidden Attack Surface)

This concept is the whole rationale, so understand it well — it's why JS mining is one of the highest-ROI recon activities on modern targets.

**The shift to client-side apps changed where the attack surface lives.** A traditional server-rendered site put its links and forms in the HTML — a crawler could map it. A modern **SPA** ships a minimal HTML page and a bundle of JavaScript that, when it runs, builds the UI and makes API calls. Consequences:

1. **Endpoints are defined in JS, not HTML.** The routes the app calls (`fetch('/api/v2/orders')`, `axios.get('/admin/config')`) are **strings inside the JavaScript**. They appear nowhere in the HTML source and nowhere a crawler following `<a href>` links would go. **Only reading the JS reveals them.**

2. **Hidden/internal/admin APIs leak.** Bundles often reference endpoints the current user can't reach through the UI — admin routes, internal APIs, debug endpoints, feature-flagged functionality, deprecated versions (`/api/v1/` still live alongside `/api/v2/`). These are prime targets (unlinked = often less-tested and less-protected), and they surface as strings in the JS.

3. **Parameters and structure leak.** The JS reveals what parameters endpoints take, request shapes, and internal naming — fuel for further testing (fuzzing with ffuf, testing with Burp).

4. **Secrets leak.** Developers embed API keys/tokens in JS believing it's private. **It isn't** — every byte of JavaScript is downloaded by the browser, so anything in it is public. Hardcoded AWS keys, third-party API keys (Google Maps, Stripe, Firebase), and auth tokens routinely end up in bundles.

**Why crawlers and content discovery miss this:** a crawler finds *linked* content; content discovery (feroxbuster/ffuf) *guesses* paths from a wordlist. Neither can find `/api/internal/xR7q-export` — it's not linked and not in any wordlist. But it's sitting in plain sight as a string in the JavaScript. **JS analysis fills the gap between "what's linked" (crawler) and "what's guessable" (brute force) with "what the app actually references."**

**The payoff:** on a modern target, mining the JS often yields **more real, high-value endpoints than any other single technique** — the internal API the developers forgot was reachable, the admin route, the leaked key. That's why experienced testers extract and read the JavaScript early and thoroughly.

---

## 3. Status and Key Facts

- **LinkFinder** — by **Gerben Javado (@GerbenJavado)**. Python. Uses **jsbeautifier** + regex to find endpoints. Pre-installed/available on **Kali/Parrot**. **Lightly maintained** — stable and still widely used, but not actively developed.
- **SecretFinder** — by **m4ll0k (Momo Outaadi)**, **based on LinkFinder**. Python. ~20 built-in secret regexes in the original. **Lightly maintained**, with community **enhanced forks** (e.g., an "Advanced Edition" with 118+ patterns, severity scoring, and JSON/CSV output).
- **Both are regex-based** — they match patterns in JS text. This is fast and simple but has real limitations vs. parser-based tools (§11).
- **Both need JavaScript to analyze** — they can fetch from a URL/domain (LinkFinder `-d`), but the modern pattern is to **gather JS with a crawler first** (§9), then mine.
- **Modern successors exist** (§13): **jsluice** (BishopFox / Tom Hudson) uses a real **AST parser** (tree-sitter) and does both endpoints *and* secrets, catching dynamically-built URLs regex misses; **xnLinkFinder** extends LinkFinder with parameters, wordlists, and more input formats. For serious work today, these are often preferred — but LinkFinder/SecretFinder remain the well-known, lightweight regex baseline and are worth knowing.
- **Practical honesty:** these tools produce **noisy output** (lots of matches, many false positives). Their value is in the *leads* they surface — you validate afterward (§12).

---

## 4. LinkFinder: What It Finds and How

**LinkFinder extracts endpoints/paths from JavaScript** by running a carefully-crafted **regular expression** over the (beautified) JS content and pulling out everything that *looks like* a URL, path, or endpoint.

**What it matches** (roughly): full URLs (`https://api.example.com/...`), absolute paths (`/api/v1/users`), relative paths (`../admin/config`), file references (`config.json`, `app.js`), and API-route-shaped strings. Its regex is tuned to catch the many forms endpoints take in JS.

**How it works:**
1. **Ingest** JavaScript — a single JS URL, a local file, a folder of files, a Burp save file, or (with `-d`) all JS discovered under a domain.
2. **Beautify** — run minified JS through **jsbeautifier** so the regex works on readable code and the output shows meaningful context.
3. **Regex-match** — apply the endpoint regex, collecting every match.
4. **Output** — list the endpoints found per file, either to the terminal (`-o cli`) or as an **HTML report** that shows each endpoint **with its surrounding code context** (so you can see how/where it's used).

**The value:** in seconds it turns a 20,000-line minified bundle into a list of the paths/URLs it references — the app's API surface, laid bare. You then filter to the interesting ones (`-r '^/api/'`), probe them (httpx), and test them (Burp).

**The limitation (important):** because it's **pure regex on text**, LinkFinder only finds endpoints that appear as **literal strings**. If the app **builds a URL dynamically** — e.g., `baseUrl + '/' + version + '/users'` where the pieces are separate variables — the full endpoint never exists as one string, so regex **misses it**. It also produces **false positives** (strings that look like paths but aren't endpoints). These are inherent to the regex approach and the main reason parser-based tools (§11, §13) exist. Still, for a fast, dependency-light sweep of literal endpoints, LinkFinder is excellent.

---

## 5. LinkFinder Options and Examples

**Options (6 inputs):**

| Option | Purpose |
|---|---|
| `-i, --input` | Input: a **URL**, a **file**, a **folder**, a **Burp XML** save file, or a **wildcard** (`'*.js'`). |
| `-o, --output` | Output: `cli` (terminal) or a **filename** (HTML report). Default is an HTML file. |
| `-r, --regex` | **Filter** results by a regex (keep only matching endpoints, e.g., `^/api/`). |
| `-d, --domain` | **Domain mode** — when input is a URL, also fetch and analyze **all JS under that domain** in one pass. |
| `-b, --burp` | Input is a **Burp** "Save selected" file of multiple items. |
| `-c, --cookies` | Cookies to send when fetching (for authenticated JS). |
| `-H` / headers | (fork-dependent) custom headers. |

**Examples:**

```bash
# 1. Analyze a single JS file, print to terminal
python3 linkfinder.py -i https://example.com/static/app.min.js -o cli

# 2. Enumerate ALL JS under a domain and extract endpoints
python3 linkfinder.py -i https://example.com -d -o results.html

# 3. Keep only API endpoints (filter noise with -r)
python3 linkfinder.py -i https://example.com -d -r '^/api/' -o cli

# 4. Analyze a whole folder of downloaded JS files
python3 linkfinder.py -i '/path/to/js/*.js' -o cli

# 5. Analyze a bundle captured in Burp
python3 linkfinder.py -i burp_saved_items.xml -b -o report.html
```

**Practical guidance:**
- **`-d` domain mode** is the quick "point it at the site" approach — it grabs the JS and mines it in one command.
- **`-r` is essential for signal** — raw output is noisy; filter to what you care about (`^/api/`, a path prefix, a keyword) so you get probeable endpoints, not every matched string.
- **HTML output** (the default) shows **code context** for each endpoint — useful to judge whether a match is a real endpoint and how it's called. **CLI output** is better for piping into other tools.
- Feed the interesting endpoints onward: resolve relative paths to full URLs, then **httpx** to see which are live, then **Burp/ffuf** to test them.

---

## 6. SecretFinder: What It Finds and How

**SecretFinder is LinkFinder's sibling aimed at secrets.** It uses the **same technique** (beautify + regex over JS), but its regex set targets **sensitive data patterns** instead of endpoints. It hunts for hardcoded credentials and keys developers leaked into client-side code.

**What it looks for** (the original ~20 patterns, more in forks):
- **Cloud keys** — AWS access keys (`AKIA...`), Google API keys (`AIza...`), Google OAuth, GCP service-account keys.
- **Third-party service keys/tokens** — Stripe, Slack tokens/webhooks, Twilio, Mailgun, Facebook, Twitter, Heroku, PayPal/Braintree, Square.
- **Auth material** — `Authorization: Bearer ...` headers, Basic-auth strings, **JWTs**, generic `api_key`/`apikey`/`secret`/`token` assignments.
- **Private keys** — RSA/EC/PGP/SSH **private key** blocks (`-----BEGIN ... PRIVATE KEY-----`).
- **Other** — passwords in config objects, connection strings, etc.

**How it works** — identical pipeline to LinkFinder (ingest → jsbeautifier → regex-match → output cli/HTML), just with the secret-pattern regexes. It can **also run LinkFinder-style endpoint extraction** in the same pass with the **`-e`** flag, so one run yields *both* secrets *and* links.

**The value:** finding a **live API key or token in JS is a direct, often-critical finding** — depending on the key, it might grant access to cloud resources (AWS), send messages/charges (Twilio/Stripe), read data, or authenticate as a user. SecretFinder surfaces these leads from bundles you'd never read by hand.

**The critical caveat (validate everything):** a regex match is **not** automatically a valid, sensitive, exploitable secret. Many matches are:
- **Public-by-design keys** — e.g., a Google Maps *browser* API key or a Firebase config is *meant* to be in client-side code and restricted by referrer/domain (not a vulnerability by itself).
- **Test/placeholder/example values** — `sk_test_...`, `YOUR_API_KEY_HERE`, dummy tokens.
- **Non-secret strings** matching a loose pattern (false positives).
So SecretFinder gives you **candidate secrets** — you must **verify** each (is it live? is it privileged? is it actually sensitive?) before reporting (§12). A "found AWS key!" that turns out to be a restricted, public, or test key is a false alarm, and reporting unvalidated secrets erodes trust.

---

## 7. Secrets in Client-Side Code (The Concept)

Understand *why* secrets end up in JavaScript — it's a fundamental, common developer mistake, and knowing it makes you both a better finder and a better adviser.

**The core truth: anything in client-side code is public.** JavaScript is downloaded and executed by the user's browser — every line is fully visible to anyone who opens DevTools or fetches the `.js` file. There is **no such thing as a "hidden" or "secret" value in front-end code.** Minification and obfuscation only make it *harder to read*, not private — the secret is still there, extractable.

**Why developers get this wrong:**
- **"It's minified, no one will find it"** — false; minification is trivially reversible (beautify), and SecretFinder reads it in seconds.
- **Convenience** — hardcoding a key in the JS is easier than proxying calls through a backend, so under deadline pressure the key goes client-side.
- **Confusion about key types** — some keys *are* safe client-side (a domain-restricted Maps key), so developers wrongly assume *all* keys are.
- **Build-time leakage** — secrets in environment variables or config get accidentally bundled into the front-end build (`.env` values compiled into the JS).

**Why it's dangerous:** a leaked **backend/privileged** key (an AWS secret key, a server-side API key, an unrestricted third-party token) in JS = **anyone on the internet has that credential.** It can lead to cloud account compromise, data access, financial abuse (sending SMS/charges), or authentication bypass — sometimes critical, all from a string in a public file.

**The correct design (remediation you'd advise):** **secrets belong on the server, never in client-side code.** Front-end code should call *your* backend, which holds the secret and makes the privileged call server-side. Client-side keys that must exist (Maps, analytics) should be **scoped/restricted** (by domain, referrer, and permissions) so exposure is harmless. Rotate any key that was ever exposed in client code.

**The takeaway for testing:** because this mistake is so common, **JS bundles are a reliable place to find leaked secrets** — and SecretFinder automates the search. But the *impact* depends entirely on *what* the key is and whether it's still live and privileged, which is why validation (§12) is inseparable from the find.

---

## 8. SecretFinder Options and Examples

**Options:**

| Option | Purpose |
|---|---|
| `-i, --input` | Input: URL, file, folder, or wildcard (`'*.js'`). |
| `-e, --extract` | Also run **LinkFinder-style endpoint extraction** (secrets *and* links in one pass). |
| `-o, --output` | `cli` or an HTML report filename. |
| `-r, --regex` | Add a **custom** secret regex (e.g., a project-specific token format). |
| `-g, --ignore` | **Ignore** JS files matching these (semicolon-separated) names (skip jquery/bootstrap/etc.). |
| `-n, --only` | Process **only** the specified JS files (semicolon-separated). |
| `-c, --cookies` | Cookies (authenticated fetch). |
| `-H, --headers` | Custom headers. |
| `-p, --proxy` | Route through a proxy (e.g., Burp). |

**Examples:**

```bash
# 1. Find secrets in all JS under a site, terminal output, also extract links
python3 SecretFinder.py -i https://example.com/ -e -o cli

# 2. Analyze a folder/wildcard of downloaded JS files
python3 SecretFinder.py -i 'test/*.js' -o cli

# 3. Ignore common library JS (reduce noise)
python3 SecretFinder.py -i https://example.com/ -e -g 'jquery;bootstrap;api.google.com' -o cli

# 4. Only analyze specific (interesting) JS files
python3 SecretFinder.py -i https://example.com/ -e -n 'app.min.js;config.js' -o cli

# 5. Custom regex + headers + cookies + proxy (through Burp)
python3 SecretFinder.py -i https://example.com/ -e -o cli \
  -c 'session=111234' -H 'x-api:val1' -p 127.0.0.1:8080 -r 'apikey=[a-zA-Z0-9]+'

# 6. HTML report
python3 SecretFinder.py -i https://example.com/ -e -o results.html
```

**Practical guidance:**
- **`-e` is worth almost always including** — you get endpoints *and* secrets in one run (SecretFinder can do LinkFinder's job too).
- **`-g` (ignore) cuts noise** — skip well-known library bundles (jQuery, Bootstrap, analytics) that flood results with irrelevant matches.
- **Custom `-r`** lets you hunt a **project-specific** secret format you've identified (e.g., the target's internal token prefix).
- **Route through Burp (`-p`)** so the fetch is visible and you can pivot to testing found endpoints immediately.
- **Every match is a candidate** — validate before believing/reporting (§12).

---

## 9. Gathering JavaScript Files (The Input Problem)

Before you can mine JS, you need the JS. LinkFinder/SecretFinder can fetch from a domain (`-d`, `-i <url>`), but on real targets there are **many** JS files (first-party bundles, chunked lazy-loaded modules, third-party scripts, historical versions), and getting *all* of them is its own step. The modern pattern is: **gather with a dedicated tool, then mine.**

**Ways to gather JavaScript URLs/files:**
- **getJS / subjs** — pull the list of JS file URLs referenced by a page/site. `getJS --url https://example.com` → a list of script URLs.
- **katana** (ProjectDiscovery) — a modern crawler that discovers URLs including JS, with JS-parsing/headless support.
- **gau / waybackurls** — pull **historical** URLs (including old JS files) from the Wayback Machine/Common Crawl/etc. — old bundles often contain **endpoints/secrets since removed from the live site** but still reachable or informative.
- **gospider / hakrawler** — crawlers that collect URLs and JS.
- **Burp** — as you browse, Burp's HTTP history captures every JS file; save them and feed to LinkFinder (`-b`).
- **httpx** — probe a list of JS URLs to confirm which are live and fetch them.

**The gather-then-mine pipeline:**
```bash
# 1. collect JS file URLs (live + historical)
katana -u https://example.com -silent | grep '\.js$' | sort -u > js_urls.txt
gau example.com | grep '\.js$' | sort -u >> js_urls.txt
sort -u js_urls.txt -o js_urls.txt

# 2. (optional) download them
mkdir js && while read u; do curl -s "$u" -o "js/$(echo $u | md5sum | cut -c1-10).js"; done < js_urls.txt

# 3. mine each for endpoints + secrets
while read u; do python3 SecretFinder.py -i "$u" -e -o cli; done < js_urls.txt
```

**Why historical JS matters:** `gau`/`waybackurls` surface **old bundles** the site no longer serves in its current HTML but that may still be hosted (or reveal endpoints/keys that still work on the backend). Mining historical JS is a classic way to find **deprecated-but-live** endpoints and **rotated-but-not-really** secrets. Always include a historical pass.

---

## 10. Installation

Both are Python scripts with a couple of dependencies.

```bash
# LinkFinder
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
python3 -m pip install -r requirements.txt      # jsbeautifier, argparse, etc.
python3 linkfinder.py -h
# (optional) install: python3 setup.py install

# SecretFinder
git clone https://github.com/m4ll0k/SecretFinder.git
cd SecretFinder
python3 -m venv venv && source venv/bin/activate
pip3 install -r requirements.txt                # jsbeautifier, requests, lxml, etc.
python3 SecretFinder.py -h

# Both are also on Kali/Parrot repos in some form, and there are
# enhanced forks (e.g. Xnuvers007/SecretFinder) with more patterns/output formats.
```

Use a **virtualenv** to avoid dependency clashes (SecretFinder's older deps can conflict with system Python). Grab the gathering tools too — **getJS**, **katana**, **gau** (§9) — since mining needs JS input.

---

## 11. Regex Mining vs AST Parsing: Strengths and Limits

Understanding *how* these tools find things — and where they fail — is what makes you use them well and know when to reach for a better tool.

**LinkFinder/SecretFinder are regex-based (pattern matching on text):**
- **Strengths:** simple, fast, dependency-light, no need to actually parse JavaScript, works on any text (even broken/partial JS), easy to add custom patterns.
- **Weaknesses:**
  - **Misses dynamically-built values.** `const url = base + '/' + ver + '/users'` never exists as one string, so a regex for `/.../users` won't match it. Concatenated URLs, config-object-assembled paths, and template literals with variables slip through.
  - **False positives.** A loose regex matches things that *look* like paths/secrets but aren't (a version string, a CSS class, a base64 blob that isn't a key).
  - **No context/semantics.** Regex sees text, not meaning — it can't tell a live secret from a test one, or a real endpoint from a comment.

**Parser-based tools (jsluice) use an AST (Abstract Syntax Tree via tree-sitter):**
- They **actually parse the JavaScript** into a syntax tree, so they understand structure and can **resolve values built from concatenation and config objects** — recovering URLs and secrets that regex tools miss, with **fewer false positives** and **context awareness** (e.g., distinguishing a variable named `apiKey` assigned a real-looking value).
- **Tradeoff:** heavier, and needs valid-enough JS to parse.

**The practical implication:** LinkFinder/SecretFinder are a great **fast, lightweight first sweep** and are everywhere, but for **thorough** JS mining on a serious target, **also run a parser-based tool (jsluice)** to catch the dynamically-constructed endpoints and secrets regex misses. Using both maximizes coverage — regex for a quick broad pull, AST for depth. This regex-vs-parser distinction is the single most important thing to know about JS-mining tool selection.

---

## 12. Reading and Validating Results

Both tools produce **candidates, not confirmed findings.** Output is noisy; validation is where the real work (and the real findings) are.

**Validating endpoints (LinkFinder output):**
1. **Resolve relative paths to full URLs** — `/api/v2/users` → `https://target.com/api/v2/users` (jsluice's `--resolve-paths`, or do it manually/scripted).
2. **Dedupe and filter** — drop obvious noise (static assets, third-party paths), keep app/API routes.
3. **Probe with httpx** — which endpoints are **live**? What status/type? `cat endpoints.txt | httpx -sc -title -silent`.
4. **Investigate the interesting ones in Burp** — hit them with your session (and without), look for unauthenticated access, IDOR, injectable params. Unlinked API endpoints are frequently under-protected — an admin/internal route reachable directly is a classic finding.

**Validating secrets (SecretFinder output) — be especially careful:**
1. **Classify the key type** — is it *meant* to be public (domain-restricted Maps/Firebase key) or a *server-side* secret that shouldn't be here?
2. **Check for test/placeholder** — `sk_test_`, `example`, `xxxx`, obviously dummy values → discard.
3. **Verify it's live and privileged** — *carefully and only in scope*: does the key actually authenticate? What can it do? (Many services have safe "who am I / list" calls to check a key's validity/permissions without causing harm.) A live, unrestricted, privileged key = a real, often critical finding; a restricted/test/dead key = not.
4. **Don't abuse the key** — validating ≠ exploiting. Confirm it's live and note the privilege; don't run up charges, exfiltrate data, or modify anything (and mind that *using* a found key may itself exceed authorization — §16).

**The discipline:** treat every match as a lead. **Endpoints → probe and test; secrets → classify and cautiously verify.** The false-positive rate is high, so the tester's judgment in triaging results is what turns noisy regex output into genuine findings. Never report an unvalidated "leaked key" or a non-existent endpoint.

---

## 13. Modern Alternatives

The JS-mining space has moved on; for real work, know these (LinkFinder/SecretFinder remain the lightweight baseline):

- **jsluice** (BishopFox / Tom Hudson) — **the modern successor.** Parses JS into a **tree-sitter AST** rather than regex, so it recovers **URLs built by concatenation/config objects** that regex tools skip, and finds **secrets in the same pass** (`jsluice urls` / `jsluice secrets`). `--resolve-paths` turns relative paths into full URLs ready to probe; `--patterns` adds custom secret formats. Doesn't fetch — pair with getJS/katana. **The go-to for thorough JS mining.**
- **xnLinkFinder** (xnl-h4ck3r) — **extends LinkFinder's regex** with more patterns and, notably, **extracts parameters, builds target-specific wordlists, and finds secrets**. Accepts URL / file / directory / **Burp XML / ZAP / Caido CSV / HAR** input. A strong, actively-developed regex-based upgrade with broad input support.
- **getJS / subjs** — **gather** JS file URLs from a target (the input step for all the above).
- **katana / gau / waybackurls / gospider** — crawlers to collect URLs (incl. live and historical JS).
- **trufflehog / gitleaks** — dedicated, **verified** secret scanners (trufflehog can *validate* many key types automatically and scan git history) — excellent for the secret-validation step.
- **Newer JS scanners** — GoLinkFinder EVO, keyana, jsfuzzer, mantra, and others (Go rewrites for speed/portability, larger pattern sets).

**How to choose:** for a **quick regex sweep**, LinkFinder/SecretFinder (or xnLinkFinder). For **thorough, low-false-positive** mining including dynamically-built URLs, **jsluice**. For **verified secret hunting**, **trufflehog/gitleaks**. Best practice on a real target: **gather (getJS/katana/gau) → mine with both a regex tool and jsluice → validate secrets with trufflehog → probe endpoints with httpx → test in Burp.**

---

## 14. Where It Fits: Workflow and Chaining

JS mining sits in **recon/discovery**, expanding the attack surface with endpoints and secrets your other recon can't find.

```
[ recon: subdomains → live hosts (httpx) ]
                 │
                 ▼
[ gather JS: getJS / katana / gau / waybackurls  (live + historical) ]
                 │
                 ▼
[ MINE JS: LinkFinder/SecretFinder  (+ jsluice for depth) ]
                 │
     ┌───────────┴───────────────────────────────┐
     ▼                                             ▼
 ENDPOINTS                                      SECRETS
 (/api/..., admin routes, params)               (keys, tokens, JWTs, private keys)
     │                                             │
     ▼                                             ▼
 resolve → httpx (live?) →                    classify → verify (in scope) →
 [ ffuf / Burp / sqlmap / dalfox ]            report critical live keys;
 test the hidden endpoints/params             rotate advice
```

**Relationship to your toolkit:**
- **fed by crawlers/recon** — katana/gau/getJS gather the JS; httpx confirms live JS URLs.
- **expands what feroxbuster/crawlers find** — JS mining adds the *referenced-but-unlinked-and-unguessable* endpoints (§2) that content discovery and crawlers both miss.
- **feeds the testing tools** — discovered endpoints → **httpx** (live?) → **ffuf** (fuzz params) → **Burp** (manual test) → **sqlmap/dalfox** (injection/XSS on the newly-found params). A hidden `/api/internal/search?q=` found in JS is a fresh injection target.
- **secrets → impact** — a validated live key is often a direct critical finding; a leaked JWT/secret may feed **jwt_tool** (§jwt_tool) or authenticate you to hidden APIs.
- **historical pass (gau)** — old JS reveals deprecated-but-live endpoints and stale-but-working secrets.

**The discipline:** *gather all the JS (live + historical) → mine it for endpoints and secrets (regex tool + jsluice) → resolve/probe endpoints and route them to your testing tools → classify and cautiously validate secrets.* On modern SPA targets, this is one of the highest-value recon steps — it uncovers the real API surface everything else misses.

---

## 15. Limitations and Pitfalls

- **Regex misses dynamic URLs** (§11) — concatenated/config-built endpoints slip through; also run **jsluice**.
- **High false-positive rate** — many matched "endpoints"/"secrets" are noise, test values, or public-by-design keys. **Validate everything** (§12); don't report unvalidated finds.
- **You need the JS first** — these tools mine, they don't thoroughly gather; pair with getJS/katana/gau.
- **Third-party/library noise** — jQuery/Bootstrap/analytics bundles flood output; ignore them (`-g`) and focus on first-party app JS.
- **Public keys ≠ vulnerabilities** — a domain-restricted Maps/Firebase key in JS is expected; know which key types are safe client-side before crying "leak."
- **Minification/obfuscation** — heavy obfuscation can defeat regex (and even parsers); beautify helps but some bundles resist clean extraction.
- **Lightly maintained** — LinkFinder/SecretFinder aren't actively developed; patterns lag new key formats. Prefer/augment with actively-maintained tools (jsluice, xnLinkFinder, trufflehog) for current coverage.
- **Validating a secret can cross a line** — *using* a found key to test it may itself be unauthorized/harmful (charges, data access). Verify minimally and in scope (§16).

---

## 16. Legal and Ethical Note

- **Reading a site's JavaScript is low-risk** — the JS is served publicly to every visitor, so *fetching and analyzing* it is generally benign (similar to viewing source). But everything **downstream** (hitting discovered endpoints, using found secrets) is active and authorization-bound.
- **Only test discovered endpoints and use discovered secrets on targets you're authorized to test** — a signed scope/rules of engagement, an in-scope bug-bounty program, or your own app. Finding an endpoint or key in JS does **not** authorize you to *use* it. Hitting a hidden admin API or authenticating with a leaked key **without authorization is unauthorized access** (CFAA and equivalents).
- **Validating secrets carefully** — confirming a key is live can itself be an action against a third-party service (AWS/Stripe/etc.), which may be **outside your engagement scope** and may incur charges or access data. Verify minimally (a safe "whoami"/list call), never exploit, and consider that the safest proof is often *reporting the exposure* without using the key.
- **Leaked secrets are highly sensitive** — a live key can compromise cloud accounts or data. Handle per your rules of engagement, report as critical, advise **rotation**, and don't retain the key beyond the engagement.
- **Historical data (gau/wayback)** — old JS may contain third parties' data or long-lived secrets; stay within your authorized target's scope.
- **Practice legally:** mine the JavaScript of **your own apps**, deliberately-vulnerable targets (**OWASP Juice Shop** is a JS-heavy SPA — great for this), or in-scope bug-bounty programs. Study leaked-secret handling with **trufflehog** against your own repos.

---

### Where to go next

- On a JS-heavy lab (**OWASP Juice Shop**), gather the bundles (`getJS`/browser) and run **SecretFinder -e** and **LinkFinder** — see the API routes and any planted secrets appear, then hit an endpoint you found in Burp. That's the "the JS is the map" realization (§2).
- Run **jsluice** on the *same* bundle and compare — watch it recover concatenated URLs the regex tools missed (§11). Seeing the difference teaches you when to use which.
- Build the pipeline on an authorized target: `katana | grep .js | httpx` → mine with SecretFinder + jsluice → resolve endpoints → **httpx** → **ffuf/Burp/sqlmap/dalfox**. That connects JS mining to the discovery, injection, and proxy tools you've already learned.
- Do a **historical pass** with `gau example.com | grep .js` and mine the old bundles — finding a deprecated-but-live endpoint or a stale secret is a classic bug-bounty win.

*End of reference.*

# Hashcat & Hydra — The Complete Reference (Beginner → Advanced)

> A ground-up reference for the two password-attack workhorses: **Hashcat** (offline hash cracking, GPU-accelerated) and **Hydra** (online login brute-forcing). How cracking actually works, why the offline/online split governs everything, and how these complete the chain that starts with CeWL.

---

## Table of Contents

1. [What These Tools Are and Why](#1-what-these-tools-are-and-why)
2. [Prerequisite: How Password Cracking Actually Works](#2-prerequisite-how-password-cracking-actually-works)
3. [Offline vs Online — The Fundamental Distinction](#3-offline-vs-online--the-fundamental-distinction)

**— HASHCAT (offline) —**
4. [Hashcat: Status and Key Facts](#4-hashcat-status-and-key-facts)
5. [How Hashcat Works](#5-how-hashcat-works)
6. [Hash Modes (-m) and Identifying Hashes](#6-hash-modes--m-and-identifying-hashes)
7. [Fast vs Slow Hashes and Salting (Crucial Concept)](#7-fast-vs-slow-hashes-and-salting-crucial-concept)
8. [Attack Modes (-a) and the Strategy Order](#8-attack-modes--a-and-the-strategy-order)
9. [Rules — Rule-Based Mangling](#9-rules--rule-based-mangling)
10. [Masks and Charsets](#10-masks-and-charsets)
11. [Hashcat Options and Performance](#11-hashcat-options-and-performance)
12. [Hashcat Installation](#12-hashcat-installation)
13. [Hashcat Worked Examples](#13-hashcat-worked-examples)

**— HYDRA (online) —**
14. [Hydra: Status and Key Facts](#14-hydra-status-and-key-facts)
15. [How Hydra Works and the Lockout Reality](#15-how-hydra-works-and-the-lockout-reality)
16. [Hydra Options and Protocols](#16-hydra-options-and-protocols)
17. [HTTP Form Brute-Forcing (The Hard Part)](#17-http-form-brute-forcing-the-hard-part)
18. [Hydra Worked Examples](#18-hydra-worked-examples)

**— SHARED —**
19. [Identifying Hashes and the Full Workflow](#19-identifying-hashes-and-the-full-workflow)
20. [Where These Fit: The Complete Chain](#20-where-these-fit-the-complete-chain)
21. [Defenses (Understanding Both Sides)](#21-defenses-understanding-both-sides)
22. [Limitations and Pitfalls](#22-limitations-and-pitfalls)
23. [Legal and Ethical Note](#23-legal-and-ethical-note)

---

## 1. What These Tools Are and Why

Both tools answer the same question — *"what is the password?"* — but attack it from opposite ends:

- **Hashcat** is the world's fastest **offline hash cracker.** You already have a **hash** (a one-way fingerprint of a password, captured from a database dump, a file, a network capture), and Hashcat finds the plaintext that produces it by making billions of guesses per second on your GPU. No target is contacted — it's pure local computation.

- **Hydra (THC-Hydra)** is a **parallelized online login cracker.** You **don't** have a hash; you have a live login service (SSH, FTP, a web form, RDP, a database) and you try username/password combinations against it directly over the network until one works.

**Why they matter to you:** you learned the theory of targeted wordlists in the CeWL reference — that CeWL supplies target-specific **base words** and mangling **rules** turn them into realistic guesses. Hashcat and Hydra are the tools that *consume* those wordlists and actually recover credentials. They're the payoff:
- **CeWL/SecLists → rules → Hashcat** cracks the hashes you dumped (e.g., via sqlmap).
- **enumerated usernames (WPScan/etc.) + wordlist → Hydra** attacks the live login.

They are the standard, industry-taught tools for the **Credential Access** phase of an assessment (MITRE ATT&CK T1110: Brute Force).

---

## 2. Prerequisite: How Password Cracking Actually Works

You cannot use either tool well without understanding this. It rests on **hashing** (recap from the glossary):

**Hashing is one-way.** A hash function (MD5, SHA-256, bcrypt) turns any input into a fixed-size fingerprint, and **you cannot mathematically reverse it** — given a hash, there's no formula to compute the original password. Applications store password *hashes* (not plaintext) so that a database breach doesn't immediately reveal everyone's password.

**So how do you "crack" a one-way hash?** You **guess and check**:
```
1. Take a candidate password guess:      "Summer2026!"
2. Hash it with the same algorithm:       hash("Summer2026!") → a1b2c3...
3. Compare to the target hash:            a1b2c3... == target?
4. Match → you've found the password. No match → try the next guess.
```
That's the entire concept. Cracking is not "reversing" a hash — it's **hashing millions/billions of guesses and looking for one whose fingerprint matches.** The password itself is never recovered from the hash; it's *rediscovered* by guessing.

**Why GPUs (and why Hashcat):** step 2 — hashing a guess — is a small, independent computation, and you need to do it an astronomical number of times. **GPUs are massively parallel** (thousands of cores), so they can hash tens of thousands of candidates *simultaneously*, where a CPU does a few dozen. On a fast hash like NTLM, a modern GPU tries **billions of guesses per second.** Hashcat is engineered to exploit that parallelism across GPUs (NVIDIA/AMD/Apple) — hence "world's fastest."

**The two things that determine whether you succeed:**
1. **Are your guesses good?** (wordlist + rules quality — this is where CeWL and rules matter.)
2. **How fast can you hash?** (GPU power × how *slow* the target hash algorithm is — §7.)

Everything in Hashcat is about maximizing both: generating smart candidates and hashing them as fast as the algorithm allows.

---

## 3. Offline vs Online — The Fundamental Distinction

This single distinction governs which tool you use and how the whole attack behaves. Internalize it.

| | **Offline (Hashcat)** | **Online (Hydra)** |
|---|---|---|
| **What you have** | A captured **hash** | A live **login service** |
| **Where it happens** | On **your** machine (local compute) | Against the **target** over the network |
| **Speed** | **Billions/sec** (fast hashes) | A **handful/sec** (network + service limits) |
| **Account lockout?** | **No** — the target never knows | **Yes** — real login attempts trigger lockouts |
| **Detectable by target?** | **No** — you never touch them | **Yes** — every attempt is logged |
| **Limited by** | GPU power + hash slowness | Network latency, rate limits, lockout policy |
| **Best strategy** | Huge wordlists + rules + masks | A **few** high-probability passwords across users |

**The practical consequences:**

- **If you have a hash, always crack offline (Hashcat).** It's astronomically faster, has no lockout risk, and is invisible to the target. Getting the hash (dumping a DB with sqlmap, capturing a network handshake, reading a file) is the prize precisely because it lets you crack offline at full speed.

- **Online cracking (Hydra) is a last resort** when you *can't* get a hash and must attack the live service. It's slow and dangerous: after N wrong tries, most services **lock the account** (denying service and alerting defenders). So online attacks favor **password spraying** (a few common passwords across many accounts, staying under lockout thresholds) over brute-forcing one account.

**The mental rule:** *hash in hand → Hashcat (offline, unlimited). Only a login prompt → Hydra (online, careful).* When you dump hashes with sqlmap, you crack them with Hashcat — not Hydra. When all you have is a login page and enumerated usernames, Hydra sprays a short list. This is why "capture the hash" is a central goal — it moves the fight to the offline arena where you have every advantage.

---

## 4. Hashcat: Status and Key Facts

- **Actively maintained**, the industry-standard offline cracker. Current stable is **v7.1.2** (2026); the landmark **v7.0.0** (Aug 2025) was the first major release in 2+ years. By Jens "atom" Steube and the Hashcat team. **MIT-licensed**, open source.
- **v7 changes you must know:**
  - **CPU and GPU engines merged** into a single binary (the old CPU-only build is now `hashcat-legacy`).
  - **`--identify`** — built-in automatic hash-type detection.
  - **Argon2 support** (mode 34000) and many new modes.
  - **The `best64.rule` → `best66.rule` rename.** Old tutorials reference `best64.rule`, which **no longer exists** on a fresh v7 install — a command failing with "missing rule file" is almost always this. Also new `top10_2025.rule`.
  - **Assimilation Bridge** — push work to CPUs/FPGAs/embedded Python alongside GPUs.
- **GPU-accelerated** via CUDA (NVIDIA), OpenCL/HIP (AMD), and Metal (Apple). CPU-only works but is far slower.
- **Supports 400+ hash types** (`-m` modes) and multiple attack modes (`-a`). Pre-installed on **Kali/Parrot**.
- **Rule/wordlist files** ship in `/usr/share/hashcat/rules/` and you supply wordlists (SecLists, rockyou, CeWL output).

---

## 5. How Hashcat Works

Hashcat's job is to feed the GPU a stream of **candidate passwords**, hash each, and compare against your target hash(es). The pieces:

1. **Load the target hash(es)** — a file of one hash per line (optionally `username:hash`), and the **hash mode** (`-m`) telling Hashcat *which algorithm* produced them.
2. **Choose an attack mode** (`-a`) — how candidates are generated (from a wordlist, a mask, combinations — §8).
3. **Generate the keyspace** — the total set of candidates the attack will produce. Hashcat estimates this and shows progress against it.
4. **Hash candidates on the GPU** — massively in parallel, at the algorithm's max rate.
5. **Compare to targets** — a match is a **crack**; the plaintext is written to the **potfile** and shown.
6. **Report** — cracked hashes, speed (hashes/sec), progress, ETA.

**Key concepts:**

- **Keyspace** — the size of the search. A wordlist of 14M words × a 66-rule file ≈ ~950M candidates. A mask `?a?a?a?a?a?a?a?a` (8 of any character) is 95⁸ ≈ 6.6 *quadrillion* — enormous. Keyspace × your hash rate = time. This is why **smart, small keyspaces (wordlist+rules) beat brute force** for most real passwords.
- **Hash rate (candidates/sec)** — depends on GPU power **and** the hash algorithm's speed (§7). Shown live as "Speed."
- **The potfile** (`hashcat.potfile`) — Hashcat records every cracked `hash:plaintext` here, so it **never re-cracks** a known hash and you can retrieve results with `--show`.
- **Sessions & resume** — long jobs can be named (`--session`) and resumed (`--restore`) after interruption — cracking can run for hours/days.

The art of Hashcat is **choosing an attack whose keyspace is large enough to contain the password but small enough to finish in time** — which is why strategy (§8) and good candidates (rules/wordlists) matter more than raw hardware.

---

## 6. Hash Modes (-m) and Identifying Hashes

Hashcat must know **which algorithm** produced your hash — that's the **hash mode** (`-m <number>`). Get it wrong and every guess mismatches. There are 400+ modes; the ones you'll meet most:

| `-m` | Hash type | Where you find it |
|---|---|---|
| `0` | MD5 | Old apps, CTFs (fast, weak). |
| `100` | SHA1 | Legacy apps. |
| `1400` | SHA-256 | Apps rolling their own hashing. |
| `1700` | SHA-512 | Same. |
| `1000` | **NTLM** | Windows account hashes (SAM/NTDS.dit). Very fast to crack. |
| `5600` | **NetNTLMv2** | Captured Windows network auth (Responder). |
| `1800` | sha512crypt | Linux `/etc/shadow` (`$6$`). Slow (good). |
| `500` | md5crypt | Older Linux/`$1$`, Cisco. |
| `3200` | **bcrypt** (`$2*$`) | Modern web apps. **Deliberately slow** (§7). |
| `34000` | Argon2 | Modern best-practice (very slow). |
| `300` | MySQL 4.1+ | MySQL `authentication_string`. |
| `22000` | **WPA-PBKDF2 / PMKID+EAPOL** | Wi-Fi captures. |
| `13100` | **Kerberoast** (TGS-REP) | Active Directory service accounts. |
| `18200` | **AS-REP roast** | AD accounts without pre-auth. |
| `1000`/`22921` | NTLM / SSH private keys | Windows / captured key files. |

**Identifying an unknown hash** (which mode?):
- **`hashcat --identify hashes.txt`** — v7's built-in detector suggests likely modes.
- **`hashid`** or **`hash-identifier`** — standalone tools that guess the type from the hash's format/length.
- **The `$prefix$`** is a strong clue: `$2b$...` = bcrypt, `$6$...` = sha512crypt, `$1$...` = md5crypt, `$krb5tgs$` = Kerberoast, `aad3b435...` = empty LM half (NTLM).

`hashcat --help | grep -i <keyword>` lists modes matching a keyword. **Getting the mode right is step one** — a bcrypt hash run as MD5 (`-m 0`) will simply never crack. When unsure, `--identify` first.

---

## 7. Fast vs Slow Hashes and Salting (Crucial Concept)

This is the concept that separates "cracked in seconds" from "uncrackable in your lifetime," and it's essential for understanding *both* offense and remediation advice.

**Fast vs slow hashes.** Not all hash algorithms cost the same to compute:
- **Fast hashes** (MD5, SHA-1, NTLM, unsalted SHA-256) were designed for *speed* (checksums, integrity). A GPU can compute **billions per second**. So a fast hash of a weak password falls almost instantly. *Fast hash = weak password storage.*
- **Slow / work-factor hashes** (bcrypt, scrypt, Argon2, sha512crypt with many rounds) are **deliberately engineered to be slow** — they include a tunable "cost/rounds" factor that makes each hash take a meaningful fraction of a second. The defender barely notices (one login), but the attacker's rate collapses from *billions/sec* to *thousands/sec* (or fewer). Example: an RTX 4090 does ~**1,700 Argon2 hashes/sec** versus **billions** of NTLM/sec — that's the difference between cracking millions of candidates and barely scratching the surface.

**The takeaway:** the *same password* behind bcrypt vs MD5 is roughly **a billion times** harder to crack. This is why modern apps must use bcrypt/scrypt/Argon2, and why capturing NTLM/MD5 hashes is a jackpot while bcrypt hashes often resist cracking entirely.

**Salting.** A **salt** is random data added to each password before hashing, stored alongside the hash:
- **Same password → different hashes** for different users (because each has a unique salt). This defeats **rainbow tables** (precomputed hash→password lookups) — you can't precompute against an unknown salt.
- **You must attack each salted hash's keyspace effectively per-salt**, so cracking 1,000 uniquely-salted hashes is far more work than 1,000 identical unsalted ones (where cracking one cracks all duplicates).
- Salting does **not** slow a single guess much — its job is preventing precomputation and duplicate-cracking, not adding per-hash cost (that's the work factor's job). Good storage uses **both**: a slow, salted hash (bcrypt/Argon2 salt automatically).

**Why this matters practically:** before you burn hours cracking, look at the hash type. Unsalted MD5/NTLM → throw huge wordlists+rules and masks, expect fast wins. bcrypt/Argon2 → only your *best*, smallest, most-targeted candidates (CeWL + top rules) have a realistic chance; mask/brute-force is usually hopeless. **Match your effort to the algorithm.**

---

## 8. Attack Modes (-a) and the Strategy Order

The **attack mode** (`-a`) decides *how candidates are generated*. There are a few, and using them **in the right order** (cheapest, most-likely first) is the core skill.

| `-a` | Mode | What it does |
|---|---|---|
| `0` | **Straight (dictionary)** | Hash each word from a wordlist, optionally transformed by **rules** (`-r`). The workhorse. |
| `1` | **Combination** | Concatenate every word of list A with every word of list B (`word1word2`). |
| `3` | **Brute-force / Mask** | Generate candidates from a **mask** (character-pattern), e.g., all 8-char passwords of a given structure. |
| `6` | **Hybrid Wordlist + Mask** | Word from a list, then append a mask (`password` + `?d?d?d` → `password123`). |
| `7` | **Hybrid Mask + Wordlist** | A mask prefix, then a word (`?d?d?d` + `password`). |
| `9` | **Association** | Pair each hash with a hint (e.g., the username) — targeted. |

**The strategy — run cheapest/most-likely first:**

1. **`-a 0` dictionary, no rules** — plain wordlist (rockyou, CeWL). Fastest; catches passwords that are exactly a known word. Seconds.
2. **`-a 0` dictionary + rules (`-r`)** — the same wordlist, mangled (capitalize, append year/symbol, leet). **This is where most real passwords fall** — `Summer` + rules → `Summer2026!`. Start here for real work (§9).
3. **`-a 6/7` hybrid** — wordlist + a small mask, for "word + predictable suffix/prefix" patterns rules don't cover.
4. **`-a 3` mask attack** — when you know or suspect the **structure** (e.g., "8 chars: uppercase + 6 lowercase + digit"), brute-force just that structure efficiently (§10).
5. **`-a 3` full brute-force** — pure last resort, only for short/fast-hash cases (the keyspace explodes fast).

**Why the order matters:** each step's keyspace grows enormously. Dictionary+rules is millions of high-probability guesses (finishes fast, high yield); full brute force is quadrillions (infeasible for anything but short passwords/fast hashes). **You escalate only when cheaper attacks fail** — and against a slow hash you often *never* escalate past step 2. Efficient cracking is about spending your limited hash-rate on the guesses most likely to be right.

---

## 9. Rules — Rule-Based Mangling

**Rules are Hashcat's most powerful feature and the direct payoff of the CeWL reference.** A rule is a tiny instruction that **transforms each wordlist word** into a variant, mimicking how humans decorate base words into passwords. With `-a 0 -r <rulefile>`, every word in your list is run through **every rule**, multiplying your candidates into realistic passwords.

**Common rule functions** (one character each, chainable):

| Rule | Effect | `password` → |
|---|---|---|
| `c` | Capitalize first letter | `Password` |
| `u` | Uppercase all | `PASSWORD` |
| `l` | Lowercase all | `password` |
| `$1` | Append `1` | `password1` |
| `$1$2$3` | Append `123` | `password123` |
| `^!` | Prepend `!` | `!password` |
| `sa@` | Substitute `a`→`@` | `p@ssword` |
| `so0 se3` | Leet `o`→`0`, `e`→`3` | `passw0rd` (combined) |
| `r` | Reverse | `drowssap` |
| `d` | Duplicate | `passwordpassword` |
| `$2$0$2$6` | Append `2026` | `password2026` |

Real rules **chain** these (`c $2 $0 $2 $6 $!` → `Password2026!`), and rule *files* contain thousands of such combinations.

**The rule files that ship with Hashcat** (in `/usr/share/hashcat/rules/`), in rough order of size/coverage:
- **`best66.rule`** (v7; was `best64.rule`) — ~66 high-yield mutations. **Always start here** — fast, catches the common patterns.
- **`top10_2025.rule`** — a compact, modern high-yield set.
- **`rockyou-30000.rule`** — 30,000 rules derived from the RockYou breach. A strong second pass.
- **`dive.rule`, `d3ad0ne.rule`** — very large, exhaustive rule sets for deep passes (slow but thorough).
- **`OneRuleToRuleThemAll.rule`** (community) — a popular, effective all-rounder.

**The command (the technique you learned in the CeWL doc):**
```bash
hashcat -m 1000 -a 0 hashes.txt cewl_words.txt -r /usr/share/hashcat/rules/best66.rule
```
This takes your **CeWL target-specific base words** and applies 66 human-style mutations to each — turning `Volganeer` into `Volganeer1`, `Volganeer!`, `Volganeer2026`, `V0lganeer`, etc. **CeWL supplies the target-relevant stems; rules supply the human-predictable decorations** — together they crack organization-specific passwords that generic lists never would. This is *the* reason to prefer wordlist+rules over brute force: it encodes how people actually build passwords.

---

## 10. Masks and Charsets

A **mask** (used with `-a 3`) describes a password's **structure** so you can brute-force *just that structure* instead of blindly trying everything — a targeted, efficient brute force.

**Built-in charset placeholders:**

| Placeholder | Matches |
|---|---|
| `?l` | lowercase `a-z` (26) |
| `?u` | uppercase `A-Z` (26) |
| `?d` | digits `0-9` (10) |
| `?s` | special characters (33) |
| `?a` | all of the above (95) |
| `?b` | all bytes `0x00–0xff` (256) |

**Example masks:**
- `?u?l?l?l?l?l?d?d` = Uppercase + 5 lowercase + 2 digits → matches `Summer26`, `Winter99`. Keyspace = 26 × 26⁵ × 10² ≈ **30 billion** — big but finite; feasible on a fast hash.
- `?d?d?d?d` = a 4-digit PIN → only **10,000** candidates (instant).
- `?a?a?a?a?a?a?a?a` = any 8 chars → 95⁸ ≈ **6.6 quadrillion** — usually infeasible.

**Custom charsets** (`-1`, `-2`, `-3`, `-4`) let you define your own set:
```bash
# -1 = digits+special; mask = 6 lowercase then one char from custom set 1
hashcat -m 0 -a 3 hashes.txt -1 ?d?s ?l?l?l?l?l?l?1
```

**Increment mode** (`-i`, with `--increment-min`/`--increment-max`) tries increasing lengths (e.g., 6-char, then 7, then 8) instead of a fixed length.

**When to use masks:** when you **know or suspect the structure** — a policy forces "1 upper, 1 digit, 8+ chars," or you've seen the pattern in other cracked passwords, or it's a short PIN/known format. Masks turn an impossible full brute-force into a targeted one by **cutting the keyspace to only plausible structures.** For unknown, human-chosen passwords, wordlist+rules (§9) still beats masks — masks shine for structured/generated passwords and known formats.

---

## 11. Hashcat Options and Performance

Beyond `-m` and `-a`, the options you'll use most:

| Option | Purpose |
|---|---|
| `-o <file>` | Write cracked results to a file. |
| `--show` | Show already-cracked hashes (from the potfile) — retrieve results. |
| `--username` | Hashes are `username:hash` — strip/track the username. |
| `--potfile-path <file>` | Use a specific potfile (or `--potfile-disable`). |
| `-w <1-4>` | **Workload profile**: 1 (low) → 4 (nightmare/max). Higher = faster but hogs the GPU (unusable desktop). `-w 3` is a common balance. |
| `-O` | **Optimized kernels** — much faster, but limits max password length (usually fine). |
| `-D <1\|2>` | Device type: 1 = CPU, 2 = GPU. |
| `-d <n>` | Use a specific device (multi-GPU). |
| `--session <name>` | Name the session (for resume). |
| `--restore` | Resume an interrupted session. |
| `-i` / `--increment-min/max` | Increment mask length. |
| `--stdout` | Print candidates **without cracking** — see exactly what your wordlist+rules/mask generates (great for debugging/learning). |
| `--status --status-timer <s>` | Periodic status updates. |
| `--loopback` | Feed cracked passwords back as new dictionary words (finds related passwords). |
| `--identify` | Detect the hash type. |
| `-b` | Benchmark your hardware's speed per hash mode. |

**Performance notes:**
- **The hash algorithm dominates speed**, not just the GPU (§7). Benchmark with `hashcat -b` to see your rate per mode.
- **`-O` (optimized) + `-w 3/4`** for maximum speed on dedicated cracking rigs.
- **`--stdout`** is the best learning tool: `hashcat -a 0 --stdout wordlist.txt -r best66.rule` prints every candidate your attack will try — run it to *see* rules in action before committing GPU time.
- **Watch the potfile:** cracked hashes are cached, so re-running skips them; use `--show` to dump what's cracked so far.

---

## 12. Hashcat Installation

```bash
# Kali / Parrot (pre-installed or apt)
sudo apt install hashcat

# From binaries (newest version) — download from hashcat.net, then:
# unzip hashcat-7.1.2.7z && cd hashcat-7.1.2 && ./hashcat.bin --version

# Verify + benchmark
hashcat --version
hashcat -b                 # benchmark all modes on your hardware
hashcat -I                 # list detected compute devices (GPUs)
```

**GPU drivers matter:** for real speed you need working GPU compute — NVIDIA CUDA drivers, AMD ROCm/OpenCL, or Apple Metal. `hashcat -I` confirms Hashcat sees your GPU; if it only lists the CPU, install/fix your GPU drivers. On a fresh v7 install, remember rule files are `best66.rule` (not `best64.rule`) in `/usr/share/hashcat/rules/`. Grab wordlists (`rockyou.txt`, SecLists) too.

---

## 13. Hashcat Worked Examples

> Output is **representative**.

### 13.1 The default real-world attack: wordlist + rules
```bash
hashcat -m 0 -a 0 -w 3 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best66.rule
```
```
Session..........: hashcat
Status...........: Running
Hash.Mode........: 0 (MD5)
Guess.Base.......: File (rockyou.txt)
Guess.Mod........: Rules (best66.rule)
Speed.#1.........: 12043.8 MH/s (billions of guesses/sec)
Recovered........: 3/5 (60.00%) Digests
...
5f4dcc3b5aa765d61d8327deb882cf99:password
e10adc3949ba59abbe56e057f20f883e:123456
d0763edaa9d9bd2a9516280e9044d885:Monkey123
```
MD5 (fast) + rockyou × 66 rules cracks weak passwords in seconds. Each `hash:plaintext` line is a recovered credential. `Recovered: 3/5` = 3 of 5 hashes cracked.

### 13.2 Windows NTLM hashes (from a dump)
```bash
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
```
NTLM is fast → aggressive rules are cheap. Common after dumping AD/SAM.

### 13.3 Mask attack (known structure)
```bash
# 1 uppercase + 5 lowercase + 2 digits (e.g., Summer26)
hashcat -m 0 -a 3 hashes.txt ?u?l?l?l?l?l?d?d
```

### 13.4 Hybrid (word + digits)
```bash
# every wordlist word followed by 0–999
hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d?d
```

### 13.5 The CeWL chain (target-specific)
```bash
# base words from the target's site + human-style rules
hashcat -m 3200 -a 0 -w 3 dumped_bcrypt.txt cewl_words.txt -r /usr/share/hashcat/rules/best66.rule
```
bcrypt is slow, so a **small, targeted CeWL list + best66** is the realistic approach (a giant list × huge rules would take forever). This is the full CeWL→rules→Hashcat payoff on a strong hash.

### 13.6 Retrieve results
```bash
hashcat -m 0 hashes.txt --show          # show cracked hash:plaintext
hashcat -m 0 hashes.txt --show --username  # with usernames
```

### 13.7 See what your attack generates (learning)
```bash
hashcat -a 0 --stdout cewl_words.txt -r /usr/share/hashcat/rules/best66.rule | head
# prints Volganeer, Volganeer1, Volganeer!, V0lganeer, VOLGANEER, ...
```

---

## 14. Hydra: Status and Key Facts

- **THC-Hydra**, by **van Hauser / THC**. Current stable **v9.6** (Sept 2025). Written in C, **GPLv3**, cross-platform. Pre-installed on **Kali/Parrot**.
- A **parallelized online network login cracker** — it tries username/password combinations against a **live service** across many parallel connections.
- **Supports 50+ protocols/services**, including: **HTTP(S) forms** (`http-post-form`, `http-get-form`), HTTP Basic/Digest (`http-get`), **SSH**, **FTP**, Telnet, **SMB**, **RDP**, **MySQL/PostgreSQL/MSSQL**, **VNC**, **SMTP/POP3/IMAP**, SNMP, LDAP, and more.
- Created as a **proof-of-concept** to show how easily weak logins fall — and remains the go-to online brute-forcer. Alternatives: **Medusa**, **Ncrack**, **patator**.

---

## 15. How Hydra Works and the Lockout Reality

Hydra **actually attempts to log in** to the target service, once per username/password combination, across parallel connections (`-t`), until a login succeeds (or the lists are exhausted).

**Because it's online (§3), everything is different from Hashcat:**

- **Slow.** Each attempt is a real network round-trip against a real service. You get **a handful to a few dozen tries per second**, not billions. A big wordlist is impractical online.
- **Lockouts are real.** Most services lock an account after **N failed attempts** (often 3–10). Blast one account with rockyou and you'll **lock it** after 5 tries — denying service, alerting defenders, and getting nowhere. This is the single biggest online-attack constraint.
- **Logged and detectable.** Every attempt hits the target's logs and can trigger IDS/WAF/rate-limiting and your IP being blocked.
- **The winning strategy is spraying, not brute force.** Try a **few** high-probability passwords (`Password1`, `Summer2026!`, the company name + year, default creds) across **many** enumerated usernames, staying under the lockout threshold — rather than hammering one account. Use `-t` low, add `-W`/`-w` waits, and know the lockout policy.

**The mental model:** Hydra is a **precision instrument for a small number of high-probability guesses against a live service you can't get a hash from.** If you can obtain a hash instead (dump it, capture it), switch to Hashcat immediately — offline is faster, safer, and lockout-free. Reach for Hydra only when the login prompt is all you have.

---

## 16. Hydra Options and Protocols

**Basic syntax:**
```
hydra [options] target service [module-options]
```

**Core options:**

| Option | Purpose |
|---|---|
| `-l <user>` | A single **login** name. |
| `-L <file>` | A **list** of usernames (from enumeration — WPScan, CeWL metadata). |
| `-p <pass>` | A single **password**. |
| `-P <file>` | A **list** of passwords (wordlist). |
| `-C <file>` | A **combo** file of `user:pass` per line (credential stuffing). |
| `-e nsr` | Also try: **n** = null/empty password, **s** = password same as login, **r** = reversed login. |
| `-u` | Loop **users** outer, passwords inner (spread attempts across users — gentler on lockout). |
| `-t <n>` | Parallel **tasks** (connections). Lower (`-t 4`) = gentler/stealthier; too high triggers lockouts/blocks. |
| `-f` | **Stop** on the first valid pair found (per host). |
| `-s <port>` | Custom port. `-S` = use SSL. |
| `-w <sec>` / `-W <sec>` | Wait times (throttle). |
| `-o <file>` | Write found credentials to a file. |
| `-V` / `-vV` | Verbose — show each attempt. |
| `-M <file>` | A list of **targets**. |

**Service module examples:** `ssh`, `ftp`, `rdp`, `smb`, `mysql`, `vnc`, `smtp`, `http-get` (Basic auth), `http-post-form` / `http-get-form` (web login forms — §17).

**Simple form:**
```bash
hydra -l admin -P passwords.txt ssh://192.168.1.10 -t 4 -f
```
"Try user `admin` with each password against SSH on that host, 4 parallel tasks, stop on success."

---

## 17. HTTP Form Brute-Forcing (The Hard Part)

Attacking a **web login form** is where people struggle with Hydra, because you must tell Hydra exactly how the form works. Use the **`http-post-form`** module (or `http-get-form`). The syntax packs three colon-separated fields into one string:

```
"<path>:<POST-body-with-placeholders>:<failure-or-success-condition>"
```

1. **`<path>`** — the form's submit URL, e.g., `/login.php`.
2. **`<POST body>`** — the exact parameters the form submits, with **`^USER^`** and **`^PASS^`** as placeholders where Hydra injects each guess: `username=^USER^&password=^PASS^`.
3. **`<condition>`** — how Hydra knows a login **failed** (or succeeded):
   - **`F=<string>`** — a string present on **failure** (e.g., `F=Invalid credentials`). Hydra treats a response *containing* it as a failed login.
   - **`S=<string>`** — a string present only on **success** (e.g., `S=Dashboard` or `S=302`). Use when there's a reliable success marker.

**Full example:**
```bash
hydra -L users.txt -P passwords.txt 192.168.1.10 \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid credentials" \
  -t 8 -f -V
```
This POSTs to `/login.php`, substituting each user/password, and marks any response containing "Invalid credentials" as a failure — so anything *without* it is a candidate success.

**Getting the three fields right (the key skill):**
- **Capture the real request in Burp** first — submit the login once, look at the POST in Burp's HTTP history, and copy the **exact path and body parameter names** (they're often not just `username`/`password` — could be `user`, `pass`, `email`, plus hidden fields).
- **Include hidden/extra fields** the form sends (e.g., `&login=Login`), or the server may reject the request.
- **Find a reliable failure/success string** by observing a wrong-password response (for `F=`) vs a correct one (for `S=`). A `302` redirect on success is a common `S=` marker.
- **Anti-CSRF tokens break simple Hydra** — if the form requires a fresh per-request token, plain Hydra fails (it can't fetch a new token each time). That's a case for Burp Intruder or ffuf with token handling, or a custom script.

**Add cookies/headers** with extra `:H=` segments if needed (e.g., a session cookie): `...:F=Invalid:H=Cookie: sess=abc`.

**Why this is fiddly:** you're hand-describing an HTTP request Hydra will replay thousands of times. One wrong field name or condition and every attempt "fails" (or every attempt looks like success). **Always build it from a real captured request in Burp**, test with `-V` (verbose) to watch attempts, and confirm the condition string behaves before a full run.

---

## 18. Hydra Worked Examples

> Output is **representative**. All examples assume **authorized** targets.

### 18.1 SSH, single user
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.5 -t 4 -f
```
```
[22][ssh] host: 10.0.0.5   login: root   password: toor
[STATUS] attack finished for 10.0.0.5 (valid pair found)
```
The `[22][ssh] ... login: root password: toor` line = a **valid credential pair found**. `-t 4` keeps it gentle; `-f` stops on success.

### 18.2 FTP with user + password lists (spraying)
```bash
hydra -L users.txt -P top-passwords.txt ftp://10.0.0.5 -u -t 4
```
`-u` loops users on the outer loop (spreads guesses across accounts — gentler on per-account lockout).

### 18.3 Web login form (the §17 pattern)
```bash
hydra -L users.txt -P passwords.txt target.com \
  http-post-form "/login:user=^USER^&pass=^PASS^:F=Login failed" -t 8 -f
```

### 18.4 HTTP Basic auth
```bash
hydra -l admin -P passwords.txt target.com http-get /admin/
```

### 18.5 The full credential-attack chain (ties your tools together)
```bash
# 1) enumerate usernames (e.g., WPScan / CeWL metadata / emails)
#    → users.txt
# 2) build a target-specific wordlist with CeWL
cewl -d 2 -m 5 -w cewl_words.txt https://target.com
# 3) spray, carefully, a few high-probability passwords across users
hydra -L users.txt -P cewl_words.txt target.com \
  http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect" -t 4 -W 2
```
This connects **user enumeration → CeWL wordlist → Hydra online spray** — the online counterpart to the offline CeWL→Hashcat chain. Note `-t 4 -W 2` (low concurrency, waits) to respect lockout/rate limits.

---

## 19. Identifying Hashes and the Full Workflow

The end-to-end credential-attack workflow, tying capture → crack:

```
1. OBTAIN the credential material
   ├─ a HASH  → sqlmap --passwords, /etc/shadow, SAM/NTDS.dit, a captured WPA/Kerberos hash, a leaked DB
   └─ only a LOGIN prompt → (no hash available)

2a. If you have a HASH → OFFLINE (Hashcat)
    ├─ identify:  hashcat --identify hashes.txt   (or hashid)
    ├─ pick -m (mode) from the type
    ├─ attack order:  wordlist → wordlist+rules → hybrid → mask → brute
    │                 (CeWL words + best66.rule first for targeted work)
    ├─ mind fast vs slow hash (§7): bcrypt/Argon2 → only best small targeted attacks
    └─ retrieve:  hashcat -m <mode> hashes.txt --show

2b. If you have only a LOGIN → ONLINE (Hydra)
    ├─ enumerate usernames first (WPScan, CeWL metadata, OSINT)
    ├─ SPRAY a few high-probability passwords across many users
    ├─ low -t, waits, know the lockout policy
    └─ build http-post-form from a REAL Burp-captured request
```

**The identification step is critical for Hashcat:** wrong `-m` = never cracks. Use `--identify`/`hashid`, and read the `$prefix$` (§6). **The obtain step decides the branch:** whenever you *can* get a hash, do — offline cracking (2a) beats online (2b) in every dimension (speed, stealth, no lockout).

---

## 20. Where These Fit: The Complete Chain

These tools are the **Credential Access** payoff of everything you've learned:

```
[ recon: nmap → find login services (SSH/RDP/DB) + web logins ]
[ enum: WPScan/OSINT → usernames ] [ CeWL → target wordlist ] [ SecLists → generic wordlists ]
                 │
       ┌─────────┴───────────────────────────────────┐
       ▼                                               ▼
 GOT A HASH?                                    ONLY A LOGIN PROMPT?
 (sqlmap --passwords,                           (web form, SSH, RDP…)
  DB dump, captured handshake)                          │
       │                                                ▼
       ▼                                        [ HYDRA ] online spray
 [ HASHCAT ] offline crack                       (few passwords ×
  wordlist + best66.rule                          many users, careful)
  (CeWL stems + human rules)                             │
       │                                                 ▼
       └───────────────► cracked credentials ◄───────────┘
                              │
                              ▼
              [ log in → access → privilege escalation → pivot ]
```

**Relationship to your toolkit:**
- **nmap** finds the login services (SSH/RDP/DB/web) to attack (Hydra) and the hosts to breach for hashes.
- **sqlmap** dumps password **hashes** (`--passwords`) → feed straight to **Hashcat** (offline).
- **WPScan / OSINT** enumerate **usernames** → feed to **Hydra** (online) or as the username side of cracking.
- **CeWL** builds the **target-specific wordlist** → the base for **both** Hashcat (with rules) and Hydra.
- **Burp** captures the exact login request you translate into a Hydra `http-post-form`.

**The discipline:** *get the credential material → if it's a hash, crack offline with Hashcat (wordlist+rules first); if it's a live login, spray carefully with Hydra → use recovered creds to gain and escalate access.* Hashcat and Hydra are where enumeration and wordlists turn into actual access.

---

## 21. Defenses (Understanding Both Sides)

Knowing what *stops* these attacks makes you a better tester (and lets you give real remediation advice):

**Against offline cracking (Hashcat):**
- **Use slow, salted, work-factor hashes** — bcrypt, scrypt, **Argon2** — not MD5/SHA/NTLM. This is the single biggest defense: it collapses the attacker's guess rate from billions/sec to thousands (§7).
- **Salt every hash** (automatic with bcrypt/Argon2) — defeats rainbow tables and duplicate-cracking.
- **Enforce strong, long, unique passwords** — length beats complexity against masks/brute force; a passphrase blows past feasible keyspace.
- **Protect the hashes** — most offline cracking presupposes a breach that leaked them;防 that breach (patching, least privilege) removes the fuel.

**Against online attacks (Hydra):**
- **Account lockout / progressive delays** after failed attempts — the core online defense.
- **Rate limiting and IP throttling / CAPTCHA** — slow automated attempts to a crawl.
- **MFA** — even a correct password isn't enough → guessing alone fails.
- **Monitoring/alerting** on failed-login spikes (spraying shows up as many users, few attempts each).
- **No default/weak credentials**, and **anti-CSRF tokens** (which also happen to break naive Hydra form attacks).

**The universal defense:** **MFA + slow hashing + strong unique passwords + monitoring.** When you report a cracked password, pair it with these remediations — that's the value of understanding the defense.

---

## 22. Limitations and Pitfalls

**Hashcat:**
- **Wrong `-m` = never cracks.** Identify the hash type first (`--identify`).
- **Slow hashes resist cracking.** Against bcrypt/Argon2, giant wordlists and brute force are usually hopeless — only small, targeted, high-probability attacks have a chance. Match effort to the algorithm.
- **`best64.rule` doesn't exist on v7** — it's `best66.rule`. A "missing rule file" error is usually this.
- **GPU drivers required for speed.** `hashcat -I` must show your GPU, or you're crawling on CPU.
- **Keyspace explosions.** Full brute force (`?a?a?a...`) is infeasible past short lengths — use wordlist+rules/masks instead.
- **You must already have the hash.** Hashcat doesn't obtain hashes; that's a separate step (dump/capture).

**Hydra:**
- **Slow and lockout-prone.** Online = a few tries/sec and real account lockouts. Spray, don't brute-force; know the policy.
- **Loud and detectable.** Every attempt is logged; expect IDS/WAF/IP blocks.
- **HTTP forms are fiddly.** Wrong path/field/condition = all attempts "fail." Build from a real Burp capture; test with `-V`.
- **Anti-CSRF tokens / dynamic forms break it.** Use Burp Intruder/ffuf/custom scripts for token-protected logins.
- **MFA defeats it entirely** — a correct password alone won't log in.

---

## 23. Legal and Ethical Note

Password cracking is among the most **legally and ethically sensitive** activities in security — you're recovering credentials that grant access to accounts and data.

- **Only crack/attack credentials you own or are explicitly authorized to test** — a signed scope/rules of engagement, an in-scope bug-bounty target that permits credential attacks (**many forbid online brute-forcing outright**), or your own lab/hashes. Cracking or brute-forcing others' credentials without authorization is a serious crime (CFAA and equivalents), regardless of intent.
- **Offline cracking presupposes lawfully-obtained hashes.** Having a hash you weren't authorized to obtain is itself a problem — the authorization must cover how you got it.
- **Online attacks can lock accounts and disrupt real users** — a denial-of-service in its own right. Get explicit permission, know the lockout policy, throttle, and prefer a few sprayed passwords over brute force.
- **Recovered credentials and cracked passwords are highly sensitive data** — handle per your engagement rules and privacy law; use only within scope; don't retain beyond the engagement.
- **Report responsibly** — pair cracked-password findings with remediation (§21: MFA, slow hashing, strong passwords).
- **Practice legally:** crack **hashes you generate yourself** (`echo -n 'password' | md5sum`), lab hashes from intentionally vulnerable VMs (**Metasploitable**, **HTB/THM**), or public cracking challenges/CTFs. For Hydra, practice only against **your own lab services** (a local DVWA, a VM you control).

---

### Where to go next

- **Make your own hashes and crack them** to internalize the loop: `echo -n 'Summer2026!' | md5sum` → put it in `hash.txt` → `hashcat -m 0 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best66.rule`. Watching a CeWL-style stem + a rule crack it is the "aha" (§9).
- **Run `--stdout`** on your CeWL wordlist + a rule file to *see* the candidates before cracking — it makes rules concrete.
- **Do the full chain in a lab:** `sqlmap --passwords` to dump hashes → identify → Hashcat to crack; separately, enumerate a DVWA login's real request in **Burp** → translate to a Hydra `http-post-form` → spray. That connects nmap, sqlmap, WPScan, CeWL, Burp, Hashcat, and Hydra into one credential-access workflow.
- Compare the *same* weak password behind **MD5 vs bcrypt** in Hashcat (`-m 0` vs `-m 3200`) and watch the speed collapse — the fast-vs-slow-hash lesson (§7) in your own terminal.

*End of reference.*

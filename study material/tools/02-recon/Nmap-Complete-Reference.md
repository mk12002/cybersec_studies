# Nmap — The Complete Reference (Beginner → Advanced)

> A ground-up reference for **Nmap** (Network Mapper): how it discovers hosts and open services, exactly **how** each scan type infers a port's state, service/OS detection, the scripting engine (NSE), evasion, and how it feeds every other tool you use.

---

## Table of Contents

1. [What Nmap Is and Why It Exists](#1-what-nmap-is-and-why-it-exists)
2. [Status and Key Facts](#2-status-and-key-facts)
3. [Prerequisite: Ports, TCP/UDP, and the 3-Way Handshake](#3-prerequisite-ports-tcpudp-and-the-3-way-handshake)
4. [Port States (The Core Concept)](#4-port-states-the-core-concept)
5. [How Nmap Works: The Scan Phases](#5-how-nmap-works-the-scan-phases)
6. [Host Discovery (Ping Scanning)](#6-host-discovery-ping-scanning)
7. [Port Scanning Techniques](#7-port-scanning-techniques)
8. [Port Specification](#8-port-specification)
9. [Service and Version Detection](#9-service-and-version-detection)
10. [OS Detection](#10-os-detection)
11. [The Nmap Scripting Engine (NSE)](#11-the-nmap-scripting-engine-nse)
12. [Timing and Performance](#12-timing-and-performance)
13. [Firewall / IDS Evasion](#13-firewall--ids-evasion)
14. [Output Formats](#14-output-formats)
15. [Target Specification](#15-target-specification)
16. [Installation](#16-installation)
17. [Command-Line Options (Full Breakdown)](#17-command-line-options-full-breakdown)
18. [Worked Examples with Output, Explained](#18-worked-examples-with-output-explained)
19. [Reading the Output](#19-reading-the-output)
20. [Companion Tools](#20-companion-tools)
21. [Where It Fits: Workflow and Chaining](#21-where-it-fits-workflow-and-chaining)
22. [Limitations and Pitfalls](#22-limitations-and-pitfalls)
23. [Legal and Ethical Note](#23-legal-and-ethical-note)

---

## 1. What Nmap Is and Why It Exists

**Nmap (Network Mapper)** is the world's most widely-used **network discovery and security scanning** tool. You give it one or more targets (IPs, ranges, hostnames), and it answers the fundamental questions of any assessment: **Which hosts are alive? Which ports are open? What services and versions are running on them? What operating system? And — via its scripting engine — are any of them vulnerable?**

Created by **Gordon Lyon (Fyodor)** in 1997, it's free, open-source, and cross-platform. It works by **crafting and sending network packets** to targets and analyzing the responses (or lack of them) to infer the state of each host and port.

**Why it exists / the problem it solves — and why it matters for *you* specifically:** every web tool you've studied so far *assumes you already found a live web server on a port*. Burp assumes you have a URL; feroxbuster assumes a running HTTP service; sqlmap assumes an endpoint. **Nmap is how you find those in the first place.** Before you can test a web app, you must know: is this host up? Is port 80/443 open? Is there *also* an admin panel on 8080, a database on 3306, an old service on 8443 nobody remembers? Nmap maps the network's **attack surface at the host/service layer** — the layer beneath everything else. Skipping it means testing only the surface you stumbled onto, not the surface that exists.

**The mental model:** Nmap turns "here's an IP range I'm authorized to test" into "here are the live hosts, their open ports, the exact software on each, and initial vulnerability leads." It's the reconnaissance backbone of virtually every network and web engagement.

---

## 2. Status and Key Facts

- **Actively maintained**, nearly 30 years old. Current stable is the **7.9x line** — **7.99** (March 2026), patched to **7.991** (2026); check `nmap --version`. By Gordon Lyon (Fyodor) and the Nmap Project.
- **Language:** C/C++ core with **Lua** for the scripting engine (NSE) and some Python tooling. Pre-installed on **Kali/Parrot**; available for Linux, macOS, Windows.
- **License:** the Nmap Public Source License (a modified/GPL-derived license). Open source.
- **On Windows** it needs **Npcap** (the raw-packet driver, bundled with the installer) for raw-socket scan types.
- **Scale:** ~600+ **NSE scripts**, ~5,000 **OS fingerprints**, thousands of **service/version signatures** — continuously grown by community fingerprint submissions.
- **Companion tools** (installed alongside): **Zenmap** (GUI), **Ncat** (a modern netcat), **Nping** (packet crafting/analysis), **Ndiff** (compare two scans).
- **Raw sockets need root/admin.** Many powerful scan types (SYN scan, OS detection) require elevated privileges; without them Nmap falls back to less stealthy methods (e.g., TCP connect scan).

---

## 3. Prerequisite: Ports, TCP/UDP, and the 3-Way Handshake

You cannot understand *any* Nmap scan type without this. It's short — learn it.

**Port** — a numbered channel (0–65535) on a host that identifies a specific network service. A running service "listens" on a port. Well-known ports: **80** (HTTP), **443** (HTTPS), **22** (SSH), **21** (FTP), **25** (SMTP), **53** (DNS), **3306** (MySQL), **3389** (RDP), **445** (SMB). A **service = IP address + port + protocol**. Finding open ports = finding the services you can attack.

**TCP vs UDP** — the two main transport protocols:
- **TCP (Transmission Control Protocol)** — **connection-oriented and reliable.** It establishes a connection (handshake) before data flows, guarantees ordered delivery, and confirms receipt. Most services you'll test (web, SSH, databases) use TCP. Its handshake is what most scans exploit.
- **UDP (User Datagram Protocol)** — **connectionless and fire-and-forget.** No handshake, no guaranteed delivery. Used by DNS, DHCP, SNMP, some VoIP. This lack of handshake makes UDP scanning slow and ambiguous (§7).

**The TCP 3-way handshake** — how every normal TCP connection begins:
```
Client                          Server
  │ ───────── SYN ──────────────▶│   "I want to connect" (synchronize)
  │ ◀──────── SYN-ACK ───────────│   "OK, I'm ready" (synchronize-acknowledge)
  │ ───────── ACK ──────────────▶│   "Great, connected" (acknowledge)
  │                              │   ← connection established, data flows
```
Three packets: **SYN → SYN-ACK → ACK**. This tiny dance is the key to port scanning:
- If a port is **open**, the server answers a SYN with a **SYN-ACK** ("I'm listening").
- If a port is **closed**, the server answers a SYN with a **RST** (reset — "nothing here").
- If a **firewall** silently drops the packet, you get **no answer at all**.

Nmap sends carefully-chosen packets and reads these responses (SYN-ACK / RST / silence) to deduce each port's state — which is the whole game (§4, §7).

---

## 4. Port States (The Core Concept)

Nmap doesn't just report "open" or "closed." It reports **six possible states**, and understanding them is *the* foundational Nmap skill — every scan type is a different way of determining which state a port is in.

| State | Meaning |
|---|---|
| **open** | An application is **actively listening** and accepting connections on this port. This is what you hunt for — every open port is a potential entry point/service to test. |
| **closed** | The port is **reachable** (the host responded), but **no application is listening**. Useful: tells you the host is up and not firewalling this port. |
| **filtered** | Nmap **can't determine** if the port is open because a **firewall/filter is blocking** the probe (no response, or an ICMP error). The packet never got a clear answer. |
| **unfiltered** | The port is **reachable but Nmap can't tell open vs closed** (seen mainly with ACK scans, which map firewalls rather than services). |
| **open\|filtered** | Nmap **can't decide between open and filtered** — no response came back, which could mean "listening but silent" or "blocked." Common in UDP and stealth (FIN/Null/Xmas) scans. |
| **closed\|filtered** | Nmap can't decide between closed and filtered (rare; seen in idle scan). |

**Why the distinctions matter:**
- **open** = a live service → your target.
- **closed** = host is up, port has no service (but the host is reachable — good to know).
- **filtered** = something is *deliberately blocking* you — a firewall. The *pattern* of filtered ports maps the firewall's rules and tells you what the defenders are protecting.
- The **combined states** (`open|filtered`, etc.) reflect **honest uncertainty** — Nmap tells you when it genuinely can't be sure, rather than guessing. That's a feature: you know where you need a different scan technique to resolve the ambiguity.

**The key insight:** a port's state is *inferred from how (or whether) it responds* to Nmap's probe. `SYN-ACK` → open. `RST` → closed. Silence → filtered (or open|filtered, depending on scan type). Every scan type in §7 is just a different probe designed to tease these states apart under different network/firewall conditions.

---

## 5. How Nmap Works: The Scan Phases

A full Nmap scan runs through phases, in order. Knowing them clarifies what every option affects.

1. **Target enumeration** — expand what you gave it (hostname → IPs, CIDR → list of addresses, `-iL` file).
2. **Host discovery ("ping scan")** — determine which targets are **alive**, so it doesn't waste time port-scanning dead hosts (§6). Skip with `-Pn`.
3. **Reverse-DNS resolution** — look up hostnames for live IPs (skip with `-n`).
4. **Port scanning** — the core: determine the **state** of ports on each live host, using the chosen scan technique (§7).
5. **Service/version detection** — if `-sV`, probe open ports to identify the **service and version** (§9).
6. **OS detection** — if `-O`, fingerprint the **operating system** (§10).
7. **NSE scripts** — if `-sC`/`--script`, run **Lua scripts** for deeper detection, vuln checks, brute-forcing, etc. (§11).
8. **Output** — print/write results in the chosen format(s) (§14).

Each phase is optional/tunable. A bare `nmap <target>` does host discovery + a default TCP port scan of the top 1000 ports. Adding flags switches on the deeper phases (version, OS, scripts). `-A` turns on the aggressive bundle (version + OS + default scripts + traceroute) at once.

---

## 6. Host Discovery (Ping Scanning)

Before scanning ports, Nmap checks **which hosts are up** — pointless to port-scan 254 addresses when only 12 are live. This phase is called "ping scanning" (though it uses far more than ICMP ping).

**Key options:**
- **`-sn`** — **host discovery only, no port scan.** The classic "who's alive on this network?" sweep. `nmap -sn 192.168.1.0/24` lists live hosts fast.
- **`-Pn`** — **skip host discovery; treat all targets as up** and go straight to port scanning. Essential when hosts **block ping** (many firewalls drop ICMP), which would otherwise make Nmap wrongly conclude "host down" and skip it. **If a scan says "host seems down" but you know it's there, add `-Pn`.**
- **`-PS<ports>`** — **TCP SYN ping**: send a SYN to given ports (default 80); a SYN-ACK or RST means the host is up. Works through firewalls that block ICMP but allow TCP.
- **`-PA<ports>`** — **TCP ACK ping**: send an ACK; a RST back means the host is up. Gets past some stateless firewalls.
- **`-PU<ports>`** — **UDP ping**.
- **`-PE` / `-PP` / `-PM`** — ICMP **echo** / **timestamp** / **netmask** requests.
- **ARP scan (automatic on local networks)** — on your own LAN, Nmap uses **ARP requests**, which is faster and 100% reliable for discovery (no host can hide from ARP on the same subnet). `-PR` forces it; `--send-ip` disables it.
- **`-n`** — skip reverse-DNS (faster). **`-R`** — always resolve. **`--dns-servers`** — specify resolvers.

**The concept:** host discovery is itself a mini port-scan-like inference — send *something* (ICMP, TCP SYN/ACK, UDP, ARP) and see if *anything* comes back. Because different networks block different probe types, Nmap sends **several kinds** by default to maximize the chance of a reply. When discovery fails but you're sure the host exists, `-Pn` forces the scan.

---

## 7. Port Scanning Techniques

This is the heart of Nmap. Each technique sends a different probe to infer port state, with different tradeoffs in **speed, stealth, privilege needs, and firewall behavior.** Understanding *how each infers state* is the core knowledge.

### -sS — SYN scan ("half-open" / stealth) — the default with root
Sends a **SYN**, then interprets the reply:
- **SYN-ACK** → port **open** (something's listening). Nmap then sends a **RST** to tear down the half-formed connection *without completing the handshake* — hence "half-open."
- **RST** → port **closed**.
- **No response** (after retries) → **filtered**.
Because it never completes the handshake, it's **fast** and historically **stealthier** (some old systems didn't log incomplete connections). **Requires root** (raw sockets). This is Nmap's **default and recommended** scan when privileged.

### -sT — TCP connect scan
Completes the **full 3-way handshake** using the OS's `connect()` call (no raw sockets needed → **works without root**). More reliable in that sense, but **slower** and **noisier**: the full connection is typically **logged** by the target application. Nmap's default **when run unprivileged**.

### -sU — UDP scan
Scans **UDP** ports. Hard and slow because UDP has no handshake:
- A **UDP response** → port **open**.
- An **ICMP "port unreachable" (type 3, code 3)** → port **closed**.
- **No response** → **open|filtered** (can't tell — the service may just be silent, or a firewall dropped it).
UDP scanning is **essential but often skipped** — DNS (53), SNMP (161), DHCP, and other UDP services are real attack surface. It's slow (rate-limited ICMP errors), so scope the ports (`-sU -p 53,161,500`) rather than scanning all 65535 UDP ports.

### -sA — ACK scan (firewall mapping)
Sends an **ACK**. It **does not determine open/closed** — instead it maps **firewall rules**: a **RST** back → **unfiltered** (the packet got through), **no response/ICMP error** → **filtered** (a firewall blocked it). Use it to discover *which ports a firewall is filtering* and whether the firewall is **stateful** or **stateless**.

### -sF / -sX / -sN — FIN, Xmas, Null scans (stealth)
These exploit **RFC 793** TCP behavior: a compliant system sends **RST** for any non-SYN packet to a **closed** port, but sends **nothing** for an **open** port. So:
- **No response** → **open|filtered**.
- **RST** → **closed**.
The three differ only in which flags they set: **FIN** (`-sF`) sets FIN, **Null** (`-sN`) sets no flags, **Xmas** (`-sX`) sets FIN+PSH+URG (lit up "like a Christmas tree"). They can **slip past simple stateless firewalls/ACLs** that only block SYN packets, and generate no full connection. **Caveat:** they don't work against systems that don't follow RFC 793 strictly (notably **Windows**, which sends RST for open ports too) — so results vary by target OS.

### -sW / -sM — Window and Maimon scans
Niche variants. **Window scan** (`-sW`) is like ACK scan but examines the **TCP window field** in RST responses to sometimes distinguish open from closed. **Maimon scan** (`-sM`) sends FIN/ACK — works against some BSD-derived systems.

### -sI — Idle scan ("zombie" scan) — the stealthiest
The most advanced evasion technique. It scans a target **without ever sending a packet from your own IP**, by bouncing off a **"zombie" host** with predictable **IP ID** sequence numbers. Nmap infers the target's port states by watching how the zombie's IP ID increments. Result: the target logs the **zombie's** IP as the scanner, not yours — **total source anonymity** (and it can exploit trust relationships between the zombie and target). Slow and finicky, but conceptually brilliant.

### -sO — IP protocol scan
Not a port scan — determines which **IP protocols** (TCP, UDP, ICMP, IGMP, etc.) a host supports.

### -sY / -sZ — SCTP scans
SCTP INIT (`-sY`) and COOKIE-ECHO (`-sZ`) scans, for the less-common SCTP protocol (telecom systems).

**Choosing:** default to **`-sS`** (root) or **`-sT`** (unprivileged) for TCP; add **`-sU`** for key UDP ports; reach for stealth scans (**FIN/Xmas/Null/idle**) when evading firewalls in an authorized test; use **`-sA`** to understand a firewall. The unifying idea across all of them: **craft a probe whose response (or silence) distinguishes the port states you care about**, chosen to work under the target's specific firewall/OS conditions.

---

## 8. Port Specification

By default Nmap scans the **top 1000 most common ports** (not all 65535). Control which ports with:

| Option | Scans |
|---|---|
| `-p 80` | A single port. |
| `-p 80,443,8080` | A specific list. |
| `-p 1-1000` | A range. |
| `-p-` | **All 65535 ports** (thorough but slow — often essential; services hide on high ports). |
| `-p U:53,161,T:80,443` | Mixed UDP (`U:`) and TCP (`T:`) ports (with `-sU -sS`). |
| `-F` | **Fast scan** — top **100** ports only (quick first look). |
| `--top-ports 20` | The N most common ports (by frequency in Nmap's data). |
| `-p http,https` | By service name (Nmap maps names to ports). |
| `-r` | Scan ports **sequentially** (default randomizes order). |

**A key habit:** the default top-1000 is a fast first pass, but **real services hide on uncommon ports** (an admin panel on 8443, a dev server on 3000, a database on 5984). For thoroughness, run a **full port scan (`-p-`)** at least once per target — it's the difference between finding the obvious web server and finding the forgotten service that gets you in. A common two-step workflow: fast top-ports scan first (quick map), then `-p-` in the background for completeness.

---

## 9. Service and Version Detection

Knowing a port is **open** isn't enough — you need to know **what's running on it and which version**, because that's what maps to known vulnerabilities and tells you how to attack it.

**`-sV`** enables **version detection.** After finding open ports, Nmap sends a series of **probes** and compares the responses against its **`nmap-service-probes`** database of thousands of signatures. It identifies:
- The **service** (is 8080 really HTTP? or something else?).
- The **product and version** (`Apache httpd 2.4.29`, `OpenSSH 8.2p1`, `MySQL 5.7.33`).
- Sometimes the **OS hint**, hostname, device type, and extra info.

**How it works (the concept):** Nmap first tries a light touch — reading any **banner** the service volunteers on connect (many services announce themselves). If that's inconclusive, it sends increasingly specific **protocol probes** and matches the responses against known signatures. It's essentially **fingerprinting by behavior**: how a service replies to particular inputs reveals exactly what it is.

**Tuning:**
- **`--version-intensity <0-9>`** — how many probes to try (higher = more accurate but slower/noisier; default 7).
- **`--version-light`** (intensity 2, fast) / **`--version-all`** (intensity 9, exhaustive).
- **`-sV --version-trace`** — see the probes as they're sent (debugging).

Version detection is often the **single most valuable phase** for a pentester: `OpenSSH 7.2` or `Apache 2.4.49` immediately tells you which CVEs to check. It's the bridge from "a port is open" to "here's the specific software to research." Feed these versions to searchsploit/Nuclei to find known exploits.

---

## 10. OS Detection

**`-O`** enables **operating system detection** via **TCP/IP stack fingerprinting.** Different operating systems implement the TCP/IP stack with subtle, characteristic differences — initial TTL values, TCP window sizes, TCP options and their ordering, how they generate sequence numbers, responses to unusual packets. Nmap sends a battery of specially-crafted probes, measures these characteristics, and matches the resulting **fingerprint** against its database of ~5,000 OS signatures.

**Output** includes the OS family/version guess(es) with confidence, device type (general purpose, router, printer, webcam, PLC…), and often uptime and network-distance estimates.

**Options:**
- **`--osscan-guess`** / **`--osscan-limit`** — guess aggressively when unsure / only fingerprint promising hosts.
- OS detection needs at least **one open and one closed port** to work well, and **root** privileges.

**Why it matters:** the OS shapes your whole approach — Windows vs Linux vs an embedded device dictates which exploits, which services (SMB on Windows), and which techniques apply. Combined with version detection, you get a full picture: "Ubuntu Linux running Apache 2.4.29 and OpenSSH 7.6 with MySQL exposed." **Caveat:** fingerprinting is a guess — firewalls, NAT, and load balancers can distort it, so treat OS results as strong hints, not certainties.

---

## 11. The Nmap Scripting Engine (NSE)

**NSE is what elevates Nmap from a port scanner to a broad vulnerability-detection and reconnaissance framework.** It runs **Lua scripts** that can do far more than the core: detailed service enumeration, vulnerability checks, brute-forcing, even basic exploitation. There are ~600+ scripts included.

**Running scripts:**
- **`-sC`** — run the **default** script set (safe, useful scripts; also included in `-A`).
- **`--script <name>`** — run a specific script: `--script http-title`.
- **`--script <category>`** — run a whole category: `--script vuln`.
- **`--script "http-*"`** — wildcard: all HTTP scripts.
- **`--script <s1>,<s2>`** — a comma-separated list.
- **`--script-args <args>`** — pass arguments (credentials, paths, etc.).
- **`--script-help <name>`** — read what a script does before running it.

**Script categories** (filter by these):

| Category | Purpose |
|---|---|
| `default` | Safe, generally-useful (run by `-sC`). |
| `safe` | Won't crash/harm targets or be intrusive. |
| `discovery` | Gather more info (SNMP, SMB shares, DNS, etc.). |
| `version` | Advanced version detection. |
| `auth` | Check authentication / bypasses (e.g., anonymous FTP). |
| `brute` | **Brute-force credentials** (`ssh-brute`, `http-brute`). |
| `vuln` | **Check for known vulnerabilities** (`smb-vuln-ms17-010`, `ssl-heartbleed`). |
| `exploit` | Actively **exploit** vulnerabilities. |
| `intrusive` | May crash services or be noisy — use with care. |
| `dos` | **Denial-of-service** checks — dangerous. |
| `malware` | Detect malware/backdoors. |
| `external` | Send data to third-party services (e.g., whois). |
| `fuzzer` | Fuzz protocols. |
| `broadcast` | Discover hosts via broadcast. |

**High-value examples:**
```bash
# Detect known vulnerabilities on all open services
nmap -sV --script vuln <target>

# EternalBlue (MS17-010) check on SMB
nmap -p 445 --script smb-vuln-ms17-010 <target>

# Heartbleed check on HTTPS
nmap -p 443 --script ssl-heartbleed <target>

# Enumerate HTTP: title, headers, methods, common dirs, robots.txt
nmap -p 80,443 --script "http-title,http-headers,http-methods,http-enum" <target>

# Grab SSL/TLS cert and supported ciphers
nmap -p 443 --script ssl-cert,ssl-enum-ciphers <target>

# Enumerate SMB shares and users
nmap -p 445 --script smb-enum-shares,smb-enum-users <target>
```

**The concept:** NSE turns detection into a **community-extensible, app-aware** capability — much like Nuclei's templates but in Lua and integrated into the scanner. `--script vuln` in particular makes Nmap a first-pass vulnerability scanner: it finds open services *and* flags known holes in them in one run. **Caution:** `brute`, `intrusive`, `exploit`, and `dos` scripts are active and potentially damaging — read `--script-help` and only run them in scope. `-sC` (default scripts) is safe for routine use.

---

## 12. Timing and Performance

Scan speed trades off against **stealth, accuracy, and target load.** Nmap gives you a simple dial and fine-grained controls.

**Timing templates `-T0` to `-T5`** (the everyday dial):

| Template | Name | Use |
|---|---|---|
| `-T0` | Paranoid | Extremely slow (one probe every ~5 min) — serious IDS evasion. |
| `-T1` | Sneaky | Very slow — evasion. |
| `-T2` | Polite | Slower, lighter on the target. |
| `-T3` | Normal | **Default** — balanced. |
| `-T4` | Aggressive | **Fast** — recommended on reliable/modern networks; the common pentest choice. |
| `-T5` | Insane | Fastest — may miss results or overwhelm targets/networks. |

**Fine-grained controls:**
- **`--min-rate <n>` / `--max-rate <n>`** — floor/ceiling on packets per second (e.g., `--min-rate 1000` to force speed, `--max-rate 100` to be gentle).
- **`--max-retries <n>`** — how many times to retry a probe (lower = faster, may miss filtered ports).
- **`--host-timeout <time>`** — give up on a host after this long (skip slow hosts).
- **`--scan-delay <time>` / `--max-scan-delay`** — wait between probes (evasion / rate-limit avoidance).
- **`--min-parallelism` / `--max-parallelism`** — how many probes in flight at once.

**Guidance:** `-T4` is the practical default for most authorized scans. Drop to `-T2`/`-T1` on fragile targets or when avoiding detection; use `--max-rate` to be explicitly gentle on production. Faster isn't always better — `-T5` and huge rates can **drop packets** (missing open ports → false negatives) or **overwhelm** a target. Tune to the network's capacity and your stealth needs.

---

## 13. Firewall / IDS Evasion

For **authorized** testing behind firewalls/IDS, Nmap offers techniques to alter how probes look on the wire. (These change request *form*, not the fact that you're scanning — modern IDS/IPS often still detect them.)

- **`-f` / `--mtu <n>`** — **fragment** packets into tiny pieces so simple packet filters can't reassemble/inspect them.
- **`-D <decoy1,decoy2,ME,...>`** — **decoys**: make the scan appear to come from **multiple spoofed source IPs** alongside yours, so the target can't tell which is the real scanner. `-D RND:10` uses 10 random decoys.
- **`-S <IP>`** — **spoof the source IP** (you won't see replies unless you control that IP or the network path — used with idle scan or to frame/confuse).
- **`--spoof-mac <mac/vendor>`** — spoof your **MAC address** (e.g., appear as a Cisco device).
- **`-g <port>` / `--source-port <port>`** — scan **from a specific source port** (e.g., 53 or 80) to slip past firewalls that trust traffic from those ports.
- **`--data-length <n>`** — append random data to change packet size/signature.
- **`--badsum`** — send packets with bad checksums (some systems respond, revealing filtering rules).
- **`--proxies <url>`** — relay through HTTP/SOCKS proxies.
- **`--randomize-hosts`** — scan targets in random order.
- **`-sI` idle scan** (§7) — the ultimate: scan via a zombie so **your IP never touches the target**.

**Honest caveat:** these are classic techniques; modern stateful firewalls and IDS/IPS normalize fragments, correlate decoys, and rate-alert on scan patterns, so evasion is **less reliable than it once was**. And a slow `-T0/-T1` scan is often stealthier than fancy packet tricks. In an authorized engagement where a WAF/firewall is in the way, coordinating an **IP allowlist** is cleaner than fighting it. Treat evasion as educational + situational, not invisibility.

---

## 14. Output Formats

Nmap can write results in several formats simultaneously — important because you'll **feed the output into other tools**.

| Option | Format |
|---|---|
| `-oN <file>` | **Normal** — the human-readable console output, saved to a file. |
| `-oX <file>` | **XML** — structured, machine-readable; parsed by other tools and importers (Metasploit, reporting). |
| `-oG <file>` | **Grepable** — one host per line, easy to `grep`/`awk` (e.g., extract all hosts with 443 open). |
| `-oA <basename>` | **All three** at once (`.nmap`, `.xml`, `.gnmap`) — the recommended default so you always have every format. |
| `-oS <file>` | "Script kiddie" (l33t-speak — a joke format). |

**Display/verbosity options:**
- **`-v` / `-vv`** — verbose / very verbose (see progress and findings as they happen).
- **`--open`** — show **only open** (and open|filtered) ports — cuts closed/filtered noise; great for readable output.
- **`--reason`** — show **why** Nmap assigned each state (e.g., "syn-ack" → open, "no-response" → filtered). Invaluable for understanding and trusting results.
- **`-d` / `-dd`** — debug.
- **`--packet-trace`** — show every packet sent/received (deep debugging/learning).
- **`--stats-every <time>`** — periodic progress updates on long scans (or press Enter/`v` during a scan for status).

**Practical habit:** run with **`-oA scan_name`** on real work so you keep all formats, and pipe the **XML/grepable** output into downstream tooling (extract live web hosts to feed httpx/Nuclei/Burp). Use `--open --reason` for clean, explained console output.

---

## 15. Target Specification

Flexible ways to say *what* to scan:

| Form | Example |
|---|---|
| Single IP | `nmap 192.168.1.10` |
| Hostname | `nmap example.com` |
| IP range | `nmap 192.168.1.1-254` |
| CIDR subnet | `nmap 192.168.1.0/24` (256 addresses) |
| Multiple targets | `nmap 10.0.0.1 10.0.0.5 example.com` |
| From a file | `nmap -iL targets.txt` (one per line) |
| Random targets | `nmap -iR 100` (100 random internet hosts — **rarely appropriate**) |
| Exclude hosts | `nmap 192.168.1.0/24 --exclude 192.168.1.1` |
| Exclude from file | `--excludefile <file>` |
| IPv6 | `nmap -6 <ipv6-address>` |

`-iL` is the workhorse for real engagements — feed it your authorized scope list. **`--exclude`** is a safety tool: carve out systems you must not touch (gateways, fragile devices, out-of-scope IPs) even within a range.

---

## 16. Installation

```bash
# Kali / Parrot / Debian / Ubuntu
sudo apt install nmap

# Fedora / RHEL
sudo dnf install nmap

# macOS (Homebrew)
brew install nmap

# Windows: download the installer from nmap.org (bundles Npcap + Zenmap)

# From source (newest features/NSE) — from the tarball at nmap.org/dist
# ./configure && make && sudo make install

# Verify
nmap --version        # expect the 7.9x line
```

Raw-packet scan types (SYN scan, OS detection) need **root/admin**: run with `sudo` on Linux/macOS, or an elevated prompt on Windows (with Npcap installed). Update NSE scripts/databases with `nmap --script-updatedb` after adding custom scripts.

---

## 17. Command-Line Options (Full Breakdown)

Grouped by purpose.

### Host discovery
`-sn` (no port scan), `-Pn` (skip discovery), `-PS`/`-PA`/`-PU` (TCP-SYN/ACK/UDP ping), `-PE`/`-PP`/`-PM` (ICMP), `-PR` (ARP), `-n` (no DNS), `-R` (force DNS), `--dns-servers`.

### Scan techniques
`-sS` (SYN), `-sT` (connect), `-sU` (UDP), `-sA` (ACK), `-sF`/`-sX`/`-sN` (FIN/Xmas/Null), `-sW` (Window), `-sM` (Maimon), `-sI` (idle/zombie), `-sO` (IP protocol), `-sY`/`-sZ` (SCTP), `-b` (FTP bounce).

### Ports
`-p` (specify), `-p-` (all), `-F` (fast/top-100), `--top-ports`, `-r` (sequential), `--exclude-ports`.

### Detection
`-sV` (version), `--version-intensity`/`--version-light`/`--version-all`, `-O` (OS), `--osscan-guess`, `-A` (aggressive: `-sV -O -sC --traceroute`).

### NSE
`-sC` (default scripts), `--script <name/category/wildcard>`, `--script-args`, `--script-help`, `--script-updatedb`, `--script-trace`.

### Timing / performance
`-T0`–`-T5`, `--min-rate`/`--max-rate`, `--max-retries`, `--host-timeout`, `--scan-delay`/`--max-scan-delay`, `--min-parallelism`/`--max-parallelism`.

### Evasion / spoofing
`-f`/`--mtu`, `-D` (decoys), `-S` (spoof source), `--spoof-mac`, `-g`/`--source-port`, `--data-length`, `--badsum`, `--proxies`, `--randomize-hosts`.

### Output
`-oN`/`-oX`/`-oG`/`-oA`, `-v`/`-vv`, `-d`/`-dd`, `--open`, `--reason`, `--packet-trace`, `--stats-every`, `--append-output`, `--resume`.

### Target / misc
`-iL` (input list), `-iR` (random), `--exclude`/`--excludefile`, `-6` (IPv6), `--traceroute`, `--datadir`.

Run `nmap -h` for the concise help, or `man nmap` for the exhaustive reference.

---

## 18. Worked Examples with Output, Explained

> Output is **representative** and trimmed.

### 18.1 Basic scan
```bash
nmap 192.168.1.10
```
```
Starting Nmap 7.99 ( https://nmap.org )
Nmap scan report for 192.168.1.10
Host is up (0.0012s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 1.85 seconds
```
**Reading it:** host is up; of the top 1000 ports, 996 are closed and **4 are open**. Each open line is `PORT/proto STATE SERVICE` — a service you can now investigate. Note `3306 mysql` **exposed to the network** (a database that maybe shouldn't be reachable) — a lead already.

### 18.2 The workhorse: aggressive scan with version + OS + scripts
```bash
sudo nmap -sS -sV -O -sC -T4 -p- -oA fullscan 192.168.1.10
```
- `-sS` SYN scan, `-sV` versions, `-O` OS, `-sC` default scripts, `-T4` fast, `-p-` all ports, `-oA` save all formats.
```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Example Corp Intranet
|_http-server-header: Apache/2.4.29 (Ubuntu)
443/tcp  open  ssl/http Apache httpd 2.4.29
|_ssl-cert: Subject: commonName=intranet.example.com
3306/tcp open  mysql    MySQL 5.7.33-0ubuntu0.18.04.1
8080/tcp open  http     Apache Tomcat 8.5.14
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Running: Linux 4.X|5.X
OS details: Linux 4.15 - 5.6
```
**Reading it:** now you have **exact versions** (`OpenSSH 7.6p1`, `Apache 2.4.29`, `MySQL 5.7.33`, `Tomcat 8.5.14`) → look each up for CVEs. The full scan found **8080 (Tomcat)** that the top-1000 default would still catch, but `-p-` guarantees nothing hides. OS is Linux 4.15–5.6. NSE default scripts added the **HTTP title** and **SSL cert** (revealing `intranet.example.com` — a new hostname/vhost lead). This one command gives a near-complete host profile.

### 18.3 Fast network sweep (who's alive?)
```bash
nmap -sn 192.168.1.0/24
```
Host-discovery-only sweep of the whole subnet → a quick list of live hosts to scan properly next. No ports touched.

### 18.4 Vulnerability scan with NSE
```bash
sudo nmap -sV --script vuln -p 80,443,445 192.168.1.10
```
```
445/tcp open  microsoft-ds
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability (MS17-010) [EternalBlue]
|     State: VULNERABLE
|     IDs: CVE:CVE-2017-0143
```
Nmap flagged **EternalBlue (MS17-010)** — a critical RCE — directly. `--script vuln` turns Nmap into a first-pass vuln scanner.

### 18.5 UDP scan of key services
```bash
sudo nmap -sU -p 53,161,123,500 --open 192.168.1.10
```
Scan common UDP ports (DNS, SNMP, NTP, IKE), show only open — UDP services other scans miss.

### 18.6 Stealthy, scoped web-host discovery feeding other tools
```bash
sudo nmap -sS -p 80,443,8080,8443 -T2 --open -oG web-hosts.gnmap 10.0.0.0/24
# then extract live web hosts for the web toolchain:
grep -E "80/open|443/open|8080/open|8443/open" web-hosts.gnmap | awk '{print $2}' > webhosts.txt
```
Find web servers across a subnet, gently (`-T2`), save grepable output, and extract the IPs to feed httpx/Nuclei/Burp.

---

## 19. Reading the Output

The core of Nmap output is the **port table**:
```
PORT     STATE         SERVICE   VERSION
22/tcp   open          ssh       OpenSSH 8.2p1
80/tcp   open          http      nginx 1.18.0
139/tcp  filtered      netbios-ssn
53/udp   open|filtered domain
```
- **PORT** — port number and protocol (`22/tcp`, `53/udp`).
- **STATE** — the six states from §4. **`open`** = your target; **`filtered`** = a firewall is blocking (note the *pattern* — it maps defenses); **`open|filtered`** = unresolved (common in UDP — may need a different technique).
- **SERVICE** — Nmap's guess of the service (from its port→service map, or confirmed by `-sV`).
- **VERSION** — (with `-sV`) the actual product and version — your CVE-lookup fuel.

**Also in the output:**
- **"Host is up (latency)"** and **"Not shown: N closed/filtered ports"** — the summary of what wasn't listed.
- **`--reason`** appends *why* each state was assigned (`syn-ack`, `reset`, `no-response`) — use it to trust and understand results.
- **NSE script output** appears indented under the relevant port (`|_` lines) — titles, certs, vuln findings.
- **OS detection** and **traceroute** blocks (with `-O`/`--traceroute`).

**Triage reading:** scan the STATE column for **`open`**, note the **VERSION** of each, flag anything unusual (a database exposed to the network, an admin port, an old version), and let the pattern of **`filtered`** ports tell you about the firewall. Every open port with a version is a research lead.

---

## 20. Companion Tools

Nmap installs alongside a small suite worth knowing:

- **Zenmap** — the official **GUI** front-end. Good for learning (it shows the command it builds, visualizes topology, and saves/compares scans) and for those who prefer a graphical interface.
- **Ncat** — a modern **netcat** reimplementation: read/write data across networks, create **reverse/bind shells**, transfer files, act as a simple listener or client, with SSL and proxy support. The go-to for "connect to that open port and interact with it" after Nmap finds it (e.g., `ncat <ip> 22` to grab a banner, or catching a reverse shell).
- **Nping** — **packet crafting and analysis** (like hping): generate custom TCP/UDP/ICMP packets, measure response times, test firewall rules, and troubleshoot. Useful for understanding exactly how a host responds to a specific packet.
- **Ndiff** — **compare two Nmap XML scans** and show what changed (new open ports, hosts that appeared/disappeared). Ideal for **monitoring**: scan periodically, diff, and get alerted when a new port opens (an early sign of a change or compromise).

Together these cover discovery (Nmap), interaction (Ncat), packet-level testing (Nping), and change tracking (Ndiff).

---

## 21. Where It Fits: Workflow and Chaining

Nmap is the **first active step** — it turns an authorized scope into a map of live hosts and services that everything downstream depends on.

```
[ authorized scope: IPs / ranges / domains ]
                 │
                 ▼
           [ NMAP ]  ── host discovery → port scan → -sV versions → -O OS → NSE (-sC / vuln)
                 │        (find live hosts, open ports, exact software, initial vulns)
                 │  -oA / -oX output
     ┌───────────┼───────────────────────────────────────────────┐
     ▼           ▼                                                 ▼
 web hosts   non-web services                              vuln leads (NSE --script vuln)
 (80/443/…)   (SSH, SMB, DB, RDP)                           + versions → searchsploit / Nuclei
     │            │                                                │
     ▼            ▼                                                ▼
[ httpx → Nuclei → feroxbuster/ffuf → Nikto/WPScan → Burp → sqlmap ]   [ service-specific attacks ]
```

**Relationship to the tools you've studied:**
- **Nmap comes first.** It finds the web servers (and *which* ports they're on) that httpx confirms and Nuclei/feroxbuster/Burp then test. Without it you only test what you happened to know about.
- **feeds the web toolchain** — extract open 80/443/8080/8443 hosts (`-oG`/`-oX`) → pipe to **httpx** → **Nuclei/feroxbuster/Nikto/WPScan/Burp**.
- **versions feed vuln research** — `-sV` output → **searchsploit**/**Nuclei** to find known exploits (overlaps with Nuclei/Nikto, but at the host/service layer for *all* services, not just web).
- **finds non-web attack surface** — SMB (445), SSH (22), RDP (3389), databases (3306/5432), etc. — that web tools can't see but are often the way in.
- **Ncat** interacts with whatever Nmap finds.

**The discipline:** *scope → Nmap sweep for live hosts → full port + version + OS scan → NSE for quick vulns → split results by service → hand web services to the web toolchain and other services to their specific attacks.* Nmap is the map the whole engagement is drawn on.

---

## 22. Limitations and Pitfalls

- **"Host seems down" false negatives.** Firewalls that block ping make Nmap skip live hosts — add **`-Pn`** when you know a host exists.
- **Default is only top-1000 ports.** Services hide on high/uncommon ports — run **`-p-`** at least once or you'll miss them.
- **Speed vs accuracy.** `-T5`/huge rates drop packets → **false negatives** (missed open ports). Don't over-crank; verify with a slower rescan.
- **UDP is slow and ambiguous.** `open|filtered` is common; scope UDP ports and be patient. Don't skip UDP entirely (DNS/SNMP matter).
- **OS/version detection are guesses.** NAT, load balancers, proxies, and firewalls distort fingerprints — treat as strong hints, verify what matters.
- **Root needed for the best scans.** Without it you get `-sT` (noisier) and no OS detection.
- **NSE `intrusive`/`brute`/`exploit`/`dos` scripts can harm targets.** Read `--script-help`; keep to `safe`/`default` unless authorized and deliberate.
- **It's noisy and detectable.** Port scanning is a classic, easily-logged, easily-alerted activity — expect detection; evasion is imperfect (§13).
- **Not an application scanner.** Nmap maps hosts/services; it doesn't crawl web apps or test app logic — that's the web toolchain's job. Nmap gets you *to* the app.

---

## 23. Legal and Ethical Note

- **Port scanning is active and, in many places, legally sensitive.** In the US, the **Computer Fraud and Abuse Act (CFAA)** makes accessing systems "without authorization" a federal offense; scanning a network you don't own or lack written permission to test can expose you to **civil or criminal liability even if you never exploit anything** — the law looks at **authorization and intent**, not whether damage occurred. Most countries have equivalent computer-misuse laws.
- **Only scan systems you own or have explicit written authorization to test** — a signed scope/rules of engagement, an in-scope bug-bounty target that permits scanning (check the rules), or your own lab.
- **Never mass-scan the internet** (`-iR`) or scan third-party networks "to learn." Scanning shared infrastructure (cloud providers) may also violate the provider's terms — some require prior notice.
- **Be careful with intrusive/DoS NSE scripts and aggressive timing** on fragile or production systems — they can disrupt services. Scope ports, exclude sensitive hosts (`--exclude`), and throttle.
- **Scanning is detectable and attributable** — unauthorized scanning is easily traced to you.
- **Practice legally:** scan your **own lab** (VMs, home network you own), intentionally vulnerable targets (**Metasploitable**, **VulnHub**), or dedicated ranges (**HTB/THM**, **scanme.nmap.org** — a host the Nmap Project explicitly permits scanning for practice).

---

### Where to go next

- Set up a lab (Metasploitable + a couple of VMs on a host-only network) and run the arc: `nmap -sn` (who's up) → `sudo nmap -sS -sV -O -sC -p- -T4 -oA scan <host>` (full profile) → `--script vuln` (quick vulns). Seeing versions and an MS17-010 hit appear makes the whole tool click.
- Practice **reading states with `--reason --open`** against `scanme.nmap.org` (authorized) — watch *why* each port is open/closed/filtered; that intuition (§4) is the core skill.
- Wire the handoff: `nmap -p 80,443,8080 --open -oG web.gnmap <range>` → extract IPs → `httpx` → `nuclei`/**Burp**. That connects Nmap to the entire web toolchain you've already learned into one real workflow.

*End of reference.*

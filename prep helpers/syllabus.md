# CYBERSECURITY FUNDAMENTALS MASTERY GUIDE (2026)
For a final-year undergrad with a strong ML background
Goal: “unshakeable fundamentals” before specialization (AppSec/CloudSec/AISec)

This document is designed as STUDY MATERIAL (not just a syllabus):
- What to learn (concepts)
- How to practice (labs)
- How to prove it (deliverables/portfolio)
- How to know you’re ready (mastery checks)

Safety / Ethics (non-negotiable)
### Only practice offensive techniques in:
- your own machines, your own code, CTFs/labs with explicit permission
- authorized internship/company environments under written scope
Never scan or attack networks/systems you don’t own or explicitly have permission to test.



## Generated Table of Contents
  - [Only practice offensive techniques in:](#only-practice-offensive-techniques-in)
- [Table of Contents](#table-of-contents)
  - [0. How to use this guide (study loop + note system)](#0-how-to-use-this-guide-study-loop-note-system)
  - [You’ll progress fastest with an “understand -> implement -> break -> detect -> report” loop.](#youll-progress-fastest-with-an-understand-implement-break-detect-report-loop)
  - [Objective: a safe place to break things, collect telemetry, and learn.](#objective-a-safe-place-to-break-things-collect-telemetry-and-learn)
  - [Why: Security issues are usually “systems behavior under stress”.](#why-security-issues-are-usually-systems-behavior-under-stress)
  - [Goal: Become fluent in Linux as an admin + investigator.](#goal-become-fluent-in-linux-as-an-admin-investigator)
  - [3.1 Linux essentials (must be automatic)](#31-linux-essentials-must-be-automatic)
  - [3.2 Linux security concepts](#32-linux-security-concepts)
  - [Goal: Understand Windows as an enterprise target and a telemetry-rich defender OS.](#goal-understand-windows-as-an-enterprise-target-and-a-telemetry-rich-defender-os)
  - [4.1 Windows concepts](#41-windows-concepts)
  - [4.2 Windows telemetry & investigation](#42-windows-telemetry-investigation)
  - [4.3 Active Directory & enterprise identity (high-level, but job-critical)](#43-active-directory-enterprise-identity-high-level-but-job-critical)
  - [Goal: Read code, reason about risks, and automate investigations.](#goal-read-code-reason-about-risks-and-automate-investigations)
  - [5.1 Python (security automation)](#51-python-security-automation)
  - [5.2 Bash (Linux glue)](#52-bash-linux-glue)
  - [5.3 PowerShell (Windows glue)](#53-powershell-windows-glue)
  - [5.4 C + memory model (for vulnerability understanding)](#54-c-memory-model-for-vulnerability-understanding)
  - [5.5 Assembly basics (enough for reverse engineering)](#55-assembly-basics-enough-for-reverse-engineering)
  - [Goal: Be able to read traffic like a story and reason about controls.](#goal-be-able-to-read-traffic-like-a-story-and-reason-about-controls)
  - [6.1 Core concepts](#61-core-concepts)
  - [6.2 Defensive controls](#62-defensive-controls)
  - [6.3 Email & messaging security fundamentals (often missed, very practical)](#63-email-messaging-security-fundamentals-often-missed-very-practical)
  - [Goal: Use crypto safely, recognize broken designs, and talk about TLS/PKI confidently.](#goal-use-crypto-safely-recognize-broken-designs-and-talk-about-tlspki-confidently)
  - [7.1 Primitives (what they guarantee, what they don’t)](#71-primitives-what-they-guarantee-what-they-dont)
  - [7.2 Protocols & systems](#72-protocols-systems)
  - [Goal: Understand the web platform as a security boundary system.](#goal-understand-the-web-platform-as-a-security-boundary-system)
  - [8.1 Web building blocks](#81-web-building-blocks)
  - [8.2 API fundamentals](#82-api-fundamentals)
  - [8.3 Modern authentication protocols (fundamental, not “advanced AppSec”)](#83-modern-authentication-protocols-fundamental-not-advanced-appsec)
  - [Goal: Recognize bug patterns, root causes, and typical mitigations.](#goal-recognize-bug-patterns-root-causes-and-typical-mitigations)
  - [9.1 Input/Injection class](#91-inputinjection-class)
  - [9.2 Web/browser class](#92-webbrowser-class)
  - [9.3 Auth/AuthZ class](#93-authauthz-class)
  - [9.4 Memory safety class (systems)](#94-memory-safety-class-systems)
  - [9.5 Supply chain & dependency class](#95-supply-chain-dependency-class)
  - [9.6 Misconfiguration & insecure defaults](#96-misconfiguration-insecure-defaults)
  - [9.7 Business logic & race conditions](#97-business-logic-race-conditions)
  - [9.8 Secrets & credential handling](#98-secrets-credential-handling)
  - [Goal: Learn attacker thinking to build better defenses and to do ethical testing.](#goal-learn-attacker-thinking-to-build-better-defenses-and-to-do-ethical-testing)
  - [Goal: Become employable in blue-team work and understand enterprise reality.](#goal-become-employable-in-blue-team-work-and-understand-enterprise-reality)
  - [11.1 Logging & telemetry fundamentals](#111-logging-telemetry-fundamentals)
  - [11.2 Detection concepts](#112-detection-concepts)
  - [11.3 Incident response](#113-incident-response)
  - [11.4 Vulnerability management & patching (core industry skill)](#114-vulnerability-management-patching-core-industry-skill)
  - [Goal: Understand evidence sources and basic analysis workflows.](#goal-understand-evidence-sources-and-basic-analysis-workflows)
  - [Goal: Be able to triage suspicious binaries safely and understand what they do.](#goal-be-able-to-triage-suspicious-binaries-safely-and-understand-what-they-do)
  - [13.1 Binary formats (conceptual)](#131-binary-formats-conceptual)
  - [13.2 Analysis workflow](#132-analysis-workflow)
  - [Goal: Move from “finding bugs” to “designing secure systems”.](#goal-move-from-finding-bugs-to-designing-secure-systems)
  - [Goal: Understand the cloud primitives that attacks and defenses are built on.](#goal-understand-the-cloud-primitives-that-attacks-and-defenses-are-built-on)
  - [Goal: Map your ML strength into security without skipping fundamentals.](#goal-map-your-ml-strength-into-security-without-skipping-fundamentals)
  - [Aim: 3–6 artifacts that prove fundamentals across systems, network, web, and defense.](#aim-36-artifacts-that-prove-fundamentals-across-systems-network-web-and-defense)
  - [You should be able to answer clearly:](#you-should-be-able-to-answer-clearly)
  - [Linux:](#linux)
  - [Foundations / Systems Security:](#foundations-systems-security)
  - [If you want a structured path, use this:](#if-you-want-a-structured-path-use-this)
  - [Use this appendix as your “checklist of subtopics” for deep mastery.](#use-this-appendix-as-your-checklist-of-subtopics-for-deep-mastery)
  - [This appendix is intentionally link-heavy. Pick ONE primary course per topic and fill gaps with labs.](#this-appendix-is-intentionally-link-heavy-pick-one-primary-course-per-topic-and-fill-gaps-with-labs)

---

## Table of Contents
### 0. How to use this guide (study loop + note system)
1. Lab environment (Windows host + Linux + network lab) + core tools
2. Computing foundations (architecture, OS concepts, virtualization)
3. Linux mastery for security (admin + internals + auditing)
4. Windows mastery for security (internals + AD basics + telemetry)
5. Programming for security (Python, Bash, PowerShell, C, basic ASM)
6. Networking fundamentals (TCP/IP, DNS, HTTP, routing, Wireshark)
7. Applied cryptography fundamentals (TLS/PKI, hashes, auth, pitfalls)
8. Web + API fundamentals (auth, sessions, browser security model)
9. Vulnerability classes (OWASP + memory + logic + supply chain)
10. Offensive fundamentals (methodology, not “tool memorization”)
11. Defensive fundamentals (SOC, logs, SIEM concepts, IR)
12. Forensics fundamentals (disk, memory, network)
13. Malware & reverse engineering fundamentals
14. Security engineering & architecture (threat modeling, controls)
15. Cloud foundations (enough to be dangerous, before CloudSec)
16. AI/ML security foundations (enough to be grounded, before AISec)
17. Capstones & portfolio (what to build to get hired)
18. Interview readiness (questions, drills, narratives)
Appendix A: Mastery checklists (printable)
Appendix B: Resource library (books, courses, docs)
Appendix C: Suggested 6–12 month timeline
Appendix D: Detailed topic outlines (what to study)
Appendix E: Courses (Coursera) + YouTube + labs + datasets (links)


0) HOW TO USE THIS GUIDE
### You’ll progress fastest with an “understand -> implement -> break -> detect -> report” loop.

Recommended weekly cadence (10–15 hrs/week baseline; increase if you can):
- 4–6 hrs concept study (notes + flashcards)
- 4–6 hrs hands-on labs (logs, PCAPs, small code)
- 1–2 hrs write-ups (clean, teachable, interview-ready)
- 1 hr review (spaced repetition)

Note system (simple, high ROI):
- A “Security Notebook” file/folder where every topic has:
	- definition (2–5 lines)
	- why it matters (threat/defense link)
	- one real-world failure mode
	- one command/tool demo
	- one detection/mitigation idea

Assessment rule: If you can’t explain it from first principles and reproduce it in a lab,
you don’t “know” it yet.


1) LAB ENVIRONMENT + CORE TOOLS
### Objective: a safe place to break things, collect telemetry, and learn.

Minimum lab (recommended):
- Windows 11 host (your laptop)
- WSL2 Ubuntu OR a Linux VM (Ubuntu)
- One additional VM you can revert (Windows or Linux)
- Snapshot capability (Hyper-V, VirtualBox, VMware)

Network isolation:
- Use NAT networks for internet access
- Use Host-only network for attacking/defending inside your lab
- Keep “dangerous” VMs disconnected when not actively labbing

Core tools (learn the concepts first; tools are just lenses):
- Wireshark (packet analysis)
- tcpdump (CLI packet capture)
- Sysinternals Suite (Windows process/files/network)
- Procmon + Autoruns + Process Explorer
- Windows Event Viewer + Sysmon (telemetry)
- Linux: journalctl, auditd (optional), ss/netstat, lsof
- Burp Suite Community (web proxy learning)
- Ghidra (reverse engineering)
- x64dbg (Windows debugging) OR gdb (Linux)
- Docker (repeatable services/labs)
- Git + GitHub (portfolio + versioned notes)

Deliverables:
- A one-page “Lab README” describing your setup + how to reset/restore.

Mastery check:
- You can capture traffic, generate traffic, and map it to a process on both Linux and Windows.


2) COMPUTING FOUNDATIONS (ARCHITECTURE + OS CONCEPTS)
### Why: Security issues are usually “systems behavior under stress”.

Concepts you must internalize:
- CPU basics: registers, instruction pointer, privilege rings (user vs kernel)
- Memory: virtual memory, paging, heap vs stack, memory-mapped files
- Processes/threads: scheduling, context switches, handles/file descriptors
- System calls and APIs: boundary crossing from user to kernel
- Filesystems: metadata, permissions, links, journaling
- Virtualization: hypervisors, VM escape concepts (high-level)

Hands-on labs:
- Observe a program’s syscalls (Linux: strace) and its file/network behavior.
- Run a benign program and map: “this line of code -> which OS API -> which kernel action”.

Deliverables:
- A diagram: process -> syscalls -> kernel -> files/network.

Mastery check:
- Explain the difference between “permissions”, “privileges”, and “capabilities”.


3) LINUX MASTERY FOR SECURITY
### Goal: Become fluent in Linux as an admin + investigator.

### 3.1 Linux essentials (must be automatic)
- Filesystem layout: /etc, /var, /home, /proc, /sys, /tmp
- Users/groups: /etc/passwd, /etc/shadow, sudoers model
- Permissions: rwx, umask, setuid/setgid, sticky bit, ACLs
- Services: systemd units, journald, cron
- Networking: ip, ss, nftables/iptables (basic reading)
- Package mgmt: apt basics + verifying sources

### 3.2 Linux security concepts
- DAC vs MAC: SELinux/AppArmor (what they are, how to read denials)
- Common persistence patterns (defensive view): services, cron, bashrc
- SSH hardening basics: keys, agents, known_hosts, config
- Logging: auth logs, syslog/journald, log rotation

Hands-on labs:
- Build a “baseline audit script” (bash) that outputs:
	- users with shells
	- sudoers membership
	- listening ports + owning processes
	- recent auth failures
	- suspicious cron entries
- Create a user, misconfigure permissions intentionally, then detect it.

Deliverables:
- A bash audit script + short write-up: what it checks and why.

Mastery check:
- Given a Linux compromise scenario, you can list 10 places to check for persistence.


4) WINDOWS MASTERY FOR SECURITY
### Goal: Understand Windows as an enterprise target and a telemetry-rich defender OS.

### 4.1 Windows concepts
- Processes/threads, services, drivers (high-level)
- Registry: what it is, common autostart locations
- Security principals: users, groups, SIDs
- Access tokens: privileges, integrity levels (high-level)
- UAC model (what it does and does not do)
- Windows authentication building blocks (conceptual): local accounts vs domain accounts, NTLM vs Kerberos

### 4.2 Windows telemetry & investigation
- Event Logs: Security, System, Application
- Sysmon: process creation, network connections, file creation (conceptual)
- PowerShell logging basics (defensive view)
- Sysinternals: Process Explorer, Procmon, Autoruns
- Windows Defender / endpoint telemetry (conceptual): alerts, quarantine events, and why EDR exists

### 4.3 Active Directory & enterprise identity (high-level, but job-critical)
- What AD is: domain, domain controller, directory (LDAP), authentication (Kerberos)
- Core objects: users, groups, computers, OUs, GPOs
- Service identities: service accounts, SPNs (why services become identity boundaries)
- Trust boundaries: forests/domains/trusts (conceptual)
- Common defensive failure modes:
	- excessive group membership / over-broad GPOs
	- weak service account practices
	- poor credential hygiene and lateral movement opportunities

Optional hands-on lab (recommended if you want enterprise realism):
- Build a tiny two-VM AD lab (DC + workstation) using evaluation images.
- Generate normal behavior (logons, group changes, scheduled tasks) and learn where evidence lands in logs.

Hands-on labs:
- Install Sysmon in a VM and generate benign activity:
	- run programs, create files, make network connections
	- then locate events that prove what happened
- Use Procmon to trace a program writing to disk and registry.

Deliverables:
- A “Windows hunting cheatsheet” mapping: question -> tool -> data source.

Mastery check:
- You can answer: “Which process opened this network connection?” with evidence.


5) PROGRAMMING FOR SECURITY (BUILDING BLOCKS)
### Goal: Read code, reason about risks, and automate investigations.

### 5.1 Python (security automation)
- Files, subprocess, sockets, http clients
- Parsing: JSON/CSV/log formats
- Cryptography usage (safe libraries), not “roll your own”
- Testing mindset: reproduce bugs, write minimal PoCs in a lab

### 5.2 Bash (Linux glue)
- pipes, redirection, quoting, exit codes
- grep/sed/awk basics
- writing robust scripts: set -euo pipefail, safe temp files

### 5.3 PowerShell (Windows glue)
- objects/pipelines, Get-WinEvent, registry queries
- basic remoting concepts (defensive view)

### 5.4 C + memory model (for vulnerability understanding)
- pointers, arrays, stack frames, heap allocation
- undefined behavior and why it becomes security bugs

### 5.5 Assembly basics (enough for reverse engineering)
- function call conventions (x64), stack usage
- common patterns: prologue/epilogue, loops, comparisons

Hands-on labs:
- Write a Python script to parse authentication logs and flag anomalies.
- Write a small C program with an intentional bug in a sandbox and explain what goes wrong.

Deliverables:
- One Python “security utility” (log parser or PCAP metadata summarizer).

Mastery check:
- You can look at a code snippet and predict where user input crosses trust boundaries.


6) NETWORKING FUNDAMENTALS (THE MOST IMPORTANT SECURITY MULTIPLIER)
### Goal: Be able to read traffic like a story and reason about controls.

### 6.1 Core concepts
- OSI vs TCP/IP models (know what lives where)
- Ethernet, ARP, MAC vs IP
- IP: CIDR, routing, NAT, TTL
- TCP: handshake, retransmits, windowing, resets
- UDP: where it’s used and why it’s tricky
- DNS: recursion, caching, common record types
- DHCP: how hosts get configured
- HTTP(s): requests/responses, headers, cookies, CORS (conceptual)
- TLS (high-level): handshake, certificates, SNI

### 6.2 Defensive controls
- Firewalls: stateful vs stateless (conceptual)
- IDS/IPS basics: signatures vs anomaly
- Segmentation: VLANs, subnets, least-privilege networking

### 6.3 Email & messaging security fundamentals (often missed, very practical)
- SMTP basics (conceptual), why email is an attacker’s favorite entry point
- SPF / DKIM / DMARC: what they try to guarantee (and what they don’t)
- Mail headers: Received chains, Return-Path vs From, display-name tricks
- Common attacks: phishing, credential harvesting, malicious attachments, BEC

Hands-on lab:
- Take a few sample phishing emails (training datasets) and write a 1-page analysis:
	- what the lure is, what the payload/goal is
	- what header evidence supports your conclusion
	- what controls could have prevented/detected it

Deliverables:
- 1 phishing analysis report + a “header reading” cheatsheet

Hands-on labs:
- Capture traffic for:
	- DNS lookup
	- HTTP request
	- TLS connection
	Then annotate a PCAP: “what happened in plain English”.
- Build a small local network map: hosts, ports, services (your lab only).

Deliverables:
- 3 PCAP write-ups (DNS, HTTP, TLS) with screenshots + interpretation.

Mastery check:
- Given a PCAP, you can tell which host initiated a connection and what protocol is used.


7) APPLIED CRYPTOGRAPHY FUNDAMENTALS
### Goal: Use crypto safely, recognize broken designs, and talk about TLS/PKI confidently.

### 7.1 Primitives (what they guarantee, what they don’t)
- Symmetric encryption: confidentiality with shared key
- Asymmetric encryption: key distribution (slow)
- Digital signatures: integrity + authenticity + non-repudiation (contextual)
- Hash functions: one-way + collision resistance (properties)
- MAC/HMAC: integrity/authenticity with shared secret
- KDFs/password hashing: why slow hashes matter (bcrypt/scrypt/Argon2)

### 7.2 Protocols & systems
- PKI: certificates, CAs, chains, revocation (conceptual)
- TLS: goals, handshake overview, what can go wrong
- Common failures:
	- ECB mode / nonce reuse
	- weak randomness
	- insecure comparisons/timing
	- storing passwords incorrectly
	- “crypto without authentication” mistakes

Hands-on labs:
- Use OpenSSL to:
	- inspect a website certificate chain
	- generate a keypair and sign/verify a file
- Implement a tiny “secure token” demo in Python using a standard library/framework (no custom crypto).

Deliverables:
- A “crypto pitfalls” cheat sheet with examples and mitigations.

Mastery check:
- You can explain the difference between encryption and hashing to a non-technical stakeholder.


8) WEB + API FOUNDATIONS (BEFORE APPSEC)
### Goal: Understand the web platform as a security boundary system.

### 8.1 Web building blocks
- URL anatomy, HTTP methods, status codes
- Cookies: attributes (Secure, HttpOnly, SameSite)
- Sessions vs tokens
- AuthN vs AuthZ (the most important distinction)
- Proxies/caches/CDNs (conceptual): where security headers and auth tokens can leak
- Browser security model:
	- Same-Origin Policy
	- CORS (what it does/doesn’t do)
	- Content Security Policy (conceptual)

### 8.2 API fundamentals
- REST basics, JSON serialization
- Pagination, rate limiting (security and reliability)
- Webhooks and signature verification (conceptual)

### 8.3 Modern authentication protocols (fundamental, not “advanced AppSec”)
- Passwords: storage, reset flows, MFA (conceptual)
- Tokens:
	- opaque session IDs vs JWTs (tradeoffs)
	- bearer token risks (replay, leakage)
- OAuth 2.0 (authorization) and OpenID Connect (authentication) at a conceptual level:
	- what problem they solve, what the key flows are
	- common mistakes: wrong audience/issuer checks, weak redirect URI validation
- API keys vs mTLS vs signed requests (when each makes sense)

Hands-on lab:
- Pick one public API auth scheme (API keys or OAuth) and document:
	- where credentials live, how they rotate, and what logs you need to detect abuse

Hands-on labs:
- Use a local intentionally vulnerable web lab (legal) and:
	- intercept requests with Burp
	- identify parameters, cookies, headers
	- replay requests and observe behavior

Deliverables:
- A “web request anatomy” diagram + notes.

Mastery check:
- You can look at an HTTP request and identify trust boundaries and sensitive data.


9) VULNERABILITY CLASSES (A FUNDAMENTALS CATALOG)
### Goal: Recognize bug patterns, root causes, and typical mitigations.

### 9.1 Input/Injection class
- SQL injection (conceptual + parameterization defense)
- Command injection (why string concatenation is deadly)
- Path traversal
- Template injection (high-level)

### 9.2 Web/browser class
- XSS (stored/reflected/DOM)
- CSRF and why SameSite helps (not magic)
- SSRF (especially relevant in cloud environments)
- Insecure deserialization (conceptual)

### 9.3 Auth/AuthZ class
- Broken access control (IDOR)
- Session fixation, weak reset flows
- MFA bypass patterns (logic flaws)

### 9.4 Memory safety class (systems)
- Buffer overflows, use-after-free (high-level)
- Mitigations: DEP/NX, ASLR, stack canaries (concepts)
- Why memory-safe languages change the landscape (but don’t eliminate logic flaws)

### 9.5 Supply chain & dependency class
- vulnerable dependencies
- typosquatting, build pipeline trust
- secrets in repos

### 9.6 Misconfiguration & insecure defaults
- Debug endpoints exposed, verbose error messages
- Default credentials, insecure CORS, weak TLS configuration
- Overly permissive cloud/storage policies (conceptual)

### 9.7 Business logic & race conditions
- “Valid individually, broken together” flows (discounts, refunds, IDOR chains)
- Time-of-check/time-of-use issues

### 9.8 Secrets & credential handling
- hardcoded keys, leaked tokens, unsafe local storage
- secret rotation and scoping (principle of least privilege)

Hands-on labs:
- PortSwigger Web Security Academy labs for each category.
- For memory safety: use safe, intentionally vulnerable training binaries in a VM.

Deliverables:
- A personal “vuln encyclopedia” where each vuln has:
	- definition, root cause, exploit idea (high-level), mitigation, detection hint.

Mastery check:
- For any vuln class above, you can describe the most common real-world mitigation.


10) OFFENSIVE FUNDAMENTALS (METHOD, NOT TOOL WORSHIP)
### Goal: Learn attacker thinking to build better defenses and to do ethical testing.

Core methodology (always legal lab scope):
- Recon: enumerate what exists
- Initial access: identify weaknesses
- Privilege escalation: expand control
- Lateral movement: move inside network
- Persistence: maintain access
- Exfiltration/impact: attacker objectives
- Reporting: reproduce + fix recommendations

Skills (fundamental, transferable):
- reading error messages, stack traces, logs
- hypothesis-driven testing
- minimizing variables (reproducible PoCs)
- knowing when to stop and escalate (ethics)

Hands-on labs:
- TryHackMe/HackTheBox learning paths, but with a rule:
	- write one paragraph after each box: “root cause” and “defense/detection”.

Deliverables:
- 5 high-quality write-ups (even if “easy” labs): focus on clarity + fixes.

Mastery check:
- You can propose defense measures and logging for each step you perform in a lab.


11) DEFENSIVE FUNDAMENTALS (SOC / DETECTION / IR)
### Goal: Become employable in blue-team work and understand enterprise reality.

### 11.1 Logging & telemetry fundamentals
- What logs exist (OS, application, network, identity)
- What good logs look like (structured, timestamps, identifiers)
- Why “no logs” = no security

### 11.2 Detection concepts
- Indicators vs behaviors
- False positives vs false negatives
- Baselines and anomaly detection (where your ML skills fit)
- MITRE ATT&CK as a shared language

### 11.3 Incident response
- Triage -> contain -> eradicate -> recover -> lessons learned
- Evidence handling basics (don’t destroy what you need)

### 11.4 Vulnerability management & patching (core industry skill)
- CVE/CVSS basics (what the numbers mean, and what they miss)
- Asset inventory and exposure: “what do we have?” is half the battle
- Prioritization: exploitability, internet exposure, privilege level, business impact
- Patch management realities: testing, rollout, compensating controls

Hands-on lab:
- Create a simple vuln triage template (spreadsheet or doc) and practice prioritizing 20 sample CVEs.

Deliverables:
- A “vuln triage playbook” + prioritized sample backlog with reasoning

Hands-on labs:
- In a VM, simulate benign events and create simple detections:
	- “new local admin created”
	- “suspicious parent-child process chain”
	- “binary executed from temp directory”
- Analyze pre-made incident datasets from blue-team lab platforms.

Deliverables:
- A small “detection notebook”: 10 detection ideas with data sources.

Mastery check:
- You can answer: “What telemetry would you need to detect X?” for common attacks.


12) FORENSICS FUNDAMENTALS
### Goal: Understand evidence sources and basic analysis workflows.

Areas:
- Disk forensics: file artifacts, timelines, deleted file concepts
- Memory forensics: processes, DLLs/modules, connections, injection concepts (high-level)
- Network forensics: PCAP analysis, DNS logs, proxy logs

Hands-on labs:
- Analyze a provided PCAP and produce:
	- timeline
	- suspected C2 or suspicious domains (if any)
	- key evidence points
- Practice with basic memory image analysis in a safe lab dataset.

Deliverables:
- 2 forensic reports: “evidence -> reasoning -> conclusion -> confidence”.

Mastery check:
- You can separate “facts observed” from “interpretations”.


13) MALWARE & REVERSE ENGINEERING FUNDAMENTALS
### Goal: Be able to triage suspicious binaries safely and understand what they do.

### 13.1 Binary formats (conceptual)
- Windows: PE format, imports/exports
- Linux: ELF format, dynamic linking

### 13.2 Analysis workflow
- Safe handling: isolated VM, no shared clipboard, snapshots
- Static triage: hashes, strings, imports, entropy
- Dynamic analysis: observe files/registry/network, process tree
- Debugging basics: breakpoints, stepping, call stack

Hands-on labs:
- Use benign or training malware samples (from reputable training sources) in an isolated VM.
- Produce a “behavioral summary”:
	- persistence? network? encryption? process injection? (high-level)

Deliverables:
- 2 malware analysis reports (even if simple samples).

Mastery check:
- You can explain: “static analysis tells you X; dynamic tells you Y; both can be fooled.”


14) SECURITY ENGINEERING & ARCHITECTURE
### Goal: Move from “finding bugs” to “designing secure systems”.

Core frameworks:
- CIA triad + extended properties (authenticity, non-repudiation, availability)
- Threat modeling:
	- assets, entry points, trust boundaries, attacker goals
	- STRIDE (Spoofing, Tampering, Repudiation, Info disclosure, DoS, Elevation)
- Risk basics:
	- likelihood vs impact
	- compensating controls
- Secure design principles:
	- least privilege
	- defense in depth
	- secure defaults
	- complete mediation
	- minimize attack surface

Secure SDLC (fundamentals that apply everywhere)
- Requirements: security objectives and “abuse cases”
- Design reviews: threat modeling as a gate
- Implementation: secure coding standards, code review checklists
- Verification: SAST/DAST concepts, dependency scanning, secrets scanning
- Release: SBOM concept, signing, release approvals
- Operations: monitoring, incident response readiness, postmortems

Hands-on labs:
- Threat model a simple app you build (or your internship product if allowed):
	- draw a data flow diagram
	- list threats and mitigations

Deliverables:
- 1 threat model doc + mitigation plan.

Mastery check:
- You can identify trust boundaries in any architecture diagram.


15) CLOUD FOUNDATIONS (BEFORE CLOUDSEC SPECIALIZATION)
### Goal: Understand the cloud primitives that attacks and defenses are built on.

Core concepts:
- Shared responsibility model
- Identity & access: IAM concepts, roles, policies, service principals
- Networking: VPC/VNet concepts, security groups/NSGs, load balancers
- Storage: object vs block vs file; access policies
- Secrets management and KMS concepts
- Observability: logs/metrics/traces (cloud-native)

Container & platform basics (increasingly unavoidable)
- Containers vs VMs (threat model differences)
- Namespaces/cgroups conceptually (why isolation isn’t “magic”)
- Image supply chain: base images, signing, scanning (conceptual)
- Kubernetes vocabulary (very high-level): cluster, node, pod, service, ingress

Hands-on labs:
- Deploy a tiny app (even local Docker) and practice:
	- principle of least privilege
	- secret handling (never hardcode)
	- logging of auth events

Deliverables:
- A “cloud fundamentals” cheat sheet: identity, network, storage, logging.

Mastery check:
- You can explain why SSRF becomes especially dangerous in cloud environments.


16) AI/ML SECURITY FOUNDATIONS (BEFORE AISEC SPECIALIZATION)
### Goal: Map your ML strength into security without skipping fundamentals.

Threats in ML systems (high-level, but concrete):
- Data poisoning (training pipeline)
- Evasion/adversarial examples (inference)
- Model extraction (API abuse)
- Privacy leakage (membership inference, data leakage)
- Supply chain risk (models, datasets, dependencies)

Defensive foundations:
- Secure data pipelines (integrity checks, provenance)
- Monitoring distribution drift and abuse patterns
- Rate limiting and abuse detection for model APIs
- Evaluation under attack assumptions

Hands-on labs (safe and ethical):
- Build a basic anomaly detector for auth logs and explain:
	- what it can catch, what it cannot
- Implement a “model API” toy service and add:
	- logging, rate limiting, input validation

Deliverables:
- One ML-for-defense mini project with rigorous evaluation and failure analysis.

Mastery check:
- You can articulate the difference between “security of AI” and “AI for security”.


17) CAPSTONES & PORTFOLIO (WHAT GETS YOU HIRED)
### Aim: 3–6 artifacts that prove fundamentals across systems, network, web, and defense.

Pick 3 (recommended set):
1) Network Investigation Portfolio
	 - 3 PCAP write-ups + a small tool that extracts metadata

2) Host Investigation Portfolio
	 - Windows Sysmon hunting notes + Linux audit script

3) Web Security Portfolio
	 - PortSwigger lab write-ups focusing on root cause + mitigation

4) Threat Model Portfolio
	 - One full threat model for a realistic app (DFD + threats + mitigations)

5) Malware Triage Portfolio
	 - Two sandboxed analysis reports (behavioral summary + IOCs in a lab)

Quality bar for every write-up:
- Repro steps (lab)
- Root cause
- Impact
- Fix and prevention
- Detection/monitoring suggestions


18) INTERVIEW READINESS (FUNDAMENTALS DRILLS)
### You should be able to answer clearly:
- Networking: Explain TCP handshake, DNS resolution, TLS at a high level
- OS: Explain processes vs threads, permissions vs privileges, why logs matter
- Web: AuthN vs AuthZ, cookies, sessions, XSS vs CSRF
- Crypto: hashing vs encryption, PKI, why password hashing must be slow
- IR: what you do in the first hour of an incident
- Engineering: how you threat model and prioritize fixes

Practice format:
- 30-minute “whiteboard a system” drills: draw a DFD and list top threats.
- 15-minute PCAP drill: identify protocol, endpoints, and suspicious patterns.
- 15-minute log drill: interpret 10 events and summarize what happened.


APPENDIX A: MASTER CHECKLISTS (PRINTABLE)
### Linux:
- I can explain and use permissions, sudo, services, logs, networking.
- I can identify persistence locations and suspicious processes.

Windows:
- I can use Sysinternals to map process->file->network actions.
- I can query Event Logs/Sysmon for investigation questions.

Networking:
- I can read a PCAP for DNS/HTTP/TLS and summarize it.
- I understand routing, NAT, and segmentation at a practical level.

Crypto:
- I know what primitives guarantee and common failure modes.
- I can inspect certificates and explain trust chains.

Web:
- I can reason about auth, sessions, browser security boundaries.
- I can explain root causes for common OWASP Top 10 classes.

Defense/IR:
- I can propose telemetry + detections for common attack behaviors.
- I can write clear reports with evidence and confidence.


APPENDIX B: RESOURCE LIBRARY (HIGH SIGNAL)
### Foundations / Systems Security:
- MIT 6.858 (course materials)
- Stanford CS155 (course materials)

Security “reference standards” (read the intent, not just the controls):
- NIST SP 800-61 (incident response)
- NIST SP 800-92 (log management)
- NIST SP 800-53 (security controls catalog)
- CIS Benchmarks (hardening baselines)
- MITRE ATT&CK (behavior taxonomy)

Web/application security:
- OWASP Top 10 (concept map)
- OWASP ASVS (what “good” looks like)

Malware/reversing:
- “Practical Malware Analysis” (workflow-driven)

Blue-team practice:
- Detection engineering write-ups and open datasets (focus on evidence-driven reasoning)

Linux:
- Official distro docs + man pages (practice-first)

Windows:
- Windows Internals (Part 1/2)
- Sysinternals documentation

Networking:
- “Computer Networking: A Top-Down Approach” (Kurose/Ross)

Applied crypto:
- “Cryptography and Network Security” (Stallings)
- Practical OpenSSL/GPG tutorials

Web security:
- PortSwigger Web Security Academy (free, excellent)

Reverse engineering:
- Ghidra docs + beginner reversing course materials

Blue-team labs:
- CyberDefenders / Blue Team Labs Online (challenge-based)

Community (Bengaluru):
- OWASP Bangalore, Null community, Cloud Security Alliance chapter


APPENDIX C: SUGGESTED 6–12 MONTH TIMELINE
### If you want a structured path, use this:

Month 1–2: Lab + Linux + Networking basics
- Build lab, baseline scripts, PCAP write-ups

Month 3–4: Windows + Web foundations
- Sysmon + Sysinternals, web request anatomy, PortSwigger basics

Month 5–6: Crypto + vulnerability catalog + defensive fundamentals
- TLS/PKI basics, OWASP Top 10 mastery, basic detections

Month 7–9: Forensics + malware triage + threat modeling
- Evidence-based reporting, reversing fundamentals, system design security

Month 10–12: Capstones + interview drills + specialization preview
- 3 portfolio artifacts + focused track (AppSec/CloudSec/AISec)


APPENDIX D: DETAILED TOPIC OUTLINES (WHAT TO STUDY)
### Use this appendix as your “checklist of subtopics” for deep mastery.
Rule: don’t move on until you can (a) explain it, (b) demo it in your lab, and (c) say how defenders detect/mitigate it.

D1) Computing foundations (architecture + OS concepts)
- CPU and execution:
	- privilege levels (user vs kernel), syscalls
	- interrupts, context switches (conceptual)
	- instruction pointer/program counter
- Memory:
	- virtual memory, pages, page faults (conceptual)
	- stack vs heap vs static memory
	- memory-mapped files
	- why “undefined behavior” becomes security bugs
- Processes:
	- process vs thread, scheduling basics
	- handles (Windows) vs file descriptors (Linux)
	- child/parent relationships, environment variables
- Filesystems:
	- metadata, permissions model
	- symlinks vs hard links
	- journaling idea (consistency after crash)
- Virtualization and isolation:
	- VMs vs containers
	- sandboxing idea (attack surface reduction)

D2) Linux mastery
- Command-line fluency:
	- files: ls/find/stat, permissions (chmod/chown), text tools (grep/sed/awk)
	- processes: ps/top, signals, systemd service status
	- networking: ip, ss, lsof, resolv.conf basics
- Auth and authorization:
	- users/groups, sudoers
	- PAM concept (high-level)
- Logging:
	- journald queries (journalctl), auth logs locations
	- time sync basics (why timestamps matter)
- Hardening fundamentals:
	- SSH keys, disabling password auth (conceptual), least privilege
	- updates and trusted repositories
- Persistence locations (defender knowledge):
	- systemd units, cron jobs, shell profiles, /etc/rc* (varies by distro)

D3) Windows mastery
- Internals you should be able to talk about:
	- processes/threads, services
	- registry fundamentals (hives, keys/values)
	- access tokens and integrity levels (conceptual)
	- UAC: threat model and limits
- Telemetry:
	- Windows Event Logs: where to find logon and privilege activity
	- Sysmon event categories (process creation, network, file, registry)
	- PowerShell logging concepts
- Persistence locations (defender knowledge):
	- Run/RunOnce keys, scheduled tasks, services, WMI event subscriptions

D4) Active Directory (identity fundamentals)
- Concept model:
	- domains, domain controllers
	- LDAP directory vs authentication
	- Kerberos overview: tickets, why time sync matters
	- NTLM (conceptual) and why it’s riskier
- Objects & policy:
	- users/groups/computers/OUs
	- Group Policy basics (what it can change)
- Enterprise investigation questions you must answer:
	- “who logged in where?”
	- “who changed group membership?”
	- “what new service/scheduled task appeared?”

D5) Programming for security
- Python:
	- parsing logs, HTTP requests, basic socket usage
	- safe subprocess patterns, avoid shell injection
	- writing reproducible tools (args, logging, tests)
- Bash:
	- quoting rules (the #1 source of mistakes)
	- safe scripting patterns
- PowerShell:
	- object pipeline, Get-WinEvent, filtering, exporting evidence
- C + memory:
	- arrays/pointers, stack frames, heap allocations
	- integer overflows, bounds checking
- Assembly reading:
	- function prologue/epilogue, calling conventions, stack usage

D6) Networking (deeper than “OSI model”)
- IP:
	- CIDR/subnetting, routing tables
	- NAT implications for attribution
- ARP:
	- how hosts resolve L2 addresses
	- what “ARP spoofing” means conceptually and what defenders watch
- TCP:
	- handshake, seq/ack basics, retransmissions
	- flags: SYN/ACK/FIN/RST meaning
- DNS:
	- recursion, authoritative vs recursive resolvers
	- record types: A/AAAA/CNAME/MX/TXT/NS
	- caching and TTL
- HTTP:
	- request/response structure, headers, cookies
	- proxies, caches, and why headers matter
- TLS:
	- certificate chains, verification basics
	- SNI, ALPN (conceptual)
- Practical skills:
	- map (process -> socket -> destination)
	- read a PCAP and narrate the session in plain English

D7) Applied cryptography
- Hashing and integrity:
	- why hashes are not encryption
	- collision vs preimage resistance (intuition)
- Password storage:
	- salt, slow KDFs, why “fast hashing” is bad
- Symmetric encryption:
	- IV/nonce basics
	- authenticated encryption concept (AEAD)
- Public key crypto:
	- signatures vs encryption
	- key management realities
- TLS/PKI:
	- certificates, CAs, chain validation
	- common operational failures: expired certs, wrong hostname, weak config

D8) Web and API fundamentals
- HTTP sessions:
	- session cookies, fixation concepts
	- JWTs: what they are, common verification mistakes (conceptual)
- Browser security:
	- same-origin policy, CORS
	- CSP intent
- AuthN vs AuthZ:
	- MFA and recovery flows (risk hotspots)
- OAuth/OIDC:
	- roles: resource owner, client, authorization server, resource server
	- redirect URI validation and token audience checks (common failures)
- Common web vulnerability “root causes”:
	- injection due to unsafe string composition
	- XSS due to untrusted data rendered as code
	- CSRF due to missing anti-CSRF measures and cookie behavior
	- SSRF due to “server fetches attacker-controlled URL”

D9) Defensive operations (SOC/IR)
- Logging:
	- what to log (auth, admin actions, sensitive object access, network egress)
	- structured logging concepts
- Detection:
	- baselines, behavior-based alerts
	- mapping detections to MITRE ATT&CK
- IR:
	- triage, containment, eradication, recovery
	- evidence preservation basics

D10) Forensics
- Timelines:
	- why time sync and consistent time formats matter
- Disk artifacts (conceptual):
	- recent file execution evidence, downloads, browser history
- Memory artifacts (conceptual):
	- processes/modules/network connections
- Network artifacts:
	- DNS logs, proxy logs, PCAPs

D11) Malware / reversing
- Safe workflow:
	- isolation and snapshots
- Static triage:
	- hashes/strings/imports, packer indicators (conceptual)
- Dynamic triage:
	- file/registry/network behavior
- Reporting:
	- what it does, how it persists, what to block/detect

D12) Security engineering
- Threat modeling:
	- assets, trust boundaries, entry points
	- STRIDE mapping
- Secure design:
	- least privilege, secure defaults, defense in depth
- Secure SDLC:
	- SAST/DAST concepts, dependency scanning, secrets scanning
	- SBOM concept and why it matters

D13) Cloud fundamentals (pre-CloudSec)
- Identity:
	- roles/policies, least privilege, token-based auth
- Networking:
	- private networking, segmentation, outbound control
- Storage:
	- public access pitfalls, object ACL/policies
- Observability:
	- logs/metrics/traces, audit logs
- Containers:
	- image supply chain, scanning, runtime isolation conceptually

D14) AI/ML security fundamentals (pre-AISec)
- Threats:
	- poisoning, evasion, extraction, privacy leakage
- Defenses:
	- pipeline integrity, monitoring, rate limiting
- Practical mindset:
	- evaluate under attack assumptions and document limitations


APPENDIX E: COURSES (COURSERA) + YOUTUBE + LABS + DATASETS (LINKS)
### This appendix is intentionally link-heavy. Pick ONE primary course per topic and fill gaps with labs.

E0) Core “always-open” references
- MITRE ATT&CK (tactics/techniques vocabulary): [https://attack.mitre.org/](https://attack.mitre.org/)
- OWASP Top 10 (web risk map): [https://owasp.org/Top10/2025/](https://owasp.org/Top10/2025/)
- OWASP ASVS (what “good web security” looks like): [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)
- OWASP Cheat Sheet Series (high ROI): [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)
- CIS Benchmarks (hardening baselines): [https://www.cisecurity.org/cis-benchmarks](https://www.cisecurity.org/cis-benchmarks)
- Sysinternals (Windows investigation tools hub): [https://learn.microsoft.com/sysinternals/](https://learn.microsoft.com/sysinternals/)
- Sysmon (host telemetry): [https://learn.microsoft.com/sysinternals/downloads/sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- Wireshark: [https://www.wireshark.org/](https://www.wireshark.org/)

Incident response & logging standards (excellent fundamentals reading):
- NIST SP 800-61 Rev. 3 (Incident Handling Guide): [https://csrc.nist.gov/pubs/sp/800/61/r3/final](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- NIST SP 800-92 (Log Management): [https://csrc.nist.gov/publications/detail/sp/800-92/final](https://csrc.nist.gov/publications/detail/sp/800-92/final)

E1) Coursera: high-signal picks (foundation-first)
Cybersecurity foundations (broad overview + portfolio-ish):
- Google Cybersecurity Professional Certificate: [https://www.coursera.org/professional-certificates/google-cybersecurity](https://www.coursera.org/professional-certificates/google-cybersecurity)

If you want extra “IT fundamentals” to make the security topics easier:
- Google IT Support Professional Certificate: [https://www.coursera.org/professional-certificates/google-it-support](https://www.coursera.org/professional-certificates/google-it-support)

Intro survey (good for terminology, but don’t stop here):
- Introduction to Cyber Security Specialization (NYU): [https://www.coursera.org/specializations/intro-cyber-security](https://www.coursera.org/specializations/intro-cyber-security)

Networking fundamentals:
- The Bits and Bytes of Computer Networking: [https://www.coursera.org/learn/computer-networking](https://www.coursera.org/learn/computer-networking)

Operating systems fundamentals:
- Operating Systems and You: Becoming a Power User: [https://www.coursera.org/learn/os-power-user](https://www.coursera.org/learn/os-power-user)

Applied cryptography foundations:
- Cryptography (Jonathan Katz, UMD): [https://www.coursera.org/learn/cryptography](https://www.coursera.org/learn/cryptography)

If a Coursera page is blocked in your region/network:
- use Coursera search for the exact course name
- or open in a different network and bookmark it

E2) University-grade course materials (free, deep)
- MIT 6.858 (Computer Systems Security): [https://web.mit.edu/6.858/](https://web.mit.edu/6.858/)
- Stanford CS155 (computer & network security): [https://cs155.stanford.edu/](https://cs155.stanford.edu/)
	- Includes projects/readings (some very advanced). Use for depth, not as your first exposure.

E3) Web security: the best free lab curriculum
- PortSwigger Web Security Academy (free learn + labs): [https://portswigger.net/web-security](https://portswigger.net/web-security)

E4) Legal local web labs you can run in your own environment
- OWASP WebGoat (deliberately insecure training app): [https://owasp.org/www-project-webgoat/](https://owasp.org/www-project-webgoat/)
- OWASP Juice Shop (deliberately insecure store app): [https://owasp.org/www-project-juice-shop/](https://owasp.org/www-project-juice-shop/)
	(If the OWASP page is blocked, search “OWASP Juice Shop GitHub” and use the official repo.)

E5) Blue-team / DFIR practice platforms
- Blue Team Labs Online: [https://blueteamlabs.online/](https://blueteamlabs.online/)
	- Great for practical investigations (PCAPs, memory dumps, logs, phishing).

- CyberDefenders (DFIR/SOC challenges): [https://cyberdefenders.org/](https://cyberdefenders.org/)

E6) General hands-on learning platforms (mixed red/blue)
- TryHackMe: [https://tryhackme.com/](https://tryhackme.com/)
- Hack The Box: [https://www.hackthebox.com/](https://www.hackthebox.com/)
- OverTheWire (wargames): [https://overthewire.org/wargames/](https://overthewire.org/wargames/)

CTF discovery (find events + practice targets):
- CTFtime: [https://ctftime.org/](https://ctftime.org/)
- picoCTF (great beginner-friendly CTF): [https://picoctf.org/](https://picoctf.org/)

E7) PCAPs, forensics, and incident write-ups (practice with real-ish data)
- Malware Traffic Analysis (training PCAPs + write-ups): [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)
- The DFIR Report (excellent incident narratives): [https://thedfirreport.com/](https://thedfirreport.com/)

Packet capture practice:
- Wireshark Sample Captures (PCAP library): [https://wiki.wireshark.org/SampleCaptures](https://wiki.wireshark.org/SampleCaptures)

E8) Windows telemetry configs and references
- SwiftOnSecurity Sysmon config (starter config): [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- Sysinternals Live (browse/run tools via UNC path): [https://live.sysinternals.com/](https://live.sysinternals.com/)

Detection engineering starter repos (practice writing detections and mapping to ATT&CK):
- Sigma rules: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- Atomic Red Team (safely simulate techniques in a lab): [https://github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)

E9) Reverse engineering & malware tooling
- Ghidra: [https://ghidra-sre.org/](https://ghidra-sre.org/)
- x64dbg: [https://x64dbg.com/](https://x64dbg.com/)
- FLARE-VM (Windows malware analysis VM setup): [https://github.com/mandiant/flare-vm](https://github.com/mandiant/flare-vm)
- REMnux (Linux malware analysis distro): [https://remnux.org/](https://remnux.org/)

E10) YouTube: channels/playlists that are consistently high-signal
Windows internals + troubleshooting:
- Sysinternals Update videos (Mark Russinovich playlist): [https://www.youtube.com/playlist?list=PLhFhDWFYccZ_GvdJ11NZwaBAhwDCWmni_](https://www.youtube.com/playlist?list=PLhFhDWFYccZ_GvdJ11NZwaBAhwDCWmni_)

Networking / Wireshark:
- Wireshark channel (talks, training content): [https://www.youtube.com/@Wireshark](https://www.youtube.com/@Wireshark)

Web security:
- PortSwigger (Burp/WebSec Academy content): [https://www.youtube.com/@PortSwigger/playlists](https://www.youtube.com/@PortSwigger/playlists)
- OWASP Global channel: [https://www.youtube.com/user/OWASPGLOBAL](https://www.youtube.com/user/OWASPGLOBAL)

Hands-on CTF-style learning (use responsibly, in labs only):
- LiveOverflow (foundational security mindset): [https://www.youtube.com/@LiveOverflow/playlists](https://www.youtube.com/@LiveOverflow/playlists)
- John Hammond (CTFs + malware/DFIR content): [https://www.youtube.com/@JohnHammond010/playlists](https://www.youtube.com/@JohnHammond010/playlists)

Certification-style fundamentals (good structured explanations; still do labs):
- Professor Messer (Security+/Network+ style fundamentals): [https://www.youtube.com/@professormesser/playlists](https://www.youtube.com/@professormesser/playlists)

Malware/reversing (intro-to-intermediate):
- MalwareAnalysisForHedgehogs: [https://www.youtube.com/@MalwareAnalysisForHedgehogs/playlists](https://www.youtube.com/@MalwareAnalysisForHedgehogs/playlists)

Note on YouTube:
- Prefer playlists on official channels when possible.
- Treat videos as “explanations”; prove understanding by reproducing the concept in a legal lab and writing a report.

E11) What to do with links (a concrete workflow)
For each topic you study, produce one artifact:
- 1 page notes (definitions + pitfalls)
- 1 lab demo (screenshots/logs/PCAP)
- 1 write-up (root cause + mitigation + detection)



END

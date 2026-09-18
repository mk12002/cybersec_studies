# Web Application Pentesting — Tools Arsenal & Study Path

A hands-on reference library for the offensive web-app toolkit: **18 tool deep-dives** (each Beginner → Advanced) plus **2 capstone guides** that tie them into a single methodology and a recommended learning order.

The folders are **numbered in the order you actually use the tools in an engagement** — and in the order you should learn them. Reconnaissance comes before discovery, discovery before scanning, scanning before exploitation, and so on. Read the two guides in [`00-start-here/`](00-start-here/) first; they explain *why* this order exists and how every tool connects.

## How to Use This Library

1. **Start with [`00-start-here/`](00-start-here/).** Read the **Glossary & Concepts Handbook** to build the vocabulary and mental models, then the **Master Guide & Study Path** for the unified methodology, the phase-by-phase study order, where to practice, and the legal framework. Everything else is the detailed per-tool reference these two guides point to.
2. **Then work phase by phase (folders `01` → `07`).** Within a phase, the tools can be learned in parallel; it's the **phase order** that matters — you can't exploit what you haven't discovered, and you can't discover well until you can see and manipulate traffic.
3. **Treat each tool file as a reference**, not a novel. Skim it when you pick the tool up, then return to it for flags, recipes, and edge cases during real work.

> ⚠️ **Authorized testing only.** Every technique here is for lab practice, CTFs, and engagements you have **explicit written permission** to test. See the Master Guide's legal section.

## The Arsenal (in engagement order)

| Phase | Folder | Tools | Role in the kill chain |
|---|---|---|---|
| **0 — Start Here** | [`00-start-here/`](00-start-here/) | Master Guide & Study Path · Glossary & Concepts Handbook | The vocabulary, the methodology, and the order to learn everything. |
| **1 — Foundation / Proxies** | [`01-foundation-proxies/`](01-foundation-proxies/) | Burp Suite · OWASP ZAP | See, edit, replay, and attack HTTP. The core workbench everything routes through. |
| **2 — Reconnaissance** | [`02-recon/`](02-recon/) | Nmap · httpx & Amass · Sublist3r · LinkFinder & SecretFinder | Map the attack surface — hosts, ports, services, subdomains, live web apps, JS secrets. |
| **3 — Content Discovery** | [`03-content-discovery/`](03-content-discovery/) | Feroxbuster · ffuf · CeWL | Find the hidden — unlinked files/dirs, parameters, vhosts, and target-specific wordlists. |
| **4 — Scanning** | [`04-scanning/`](04-scanning/) | Nikto · Nuclei · WPScan | Sweep the mapped surface for *known* issues, CVEs, and misconfigurations. |
| **5 — Exploitation** | [`05-exploitation/`](05-exploitation/) | sqlmap · Dalfox (& XSStrike) · Commix · jwt_tool | Confirm and exploit the injection classes + auth/token flaws you found. |
| **6 — Credential Attacks** | [`06-credential-attacks/`](06-credential-attacks/) | Hashcat & Hydra | Crack dumped hashes offline (Hashcat); brute-force live logins online (Hydra). |
| **7 — Framework / Post-Ex** | [`07-framework-post-exploitation/`](07-framework-post-exploitation/) | Metasploit Framework | The capstone — exploitation, payloads, pivoting, and post-exploitation, tying it all together. |

## Tool Index (A → Z)

| Tool | Phase | Reference |
|---|---|---|
| Amass (with httpx) | Recon | [02-recon/httpx-Amass-Complete-Reference.md](02-recon/httpx-Amass-Complete-Reference.md) |
| Burp Suite | Foundation | [01-foundation-proxies/Burp-Suite-Complete-Reference.md](01-foundation-proxies/Burp-Suite-Complete-Reference.md) |
| CeWL | Content Discovery / Creds | [03-content-discovery/CeWL-Complete-Reference.md](03-content-discovery/CeWL-Complete-Reference.md) |
| Commix | Exploitation | [05-exploitation/Commix-Complete-Reference.md](05-exploitation/Commix-Complete-Reference.md) |
| Dalfox (& XSStrike) | Exploitation | [05-exploitation/Dalfox-XSStrike-Complete-Reference.md](05-exploitation/Dalfox-XSStrike-Complete-Reference.md) |
| Feroxbuster | Content Discovery | [03-content-discovery/Feroxbuster-Complete-Reference.md](03-content-discovery/Feroxbuster-Complete-Reference.md) |
| ffuf | Content Discovery | [03-content-discovery/ffuf-Complete-Reference.md](03-content-discovery/ffuf-Complete-Reference.md) |
| Hashcat & Hydra | Credential Attacks | [06-credential-attacks/Hashcat-Hydra-Complete-Reference.md](06-credential-attacks/Hashcat-Hydra-Complete-Reference.md) |
| httpx | Recon | [02-recon/httpx-Amass-Complete-Reference.md](02-recon/httpx-Amass-Complete-Reference.md) |
| jwt_tool | Exploitation | [05-exploitation/jwt_tool-Complete-Reference.md](05-exploitation/jwt_tool-Complete-Reference.md) |
| LinkFinder & SecretFinder | Recon | [02-recon/LinkFinder-SecretFinder-Complete-Reference.md](02-recon/LinkFinder-SecretFinder-Complete-Reference.md) |
| Metasploit Framework | Framework / Post-Ex | [07-framework-post-exploitation/Metasploit-Framework-Complete-Reference.md](07-framework-post-exploitation/Metasploit-Framework-Complete-Reference.md) |
| Nikto | Scanning | [04-scanning/Nikto-Complete-Reference.md](04-scanning/Nikto-Complete-Reference.md) |
| Nmap | Recon | [02-recon/Nmap-Complete-Reference.md](02-recon/Nmap-Complete-Reference.md) |
| Nuclei | Scanning | [04-scanning/Nuclei-Complete-Reference.md](04-scanning/Nuclei-Complete-Reference.md) |
| OWASP ZAP | Foundation | [01-foundation-proxies/OWASP-ZAP-Complete-Reference.md](01-foundation-proxies/OWASP-ZAP-Complete-Reference.md) |
| sqlmap | Exploitation | [05-exploitation/sqlmap-Complete-Reference.md](05-exploitation/sqlmap-Complete-Reference.md) |
| Sublist3r | Recon | [02-recon/Sublist3r-Complete-Reference.md](02-recon/Sublist3r-Complete-Reference.md) |
| WPScan | Scanning | [04-scanning/WPScan-Complete-Reference.md](04-scanning/WPScan-Complete-Reference.md) |

## Suggested Learning Sequence

**Phase 0 — Foundations (before any tool):** the **Glossary & Concepts Handbook**, plus build a lab (Kali + vulnerable targets). This is the single highest-leverage step — every tool manipulates these primitives.

**Phase 1 — See & manipulate traffic:** **Burp Suite** first (then **ZAP**). Once you can intercept, read, edit, and replay any HTTP request, every other tool clicks. Do manual testing here before automating anything.

**Phase 2 — Recon & mapping:** **Nmap** → **Amass + httpx** (Sublist3r first only as a gentle concept-teacher) → **LinkFinder / SecretFinder**. You can't test what you haven't found.

**Phase 3 — Content discovery:** **Feroxbuster** → **ffuf** → **CeWL**. Expand the surface with unlinked/unguessable content.

**Phase 4 — Scanning:** **Nikto** → **Nuclei** → **WPScan** (when the target is WordPress). Sweep for known issues to produce leads you verify next.

**Phase 5 — Exploitation:** **sqlmap** first (its channel model transfers everywhere) → **Dalfox** (XSS) → **Commix** (command injection) → **jwt_tool** (auth/JWT). Always confirm a vuln manually in Burp before running the automated exploiter.

**Phase 6 — Credential attacks:** **Hashcat** (offline cracking) then **Hydra** (online brute-forcing), folding in CeWL wordlists.

**Phase 7 — Framework & post-exploitation:** **Metasploit** last, deliberately — learn it after you can exploit manually, so you understand what it's automating.

---

### Related material in this repo

- **[../TOOLS_CHEAT_SHEET.md](../TOOLS_CHEAT_SHEET.md)** — quick command cheat sheet across 50+ infosec tools.
- **[../web_security_attacks_complete_guide.md](../web_security_attacks_complete_guide.md)** — the *vulnerabilities* these tools find and exploit, explained in depth.
- **[../threat_modeling_complete_guide.md](../threat_modeling_complete_guide.md)** — how to reason about where to point these tools.
- **[../system breakdowns/](../system%20breakdowns/)** — architectural deep-dives on real-world systems.

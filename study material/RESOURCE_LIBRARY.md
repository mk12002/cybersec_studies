RESOURCE_LIBRARY.md

# RESOURCE LIBRARY (CURATED FOR BANGALORE SECURITY CAREERS)

**Goal:** Save you time with the highest ROI resources across AppSec, CloudSec, Detection, and ML/AI Security.

---

## Table of Contents

- [How to Use This Library](#how-to-use-this-library)
- [Web/AppSec Resources](#webappsec-resources)
- [Cloud Security Resources](#cloud-security-resources)
- [Detection Engineering Resources](#detection-engineering-resources)
- [ML/AI Security Resources](#mlai-security-resources)
- [Programming for Security](#programming-for-security)
- [Hands-On Labs and Platforms](#hands-on-labs-and-platforms)
- [Books Worth Reading](#books-worth-reading)
- [Newsletters and Staying Current](#newsletters-and-staying-current)
- [Podcasts and YouTube](#podcasts-and-youtube)
- [India-Specific Resources](#india-specific-resources)
- [Tools Reference](#tools-reference)
- [Resource Evaluation Framework](#resource-evaluation-framework)

---

## How to Use This Library

### The 1-1-1 Rule

For each topic you're learning:
- **1 Primary Resource:** Your main learning source
- **1 Hands-on Platform:** Where you practice
- **1 Reference:** For deeper dives when needed

**Don't:**
- Collect 20 resources and read none
- Jump between resources constantly
- Spend more time organizing than learning

### Quality Indicators

Before investing time in any resource, check:

| Indicator | Good Sign | Warning Sign |
|-----------|-----------|--------------|
| **Last Updated** | Within 2 years | 5+ years old |
| **Hands-on Labs** | Included | Theory only |
| **Real-world Focus** | Based on actual work | Academic only |
| **Portfolio Value** | Can build something | Just reading |
| **Cost vs Value** | Free or reasonable | Expensive without justification |

---

## Web/AppSec Resources

### Primary Learning (Pick ONE)

#### PortSwigger Web Security Academy [FREE]
**Link:** https://portswigger.net/web-security
**Best For:** Web application security mastery
**Time:** 80-120 hours for full completion
**Why It's Best:**
- Created by Burp Suite makers
- Most comprehensive free resource
- Hands-on labs for every topic
- Industry-recognized completion badges

**Recommended Path:**
```
1. SQL Injection (18 labs)
2. Authentication (14 labs)
3. Access Control (13 labs)
4. XSS (30 labs)
5. CSRF (12 labs)
6. SSRF (7 labs)
7. Business Logic (12 labs)
```

#### OWASP Resources [FREE]
**Primary Reference Documents:**

| Resource | Link | Use For |
|----------|------|---------|
| OWASP Top 10 | owasp.org/Top10 | Web vulnerability baseline |
| OWASP API Top 10 | owasp.org/API-Security | API security focus |
| OWASP ASVS | owasp.org/ASVS | Security verification standard |
| OWASP Testing Guide | owasp.org/testing-guide | Testing methodology |
| Cheat Sheet Series | cheatsheetseries.owasp.org | Quick reference |

**How to Use OWASP:**
```
1. Read OWASP Top 10 first (2-3 hours)
2. Map to PortSwigger labs
3. Use Cheat Sheets as quick reference
4. Reference Testing Guide for methodology
5. Use ASVS for comprehensive testing
```

### Vulnerable Applications for Practice

| Application | Focus | Setup Difficulty |
|-------------|-------|------------------|
| OWASP Juice Shop | Full OWASP Top 10 | Docker (easy) |
| DVWA | Classic web vulns | Docker (easy) |
| WebGoat | Learning-focused | Docker (easy) |
| HackTheBox Web Challenges | CTF-style | Browser (easiest) |
| bWAPP | 100+ vulnerabilities | VM (moderate) |

**Quick Start Commands:**
```bash
# Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# DVWA
docker run -d -p 80:80 vulnerables/web-dvwa

# WebGoat
docker run -d -p 8080:8080 -p 9090:9090 webgoat/webgoat
```

### API Security Resources

| Resource | Type | Link |
|----------|------|------|
| OWASP API Security Top 10 | Guide | owasp.org/API-Security |
| API Security Checklist | Checklist | github.com/shieldfy/API-Security-Checklist |
| Postman Learning Center | Course | learning.postman.com |
| crAPI (OWASP) | Vulnerable API | github.com/OWASP/crAPI |

### Burp Suite Learning

| Resource | Type | Cost |
|----------|------|------|
| PortSwigger Academy | Official | Free |
| Burp Suite Documentation | Reference | Free |
| "Real-World Bug Hunting" Book | Book | ~$40 |

---

## Cloud Security Resources

### AWS Security

#### Primary Learning

| Resource | Type | Cost | Quality |
|----------|------|------|---------|
| AWS Security Specialty Path (Skill Builder) | Course | Free tier | Excellent |
| flaws.cloud | CTF | Free | Excellent |
| flaws2.cloud | CTF | Free | Excellent |
| AWS Security Best Practices (Whitepaper) | Doc | Free | Essential |

**AWS Security Learning Path:**
```
Week 1-2: IAM Deep Dive
├── IAM policies, roles, trust relationships
├── STS, AssumeRole, federation
├── Organizations, SCPs
└── Lab: Build multi-account setup

Week 3-4: Network Security
├── VPC, subnets, NACLs, SGs
├── VPC endpoints, PrivateLink
├── WAF, Shield, Network Firewall
└── Lab: Secure VPC architecture

Week 5-6: Data Security
├── S3 security, bucket policies
├── KMS, CloudHSM
├── Secrets Manager, Parameter Store
└── Lab: Encryption implementation

Week 7-8: Detection & Monitoring
├── CloudTrail, CloudWatch
├── GuardDuty, Security Hub
├── Config Rules
└── Lab: Centralized logging

Week 9-10: Incident Response
├── Automated remediation
├── EventBridge, Lambda
├── Forensics basics
└── Lab: IR automation
```

#### AWS Documentation (Essential Reading)

| Document | Link | Priority |
|----------|------|----------|
| Security Pillar | docs.aws.amazon.com/wellarchitected | Essential |
| IAM Best Practices | docs.aws.amazon.com/IAM | Essential |
| Security Best Practices | docs.aws.amazon.com/security | High |
| Incident Response Guide | AWS IR whitepaper | High |

#### Hands-On AWS Labs

| Resource | Focus | Cost |
|----------|-------|------|
| flaws.cloud | AWS exploitation | Free |
| flaws2.cloud | Attack + defense | Free |
| CloudGoat | Vulnerable AWS | Free |
| AWS Workshops | Official labs | Free |
| Sadcloud | Terraform misconfigs | Free |

### Azure Security

#### Primary Learning

| Resource | Type | Cost | Quality |
|----------|------|------|---------|
| Microsoft Learn AZ-500 Path | Course | Free | Excellent |
| John Savill's AZ-500 (YouTube) | Videos | Free | Excellent |
| Azure Security Documentation | Docs | Free | Good |

**Azure Security Learning Path:**
```
Week 1-2: Identity & Access
├── Entra ID (Azure AD)
├── Conditional Access
├── Privileged Identity Management
└── Lab: Complete identity solution

Week 3-4: Network Security
├── NSGs, Azure Firewall
├── Application Gateway, WAF
├── Private Link, Service Endpoints
└── Lab: Hub-spoke network security

Week 5-6: Data & Compute Security
├── Key Vault
├── Storage encryption
├── VM security, disk encryption
└── Lab: Secure workload deployment

Week 7-8: Security Operations
├── Microsoft Defender for Cloud
├── Microsoft Sentinel
├── Azure Policy, Blueprints
└── Lab: SIEM implementation
```

#### Azure Documentation

| Document | Link |
|----------|------|
| Azure Security Documentation | docs.microsoft.com/azure/security |
| Azure Security Benchmark | Microsoft Security Benchmark |
| Defender for Cloud Docs | Defender documentation |
| Sentinel Documentation | Sentinel docs |

### Multi-Cloud & General

| Resource | Focus | Link |
|----------|-------|------|
| CIS Benchmarks | Compliance baselines | cisecurity.org/cis-benchmarks |
| Cloud Security Alliance | Research/frameworks | cloudsecurityalliance.org |
| NIST Cloud Guidelines | SP 800-144, 800-145 | nist.gov |

---

## Detection Engineering Resources

### MITRE ATT&CK

| Resource | Type | Link |
|----------|------|------|
| ATT&CK Matrix | Framework | attack.mitre.org |
| ATT&CK Navigator | Visualization | mitre-attack.github.io/attack-navigator |
| ATT&CK Workbench | Customization | github.com/center-for-threat-informed-defense |
| MITRE ATLAS | ML threats | atlas.mitre.org |

**How to Use ATT&CK:**
```
1. Understand tactics (WHY)
2. Learn techniques (HOW)
3. Map detections to techniques
4. Prioritize by relevance to your environment
5. Build detection coverage matrix
```

### Sigma Rules

| Resource | Type | Link |
|----------|------|------|
| Sigma HQ Repository | Rules | github.com/SigmaHQ/sigma |
| Sigma Specification | Docs | github.com/SigmaHQ/sigma-specification |
| Sigma CLI | Tool | github.com/SigmaHQ/sigma-cli |
| pySigma | Python library | github.com/SigmaHQ/pySigma |

**Sigma Learning Path:**
```
Week 1: Sigma Basics
├── Rule format and structure
├── Log source mapping
├── Condition syntax
└── Write 5 basic rules

Week 2: Sigma Advanced
├── Aggregation rules
├── Correlation rules
├── Custom log sources
└── Write 10 more rules

Week 3: Sigma Operations
├── Convert to SIEM queries
├── Testing rules
├── CI/CD for detections
└── Build detection pipeline
```

### SIEM-Specific Resources

#### Splunk

| Resource | Type | Cost |
|----------|------|------|
| Splunk Fundamentals 1 | Course | Free |
| Splunk BOTS (Boss of the SOC) | CTF | Free |
| Splunk Search Tutorial | Docs | Free |
| Splunk Security Essentials | App | Free |

#### Microsoft Sentinel

| Resource | Type | Cost |
|----------|------|------|
| SC-200 Learning Path | Course | Free |
| KQL (Kusto) Tutorial | Docs | Free |
| Sentinel GitHub | Rules | Free |
| Sentinel Training Lab | Lab | Free with Azure trial |

**KQL Quick Reference:**
```kql
// Basic search
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize count() by Account

// Threat hunting query
let threshold = 10;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName
| where FailedAttempts > threshold
```

### Detection Engineering Blogs

| Blog | Focus | Link |
|------|-------|------|
| SpecterOps | Adversary simulation | posts.specterops.io |
| Red Canary | Detection strategies | redcanary.com/blog |
| Elastic Security | Detection rules | elastic.co/security-labs |
| Microsoft Security | Threat research | microsoft.com/security/blog |

---

## ML/AI Security Resources

### Primary References

| Resource | Type | Link |
|----------|------|------|
| OWASP LLM Top 10 | Framework | owasp.org/llm-top-10 |
| MITRE ATLAS | ML threat matrix | atlas.mitre.org |
| NIST AI RMF | Risk framework | nist.gov/ai-rmf |
| Google Secure AI Framework | Guidelines | safety.google/saif |

### Research Papers (Accessible)

| Topic | Paper/Resource |
|-------|----------------|
| Prompt Injection | "Ignore This Title and HackAPrompt" |
| Model Extraction | "Stealing Machine Learning Models via Prediction APIs" |
| Adversarial Examples | "Explaining and Harnessing Adversarial Examples" |
| Data Poisoning | "Poisoning Attacks against Support Vector Machines" |
| Membership Inference | "Membership Inference Attacks Against ML Models" |

### Hands-On ML Security

| Resource | Focus | Link |
|----------|-------|------|
| Adversarial Robustness Toolbox | Defense | github.com/Trusted-AI/adversarial-robustness-toolbox |
| TextAttack | NLP attacks | github.com/QData/TextAttack |
| Garak | LLM vulnerability scanner | github.com/leondz/garak |
| Rebuff | Prompt injection detection | github.com/protectai/rebuff |

### ML Security Learning Path

```
Phase 1: Understanding (Month 1)
├── Read OWASP LLM Top 10
├── Explore MITRE ATLAS
├── Understand threat categories
└── Document key risks

Phase 2: Hands-On (Month 2)
├── Set up LLM security testing
├── Practice prompt injection
├── Build detection mechanisms
└── Create test suite

Phase 3: Building (Month 3)
├── Secure ML inference API
├── Input validation for ML
├── Output filtering
└── Monitoring and alerting

Phase 4: Advanced (Month 4+)
├── Model extraction detection
├── Adversarial input detection
├── Data poisoning awareness
└── Red teaming ML systems
```

---

## Programming for Security

### Python for Security

| Resource | Type | Cost |
|----------|------|------|
| Automate the Boring Stuff | Book (free online) | Free |
| Black Hat Python, 2nd Ed | Book | ~$40 |
| Violent Python | Book | ~$35 |
| Python for Defenders | Blog series | Free |

**Essential Python Libraries:**

```python
# Web requests and scraping
import requests
from bs4 import BeautifulSoup

# Security-specific
import scapy       # Network packets
import pwntools    # CTF/exploitation
import cryptography # Crypto operations

# Data analysis
import pandas
import json

# Automation
import subprocess
import argparse
```

**Python Security Script Template:**
```python
#!/usr/bin/env python3
"""
Security Tool: [Name]
Purpose: [What it does]
Author: [Your name]
"""

import argparse
import logging
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description='Tool description')
    parser.add_argument('-t', '--target', required=True, help='Target')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Main logic here
    logger.info(f"Processing target: {args.target}")

if __name__ == '__main__':
    main()
```

### Bash/Shell Scripting

| Resource | Type | Cost |
|----------|------|------|
| Linux Command Line (William Shotts) | Book (free online) | Free |
| OverTheWire Bandit | Wargame | Free |
| ExplainShell | Reference | Free |

**Essential Bash for Security:**
```bash
# File operations
find /var/log -name "*.log" -mtime -1
grep -r "password" /etc/

# Network
curl -s -o /dev/null -w "%{http_code}" https://target.com
nc -zv target.com 1-1000

# Text processing
cat file.txt | sort | uniq -c | sort -rn
awk '{print $1}' access.log | sort | uniq -c
```

### Go for Security Tools

| Resource | Type | Use Case |
|----------|------|----------|
| Go by Example | Tutorial | Learning Go |
| Black Hat Go | Book | Security tools |
| ProjectDiscovery tools | Examples | Real tools |

---

## Hands-On Labs and Platforms

### Comprehensive Comparison

| Platform | Best For | Cost | Quality |
|----------|----------|------|---------|
| **PortSwigger** | Web security | Free | Excellent |
| **TryHackMe** | Beginners | Free/$8/mo | Excellent |
| **HackTheBox** | Intermediate+ | Free/$14/mo | Excellent |
| **PicoCTF** | CTF basics | Free | Good |
| **flaws.cloud** | AWS | Free | Excellent |
| **CyberDefenders** | Blue team | Free | Good |

### Platform Selection Guide

```
If you're a complete beginner:
└── Start with TryHackMe → Move to PortSwigger

If you know basics but need structure:
└── PortSwigger Academy → HackTheBox

If you want cloud security:
└── flaws.cloud → AWS Security labs

If you want detection/blue team:
└── CyberDefenders → LetsDefend

If you want offensive security career:
└── TryHackMe → HackTheBox → OSCP labs
```

### Free Lab Resources

| Lab | Focus | Setup |
|-----|-------|-------|
| DVWA | Web basics | Docker |
| Juice Shop | Modern web | Docker |
| Metasploitable | Network attacks | VM |
| VulnHub | Various | VM |
| HackTheBox Starting Point | Guided hacking | Browser |

---

## Books Worth Reading

### Essential Security Books

| Book | Author | Best For |
|------|--------|----------|
| The Web Application Hacker's Handbook | Stuttard & Pinto | AppSec foundations |
| Real-World Bug Hunting | Peter Yaworski | Bug bounty |
| Hacking: The Art of Exploitation | Jon Erickson | Deep technical |
| The Tangled Web | Michal Zalewski | Browser security |
| Practical Cloud Security | Chris Dotson | Cloud security |

### Books by Career Stage

**Beginner (0-1 year):**
- "The Web Application Hacker's Handbook"
- "Real-World Bug Hunting"
- "Penetration Testing" (Georgia Weidman)

**Intermediate (1-3 years):**
- "Practical Cloud Security"
- "Black Hat Python"
- "The Art of Intrusion" (Kevin Mitnick)

**Advanced (3+ years):**
- "Hacking: The Art of Exploitation"
- "The Shellcoder's Handbook"
- "Serious Cryptography"

### Free Books/Resources

| Resource | Topic | Link |
|----------|-------|------|
| OWASP Testing Guide | Web testing | owasp.org |
| AWS Security Whitepapers | Cloud security | aws.amazon.com |
| Crypto101 | Cryptography | crypto101.io |
| CTF Field Guide | CTF basics | trailofbits.github.io/ctf |

---

## Newsletters and Staying Current

### Must-Subscribe Newsletters

| Newsletter | Focus | Frequency | Link |
|------------|-------|-----------|------|
| tl;dr sec | Security digest | Weekly | tldrsec.com |
| This Week in Security | News roundup | Weekly | thisweekin4n6.com |
| Risky Business | Security news | Weekly | risky.biz |
| CloudSecList | Cloud security | Weekly | cloudseclist.com |
| API Security Newsletter | API security | Weekly | apisecurity.io |

### News Sites

| Site | Focus | Quality |
|------|-------|---------|
| Krebs on Security | Investigations | Excellent |
| The Hacker News | Breaking news | Good |
| BleepingComputer | Security news | Good |
| Dark Reading | Enterprise security | Good |
| SANS ISC | Daily handlers | Excellent |

### Twitter/X Follows

**Must-Follow for Security:**
- @SwiftOnSecurity (security + humor)
- @troaborist (detection)
- @_JohnHammond (CTF/education)
- @NahamSec (bug bounty)
- @jhaddix (recon/bounty)
- @taboramina (cloud security)

### Staying Current Strategy

```
Daily (10 min):
├── Skim tl;dr sec or newsletter
├── Check 1-2 security news sites
└── Note anything relevant to your focus

Weekly (30 min):
├── Read 1 deep-dive article
├── Check new CVEs in your stack
└── Review community discussions

Monthly (2 hours):
├── Explore new tools/techniques
├── Update your methodology
└── Review and organize bookmarks
```

---

## Podcasts and YouTube

### Security Podcasts

| Podcast | Focus | Length | Best For |
|---------|-------|--------|----------|
| Darknet Diaries | Stories | 1 hour | Entertainment + learning |
| Risky Business | News | 1 hour | Industry news |
| Security Now | Technical | 2 hours | Deep technical |
| Malicious Life | History | 30 min | Security history |
| Smashing Security | News | 45 min | News + humor |

### YouTube Channels

| Channel | Focus | Quality |
|---------|-------|---------|
| John Hammond | CTF, Malware | Excellent |
| LiveOverflow | Technical deep dives | Excellent |
| NetworkChuck | Beginner-friendly | Good |
| IppSec | HTB walkthroughs | Excellent |
| Professor Messer | Certifications | Excellent |
| David Bombal | Networking + security | Good |
| The Cyber Mentor | Pentesting | Good |
| John Savill | Azure | Excellent |

### YouTube Learning Paths

**Web Security Path:**
```
1. NetworkChuck security basics
2. John Hammond web hacking
3. LiveOverflow technical details
4. IppSec for machine walkthroughs
```

**Cloud Security Path:**
```
1. AWS/Azure official channels
2. John Savill for Azure
3. Adrian Cantrill clips for AWS
4. A Cloud Guru YouTube
```

---

## India-Specific Resources

### Communities

#### null Community (Primary)
- **Website:** null.community
- **Bangalore Chapter:** Very active
- **Events:** Monthly meetups, conferences
- **Value:** Networking, learning, CTF teams

**How to Engage:**
```
1. Create account on null.community
2. Join Bangalore chapter
3. Attend null Puliya (beginner sessions)
4. Progress to null Humla/Bachaav
5. Join a CTF team
6. Present your learnings
```

#### OWASP Bangalore
- **Focus:** Application security
- **Events:** Chapter meetings, workshops
- **Value:** AppSec network, project contributions

#### Infosec Meetup Groups

| Group | Platform | Focus |
|-------|----------|-------|
| null Bangalore | null.community | General security |
| OWASP Bangalore | OWASP/Meetup | AppSec |
| Bangalore Security Meetup | Meetup.com | Various |
| Cloud Security Alliance Bangalore | CSA | Cloud security |

### Indian Conferences

| Conference | Location | Month | Focus |
|------------|----------|-------|-------|
| Nullcon | Goa | March | All security |
| BSides Bangalore | Bangalore | Varies | Community |
| c0c0n | Kerala | Sept | Gov + enterprise |
| OWASP India | Varies | Varies | AppSec |
| Ground Zero | Delhi | Nov | Offensive |

### Indian Security Professionals to Follow

Look for speakers from:
- Nullcon talks
- BSides India talks
- null community leaders
- OWASP India chapter leads

### India-Specific Job Resources

| Platform | Focus | Notes |
|----------|-------|-------|
| LinkedIn | All levels | Primary platform |
| Naukri | All levels | Filter by security |
| Instahyre | Startups | Good for product companies |
| null community | Jobs board | Security-specific |
| Company careers pages | Direct | Best for target companies |

---

## Tools Reference

### Web Application Testing

| Tool | Purpose | Cost |
|------|---------|------|
| Burp Suite Community | Web proxy | Free |
| Burp Suite Pro | Advanced web testing | $449/year |
| OWASP ZAP | Web proxy | Free |
| Postman | API testing | Free tier |
| SQLMap | SQL injection | Free |
| ffuf | Fuzzing | Free |
| Nuclei | Vulnerability scanning | Free |

### Reconnaissance

| Tool | Purpose | Link |
|------|---------|------|
| Subfinder | Subdomain enumeration | projectdiscovery |
| Amass | Attack surface mapping | OWASP |
| httpx | HTTP probing | projectdiscovery |
| Shodan | Internet scanning | shodan.io |
| theHarvester | OSINT | Free |

### Cloud Security

| Tool | Purpose | Cloud |
|------|---------|-------|
| Prowler | Security assessment | AWS |
| ScoutSuite | Multi-cloud audit | Multi |
| Checkov | IaC scanning | Multi |
| tfsec | Terraform security | Terraform |
| CloudSploit | Configuration audit | Multi |

### Detection Engineering

| Tool | Purpose |
|------|---------|
| Sigma | Detection rules |
| Yara | Malware rules |
| OSQuery | Endpoint querying |
| Velociraptor | DFIR |
| Chainsaw | Log analysis |

### Vulnerability Scanning

| Tool | Purpose | Cost |
|------|---------|------|
| Nmap | Port scanning | Free |
| Nessus | Vulnerability scanning | Free tier |
| OpenVAS | Vulnerability scanning | Free |
| Trivy | Container scanning | Free |
| Semgrep | SAST | Free tier |

---

## Resource Evaluation Framework

### Before Adding Any Resource

Ask these questions:

| Question | Good Answer | Skip If |
|----------|-------------|---------|
| Is it updated recently? | Within 2 years | 5+ years old |
| Does it have hands-on? | Labs included | Theory only |
| Does it map to jobs? | Yes, clearly | Academic only |
| Can I build something? | Yes | Just reading |
| What's the time investment? | Clear estimate | Unclear scope |

### Resource Priority Matrix

| Priority | Criteria | Action |
|----------|----------|--------|
| **P0 (Essential)** | Directly maps to job requirements | Do immediately |
| **P1 (Important)** | Builds foundation for P0 | Do within 1 month |
| **P2 (Useful)** | Nice to have, not critical | Do when time permits |
| **P3 (Optional)** | Interesting but not necessary | Bookmark for later |

### Personal Resource Audit

Every 3 months, review:
```
1. What resources am I actually using?
2. What have I bookmarked but never touched?
3. What gaps do I still have?
4. What should I add/remove?
```

---

## Quick Start Recommendations

### For AppSec Focus

**Primary:**
1. PortSwigger Academy (100+ hours)
2. OWASP Top 10 (reference)
3. Real-World Bug Hunting (book)

**Secondary:**
- TryHackMe Web path
- Juice Shop practice
- Bug bounty programs

### For Cloud Security Focus

**Primary:**
1. AWS Skill Builder or Microsoft Learn (80+ hours)
2. flaws.cloud series (20 hours)
3. Cloud provider security docs

**Secondary:**
- Prowler/ScoutSuite hands-on
- CIS Benchmarks review
- Cloud security blogs

### For Detection Engineering Focus

**Primary:**
1. MITRE ATT&CK (ongoing reference)
2. Sigma rules repository
3. Splunk Fundamentals or SC-200

**Secondary:**
- CyberDefenders challenges
- Blue Team Labs
- Detection blogs

### For ML Security Focus

**Primary:**
1. OWASP LLM Top 10
2. MITRE ATLAS
3. Hands-on with your own LLM apps

**Secondary:**
- Research papers
- ART (Adversarial Robustness Toolbox)
- ML security tools

---

## Next Steps

1. **Identify your primary focus** (AppSec/Cloud/Detection/ML)
2. **Select 1 primary resource** from that section
3. **Set up 1 hands-on platform**
4. **Bookmark 1-2 references** for deep dives
5. **Subscribe to 2 newsletters** for staying current
6. **Schedule weekly learning time** (minimum 6 hours)

**Remember:** Depth beats breadth. Master one area before expanding.


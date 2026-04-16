# CTF AND BUG BOUNTY GUIDE (BEGINNER TO JOB-READY)

**Focus:** Ethical, legal, portfolio-friendly learning for Bangalore job market

---

## Table of Contents

- [Rule #0: Stay Legal and Ethical](#rule-0-stay-legal-and-ethical)
- [Why CTFs and Bug Bounty Matter](#why-ctfs-and-bug-bounty-matter)
- [Skill Map: What to Practice](#skill-map-what-to-practice)
- [CTF Platforms Guide](#ctf-platforms-guide)
- [12-Week CTF Practice Plan](#12-week-ctf-practice-plan)
- [Bug Bounty Getting Started](#bug-bounty-getting-started)
- [Methodology and Checklists](#methodology-and-checklists)
- [Write-Up Templates](#write-up-templates)
- [Building Your Portfolio](#building-your-portfolio)
- [India Community](#india-community)

---

## Rule #0: Stay Legal and Ethical

### CTFs - Safe by Design
- CTFs are intentionally vulnerable - designed to be attacked
- Follow competition/platform rules strictly
- Don't attack infrastructure outside the challenge scope
- Respect other participants

### Bug Bounty - Permission Required
- ONLY test targets with explicit bug bounty programs
- Read and follow program scope carefully
- Never test assets not listed in scope
- Report responsibly - no public disclosure before fix

### The Golden Rules

```
1. No permission = No testing (ever)
2. Stay within defined scope
3. Don't access/exfiltrate real user data
4. Report findings professionally
5. Wait for fix before any disclosure
6. When in doubt, ask the program
```

### Legal Protections in India

- IT Act 2000 Section 66 covers unauthorized access
- Bug bounty safe harbor only protects in-scope testing
- Keep detailed logs of your testing
- Save all communications with programs

---

## Why CTFs and Bug Bounty Matter

### For Hiring in Bangalore

| Benefit | How It Helps |
|---------|--------------|
| **Real Stories** | Interview answers with actual examples |
| **Write-ups** | Published proof of security thinking |
| **Practical Skills** | Faster learning than theory alone |
| **Recognition** | Hall of fame entries on profiles |
| **Portfolio Artifacts** | GitHub repos of solutions |
| **Community Cred** | Known in null/OWASP circles |

### What Recruiters See

```
Strong Candidate:
├── "Found and reported 5 valid bugs to HackerOne programs"
├── "Published 20+ CTF write-ups on Medium"
├── "Ranked top 5% on TryHackMe"
└── "Active contributor to null Bangalore CTF team"

Weak Candidate:
├── "Interested in bug bounty"
├── "Learning hacking"
└── No demonstrated results
```

### Skills Developed

| Through CTFs | Through Bug Bounty |
|--------------|-------------------|
| Foundational techniques | Real-world complexity |
| Structured learning | Business logic understanding |
| Time-pressured problem solving | Professional reporting |
| Team collaboration | Responsible disclosure |
| Creative thinking | Scope management |

---

## Skill Map: What to Practice

### Web/AppSec Skills (Highest Demand)

| Skill | Priority | Practice Platform |
|-------|----------|-------------------|
| SQL Injection | Critical | PortSwigger |
| XSS (all types) | Critical | PortSwigger |
| IDOR/BOLA | Critical | PortSwigger, Real programs |
| SSRF | High | PortSwigger |
| Authentication Bugs | High | PortSwigger |
| Business Logic | High | Real bug bounty |
| API Security | Critical | PortSwigger, Postman |
| File Upload | Medium | PortSwigger |
| Deserialization | Medium | PortSwigger |

**Beginner Focus (First 3 Months):**
```
1. SQL Injection (all variations)
2. XSS (reflected, stored, DOM)
3. IDOR/BOLA (access control)
4. Authentication bypasses
5. CSRF
```

### Cloud Security Skills

| Skill | Priority | Practice Platform |
|-------|----------|-------------------|
| S3 Misconfigurations | High | flaws.cloud |
| IAM Issues | High | flaws.cloud, flaws2.cloud |
| Metadata Service | High | flaws.cloud |
| SSRF to Cloud | High | Custom labs |
| Public Exposure | Medium | Real programs |

**Practice Path:**
```
Week 1-2: Complete flaws.cloud (all levels)
Week 3-4: Complete flaws2.cloud (attacker + defender)
Week 5-6: Try CloudGoat scenarios
Week 7-8: Build cloud security project
```

### Detection/Blue Team Skills

| Skill | Priority | Practice |
|-------|----------|----------|
| Log Analysis | High | Blue Team Labs |
| Sigma Rules | High | SigmaHQ repo |
| MITRE Mapping | High | ATT&CK Navigator |
| Threat Hunting | Medium | Splunk BOTS |
| Incident Response | Medium | CyberDefenders |

### ML/AI Security Skills

| Skill | Priority | Practice |
|-------|----------|----------|
| Prompt Injection | High | Your own LLM apps |
| Jailbreaking | Medium | Research + documentation |
| Model Analysis | Medium | Academic papers |
| Input Validation | High | Custom projects |

---

## CTF Platforms Guide

### Tier 1: Beginner-Friendly (Start Here)

#### TryHackMe
- **Best For:** Complete beginners, guided learning
- **Cost:** Free tier available, Premium ~₹800/month
- **Format:** Guided rooms with walkthroughs
- **Time Commitment:** 2-4 hours/week minimum

**Recommended Learning Paths:**
```
1. Pre-Security (start here)
2. Complete Beginner
3. Web Fundamentals
4. Jr Penetration Tester
5. CompTIA Pentest+
```

**Key Rooms to Complete:**
- OWASP Top 10
- Burp Suite basics
- SQL Injection
- Authentication Bypass
- IDOR
- SSRF

#### PortSwigger Web Security Academy
- **Best For:** Web application security mastery
- **Cost:** Completely FREE
- **Format:** Labs with detailed explanations
- **Time Commitment:** 4-6 hours/week for full coverage

**Learning Path (Recommended Order):**
```
Phase 1: Foundations
├── SQL Injection (all 18 labs)
├── Authentication (all 14 labs)
├── Path Traversal (all 6 labs)
└── Command Injection (all 5 labs)

Phase 2: Client-Side
├── XSS (all 30 labs)
├── CSRF (all 12 labs)
└── CORS (all 4 labs)

Phase 3: Server-Side
├── SSRF (all 7 labs)
├── XXE (all 9 labs)
├── Access Control (all 13 labs)
└── Business Logic (all 12 labs)

Phase 4: Advanced
├── HTTP Request Smuggling
├── Web Cache Poisoning
├── Prototype Pollution
└── Server-Side Template Injection
```

#### PicoCTF
- **Best For:** CTF fundamentals, students
- **Cost:** Free
- **Format:** Jeopardy-style challenges
- **Categories:** Web, Forensics, Crypto, Binary, Reverse

### Tier 2: Intermediate Platforms

#### Hack The Box
- **Best For:** Realistic machine exploitation
- **Cost:** Free tier limited, VIP ~₹1,000/month
- **Format:** Vulnerable machines to fully compromise
- **Difficulty:** Harder than TryHackMe

**Progression Path:**
```
1. Starting Point (free, guided)
2. Easy machines (10-15 before moving up)
3. Medium machines (build methodology)
4. Hard machines (when ready)
5. Pro Labs (professional scenarios)
```

**Essential Easy Machines:**
- Lame, Jerry, Blue (Windows basics)
- Bashed, Shocker, Nibbles (Linux basics)
- Netmon, Active (Active Directory intro)

#### HackTheBox Academy
- **Best For:** Structured learning paths
- **Cost:** Subscription-based
- **Format:** Modules with labs

### Tier 3: Specialized Platforms

#### Cloud Security Labs

| Platform | Focus | Cost |
|----------|-------|------|
| flaws.cloud | AWS security | Free |
| flaws2.cloud | AWS attack/defend | Free |
| CloudGoat | AWS exploitation | Free |
| Thunder CTF | GCP security | Free |
| AzureGoat | Azure security | Free |

#### Blue Team / Detection

| Platform | Focus | Cost |
|----------|-------|------|
| CyberDefenders | DFIR challenges | Free |
| Blue Team Labs | SOC scenarios | Free tier |
| LetsDefend | SOC analyst training | Free tier |
| Splunk BOTS | Splunk hunting | Free |

#### Mobile Security

| Platform | Focus | Cost |
|----------|-------|------|
| MOBISEC | Mobile challenges | Free |
| DIVA | Android security | Free |
| OWASP iGoat | iOS security | Free |

---

## 12-Week CTF Practice Plan

**Time Budget:** 6 hours/week
**Goal:** Build solid foundations + portfolio artifacts

### Phase 1: Web Fundamentals (Weeks 1-4)

#### Week 1: SQL Injection Deep Dive
```
Hours Allocation:
├── 2 hrs: PortSwigger SQLi labs (first 8)
├── 2 hrs: PortSwigger SQLi labs (next 5)
├── 1 hr: Write-up for 1 interesting lab
└── 1 hr: Practice on TryHackMe SQL room

Output: 1 write-up published
```

#### Week 2: XSS Mastery
```
Hours Allocation:
├── 2 hrs: Reflected XSS labs
├── 2 hrs: Stored XSS labs
├── 1 hr: DOM XSS labs
└── 1 hr: Write-up on XSS types

Output: 1 write-up comparing XSS types
```

#### Week 3: Authentication Attacks
```
Hours Allocation:
├── 2 hrs: Authentication labs (PortSwigger)
├── 2 hrs: Password reset vulnerabilities
├── 1 hr: 2FA bypass techniques
└── 1 hr: Write-up on auth testing

Output: 1 write-up + testing checklist
```

#### Week 4: Access Control (IDOR/BOLA)
```
Hours Allocation:
├── 2 hrs: Access control labs (PortSwigger)
├── 2 hrs: IDOR finding methodology
├── 1 hr: API access control testing
└── 1 hr: Write-up on IDOR hunting

Output: 1 write-up + IDOR checklist
```

**Phase 1 Deliverables:**
- [ ] 4 published write-ups
- [ ] 40+ labs completed
- [ ] Testing methodology notes
- [ ] Ready for bug bounty basics

### Phase 2: API and Cloud (Weeks 5-8)

#### Week 5: API Security Fundamentals
```
Hours Allocation:
├── 2 hrs: API testing basics (PortSwigger)
├── 2 hrs: Postman/Burp for APIs
├── 1 hr: REST vs GraphQL security
└── 1 hr: Write-up on API testing

Output: 1 API security write-up
```

#### Week 6: API Advanced + SSRF
```
Hours Allocation:
├── 2 hrs: SSRF labs (PortSwigger)
├── 2 hrs: API authentication testing
├── 1 hr: Rate limiting bypass
└── 1 hr: Write-up on SSRF

Output: 1 SSRF write-up
```

#### Week 7: Cloud Security (AWS)
```
Hours Allocation:
├── 2 hrs: flaws.cloud (levels 1-3)
├── 2 hrs: flaws.cloud (levels 4-6)
├── 1 hr: Document findings
└── 1 hr: Write-up on cloud misconfig

Output: 1 cloud security write-up
```

#### Week 8: Cloud Security (Advanced)
```
Hours Allocation:
├── 2 hrs: flaws2.cloud attacker path
├── 2 hrs: flaws2.cloud defender path
├── 1 hr: Cloud security checklist
└── 1 hr: Write-up on cloud attack chains

Output: 1 write-up + cloud checklist
```

**Phase 2 Deliverables:**
- [ ] 4 more write-ups (total: 8)
- [ ] API testing methodology
- [ ] Cloud security fundamentals
- [ ] Ready for intermediate challenges

### Phase 3: Detection + Blue Team (Weeks 9-10)

#### Week 9: Sigma Rules and Detection
```
Hours Allocation:
├── 2 hrs: Sigma rule format learning
├── 2 hrs: Write 5 basic Sigma rules
├── 1 hr: Map to MITRE ATT&CK
└── 1 hr: Document your rules

Output: 5 Sigma rules + documentation
```

#### Week 10: Log Analysis
```
Hours Allocation:
├── 2 hrs: CyberDefenders easy challenge
├── 2 hrs: Blue Team Labs scenario
├── 1 hr: Write detection for findings
└── 1 hr: Threat hunting write-up

Output: 1 blue team write-up
```

### Phase 4: ML Security + Portfolio (Weeks 11-12)

#### Week 11: ML/AI Security
```
Hours Allocation:
├── 2 hrs: Prompt injection testing
├── 2 hrs: Build LLM security tests
├── 1 hr: Document attack patterns
└── 1 hr: Write-up on LLM security

Output: 1 ML security write-up
```

#### Week 12: Portfolio Packaging
```
Hours Allocation:
├── 2 hrs: Clean up all write-ups
├── 2 hrs: Create GitHub portfolio repo
├── 1 hr: Update LinkedIn with achievements
└── 1 hr: Plan next 12 weeks

Output: Complete portfolio ready
```

**12-Week Final Deliverables:**
- [ ] 10+ published write-ups
- [ ] 100+ labs completed
- [ ] Testing methodology documents
- [ ] Sigma rules repository
- [ ] Cloud security knowledge
- [ ] ML security exploration
- [ ] Portfolio-ready GitHub

---

## Bug Bounty Getting Started

### Platform Comparison

| Platform | Best For | Payout | Competition |
|----------|----------|--------|-------------|
| HackerOne | Wide variety | $50-$100K+ | High |
| Bugcrowd | Good programs | $50-$50K+ | High |
| Intigriti | EU programs | €50-€50K+ | Medium |
| YesWeHack | EU focus | €50-€25K+ | Medium |
| Synack | Invite-only | High | Lower (vetted) |

### Getting Started Steps

#### Step 1: Platform Setup (Day 1)
```
1. Create HackerOne account
2. Create Bugcrowd account
3. Complete platform tutorials
4. Read platform policies
5. Set up 2FA
```

#### Step 2: Choose First Program (Day 2-3)
```
Look for programs with:
├── Clear and wide scope
├── Good response time (<1 week)
├── Published bounty table
├── Beginner-friendly tag
└── Active recent payouts
```

**Good First Programs (Examples):**
- Programs with "managed" tag
- Programs paying $50+ for low severity
- Programs with VDP (no bounty but good practice)

#### Step 3: Reconnaissance (Day 4-7)
```
For chosen target:
├── Read all documentation
├── Map all subdomains
├── Identify technology stack
├── Find all entry points
├── Note excluded areas
```

#### Step 4: Focused Testing (Weeks 2-4)
```
Pick ONE vulnerability class:
├── Week 1: IDOR only
├── Week 2: Auth issues only
├── Week 3: XSS only
├── Week 4: Business logic only
```

### Bug Bounty Methodology

#### Recon Phase
```bash
# Subdomain enumeration
subfinder -d target.com -o subs.txt
amass enum -d target.com -o amass_subs.txt

# Combine and probe
cat subs.txt amass_subs.txt | sort -u | httpx -o live.txt

# Technology detection
whatweb -i live.txt -a 3

# Directory discovery
ffuf -u https://target.com/FUZZ -w wordlist.txt
```

#### Testing Phase by Vulnerability

**IDOR Testing:**
```
1. Create two accounts (user A and user B)
2. Perform actions as user A
3. Capture all requests with IDs
4. Replace IDs with user B's IDs
5. Check if action succeeds
```

**Authentication Testing:**
```
1. Test password reset flow
2. Test rate limiting on login
3. Test session management
4. Test 2FA bypass possibilities
5. Test OAuth misconfigurations
```

**XSS Testing:**
```
1. Identify all input points
2. Test reflection in response
3. Try basic payloads
4. Bypass filters
5. Escalate impact
```

### Bug Report Writing

#### Good Report Structure

```markdown
## Summary
[One paragraph describing the vulnerability]

## Severity
[Your assessment with justification]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]
...

## Impact
[What can an attacker do with this?]

## Proof of Concept
[Screenshots, video, or code]

## Remediation
[How to fix this issue]

## References
[CVEs, OWASP, similar reports]
```

#### Report Quality Checklist
- [ ] Clear, descriptive title
- [ ] Executive summary (non-technical)
- [ ] Detailed reproduction steps
- [ ] Working proof of concept
- [ ] Impact explanation
- [ ] Fix recommendations
- [ ] Screenshots/video evidence
- [ ] Professional tone

### Common Beginner Mistakes

| Mistake | Why It's Bad | Fix |
|---------|--------------|-----|
| Testing out of scope | Policy violation | Read scope carefully |
| Duplicate hunting | Wasted effort | Check disclosed reports |
| Poor reports | Gets rejected | Use template above |
| Giving up too early | Miss easy bugs | Spend more time on recon |
| Only using tools | Miss logic bugs | Manual testing essential |
| No documentation | Can't reproduce | Take notes constantly |

---

## Methodology and Checklists

### Web Application Testing Checklist

#### Authentication Testing
```
☐ Registration process
  ├── Email enumeration via registration
  ├── Password policy bypass
  ├── Weak password allowed
  └── Registration bypass

☐ Login process
  ├── Brute force possible
  ├── Rate limiting exists
  ├── Account lockout behavior
  ├── Error message differences
  └── Default credentials

☐ Password reset
  ├── Token predictability
  ├── Token reuse
  ├── Token expiration
  ├── User enumeration
  └── Password reset poisoning

☐ Session management
  ├── Session token randomness
  ├── Session fixation
  ├── Session timeout
  ├── Concurrent sessions
  └── Session termination on logout

☐ Multi-factor authentication
  ├── 2FA bypass via direct API
  ├── 2FA code brute force
  ├── 2FA code reuse
  └── Backup code issues
```

#### Authorization Testing
```
☐ Horizontal privilege escalation
  ├── IDOR in URLs
  ├── IDOR in POST body
  ├── IDOR in headers
  └── IDOR in file paths

☐ Vertical privilege escalation
  ├── Access admin functions
  ├── Role manipulation
  ├── Forced browsing
  └── Parameter tampering

☐ Function-level access
  ├── API endpoint access
  ├── Hidden functionality
  └── Debug endpoints
```

#### Input Validation Testing
```
☐ SQL Injection
  ├── GET parameters
  ├── POST body
  ├── Headers
  ├── Cookies
  └── JSON/XML data

☐ Cross-Site Scripting
  ├── Reflected in URL
  ├── Stored in database
  ├── DOM-based
  └── In file uploads

☐ Server-Side Request Forgery
  ├── URL parameters
  ├── File imports
  ├── Webhooks
  └── Image/PDF generation

☐ Other injections
  ├── Command injection
  ├── Template injection
  ├── LDAP injection
  └── XPath injection
```

#### Business Logic Testing
```
☐ Price manipulation
☐ Coupon/discount abuse
☐ Quantity manipulation
☐ Race conditions
☐ State bypass
☐ Feature misuse
```

### API Security Checklist

```
☐ Authentication
  ├── API key exposure
  ├── JWT vulnerabilities
  ├── OAuth misconfig
  └── Session handling

☐ Authorization (BOLA)
  ├── Object ID enumeration
  ├── Function-level access
  └── Resource-level access

☐ Rate limiting
  ├── No rate limit
  ├── Bypassable rate limit
  └── Different endpoints

☐ Input validation
  ├── Parameter tampering
  ├── Mass assignment
  ├── Type confusion
  └── Injection attacks

☐ Information exposure
  ├── Verbose errors
  ├── Debug info
  ├── Stack traces
  └── Sensitive data in responses
```

### Cloud Security Checklist

```
☐ Storage
  ├── Public S3 buckets
  ├── Blob storage access
  ├── Sensitive data exposed
  └── Backup exposures

☐ Compute
  ├── Metadata service access
  ├── SSRF to cloud
  ├── Instance credentials
  └── User data exposure

☐ Identity
  ├── Overly permissive IAM
  ├── Credential exposure
  ├── Role assumption
  └── Key rotation

☐ Network
  ├── Security group rules
  ├── Open ports
  ├── VPC misconfig
  └── DNS exposure
```

---

## Write-Up Templates

### CTF Write-Up Template

```markdown
# [CTF Name] - [Challenge Name] Write-Up

## Challenge Information
- **Category:** Web/Pwn/Crypto/Forensics/Misc
- **Difficulty:** Easy/Medium/Hard
- **Points:** XXX
- **Platform:** HackTheBox/TryHackMe/PicoCTF

## TL;DR
[2-3 sentences summarizing the challenge and solution]

## Challenge Description
[Original challenge description]

## Initial Reconnaissance
[What I noticed first, initial observations]

## Discovery Process
[How I found the vulnerability/solution]

### Step 1: [First Major Step]
[Details with commands/screenshots]

### Step 2: [Second Major Step]
[Details with commands/screenshots]

## Exploitation
[How I exploited the finding]

```python
# Code used (if applicable)
exploit_code_here()
```

## Flag
`flag{example_flag_here}`

## Lessons Learned
- [Key takeaway 1]
- [Key takeaway 2]
- [Key takeaway 3]

## Prevention
[How developers should prevent this vulnerability]

## References
- [Link 1]
- [Link 2]
```

### Bug Bounty Write-Up Template (For Portfolio)

```markdown
# [Vulnerability Type] in [Redacted Program]

**Severity:** Critical/High/Medium/Low
**Bounty:** $XXX (if disclosed)
**Disclosed:** Yes/No

## Summary
[Brief description of the vulnerability without revealing program]

## Technical Details

### Vulnerability Type
[Classification: IDOR, XSS, SSRF, etc.]

### Root Cause
[Why this vulnerability existed]

### Discovery
[How you found it - your methodology]

## Impact Assessment
[What an attacker could do]

## Proof of Concept
[Sanitized reproduction steps]

## Timeline
- **Reported:** YYYY-MM-DD
- **Triaged:** YYYY-MM-DD
- **Fixed:** YYYY-MM-DD
- **Bounty:** YYYY-MM-DD

## Remediation Applied
[How it was fixed]

## Key Learnings
[What this taught you]
```

### PortSwigger Lab Write-Up Template

```markdown
# PortSwigger Lab: [Lab Name]

## Lab Information
- **Topic:** [e.g., SQL Injection]
- **Difficulty:** Apprentice/Practitioner/Expert
- **Link:** [Lab URL]

## Objective
[What the lab asks you to do]

## Solution

### Step 1: Reconnaissance
[Initial observations]

### Step 2: Identify Vulnerability
[How you confirmed the vuln]

### Step 3: Exploitation
[Payload and method used]

**Payload:**
```
[actual payload]
```

### Step 4: Lab Completion
[Final step to solve]

## Why This Works
[Technical explanation]

## Real-World Impact
[How this applies to actual applications]

## Prevention
[Developer mitigation]
```

---

## Building Your Portfolio

### GitHub Repository Structure

```
security-writeups/
├── README.md (portfolio overview)
├── ctf-writeups/
│   ├── hackthebox/
│   │   ├── machine-name-1.md
│   │   └── machine-name-2.md
│   ├── tryhackme/
│   │   └── room-name.md
│   └── picoctf/
│       └── challenge-name.md
├── portswigger-labs/
│   ├── sql-injection/
│   ├── xss/
│   ├── authentication/
│   └── access-control/
├── bug-bounty/
│   └── redacted-findings/
├── tools/
│   └── custom-scripts/
├── checklists/
│   ├── web-app-checklist.md
│   ├── api-checklist.md
│   └── cloud-checklist.md
└── resources/
    └── learning-notes/
```

### Portfolio README Template

```markdown
# Security Research Portfolio

## About Me
[Brief intro - 2-3 sentences about your focus]

## Statistics
- **CTF Write-ups:** XX
- **PortSwigger Labs:** XX/XXX completed
- **Bug Bounties:** XX valid reports
- **Platform Ranks:** [TryHackMe rank, HTB rank]

## Featured Write-ups
1. Interesting Challenge 1 - Brief description + add URL
2. Interesting Challenge 2 - Brief description + add URL
3. Interesting Challenge 3 - Brief description + add URL

## Skills Demonstrated
- Web Application Security
- API Security Testing
- Cloud Security
- [Others]

## Certifications
- [Cert 1]
- [Cert 2]

## Contact
- LinkedIn: [link]
- Blog: [link]
```

### What to Include vs Exclude

**Include:**
- CTF write-ups (any platform)
- PortSwigger lab solutions
- Redacted bug bounty findings (with permission)
- Custom tools you've built
- Methodology documents
- Sigma rules/detection content

**Exclude:**
- Active bug bounty program details
- Sensitive reproduction steps
- Actual credentials or tokens
- Proprietary company information
- Unpatched vulnerabilities

### Promotion Strategy

```
Weekly Routine:
├── Complete 2-3 labs/challenges
├── Write 1 quality write-up
├── Share on LinkedIn (Tuesday or Wednesday)
├── Share in null/OWASP communities
└── Engage with comments

Monthly Goals:
├── 4 published write-ups
├── 1 longer technical blog post
├── Attend 1 community meetup
└── Connect with 5 security professionals
```

---

## India Community

### Why Community Matters in Bangalore

- **Referrals:** Most security jobs filled through referrals
- **Learning:** Faster growth through collaboration
- **Recognition:** Known names get interview calls
- **Accountability:** Study groups keep you consistent
- **Opportunities:** Learn about unlisted jobs

### Key Communities

#### null Community (Primary)

**What:** India's largest security community
**Where:** [null.community](https://null.community) + city chapters
**Bangalore Chapter:** Very active, monthly meetups

**How to Engage:**
1. Join [https://null.community](https://null.community)
2. Join Bangalore chapter
3. Attend monthly meetups
4. Present a 5-minute lightning talk
5. Volunteer for events
6. Join CTF teams

**Meetup Types:**
- null Puliya (beginner-friendly sessions)
- null Humla (attack sessions)
- null Bachaav (defense sessions)
- null Monthly Meets (general)

#### OWASP Bangalore

**What:** Application security focused
**Where:** OWASP chapter meetings
**Focus:** AppSec, secure development

**How to Engage:**
```
1. Join OWASP Bangalore mailing list
2. Attend chapter meetings
3. Contribute to OWASP projects
4. Present on AppSec topics
```

### Telegram/Discord Groups

| Group | Focus | Activity |
|-------|-------|----------|
| null Community | General security | High |
| Indian Bug Bounty | Bug bounty | Medium |
| InfoSec India | News + discussion | Medium |
| CTF India | CTF teams | Medium |

### Conference Calendar (India)

| Conference | Location | Best For | Cost |
|------------|----------|----------|------|
| Nullcon | Goa (March) | All security | ₹10K-30K |
| BSides Bangalore | Bangalore | Local network | Low/Free |
| c0c0n | Kerala | Government + enterprise | ₹5K-15K |
| OWASP AppSec India | Varies | AppSec | ₹5K-10K |
| Ground Zero | Delhi | Offensive | ₹10K-20K |

### Building Your Network

**Before Meetups:**
```
1. Prepare 30-second intro
2. Have LinkedIn ready on phone
3. Know what you want to learn
4. Prepare 1-2 questions for speakers
```

**At Meetups:**
```
1. Arrive early
2. Introduce yourself to 3-5 people
3. Ask about their current work
4. Take notes on interesting topics
5. Volunteer to help if possible
```

**After Meetups:**
```
1. Connect on LinkedIn (same day)
2. Send personalized message
3. Share something relevant
4. Follow up in 1-2 weeks
```

---

## Quick Reference

### Best Platforms by Skill Level

| Level | Platforms | Time Needed |
|-------|-----------|-------------|
| Beginner | TryHackMe, PicoCTF, PortSwigger | 3-6 months |
| Intermediate | HackTheBox, Bug Bounty VDPs | 6-12 months |
| Advanced | HTB Pro Labs, Private Programs | 12+ months |

### Best Platforms by Focus Area

| Focus | Best Platform |
|-------|---------------|
| Web Security | PortSwigger Academy |
| General Hacking | TryHackMe |
| Realistic Machines | HackTheBox |
| Cloud Security | flaws.cloud |
| Blue Team | CyberDefenders |
| Bug Bounty | HackerOne, Bugcrowd |

### Weekly Time Investment Guide

| Hours/Week | Expected Progress |
|------------|-------------------|
| 2-4 hours | Slow but steady, 6+ months to intermediate |
| 6-8 hours | Good progress, 3-4 months to intermediate |
| 10+ hours | Fast progress, 2-3 months to intermediate |

---

## Next Steps

### This Week
- [ ] Create accounts on TryHackMe + PortSwigger
- [ ] Complete first 5 PortSwigger SQL injection labs
- [ ] Join null community
- [ ] Set up write-up repository on GitHub

### This Month
- [ ] Complete 25+ PortSwigger labs
- [ ] Write 2 quality write-ups
- [ ] Attend one null Bangalore meetup
- [ ] Create HackerOne/Bugcrowd account

### This Quarter
- [ ] Complete Phase 1-2 of 12-week plan
- [ ] Publish 6+ write-ups
- [ ] Submit first bug bounty report
- [ ] Build portfolio repository

---

**Remember:** Consistency beats intensity. 6 hours/week for 12 months beats 60 hours for 1 month.

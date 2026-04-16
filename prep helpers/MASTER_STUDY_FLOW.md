# 🎯 MASTER STUDY FLOW GUIDE
**Your complete roadmap to navigate all 20 study documents**
**Version:** April 2026

---

## ⚠️ READ THIS FIRST — THE BIG PICTURE

You have ~19,000+ lines of study material across 20 files. This guide tells you **exactly what to read, in what order, and why**.

### The 3 Types of Documents You Have

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           YOUR STUDY MATERIALS                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   TYPE 1: CORE STUDY MATERIAL (Read & Learn)                               │
│   ─────────────────────────────────────────                                │
│   📚 These are your "textbooks" — read them deeply                          │
│   • cybersecurity_fundamentals_study_material.md (3,400 lines)             │
│   • appsec_study_material.md (1,600 lines)                                 │
│   • cloudsec_study_material.md (1,300 lines)                               │
│   • cryptography_study_material.md (780 lines)                             │
│   • ml_security_study_material.md (380 lines)                              │
│   • cybersecurity_foundations_plus.md (310 lines)                          │
│                                                                             │
│   TYPE 2: PLANNING & EXECUTION (Follow the Schedule)                       │
│   ───────────────────────────────────────────────                          │
│   📋 These tell you WHAT to do WHEN                                         │
│   • syllabus.md — master topic list (reference)                            │
│   • execution_plan_12_ml_app_cloud.md — weekly schedule (follow!)           │
│   • WEEKLY_STUDY_TEMPLATE.md — session planning                            │
│                                                                             │
│   TYPE 3: SUPPORT TOOLS (Reference While Doing)                            │
│   ──────────────────────────────────────────────                           │
│   🔧 Keep these open while practicing                                       │
│   • BEGINNER_START_HERE.md — setup, glossary, mindset                      │
│   • FLASHCARDS_QUICK_REF.md — daily 10-min review                          │
│   • TOOLS_CHEAT_SHEET.md — command reference                               │
│   • HANDS_ON_EXERCISES.md — step-by-step labs                              │
│                                                                             │
│   TYPE 4: CAREER & PORTFOLIO (Build & Apply)                               │
│   ─────────────────────────────────────────                                │
│   💼 Use these to build your professional profile                           │
│   • PORTFOLIO_PROJECTS.md — project ideas                                  │
│   • INTERVIEW_AND_NETWORKING.md — career prep                              │
│   • CERTIFICATIONS_ROADMAP_INDIA.md — cert planning                        │
│   • CTF_AND_BUG_BOUNTY_GUIDE.md — practice platforms                       │
│   • TEMPLATES_PACK.md — resume, LinkedIn, outreach                         │
│   • RESOURCE_LIBRARY.md — curated external resources                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📅 THE COMPLETE STUDY TIMELINE

### Overview: 16-Week Journey

```
PHASE 1: FOUNDATION (Weeks 1-4)
├── Week 1: Setup + Orientation
├── Week 2-3: Core Fundamentals (OS, Networking)
└── Week 4: Cryptography + Programming

PHASE 2: SPECIALIZATION (Weeks 5-10)
├── Week 5-6: Application Security
├── Week 7-8: Cloud Security
└── Week 9-10: ML Security

PHASE 3: INTEGRATION (Weeks 11-14)
├── Week 11-12: Portfolio Projects
├── Week 13: Detection Engineering
└── Week 14: Advanced Topics

PHASE 4: CAREER PREP (Weeks 15-16)
├── Week 15: Interview Preparation
└── Week 16: Job Search Launch
```

---

## 🚀 PHASE 1: FOUNDATION (Weeks 1-4)

### Week 1: Setup & Orientation (6 hours)

**Goal:** Environment ready, mental model clear, first lab completed

| Day | Time | Activity | Document |
|-----|------|----------|----------|
| Day 1 | 2h | Read completely, set up environment | [BEGINNER_START_HERE.md](BEGINNER_START_HERE.md) |
| Day 2 | 2h | Install tools (Burp, VM, Python) | [BEGINNER_START_HERE.md](BEGINNER_START_HERE.md) |
| Day 3 | 2h | First lab (SQLi) + write-up | [HANDS_ON_EXERCISES.md](HANDS_ON_EXERCISES.md) Exercise 1 |

**Checkpoint:** 
- [ ] VM/WSL working
- [ ] Burp Suite installed
- [ ] Completed Exercise 1 with write-up
- [ ] Can explain CIA triad, AuthN vs AuthZ

**Documents to read this week:**
1. ✅ [BEGINNER_START_HERE.md](BEGINNER_START_HERE.md) — **100% (required)**
2. ✅ [STUDY_INDEX.md](STUDY_INDEX.md) — **100% (understand the map)**

---

### Week 2-3: Core Fundamentals (12 hours total)

**Goal:** Master OS, networking, and protocol basics

| Week | Focus | Primary Reading | Practice |
|------|-------|-----------------|----------|
| Week 2 | Systems | Fundamentals Parts 1-2 (OS, Linux, Windows) | Linux audit script |
| Week 3 | Networking | Fundamentals Parts 3 (Networking, Protocols) | Wireshark captures |

**Reading Schedule:**

**Week 2 (6 hours):**
```
Session A (3h):
├── Read: cybersecurity_fundamentals_study_material.md
│   └── PART 1: Systems Fundamentals (sections 1.1-1.5)
│       • Computer architecture
│       • OS fundamentals
│       • Linux fundamentals
│       • Windows fundamentals
│       • Active Directory basics
└── Practice: HANDS_ON_EXERCISES.md Exercise 3 (Juice Shop setup)

Session B (3h):
├── Read: cybersecurity_fundamentals_study_material.md
│   └── PART 2: Programming Foundations (sections 2.1-2.6)
│       • Python for security
│       • Bash fundamentals
│       • PowerShell basics
│       • C memory model (concepts)
└── Practice: HANDS_ON_EXERCISES.md Exercise 5 (Log parser)
```

**Week 3 (6 hours):**
```
Session A (3h):
├── Read: cybersecurity_fundamentals_study_material.md
│   └── PART 3: Networking Fundamentals (sections 3.1-3.9)
│       • TCP/IP model
│       • DNS deep dive
│       • HTTP and proxies
│       • TLS/PKI basics
│       • Email security
└── Practice: HANDS_ON_EXERCISES.md Exercise 4 (Wireshark)

Session B (3h):
├── Read: cybersecurity_fundamentals_study_material.md
│   └── PART 4-6: Crypto + Web + Defense basics
└── Create: 3 PCAP write-ups (DNS, HTTP, TLS)
```

**Documents to read Weeks 2-3:**
1. [cybersecurity_fundamentals_study_material.md](../study%20material/cybersecurity_fundamentals_study_material.md) — **Parts 1-6**
2. [TOOLS_CHEAT_SHEET.md](../study%20material/TOOLS_CHEAT_SHEET.md) — **Reference while practicing**
3. [FLASHCARDS_QUICK_REF.md](../study%20material/FLASHCARDS_QUICK_REF.md) — **10 min daily review**

---

### Week 4: Cryptography + Programming (6 hours)

**Goal:** Understand crypto primitives, safe usage, common mistakes

**Session A (3h):**
```
Read: cryptography_study_material.md
├── C0-C5: Fundamentals
│   • Security goals (CIA)
│   • Threat models
│   • Symmetric crypto (AES-GCM)
│   • Hash functions & MACs
│   • Password hashing
└── Exercise: Python crypto lab (HMAC, hashing)
```

**Session B (3h):**
```
Read: cryptography_study_material.md
├── C6-C13: Advanced + Practical
│   • Public-key crypto
│   • TLS/PKI
│   • Key management
│   • Common mistakes
└── Create: "Crypto pitfalls" cheat sheet
```

**Documents to read Week 4:**
1. [cryptography_study_material.md](../study%20material/cryptography_study_material.md) — **100%**

**Checkpoint for Phase 1:**
- [ ] Can explain how Linux/Windows handle processes, permissions, logs
- [ ] Can capture and read network traffic in Wireshark
- [ ] Can explain TCP handshake, DNS resolution, TLS handshake
- [ ] Can explain hash vs encryption vs signature with examples
- [ ] Completed 5+ write-ups

---

## 🔐 PHASE 2: SPECIALIZATION (Weeks 5-10)

### Weeks 5-6: Application Security (12 hours)

**This is your primary specialization focus**

**Week 5 (6 hours):**
```
Session A (3h):
├── Read: appsec_study_material.md
│   └── PART 0-1: Orientation + Web Foundations
│       • AppSec mental models
│       • HTTP deep dive
│       • Sessions, cookies, browser security
│       • APIs and rate limiting
└── Lab: PortSwigger "Access Control" (2 labs)

Session B (3h):
├── Read: appsec_study_material.md
│   └── PART 2: Vulnerability Classes (2.1-2.5)
│       • Broken access control (IDOR)
│       • Security misconfiguration
│       • Supply chain
│       • Crypto failures
│       • Injection (SQL/NoSQL/Command)
└── Lab: PortSwigger "SQL Injection" (2 labs)
```

**Week 6 (6 hours):**
```
Session A (3h):
├── Read: appsec_study_material.md
│   └── PART 2-3: Remaining vulns + Modern surfaces
│       • Authentication failures
│       • Integrity failures
│       • SSRF
│       • File upload
│       • Microservices
└── Lab: PortSwigger "SSRF" (2 labs)

Session B (3h):
├── Read: appsec_study_material.md
│   └── PART 4-6: Engineering + Testing + Standards
│       • Threat modeling
│       • Secure design patterns
│       • Testing methodology
│       • OWASP standards
└── Create: Threat model for sample app
```

**Documents to read Weeks 5-6:**
1. [appsec_study_material.md](../study%20material/appsec_study_material.md) — **100%**
2. Reference: [cybersecurity_foundations_plus.md](../study%20material/cybersecurity_foundations_plus.md) F+1 (Secure SDLC)

---

### Weeks 7-8: Cloud Security (12 hours)

**Week 7 (6 hours):**
```
Session A (3h):
├── Read: cloudsec_study_material.md
│   └── CS0-CS4: Mental model + IAM
│       • Shared responsibility model
│       • Cloud basics primer
│       • Threat model for cloud
│       • IAM deep dive
└── Practice: Set up AWS/Azure free tier with secure baseline

Session B (3h):
├── Read: cloudsec_study_material.md
│   └── CS5-CS8: Network + Storage + Compute + K8s
│       • VPC/VNet security
│       • Storage security
│       • Compute security
│       • Kubernetes basics
└── Lab: Enable CloudTrail/Activity Log, make a change, find it
```

**Week 8 (6 hours):**
```
Session A (3h):
├── Read: cloudsec_study_material.md
│   └── CS9-CS14: Secrets + Logging + Governance + IR
│       • Key management
│       • Detection in cloud
│       • Policy as code
│       • Cloud IR playbooks
└── Create: "Day-0 Cloud Baseline" checklist

Session B (3h):
├── Read: cloudsec_study_material.md
│   └── CS16-CS22: AWS/Azure specifics
│       • AWS appendix
│       • Azure appendix
│       • Common rookie mistakes
└── Lab: flaws.cloud or flaws2.cloud challenges
```

**Documents to read Weeks 7-8:**
1. [cloudsec_study_material.md](../study%20material/cloudsec_study_material.md) — **100%**
2. Reference: [cybersecurity_foundations_plus.md](../study%20material/cybersecurity_foundations_plus.md) F+5 (Containers/K8s)

---

### Weeks 9-10: ML Security (12 hours)

**Week 9 (6 hours):**
```
Session A (3h):
├── Read: ml_security_study_material.md
│   └── ML0-ML3: Mental model + Training-time attacks
│       • ML security overview
│       • Threat modeling for ML
│       • Data poisoning
│       • Adversarial examples
└── Create: ML system DFD + threat model

Session B (3h):
├── Read: ml_security_study_material.md
│   └── ML4-ML5: Inference attacks + Privacy
│       • Model extraction
│       • Membership inference
│       • Privacy defenses
└── Design: API policy for ML inference endpoint
```

**Week 10 (6 hours):**
```
Session A (3h):
├── Read: ml_security_study_material.md
│   └── ML6-ML7: LLM Security + MLOps
│       • Prompt injection
│       • Tool abuse
│       • Pipeline security
└── Create: Prompt injection write-up

Session B (3h):
├── Read: ml_security_study_material.md
│   └── ML8-ML9: Evaluation + Portfolio projects
└── Start: Portfolio Project A (Secure ML API)
```

**Documents to read Weeks 9-10:**
1. [ml_security_study_material.md](../study%20material/ml_security_study_material.md) — **100%**

---

## 🏗️ PHASE 3: INTEGRATION (Weeks 11-14)

### Weeks 11-12: Portfolio Projects

**Goal:** Build 3 portfolio-ready projects

```
Week 11:
├── Session A: Complete Portfolio Project 1 (from PORTFOLIO_PROJECTS.md)
└── Session B: Start Portfolio Project 2

Week 12:
├── Session A: Complete Portfolio Project 2
└── Session B: Complete Portfolio Project 3
```

**What you're building:**
1. **Secure API Demo** (AppSec focus)
2. **Cloud Security Lab** (CloudSec focus)
3. **ML Security Evaluation** (ML Security focus)

**Documents for Weeks 11-12:**
1. [PORTFOLIO_PROJECTS.md](PORTFOLIO_PROJECTS.md) — **Select 3 projects**
2. [execution_plan_12_ml_app_cloud.md](execution_plan_12_ml_app_cloud.md) — **Week 11-12 specifics**

---

### Week 13: Detection Engineering

**Goal:** Write detection rules, understand SOC operations

```
Session A (3h):
├── Read: cybersecurity_foundations_plus.md F+3 (Logging & Detection)
├── Write: 5 detection rules (Sigma-style)
└── Map: MITRE ATT&CK techniques to your detections

Session B (3h):
├── Review: cloudsec_study_material.md CS10 (Detection)
├── Create: IR playbook for one scenario
└── Practice: Hunt in your lab logs
```

---

### Week 14: Advanced Topics + Gap Filling

**Goal:** Cover any gaps, deepen weak areas

```
Session A (3h):
├── Self-assess: Which areas feel weakest?
├── Re-read: Relevant sections
└── Practice: More labs in weak areas

Session B (3h):
├── Read: cybersecurity_fundamentals_study_material.md
│   └── Parts 7-11 (Forensics, Malware, Security Engineering)
└── Create: Final write-ups
```

---

## 💼 PHASE 4: CAREER PREP (Weeks 15-16)

### Week 15: Interview Preparation

```
Session A (3h):
├── Read: INTERVIEW_AND_NETWORKING.md (sections 1-3)
├── Practice: Technical questions
└── Create: STAR stories for behavioral questions

Session B (3h):
├── Read: TEMPLATES_PACK.md
├── Update: Resume with security bullets
├── Optimize: LinkedIn profile
└── Write: Outreach scripts
```

**Documents for Week 15:**
1. [INTERVIEW_AND_NETWORKING.md](INTERVIEW_AND_NETWORKING.md) — **100%**
2. [TEMPLATES_PACK.md](TEMPLATES_PACK.md) — **100%**

---

### Week 16: Job Search Launch

```
Session A (3h):
├── Read: CERTIFICATIONS_ROADMAP_INDIA.md
├── Plan: Certification timeline
└── Identify: Target companies

Session B (3h):
├── Apply: First 5 applications
├── Network: Reach out to 3 contacts
└── Continue: CTFs and bug bounty practice
```

**Documents for Week 16:**
1. [CERTIFICATIONS_ROADMAP_INDIA.md](CERTIFICATIONS_ROADMAP_INDIA.md)
2. [CTF_AND_BUG_BOUNTY_GUIDE.md](CTF_AND_BUG_BOUNTY_GUIDE.md)
3. [RESOURCE_LIBRARY.md](../study%20material/RESOURCE_LIBRARY.md)

---

## 📊 DAILY ROUTINE (Recommended)

```
MORNING (15 min)
├── Review: 10-15 flashcards from FLASHCARDS_QUICK_REF.md
└── Read: One security news article (Krebs, The Hacker News)

STUDY SESSION (1-3 hours when available)
├── Read: Current week's study material
├── Practice: Hands-on lab or exercise
└── Write: Document what you learned

BEFORE BED (10 min)
└── Quick review: What did I learn today?
```

---

## 🗂️ DOCUMENT DEPENDENCIES (What Requires What)

```
PREREQUISITE CHAIN:
──────────────────

BEGINNER_START_HERE.md
        │
        ▼
cybersecurity_fundamentals_study_material.md
        │
        ├──────────────────────────────┬─────────────────────┐
        ▼                              ▼                     ▼
cryptography_study_material.md   appsec_study_material.md   cloudsec_study_material.md
        │                              │                     │
        └──────────────────────────────┴─────────────────────┘
                                       │
                                       ▼
                         ml_security_study_material.md
                                       │
                                       ▼
                         cybersecurity_foundations_plus.md
                              (capstone concepts)
```

**What this means:**
- Don't read AppSec before Fundamentals
- Don't read ML Security before AppSec and CloudSec basics
- Foundations+ assumes you've read everything else

---

## ⚡ QUICK REFERENCE: WHICH DOC FOR WHICH QUESTION

| If you need to... | Read this document |
|-------------------|-------------------|
| Set up your environment | [BEGINNER_START_HERE.md](BEGINNER_START_HERE.md) |
| Understand a security term | [BEGINNER_START_HERE.md](BEGINNER_START_HERE.md) glossary |
| Know what to study this week | [execution_plan_12_ml_app_cloud.md](execution_plan_12_ml_app_cloud.md) |
| Find a command syntax | [TOOLS_CHEAT_SHEET.md](../study%20material/TOOLS_CHEAT_SHEET.md) |
| Review a concept quickly | [FLASHCARDS_QUICK_REF.md](../study%20material/FLASHCARDS_QUICK_REF.md) |
| Practice hands-on | [HANDS_ON_EXERCISES.md](HANDS_ON_EXERCISES.md) |
| Deep dive into OS/Networking | [cybersecurity_fundamentals_study_material.md](../study%20material/cybersecurity_fundamentals_study_material.md) |
| Deep dive into web security | [appsec_study_material.md](../study%20material/appsec_study_material.md) |
| Deep dive into cloud | [cloudsec_study_material.md](../study%20material/cloudsec_study_material.md) |
| Deep dive into crypto | [cryptography_study_material.md](../study%20material/cryptography_study_material.md) |
| Deep dive into ML security | [ml_security_study_material.md](../study%20material/ml_security_study_material.md) |
| Build portfolio projects | [PORTFOLIO_PROJECTS.md](PORTFOLIO_PROJECTS.md) |
| Prepare for interviews | [INTERVIEW_AND_NETWORKING.md](INTERVIEW_AND_NETWORKING.md) |
| Update resume/LinkedIn | [TEMPLATES_PACK.md](TEMPLATES_PACK.md) |
| Plan certifications | [CERTIFICATIONS_ROADMAP_INDIA.md](CERTIFICATIONS_ROADMAP_INDIA.md) |
| Find practice platforms | [CTF_AND_BUG_BOUNTY_GUIDE.md](CTF_AND_BUG_BOUNTY_GUIDE.md) |
| Find courses/books | [RESOURCE_LIBRARY.md](../study%20material/RESOURCE_LIBRARY.md) |

---

## 🎯 SUCCESS METRICS BY PHASE

### End of Phase 1 (Week 4):
- [ ] 6+ write-ups completed
- [ ] Can explain fundamentals without notes
- [ ] Lab environment fully functional
- [ ] Daily flashcard habit established

### End of Phase 2 (Week 10):
- [ ] 18+ write-ups completed
- [ ] PortSwigger Academy progress (30+ labs)
- [ ] Cloud free tier set up securely
- [ ] ML threat model created
- [ ] Can explain OWASP Top 10 with examples

### End of Phase 3 (Week 14):
- [ ] 3 portfolio projects completed
- [ ] GitHub repo organized with artifacts
- [ ] 5+ detection rules written
- [ ] Can threat model any simple system

### End of Phase 4 (Week 16):
- [ ] Resume updated with security focus
- [ ] LinkedIn optimized
- [ ] 10+ job applications sent
- [ ] 5+ networking conversations had
- [ ] Certification study plan in place

---

## 🆘 TROUBLESHOOTING COMMON PROBLEMS

### "I feel overwhelmed by the amount of material"
**Solution:** Focus ONLY on the current week's reading. Trust the schedule.

### "I don't understand a concept"
**Solution:** 
1. Re-read the fundamentals section
2. Search for a YouTube explanation
3. Do a hands-on lab related to it
4. Write a teach-back explanation

### "I'm not sure if I'm making progress"
**Solution:** 
1. Count your write-ups (target: 3-4 per week)
2. Try to explain a concept from memory
3. Do a PortSwigger lab and time yourself

### "I'm spending too much time on one topic"
**Solution:** Time-box your sessions. Move on after 3 hours even if incomplete.

### "I skipped some weeks and lost momentum"
**Solution:** Don't restart from zero. Resume from where you stopped.

---

**Remember:** The goal is not to memorize everything. The goal is to build mental models and practical skills. If you can explain it simply and demonstrate it in a lab, you understand it.

**Now go to Week 1 and start!** 🚀

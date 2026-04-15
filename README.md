# 🔐 Cybersecurity Study Repository

**A comprehensive, self-paced study guide for breaking into cybersecurity**

**Focus Areas:** Application Security (AppSec) | Cloud Security (CloudSec) | ML Security | Detection Engineering  
**Target Location:** Bangalore, India 🇮🇳  
**Study Budget:** 6 hours/week  
**Total Content:** 21 files | ~30,000+ lines of curated material

---

## 📋 Table of Contents

- [What Is This?](#what-is-this)
- [Who Is This For?](#who-is-this-for)
- [Repository Structure](#repository-structure)
- [Quick Start Guide](#quick-start-guide)
- [Study Flow](#study-flow)
- [Document Overview](#document-overview)
- [How to Use This Repository](#how-to-use-this-repository)
- [Prerequisites](#prerequisites)
- [Learning Paths](#learning-paths)
- [FAQ](#faq)

---

## 🎯 What Is This?

This repository contains **everything you need** to transition into a cybersecurity career, specifically targeting:

- **Application Security Engineer** roles
- **Cloud Security Engineer** roles  
- **ML/AI Security Specialist** roles
- **Security Operations / Detection Engineering** roles

The materials are designed to be:
- ✅ **Practical** — Hands-on labs, real tools, portfolio projects
- ✅ **Comprehensive** — Covers fundamentals through advanced topics
- ✅ **Structured** — Clear study order with weekly schedules
- ✅ **Job-focused** — Aligned with actual job requirements in India
- ✅ **Self-contained** — Everything in one place

---

## 👤 Who Is This For?

**Ideal for:**
- Final-year undergraduate students with programming background
- Software engineers transitioning to security
- Anyone with ML/Python experience wanting to enter security
- Self-learners who prefer structured, comprehensive materials

**Assumptions:**
- You can write Python code
- You understand basic programming concepts
- You have 6+ hours/week dedicated study time
- You're targeting Bangalore/India security job market

---

## 📁 Repository Structure

```
study/
├── README.md                          ← You are here
│
├── prep helpers/                      ← Planning, execution, career tools
│   ├── MASTER_STUDY_FLOW.md          ★ START HERE - Complete 16-week roadmap
│   ├── STUDY_INDEX.md                 Index of all documents
│   ├── BEGINNER_START_HERE.md         First-day setup and orientation
│   ├── syllabus.md                    Master topic list (17 modules)
│   ├── execution_plan_12_weeks_ml_app_cloud.md   Weekly schedule
│   ├── WEEKLY_STUDY_TEMPLATE.md       Session planning templates
│   ├── HANDS_ON_EXERCISES.md          11 step-by-step labs
│   ├── PORTFOLIO_PROJECTS.md          22+ project ideas with guides
│   ├── INTERVIEW_AND_NETWORKING.md    Interview prep, networking tips
│   ├── CERTIFICATIONS_ROADMAP_INDIA.md  Cert planning for India
│   ├── CTF_AND_BUG_BOUNTY_GUIDE.md    Practice platforms guide
│   └── TEMPLATES_PACK.md              Resume, LinkedIn, outreach templates
│
└── study material/                    ← Core learning content
    ├── cybersecurity_fundamentals_study_material.md   OS, networking, protocols
    ├── appsec_study_material.md                       Web security, OWASP Top 10
    ├── cloudsec_study_material.md                     AWS/Azure/GCP, K8s, containers
    ├── ml_security_study_material.md                  LLM security, ML threats
    ├── cryptography_study_material.md                 Crypto fundamentals, PKI
    ├── cybersecurity_foundations_plus.md              SDLC, identity, detection
    ├── FLASHCARDS_QUICK_REF.md                        Daily review cards
    ├── TOOLS_CHEAT_SHEET.md                           Command reference (50+ tools)
    └── RESOURCE_LIBRARY.md                            200+ curated external links
```

---

## 🚀 Quick Start Guide

### Day 1: Orientation (2 hours)
```
1. Read this README completely
2. Open: prep helpers/MASTER_STUDY_FLOW.md (your complete roadmap)
3. Open: prep helpers/BEGINNER_START_HERE.md (setup guide)
4. Set up your environment (VM/WSL, Burp Suite, Python)
```

### Day 2-3: First Lab (4 hours)
```
1. Follow: prep helpers/HANDS_ON_EXERCISES.md → Exercise 1 (SQL Injection)
2. Reference: study material/TOOLS_CHEAT_SHEET.md as needed
3. Write up your findings (practice documentation)
```

### Week 1+: Follow the Schedule
```
1. Follow: prep helpers/MASTER_STUDY_FLOW.md week-by-week
2. Daily: Review study material/FLASHCARDS_QUICK_REF.md (10 min)
3. Weekly: Complete assigned reading + 1-2 labs
```

---

## 📊 Study Flow

```
                            STUDY FLOW OVERVIEW
═══════════════════════════════════════════════════════════════════════════════

  WEEK 1              WEEKS 2-4            WEEKS 5-10           WEEKS 11-16
┌─────────────┐    ┌─────────────┐    ┌─────────────────┐    ┌─────────────┐
│   SETUP &   │    │ FOUNDATIONS │    │ SPECIALIZATION  │    │   CAREER    │
│ ORIENTATION │ →  │  OS, Net,   │ →  │ AppSec, Cloud,  │ →  │   PREP      │
│             │    │  Crypto     │    │ ML Security     │    │             │
└─────────────┘    └─────────────┘    └─────────────────┘    └─────────────┘
       │                  │                   │                     │
       ▼                  ▼                   ▼                     ▼
  BEGINNER_          FUNDAMENTALS        APPSEC_STUDY         INTERVIEW_
  START_HERE.md      _STUDY_MATERIAL     CLOUDSEC_STUDY       PORTFOLIO_
  MASTER_FLOW.md     CRYPTO_STUDY        ML_SECURITY          CERTIFICATIONS

═══════════════════════════════════════════════════════════════════════════════
```

---

## 📚 Document Overview

### 🗺️ Navigation & Planning

| Document | Lines | Purpose | When to Use |
|----------|-------|---------|-------------|
| **MASTER_STUDY_FLOW.md** | ~600 | Complete 16-week roadmap | First thing to read, reference weekly |
| **STUDY_INDEX.md** | ~150 | Quick navigation to all docs | When you need to find something |
| **BEGINNER_START_HERE.md** | ~350 | Environment setup, glossary | Day 1, setup reference |
| **syllabus.md** | ~1,200 | All topics in detail | Reference for coverage |
| **execution_plan_12_weeks_ml_app_cloud.md** | ~300 | Detailed weekly schedule | Follow alongside MASTER_FLOW |

### 📖 Core Study Material

| Document | Lines | Topics Covered |
|----------|-------|----------------|
| **cybersecurity_fundamentals_study_material.md** | ~3,400 | OS internals, Linux/Windows, networking, TCP/IP, DNS, HTTP, TLS |
| **appsec_study_material.md** | ~1,900 | OWASP Top 10, injection, XSS, SSRF, API security, SAST/DAST |
| **cloudsec_study_material.md** | ~2,300 | AWS/Azure/GCP IAM, S3/Blob security, K8s, containers, IR playbooks |
| **ml_security_study_material.md** | ~1,100 | LLM Top 10, prompt injection, model extraction, data poisoning |
| **cryptography_study_material.md** | ~1,200 | Symmetric/asymmetric, hashing, PKI, TLS, post-quantum |
| **cybersecurity_foundations_plus.md** | ~400 | Secure SDLC, identity, detection engineering |

### 🛠️ Reference & Practice

| Document | Lines | Purpose |
|----------|-------|---------|
| **FLASHCARDS_QUICK_REF.md** | ~1,300 | Daily review, interview prep, quick concepts |
| **TOOLS_CHEAT_SHEET.md** | ~1,400 | 50+ tools with commands and examples |
| **HANDS_ON_EXERCISES.md** | ~1,200 | 11 guided labs (SQLi, XSS, Cloud, JWT, etc.) |
| **RESOURCE_LIBRARY.md** | ~1,300 | 200+ curated links to external resources |

### 💼 Career & Portfolio

| Document | Lines | Purpose |
|----------|-------|---------|
| **PORTFOLIO_PROJECTS.md** | ~3,750 | 22+ project ideas with implementation guides |
| **INTERVIEW_AND_NETWORKING.md** | ~1,700 | Interview questions, networking strategies |
| **CERTIFICATIONS_ROADMAP_INDIA.md** | ~1,200 | Cert comparison, study plans, ROI analysis |
| **CTF_AND_BUG_BOUNTY_GUIDE.md** | ~920 | Platform guides, methodology |
| **TEMPLATES_PACK.md** | ~810 | Resume bullets, LinkedIn, outreach scripts |
| **WEEKLY_STUDY_TEMPLATE.md** | ~760 | Session planning, tracking |

---

## 📖 How to Use This Repository

### The Golden Rule
**Don't read everything at once.** Follow the MASTER_STUDY_FLOW.md week by week.

### Daily Routine (Recommended)
```
Morning (10 min):
└── Review 5 flashcards from FLASHCARDS_QUICK_REF.md

Study Session (2-3 hours, 2-3x per week):
├── Follow the week's reading from MASTER_STUDY_FLOW.md
├── Complete associated lab from HANDS_ON_EXERCISES.md
└── Reference TOOLS_CHEAT_SHEET.md as needed

Evening (10 min):
└── Note questions, update progress tracker
```

### Which Document When?

```
"I'm just starting"
    → BEGINNER_START_HERE.md → MASTER_STUDY_FLOW.md

"I don't know what order to study"
    → MASTER_STUDY_FLOW.md

"I'm learning [topic]"
    → Corresponding study material file

"I'm doing hands-on practice"
    → HANDS_ON_EXERCISES.md + TOOLS_CHEAT_SHEET.md

"I need to review concepts quickly"
    → FLASHCARDS_QUICK_REF.md

"I'm building my portfolio"
    → PORTFOLIO_PROJECTS.md

"I'm preparing for interviews"
    → INTERVIEW_AND_NETWORKING.md + FLASHCARDS_QUICK_REF.md

"I want external resources"
    → RESOURCE_LIBRARY.md
```

---

## ⚙️ Prerequisites

### Required Software
```bash
# Option A: Windows with WSL2
- Windows 10/11 with WSL2 installed
- Ubuntu on WSL2

# Option B: Linux VM
- VirtualBox or VMware
- Kali Linux or Ubuntu

# Both need:
- Python 3.9+
- Docker Desktop
- Burp Suite Community Edition
- VS Code (recommended)
- Git
```

### Setup Checklist
- [ ] WSL2 or Linux VM working
- [ ] Python 3 installed (`python3 --version`)
- [ ] Docker installed (`docker --version`)
- [ ] Burp Suite downloaded and running
- [ ] Can run `docker run -d -p 3000:3000 bkimminich/juice-shop`

---

## 🛤️ Learning Paths

### Path A: Application Security Focus
```
Week 1:    BEGINNER_START_HERE.md
Week 2-4:  cybersecurity_fundamentals (networking focus)
Week 5-8:  appsec_study_material.md (complete)
Week 9-10: PortSwigger Academy labs
Week 11+:  Bug bounty + Portfolio projects
```

### Path B: Cloud Security Focus
```
Week 1:    BEGINNER_START_HERE.md
Week 2-4:  cybersecurity_fundamentals (full)
Week 5-6:  appsec_study_material.md (API security)
Week 7-10: cloudsec_study_material.md (complete)
Week 11+:  flaws.cloud + AWS/Azure certs
```

### Path C: ML Security Focus
```
Week 1:    BEGINNER_START_HERE.md
Week 2-4:  cybersecurity_fundamentals
Week 5-6:  appsec_study_material.md (API, auth)
Week 7-8:  cloudsec_study_material.md (basics)
Week 9-12: ml_security_study_material.md (complete)
Week 13+:  ML security portfolio projects
```

### Path D: Balanced (Recommended)
```
Follow MASTER_STUDY_FLOW.md exactly — it covers all areas
in the optimal order over 16 weeks.
```

---

## ❓ FAQ

### How long will this take?
At 6 hours/week: **16 weeks** to complete core material. Add 4-8 weeks for portfolio projects and job search prep.

### Do I need to read everything?
No. Follow MASTER_STUDY_FLOW.md which tells you exactly what to read each week. Other documents are references.

### What if I get stuck?
1. Check FLASHCARDS_QUICK_REF.md for concept refreshers
2. Search RESOURCE_LIBRARY.md for external tutorials
3. Join null.community (Bangalore chapter) for help

### Is this enough to get a job?
This material + hands-on practice + portfolio projects = strong foundation. You'll also need:
- Networking (null community, LinkedIn)
- Interview practice
- Possibly 1 certification (see CERTIFICATIONS_ROADMAP_INDIA.md)

### How do I track progress?
Use the WEEKLY_STUDY_TEMPLATE.md to plan sessions and track completion.

### What makes this different from random tutorials?
- **Structured progression** — Topics build on each other
- **India-focused** — Relevant certifications, communities, companies
- **Portfolio-oriented** — Everything connects to demonstrable skills
- **Comprehensive** — No gaps in coverage

---

## 📊 Content Statistics

| Category | Files | Lines | Topics |
|----------|-------|-------|--------|
| Study Material | 9 | ~13,000 | Core security concepts |
| Prep Helpers | 12 | ~12,000 | Planning, exercises, career |
| **Total** | **21** | **~30,000** | Complete security education |

### Coverage by Domain
- ✅ Operating Systems (Linux, Windows)
- ✅ Networking (TCP/IP, DNS, HTTP, TLS)
- ✅ Web Security (OWASP Top 10, APIs)
- ✅ Cloud Security (AWS, Azure, GCP, K8s)
- ✅ ML/AI Security (LLMs, prompt injection)
- ✅ Cryptography (applied, not theoretical)
- ✅ Detection Engineering (SIEM, Sigma)
- ✅ Career Prep (India-specific)

---

## 🎓 Success Metrics

After completing this material, you should be able to:

### Knowledge
- [ ] Explain OWASP Top 10 vulnerabilities with examples
- [ ] Describe cloud IAM security for AWS/Azure/GCP
- [ ] Identify ML security threats (LLM Top 10)
- [ ] Understand cryptographic primitives and their misuse

### Skills
- [ ] Use Burp Suite for web security testing
- [ ] Write Python security scripts
- [ ] Analyze CloudTrail/Activity logs
- [ ] Set up and secure cloud resources

### Portfolio
- [ ] 3+ write-ups published (blog or GitHub)
- [ ] 1-2 security tools built
- [ ] CTF participation record
- [ ] Bug bounty submission (optional)

### Career
- [ ] Resume optimized for security roles
- [ ] LinkedIn profile complete
- [ ] Network of security contacts
- [ ] Interview-ready (technical + behavioral)

---

## 🤝 Contributing

This is a personal study repository. If you find errors or have suggestions:
1. The content was generated with AI assistance
2. Some links may become outdated
3. Feel free to fork and customize for your needs

---

## 📜 License

Personal educational use. External links point to their respective owners' content.

---

## 🚀 Start Now

**Your first action:** Open [MASTER_STUDY_FLOW.md](prep%20helpers/MASTER_STUDY_FLOW.md) and begin Week 1.

---

*Last updated: April 2026*

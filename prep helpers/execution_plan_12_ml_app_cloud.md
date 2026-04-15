# 12-WEEK EXECUTION PLAN (6 HOURS/WEEK)
Track: ML Security + AppSec + CloudSec
Primary language: Python
Goal: build a personal knowledgebase + portfolio artifacts (write-ups + small projects)
Version: April 2026

How to run this plan
- Weekly time: ~6 hours = 2 sessions x 3 hours (recommended)
- Every session ends with an artifact:
  - a 0.5–1 page note (knowledgebase)
  - OR a lab write-up (root cause → fix → detection)
  - OR a small PR/commit in your portfolio repo

Artifacts you’ll produce by Week 12
- 12–18 short write-ups (labs/incidents)
- 3 portfolio mini-projects (AppSec, CloudSec, ML Sec)
- 1 “security design doc” per project (threat model + controls + logging)

Where this plan references your existing materials
- AppSec text: [appsec_study_material.md](../study%20material/appsec_study_material.md)
- CloudSec text: [cloudsec_study_material.md](../study%20material/cloudsec_study_material.md)
- Crypto text: [cryptography_study_material.md](../study%20material/cryptography_study_material.md)
- Foundations+: [cybersecurity_foundations_plus.md](../study%20material/cybersecurity_foundations_plus.md)



## Generated Table of Contents
- [WEEK 0 (SETUP, 1–2 HOURS OPTIONAL)](#week-0-setup-12-hours-optional)
- [Create your working structure](#create-your-working-structure)
- [WEEK 1 — AppSec foundation: AuthN/AuthZ and IDOR](#week-1-appsec-foundation-authnauthz-and-idor)
- [Session A (3h)](#session-a-3h)
- [WEEK 2 — AppSec foundation: injection basics (SQLi/NoSQLi)](#week-2-appsec-foundation-injection-basics-sqlinosqli)
- [Session A (3h)](#session-a-3h)
- [WEEK 3 — Web security basics: sessions, CSRF, cookies](#week-3-web-security-basics-sessions-csrf-cookies)
- [Session A (3h)](#session-a-3h)
- [WEEK 4 — CloudSec foundation: identity and control-plane logging](#week-4-cloudsec-foundation-identity-and-control-plane-logging)
- [Session A (3h)](#session-a-3h)
- [WEEK 5 — Cloud data security: storage + guardrails](#week-5-cloud-data-security-storage-guardrails)
- [Session A (3h)](#session-a-3h)
- [WEEK 6 — Detection mindset: make AppSec + CloudSec observable](#week-6-detection-mindset-make-appsec-cloudsec-observable)
- [Session A (3h)](#session-a-3h)
- [WEEK 7 — ML Security foundation: threat model for ML systems](#week-7-ml-security-foundation-threat-model-for-ml-systems)
- [Session A (3h)](#session-a-3h)
- [WEEK 8 — ML Security: data poisoning and evaluation basics](#week-8-ml-security-data-poisoning-and-evaluation-basics)
- [Session A (3h)](#session-a-3h)
- [WEEK 9 — ML Security: model extraction, membership inference (high-level)](#week-9-ml-security-model-extraction-membership-inference-high-level)
- [Session A (3h)](#session-a-3h)
- [WEEK 10 — LLM / GenAI App Security (prompt injection + tool abuse)](#week-10-llm-genai-app-security-prompt-injection-tool-abuse)
- [Session A (3h)](#session-a-3h)
- [WEEK 11 — Portfolio integration: one project, end-to-end](#week-11-portfolio-integration-one-project-end-to-end)
- [Session A (3h)](#session-a-3h)
- [WEEK 12 — Final packaging: knowledgebase + interview-ready summaries](#week-12-final-packaging-knowledgebase-interview-ready-summaries)
- [Session A (3h)](#session-a-3h)

---

## WEEK 0 (SETUP, 1–2 HOURS OPTIONAL)
## Create your working structure
- One folder: notes/ (markdown or txt)
- One repo: portfolio/ (public if possible; no secrets)
- One template you reuse:
  - Title, System, Threat model, Finding, Fix, What to log, What to alert, References

Recommended folder structure:
```
study/
├── notes/
│   ├── appsec/
│   ├── cloudsec/
│   ├── mlsec/
│   └── templates/
│       └── finding_template.md
├── portfolio/
│   ├── README.md
│   ├── projects/
│   │   ├── secure-api-demo/
│   │   ├── cloud-security-lab/
│   │   └── ml-security-eval/
│   └── writeups/
│       ├── idor-analysis.md
│       ├── ssrf-cloud-metadata.md
│       └── ...
└── labs/
    └── lab-notes.md
```

Finding template (use for every lab):
```markdown
# [Title]

## System Description
Brief description of the application/system

## Threat Model
- Assets: 
- Entry points:
- Trust boundaries:

## Finding
- Vulnerability type:
- Severity: Critical/High/Medium/Low
- Location:

## Root Cause
Why does this vulnerability exist?

## Reproduction Steps
1. 
2. 
3. 

## Fix
- Code-level fix:
- Architecture-level fix:

## Detection
- What to log:
- What to alert on:
- Indicators of compromise:

## References
- 
```

Tooling (minimum)
- Burp Community
- Python 3.x
- Git
- VS Code with REST Client extension
- Optional: Docker


## WEEK 1 — AppSec foundation: AuthN/AuthZ and IDOR
## Session A (3h)
- Read: [appsec_study_material.md](../study%20material/appsec_study_material.md) sections on AuthN/AuthZ + access control + API security mental model
- Lab: PortSwigger “Access control” (at least 2 labs)
- Artifact: 1 write-up: IDOR/BOLA with fix patterns + detection signals

Session B (3h)
- Read: OWASP ASVS (skim control headings)
- Practice: write an authorization policy for a toy API:
  - GET /users/{id}
  - GET /users/{id}/orders
  - POST /orders
- Artifact: 1-page “Authorization ruleset” note + what to log


## WEEK 2 — AppSec foundation: injection basics (SQLi/NoSQLi)
## Session A (3h)
- Read: injection checklist in [appsec_study_material.md](../study%20material/appsec_study_material.md)
- Lab: PortSwigger SQLi (2 labs)
- Artifact: write-up focusing on root cause + parameterization fix

Session B (3h)
- Build a tiny Python demo locally (safe):
  - show bad string concatenation vs parameterized query (sqlite)
- Artifact: note: “How injection happens” + “safe query patterns”


## WEEK 3 — Web security basics: sessions, CSRF, cookies
## Session A (3h)
- Read: cookie attributes + CSRF mental model (appsec doc)
- Lab: PortSwigger CSRF (2 labs)
- Artifact: write-up: CSRF defenses + what breaks them

Session B (3h)
- Read: [cryptography_study_material.md](../study%20material/cryptography_study_material.md) sections on MAC vs signature vs AEAD
- Artifact: note mapping session security to crypto primitives (what is bearer, what is bound)


## WEEK 4 — CloudSec foundation: identity and control-plane logging
## Session A (3h)
- Read: [cloudsec_study_material.md](../study%20material/cloudsec_study_material.md) CS0A + CS4 + AWS/Azure runbooks sections
- Artifact: 1-page checklist: “Day-0 Cloud baseline” (AWS and Azure)

Session B (3h)
- Hands-on (pick ONE first: AWS or Azure):
  - enable control-plane logging (CloudTrail or Activity Log + diagnostics)
  - perform one safe change (e.g., NSG rule edit) and find it in logs
- Artifact: write-up: “who changed what” investigation with screenshots


## WEEK 5 — Cloud data security: storage + guardrails
## Session A (3h)
- Read: storage section in cloudsec doc + rookie mistakes section
- Artifact: note: “Public storage failure modes + guardrails”

Session B (3h)
- Hands-on:
  - create a storage resource
  - confirm public access is blocked (or demonstrate risk safely and then fix)
  - add a policy guardrail (AWS: block public access + policy; Azure: policy deny)
- Artifact: write-up with: misconfig → impact → fix → detection


## WEEK 6 — Detection mindset: make AppSec + CloudSec observable
## Session A (3h)
- Read: [cybersecurity_foundations_plus.md](../study%20material/cybersecurity_foundations_plus.md) logging/detection module
- Artifact: “Top 20 security events to log” for your future services

Session B (3h)
- Create 5 detection rules as plain English (Sigma-like logic):
  - IAM/RBAC changes
  - new public exposure
  - abnormal object-ID scans
  - brute force/login spray
  - suspicious outbound (SSRF/exfil patterns)
- Artifact: detection notes (no need for a SIEM yet)


## WEEK 7 — ML Security foundation: threat model for ML systems
## Session A (3h)
- Read: [ml_security_study_material.md](../study%20material/ml_security_study_material.md) (Covers ML threat model + core attack types)
- Artifact: 1-page “ML system DFD + assets + trust boundaries”

Session B (3h)
- Choose one ML scenario (recommendations):
  - resume screening model
  - fraud model
  - content moderation
  - LLM chat assistant with tools
- Artifact: threat model write-up using STRIDE + ML-specific threats


## WEEK 8 — ML Security: data poisoning and evaluation basics
## Session A (3h)
- Learn: poisoning vs backdoors; label noise vs targeted poisoning
- Artifact: note: “What data poisoning looks like in pipelines + defenses”

Session B (3h)
- Build a tiny evaluation harness in Python:
  - dataset split
  - metric tracking
  - basic drift check concept (distribution shift)
- Artifact: minimal repo code + README


## WEEK 9 — ML Security: model extraction, membership inference (high-level)
## Session A (3h)
- Read: threats: model stealing, inference attacks
- Artifact: note: “What can be learned from APIs” + rate limiting and output control

Session B (3h)
- Design: an API policy for an ML inference endpoint:
  - auth
  - quotas
  - logging
  - output minimization
- Artifact: design doc page


## WEEK 10 — LLM / GenAI App Security (prompt injection + tool abuse)
## Session A (3h)
- Study: OWASP LLM Top 10 + tool/plugin risks
- Artifact: note: “LLM threat model checklist”

Session B (3h)
- Build (local, safe) a tiny “LLM app skeleton” WITHOUT needing paid APIs:
  - simulate tool calls (functions) + add allowlist policy
  - add logging of tool invocations
- Artifact: repo skeleton + write-up: “prompt injection defense-in-depth”


## WEEK 11 — Portfolio integration: one project, end-to-end
## Session A (3h)
- Pick ONE portfolio project to polish (see portfolio_projects_blueprints in [ml_security_study_material.md](../study%20material/ml_security_study_material.md))
- Add: threat model + logging plan + tests

Session B (3h)
- Write: final report
  - system overview
  - risks
  - mitigations
  - what you can detect


## WEEK 12 — Final packaging: knowledgebase + interview-ready summaries
## Session A (3h)
- Create 5 “one-pagers”:
  - AppSec: AuthZ/IDOR
  - AppSec: Injection
  - CloudSec: IAM + logging
  - CloudSec: storage guardrails
  - ML Sec: end-to-end threat model

Session B (3h)
- Clean portfolio repo READMEs
- Make an index page listing:
  - write-ups
  - projects
  - what you learned

END OF 12-WEEK EXECUTION PLAN

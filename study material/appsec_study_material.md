# APPLICATION SECURITY (APPSEC) — VERY DETAILED STUDY MATERIAL (2026)
Goal: become strong in AppSec basics before specializing further
Audience: you already finished cybersecurity fundamentals

How this document relates to your Fundamentals doc
### This AppSec document assumes you have the foundations in:
- Networking (HTTP, DNS, TLS, proxies, PCAPs)
- OS fundamentals (processes, permissions, logs)
- Crypto basics (hashing vs encryption, TLS/PKI)
- Security engineering (threat modeling, secure design, SDLC)
- Python tooling (safe parsing, logging, dependency hygiene)

If you feel weak on a concept, jump back to your fundamentals doc:
- MODULE F (Networking) for HTTP/TLS/DNS
- MODULE G (Crypto) for TLS/PKI + password hashing
- MODULE L (Secure SDLC) for threat modeling + secure design
- MODULE O (Coding for security with Python) for safe tooling and validators

Safety & ethics (non-negotiable)
### Only test applications you own or have explicit permission to test.
Use training labs (PortSwigger/WebGoat/Juice Shop/CTFs) for offensive practice.



## Generated Table of Contents
  - [This AppSec document assumes you have the foundations in:](#this-appsec-document-assumes-you-have-the-foundations-in)
  - [Only test applications you own or have explicit permission to test.](#only-test-applications-you-own-or-have-explicit-permission-to-test)
- [Table of Contents](#table-of-contents)
  - [PART 0 — AppSec Orientation](#part-0-appsec-orientation)
  - [0.1 What AppSec is (and what it is not)](#01-what-appsec-is-and-what-it-is-not)
  - [0.2 AppSec mental models: assets, trust boundaries, parsing, identity](#02-appsec-mental-models-assets-trust-boundaries-parsing-identity)
  - [0.3 The AppSec “control stack”: product, platform, pipeline](#03-the-appsec-control-stack-product-platform-pipeline)
- [PART 1 — Web & API Foundations (AppSec View)](#part-1-web-api-foundations-appsec-view)
  - [1.1 HTTP deep fundamentals for AppSec](#11-http-deep-fundamentals-for-appsec)
  - [1.2 Cookies, sessions, and browser security model](#12-cookies-sessions-and-browser-security-model)
  - [1.3 APIs: REST, JSON, rate limits, idempotency, pagination](#13-apis-rest-json-rate-limits-idempotency-pagination)
  - [1.4 Authentication vs Authorization (the core distinction)](#14-authentication-vs-authorization-the-core-distinction)
  - [1.5 OAuth 2.0 + OpenID Connect (conceptual but practical)](#15-oauth-20-openid-connect-conceptual-but-practical)
- [PART 2 — Vulnerability Classes (Root Cause → Exploit Shape → Fix)](#part-2-vulnerability-classes-root-cause-exploit-shape-fix)
  - [2.1 Broken access control (IDOR and object-level authorization)](#21-broken-access-control-idor-and-object-level-authorization)
  - [2.2 Security misconfiguration](#22-security-misconfiguration)
  - [2.3 Software supply chain failures](#23-software-supply-chain-failures)
  - [2.4 Cryptographic failures (app-level)](#24-cryptographic-failures-app-level)
  - [2.5 Injection (SQL/NoSQL/OS command/template)](#25-injection-sqlnosqlos-commandtemplate)
  - [2.6 Insecure design (missing threat model)](#26-insecure-design-missing-threat-model)
  - [2.7 Authentication failures](#27-authentication-failures)
  - [2.8 Integrity failures (deserialization, CI/CD, update channels)](#28-integrity-failures-deserialization-cicd-update-channels)
  - [2.9 Logging and alerting failures](#29-logging-and-alerting-failures)
  - [2.10 Mishandling exceptional conditions (DoS, crashes, error leaks)](#210-mishandling-exceptional-conditions-dos-crashes-error-leaks)
- [PART 3 — Modern App Surface Areas](#part-3-modern-app-surface-areas)
  - [3.1 SSRF and internal service trust](#31-ssrf-and-internal-service-trust)
  - [3.2 File upload and content handling](#32-file-upload-and-content-handling)
  - [3.3 Caching layers (CDN/proxy) and security](#33-caching-layers-cdnproxy-and-security)
  - [3.4 Microservices & service-to-service auth](#34-microservices-service-to-service-auth)
  - [3.5 WebSockets and real-time systems](#35-websockets-and-real-time-systems)
  - [3.6 Mobile + API backends (high-level)](#36-mobile-api-backends-high-level)
- [PART 4 — AppSec Engineering (How to build secure apps)](#part-4-appsec-engineering-how-to-build-secure-apps)
  - [4.1 Threat modeling for apps (DFD + STRIDE)](#41-threat-modeling-for-apps-dfd-stride)
  - [4.2 Secure design patterns (least privilege, secure defaults)](#42-secure-design-patterns-least-privilege-secure-defaults)
  - [4.3 Secure logging & audit trails (what to log, what not to log)](#43-secure-logging-audit-trails-what-to-log-what-not-to-log)
  - [4.4 Secure error handling and safe defaults](#44-secure-error-handling-and-safe-defaults)
  - [4.5 Secrets management for apps](#45-secrets-management-for-apps)
- [PART 5 — AppSec Testing Methodology (Legal, repeatable)](#part-5-appsec-testing-methodology-legal-repeatable)
  - [5.1 How to think like a tester without becoming “tool-only”](#51-how-to-think-like-a-tester-without-becoming-tool-only)
  - [5.2 Manual testing workflow with Burp + browser devtools](#52-manual-testing-workflow-with-burp-browser-devtools)
  - [5.3 Basic code review mindset (language-agnostic)](#53-basic-code-review-mindset-language-agnostic)
  - [5.4 How to write a high-quality finding report](#54-how-to-write-a-high-quality-finding-report)
- [PART 6 — Standards, Checklists, and What “Good” Looks Like](#part-6-standards-checklists-and-what-good-looks-like)
  - [6.1 OWASP Top 10 (2025) mapping](#61-owasp-top-10-2025-mapping)
  - [6.2 OWASP ASVS levels (how to use as a checklist)](#62-owasp-asvs-levels-how-to-use-as-a-checklist)
  - [6.3 OWASP Cheat Sheets (how to apply)](#63-owasp-cheat-sheets-how-to-apply)
  - [6.4 Secure SDLC: SAST/DAST/dep scanning/secrets scanning](#64-secure-sdlc-sastdastdep-scanningsecrets-scanning)
- [PART 7 — Case Studies (Root cause thinking)](#part-7-case-studies-root-cause-thinking)
  - [7.1 Typical IDOR breach story](#71-typical-idor-breach-story)
  - [7.2 Typical SSRF-to-data-access story](#72-typical-ssrf-to-data-access-story)
  - [7.3 Typical supply chain incident story](#73-typical-supply-chain-incident-story)
  - [7.4 Typical auth reset flow failure story](#74-typical-auth-reset-flow-failure-story)
- [PART 8 — Labs and Resources (extensive)](#part-8-labs-and-resources-extensive)
  - [8.1 Best free lab curriculum (PortSwigger Academy)](#81-best-free-lab-curriculum-portswigger-academy)
  - [8.2 Local vulnerable apps (WebGoat/Juice Shop)](#82-local-vulnerable-apps-webgoatjuice-shop)
  - [8.3 API security practice](#83-api-security-practice)
  - [8.4 Code review practice sources](#84-code-review-practice-sources)
  - [8.5 YouTube and courses (curated)](#85-youtube-and-courses-curated)
- [PART 0 — APPSEC ORIENTATION](#part-0-appsec-orientation)
  - [0.1 What AppSec is (and what it is not)](#01-what-appsec-is-and-what-it-is-not)
  - [AppSec is the discipline of designing, building, reviewing, and testing software](#appsec-is-the-discipline-of-designing-building-reviewing-and-testing-software)
  - [0.2 AppSec mental models](#02-appsec-mental-models)
  - [Model #1: Trust boundaries](#model-1-trust-boundaries)
  - [0.3 The AppSec control stack](#03-the-appsec-control-stack)
  - [Controls exist at multiple layers:](#controls-exist-at-multiple-layers)
- [PART 1 — WEB & API FOUNDATIONS (APPSEC VIEW)](#part-1-web-api-foundations-appsec-view)
  - [1.1 HTTP deep fundamentals for AppSec](#11-http-deep-fundamentals-for-appsec)
  - [You must be comfortable reading raw HTTP.](#you-must-be-comfortable-reading-raw-http)
  - [1.2 Cookies, sessions, and browser security model](#12-cookies-sessions-and-browser-security-model)
  - [Sessions](#sessions)
  - [1.3 APIs: REST, JSON, rate limits](#13-apis-rest-json-rate-limits)
  - [What makes APIs vulnerable](#what-makes-apis-vulnerable)
  - [1.4 Authentication vs Authorization](#14-authentication-vs-authorization)
  - [Repeat until automatic:](#repeat-until-automatic)
  - [1.5 OAuth 2.0 + OpenID Connect (conceptual but practical)](#15-oauth-20-openid-connect-conceptual-but-practical)
  - [You should be able to draw these roles:](#you-should-be-able-to-draw-these-roles)
- [PART 2 — VULNERABILITY CLASSES (ROOT CAUSE → FIX)](#part-2-vulnerability-classes-root-cause-fix)
- [This section uses a standard format:](#this-section-uses-a-standard-format)
  - [2.1 Broken access control (IDOR)](#21-broken-access-control-idor)
  - [What it is](#what-it-is)
  - [2.2 Security misconfiguration](#22-security-misconfiguration)
  - [Examples](#examples)
  - [2.3 Software supply chain failures](#23-software-supply-chain-failures)
  - [Root cause](#root-cause)
  - [2.4 Cryptographic failures (app-level)](#24-cryptographic-failures-app-level)
  - [Root cause](#root-cause)
  - [2.5 Injection (SQL/NoSQL/OS command/template)](#25-injection-sqlnosqlos-commandtemplate)
  - [Root cause](#root-cause)
  - [2.6 Insecure design](#26-insecure-design)
  - [Root cause](#root-cause)
  - [2.7 Authentication failures](#27-authentication-failures)
  - [Root cause](#root-cause)
  - [2.8 Integrity failures](#28-integrity-failures)
  - [Examples](#examples)
  - [2.9 Logging and alerting failures](#29-logging-and-alerting-failures)
  - [Root cause](#root-cause)
  - [2.10 Mishandling exceptional conditions](#210-mishandling-exceptional-conditions)
  - [Examples](#examples)
- [PART 3 — MODERN APP SURFACE AREAS](#part-3-modern-app-surface-areas)
  - [3.1 SSRF](#31-ssrf)
  - [What it is](#what-it-is)
  - [3.2 File upload](#32-file-upload)
  - [Risks](#risks)
  - [3.3 Caching layers](#33-caching-layers)
  - [Risks](#risks)
  - [3.4 Microservices](#34-microservices)
  - [Risks](#risks)
- [PART 4 — APPSEC ENGINEERING](#part-4-appsec-engineering)
  - [4.1 Threat modeling for apps](#41-threat-modeling-for-apps)
  - [- draw DFD](#draw-dfd)
  - [4.2 Secure design patterns](#42-secure-design-patterns)
  - [- least privilege](#least-privilege)
  - [4.3 Secure logging](#43-secure-logging)
  - [Log](#log)
- [PART 5 — APPSEC TESTING METHODOLOGY (LEGAL)](#part-5-appsec-testing-methodology-legal)
  - [5.1 Testing mindset](#51-testing-mindset)
  - [- hypothesis-driven](#hypothesis-driven)
  - [5.2 Manual testing workflow (Burp)](#52-manual-testing-workflow-burp)
  - [- intercept requests](#intercept-requests)
  - [5.3 Code review mindset](#53-code-review-mindset)
  - [- find trust boundary crossings](#find-trust-boundary-crossings)
  - [5.4 Reporting](#54-reporting)
  - [A good finding includes](#a-good-finding-includes)
- [PART 6 — STANDARDS](#part-6-standards)
  - [6.1 OWASP Top 10 (2025)](#61-owasp-top-10-2025)
  - [6.2 OWASP ASVS](#62-owasp-asvs)
  - [6.3 OWASP Cheat Sheets](#63-owasp-cheat-sheets)
- [PART 7 — CASE STUDIES (TEMPLATES)](#part-7-case-studies-templates)
- [These are patterns you’ll see repeatedly.](#these-are-patterns-youll-see-repeatedly)
  - [7.1 IDOR breach pattern](#71-idor-breach-pattern)
  - [- root cause: missing object-level authZ](#root-cause-missing-object-level-authz)
  - [7.2 SSRF pattern](#72-ssrf-pattern)
  - [- root cause: server fetches URL from user input](#root-cause-server-fetches-url-from-user-input)
  - [7.3 Supply chain pattern](#73-supply-chain-pattern)
  - [- root cause: dependency/pipeline trust failure](#root-cause-dependencypipeline-trust-failure)
- [PART 8 — LABS AND RESOURCES (EXTENSIVE)](#part-8-labs-and-resources-extensive)
  - [8.1 Best free AppSec lab curriculum](#81-best-free-appsec-lab-curriculum)
  - [PortSwigger Web Security Academy (free learn + labs)](#portswigger-web-security-academy-free-learn-labs)
  - [8.2 Local vulnerable apps](#82-local-vulnerable-apps)
  - [8.3 AppSec references](#83-appsec-references)
  - [8.4 Tools (learning)](#84-tools-learning)
  - [8.5 YouTube (curated)](#85-youtube-curated)
  - [8.6 How to build portfolio for AppSec](#86-how-to-build-portfolio-for-appsec)
  - [Produce 10 write-ups (even from labs):](#produce-10-write-ups-even-from-labs)
- [APPSEC DEEP DIVE ADDENDUM (FULLER COVERAGE)](#appsec-deep-dive-addendum-fuller-coverage)
- [This addendum expands the earlier sections into “study notes” you can read like a textbook.](#this-addendum-expands-the-earlier-sections-into-study-notes-you-can-read-like-a-textbook)
  - [AD0) Primary AppSec standards & canonical references](#ad0-primary-appsec-standards-canonical-references)
  - [Use these as your “ground truth” texts for AppSec.](#use-these-as-your-ground-truth-texts-for-appsec)
  - [AD1) AppSec mental model: data, identity, and interpreters](#ad1-appsec-mental-model-data-identity-and-interpreters)
  - [Most AppSec bugs can be placed into one of these buckets:](#most-appsec-bugs-can-be-placed-into-one-of-these-buckets)
  - [AD1A) Extra basics that make AppSec “click”](#ad1a-extra-basics-that-make-appsec-click)
  - [These are the small fundamentals that dramatically improve AppSec intuition.](#these-are-the-small-fundamentals-that-dramatically-improve-appsec-intuition)
  - [AD2) HTTP and browser fundamentals (AppSec-level detail)](#ad2-http-and-browser-fundamentals-appsec-level-detail)
  - [You already learned HTTP in fundamentals. Here’s what AppSec needs beyond “how it works.”](#you-already-learned-http-in-fundamentals-heres-what-appsec-needs-beyond-how-it-works)
  - [AD2A) JavaScript for AppSec (minimal subset you actually need)](#ad2a-javascript-for-appsec-minimal-subset-you-actually-need)
  - [You do NOT need to become a front-end engineer to do AppSec.](#you-do-not-need-to-become-a-front-end-engineer-to-do-appsec)
  - [AD3) Authentication & authorization (deep, practical)](#ad3-authentication-authorization-deep-practical)
  - [AD3.1 Authentication (AuthN) failure patterns](#ad31-authentication-authn-failure-patterns)
  - [AD3A) OWASP API Security Top 10 (API threat model + practice)](#ad3a-owasp-api-security-top-10-api-threat-model-practice)
  - [Status note: OWASP’s API Top 10 is currently most commonly referenced as “2023”.](#status-note-owasps-api-top-10-is-currently-most-commonly-referenced-as-2023)
  - [AD4) Detailed vulnerability chapters (checklists)](#ad4-detailed-vulnerability-chapters-checklists)
  - [Use these as your testing + secure design checklists.](#use-these-as-your-testing-secure-design-checklists)
  - [AD5) AppSec engineering: building secure systems (beyond bug hunting)](#ad5-appsec-engineering-building-secure-systems-beyond-bug-hunting)
  - [AD5.1 Threat modeling workflow (practical)](#ad51-threat-modeling-workflow-practical)
  - [AD6) Case studies (deeper templates)](#ad6-case-studies-deeper-templates)
  - [Use these templates to practice reasoning. Replace details with your lab observations.](#use-these-templates-to-practice-reasoning-replace-details-with-your-lab-observations)
  - [AD7A) Secure API mini-reference (build & review checklist)](#ad7a-secure-api-mini-reference-build-review-checklist)
  - [Use this as a “design + code review” checklist for any API you build or assess.](#use-this-as-a-design-code-review-checklist-for-any-api-you-build-or-assess)
  - [AD7) AppSec labs: a structured way to do “extensive study”](#ad7-appsec-labs-a-structured-way-to-do-extensive-study)
  - [Instead of random labs, use a disciplined structure:](#instead-of-random-labs-use-a-disciplined-structure)
  - [AD8) Resources expansion (books, courses, videos)](#ad8-resources-expansion-books-courses-videos)
  - [If you only use a few resources, prioritize: OWASP + PortSwigger + one solid book + consistent labs.](#if-you-only-use-a-few-resources-prioritize-owasp-portswigger-one-solid-book-consistent-labs)
  - [AD9) Optional but valuable: modern AppSec surfaces (appendix)](#ad9-optional-but-valuable-modern-appsec-surfaces-appendix)
  - [This section is for “industry completeness” once your core skills are solid.](#this-section-is-for-industry-completeness-once-your-core-skills-are-solid)

---

## Table of Contents
### PART 0 — AppSec Orientation
### 0.1 What AppSec is (and what it is not)
### 0.2 AppSec mental models: assets, trust boundaries, parsing, identity
### 0.3 The AppSec “control stack”: product, platform, pipeline

## PART 1 — Web & API Foundations (AppSec View)
### 1.1 HTTP deep fundamentals for AppSec
### 1.2 Cookies, sessions, and browser security model
### 1.3 APIs: REST, JSON, rate limits, idempotency, pagination
### 1.4 Authentication vs Authorization (the core distinction)
### 1.5 OAuth 2.0 + OpenID Connect (conceptual but practical)

## PART 2 — Vulnerability Classes (Root Cause → Exploit Shape → Fix)
### 2.1 Broken access control (IDOR and object-level authorization)
### 2.2 Security misconfiguration
### 2.3 Software supply chain failures
### 2.4 Cryptographic failures (app-level)
### 2.5 Injection (SQL/NoSQL/OS command/template)
### 2.6 Insecure design (missing threat model)
### 2.7 Authentication failures
### 2.8 Integrity failures (deserialization, CI/CD, update channels)
### 2.9 Logging and alerting failures
### 2.10 Mishandling exceptional conditions (DoS, crashes, error leaks)

## PART 3 — Modern App Surface Areas
### 3.1 SSRF and internal service trust
### 3.2 File upload and content handling
### 3.3 Caching layers (CDN/proxy) and security
### 3.4 Microservices & service-to-service auth
### 3.5 WebSockets and real-time systems
### 3.6 Mobile + API backends (high-level)

## PART 4 — AppSec Engineering (How to build secure apps)
### 4.1 Threat modeling for apps (DFD + STRIDE)
### 4.2 Secure design patterns (least privilege, secure defaults)
### 4.3 Secure logging & audit trails (what to log, what not to log)
### 4.4 Secure error handling and safe defaults
### 4.5 Secrets management for apps

## PART 5 — AppSec Testing Methodology (Legal, repeatable)
### 5.1 How to think like a tester without becoming “tool-only”
### 5.2 Manual testing workflow with Burp + browser devtools
### 5.3 Basic code review mindset (language-agnostic)
### 5.4 How to write a high-quality finding report

## PART 6 — Standards, Checklists, and What “Good” Looks Like
### 6.1 OWASP Top 10 (2025) mapping
### 6.2 OWASP ASVS levels (how to use as a checklist)
### 6.3 OWASP Cheat Sheets (how to apply)
### 6.4 Secure SDLC: SAST/DAST/dep scanning/secrets scanning

## PART 7 — Case Studies (Root cause thinking)
### 7.1 Typical IDOR breach story
### 7.2 Typical SSRF-to-data-access story
### 7.3 Typical supply chain incident story
### 7.4 Typical auth reset flow failure story

## PART 8 — Labs and Resources (extensive)
### 8.1 Best free lab curriculum (PortSwigger Academy)
### 8.2 Local vulnerable apps (WebGoat/Juice Shop)
### 8.3 API security practice
### 8.4 Code review practice sources
### 8.5 YouTube and courses (curated)


## PART 0 — APPSEC ORIENTATION

### 0.1 What AppSec is (and what it is not)
### AppSec is the discipline of designing, building, reviewing, and testing software
so that:
- untrusted input cannot cause unsafe behavior
- identity and authorization are enforced correctly
- secrets and sensitive data are handled safely
- software updates and dependencies don’t become the attack vector
- monitoring makes incidents detectable and recoverable

AppSec is not:
- running scanners without understanding root causes
- “bug bounty tricks” without secure engineering mindset

### 0.2 AppSec mental models
### Model #1: Trust boundaries
- A trust boundary is where assumptions change.
- AppSec is largely “validate/authorize/log at boundaries.”

Model #2: Parsing and interpretation
- Many vulns happen because input is interpreted in multiple ways:
  - SQL parser interprets input as query
  - shell interprets input as commands
  - browser interprets input as JavaScript/HTML
  - template engines interpret input as code

Model #3: Identity is central
- Most serious application breaches are authorization failures.
- AuthN proves identity; AuthZ enforces permissions.

Model #4: Secure by default
- insecure defaults become mass-scale incidents.

### 0.3 The AppSec control stack
### Controls exist at multiple layers:
- Product/design: threat modeling, secure requirements
- Code: safe APIs, validation, authZ checks
- Build pipeline: dependency scanning, secret scanning, signing
- Runtime: WAF/proxy, rate limits, monitoring, alerting


## PART 1 — WEB & API FOUNDATIONS (APPSEC VIEW)

### 1.1 HTTP deep fundamentals for AppSec
### You must be comfortable reading raw HTTP.

Key concepts
- Request line: method + path + version
- Headers: Host, Cookie, Authorization, Content-Type, Origin/Referer
- Body: JSON, form-encoded, multipart
- Response: status code, headers, body

Methods (security implications)
- GET: should be safe and idempotent (in practice, sometimes isn’t)
- POST/PUT/PATCH/DELETE: state-changing; enforce CSRF protections in browser contexts

Status codes (security relevance)
- 401 vs 403:
  - 401 = not authenticated
  - 403 = authenticated but not authorized
- 404:
  - can hide existence but also used for security through obscurity (don’t rely solely)

Headers you must understand
- Cookie: session state
- Authorization: bearer tokens (risk: leakage → replay)
- Origin/Referer: CSRF defenses often rely on these (must be careful)

Practice
- Take any PortSwigger lab request and rewrite it as:
  - “Actor does X to object Y and server responds with Z.”

### 1.2 Cookies, sessions, and browser security model
### Sessions
- server stores session state; client stores session ID (cookie)

Cookie attributes
- Secure: only sent over HTTPS
- HttpOnly: JS cannot read (mitigates some token theft)
- SameSite: reduces CSRF in many cases

Browser security model
- Same-Origin Policy: prevents cross-origin reads
- CORS: controlled relaxation; NOT authorization
- CSP: reduces XSS impact

Practice
- In a lab app, identify cookie attributes and explain the risk tradeoffs.

### 1.3 APIs: REST, JSON, rate limits
### What makes APIs vulnerable
- APIs often bypass browser protections (no SOP/CSRF in the same way)
- APIs are “direct object” surfaces (IDOR risk)

Core API design concepts
- resource identity: stable IDs
- pagination: avoid returning too much data
- rate limiting: limit abuse and brute force
- versioning: prevent breaking clients and enable safe evolution

Security implications
- Rate limiting is both availability and auth protection.
- Pagination mistakes can become data leaks.

### 1.4 Authentication vs Authorization
### Repeat until automatic:
- Authentication: who are you?
- Authorization: what are you allowed to do?

Common AppSec failure
- “User is logged in” is mistakenly treated as “User can access any object.”

Gold standard
- Every request does server-side authorization checks for the target object.

### 1.5 OAuth 2.0 + OpenID Connect (conceptual but practical)
### You should be able to draw these roles:
- user (resource owner)
- client (app)
- authorization server (IdP)
- resource server (API)

Core security checks (conceptual)
- validate token issuer
- validate audience
- validate signature
- validate expiration

Common failure modes
- redirect URI validation mistakes
- weak token validation
- confusing OIDC (auth) with OAuth (authorization)


## PART 2 — VULNERABILITY CLASSES (ROOT CAUSE → FIX)
## This section uses a standard format:
- What it is
- Why it happens (root cause)
- Typical “exploit shape” (high-level)
- What to test (in labs)
- Fix patterns
- What to log

### 2.1 Broken access control (IDOR)
### What it is
- Users access objects they shouldn’t by manipulating IDs or parameters.

Root cause
- Missing or incorrect server-side authorization checks.

Exploit shape (high-level)
- Change object ID in request; server returns other user’s data.

What to test (labs)
- Are IDs predictable?
- Are there object-level checks?
- Do endpoints rely only on client-side UI restrictions?

Fix patterns
- Centralize authorization logic.
- Use ownership checks.
- Use policy-as-code where possible.

What to log
- denied authorization attempts
- cross-user object access patterns

### 2.2 Security misconfiguration
### Examples
- debug endpoints exposed
- overly permissive CORS
- insecure headers
- default creds
- exposed admin panels

Fix patterns
- secure defaults, environment separation
- hardening baselines

### 2.3 Software supply chain failures
### Root cause
- dependencies, build pipeline, or artifacts are not trusted/verified.

Fix patterns
- dependency pinning
- SBOM, signing, scanning

### 2.4 Cryptographic failures (app-level)
### Root cause
- wrong primitives or wrong usage.

Fix patterns
- use standard libraries
- use AEAD where appropriate
- strong password hashing

### 2.5 Injection (SQL/NoSQL/OS command/template)
### Root cause
- untrusted input becomes code in another interpreter.

Fix patterns
- parameterization
- safe APIs
- avoid shell

### 2.6 Insecure design
### Root cause
- threat model missing; no abuse cases; insecure workflow assumptions.

Fix patterns
- threat modeling
- secure requirements

### 2.7 Authentication failures
### Root cause
- weak passwords, weak reset flows, missing rate limits, MFA bypass logic.

Fix patterns
- MFA
- rate limiting
- secure reset flows

### 2.8 Integrity failures
### Examples
- insecure deserialization
- unsigned updates
- pipeline trust failures

Fix patterns
- signed artifacts
- safe serialization

### 2.9 Logging and alerting failures
Root cause
- No evidence means no detection, no response, and no forensics.
- Most breaches are discovered months later (or by third parties) because logging was absent or not monitored.

What you MUST log (minimum)
- Authentication events (success, failure, lockout)
- Authorization denials (who tried to access what)
- Admin/privileged actions
- Sensitive data access (PII reads, exports)
- Input validation failures (potential attack signals)
- Rate limit triggers

What you must NOT log
- Passwords (even failed ones)
- Full credit card numbers
- Session tokens / API keys
- Private keys or secrets

Log format best practice (structured JSON)
```json
{
  "timestamp": "2026-04-13T10:15:30Z",
  "event": "auth_failure",
  "actor": "user@example.com",
  "ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0...",
  "reason": "invalid_password",
  "request_id": "req-abc123"
}
```

Fix patterns
- Centralized logging (SIEM or log aggregation)
- Alerting on anomalies (auth failures, unusual patterns)
- Retention policy (compliance + investigation needs)
- Log integrity protection (immutable storage)

### 2.10 Mishandling exceptional conditions
### Examples
- error leaks
- DoS via expensive queries
- crash-only security

Fix patterns
- safe error handling
- resource limits


## PART 3 — MODERN APP SURFACE AREAS

### 3.1 SSRF (Server-Side Request Forgery)
What it is
- Application fetches a URL provided (or influenced) by the attacker.
- The server makes the request, so it has access to internal resources the attacker cannot reach directly.

Why SSRF is critical in cloud environments
- Cloud metadata endpoints (169.254.169.254) return credentials
- Internal services often have no authentication (trusted network assumption)
- Can pivot to databases, admin panels, other microservices

Common SSRF vectors
```
# Direct URL parameter
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Webhook/callback URLs
POST /api/webhook {"callback_url": "http://internal-admin:8080/"}

# PDF generators, image processors, URL previews
POST /generate-pdf {"source": "http://localhost:6379/"}

# Redirects (bypass naive allowlists)
http://attacker.com/redirect?to=http://169.254.169.254/
```

SSRF attack chain (real-world pattern)
1. Find URL fetch functionality
2. Test for internal access (localhost, 127.0.0.1, 169.254.x.x)
3. Retrieve cloud credentials from metadata endpoint
4. Use credentials to access S3/storage, escalate privileges
5. Exfiltrate data or persist access

Fix patterns (defense in depth)
- URL allowlist (specific domains/IPs only)
- Block private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8
- Block IPv6 equivalents (::1, fc00::/7, fe80::/10)
- Disable HTTP redirects or validate redirect targets
- Network egress controls (firewall/proxy)
- Cloud-specific: require IMDSv2 (AWS), disable metadata where possible
- Use dedicated egress proxy with logging

### 3.2 File upload
### Risks
- content-type confusion
- executable uploads
- storage bucket exposure

Fix patterns
- strict allowlists
- store outside webroot
- scan content

### 3.3 Caching layers
### Risks
- cache poisoning/deception (conceptual)

Fix
- correct cache keys, headers

### 3.4 Microservices
### Risks
- service-to-service trust assumptions

Fix
- mTLS/service identity


## PART 4 — APPSEC ENGINEERING

### 4.1 Threat modeling for apps
### - draw DFD
- mark trust boundaries
- list threats (STRIDE)
- mitigations

### 4.2 Secure design patterns
### - least privilege
- defense in depth
- secure defaults

### 4.3 Secure logging
### Log
- auth events
- admin actions
- authorization denials

Do NOT log
- passwords
- tokens


## PART 5 — APPSEC TESTING METHODOLOGY (LEGAL)

### 5.1 Testing mindset
### - hypothesis-driven
- evidence-driven
- minimize variables

### 5.2 Manual testing workflow (Burp)
### - intercept requests
- understand parameters
- replay safely in labs

### 5.3 Code review mindset
### - find trust boundary crossings
- find unsafe string composition
- find missing authZ checks

### 5.4 Reporting
### A good finding includes
- summary
- impact
- repro steps (lab)
- root cause
- fix
- detection/logging suggestions


## PART 6 — STANDARDS

### 6.1 OWASP Top 10 (2025)
[https://owasp.org/Top10/2025/](https://owasp.org/Top10/2025/)

Mapping to your study (priority order for AppSec roles):
| Rank | Category | Your Focus Area |
|------|----------|----------------|
| A01 | Broken Access Control | IDOR, missing authZ, privilege escalation |
| A02 | Cryptographic Failures | Weak hashing, cleartext secrets, bad TLS |
| A03 | Injection | SQLi, NoSQLi, command injection, template injection |
| A04 | Insecure Design | Missing threat model, unsafe architecture |
| A05 | Security Misconfiguration | Default creds, verbose errors, open cloud storage |
| A06 | Vulnerable Components | Outdated deps, no SCA, no SBOM |
| A07 | Auth Failures | Weak passwords, broken session, credential stuffing |
| A08 | Software/Data Integrity | Insecure deserialization, unsigned updates |
| A09 | Logging Failures | No logs, no alerts, no forensic capability |
| A10 | SSRF | Server fetches attacker URL, cloud metadata theft |

### 6.2 OWASP ASVS (Application Security Verification Standard)
[https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)

How to use ASVS:
- Level 1: Minimum baseline (all apps)
- Level 2: Standard security (most business apps)
- Level 3: High security (financial, healthcare, critical infra)

ASVS as a checklist workflow:
1. Pick a control category (e.g., V4 Access Control)
2. For each requirement, ask: "Does this app do this?"
3. Document gaps and prioritize fixes

### 6.3 OWASP Cheat Sheets
[https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)

Must-read cheat sheets for AppSec:
- Input Validation
- SQL Injection Prevention
- XSS Prevention
- CSRF Prevention
- Authentication
- Session Management
- Access Control
- Secrets Management
- Logging
- REST Security


## PART 7 — CASE STUDIES (TEMPLATES)
## These are patterns you’ll see repeatedly.

### 7.1 IDOR breach pattern
### - root cause: missing object-level authZ
- fix: server-side checks
- detection: cross-user access patterns

### 7.2 SSRF pattern
### - root cause: server fetches URL from user input
- fix: allowlist + egress control

### 7.3 Supply chain pattern
### - root cause: dependency/pipeline trust failure
- fix: signing + scanning + SBOM


## PART 8 — LABS AND RESOURCES (EXTENSIVE)

### 8.1 Best free AppSec lab curriculum
### PortSwigger Web Security Academy (free learn + labs)
- [https://portswigger.net/web-security](https://portswigger.net/web-security)

Suggested order (high ROI)
- Authentication
- Access control
- SQL injection
- XSS
- CSRF
- SSRF
- Deserialization
- OAuth
- CORS

### 8.2 Local vulnerable apps
- OWASP WebGoat: [https://owasp.org/www-project-webgoat/](https://owasp.org/www-project-webgoat/)
- OWASP Juice Shop: [https://owasp.org/www-project-juice-shop/](https://owasp.org/www-project-juice-shop/)

### 8.3 AppSec references
- OWASP Cheat Sheets: [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)
- OWASP ASVS: [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)

### 8.4 Tools (learning)
- Burp Suite Community (free): [https://portswigger.net/burp/communitydownload](https://portswigger.net/burp/communitydownload)
- Browser DevTools

### 8.5 YouTube (curated)
- PortSwigger playlists: [https://www.youtube.com/@PortSwigger/playlists](https://www.youtube.com/@PortSwigger/playlists)
- OWASP Global: [https://www.youtube.com/user/OWASPGLOBAL](https://www.youtube.com/user/OWASPGLOBAL)

### 8.6 How to build portfolio for AppSec
### Produce 10 write-ups (even from labs):
- focus on root cause + fix + detection
- include screenshots and sanitized request/response snippets


## APPSEC DEEP DIVE ADDENDUM (FULLER COVERAGE)
## This addendum expands the earlier sections into “study notes” you can read like a textbook.
It also adds AppSec-specific standards (OWASP API Security, OWASP Testing Guide) and more detailed checklists.


### AD0) Primary AppSec standards & canonical references
### Use these as your “ground truth” texts for AppSec.

OWASP
- OWASP Top 10 (2025): [https://owasp.org/Top10/2025/](https://owasp.org/Top10/2025/)
- OWASP ASVS: [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)
- OWASP Cheat Sheet Series: [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)
- OWASP Testing Guide (methodology reference): [https://owasp.org/www-project-web-security-testing-guide/](https://owasp.org/www-project-web-security-testing-guide/)

API security
- OWASP API Security Project (contains API Top 10): [https://owasp.org/www-project-api-security/](https://owasp.org/www-project-api-security/)

PortSwigger
- Web Security Academy (free learn + labs): [https://portswigger.net/web-security](https://portswigger.net/web-security)


### AD1) AppSec mental model: data, identity, and interpreters
### Most AppSec bugs can be placed into one of these buckets:

1) Identity failures
   - Authentication failures (who are you?)
   - Authorization failures (what are you allowed to do?)

2) Input/Interpreter failures
   - Untrusted data is interpreted as code (SQL, shell, JS, template)

3) Trust boundary failures
   - Server trusts internal network too much (SSRF)
   - Service trusts another service without a strong identity (microservices)

4) Operational failures
   - secrets leakage
   - weak logging
   - vulnerable dependencies

If you can label the bucket, you can usually find the fix pattern.


### AD1A) Extra basics that make AppSec “click”
### These are the small fundamentals that dramatically improve AppSec intuition.

AD1A.1 Encoding, parsing, and canonicalization (the hidden root cause)
- Know common encodings and when they are applied:
  - URL encoding (%2F), plus/space rules
  - HTML entity encoding (&lt;)
  - Base64 (not encryption)
  - Unicode normalization issues
- Why it matters: security checks often run on one representation while the sink uses another.

Practice checklist
- For any input validation rule, ask:
  - “What exact bytes arrive?”
  - “When is decoding done?”
  - “Can the input be represented in an equivalent way?”

AD1A.2 Data formats and dangerous transformations
- JSON: type confusion, duplicate keys, unexpected fields.
- XML: XXE risks (when enabled), entity expansion.
- YAML: unsafe loaders in some languages.
- Multipart forms: file upload handling is full of edge cases.

AD1A.3 Storage, state, and caching
- Cache keys and cache poisoning basics (CDN/proxy/app caches).
- Session state vs stateless JWTs (tradeoffs; revocation; audience/issuer).
- Replay risks if tokens aren’t bound to context.

AD1A.4 Databases and query building
- Understand parameterization vs string concatenation.
- Know how ORMs can still be vulnerable (raw queries, unsafe filters, dynamic order-by).

AD1A.5 Concurrency and time-of-check/time-of-use (TOCTOU)
- Race conditions in business flows (coupon usage, inventory, password reset).
- Idempotency keys and transaction boundaries.

AD1A.6 Minimal crypto hygiene for AppSec
- Password storage must be slow hashes (argon2/bcrypt/scrypt), never fast hashes.
- TLS is table stakes; don’t roll your own crypto.
- Sign vs encrypt (and why MAC/signatures matter for integrity).

If you understand AD1A well, AppSec goes from “bag of tricks” to predictable engineering.


### AD2) HTTP and browser fundamentals (AppSec-level detail)
### You already learned HTTP in fundamentals. Here’s what AppSec needs beyond “how it works.”

AD2.1 Methods and safety semantics
- GET should be safe (no state changes). When GET changes state, CSRF and caching risks explode.
- POST/PUT/PATCH/DELETE are state-changing and need stronger safeguards.

AD2.2 Cookies and session risk
Session cookies are bearer tokens: whoever has them can often act as the user.

Cookie attributes (must memorize meaning)
- Secure: only over HTTPS
- HttpOnly: JS can’t read (reduces some XSS token theft)
- SameSite:
  - Lax: blocks many CSRF patterns but not all
  - Strict: strongest but can break flows
  - None: allows cross-site but must be Secure

AD2.3 CSRF mechanics (correct mental model)
- CSRF happens because browsers automatically attach cookies.
- It is not “a JavaScript attack”; it’s a browser credential attachment behavior.

Standard CSRF defenses
- anti-CSRF tokens bound to session
- Origin/Referer validation (careful with proxies)
- SameSite (helpful, not magic)

AD2.4 Browser security model (what to actually remember)
- Same-Origin Policy prevents cross-origin reads by default.
- CORS relaxes SOP for specific origins.
- CORS is not authorization.

AD2.5 Security headers you must know
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options: nosniff
- Referrer-Policy
- Permissions-Policy

What to practice
- For any lab/app you test, write down:
  - which cookies exist, with which attributes
  - which security headers exist
  - what the threat model is if they are missing


### AD2A) JavaScript for AppSec (minimal subset you actually need)
### You do NOT need to become a front-end engineer to do AppSec.
You need enough JavaScript + DOM knowledge to:
- understand XSS (especially DOM XSS)
- spot dangerous client-side patterns in code reviews
- understand how SPAs call APIs (so you can find endpoints/params)

AD2A.1 Minimal JavaScript topics (learn these first)
- Data types: strings, numbers, booleans, null/undefined
- Collections: arrays, objects (JSON)
- Functions + arrow functions
- Conditionals/loops
- Promises and async/await (enough to read code)
- fetch basics (requests + reading JSON)

Minimal examples to understand
- JSON parse/stringify
- URL building and query params
- reading/writing DOM elements

AD2A.2 DOM basics (what matters for security)
Key concepts
- The DOM is a tree of nodes representing the page.
- DOM XSS happens when untrusted data flows into a dangerous sink.
- “Sanitize later” often fails; prefer safe rendering APIs.

Common sources (untrusted inputs)
- location.search, location.hash
- document.URL, document.referrer
- window.name
- postMessage data (message events)
- localStorage / sessionStorage (treat as attacker-controlled if XSS exists)
- server responses (APIs returning HTML or unsafe strings)

Common sinks (dangerous outputs)
- element.innerHTML, element.outerHTML
- element.insertAdjacentHTML(...)
- document.write(...)
- eval(...), Function(...)
- setTimeout(string), setInterval(string)
- element.src / href / style with attacker-controlled values (context matters)
- navigation sinks: location = ..., location.assign(...)

Rule of thumb
- If data can reach any of these sinks without context-aware encoding or safe APIs, assume XSS risk.

AD2A.3 Safe patterns you should recognize
- Prefer text APIs:
  - element.textContent
  - document.createElement + setAttribute (careful with URL attributes)
- Template rendering that escapes by default (framework-dependent)
- Strict CSP as defense-in-depth (not a replacement for fixing the bug)

AD2A.4 SPA/API reality check
- Many modern apps are SPAs.
- Even if you don’t “write JS”, you must be able to:
  - find API calls in the Network tab
  - locate endpoints in bundled JS
  - understand token storage choices (cookies vs localStorage)

Token storage quick guidance
- HttpOnly cookies reduce some token-theft XSS paths.
- localStorage is readable by any injected JS; treat as higher risk.
- Neither choice fixes broken authorization.

AD2A.5 Practice plan (10–15 hours total)
1) Learn the basics (syntax + async/await + fetch)
2) Read 10 DOM XSS examples and identify source->sink
3) Do PortSwigger labs:
   - XSS
   - DOM-based XSS
4) Write 5 mini write-ups:
   - source
   - sink
   - exploit payload
   - fix pattern
   - what to log

If you can do DOM XSS labs confidently, you have enough JavaScript for most AppSec roles.


### AD3) Authentication & authorization (deep, practical)
### AD3.1 Authentication (AuthN) failure patterns
- brute force/spraying allowed due to missing rate limits
- weak password reset flow:
  - predictable tokens
  - token not bound to user
  - token not expiring
  - reset leaks whether account exists
- MFA bypass via logic:
  - “remember this device” implemented incorrectly
  - step-up auth not enforced for sensitive actions

AD3.2 Authorization (AuthZ) failure patterns
- missing object-level checks (IDOR)
- role checks done only in UI/client
- multi-tenant isolation failures
- confused-deputy problems: service A calls service B with too much privilege

AuthZ “gold rule”
- Every sensitive action must check:
  - who is the actor
  - what object they are acting on
  - what policy applies

What to log
- auth failures (with rate info)
- successful logins (with device/IP context)
- authorization denials
- privilege changes


### AD3A) OWASP API Security Top 10 (API threat model + practice)
### Status note: OWASP’s API Top 10 is currently most commonly referenced as “2023”.
Use it alongside OWASP Top 10 and ASVS; API risk is mostly AuthZ + abuse + inventory.

API-first mental model
- APIs are usually “headless”: the browser isn’t your main security boundary.
- The core boundary is the server enforcing identity + authorization + resource limits.
- Treat every API endpoint as a public interface unless proven otherwise.

API-specific assets & trust boundaries
- Assets: account data, payment actions, PII, admin functions, internal services.
- Identities:
  - end-user identity
  - service identity (microservices)
  - device/session identity (mobile)
- Trust boundaries:
  - internet -> API gateway
  - gateway -> service
  - service -> database
  - service -> other internal services

How to study APIs (repeat on every target)
1) Inventory endpoints: paths, methods, auth requirements, roles.
2) Identify object identifiers: accountId, userId, orderId, tenantId.
3) Identify “sensitive flows”: password reset, money movement, invite/transfer.
4) Identify resource-heavy endpoints: search, export, report, image processing.
5) Define expected authorization policy (write it down) before you test.

API1:2023 Broken Object Level Authorization (BOLA)
- Symptom: you can access another user’s object by changing an ID.
- Test:
  - change object IDs in URL/body/query
  - use a different user token
  - test “list” endpoints (do you see others?)
- Fix:
  - server-side ownership checks per request
  - tenant scoping everywhere (query + policy)
- Telemetry:
  - one user requesting many distinct object IDs
  - spikes in 403/404 on object endpoints

API2:2023 Broken Authentication
- Symptom: weak tokens, missing MFA for sensitive flows, brute force allowed.
- Test:
  - rate limiting on login/token endpoints
  - token lifetime, revocation, audience/issuer validation
- Fix:
  - strong token validation, MFA/step-up, brute-force protections
- Telemetry:
  - high failed logins, credential stuffing patterns

API3:2023 Broken Object Property Level Authorization (BOPLA)
- Symptom: you can read/write fields you shouldn’t (overexposure / mass assignment).
- Test:
  - try adding extra JSON fields (e.g., role, isAdmin, price, userId)
  - check responses for overexposed PII fields
- Fix:
  - explicit DTOs / allowlisted fields
  - response shaping / remove sensitive fields by default
- Telemetry:
  - requests containing unexpected fields

API4:2023 Unrestricted Resource Consumption
- Symptom: DoS/cost blowups via large payloads, expensive queries, huge page sizes.
- Test:
  - set extreme pagination values
  - large JSON bodies, repeated exports, heavy filters
- Fix:
  - per-user/IP rate limits and quotas
  - max page size, request size caps
  - timeouts and circuit breakers
- Telemetry:
  - latency spikes, high cardinality query parameters, large response sizes

API5:2023 Broken Function Level Authorization (BFLA)
- Symptom: you can call admin endpoints as a normal user.
- Test:
  - enumerate endpoints from client apps / OpenAPI specs
  - try privileged actions with low-priv tokens
- Fix:
  - enforce role checks server-side for every privileged function
- Telemetry:
  - normal users calling admin routes

API6:2023 Unrestricted Access to Sensitive Business Flows
- Symptom: abuse of business flows (e.g., password reset spam, promo abuse, scalping).
- Test:
  - automate flow steps; see if limits exist
- Fix:
  - per-user + per-identity rate limits
  - bot mitigation where appropriate
- Telemetry:
  - repeated flow executions, abnormal success rates

API7:2023 Server Side Request Forgery (SSRF)
- Symptom: API fetches URLs or makes internal calls based on user input.
- Test:
  - supply internal URLs, redirects, alternate IP formats
- Fix:
  - allowlists + block private ranges + egress control
- Telemetry:
  - outbound calls to internal IP ranges or metadata endpoints

API8:2023 Security Misconfiguration
- Symptom: debug settings, permissive CORS, weak TLS, verbose errors.
- Test:
  - check headers, error bodies, CORS allowlists, TLS config
- Fix:
  - secure defaults + hardened deployment templates
- Telemetry:
  - config drift and policy violations

API9:2023 Improper Inventory Management
- Symptom: shadow APIs, old versions still live, undocumented endpoints.
- Test:
  - look for multiple versions (/v1, /v2)
  - probe for “hidden” endpoints from mobile/web clients
- Fix:
  - maintain an API inventory (OpenAPI), deprecate old versions
- Telemetry:
  - traffic to deprecated routes

API10:2023 Unsafe Consumption of APIs
- Symptom: you trust third-party API responses too much; SSRF-like behavior; injection.
- Test:
  - validate assumptions about external API data
- Fix:
  - validate third-party data, enforce schemas, timeouts, retries
- Telemetry:
  - failures talking to dependencies; suspicious external payload patterns

API testing practice (tooling-agnostic)
- Use Burp for exploration and session handling.
- Use curl/http clients for repeatable test cases.
- Build a habit: every issue should include (1) proof (2) fix (3) what to log.


### AD4) Detailed vulnerability chapters (checklists)
### Use these as your testing + secure design checklists.

AD4.1 Broken Access Control / IDOR
Checklist
- Object IDs:
  - are IDs guessable/sequential?
  - are there alternate IDs (email, username) used as identifiers?
- Authorization enforcement:
  - does the server check ownership/role per request?
  - are list endpoints filtered correctly?
- Multi-step flows:
  - can a user access “step 2” directly?

Fix patterns
- policy checks centralized
- deny-by-default
- server-side filtering for lists

Detection ideas
- repeated 403/404 patterns on object endpoints
- one user accessing many different object IDs

Labs
- PortSwigger: Access Control topic


AD4.2 Injection (SQL/NoSQL/OS command/template)
Checklist
- Identify interpreter boundaries:
  - SQL
  - shell
  - template engine
  - LDAP queries
- Look for unsafe composition:
  - concatenated strings
  - dynamic query building

Fix patterns
- parameterized queries
- safe library APIs
- input validation + allowlists

Labs
- PortSwigger: SQL injection, NoSQL injection, OS command injection, SSTI


AD4.3 XSS
Checklist
- Where is user-controlled data rendered?
  - HTML body
  - attributes
  - JavaScript contexts
  - DOM updates
- Are there encoding and output context protections?
- Is CSP present and meaningful?

Fix patterns
- context-aware output encoding
- CSP as defense-in-depth
- avoid dangerous sinks in DOM

Labs
- PortSwigger: XSS


AD4.4 CSRF
Checklist
- Are state-changing endpoints cookie-authenticated?
- Are anti-CSRF tokens used?
- Are Origin/Referer checks used correctly?
- Are cookies SameSite appropriately?

Fix patterns
- CSRF tokens + SameSite + origin checks

Labs
- PortSwigger: CSRF


AD4.5 SSRF
Checklist
- Does the server fetch URLs based on user input?
- Are internal IP ranges blocked?
- Are redirects handled safely?
- Is egress restricted?

Fix patterns
- allowlists
- block internal address ranges
- isolate sensitive metadata endpoints
- egress control + monitoring

Labs
- PortSwigger: SSRF


AD4.6 Insecure deserialization / integrity failures
Checklist
- Are unsafe serializers used for untrusted input?
- Are signed artifacts required?
- Are update channels verified?

Fix patterns
- avoid unsafe serializers
- sign and verify

Labs
- PortSwigger: Deserialization


AD4.7 Security misconfiguration
Checklist
- Debug mode off in production?
- CORS allowlist correct?
- TLS configuration correct?
- Directory listing/admin panels exposed?

Fix patterns
- secure defaults
- hardened deployment templates


AD4.8 Supply chain failures
Checklist
- are dependencies pinned and reviewed?
- is there dependency scanning?
- are build artifacts signed?

Fix patterns
- SBOM + signing + scanning


### AD5) AppSec engineering: building secure systems (beyond bug hunting)
### AD5.1 Threat modeling workflow (practical)
1) Draw a DFD
2) Mark trust boundaries
3) Identify assets
4) Apply STRIDE to each boundary
5) Write mitigations
6) Define logging requirements

Deliverable
- DFD + threat list + mitigation plan + telemetry plan

AD5.2 Secure SDLC for AppSec
- Code time:
  - secure code review checklists
  - secret scanning
  - dependency scanning
- Build time:
  - CI gates
  - artifact signing
- Run time:
  - monitoring
  - rate limiting

AD5.3 Secure code review: what to look for (language-agnostic)
- Data sources:
  - user input enters system
- Trust boundaries:
  - where data crosses into SQL/shell/template
- Authorization checks:
  - ensure checks exist per request
- Error handling:
  - ensure errors don’t leak secrets
- Logging:
  - ensure security events exist


### AD6) Case studies (deeper templates)
### Use these templates to practice reasoning. Replace details with your lab observations.

AD6.1 IDOR case study template
- System: (describe app)
- Asset: (what data is exposed)
- Root cause: missing object-level check
- Evidence:
  - request/response differences
  - logs you would expect
- Fix:
  - authorization policy
  - tests
- Detection:
  - rate anomalies, object ID scans

AD6.2 SSRF case study template
- System: endpoint that fetches URL
- Root cause: unvalidated URL + internal reachability
- Fix: allowlist + network egress control
- Detection: outbound requests to internal ranges

AD6.3 Supply chain case study template
- System: dependency update introduces malicious behavior
- Root cause: no pinning / no integrity verification
- Fix: SBOM + signing + scanning + review


### AD7A) Secure API mini-reference (build & review checklist)
### Use this as a “design + code review” checklist for any API you build or assess.

Identity & tokens
- Prefer short-lived access tokens; keep refresh tokens protected.
- Validate tokens correctly:
  - signature
  - issuer (iss), audience (aud), expiry (exp), not-before (nbf)
  - algorithm pinned (avoid alg confusion)
- Implement logout/revocation strategy (or justify why not possible).

Authorization
- Object-level checks: ownership/tenant scoping on every object access.
- Function-level checks: admin endpoints require admin roles server-side.
- Property-level controls:
  - allowlist writable fields (prevent mass assignment)
  - avoid overexposing response fields by default

Abuse controls
- Rate limit:
  - login/token endpoints
  - sensitive business flows
  - expensive endpoints (search/export)
- Add quotas (per user / per tenant) for cost-heavy operations.

Input validation & schema
- Enforce request size limits.
- Validate JSON schema strictly (types, ranges, required fields).
- Reject unexpected fields by default (helps against BOPLA/mass assignment).

Operational hardening
- Consistent error handling (no stack traces, no secret leakage).
- Security headers for browser-facing APIs (if used by web clients).
- CORS allowlists tight and reviewed; remember: CORS != authorization.

Logging & detection
- Log security events:
  - auth failures/success
  - authorization denials
  - rate limit triggers
  - privilege changes
- Include request IDs and user/tenant IDs for correlation.

Versioning & inventory
- Maintain an OpenAPI spec and use it as inventory.
- Deprecate old versions with an explicit timeline.


### AD7) AppSec labs: a structured way to do “extensive study”
### Instead of random labs, use a disciplined structure:

For each vulnerability topic:
1) Read the PortSwigger explanation
2) Do 3–10 labs
3) For each lab, write:
   - root cause
   - fix pattern
   - what to log
   - what an alert would look like
4) Add 5 flashcards

Suggested deep study order (repeat for mastery)
1) Authentication
2) Access control
3) SQL injection
4) XSS
5) SSRF
6) Deserialization/integrity
7) OAuth/OIDC
8) Business logic


### AD8) Resources expansion (books, courses, videos)
### If you only use a few resources, prioritize: OWASP + PortSwigger + one solid book + consistent labs.

Standards and reference docs (authoritative)
- OWASP Cheat Sheets: [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)
- OWASP ASVS: [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)
- OWASP Web Security Testing Guide: [https://owasp.org/www-project-web-security-testing-guide/](https://owasp.org/www-project-web-security-testing-guide/)
- OWASP API Security Project: [https://owasp.org/www-project-api-security/](https://owasp.org/www-project-api-security/)
- OWASP Proactive Controls: [https://top10proactive.owasp.org/](https://top10proactive.owasp.org/)

Web platform references (must-have for modern web/AppSec)
- MDN Web Docs (cookies, CORS, CSP, fetch, DOM): [https://developer.mozilla.org/](https://developer.mozilla.org/)

Protocol / token specs (useful when you go deeper)
- RFC Editor (search portal): [https://www.rfc-editor.org/](https://www.rfc-editor.org/)
- OAuth 2.0 (RFC 6749): [https://www.rfc-editor.org/rfc/rfc6749](https://www.rfc-editor.org/rfc/rfc6749)
- HTTP Semantics (RFC 9110): [https://www.rfc-editor.org/rfc/rfc9110](https://www.rfc-editor.org/rfc/rfc9110)
- Cookies (RFC 6265): [https://www.rfc-editor.org/rfc/rfc6265](https://www.rfc-editor.org/rfc/rfc6265)
- JWT (RFC 7519): [https://www.rfc-editor.org/rfc/rfc7519](https://www.rfc-editor.org/rfc/rfc7519)

Labs / learning platforms (high ROI)
- PortSwigger Web Security Academy: [https://portswigger.net/web-security](https://portswigger.net/web-security)
- OWASP Juice Shop: [https://owasp.org/www-project-juice-shop/](https://owasp.org/www-project-juice-shop/)
- WebGoat: [https://owasp.org/www-project-webgoat/](https://owasp.org/www-project-webgoat/)
- DVWA (Damn Vulnerable Web Application): [https://dvwa.co.uk/](https://dvwa.co.uk/)

Books (high-signal)
- Web Application Hacker’s Handbook (classic reference)
- Real-World Bug Hunting (Nogueras)
- Bug Bounty Bootcamp (Sönmez)
- Tangled Web (Zalewski) (browser/web security mental models)
- API Security in Action (API-focused)
- Threat Modeling: Designing for Security (Shostack)

YouTube (good for reinforcement)
- PortSwigger
- OWASP Foundation / OWASP Global

Tooling docs (learn the tool from the source)
- Burp Suite docs: [https://portswigger.net/burp/documentation](https://portswigger.net/burp/documentation)
- OWASP ZAP: [https://www.zaproxy.org/](https://www.zaproxy.org/)

Secure coding + code review (especially useful with Python/Java)
- OWASP Code Review Guide: [https://owasp.org/www-project-code-review-guide/](https://owasp.org/www-project-code-review-guide/)
- OWASP Secure Coding Practices: [https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

If you want “one path”
1) PortSwigger Academy (systematically)
2) OWASP Cheat Sheets (per topic)
3) One book (Bug Bounty Bootcamp or WAHH)
4) Write-ups from every lab (root cause + fix + detection)


### AD9) Optional but valuable: modern AppSec surfaces (appendix)
### This section is for “industry completeness” once your core skills are solid.

AD9.1 GraphQL security (common failure modes)
- Introspection exposure: can leak schema and help attackers enumerate.
- Authorization:
  - field-level and object-level authorization must still be enforced.
  - don’t assume “one endpoint” is simpler; it often hides more complexity.
- Query complexity abuse:
  - nested queries can be expensive (DoS/cost).
  - add depth/complexity limits.
- Mass assignment-like issues via flexible inputs.

What to test
- Can you access fields you shouldn’t?
- Can you request objects for another user/tenant?
- Can you cause large/slow queries?

References
- OWASP GraphQL Security Cheat Sheet: [https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)


AD9.2 WebSockets / real-time APIs
- Auth model:
  - is auth checked only at connect time?
  - can you keep a socket after logout/token expiry?
- Message authorization:
  - is every message validated and authorized?
- Origin checks:
  - browser clients send Origin; servers should validate if relevant.
- Input validation:
  - treat every message as untrusted input.

What to log
- connect/disconnect
- auth failures
- unusual message rates


AD9.3 Cloud metadata SSRF (why SSRF is worse in cloud)
- Many cloud environments expose instance metadata endpoints.
- SSRF can become credential theft.

### AD9.3A Cloud SSRF Deep Dive (Critical Knowledge)

**Why SSRF is devastating in cloud:**
```
Traditional SSRF: Access internal services, port scan
Cloud SSRF: Steal IAM credentials → full account compromise

The metadata service is an internal API that provides:
- Instance identity
- Temporary credentials
- Configuration data
- Network information
```

**AWS Metadata Service (IMDS):**
```
IMDSv1 (legacy, vulnerable):
  curl http://169.254.169.254/latest/meta-data/
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name

IMDSv2 (more secure):
  # Requires a token obtained via PUT request
  TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  curl -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/
```

**SSRF bypassing IMDSv2:**
```
IMDSv2 helps but isn't perfect:
- Some SSRF vulnerabilities allow setting headers (full bypass)
- DNS rebinding can work in some cases
- Containers/ECS tasks may use different metadata endpoints
```

**Azure Instance Metadata:**
```
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Get managed identity token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

**GCP Metadata:**
```
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/"

# Get service account token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

**Kubernetes Service Account Tokens:**
```
# In a pod, credentials are mounted:
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# SSRF to internal K8s API
curl -k https://kubernetes.default.svc/api/v1/namespaces
```

**SSRF Defense Layers:**
```python
from urllib.parse import urlparse
import ipaddress
import socket

# Layer 1: URL scheme validation
ALLOWED_SCHEMES = {'http', 'https'}

# Layer 2: Blocked IP ranges
BLOCKED_RANGES = [
    '10.0.0.0/8',       # Private
    '172.16.0.0/12',    # Private
    '192.168.0.0/16',   # Private
    '169.254.0.0/16',   # Link-local (METADATA!)
    '127.0.0.0/8',      # Localhost
    '0.0.0.0/8',        # Current network
    '100.64.0.0/10',    # Carrier-grade NAT
    'fd00::/8',         # IPv6 private
    '::1/128',          # IPv6 localhost
]

# Layer 3: Domain allowlist (most secure)
ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com'}

def is_safe_url(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False, "Invalid scheme"
        
        # Check domain allowlist
        if parsed.hostname not in ALLOWED_DOMAINS:
            return False, "Domain not allowed"
        
        # Resolve and check IP
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        for cidr in BLOCKED_RANGES:
            if ip_obj in ipaddress.ip_network(cidr):
                return False, f"Blocked IP range: {cidr}"
        
        return True, "OK"
    except Exception as e:
        return False, str(e)
```

**Cloud-level defenses:**
```yaml
AWS:
  - Require IMDSv2 (blocks simple SSRF)
  - Use VPC endpoints for AWS services
  - Use workload identity (IRSA) instead of instance roles
  - Enable metadata endpoint restrictions

Azure:
  - Use managed identities with minimal permissions
  - Implement NSG rules
  - Use private endpoints

GCP:
  - Enable Workload Identity
  - Use VPC Service Controls
  - Restrict metadata access
```

### AD9.3B SSRF Testing Checklist

```yaml
ssrf_testing:
  discovery:
    - Find URL input parameters (url=, src=, dest=, redirect=)
    - Find webhook configurations
    - Find URL preview/unfurl features
    - Find file import from URL features
    - Find PDF/image generators that fetch URLs
    
  basic_tests:
    - http://127.0.0.1/
    - http://localhost/
    - http://[::1]/
    - http://0.0.0.0/
    
  cloud_metadata:
    - http://169.254.169.254/ (AWS/Azure)
    - http://metadata.google.internal/ (GCP)
    - http://100.100.100.200/ (Alibaba)
    
  bypass_attempts:
    - URL encoding: http://169.254.169.254 → http://%31%36%39%2e%32%35%34...
    - Decimal IP: http://2852039166/ (169.254.169.254 as integer)
    - Redirect: http://attacker.com/redirect?to=http://169.254.169.254
    - DNS rebinding: Use a domain that resolves to internal IP
    - IPv6: http://[::ffff:169.254.169.254]/
    
  what_to_log:
    - All outbound HTTP requests with destination
    - Failed requests (blocked by firewall)
    - Requests to internal IP ranges
    - Unusual URL patterns
```


AD9.4 CI/CD and build pipeline security (supply chain reality)
Threats
- malicious dependency updates
- compromised build runner
- leaked signing keys
- insecure artifact publishing

Controls
- pin dependencies + lockfiles
- run SCA + secret scanning in CI
- sign artifacts
- least privilege for CI tokens

References
- SLSA (Supply-chain Levels for Software Artifacts): [https://slsa.dev/](https://slsa.dev/)


### AD9.4A Deserialization Vulnerabilities Deep Dive

**What is Deserialization?**
```
Serialization: Object → Bytes (for storage/transmission)
Deserialization: Bytes → Object

The danger: Deserializing untrusted data can execute arbitrary code
```

**Why it's dangerous:**
```
1. Many serialization formats allow code execution during deserialization
2. Attackers can craft payloads that:
   - Execute system commands
   - Create reverse shells
   - Read/write files
   - Establish persistence
```

**Language-Specific Examples:**

**Python (pickle):**
```python
import pickle

# Malicious payload that executes code on unpickle
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('id',))  # Executes 'id' command

# When unpickled, this runs arbitrary code
payload = pickle.dumps(Exploit())
pickle.loads(payload)  # DANGER: Executes 'id'
```

**Java (ObjectInputStream):**
```java
// Vulnerable code
ObjectInputStream ois = new ObjectInputStream(untrustedInput);
Object obj = ois.readObject();  // DANGER!

// This has led to many CVEs:
// - Apache Commons Collections gadget chains
// - Log4Shell (CVE-2021-44228) partially related
// - Many application server vulnerabilities
```

**PHP (unserialize):**
```php
// Vulnerable code
$data = unserialize($_POST['data']);  // DANGER!

// Magic methods like __wakeup(), __destruct() can be abused
```

**YAML (unsafe load):**
```python
import yaml

# VULNERABLE
data = yaml.load(user_input)  # Can execute code!

# SAFE
data = yaml.safe_load(user_input)  # Only basic types
```

**Defenses:**

```python
# 1. Don't deserialize untrusted data (best)
# 2. Use safe formats (JSON, protobuf)
# 3. Sign serialized data

import json
import hmac
import hashlib
import base64

SECRET_KEY = b"your-secret-key"

def safe_serialize(obj):
    """Serialize with integrity protection."""
    json_data = json.dumps(obj)
    signature = hmac.new(SECRET_KEY, json_data.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(f"{json_data}|{signature}".encode()).decode()

def safe_deserialize(data):
    """Deserialize with signature verification."""
    decoded = base64.b64decode(data).decode()
    json_data, signature = decoded.rsplit('|', 1)
    
    expected = hmac.new(SECRET_KEY, json_data.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid signature")
    
    return json.loads(json_data)
```

**Detection:**
```yaml
detection_signals:
  - Unusual POST bodies with serialized objects
  - Java: "aced0005" magic bytes (serialized Java)
  - Python: Pickle magic bytes
  - Errors mentioning deserialization, ObjectInputStream, pickle
  - Unexpected outbound connections after processing data
```

**Testing:**
```
Tools:
- ysoserial (Java gadget chains)
- marshalsec (Java/other)
- Custom pickle payloads (Python)

Manual testing:
1. Identify deserialization points
2. Try standard gadget chains
3. Monitor for code execution indicators
4. Check for out-of-band callbacks
```


AD9.5 SAST/DAST/SCA (what they are and how to use them)
SAST (static)
- finds patterns in code (good for injection patterns, insecure APIs)
- needs tuning; will have false positives

DAST (dynamic)
- tests running app (good for auth/session misconfigs, some injection)
- struggles with deep auth flows unless configured

SCA (dependency)
- finds vulnerable packages and licenses

What to learn as a beginner
- how to read and triage findings
- how to write “fix PRs” rather than just reports

Good starter tools to know (not mandatory)
- Semgrep: [https://semgrep.dev/](https://semgrep.dev/)
- OWASP Dependency-Check: [https://owasp.org/www-project-dependency-check/](https://owasp.org/www-project-dependency-check/)
- OWASP ZAP (DAST): [https://www.zaproxy.org/](https://www.zaproxy.org/)


AD9.6 Secrets management basics
- Never commit secrets; treat logs as sensitive.
- Use secret scanners and rotate credentials.

References
- OWASP Secrets Management Cheat Sheet: [https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)


AD9.7 Infrastructure-as-Code (IaC) security (only the minimum)
- Misconfigurations can become AppSec incidents (public buckets, permissive security groups).
- Learn to review IaC like code.

References
- CIS Benchmarks (general hardening): [https://www.cisecurity.org/cis-benchmarks/](https://www.cisecurity.org/cis-benchmarks/)


END OF APPSEC STUDY MATERIAL

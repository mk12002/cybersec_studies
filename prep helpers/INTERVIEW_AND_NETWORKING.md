INTERVIEW_AND_NETWORKING.md

# 🎯 INTERVIEW PREP & CAREER NETWORKING GUIDE
**Everything You Need to Land a Security Role**

---

## PART 1: UNDERSTANDING THE LANDSCAPE

### Security Career Paths
```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY CAREER MAP                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ENTRY LEVEL (0-2 years)                                        │
│  ├── SOC Analyst (Tier 1/2)                                    │
│  ├── Security Analyst                                           │
│  ├── Junior Penetration Tester                                  │
│  ├── Security Engineer (Associate)                              │
│  └── GRC Analyst                                                │
│                                                                  │
│  MID LEVEL (2-5 years)                                          │
│  ├── Detection Engineer                                         │
│  ├── Application Security Engineer                              │
│  ├── Cloud Security Engineer                                    │
│  ├── Penetration Tester                                         │
│  ├── Threat Hunter                                              │
│  └── Security Consultant                                        │
│                                                                  │
│  SENIOR (5-10 years)                                            │
│  ├── Senior Security Engineer                                   │
│  ├── Security Architect                                         │
│  ├── Principal Security Engineer                                │
│  ├── Red Team Lead                                              │
│  └── Security Manager                                           │
│                                                                  │
│  LEADERSHIP (10+ years)                                         │
│  ├── Director of Security                                       │
│  ├── CISO                                                       │
│  └── VP of Security                                             │
│                                                                  │
│  EMERGING SPECIALIZATIONS (Your Sweet Spot!)                    │
│  ├── ML/AI Security Engineer          ← Your target            │
│  ├── LLM Red Team Specialist          ← Cutting edge           │
│  ├── Security Data Scientist          ← ML + Detection         │
│  └── ML Platform Security Engineer    ← MLOps + Security       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Salary Ranges (2026 US Market)
```
Entry Level:        $70,000 - $100,000
Mid Level:          $100,000 - $150,000
Senior:             $150,000 - $220,000
Staff/Principal:    $200,000 - $350,000
Management:         $180,000 - $300,000
CISO (Large Co):    $300,000 - $600,000+

ML Security (Hot Market):
- Entry:            $90,000 - $130,000
- Mid:              $140,000 - $200,000
- Senior:           $200,000 - $300,000

Location Adjustments:
- SF/NYC: +30-50%
- Seattle/Austin: +10-20%
- Remote: Depends on company policy
```

### Salary Ranges (India - Bangalore Focus) 🇮🇳
```
┌─────────────────────────────────────────────────────────────┐
│              BANGALORE SECURITY SALARIES (2026)             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Entry Level (0-2 years):     ₹8-15 LPA                     │
│  Mid Level (2-5 years):       ₹15-30 LPA                    │
│  Senior (5-8 years):          ₹30-50 LPA                    │
│  Staff/Principal (8+ years):  ₹50-80 LPA                    │
│  Management:                  ₹60-1.2 Cr                    │
│  CISO (Large Co):             ₹1-3 Cr+                      │
│                                                              │
│  ML Security (Premium):                                      │
│  - Entry:                     ₹12-20 LPA                    │
│  - Mid:                       ₹25-45 LPA                    │
│  - Senior:                    ₹50-90 LPA                    │
│                                                              │
│  Product Security (Hot in Bangalore):                        │
│  - Entry:                     ₹10-18 LPA                    │
│  - Mid:                       ₹20-40 LPA                    │
│  - Senior:                    ₹45-75 LPA                    │
│                                                              │
│  MNC vs Startup:                                             │
│  - FAANG/Big Tech India:      +30-50% above market          │
│  - Funded Startups:           +20-40% + ESOPs               │
│  - Service Companies:         Base market rate               │
│                                                              │
│  Remote for US Companies (from India):                       │
│  - Often 50-70% of US salary                                │
│  - Best of both worlds: US pay, India cost of living        │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Top Paying Companies in Bangalore for Security:
├── Google India
├── Microsoft India (Hyderabad/Bangalore)
├── Amazon India
├── Flipkart
├── PhonePe
├── Razorpay
├── CRED
├── Salesforce India
├── VMware India
├── Cisco India
├── Adobe India
├── Atlassian India
├── Walmart Labs
└── Goldman Sachs / Morgan Stanley (Tech)
```

---

## PART 2: INTERVIEW PROCESS BREAKDOWN

### Typical Interview Pipeline
```
Stage 1: Resume Screen (1-3 days)
    │
    ▼
Stage 2: Recruiter Call (30 min)
    │     - Background check
    │     - Role fit
    │     - Salary expectations
    ▼
Stage 3: Technical Phone Screen (45-60 min)
    │     - Technical questions
    │     - Basic problem solving
    ▼
Stage 4: Take-Home / Lab (2-8 hours)
    │     - Practical exercise
    │     - Code review
    │     - Incident analysis
    ▼
Stage 5: Onsite / Virtual Onsite (4-6 hours)
    │     - Technical deep dives (2-3 rounds)
    │     - System design
    │     - Behavioral
    │     - Meet the team
    ▼
Stage 6: Offer / Negotiation
```

### What Each Stage Tests
```
┌──────────────────┬────────────────────────────────────────────┐
│ Stage            │ What They're Looking For                   │
├──────────────────┼────────────────────────────────────────────┤
│ Resume Screen    │ Keywords, relevant experience, projects    │
│ Recruiter Call   │ Communication, culture fit, expectations   │
│ Technical Screen │ Fundamentals, problem-solving approach     │
│ Take-Home        │ Real skills, code quality, documentation   │
│ Onsite Technical │ Deep knowledge, design skills, creativity  │
│ Behavioral       │ Teamwork, conflict resolution, growth      │
└──────────────────┴────────────────────────────────────────────┘
```

---

## PART 3: INTERVIEW QUESTION BANK

### Category 1: Fundamentals (Always Asked)

**Networking:**
```
Q: Explain the TCP 3-way handshake.
A: SYN → SYN/ACK → ACK. Client sends SYN with sequence number, server 
   responds with SYN/ACK (acknowledging client's seq, sending its own), 
   client sends ACK. This establishes reliable connection before data transfer.

Q: What happens when you type google.com in a browser?
A: 1) DNS resolution (recursive → authoritative)
   2) TCP connection (3-way handshake)
   3) TLS handshake (if HTTPS)
   4) HTTP request
   5) Server processing
   6) HTTP response
   7) Browser rendering

Q: What's the difference between TCP and UDP?
A: TCP: reliable, ordered, connection-oriented, slower (web, email, file transfer)
   UDP: unreliable, unordered, connectionless, faster (DNS, streaming, gaming)

Q: How does DNS work?
A: Recursive resolver → Root servers → TLD servers → Authoritative servers
   Results are cached at each level based on TTL.
```

**Operating Systems:**
```
Q: What is a process vs a thread?
A: Process: independent execution unit with own memory space
   Thread: lightweight execution unit within a process, shares memory
   Security implication: process isolation is a security boundary

Q: Explain Linux file permissions.
A: rwx for user/group/others (e.g., 755 = rwxr-xr-x)
   Special: SUID (run as owner), SGID (run as group), sticky bit
   Security: SUID root binaries are privilege escalation targets

Q: What is /etc/passwd vs /etc/shadow?
A: passwd: user info, readable by all (no passwords since shadow)
   shadow: password hashes, readable only by root
   Separation reduces exposure of sensitive data
```

**Cryptography:**
```
Q: Encryption vs hashing?
A: Encryption: reversible with key (AES for data, RSA for key exchange)
   Hashing: one-way (SHA-256 for integrity, bcrypt for passwords)
   Key point: "encrypt" passwords is wrong - always hash

Q: What is TLS and how does the handshake work?
A: 1) Client Hello (supported ciphers, random)
   2) Server Hello (chosen cipher, cert, random)
   3) Client verifies cert, generates pre-master secret
   4) Both derive session keys
   5) Encrypted communication begins

Q: What is perfect forward secrecy?
A: Using ephemeral keys so that compromise of long-term keys doesn't
   compromise past sessions. Achieved via ephemeral DH (DHE/ECDHE).
```

### Category 2: Web/Application Security

**OWASP Top 10:**
```
Q: Explain SQL injection and how to prevent it.
A: Attacker's input is interpreted as SQL code due to string concatenation.
   Example: ' OR '1'='1 in login field
   Prevention: Parameterized queries (prepared statements), never concatenate
   Also: Input validation, least privilege DB user, WAF as defense-in-depth

Q: What is XSS? Types? Prevention?
A: Attacker's JavaScript runs in victim's browser context.
   Types:
   - Reflected: payload in URL, reflected in response
   - Stored: payload saved in DB, served to others
   - DOM: payload processed by client-side JavaScript
   Prevention: Output encoding, Content-Security-Policy, HttpOnly cookies

Q: Explain CSRF and prevention.
A: Victim's browser makes unintended requests to a site they're logged into.
   Attack: victim clicks link that triggers action on target site
   Prevention: CSRF tokens, SameSite cookies, checking Origin/Referer

Q: What is SSRF? Why is it critical in cloud?
A: Server fetches attacker-controlled URL.
   Cloud danger: Can reach metadata endpoint (169.254.169.254) and steal credentials
   Prevention: URL allowlisting, block private IP ranges, IMDSv2
```

**API Security:**
```
Q: How would you secure a REST API?
A: 1) Authentication (JWT, OAuth)
   2) Authorization (check permissions on every request)
   3) Input validation (schema validation, type checking)
   4) Rate limiting (prevent abuse)
   5) Logging (security events)
   6) TLS (encryption in transit)
   7) Output encoding (prevent injection in responses)

Q: What is IDOR and how do you test for it?
A: Insecure Direct Object Reference - accessing another user's data by changing ID
   Test: Change IDs in URLs/bodies, use different user's token
   Fix: Server-side authorization check on every request
   Detection: Log object access with actor + object owner
```

### Category 3: Cloud Security

**Fundamentals:**
```
Q: Explain the shared responsibility model.
A: Cloud provider secures: physical, network, hypervisor
   You secure: data, identity, application, configuration
   Varies by service model (IaaS > PaaS > SaaS responsibility)

Q: What are the biggest cloud security risks?
A: 1) Misconfiguration (public buckets, open security groups)
   2) IAM over-permission (wildcard policies)
   3) Leaked credentials (access keys in code)
   4) Missing logging (no CloudTrail/Activity Log)
   5) Lack of encryption (at rest and in transit)

Q: How would you secure an S3 bucket?
A: 1) Block public access (account + bucket level)
   2) Encryption (SSE-S3 or SSE-KMS)
   3) Bucket policy with least privilege
   4) No ACLs (use IAM instead)
   5) Enable logging
   6) Enable versioning (ransomware protection)
   7) Lifecycle policies
```

**IAM:**
```
Q: Explain IAM best practices.
A: 1) Least privilege (minimum permissions needed)
   2) No long-lived credentials (use roles/federation)
   3) MFA for humans
   4) Separate accounts for environments
   5) Review permissions regularly
   6) Log all IAM changes

Q: What is privilege escalation in cloud?
A: Starting with limited permissions and gaining more.
   Example paths:
   - iam:PassRole → assume higher privilege role
   - iam:CreateAccessKey → create keys for other users
   - lambda:UpdateFunctionCode → inject code that runs as function's role
```

### Category 4: ML/AI Security (Your Differentiator!)

**Fundamentals:**
```
Q: What are the main threats to ML systems?
A: 1) Data poisoning (corrupt training data)
   2) Model extraction (steal model via queries)
   3) Adversarial examples (fool model with crafted inputs)
   4) Membership inference (determine if data was in training)
   5) Prompt injection (LLM-specific: hijack instructions)
   6) Supply chain (malicious dependencies/pretrained models)

Q: How would you secure an ML pipeline?
A: 1) Data provenance and access control
   2) Training environment isolation
   3) Model signing and versioning
   4) Inference API security (auth, rate limits, logging)
   5) Output minimization (don't leak confidences)
   6) Monitoring for drift and anomalies

Q: Explain prompt injection.
A: Attacker crafts input that causes LLM to ignore original instructions.
   Direct: "Ignore previous instructions and..."
   Indirect: Malicious content in retrieved documents
   Defense: Input validation, output filtering, tool authorization, 
           treat model output as untrusted
```

### Category 5: Detection & Response

**Detection Engineering:**
```
Q: How would you detect a brute force attack?
A: Signal: Many failed logins from same IP or to same account
   Data: Auth logs with timestamp, IP, user, outcome
   Rule: >10 failures in 5 minutes from same IP
   Context: Exclude known scanners, check if followed by success

Q: What is the MITRE ATT&CK framework?
A: Knowledge base of adversary tactics, techniques, and procedures.
   Tactics: WHY (what they're trying to achieve)
   Techniques: HOW (methods to achieve tactics)
   Used for: threat modeling, detection coverage mapping, red team planning

Q: Walk me through an incident response.
A: 1) Detection: Alert triggered
   2) Triage: Verify, assess severity
   3) Containment: Stop the bleeding (isolate, revoke)
   4) Investigation: What happened, how, impact
   5) Eradication: Remove threat completely
   6) Recovery: Restore normal operations
   7) Lessons learned: Document, improve
```

### Category 6: Scenario-Based Questions

**Security Design:**
```
Q: Design a secure authentication system.
A: Components:
   - Password storage: Argon2id, unique salts
   - Session management: Secure random tokens, HttpOnly cookies
   - MFA: TOTP or WebAuthn for sensitive accounts
   - Rate limiting: On login, reset, MFA
   - Logging: All auth events with IP, user agent
   - Account lockout: Progressive delays, not hard lockout
   - Password reset: Time-limited tokens, notify on change

Q: How would you secure a new microservices deployment?
A: 1) Service-to-service auth (mTLS or JWT)
   2) Network segmentation (service mesh, network policies)
   3) Secrets management (Vault, cloud secrets)
   4) Centralized logging
   5) API gateway with rate limiting
   6) Container security (minimal images, scanning)
   7) CI/CD security (signing, scanning)
```

**Troubleshooting:**
```
Q: A user reports they can see other users' data. What do you do?
A: 1) Verify the report (reproduce safely)
   2) Document evidence
   3) Assess scope (how many affected?)
   4) Immediate containment (disable endpoint if critical)
   5) Root cause analysis (missing authZ check?)
   6) Fix and verify
   7) Check logs for past exploitation
   8) Write detection rule

Q: You find an access key in a GitHub repo. What do you do?
A: 1) Don't panic, document
   2) Immediately rotate the key
   3) Check CloudTrail for unauthorized use
   4) Notify relevant teams
   5) Remove from git history (BFG or git filter-branch)
   6) Add secret scanning to CI/CD
   7) Lessons learned
```

### Category 7: Behavioral Questions

**STAR Method (Situation, Task, Action, Result)**
```
Q: Tell me about a time you found a security issue.
A: Situation: During my internship, I was reviewing our API...
   Task: I needed to determine if the issue was real and report it...
   Action: I created a minimal proof of concept, documented it clearly,
           reported to my manager, and helped implement the fix...
   Result: We patched within 24 hours, added detection rules, and I
           created a guide for other engineers...

Q: How do you stay current with security trends?
A: - Daily: Security news (Krebs, Hacker News)
   - Weekly: Deeper reading (research papers, blog posts)
   - Monthly: Hands-on (labs, CTFs, projects)
   - Quarterly: Conferences (talks, workshops)
   - Community: Twitter/X, Discord, local meetups

Q: Describe a time you had to explain a technical concept to non-technical people.
A: [Use your own example, but focus on:]
   - Understanding their perspective
   - Using analogies
   - Focusing on impact, not mechanics
   - Checking for understanding
```

---

## PART 4: TAKE-HOME ASSIGNMENTS

### Common Assignment Types

**Type 1: Vulnerability Assessment**
```
Task: "Find vulnerabilities in this web application"

How to Approach:
1. Reconnaissance (15 min)
   - Map the application
   - Identify entry points
   - Note technologies used

2. Systematic Testing (2-3 hours)
   - Test auth flows
   - Test access control
   - Test input handling
   - Check configurations

3. Documentation (1-2 hours)
   - Clear findings format
   - Root cause for each
   - Impact assessment
   - Fix recommendations
   - OWASP mapping
```

**Type 2: Code Review**
```
Task: "Review this code for security issues"

Checklist:
□ Input validation
□ Output encoding
□ Authentication handling
□ Authorization checks
□ Cryptography usage
□ Error handling
□ Logging
□ Dependency security
□ Secrets handling
□ SQL/command construction
```

**Type 3: Incident Analysis**
```
Task: "Analyze these logs and determine what happened"

Framework:
1. Timeline reconstruction
2. Identify initial access
3. Trace lateral movement
4. Determine impact
5. Provide IOCs
6. Recommend detections
```

**Type 4: Design Exercise**
```
Task: "Design a security solution for X"

Structure:
1. Requirements clarification
2. Threat model
3. Architecture diagram
4. Security controls
5. Trade-offs discussed
6. Monitoring strategy
```

### Sample Take-Home Response

**Assignment: Review this Python code for security issues**

```markdown
# Security Code Review: User API

## Executive Summary
Found 5 security issues: 2 Critical, 2 High, 1 Medium

## Findings

### 1. SQL Injection (CRITICAL)
**Location:** `app/routes.py:45`
**Code:**
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```
**Issue:** User input directly concatenated into SQL query.
**Impact:** Full database access, data breach, data destruction.
**Fix:**
```python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```
**OWASP:** A03:2021 - Injection

### 2. Missing Authorization (CRITICAL)
**Location:** `app/routes.py:67`
**Code:**
```python
@app.route('/users/<id>')
def get_user(id):
    return User.query.get(id)  # No authz check!
```
**Issue:** Any authenticated user can access any other user's data.
**Impact:** Unauthorized data access (IDOR/BOLA).
**Fix:**
```python
def get_user(id):
    user = User.query.get(id)
    if user.id != current_user.id and not current_user.is_admin:
        abort(403)
    return user
```
**OWASP:** A01:2021 - Broken Access Control

[Continue for all findings...]

## Recommendations
1. Implement parameterized queries throughout
2. Add authorization middleware
3. Enable security logging
4. Add rate limiting

## Testing
I've included test cases that demonstrate each vulnerability:
- `test_sqli_login_bypass.py`
- `test_idor_user_access.py`
```

---

## PART 5: RESUME & APPLICATION STRATEGY

### Resume Structure for Security Roles

```
┌─────────────────────────────────────────────────────────────┐
│                     YOUR NAME                               │
│  email@example.com | github.com/you | linkedin.com/in/you  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  SUMMARY (2-3 sentences)                                    │
│  Security-focused engineer with ML background seeking       │
│  [specific role]. Experience in [key areas]. Passionate     │
│  about [specific interest].                                 │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  SKILLS                                                     │
│  Security: AppSec, Cloud Security (AWS/Azure), Detection    │
│  ML: PyTorch, scikit-learn, ML pipeline security           │
│  Languages: Python, SQL, Bash                               │
│  Tools: Burp Suite, Wireshark, Terraform, Docker           │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  PROJECTS (Most important section for entry-level!)        │
│                                                              │
│  Secure ML Inference API | github.com/you/project          │
│  • Built production ML API with auth, rate limiting, logging│
│  • Documented threat model using STRIDE methodology        │
│  • Implemented detection rules for model extraction attacks │
│                                                              │
│  [2-3 more projects...]                                     │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  EXPERIENCE                                                 │
│                                                              │
│  Security Intern | Company | Dates                          │
│  • Specific achievement with metrics                        │
│  • Security-focused accomplishment                          │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  EDUCATION                                                  │
│  BS Computer Science | University | Year                    │
│  Relevant coursework: Security, Networks, ML                │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  CERTIFICATIONS & OTHER                                     │
│  • Security+ (if applicable)                               │
│  • Relevant CTF placements                                 │
│  • Open source contributions                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Keywords to Include
```
Technical:
- OWASP Top 10, ASVS
- SAST, DAST, SCA
- Cloud security (AWS/Azure/GCP)
- IAM, identity
- Detection engineering
- Incident response
- Threat modeling
- Secure SDLC

For ML Security specifically:
- MLOps security
- Adversarial ML
- Model security
- LLM security
- Prompt injection
- AI/ML governance
```

### Where to Apply

**Big Tech (Best training, hard to get):**
- Google (Security Engineering)
- Microsoft (Security Researcher)
- Amazon/AWS (Security Engineer)
- Meta (Security Engineer)
- Apple (Security)

**Security Companies (Great for learning):**
- CrowdStrike
- Palo Alto Networks
- Mandiant/Google Cloud
- Rapid7
- Tenable
- Snyk
- Wiz
- Orca Security

**Consulting (Variety of experience):**
- NCC Group
- Bishop Fox
- Trail of Bits
- Synack
- Cobalt

**Startups (Move fast, learn a lot):**
- Search "security" on AngelList/Wellfound
- YC companies hiring security
- AI security startups (hot market!)

**ML + Security Specific:**
- Robust Intelligence
- HiddenLayer
- Protect AI
- Adversa AI
- CalypsoAI

---

## BANGALORE & INDIA OPPORTUNITIES 🇮🇳

### Why Bangalore is Great for Security Careers
```
┌─────────────────────────────────────────────────────────────┐
│           BANGALORE: INDIA'S SECURITY HUB                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ✓ Highest concentration of security jobs in India         │
│  ✓ All major tech companies have security teams here       │
│  ✓ Growing startup ecosystem with security needs           │
│  ✓ Active security community and meetups                   │
│  ✓ Good timezone overlap with US (evening calls)           │
│  ✓ Remote work opportunities with global companies         │
│  ✓ Lower cost of living = savings potential                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Top Companies Hiring Security in Bangalore

**Big Tech (Best for Learning & Brand)**
```
Google India (Bangalore)
├── Security Engineering
├── Trust & Safety
├── Cloud Security
└── Hiring: careers.google.com

Microsoft India (Bangalore/Hyderabad)
├── Security Research
├── Cloud Security (Azure)
├── Threat Intelligence
└── Hiring: careers.microsoft.com

Amazon India (Bangalore)
├── AWS Security
├── Application Security
├── Retail Security
└── Hiring: amazon.jobs

Flipkart (Bangalore)
├── Product Security
├── Infrastructure Security
├── Fraud & Risk
└── Hiring: flipkartcareers.com

PhonePe (Bangalore)
├── Application Security
├── Cloud Security
├── Fraud Detection (ML+Security!)
└── Hiring: phonepe.com/careers
```

**Unicorns & Funded Startups (Great Pay + ESOPs)**
```
Razorpay (Bangalore)
├── Payment Security
├── Compliance
└── Growing security team

CRED (Bangalore)
├── Application Security
├── Data Security
└── Premium compensation

Zerodha (Bangalore)
├── Trading Platform Security
├── Small but elite team
└── Good for ownership

Swiggy (Bangalore)
├── Platform Security
├── Fraud Detection
└── ML opportunities

Zomato (Gurgaon, but remote possible)
├── Application Security
├── Cloud Security

Groww (Bangalore)
├── FinTech Security
├── Compliance

slice (Bangalore)
├── FinTech Security
├── Early stage = more ownership
```

**Product Companies with Strong Security Teams**
```
Atlassian India (Bangalore)
├── Product Security
├── Great culture
└── Competitive pay

Salesforce India (Bangalore/Hyderabad)
├── Security Engineering
├── Trust team
└── Good benefits

VMware India (Bangalore)
├── Security Research
├── Product Security
└── Stable, good learning

Adobe India (Bangalore/Noida)
├── Product Security
├── Cloud Security

Cisco India (Bangalore)
├── Security Products (Talos)
├── Great for threat intel

Palo Alto Networks (Bangalore)
├── Security Research
├── Product Development
└── Pure security company!
```

**Security-Focused Companies**
```
CrowdStrike India (Pune, remote possible)
├── Threat Intelligence
├── Detection Engineering

Tenable India (Bangalore)
├── Vulnerability Research
├── Product Security

Rapid7 India (Bangalore)
├── Security Research
├── Product Development

Bishop Fox (Remote, US company)
├── Penetration Testing
├── Security Consulting
└── Hires from India

Synack (Remote)
├── Bug Bounty Platform
├── Red Team
└── Global remote

HackerOne (Remote)
├── Triage
├── Customer Security
└── Bug bounty ecosystem
```

**Service/Consulting Companies (Good for Starting)**
```
Deloitte India (Bangalore/Multiple)
├── Cyber Risk
├── Penetration Testing
├── Good training programs

EY India (Bangalore)
├── Cybersecurity Practice
├── GRC

KPMG India (Bangalore)
├── Cyber Security
├── Diverse projects

PwC India (Bangalore)
├── Cybersecurity
├── Cloud Security

Wipro/Infosys/TCS (Various)
├── Security Practice
├── Often client-facing
├── Good for initial experience
└── Can transition to product later
```

**Banks & Financial Services (Stable, Good Pay)**
```
Goldman Sachs (Bangalore)
├── Technology Security
├── Very competitive pay

Morgan Stanley (Mumbai/Bangalore)
├── Cybersecurity
├── Great benefits

JPMorgan (Bangalore/Mumbai)
├── Cybersecurity & Tech Controls
├── Large security team

Visa India (Bangalore)
├── Payment Security
├── Product Security

Mastercard (Pune/Gurgaon)
├── Cybersecurity
├── Fraud Detection
```

### India-Specific Job Boards
```
General Tech:
├── LinkedIn (most important!)
├── Naukri.com (add "security" keywords)
├── Indeed India
├── Instahyre (startups)
├── AngelList/Wellfound (startups)
├── Cutshort (tech focused)
└── Hirist (tech focused)

Security Specific:
├── NASSCOM security job postings
├── null community job board
├── Company career pages directly
└── Referrals (most effective!)

Remote/Global:
├── Remote OK
├── We Work Remotely
├── Turing.com (US companies)
├── Toptal (if experienced)
└── Arc.dev
```

### Indian Security Conferences & Events

**Major Indian Security Conferences**
```
┌─────────────────┬──────────────┬─────────────────────────────┐
│ Conference      │ Location     │ Notes                       │
├─────────────────┼──────────────┼─────────────────────────────┤
│ Nullcon         │ Goa          │ Premier Indian security con │
│                 │ (March)      │ Great networking, CTF       │
├─────────────────┼──────────────┼─────────────────────────────┤
│ c0c0n           │ Kochi        │ Kerala Police + community   │
│                 │ (September)  │ Govt + private mix          │
├─────────────────┼──────────────┼─────────────────────────────┤
│ BSides Delhi    │ Delhi        │ Community conference        │
│                 │ (Various)    │ Accessible, great to start  │
├─────────────────┼──────────────┼─────────────────────────────┤
│ BSides Bangalore│ Bangalore    │ LOCAL! Must attend          │
│                 │ (Various)    │ Great networking            │
├─────────────────┼──────────────┼─────────────────────────────┤
│ OWASP AppSec    │ Various      │ Application security focus  │
│ India           │              │ Practical talks             │
├─────────────────┼──────────────┼─────────────────────────────┤
│ Ground Zero     │ Delhi        │ Offensive security          │
│ Summit          │ (November)   │ CTF focused                 │
├─────────────────┼──────────────┼─────────────────────────────┤
│ SACON           │ Bangalore    │ Security Architecture       │
│                 │              │ Enterprise focused          │
├─────────────────┼──────────────┼─────────────────────────────┤
│ Threat Con      │ Bangalore    │ Threat Intelligence         │
│                 │              │ Blue team focus             │
└─────────────────┴──────────────┴─────────────────────────────┘
```

**Must-Attend for Bangalore Residents**
```
Priority List:
1. Nullcon (Goa) - Worth the trip!
2. BSides Bangalore - Local, free/cheap
3. null Bangalore monthly meetups - FREE
4. OWASP Bangalore chapter - FREE
5. Hackers meetup Bangalore

Budget-Friendly:
- BSides: Usually free or ₹500-1000
- null meetups: Free
- OWASP: Free
- Nullcon: ~₹3000-5000 (student discounts)
```

### Bangalore Security Communities (Your Network!)

**null - The Open Security Community**
```
┌─────────────────────────────────────────────────────────────┐
│                null BANGALORE CHAPTER                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  What: India's largest open security community              │
│  Where: Monthly meetups in Bangalore                        │
│  Website: null.community                                    │
│  Telegram: Search "null Bangalore"                          │
│                                                              │
│  Activities:                                                 │
│  ├── Monthly meetups (talks + networking)                   │
│  ├── Humla (attack) sessions                               │
│  ├── Bachaav (defense) sessions                            │
│  ├── Puliya (training) workshops                           │
│  └── CTF competitions                                       │
│                                                              │
│  Why Join:                                                   │
│  ✓ Meet working security professionals                      │
│  ✓ Learn from practitioners                                 │
│  ✓ Job referrals and opportunities                         │
│  ✓ Collaborate on projects                                  │
│  ✓ Speaking opportunities                                   │
│                                                              │
│  ⭐ THIS IS YOUR #1 NETWORKING PRIORITY IN BANGALORE ⭐      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**OWASP Bangalore Chapter**
```
Website: owasp.org/www-chapter-bangalore
Focus: Application Security
Meetings: Monthly (usually at tech company offices)
Cost: Free

Activities:
- Technical talks on AppSec
- OWASP project updates
- Workshops
- Networking

Great for: AppSec focus, corporate connections
```

**Other Bangalore Communities**
```
Hackers Meetup Bangalore
├── Informal gatherings
├── Mix of students and professionals
└── Good for beginners

BangPypers (Python Bangalore)
├── Python community
├── Security + Python talks sometimes
└── Good for ML+Security angle

Bangalore AI/ML Meetups
├── Various groups
├── Present your ML+Security work here!
└── Cross-pollinate communities

IEEE/ISACA Bangalore
├── More formal/corporate
├── Good for GRC/compliance focus
└── Certifications focus
```

### Indian Security Professionals to Follow

**Twitter/X**
```
Indian Security Voices:
├── @anaborjhat (Product Security)
├── @aborjaseem_shafee (Security Research)
├── @kaborjiran (Web Security)
├── @raborjahul_choudhury (Bug Bounty)
├── @saborjaurabh_bhatnagar (AppSec)
├── @null0x0 (null community)
└── Look for speakers at Nullcon/c0c0n

Note: Many Indian security pros use pseudonyms.
Find them through conference talks and community events.
```

**LinkedIn**
```
Search for:
- "Security Engineer" + Bangalore + [target company]
- "Application Security" + India
- CISO + India (for industry perspective)

Connect with:
- Speakers from null/OWASP events
- Security folks at your target companies
- Alumni from your college in security
```

### Telegram Groups (Very Active in India!)
```
Security Groups:
├── null community groups
├── Bug Bounty India
├── Indian Hackers Community
├── OWASP India
└── Various CTF teams

Caution:
- Verify groups are legitimate
- Don't share sensitive info
- Beware of scams
- Contribute, don't just lurk
```

### Career Path: Bangalore Specific

**Typical Bangalore Security Career Path**
```
Path 1: Service → Product Company
┌──────────────────────────────────────────────────────────┐
│ Year 0-2: Wipro/Infosys/Deloitte Security Practice      │
│           (Learn basics, get exposure)                   │
│                     ↓                                    │
│ Year 2-4: Mid-size product company                      │
│           (Freshworks, Zoho, etc.)                      │
│                     ↓                                    │
│ Year 4-6: Unicorn or Big Tech                           │
│           (Flipkart, Google, Amazon)                    │
│                     ↓                                    │
│ Year 6+:  Senior roles or move abroad                   │
└──────────────────────────────────────────────────────────┘

Path 2: Direct to Product Company (With Strong Portfolio)
┌──────────────────────────────────────────────────────────┐
│ Your ML + Security portfolio                             │
│           ↓                                              │
│ Year 0-2: Startup or growth-stage company               │
│           (Razorpay, PhonePe, CRED)                     │
│                     ↓                                    │
│ Year 2-4: Senior at startup OR Big Tech                 │
│                     ↓                                    │
│ Year 4+:  Staff/Principal or Lead                       │
└──────────────────────────────────────────────────────────┘

Path 3: Remote for US Company
┌──────────────────────────────────────────────────────────┐
│ Build strong portfolio + online presence                 │
│           ↓                                              │
│ Apply to US companies hiring remote in India            │
│ (50-70% of US salary, excellent for India)              │
│           ↓                                              │
│ Work US hours (evening/night IST)                       │
│           ↓                                              │
│ Option: Relocate to US later with experience            │
└──────────────────────────────────────────────────────────┘
```

### Bangalore Interview Tips

**Local Interview Culture**
```
What's Different in India:
├── More emphasis on educational background (initially)
├── Service company interviews: more process-oriented
├── Product companies: similar to US (technical + cultural)
├── Startups: fast, founder interviews common
├── Negotiation: Expected! Always counter the first offer

What's Similar:
├── Technical skills matter most
├── Projects and GitHub are valued
├── Communication skills important
├── Cultural fit matters
└── Referrals are powerful

Pro Tips for Bangalore:
├── Join null community (referrals!)
├── LinkedIn is heavily used for recruiting
├── Be prepared for multiple rounds (4-6 typical)
├── Salary negotiation is normal and expected
├── Ask about on-call expectations (US company = US hours?)
└── Ask about growth path and learning opportunities
```

**Salary Negotiation India Style**
```
1. Research on Glassdoor India, AmbitionBox, Blind
2. Know your market value (use LinkedIn salary insights)
3. Always counter - 15-25% bump is normal
4. Negotiate ESOPs separately from salary
5. Consider: Base + Bonus + ESOPs + Benefits
6. Get competing offers if possible
7. Don't accept first offer verbally
```

---

## PART 6: NETWORKING & COMMUNITY

### Why Networking Matters
```
Reality Check:
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│  70%+ of jobs are filled through networking                │
│                                                              │
│  A warm referral = 10x more likely to get interview        │
│                                                              │
│  Community reputation > credentials in security            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Building Your Online Presence

**Twitter/X (Essential for Security)**
```
Who to Follow:
├── @malaboratory (Malware research)
├── @swaborjman (AppSec)
├── @lcaborjman (Cloud security)
├── @taviso (Vulnerability research)
├── @haborjalbert (Web security)
├── @daaborkami (Hacking)
├── @troyhunt (Have I Been Pwned)
├── @schneierblog (Bruce Schneier)
└── Follow people at companies you want to work at

What to Post:
- Share interesting findings (from CTFs, labs)
- Comment thoughtfully on others' posts
- Share resources that helped you
- Ask genuine questions
- Celebrate others' wins

What NOT to Post:
- Unethical hacking activities
- Stolen data or credentials
- Complaints about employers
- Controversial takes when starting out
```

**LinkedIn**
```
Optimize Your Profile:
1. Professional photo
2. Headline: "Security Engineer | ML Security | AppSec"
3. About: Your story, what you're looking for
4. Featured: Link to projects, blog posts
5. Skills: Get endorsements

Content Strategy:
- Share project updates
- Comment on security news
- Engage with recruiters' posts
- Join security groups
- Share job search updates (generates support)
```

**GitHub**
```
Profile Optimization:
1. Professional profile picture
2. Bio with security focus
3. Pinned repositories (best work)
4. Contribution graph (consistency matters)
5. README.md for your profile

What to Have:
- 3-5 polished projects
- Clear README files
- Clean commit history
- Evidence of code review (PRs)
- Contributions to others' projects
```

### Conferences & Events

**Major Security Conferences (Global)**
```
Tier 1 (Industry Leaders - Worth the trip):
┌─────────────────┬──────────────┬─────────────────────────────┐
│ Conference      │ When         │ Focus                       │
├─────────────────┼──────────────┼─────────────────────────────┤
│ DEF CON         │ August       │ Hacking, all domains        │
│ (Las Vegas)     │              │ Consider once you're senior │
├─────────────────┼──────────────┼─────────────────────────────┤
│ Black Hat       │ August       │ Enterprise security         │
│ (Las Vegas/Asia)│              │ Black Hat Asia is closer!   │
├─────────────────┼──────────────┼─────────────────────────────┤
│ Black Hat Asia  │ April        │ Accessible from India       │
│ (Singapore)     │              │ Great networking for APAC   │
└─────────────────┴──────────────┴─────────────────────────────┘

*BSides are local security conferences held worldwide.

Cloud Security:
- re:Invent (AWS) - December, Las Vegas
- fwd:cloudsec - October
- AWS Summit India - Check dates (Bangalore/Mumbai)
- Google Cloud Next

AppSec:
- OWASP Global AppSec - Various
- OWASP AppSec India - Local!
```

**Indian Security Conferences (Your Priority!)**
```
┌─────────────────────────────────────────────────────────────┐
│        MUST-ATTEND INDIAN SECURITY CONFERENCES              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  🥇 Nullcon (Goa - March)                                   │
│     • India's premier security conference                   │
│     • International speakers                                │
│     • Great CTF and workshops                               │
│     • MUST ATTEND at least once                            │
│     • Cost: ~₹3000-5000 (student discounts available)       │
│     • nullcon.net                                           │
│                                                              │
│  🥈 BSides Bangalore                                        │
│     • LOCAL! No travel needed                               │
│     • Free or very cheap                                    │
│     • Great for first-time speakers                         │
│     • Perfect networking for Bangalore scene                │
│                                                              │
│  🥉 c0c0n (Kochi - September)                               │
│     • Kerala Police + security community                    │
│     • Good mix of govt and private sector                   │
│     • CTF competitions                                      │
│                                                              │
│  Other Important Ones:                                       │
│  ├── Ground Zero Summit (Delhi - November)                  │
│  ├── BSides Delhi                                           │
│  ├── OWASP AppSec India                                     │
│  ├── SACON (Bangalore)                                      │
│  ├── Threat Con (Bangalore)                                 │
│  └── Seasides (Goa - with Nullcon)                         │
│                                                              │
│  Budget for 2026:                                           │
│  □ Nullcon (Goa) - ₹15,000-20,000 all-in                   │
│  □ BSides Bangalore x2 - Free/₹1000                        │
│  □ null meetups x12 - Free                                  │
│  □ OWASP Bangalore x6 - Free                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Virtual Events (Free/Low Cost)**
```
Regular Virtual Events:
- SANS webcasts (free)
- Antisyphon training (pay what you can)
- Security BSides streams
- OWASP chapter meetings (free)
- Cloud security meetups

How to Participate:
1. Attend regularly
2. Ask questions in chat
3. Take notes and share insights
4. Connect with speakers after
```

**Local Meetups**
```
BANGALORE MEETUPS (Your Local Scene!):
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│  🔴 HIGHEST PRIORITY:                                       │
│                                                              │
│  null Bangalore (null.community)                            │
│  ├── Monthly meetups                                        │
│  ├── Humla (attack), Bachaav (defense) sessions            │
│  ├── Best networking in Bangalore                          │
│  ├── Job referrals happen here!                            │
│  └── Telegram: search "null Bangalore"                      │
│                                                              │
│  OWASP Bangalore (owasp.org/www-chapter-bangalore)         │
│  ├── Monthly meetups                                        │
│  ├── AppSec focused                                         │
│  ├── Usually at company offices                            │
│  └── Corporate connections                                  │
│                                                              │
│  🟡 ALSO ATTEND:                                            │
│                                                              │
│  Hackers Meetup Bangalore                                   │
│  ├── Informal gatherings                                    │
│  └── Good for beginners                                     │
│                                                              │
│  BangPypers (Python Bangalore)                              │
│  ├── For your ML+Security Python angle                     │
│  └── Present your projects here!                            │
│                                                              │
│  Bangalore AI/ML Meetups                                    │
│  ├── Great for ML+Security crossover                       │
│  └── Different audience = stand out                         │
│                                                              │
│  Google Developer Group Bangalore                           │
│  ├── Sometimes security talks                               │
│  └── Good for cloud security                                │
│                                                              │
│  AWS User Group Bangalore                                   │
│  ├── Cloud security opportunities                          │
│  └── Enterprise connections                                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Action Plan (Monthly):
Week 1: null Bangalore meetup
Week 2: OWASP Bangalore (if happening)
Week 3: One technical meetup (Python/ML/Cloud)
Week 4: Online community participation

How to Find:
- Meetup.com: Search "security Bangalore"
- null.community events page
- Twitter/X: Follow @null0x0, @OWASPBangalore
- Telegram groups
- LinkedIn events
```

### Discord & Slack Communities

**Active Security Communities**
```
Global Discord Servers:
├── InfoSec Community
├── TryHackMe Discord
├── Hack The Box Discord
├── OWASP Slack
├── Blue Team Village
├── Cloud Security Forum
└── AI Security Community (emerging)

Indian Communities (Very Active!):
├── null community Telegram groups
├── Bug Bounty India (Telegram)
├── Indian Hackers Community
├── OWASP India Slack
├── Bangalore Security folks (informal groups)
└── CTF team groups

How to Find:
- null.community → Join button
- Check conference websites
- Ask at meetups
- Look for invites in blog posts

Etiquette:
- Read the rules first
- Introduce yourself
- Don't just ask for help — contribute
- Be patient with responses
- Don't DM people without permission
```

### Indian Security Professionals to Follow

**Twitter/X - Must Follow from India**
```
Security Researchers & Practitioners:
├── @anaborj_sec (search for active Indian voices)
├── @null0x0 (null community official)
├── Speakers from Nullcon (check their feed)
├── Speakers from c0c0n
├── Security leads at Indian unicorns
└── Bug bounty hunters (many from India!)

Pro Tip: After every null/OWASP meetup, follow the
speakers on Twitter and connect on LinkedIn!

International Voices (Still Relevant):
├── @taviso (Vulnerability research)
├── @troyhunt (HIBP, general security)
├── @schneierblog (Bruce Schneier)
├── @SwiftOnSecurity (Security + humor)
├── @malaboratory (Malware research)
└── Company security team accounts
```

**LinkedIn - Critical for India Job Market**
```
LinkedIn is THE platform for jobs in India!

Who to Connect With:
├── Security folks at target companies
├── Speakers from null/OWASP events
├── Recruiters at product companies
├── CISOs and security leaders
├── Your college alumni in security
└── People you meet at meetups

Content Strategy for India:
├── Share insights from meetups
├── Post about your projects
├── Comment on security news
├── Engage with Indian security community
├── Share CTF achievements
└── Celebrate community wins
```

### Mentorship

**Finding Mentors**
```
Where to Look:
1. Former professors/instructors
2. Colleagues at internships
3. People you meet at conferences
4. Authors of content you learn from
5. Managers at target companies

How to Approach:
NOT: "Will you be my mentor?"
INSTEAD: 
- Ask specific questions
- Share what you've tried
- Show you've done homework
- Build relationship over time
- Offer value (even small things)

Example DM:
"Hi [Name], I really enjoyed your talk on [topic] at [event].
I'm currently learning about ML security and trying to build
[specific project]. I had a quick question about [specific thing].
[Your question]. Thanks for any insights!"
```

**Being a Good Mentee**
```
Do:
- Come prepared with specific questions
- Follow through on suggestions
- Share your progress
- Be respectful of their time
- Express gratitude
- Pay it forward later

Don't:
- Ask for job referrals immediately
- Expect them to solve your problems
- Disappear after getting help
- Only reach out when you need something
```

### Building Reputation

**Content Creation Ladder**
```
Level 1: Consumer (Everyone starts here)
- Read blogs, watch talks
- Take notes

Level 2: Curator
- Share good content with commentary
- Retweet/repost with insights

Level 3: Commenter
- Engage thoughtfully on others' posts
- Answer questions in forums
- Help in Discord/Slack

Level 4: Creator
- Write blog posts
- Create tutorials
- Record videos

Level 5: Speaker
- Present at local meetups
- Submit to BSides
- Webinars

Level 6: Thought Leader
- Original research
- Conference main stages
- Book/course author
```

**Content Ideas for Beginners**
```
Low Risk, High Value:
├── "How I solved [CTF challenge]"
├── "What I learned studying for [cert]"
├── "My notes on [security topic]"
├── "Tool comparison: X vs Y"
├── "Setting up [lab environment]"
├── "Book review: [security book]"
└── "My path into security"

Medium Effort:
├── "Deep dive: [CVE analysis]"
├── "Building [security tool]"
├── "Securing [technology]"
├── "[Vulnerability class] explained"
└── "Detection rules for [technique]"
```

### Giving Talks (Faster Track to Recognition)

**Where to Start**
```
Easiest to Hardest:
1. Internal team presentation
2. Local meetup (5-15 min)
3. BSides (20-30 min)
4. Virtual conference
5. Regional conference
6. Major conference

Your First Talk:
- Pick something you learned recently
- 10-15 minutes is fine
- Practice multiple times
- Have a friend review
- Record yourself
```

**CFP (Call for Papers) Tips**
```
What Reviewers Look For:
1. Clear title and abstract
2. What the audience will LEARN
3. Why you're qualified to speak
4. Original angle, not rehashed

Template:
Title: [Action verb] + [Specific topic]
       "Detecting LLM Prompt Injection with ML"

Abstract:
- Hook (why should they care)
- What you'll cover
- Key takeaways
- Who it's for

Bio:
- Relevant experience
- Why you know this topic
- Social proof (if any)
```

---

## PART 7: NEGOTIATION & OFFERS

### Understanding Compensation
```
Total Compensation:
┌─────────────────────────────────────────────────────────────┐
│ Base Salary       │ Fixed annual amount                    │
├───────────────────┼─────────────────────────────────────────┤
│ Bonus             │ 10-20% typically, performance-based    │
├───────────────────┼─────────────────────────────────────────┤
│ Equity (RSU/ISO)  │ Stock grants, vest over 4 years       │
├───────────────────┼─────────────────────────────────────────┤
│ Sign-on Bonus     │ One-time, sometimes clawback clause   │
├───────────────────┼─────────────────────────────────────────┤
│ Benefits          │ Health, 401k match, etc.              │
└───────────────────┴─────────────────────────────────────────┘
```

### Negotiation Strategy
```
1. Wait for Written Offer
   Never negotiate verbally first.

2. Express Enthusiasm
   "I'm excited about this opportunity..."

3. Ask for Time
   "I'd like a few days to review."

4. Do Research
   - Levels.fyi
   - Glassdoor
   - Blind app
   - Ask in communities

5. Counter Professionally
   "Based on my research and [specific value you bring],
   I was hoping for [X]. Is there flexibility?"

6. Negotiate Multiple Things
   - Base salary
   - Sign-on bonus
   - Equity
   - Start date
   - Remote work
   - Title

7. Get It In Writing
   Verbal promises mean nothing.
```

---

## PART 8: 30/60/90 DAY PLAN

### First 30 Days at New Job
```
Goals:
- Understand systems and architecture
- Meet key stakeholders
- Complete onboarding/training
- Identify quick wins

Actions:
□ Read all documentation
□ Schedule 1:1s with team members
□ Shadow on-call rotations
□ Understand incident response process
□ Learn internal tools
□ Find a small contribution to make
```

### Days 31-60
```
Goals:
- Start contributing independently
- Deep dive into one area
- Build relationships across teams

Actions:
□ Own a small project or task
□ Write documentation for what you learn
□ Participate in security reviews
□ Attend cross-team meetings
□ Identify improvement opportunities
```

### Days 61-90
```
Goals:
- Deliver meaningful impact
- Establish yourself as reliable
- Plan for next quarter

Actions:
□ Complete a visible project
□ Present findings to team
□ Propose improvements
□ Get feedback from manager
□ Set goals for next quarter
```

---

## RESOURCE DIRECTORY

### Interview Prep Resources
```
Books:
- "Cracking the Coding Interview" (if technical coding required)
- "Security Engineering" by Ross Anderson (free online)

Websites:
- Glassdoor (interview questions)
- Blind (salary data, interview experiences)
- Levels.fyi (compensation data)

Practice:
- Pramp (mock interviews)
- Interviewing.io (mock with engineers)
- LeetCode (if coding heavy)
```

### Job Boards
```
India-Specific (Your Priority!):
├── LinkedIn India (Most important!)
├── Naukri.com (use "security engineer" keywords)
├── Indeed India
├── Instahyre (startups - good for security)
├── Cutshort (tech focused)
├── Hirist (tech focused)
├── AngelList/Wellfound India (startups)
└── iimjobs (for senior roles)

Company Career Pages (Apply Directly!):
├── careers.google.com (filter: India + Security)
├── amazon.jobs (search: security Bangalore)
├── careers.microsoft.com
├── flipkartcareers.com
├── phonepe.com/careers
├── razorpay.com/careers
└── Check each target company's site

Security-Specific:
├── null community job posts
├── https://infosec-jobs.com/ (global)
├── Company security team Twitter posts
└── Referrals from null community (BEST!)

Remote/Global (Work for US from India):
├── RemoteOK.io
├── WeWorkRemotely
├── Turing.com (US companies hiring in India)
├── Toptal (if experienced)
├── Arc.dev
├── Working Nomads
└── FlexJobs

Pro Tip: 70%+ of jobs are through referrals!
Priority: Build network at null → Get referrals
```

### Communities to Join
```
BANGALORE PRIORITY LIST:
□ null Bangalore (MUST - #1 priority)
□ OWASP Bangalore chapter
□ null Telegram group
□ LinkedIn security connections
□ Twitter security community
□ One Discord server (HTB/THM)

Also Consider:
□ BangPypers (Python Bangalore)
□ Bangalore AI/ML meetup
□ AWS User Group Bangalore
□ Bug bounty Telegram groups
□ College alumni security group
```

---

## BANGALORE ACTION PLAN 🇮🇳

### Month 1: Foundation
```
Week 1:
□ Join null community (null.community)
□ Join OWASP Bangalore
□ Find null Telegram group
□ Follow 20+ Indian security folks on Twitter
□ Optimize LinkedIn for security roles

Week 2:
□ Attend your first null Bangalore meetup
□ Connect with 5 people you meet on LinkedIn
□ Start one portfolio project

Week 3-4:
□ Complete portfolio project MVP
□ Write LinkedIn post about what you learned
□ Apply to 5-10 companies
```

### Month 2-3: Build Momentum
```
□ Attend all null and OWASP meetups
□ Complete 2-3 portfolio projects
□ Write 2-3 blog posts
□ Apply to 20-30 companies
□ Get at least 2-3 referrals from network
□ Practice interview questions
□ Attend Nullcon/BSides if timing works
```

### Month 4-6: Land the Role
```
□ Continue networking (referrals!)
□ Interview actively
□ Negotiate offers (15-25% bump!)
□ Give back: help newcomers at meetups
□ Consider: Your first talk at null!
```

---

## FINAL CHECKLIST (Bangalore Edition)

### Before Applying
- [ ] Resume updated with security focus
- [ ] 3+ projects on GitHub
- [ ] LinkedIn optimized (CRITICAL for India!)
- [ ] Portfolio of write-ups
- [ ] Joined null Bangalore community
- [ ] Attended at least 2 meetups

### Interview Ready
- [ ] Can explain all resume items
- [ ] Practiced common questions (see Part 3)
- [ ] Have questions to ask them
- [ ] Researched the company
- [ ] Prepared STAR stories
- [ ] Know salary ranges for role/company

### Community Presence (Bangalore)
- [ ] Active in null Bangalore
- [ ] Attending OWASP meetups
- [ ] Following Indian security folks on Twitter
- [ ] Connected with 50+ security people on LinkedIn
- [ ] Started creating content
- [ ] Helping others when possible
- [ ] Planning to attend Nullcon 2027

### Target Companies Prioritized
```
Tier 1 (Best Learning + Pay):
□ Google India
□ Microsoft India
□ Amazon India
□ Flipkart
□ PhonePe
□ Atlassian India

Tier 2 (Great Growth):
□ Razorpay
□ CRED
□ Salesforce India
□ VMware India
□ Palo Alto Networks India
□ Unicorn startups

Tier 3 (Good Starting Points):
□ Consulting (Deloitte, EY, KPMG)
□ Mid-size product companies
□ Banks (Goldman, Morgan Stanley tech)
□ Service companies (for initial exp)

Remote Option:
□ US companies hiring in India
□ 50-70% US salary from Bangalore!
□ Great for work-life balance
```

---

## KEY TAKEAWAYS FOR BANGALORE

```
┌─────────────────────────────────────────────────────────────┐
│              YOUR BANGALORE ADVANTAGE                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. ML + Security is RARE in India                          │
│     → You have almost no competition                        │
│     → Companies will pay premium                            │
│                                                              │
│  2. null community is your secret weapon                    │
│     → Referrals > Random applications                       │
│     → 70% of jobs filled through network                    │
│                                                              │
│  3. Product companies > Service companies                   │
│     → Better learning, pay, and growth                      │
│     → Target unicorns and big tech India                    │
│                                                              │
│  4. Remote US jobs are accessible                           │
│     → Build strong online presence                          │
│     → 50-70% US salary from India = excellent               │
│                                                              │
│  5. Bangalore is India's security hub                       │
│     → More opportunities than anywhere else                 │
│     → Active community and meetups                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

**The Indian security community is incredibly welcoming. null Bangalore will become your professional family. Show up, contribute, learn, and doors will open!** 🇮🇳🚀

**Pro tip: Your ML + Security combination is RARE in India. Most security folks don't have ML background. Most ML folks don't understand security. You're the bridge. USE IT!** 💪


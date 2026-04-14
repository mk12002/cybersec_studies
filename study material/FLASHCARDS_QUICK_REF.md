FLASHCARDS_QUICK_REF.md

# 📚 FLASHCARDS & QUICK REFERENCE
**Key concepts to memorize — review daily**

---

## Core Security Concepts

### CIA Triad
```
┌─────────────────────┐
│   CONFIDENTIALITY   │ → Only authorized can READ
├─────────────────────┤
│     INTEGRITY       │ → Only authorized can MODIFY
├─────────────────────┤
│    AVAILABILITY     │ → Systems stay ACCESSIBLE
└─────────────────────┘
```

### Authentication vs Authorization
```
AuthN (Authentication) = WHO are you?
  "Prove your identity"
  → Password, MFA, certificate, biometric
  
AuthZ (Authorization) = WHAT can you do?
  "Check your permissions"
  → Read file? Delete user? Access admin panel?

Remember: You can be AUTHENTICATED but not AUTHORIZED
```

### Defense in Depth
```
Layer 1: Network     → Firewall, segmentation
Layer 2: Host        → Patching, hardening, EDR
Layer 3: Application → Input validation, authZ
Layer 4: Data        → Encryption, access control
Layer 5: Human       → Training, awareness

If one layer fails, others protect you.
```

---

## Web Vulnerabilities (OWASP Top 10)

### A01: Broken Access Control (IDOR)
```
What: Access other users' data by changing IDs
Why:  Server doesn't verify ownership
Fix:  Server-side authorization checks on EVERY request
Test: Change user_id/order_id in requests
```

### A02: Cryptographic Failures
```
What: Sensitive data exposed (weak crypto, cleartext)
Why:  No encryption, weak algorithms, key mismanagement
Fix:  TLS everywhere, AES-GCM, proper key storage
Test: Check for HTTP, look at storage
```

### A03: Injection
```
What: Attacker's code executed by interpreter
Why:  User input concatenated into queries/commands
Fix:  Parameterized queries, never concatenate
Test: Add quotes, see what breaks

Types:
- SQLi:  ' OR 1=1--
- XSS:   <script>alert(1)</script>
- CMDi:  ; ls -la
- LDAPi: *)(uid=*)
```

### A04: Insecure Design
```
What: Flaws in architecture, not just code
Why:  No threat modeling, wrong assumptions
Fix:  Threat model BEFORE building
Test: Think: "What if attacker does X?"
```

### A05: Security Misconfiguration
```
What: Default creds, verbose errors, open ports
Why:  Didn't change defaults, didn't harden
Fix:  Hardening guides, config management
Test: Check defaults, error messages
```

### A06: Vulnerable Components
```
What: Using libraries with known CVEs
Why:  No dependency scanning, no updates
Fix:  SCA tools, regular updates, SBOM
Test: Check versions, search CVE databases
```

### A07: Auth Failures
```
What: Weak passwords, no MFA, broken sessions
Why:  Weak requirements, bad session handling
Fix:  MFA, rate limiting, secure session
Test: Brute force, session fixation
```

### A08: Software Integrity
```
What: Untrusted code/data (deserialization, updates)
Why:  No verification of code/data source
Fix:  Signatures, safe deserialization
Test: Modify data, check signatures
```

### A09: Logging Failures
```
What: No logs = no detection = no response
Why:  Logging not prioritized
Fix:  Log security events, alert on anomalies
Test: Do attacks appear in logs?
```

### A10: SSRF
```
What: Server fetches attacker-controlled URL
Why:  No URL validation on server-side requests
Fix:  Allowlist domains, block internal IPs
Test: Request internal IPs, cloud metadata
```

---

## Attack Patterns (Quick Reference)

### SQL Injection
```
Test strings:
  '
  ' OR '1'='1
  ' OR '1'='1'--
  1' ORDER BY 1--
  ' UNION SELECT NULL--

Fix: PARAMETERIZED QUERIES
  BAD:  query = "SELECT * FROM users WHERE id = " + user_input
  GOOD: cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
```

### XSS (Cross-Site Scripting)
```
Types:
  Reflected:  Payload in URL, reflected in response
  Stored:     Payload saved in database, served to others
  DOM:        Payload processed by client-side JavaScript

Test strings:
  <script>alert(1)</script>
  <img src=x onerror=alert(1)>
  javascript:alert(1)
  
Fix: Output encoding, CSP, HttpOnly cookies
```

### SSRF (Server-Side Request Forgery)
```
Test URLs:
  http://127.0.0.1/
  http://localhost/
  http://169.254.169.254/  (AWS metadata)
  http://[::1]/            (IPv6 localhost)

Impact in cloud:
  → Steal cloud credentials
  → Access internal services
  → Pivot to backend systems

Fix: Allowlist URLs, block private IPs
```

### Path Traversal
```
Test strings:
  ../../../etc/passwd
  ..%2f..%2f..%2fetc/passwd
  ....//....//etc/passwd
  
Fix: Validate paths, use basename(), chroot
```

---

## Crypto Quick Reference

### What to Use
```
Symmetric encryption:  AES-256-GCM or ChaCha20-Poly1305
Password hashing:      Argon2id > bcrypt > scrypt > PBKDF2
General hashing:       SHA-256 or SHA-3
MAC:                   HMAC-SHA-256
Key exchange:          X25519 (ECDH)
Signatures:            Ed25519 or RSA-PSS
```

### What NOT to Use
```
❌ MD5         (broken)
❌ SHA-1       (broken for signatures)
❌ DES/3DES    (weak)
❌ RC4         (broken)
❌ ECB mode    (patterns visible)
❌ Plain RSA   (needs padding)
```

### AEAD (Authenticated Encryption)
```
Provides: Confidentiality + Integrity + Authenticity

How it works:
  Encrypt(key, nonce, plaintext, AAD) → ciphertext + tag
  
Critical rule: NEVER reuse a nonce with the same key
```

### Password Storage
```
WRONG:
  hash = SHA256(password)              # Too fast to brute force
  hash = SHA256(salt + password)       # Still too fast

RIGHT:
  hash = argon2id(password, salt, memory=64MB, iterations=3)
  hash = bcrypt(password, cost=12)
```

---

## Cloud Security

### Shared Responsibility Model
```
┌────────────────────────────────────────────────┐
│                    YOU OWN                      │
├────────────────────────────────────────────────┤
│ IaaS: OS, apps, data, network config, identity │
│ PaaS: Apps, data, identity                      │
│ SaaS: Data, identity, configuration            │
├────────────────────────────────────────────────┤
│              CLOUD PROVIDER OWNS                │
├────────────────────────────────────────────────┤
│ Physical, network, hypervisor, (and more based │
│ on service model)                              │
└────────────────────────────────────────────────┘
```

### IAM Best Practices
```
✓ Least privilege (minimum needed permissions)
✓ No long-lived credentials (use roles/federation)
✓ MFA for humans (especially admins)
✓ Separate accounts for dev/staging/prod
✓ Regular access reviews
✓ Log and alert on IAM changes
```

### Dangerous IAM Actions (AWS)
```
iam:CreateAccessKey     → Create persistent credentials
iam:CreateUser          → Create new identities
iam:AttachUserPolicy    → Grant permissions
iam:PassRole            → Assume other roles
sts:AssumeRole          → Become another identity
s3:PutBucketPolicy      → Make buckets public
lambda:UpdateFunction   → Inject code
```

### Cloud Attack Chain
```
1. Initial Access
   └─ Leaked credentials, SSRF, phishing

2. Privilege Escalation  
   └─ Over-permissive roles, assume-role abuse

3. Lateral Movement
   └─ Cross-account trust, shared credentials

4. Persistence
   └─ New access keys, backdoor roles

5. Impact
   └─ Data exfil, crypto mining, ransomware
```

---

## HTTP Quick Reference

### Important Headers
```
Cookie:           Session state
Authorization:    Bearer tokens
Content-Type:     Data format (application/json)
X-Forwarded-For:  Original client IP (behind proxy)
Origin:           Request origin (CORS/CSRF)
```

### Status Codes (Security Relevant)
```
200 OK            → Success
301/302 Redirect  → Watch for open redirects
400 Bad Request   → Input validation caught something
401 Unauthorized  → Not authenticated
403 Forbidden     → Authenticated but not authorized
404 Not Found     → Or security through obscurity
500 Server Error  → Might leak stack traces
```

### Cookie Attributes
```
HttpOnly   → JS can't read (protects from XSS)
Secure     → HTTPS only
SameSite   → CSRF protection (Strict/Lax/None)
Path       → Cookie scope
Domain     → Cookie scope
```

---

## Linux Commands (Security)

### User/Permission Investigation
```bash
id                    # Current user info
whoami                # Current username
cat /etc/passwd       # All users
cat /etc/group        # All groups
sudo -l               # What can I sudo?
find / -perm -4000    # SUID binaries
ls -la /etc/shadow    # Password hash permissions
```

### Network Investigation
```bash
netstat -tulpn        # Listening ports
ss -tulpn             # Same, newer command
ip addr               # Network interfaces
arp -a                # ARP cache
route -n              # Routing table
cat /etc/resolv.conf  # DNS config
```

### Process Investigation
```bash
ps aux                # All processes
top                   # Live process view
lsof -i               # Open network files
pstree                # Process tree
```

### Log Locations
```bash
/var/log/auth.log     # Authentication (Debian/Ubuntu)
/var/log/secure       # Authentication (RHEL/CentOS)
/var/log/syslog       # System messages
/var/log/messages     # System messages (RHEL)
/var/log/apache2/     # Apache logs
~/.bash_history       # Command history
```

---

## Windows Commands (Security)

### User Investigation
```powershell
whoami /all               # Current user + groups + privs
net user                  # List users
net localgroup            # List groups
net localgroup Administrators  # Admin group members
```

### Network Investigation
```powershell
netstat -ano              # Connections with PIDs
Get-NetTCPConnection      # Same, PowerShell
ipconfig /all             # Network config
arp -a                    # ARP cache
route print               # Routing table
```

### Event Log Queries
```powershell
# Logon events (4624)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 10

# Failed logons (4625)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 10

# Service installs (7045)
Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} -MaxEvents 10
```

---

## Detection Patterns

### Brute Force
```
Signal: Many failed logins from same IP or to same account
Alert:  > 5 failed logins in 5 minutes
Log:    auth failures with IP, user, timestamp
```

### IDOR/BOLA
```
Signal: User accessing many different object IDs
Alert:  > 10 distinct object_owner_ids in 5 minutes
Log:    object access with actor, object_id, owner_id
```

### Privilege Escalation
```
Signal: Role changes, new admin accounts, policy changes
Alert:  Any privilege modification outside change window
Log:    IAM events with before/after state
```

### Data Exfiltration
```
Signal: Unusual data volume, off-hours access, new destinations
Alert:  > 100MB data transfer or unusual destination
Log:    data access with size, destination, time
```

---

## Interview Quick Answers

**Q: Explain XSS in 30 seconds**
> XSS lets an attacker run their JavaScript in a victim's browser. It happens when user input is reflected in a page without encoding. The attacker's script can steal cookies, modify the page, or perform actions as the victim. Fix it with output encoding and CSP.

**Q: What's the difference between encryption and hashing?**
> Encryption is reversible with a key—use it when you need data back. Hashing is one-way—use it for verification like passwords or file integrity.

**Q: How would you secure an API?**
> Authentication (verify who's calling), authorization (verify they can do this action), input validation (reject bad data), rate limiting (prevent abuse), logging (detect attacks), TLS (encrypt in transit).

**Q: What would you do if you found a vulnerability in production?**
> Document minimally without accessing real data, report to security team immediately, suggest quick mitigation (disable endpoint/add WAF rule), help with root cause fix, verify the fix, add detection.

---

## Daily Review Checklist

□ Review 5 terms from this document
□ Explain one attack to yourself (out loud or written)
□ Think: "How would I detect this attack?"
□ Think: "How would I prevent this attack?"

**Consistency beats intensity. 10 minutes daily > 2 hours once a week.**


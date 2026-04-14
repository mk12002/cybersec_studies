TOOLS_CHEAT_SHEET.md

# 🛠️ SECURITY TOOLS CHEAT SHEET
**Quick reference for common security tools and commands**

---

## Web Security Testing

### Burp Suite (Web Proxy)

**Setup Checklist:**
```
1. Start Burp → Proxy → Options → Confirm running on 127.0.0.1:8080
2. Firefox → Settings → Network → Manual Proxy → 127.0.0.1:8080
3. Visit http://burp → Download CA Certificate
4. Firefox → Settings → Privacy → Certificates → Import Burp CA
5. Proxy → Intercept → Turn ON
```

**Essential Shortcuts:**
```
Ctrl+I          Send to Intruder
Ctrl+R          Send to Repeater
Ctrl+U          URL encode selection
Ctrl+Shift+U    URL decode selection
Ctrl+F          Forward intercepted request
Ctrl+D          Drop intercepted request
```

**Common Workflows:**

*Testing for SQLi:*
```
1. Capture request in Proxy
2. Send to Repeater (Ctrl+R)
3. Modify parameter: username=admin'
4. Send and observe response
5. If error/different behavior → potential SQLi
```

*Testing for IDOR:*
```
1. Login as User A, capture request to /api/users/123
2. Note User A's ID (123)
3. Login as User B (different session)
4. Replay request with User A's ID
5. If you see User A's data → IDOR confirmed
```

*Fuzzing with Intruder:*
```
1. Send request to Intruder (Ctrl+I)
2. Clear existing positions → Add position around target param
3. Payloads → Load wordlist or use built-in
4. Start attack
5. Sort by response length/status to find anomalies
```

---

### Browser DevTools (F12)

**Network Tab:**
```
• View all HTTP requests/responses
• Right-click → Copy as cURL (useful for automation)
• Filter by XHR to see API calls
• Check timing for potential timing attacks
```

**Console Tab:**
```javascript
// View cookies
document.cookie

// Check for DOM XSS sinks
document.location.search    // URL parameters
document.location.hash      # Fragment
window.name                 // Persistent across pages

// Test localStorage access
localStorage.getItem('token')
```

**Application Tab:**
```
• View/edit cookies
• Check localStorage and sessionStorage
• See service workers
• Clear site data for fresh testing
```

---

## Network Analysis

### Wireshark

**Capture Filters (before capture):**
```
host 192.168.1.100              # Traffic to/from IP
port 80                         # HTTP traffic
port 443                        # HTTPS traffic
tcp port 22                     # SSH
not port 22                     # Exclude SSH
```

**Display Filters (after capture):**
```
http                            # All HTTP
http.request.method == "POST"   # POST requests only
ip.addr == 192.168.1.100        # Specific IP
tcp.flags.syn == 1              # SYN packets (new connections)
dns                             # DNS queries
http contains "password"        # Search in HTTP
frame contains "admin"          # Search anywhere
```

**Useful Analysis:**
```
Statistics → Conversations      # Who talked to whom
Statistics → Protocol Hierarchy # What protocols used
Analyze → Follow → TCP Stream  # Reconstruct conversation
File → Export Objects → HTTP   # Extract files
```

### tcpdump (Command Line)

```bash
# Capture to file
sudo tcpdump -i eth0 -w capture.pcap

# Read from file
tcpdump -r capture.pcap

# Specific host
sudo tcpdump -i eth0 host 192.168.1.100

# Specific port
sudo tcpdump -i eth0 port 80

# HTTP traffic with content
sudo tcpdump -i eth0 -A port 80

# DNS queries
sudo tcpdump -i eth0 port 53

# Common combination
sudo tcpdump -i eth0 -n -v port 80 and host 10.0.0.1
```

### Nmap (Network Scanner)

⚠️ **ONLY scan systems you own or have explicit permission to test!**

```bash
# Basic scan (most common)
nmap 192.168.1.0/24             # Scan subnet
nmap -sV 192.168.1.100          # Service version detection
nmap -sC 192.168.1.100          # Default scripts
nmap -A 192.168.1.100           # Aggressive (OS + version + scripts)

# Specific ports
nmap -p 80,443 192.168.1.100    # Specific ports
nmap -p- 192.168.1.100          # All ports (slow)
nmap -p 1-1000 192.168.1.100    # Port range

# Stealth options
nmap -sS 192.168.1.100          # SYN scan (default, needs root)
nmap -sT 192.168.1.100          # Connect scan (no root needed)

# Output
nmap -oN scan.txt 192.168.1.100     # Normal output
nmap -oX scan.xml 192.168.1.100     # XML output
nmap -oA scan_results 192.168.1.100 # All formats
```

---

## Reconnaissance

### DNS Enumeration

```bash
# Basic lookup
nslookup example.com
dig example.com

# Specific record types
dig example.com MX       # Mail servers
dig example.com TXT      # TXT records (SPF, DKIM)
dig example.com NS       # Name servers
dig example.com ANY      # All records (may be blocked)

# Reverse lookup
dig -x 93.184.216.34

# Zone transfer attempt (often blocked)
dig axfr @ns1.example.com example.com
```

### Subdomain Discovery

```bash
# Using crt.sh (Certificate Transparency)
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq '.[].name_value' | sort -u

# Using subfinder (install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
subfinder -d example.com

# Using amass (install: apt install amass)
amass enum -d example.com
```

---

## Password & Hash Tools

### Hashcat (GPU Cracking)

```bash
# Identify hash type
hashcat --identify hash.txt

# Common hash modes
# 0    = MD5
# 100  = SHA1
# 1400 = SHA256
# 1800 = SHA512crypt ($6$)
# 3200 = bcrypt
# 1000 = NTLM

# Dictionary attack
hashcat -m 0 hash.txt wordlist.txt

# With rules
hashcat -m 0 hash.txt wordlist.txt -r rules/best64.rule

# Brute force
hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a?a  # 6 char all
```

### John the Ripper

```bash
# Auto-detect and crack
john hash.txt

# Specify format
john --format=raw-md5 hash.txt

# Use wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Show cracked
john --show hash.txt
```

---

## Python Security Scripts

### HTTP Request Testing

```python
import requests

# Basic authenticated request
session = requests.Session()
session.auth = ('user', 'password')

# POST with JSON
response = session.post(
    'https://api.example.com/login',
    json={'username': 'admin', 'password': 'test'},
    headers={'Content-Type': 'application/json'},
    timeout=10,
    verify=True  # SSL verification
)

print(f"Status: {response.status_code}")
print(f"Headers: {response.headers}")
print(f"Body: {response.text}")

# Cookie handling
print(f"Cookies: {session.cookies.get_dict()}")
```

### Directory Brute Force

```python
import requests
from concurrent.futures import ThreadPoolExecutor

def check_path(base_url, path):
    url = f"{base_url}/{path}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code != 404:
            return f"[{r.status_code}] {url}"
    except:
        pass
    return None

base_url = "https://target.com"
wordlist = ['admin', 'login', 'api', 'backup', 'config']

with ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(lambda p: check_path(base_url, p), wordlist)
    for r in results:
        if r:
            print(r)
```

### Log Parser

```python
import re
from collections import Counter

# Parse auth failures from log
auth_failures = Counter()
pattern = r'Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)'

with open('/var/log/auth.log') as f:
    for line in f:
        match = re.search(pattern, line)
        if match:
            user, ip = match.groups()
            auth_failures[ip] += 1

# Top 10 offenders
for ip, count in auth_failures.most_common(10):
    print(f"{ip}: {count} failures")
```

---

## Cloud CLI Tools

### AWS CLI

```bash
# Configure credentials
aws configure

# IAM
aws iam list-users
aws iam list-roles
aws iam get-user --user-name admin
aws iam list-attached-user-policies --user-name admin

# S3
aws s3 ls                          # List buckets
aws s3 ls s3://bucket-name         # List objects
aws s3api get-bucket-acl --bucket name
aws s3api get-bucket-policy --bucket name

# CloudTrail (audit logs)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=admin

# EC2
aws ec2 describe-instances
aws ec2 describe-security-groups
```

### Azure CLI

```bash
# Login
az login

# Identity
az ad user list
az role assignment list
az ad sp list                      # Service principals

# Storage
az storage account list
az storage container list --account-name <name>

# Activity Log
az monitor activity-log list --offset 1h
```

---

## Quick Payload Reference

### SQL Injection Test Strings
```sql
'                           -- Basic break
' OR '1'='1                 -- Always true
' OR '1'='1' --            -- Comment rest
' UNION SELECT NULL--      -- Union test
admin'--                    -- Login bypass attempt
1; DROP TABLE users--      -- Destructive (NEVER in prod!)
```

### XSS Test Strings
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
"><script>alert(1)</script>
'-alert(1)-'
```

### Path Traversal
```
../../../etc/passwd
..%2f..%2f..%2fetc/passwd
....//....//....//etc/passwd
/etc/passwd%00.jpg
```

### SSRF Test URLs
```
http://127.0.0.1/
http://localhost/
http://169.254.169.254/latest/meta-data/  # AWS metadata
http://[::1]/                              # IPv6 localhost
http://0.0.0.0/
http://2130706433/                         # Decimal IP for 127.0.0.1
```

---

## File Locations Reference

### Linux Important Files
```
/etc/passwd           # User accounts
/etc/shadow           # Password hashes (root only)
/etc/hosts            # Host mappings
/etc/ssh/sshd_config  # SSH configuration
/var/log/auth.log     # Authentication logs
/var/log/syslog       # System logs
~/.bash_history       # Command history
~/.ssh/               # SSH keys
```

### Windows Important Files/Locations
```
C:\Windows\System32\config\SAM           # Password hashes
C:\Windows\System32\config\SYSTEM        # System config
C:\Users\<user>\NTUSER.DAT               # User registry
C:\Windows\System32\winevt\Logs\         # Event logs
C:\Windows\Prefetch\                     # Execution evidence
%APPDATA%\                               # User app data
```

---

## Wordlists Location

**Kali Linux:**
```
/usr/share/wordlists/
/usr/share/wordlists/rockyou.txt        # Common passwords
/usr/share/wordlists/dirb/              # Directory lists
/usr/share/wordlists/dirbuster/         # More directories
/usr/share/seclists/                    # SecLists collection
```

**SecLists (install separately):**
```bash
git clone https://github.com/danielmiessler/SecLists.git
# Contains: passwords, usernames, URLs, payloads, etc.
```

---

## Quick Reference Card

```
+------------------+------------------------+-------------------------+
| Task             | Tool                   | Basic Command           |
+------------------+------------------------+-------------------------+
| Web proxy        | Burp Suite             | Start → Proxy tab       |
| Network capture  | Wireshark              | wireshark               |
| CLI capture      | tcpdump                | tcpdump -i eth0 -w out  |
| Port scan        | nmap                   | nmap -sV target         |
| Dir brute        | gobuster/ffuf          | gobuster dir -u URL -w  |
| Password crack   | hashcat                | hashcat -m 0 hash.txt   |
| SQLi testing     | sqlmap                 | sqlmap -u "url?id=1"    |
| DNS lookup       | dig                    | dig example.com ANY     |
+------------------+------------------------+-------------------------+
```

---

**Remember: Tools are just tools. Understanding WHY they work is what makes you a security professional.** 🔧


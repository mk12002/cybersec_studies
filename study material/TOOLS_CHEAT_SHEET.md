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


---

# ADVANCED TOOLS DEEP DIVE

## SAST/DAST Tools

### Semgrep (Static Analysis)

**Installation:**
```bash
pip install semgrep
```

**Basic Usage:**
```bash
# Run with default rules
semgrep --config auto path/to/code

# Specific rule sets
semgrep --config p/security-audit path/to/code
semgrep --config p/owasp-top-ten path/to/code
semgrep --config p/python path/to/code

# Custom rule
semgrep --config custom-rule.yml path/to/code
```

**Custom Rule Example:**
```yaml
rules:
  - id: hardcoded-secret
    pattern: |
      password = "..."
    message: "Hardcoded password detected"
    severity: ERROR
    languages: [python]
    
  - id: sql-injection
    pattern: |
      cursor.execute("..." % ...)
    message: "Potential SQL injection - use parameterized queries"
    severity: ERROR
    languages: [python]
```

### Nuclei (Vulnerability Scanner)

**Installation:**
```bash
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

**Basic Usage:**
```bash
# Update templates
nuclei -ut

# Scan with all templates
nuclei -u https://target.com

# Specific template categories
nuclei -u https://target.com -tags cve
nuclei -u https://target.com -tags takeover
nuclei -u https://target.com -tags exposure

# Multiple targets
nuclei -l urls.txt -t exposures/

# Custom severity
nuclei -u https://target.com -severity critical,high
```

### OWASP ZAP (Alternative to Burp)

**Headless Scan:**
```bash
# Spider and scan
docker run -v C:\Users\66303\Downloads\study:/zap/wrk/:rw owasp/zap2docker-stable zap-baseline.py -t https://target.com -r report.html

# API scan
docker run -v C:\Users\66303\Downloads\study:/zap/wrk/:rw owasp/zap2docker-stable zap-api-scan.py -t https://target.com/api/openapi.json -f openapi -r report.html

# Full scan (longer)
docker run -v C:\Users\66303\Downloads\study:/zap/wrk/:rw owasp/zap2docker-stable zap-full-scan.py -t https://target.com -r report.html
```

---

## Container Security

### Trivy (Container Scanner)

**Installation:**
```bash
# Install
brew install trivy  # macOS
apt install trivy   # Debian/Ubuntu
```

**Usage:**
```bash
# Scan image
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL nginx:latest

# Scan filesystem
trivy fs /path/to/project

# Scan Kubernetes
trivy k8s --report summary cluster

# Output formats
trivy image -f json nginx:latest > results.json
trivy image -f template --template "@contrib/html.tpl" nginx:latest > report.html
```

### Docker Bench Security

```bash
# Run Docker security benchmark
docker run -it --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST= \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /etc:/etc:ro \
  --label docker_bench_security \
  docker/docker-bench-security
```

---

## Cloud Security Tools

### Prowler (AWS Security)

**Installation:**
```bash
pip install prowler
```

**Usage:**
```bash
# Full AWS assessment
prowler aws

# Specific checks
prowler aws -c check11,check12,check13

# Specific services
prowler aws --services s3,iam,ec2

# Output
prowler aws -M csv,json,html
```

### ScoutSuite (Multi-Cloud)

**Installation:**
```bash
pip install scoutsuite
```

**Usage:**
```bash
# AWS
scout aws

# Azure
scout azure --cli

# GCP
scout gcp --user-account

# Generate report
scout aws -r us-east-1 --report-dir ./reports
```

### Checkov (IaC Security)

**Installation:**
```bash
pip install checkov
```

**Usage:**
```bash
# Scan Terraform
checkov -d /path/to/terraform

# Scan specific file
checkov -f main.tf

# Scan CloudFormation
checkov -f template.yaml --framework cloudformation

# Scan Kubernetes
checkov -f deployment.yaml --framework kubernetes

# Skip checks
checkov -d . --skip-check CKV_AWS_1,CKV_AWS_2

# Output
checkov -d . -o json > results.json
```

---

## Detection and Forensics

### Sigma CLI

**Installation:**
```bash
pip install sigma-cli
```

**Usage:**
```bash
# Convert to Splunk
sigma convert -t splunk -p sysmon rules/

# Convert to Elastic
sigma convert -t elasticsearch rules/

# Convert to Microsoft Sentinel/KQL
sigma convert -t microsoft365defender rules/

# List backends
sigma backend list

# Validate rules
sigma check rules/
```

**Example Sigma Rule:**
```yaml
title: Suspicious PowerShell Download Cradle
status: experimental
description: Detects PowerShell download cradles
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - 'downloadstring'
    condition: selection
level: high
```

### Chainsaw (Log Analysis)

**Usage:**
```bash
# Hunt with Sigma rules
chainsaw hunt evtx_files/ -s sigma_rules/ --mapping mappings/sigma-event-logs-all.yml

# Search for keyword
chainsaw search evtx_files/ -s "mimikatz"

# Dump events
chainsaw dump evtx_files/ --json
```

### Velociraptor (DFIR)

**Common Artifacts:**
```yaml
# Windows process listing
SELECT * FROM Artifact.Windows.System.Pslist()

# Recent file executions
SELECT * FROM Artifact.Windows.System.Amcache()

# Browser history
SELECT * FROM Artifact.Windows.Applications.Chrome.History()

# Scheduled tasks
SELECT * FROM Artifact.Windows.System.TaskScheduler()

# Network connections
SELECT * FROM Artifact.Windows.Network.Netstat()
```

---

## Fuzzing Tools

### ffuf (Web Fuzzer)

**Installation:**
```bash
go install github.com/ffuf/ffuf@latest
```

**Usage:**
```bash
# Directory brute force
ffuf -w /path/to/wordlist -u https://target.com/FUZZ

# With extensions
ffuf -w wordlist -u https://target.com/FUZZ -e .php,.html,.js

# POST data fuzzing
ffuf -w wordlist -u https://target.com/api/login -X POST -d "user=admin&pass=FUZZ"

# Header fuzzing
ffuf -w wordlist -u https://target.com -H "X-Custom-Header: FUZZ"

# Virtual host discovery
ffuf -w wordlist -u https://target.com -H "Host: FUZZ.target.com"

# Filtering
ffuf -w wordlist -u https://target.com/FUZZ -fc 404        # Filter by status code
ffuf -w wordlist -u https://target.com/FUZZ -fs 1234       # Filter by size
ffuf -w wordlist -u https://target.com/FUZZ -fw 10         # Filter by word count

# Output
ffuf -w wordlist -u https://target.com/FUZZ -o results.json -of json
```

### Gobuster

```bash
# Directory brute force
gobuster dir -u https://target.com -w wordlist.txt

# With extensions
gobuster dir -u https://target.com -w wordlist.txt -x php,html,txt

# DNS subdomain
gobuster dns -d target.com -w subdomains.txt

# Virtual host
gobuster vhost -u https://target.com -w wordlist.txt
```

---

## API Testing

### Postman CLI (Newman)

**Installation:**
```bash
npm install -g newman
```

**Usage:**
```bash
# Run collection
newman run collection.json

# With environment
newman run collection.json -e environment.json

# With iteration data
newman run collection.json -d data.csv

# Export results
newman run collection.json -r html,json --reporter-html-export report.html
```

### HTTPie (Command Line HTTP Client)

**Installation:**
```bash
pip install httpie
```

**Usage:**
```bash
# GET request
http https://api.example.com/users

# POST with JSON
http POST https://api.example.com/users name=John email=john@example.com

# With headers
http https://api.example.com/users Authorization:"Bearer token123"

# Form data
http -f POST https://api.example.com/login username=admin password=secret

# Download
http --download https://example.com/file.zip
```

---

## Git Security

### GitLeaks

**Installation:**
```bash
brew install gitleaks  # macOS
```

**Usage:**
```bash
# Scan repo
gitleaks detect --source=/path/to/repo

# Scan specific commits
gitleaks detect --source=/path/to/repo --log-opts="--all"

# Output
gitleaks detect --source=/path/to/repo -r report.json
```

### TruffleHog

**Installation:**
```bash
pip install trufflehog
```

**Usage:**
```bash
# Scan repo
trufflehog git https://github.com/user/repo

# Scan filesystem
trufflehog filesystem /path/to/code

# Scan GitHub org
trufflehog github --org=organization-name
```

---

## Kubernetes Security

### kubesec (Manifest Analysis)

```bash
# Scan manifest
kubesec scan deployment.yaml

# Online scan
curl -sSX POST --data-binary @deployment.yaml https://v2.kubesec.io/scan
```

### kube-hunter (Cluster Scanning)

```bash
# Run in cluster
kubectl run kube-hunter --image=aquasec/kube-hunter --restart=Never --command -- kube-hunter --pod

# Remote scan
docker run -it --rm aquasec/kube-hunter --remote target-ip
```

### kubectl Security Commands

```bash
# Check RBAC
kubectl auth can-i --list --namespace default
kubectl auth can-i create pods --namespace kube-system

# Find privileged pods
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'

# Check for pods running as root
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.runAsUser==0) | .metadata.name'

# List service accounts
kubectl get serviceaccounts --all-namespaces

# Check secrets
kubectl get secrets --all-namespaces
```

---

## Network Security

### Netcat (Swiss Army Knife)

```bash
# Port scanning
nc -zv target.com 1-1000

# Banner grabbing
nc -v target.com 80

# Listen mode (reverse shell catcher)
nc -lvnp 4444

# File transfer
# Sender:
nc -w 3 target.com 1234 < file.txt
# Receiver:
nc -l -p 1234 > file.txt

# Simple chat
# Server:
nc -l -p 1234
# Client:
nc server.com 1234
```

### Masscan (Fast Port Scanner)

```bash
# Scan top ports fast
masscan -p1-1000 192.168.1.0/24 --rate=10000

# Scan specific ports
masscan -p80,443,8080 192.168.1.0/24

# Output
masscan -p1-65535 192.168.1.0/24 -oJ results.json
```

---

## Quick Install Script (Kali/Ubuntu)

```bash
#!/bin/bash
# Install common security tools

# Update
sudo apt update && sudo apt upgrade -y

# Essential tools
sudo apt install -y nmap wireshark tcpdump netcat-traditional
sudo apt install -y john hashcat
sudo apt install -y gobuster ffuf
sudo apt install -y sqlmap
sudo apt install -y python3-pip

# Python tools
pip3 install semgrep
pip3 install prowler
pip3 install scoutsuite
pip3 install checkov
pip3 install trufflehog
pip3 install httpie

# Go tools (ensure Go is installed)
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf@latest

echo "Installation complete!"
```

---

## Tool Selection Guide

```yaml
task: "I need to..."

find_subdomains:
  quick: "subfinder -d target.com"
  thorough: "amass enum -d target.com"
  passive: "crt.sh + securitytrails"

scan_web_app:
  manual: "Burp Suite"
  automated: "nuclei -u target.com"
  ci_cd: "OWASP ZAP baseline scan"

check_for_secrets:
  repo: "gitleaks detect"
  filesystem: "trufflehog filesystem ."
  ci_cd: "pre-commit hooks"

scan_cloud:
  aws: "prowler aws"
  multi_cloud: "scoutsuite"
  iac: "checkov -d ."

analyze_logs:
  windows_evtx: "chainsaw hunt"
  live_system: "velociraptor"
  detection_rules: "sigma convert"

scan_containers:
  images: "trivy image"
  k8s_manifests: "kubesec scan"
  running_cluster: "kube-hunter"
```


**Master the fundamentals before chasing tools. A skilled analyst with basic tools beats an amateur with premium ones.** ??


---

# DEFENSIVE AND ANALYSIS TOOLS

## Log Analysis Tools

### jq (JSON Processing)

```bash
# Pretty print JSON
cat file.json | jq '.'

# Extract specific field
cat logs.json | jq '.events[].sourceIP'

# Filter by condition
cat logs.json | jq '.events[] | select(.statusCode == 403)'

# Count occurrences
cat logs.json | jq '[.events[].sourceIP] | group_by(.) | map({ip: .[0], count: length}) | sort_by(.count) | reverse'

# Multiple filters
cat logs.json | jq '.events[] | select(.eventName == "ConsoleLogin" and .errorCode != null)'
```

### awk/sed (Text Processing)

```bash
# Extract specific columns
awk '{print $1, $4}' access.log

# Sum values
awk '{sum += $10} END {print sum}' access.log

# Filter and count
awk '/POST/ {count++} END {print count}' access.log

# Replace text
sed 's/old/new/g' file.txt

# Delete lines matching pattern
sed '/pattern/d' file.txt

# Extract between patterns
sed -n '/START/,/END/p' file.txt
```

---

## Network Analysis Tools

### tshark (Command-line Wireshark)

```bash
# Capture to file
tshark -i eth0 -w capture.pcap

# Read and filter
tshark -r capture.pcap -Y "http.request.method == POST"

# Extract specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e http.host

# Statistics
tshark -r capture.pcap -q -z endpoints,ip

# Follow TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

### curl (HTTP Testing)

```bash
# Basic request with headers
curl -v https://example.com

# POST JSON
curl -X POST -H "Content-Type: application/json" -d '{"key":"value"}' https://api.example.com

# With authentication
curl -u user:password https://example.com
curl -H "Authorization: Bearer token123" https://api.example.com

# Follow redirects
curl -L https://example.com

# Save response headers
curl -D headers.txt https://example.com

# Timing info
curl -w "@curl-format.txt" -o /dev/null -s https://example.com
```

---

## Security Scanning (Defensive)

### OpenSSL (Certificate/TLS Testing)

```bash
# Check certificate
openssl s_client -connect example.com:443 -servername example.com

# View certificate details
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -text

# Check expiration
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates

# Test specific TLS version
openssl s_client -connect example.com:443 -tls1_2
openssl s_client -connect example.com:443 -tls1_3

# Check cipher suites
openssl s_client -connect example.com:443 -cipher 'HIGH:!aNULL:!MD5'
```

### testssl.sh (TLS Configuration)

```bash
# Full scan
./testssl.sh https://example.com

# Quick scan
./testssl.sh --fast https://example.com

# Check specific vulnerability
./testssl.sh --heartbleed https://example.com
./testssl.sh --robot https://example.com

# Output to file
./testssl.sh --jsonfile results.json https://example.com
```

### Nikto (Web Server Scanner)

```bash
# Basic scan
nikto -h https://target.com

# With authentication
nikto -h https://target.com -id admin:password

# Specific port
nikto -h target.com -p 8080

# Save output
nikto -h https://target.com -o report.html -Format html
```

---

## Forensics Tools

### Volatility (Memory Analysis)

```bash
# Identify image profile
volatility -f memory.dmp imageinfo

# List processes
volatility -f memory.dmp --profile=Win10x64 pslist
volatility -f memory.dmp --profile=Win10x64 pstree

# Network connections
volatility -f memory.dmp --profile=Win10x64 netscan

# Command history
volatility -f memory.dmp --profile=Win10x64 cmdscan
volatility -f memory.dmp --profile=Win10x64 consoles

# Dump process memory
volatility -f memory.dmp --profile=Win10x64 memdump -p 1234 -D output/
```

### Sleuthkit/Autopsy (Disk Forensics)

```bash
# List partitions
mmls disk.img

# List files
fls -r disk.img

# Extract file by inode
icat disk.img 12345 > recovered_file

# Search for string
srch_strings disk.img

# Create timeline
fls -m "/" -r disk.img > body.txt
mactime -b body.txt > timeline.csv
```

---

## Automation Scripts

### Security Audit Script Template

```bash
#!/bin/bash
# Basic security audit script

echo "=== System Information ==="
uname -a
cat /etc/os-release

echo "=== Users with UID 0 ==="
awk -F: '($3 == 0) {print}' /etc/passwd

echo "=== Listening Ports ==="
ss -tulpn

echo "=== SUID Files ==="
find / -perm -4000 -type f 2>/dev/null

echo "=== World-Writable Files ==="
find / -perm -002 -type f 2>/dev/null | head -20

echo "=== Failed Logins (last 24h) ==="
grep "Failed password" /var/log/auth.log | tail -20

echo "=== Cron Jobs ==="
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null
done
```

### Log Parser Template (Python)

```python
import re
from collections import Counter
import json
from datetime import datetime

def parse_auth_log(logfile):
    failed_logins = Counter()
    pattern = r'Failed password for (?:invalid user )?(\S+) from (\S+)'
    
    with open(logfile) as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                user, ip = match.groups()
                failed_logins[ip] += 1
    
    # Top 10 offenders
    print("Top 10 IPs with failed logins:")
    for ip, count in failed_logins.most_common(10):
        print(f"  {ip}: {count}")

def parse_json_logs(logfile):
    events = []
    with open(logfile) as f:
        for line in f:
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError:
                continue
    
    # Analyze events
    event_types = Counter(e.get('eventType') for e in events)
    print("Event type distribution:")
    for event_type, count in event_types.most_common():
        print(f"  {event_type}: {count}")

if __name__ == "__main__":
    parse_auth_log("/var/log/auth.log")
```

---

## Compliance Checking

### Lynis (System Hardening)

```bash
# Run audit
sudo lynis audit system

# Quick scan
sudo lynis audit system --quick

# Specific profile
sudo lynis audit system --profile server

# Output to file
sudo lynis audit system --report-file report.txt
```

### InSpec (Compliance as Code)

```ruby
# Example InSpec profile
control 'ssh-config' do
  impact 1.0
  title 'SSH Configuration'
  desc 'Ensure SSH is configured securely'
  
  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
    its('PasswordAuthentication') { should eq 'no' }
    its('Protocol') { should eq '2' }
  end
end

control 'password-policy' do
  impact 0.7
  title 'Password Policy'
  
  describe file('/etc/login.defs') do
    its('content') { should match /PASS_MAX_DAYS\s+90/ }
    its('content') { should match /PASS_MIN_DAYS\s+1/ }
  end
end
```

```bash
# Run InSpec
inspec exec profile_directory/
inspec exec profile_directory/ -t ssh://user@host
inspec exec profile_directory/ --reporter json:results.json
```

---

## CI/CD Security Integration

### Git Hooks for Security

```bash
# pre-commit hook (.git/hooks/pre-commit)
#!/bin/bash

# Check for secrets
if git diff --cached | grep -iE "(password|secret|key|token)\s*=\s*['\"][^'\"]+['\"]"; then
    echo "ERROR: Potential secret detected in commit"
    exit 1
fi

# Check for large files
for file in $(git diff --cached --name-only); do
    size=$(wc -c < "$file" 2>/dev/null || echo 0)
    if [ "$size" -gt 1000000 ]; then
        echo "ERROR: File $file is larger than 1MB"
        exit 1
    fi
done

exit 0
```

### GitHub Actions Security Workflow

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: p/security-audit
          
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          severity: 'CRITICAL,HIGH'
          
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: all
```

---

**Security is a continuous process. Automate what you can, but always understand what your tools are doing.**

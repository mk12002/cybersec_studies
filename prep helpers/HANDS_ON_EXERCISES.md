HANDS_ON_EXERCISES.md

# 🎯 HANDS-ON EXERCISES (Beginner-Friendly)
**Practical exercises to build real skills**

---

## How to Use This Document

Each exercise follows this structure:
1. **Objective** — What you'll learn
2. **Prerequisites** — What you need first
3. **Steps** — Detailed walkthrough
4. **Verification** — How to know you succeeded
5. **Write-up Prompt** — What to document

**Rule: Don't skip the write-up!** Documentation is 50% of security work.

---

## EXERCISE 1: Your First SQL Injection (PortSwigger Lab)

### Objective
Understand how SQL injection works by exploiting a real (safe) vulnerable application.

### Prerequisites
- Burp Suite Community installed
- Browser configured with Burp proxy
- PortSwigger account (free)

### Steps

**Step 1: Access the lab**
```
1. Go to: https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data
2. Click "Access the lab"
3. You'll see a shopping site with product categories
```

**Step 2: Understand normal behavior**
```
1. Click on "Gifts" category
2. Notice the URL: https://[lab-id].web-security-academy.net/filter?category=Gifts
3. In Burp, find this request in HTTP History
4. The SQL query probably looks like:
   SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Step 3: Test for SQLi**
```
1. In the URL, change category=Gifts to category=Gifts'
2. If you see an error or different behavior, SQLi might be possible
3. The query became: ... WHERE category = 'Gifts'' — broken syntax!
```

**Step 4: Exploit to see hidden products**
```
1. Try this payload: Gifts'+OR+1=1--
2. Full URL: /filter?category=Gifts'+OR+1=1--
3. The query becomes:
   SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
   
4. The -- comments out the rest, and OR 1=1 is always true
5. You should see ALL products, including unreleased ones
```

### Verification
- Lab shows "Congratulations, you solved the lab!"
- You can see products that weren't visible before

### Write-up Prompt
Answer these questions in your notes:
1. What was the vulnerable parameter?
2. What did the original SQL query look like?
3. How did your payload modify the query?
4. What's the root cause? (Why did this work?)
5. How would you fix this in code?
6. What would you log to detect this attack?

---

## EXERCISE 2: Finding an IDOR Vulnerability

### Objective
Understand authorization failures by accessing another user's data.

### Prerequisites
- Burp Suite
- PortSwigger lab: https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references

### Steps

**Step 1: Understand the application**
```
1. Access the lab — it's a chat application
2. Click "Live chat" and send a message
3. Click "View transcript" to download your chat
4. Notice the downloaded file name: 2.txt (or similar number)
```

**Step 2: Analyze the request**
```
1. In Burp HTTP History, find the transcript download request
2. It probably looks like: GET /download-transcript/2.txt
3. The "2" is YOUR chat ID
```

**Step 3: Access another user's data**
```
1. Send this request to Repeater (Ctrl+R)
2. Change 2.txt to 1.txt
3. Send the request
4. You should see ANOTHER USER's chat transcript!
```

**Step 4: Find the sensitive data**
```
1. Read the transcript — it contains a password
2. Use those credentials to log in
3. Lab solved!
```

### Verification
- You can read chat transcripts from other users
- You found credentials in transcript 1.txt

### Write-up Prompt
1. What was the authorization flaw?
2. Why is using sequential IDs risky?
3. How would you fix this? (Hint: authorization checks, random IDs)
4. What would proper logging look like?

---

## EXERCISE 3: Setting Up Local Vulnerable App (Juice Shop)

### Objective
Set up OWASP Juice Shop locally for unlimited practice.

### Prerequisites
- Docker installed OR Node.js installed

### Steps (Docker method — recommended)

**Step 1: Install Docker Desktop**
```
1. Download from: https://www.docker.com/products/docker-desktop
2. Install and restart computer
3. Verify: docker --version
```

**Step 2: Run Juice Shop**
```bash
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop
```

**Step 3: Access and explore**
```
1. Open browser: http://localhost:3000
2. Register an account (use fake email)
3. Browse the store
4. Open DevTools (F12) → Network tab
5. Watch the API calls as you browse
```

### Steps (Node.js method — alternative)

```bash
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start
# Access at http://localhost:3000
```

### First Challenges to Try

**Challenge 1: Find the Score Board**
```
Hint: Look at the JavaScript files in DevTools
The scoreboard URL is hidden but referenced in the code
```

**Challenge 2: Access Admin Section**
```
1. Create a regular account
2. Try accessing: http://localhost:3000/#/administration
3. You'll get a 403 — but watch the network tab!
4. The data might be leaked even though the page is "blocked"
```

**Challenge 3: SQL Injection Login Bypass**
```
1. Go to login page
2. For email, enter: ' OR 1=1--
3. Password: anything
4. You'll be logged in as admin!
```

### Verification
- Juice Shop running on localhost:3000
- You can access the hidden score board
- You've found at least 3 vulnerabilities

### Write-up Prompt
- Document each vulnerability you find using the template
- Include screenshots
- Explain the fix for each one

---

## EXERCISE 4: Capture and Analyze Network Traffic

### Objective
Learn to use Wireshark to understand network protocols.

### Prerequisites
- Wireshark installed
- Admin/root access on your machine

### Steps

**Step 1: Capture HTTP traffic**
```
1. Open Wireshark
2. Select your network interface (usually "Ethernet" or "Wi-Fi")
3. Start capture (blue shark fin icon)
4. Open a browser and go to: http://httpbin.org/get
5. Stop capture (red square icon)
```

**Step 2: Filter and analyze**
```
1. Apply filter: http
2. Find your request (GET /get)
3. Click on it to see details
4. Expand "Hypertext Transfer Protocol" section
5. See the headers, method, path
```

**Step 3: Follow the stream**
```
1. Right-click on HTTP packet
2. Follow → TCP Stream
3. See the full request/response conversation
4. Note: Red = client (your request), Blue = server (response)
```

**Step 4: Compare HTTP vs HTTPS**
```
1. Start new capture
2. Visit: https://httpbin.org/get
3. Stop capture
4. Filter: tls
5. Notice you can't read the content — it's encrypted!
6. This is why HTTPS matters
```

### Verification
- You can capture packets
- You can read HTTP request/response content
- You understand why HTTPS content is unreadable

### Write-up Prompt
1. What HTTP headers did you see in the request?
2. What's the difference between HTTP and TLS packets in Wireshark?
3. Why is unencrypted HTTP dangerous?

---

## EXERCISE 5: Write a Security Log Parser (Python)

### Objective
Build a simple tool to analyze authentication logs.

### Prerequisites
- Python 3 installed
- Text editor or VS Code

### Steps

**Step 1: Create sample log file**

Create `sample_auth.log`:
```
2026-04-13 10:00:01 Failed password for admin from 192.168.1.100
2026-04-13 10:00:02 Failed password for admin from 192.168.1.100
2026-04-13 10:00:03 Failed password for admin from 192.168.1.100
2026-04-13 10:00:04 Accepted password for admin from 192.168.1.100
2026-04-13 10:00:10 Failed password for root from 10.0.0.50
2026-04-13 10:00:11 Failed password for root from 10.0.0.50
2026-04-13 10:00:15 Failed password for user1 from 192.168.1.100
2026-04-13 10:00:20 Accepted password for user2 from 172.16.0.1
2026-04-13 10:00:25 Failed password for admin from 10.0.0.50
2026-04-13 10:00:26 Failed password for admin from 10.0.0.50
2026-04-13 10:00:27 Failed password for admin from 10.0.0.50
2026-04-13 10:00:28 Failed password for admin from 10.0.0.50
2026-04-13 10:00:29 Failed password for admin from 10.0.0.50
```

**Step 2: Write the parser**

Create `log_analyzer.py`:
```python
#!/usr/bin/env python3
"""
Security Log Analyzer
Detects potential brute force attacks from auth logs
"""

import re
from collections import defaultdict
from datetime import datetime

def parse_log(filename):
    """Parse auth log and extract events."""
    events = []
    pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (Failed|Accepted) password for (\w+) from ([\d.]+)'
    
    with open(filename, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                timestamp, status, user, ip = match.groups()
                events.append({
                    'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'),
                    'status': status,
                    'user': user,
                    'ip': ip
                })
    return events

def analyze_events(events):
    """Analyze events for suspicious patterns."""
    
    # Count failures by IP
    failures_by_ip = defaultdict(int)
    # Count failures by user
    failures_by_user = defaultdict(int)
    # Track IPs per user
    ips_per_user = defaultdict(set)
    
    for event in events:
        if event['status'] == 'Failed':
            failures_by_ip[event['ip']] += 1
            failures_by_user[event['user']] += 1
        ips_per_user[event['user']].add(event['ip'])
    
    return {
        'failures_by_ip': dict(failures_by_ip),
        'failures_by_user': dict(failures_by_user),
        'ips_per_user': {k: list(v) for k, v in ips_per_user.items()}
    }

def detect_brute_force(analysis, threshold=5):
    """Detect potential brute force attempts."""
    alerts = []
    
    for ip, count in analysis['failures_by_ip'].items():
        if count >= threshold:
            alerts.append({
                'type': 'BRUTE_FORCE_IP',
                'severity': 'HIGH' if count >= 10 else 'MEDIUM',
                'ip': ip,
                'failure_count': count,
                'message': f"IP {ip} has {count} failed login attempts"
            })
    
    for user, count in analysis['failures_by_user'].items():
        if count >= threshold:
            alerts.append({
                'type': 'BRUTE_FORCE_USER',
                'severity': 'HIGH' if user in ['admin', 'root'] else 'MEDIUM',
                'user': user,
                'failure_count': count,
                'message': f"User '{user}' has {count} failed login attempts"
            })
    
    return alerts

def generate_report(events, analysis, alerts):
    """Generate a security report."""
    print("=" * 60)
    print("SECURITY LOG ANALYSIS REPORT")
    print("=" * 60)
    
    print(f"\nTotal events analyzed: {len(events)}")
    print(f"Failed logins: {sum(1 for e in events if e['status'] == 'Failed')}")
    print(f"Successful logins: {sum(1 for e in events if e['status'] == 'Accepted')}")
    
    print("\n--- FAILURES BY IP ---")
    for ip, count in sorted(analysis['failures_by_ip'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {ip}: {count} failures")
    
    print("\n--- FAILURES BY USER ---")
    for user, count in sorted(analysis['failures_by_user'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {user}: {count} failures")
    
    if alerts:
        print("\n" + "!" * 60)
        print("ALERTS")
        print("!" * 60)
        for alert in alerts:
            print(f"\n[{alert['severity']}] {alert['type']}")
            print(f"  {alert['message']}")
    else:
        print("\n✓ No alerts triggered")
    
    print("\n" + "=" * 60)

def main():
    # Parse the log file
    events = parse_log('sample_auth.log')
    
    # Analyze for patterns
    analysis = analyze_events(events)
    
    # Detect potential attacks
    alerts = detect_brute_force(analysis, threshold=3)
    
    # Generate report
    generate_report(events, analysis, alerts)

if __name__ == '__main__':
    main()
```

**Step 3: Run the analyzer**
```bash
python log_analyzer.py
```

**Step 4: Extend the script**

Add these features:
- Time-based analysis (failures within 1 minute)
- JSON output for SIEM ingestion
- Multiple users from same IP (password spraying)

### Verification
- Script runs without errors
- Detects the brute force patterns in sample data
- Generates readable report

### Write-up Prompt
1. What patterns indicate brute force vs password spraying?
2. What threshold would you use in production?
3. What other log fields would be useful?
4. How would you reduce false positives?

---

## EXERCISE 6: Build a Secure REST API Endpoint (Python)

### Objective
Learn secure coding by building an API with proper controls.

### Prerequisites
- Python 3
- pip install flask

### Steps

**Step 1: Create the INSECURE version first**

Create `insecure_api.py`:
```python
from flask import Flask, request, jsonify

app = Flask(__name__)

# Fake database
users = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "user"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.com", "role": "admin"},
}

# INSECURE: No authentication
# INSECURE: No authorization check
# INSECURE: Returns all fields including sensitive ones
@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    if user_id in users:
        return jsonify(users[user_id])
    return jsonify({"error": "Not found"}), 404

# INSECURE: No input validation
# INSECURE: Allows setting any field including role
@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    if user_id in users:
        data = request.get_json()
        users[user_id].update(data)  # DANGER: Mass assignment!
        return jsonify(users[user_id])
    return jsonify({"error": "Not found"}), 404

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

**Step 2: Test the vulnerabilities**

```bash
# Start the server
python insecure_api.py

# Test IDOR (access any user)
curl http://localhost:5000/api/users/1
curl http://localhost:5000/api/users/2

# Test Mass Assignment (escalate to admin!)
curl -X PUT http://localhost:5000/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

**Step 3: Now build the SECURE version**

Create `secure_api.py`:
```python
from flask import Flask, request, jsonify, g
from functools import wraps
import logging
import uuid
from datetime import datetime

app = Flask(__name__)

# Configure security logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
security_logger = logging.getLogger('security')

# Fake database
users = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "user"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.com", "role": "admin"},
}

# Fake tokens (in production, use JWT or session)
tokens = {
    "token_alice": {"user_id": 1, "role": "user"},
    "token_bob": {"user_id": 2, "role": "admin"},
}

# SECURE: Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            security_logger.warning(f"Missing auth header from {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}), 401
        
        token = auth_header.split(' ')[1]
        
        if token not in tokens:
            security_logger.warning(f"Invalid token attempt from {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}), 401
        
        g.current_user = tokens[token]
        g.request_id = str(uuid.uuid4())[:8]
        return f(*args, **kwargs)
    return decorated

# SECURE: Authorization check
def can_access_user(requester, target_user_id):
    # Users can only access their own data
    # Admins can access anyone
    if requester['role'] == 'admin':
        return True
    return requester['user_id'] == target_user_id

# SECURE: Response shaping - only return safe fields
def safe_user_response(user, include_email=False):
    response = {
        "id": user["id"],
        "name": user["name"],
    }
    if include_email:
        response["email"] = user["email"]
    # Never include: role, internal IDs, etc. unless needed
    return response

# SECURE: Input validation
ALLOWED_UPDATE_FIELDS = {"name", "email"}

def validate_update_data(data):
    if not isinstance(data, dict):
        return False, "Invalid data format"
    
    for key in data.keys():
        if key not in ALLOWED_UPDATE_FIELDS:
            return False, f"Field '{key}' cannot be updated"
    
    if "email" in data:
        # Basic email validation
        if "@" not in data["email"]:
            return False, "Invalid email format"
    
    return True, None

@app.route('/api/users/<int:user_id>')
@require_auth
def get_user(user_id):
    # Authorization check
    if not can_access_user(g.current_user, user_id):
        security_logger.warning(
            f"[{g.request_id}] User {g.current_user['user_id']} "
            f"attempted to access user {user_id} - DENIED"
        )
        return jsonify({"error": "Forbidden"}), 403
    
    if user_id not in users:
        return jsonify({"error": "Not found"}), 404
    
    # Log successful access
    security_logger.info(
        f"[{g.request_id}] User {g.current_user['user_id']} "
        f"accessed user {user_id} - ALLOWED"
    )
    
    # Return only safe fields, include email only for own profile
    include_email = (g.current_user['user_id'] == user_id)
    return jsonify(safe_user_response(users[user_id], include_email))

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    # Authorization: only update own profile
    if g.current_user['user_id'] != user_id:
        security_logger.warning(
            f"[{g.request_id}] User {g.current_user['user_id']} "
            f"attempted to update user {user_id} - DENIED"
        )
        return jsonify({"error": "Forbidden"}), 403
    
    if user_id not in users:
        return jsonify({"error": "Not found"}), 404
    
    data = request.get_json()
    
    # Validate input
    valid, error = validate_update_data(data)
    if not valid:
        security_logger.warning(
            f"[{g.request_id}] Invalid update data from user {user_id}: {error}"
        )
        return jsonify({"error": error}), 400
    
    # Safe update - only allowed fields
    for key in ALLOWED_UPDATE_FIELDS:
        if key in data:
            users[user_id][key] = data[key]
    
    security_logger.info(
        f"[{g.request_id}] User {user_id} updated their profile"
    )
    
    return jsonify(safe_user_response(users[user_id], include_email=True))

if __name__ == '__main__':
    app.run(debug=False, port=5000)  # debug=False in "production"
```

**Step 4: Test the secure version**

```bash
# Start secure server
python secure_api.py

# Test without auth (should fail)
curl http://localhost:5000/api/users/1
# Response: {"error": "Unauthorized"}

# Test with auth (Alice accessing her own data)
curl http://localhost:5000/api/users/1 \
  -H "Authorization: Bearer token_alice"
# Response: {"id": 1, "name": "Alice", "email": "alice@example.com"}

# Test IDOR (Alice accessing Bob - should fail)
curl http://localhost:5000/api/users/2 \
  -H "Authorization: Bearer token_alice"
# Response: {"error": "Forbidden"}

# Test Mass Assignment (should fail)
curl -X PUT http://localhost:5000/api/users/1 \
  -H "Authorization: Bearer token_alice" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
# Response: {"error": "Field 'role' cannot be updated"}
```

### Verification
- Insecure version has IDOR and mass assignment
- Secure version blocks both attacks
- Security logs show access attempts

### Write-up Prompt
1. What security controls did you add?
2. What's the difference between authentication and authorization in your code?
3. What else would you add for production? (rate limiting, input length limits, etc.)
4. How do the logs help with incident response?

---

## EXERCISE 7: Cloud IAM Policy Analysis

### Objective
Learn to read and assess cloud IAM policies for security issues.

### Prerequisites
- AWS free tier account OR just use the examples below

### Steps

**Step 1: Analyze this overly permissive policy**

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "TooPermissive",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
}
```

Questions:
- What can someone with this policy do?
- Why is this dangerous?
- What's the minimum they probably actually need?

**Step 2: Analyze this slightly better (but still bad) policy**

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:*"
            ],
            "Resource": "*"
        }
    ]
}
```

Issues to identify:
- Can access ALL S3 buckets (not just their own)
- Can delete buckets, not just read
- Can make buckets public
- Can read other teams' sensitive data

**Step 3: Write a least-privilege version**

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ReadOwnAppBucket",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::my-app-bucket",
                "arn:aws:s3:::my-app-bucket/*"
            ]
        }
    ]
}
```

**Step 4: Find the vulnerability in this policy**

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateAccessKey",
                "iam:CreateUser"
            ],
            "Resource": "*"
        }
    ]
}
```

Answer: This is a privilege escalation path! User can:
1. Create a new IAM user
2. Create access keys for that user
3. Attach admin policy to that user
4. Use those keys to become admin

### Verification
- You can identify overly permissive policies
- You can write least-privilege alternatives
- You can spot privilege escalation paths

### Write-up Prompt
1. What questions do you ask when reviewing an IAM policy?
2. What are the "dangerous" IAM actions to watch for?
3. How would you detect IAM policy changes?

---

## Next Steps

After completing these exercises:

1. ✅ Complete at least 10 PortSwigger labs
2. ✅ Solve 5+ Juice Shop challenges
3. ✅ Build 2 Python security tools
4. ✅ Write a full threat model for one of your own apps
5. ✅ Create a portfolio repo with all your write-ups

**Remember: Quality of write-ups > Quantity of labs completed** 📝


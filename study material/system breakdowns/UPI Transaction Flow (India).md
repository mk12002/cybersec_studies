# UPI Transaction Flow (India) — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** All Engineers (Beginner to Senior), Security Engineers, Systems Architects  
**Scope:** Complete breakdown of how a UPI payment flows from a user tapping "Pay" to money leaving one bank and arriving in another  
**Regulatory context:** RBI (Reserve Bank of India), NPCI (National Payments Corporation of India), PCI DSS

---

## A Plain-English Introduction Before We Begin

**What is UPI?**  
UPI (Unified Payments Interface) is India's real-time payment system. It lets you send money from your bank account to someone else's bank account in under 10 seconds using just a phone number or a UPI ID (like `rahul@okhdfcbank`). It processed over 13 billion transactions per month as of 2024.

**Who built it?**  
NPCI (National Payments Corporation of India) — a non-profit umbrella organization owned by Indian banks and mandated by RBI. NPCI built and operates the central routing infrastructure (called UPI Switch).

**Key players in every transaction:**
- **User (Payer):** Person sending money
- **PSP (Payment Service Provider):** The app the user is using — PhonePe, GPay, Paytm, BHIM, etc.
- **Payer's Bank (Issuer):** Where the payer's money currently lives (e.g., HDFC Bank)
- **NPCI UPI Switch:** Central router that connects all banks
- **Payee's Bank (Acquirer):** Where the money needs to go (e.g., SBI)
- **Payee:** Person receiving money

**The magic of UPI:** Before UPI, sending money required knowing someone's full bank account number and IFSC code. UPI abstracts this into a simple "address" (`name@bankhandle`) and lets transfers happen in real-time, 24x7, including holidays.

---

## Table of Contents

1. [User Journey (Narrative)](#1-user-journey-narrative)
2. [Network Layer Flow](#2-network-layer-flow)
3. [Application Layer Flow](#3-application-layer-flow)
4. [Backend Architecture](#4-backend-architecture)
5. [Authentication & Authorization Flow](#5-authentication--authorization-flow)
6. [Data Flow](#6-data-flow)
7. [Security Controls](#7-security-controls)
8. [Attack Surface Mapping](#8-attack-surface-mapping)
9. [Attack Scenarios (Very Detailed)](#9-attack-scenarios-very-detailed)
10. [Failure Points](#10-failure-points)
11. [Mitigations](#11-mitigations)
12. [Observability](#12-observability)
13. [Scaling Considerations](#13-scaling-considerations)
14. [Interview Questions](#14-interview-questions)

---

## 1. User Journey (Narrative)

### Setting the Scene

Rahul (payer) wants to pay ₹500 to Priya (payee) using PhonePe on his Android phone. Rahul's bank is HDFC. Priya's UPI ID is `priya@oksbi` (her bank is SBI).

---

### Phase 1: The App Opens (T-∞ to T+0)

Before Rahul even thinks about paying, PhonePe has already:
- Registered with NPCI as a licensed PSP (Payment Service Provider)
- Been issued a unique PSP ID
- Established a secure VPN/leased line tunnel to NPCI's servers (not regular internet — dedicated connectivity)
- Pulled Rahul's device fingerprint, stored it encrypted locally

Rahul opens PhonePe. **What the user sees:** A home screen with a search bar and "Pay" button.

**What actually happens:**
- App checks if the session token (issued at last login) is still valid
- App re-validates the device binding (is this still the same phone?)
- App checks for pending failed transactions from previous sessions
- App pulls notification data (pending collect requests, etc.)

---

### Phase 2: Initiating the Payment (T+0 to T+0.5s)

Rahul types `priya@oksbi` in the "Pay" field and enters ₹500.

**What the user sees:** A simple text field and an amount input.

**What actually happens:**

**Step 1: VPA Resolution (Virtual Payment Address lookup)**

PhonePe's app sends a request to PhonePe's backend:
```
POST /upi/vpa/resolve
Body: {vpa: "priya@oksbi", requester_vpa: "rahul@okhdfcbank"}
```

PhonePe's backend forwards this to NPCI's UPI Switch as a `ReqValAdd` (Request Validate Address) message.

NPCI's switch looks up which bank handles the `@oksbi` handle — that's SBI (State Bank of India). NPCI routes the validation request to SBI's UPI server.

SBI confirms: "Yes, `priya@oksbi` maps to account number XXXX0001234 at SBI branch IFSC SBIN0000001, account holder name: Priya Sharma."

NPCI returns this to PhonePe. PhonePe shows Rahul: **"Priya Sharma | SBI"** — the name and bank confirm Priya is the right person.

**Timing:** This VPA resolution takes ~200–800ms.

---

### Phase 3: UPI PIN Entry (T+0.5s to T+3s)

Rahul sees: "Paying ₹500 to Priya Sharma. Enter UPI PIN to confirm."

**What the user sees:** A numeric keypad, hidden by the UPI SDK — not inside PhonePe's code, but inside a system-level secure overlay.

**What actually happens:**

This is the most security-critical step. The UPI PIN entry does NOT happen inside the PhonePe app. It happens inside NPCI's device SDK (or bank's SDK), which runs in a **separate process** with elevated OS permissions. Here's why:

- PhonePe's app cannot read what the user types into this keypad
- The PIN is encrypted ON-DEVICE before ever being sent anywhere
- The encrypted PIN is sent directly to the bank, not to PhonePe

**PIN encryption mechanism:**
1. The bank's UPI server has a public key registered with NPCI
2. When the PIN keypad loads, the app fetches a session-specific challenge from the bank
3. User types PIN: `1234`
4. On-device: `ENCRYPTED_PIN = RSA_ENCRYPT(PIN, Bank_Public_Key) XOR SESSION_CHALLENGE`
5. This encrypted blob travels to the bank
6. Only the bank's HSM (Hardware Security Module) can decrypt it with the corresponding private key

No intermediary — not PhonePe, not NPCI — can see the raw PIN. Ever.

---

### Phase 4: The Transaction Flow (T+3s to T+8s)

User hits "Pay." Now the real action begins.

**Step 1: Payer PSP (PhonePe) → NPCI**

PhonePe sends a `ReqPay` (Request Pay) message to NPCI:
```json
{
  "msgId": "PhonePe20241115103045001",
  "type": "PAY",
  "payerVPA": "rahul@okhdfcbank",
  "payeeVPA": "priya@oksbi",
  "amount": "500.00",
  "currency": "INR",
  "note": "Coffee",
  "encryptedUPIPin": "BASE64_ENCRYPTED_BLOB",
  "deviceFingerprint": "HASH_OF_DEVICE_PARAMS",
  "timestamp": "2024-11-15T10:30:45.123Z"
}
```

**Step 2: NPCI → Payer's Bank (HDFC)**

NPCI routes this to HDFC's UPI server (called the Issuer Bank). HDFC receives the debit request:
- Decrypt PIN using HSM
- Verify PIN is correct
- Check account balance: Does Rahul have ₹500?
- Check daily transaction limits: Has Rahul exceeded ₹1 lakh/day?
- Fraud checks: Is this transaction pattern suspicious?
- Debit the account: Move ₹500 from Rahul's account

HDFC responds: "Debit of ₹500 successful. Debit reference: HDFC20241115103046789"

**Step 3: NPCI → Payee's Bank (SBI)**

NPCI now sends a credit request to SBI's UPI server:
- Credit Priya's account with ₹500
- SBI responds: "Credit successful. Credit reference: SBI20241115103047456"

**Step 4: NPCI settles and notifies**

NPCI records the transaction as complete and sends success responses back up the chain:
- SBI is notified: "Credit confirmed"
- HDFC is notified: "Debit confirmed, credit done"
- PhonePe is notified: "Transaction Successful"
- PhonePe shows Rahul: "₹500 paid to Priya Sharma ✓"

**Timing breakdown:**
```
VPA Resolution:     200-800ms
PIN Entry (user):   1-5 seconds (human time)
NPCI Processing:    50-200ms
HDFC Debit:         100-500ms
SBI Credit:         100-500ms
NPCI Settlement:    50-100ms
Total (excl PIN):   500ms - 2 seconds
```

---

### Phase 5: Settlement (T+30s to next business day)

What just happened is called **"real-time gross settlement authorization."** The money appears to move instantly from Rahul's perspective, but the actual interbank transfer (moving money between HDFC's account at RBI and SBI's account at RBI) happens in batch settlement cycles.

NPCI runs settlement cycles multiple times per day. At each cycle:
- All transactions between banks are netted (e.g., if HDFC owes SBI ₹1 crore and SBI owes HDFC ₹60 lakh, the net transfer is ₹40 lakh from HDFC to SBI at RBI)
- The net amounts are transferred via RBI's RTGS system

The user never sees this. From Rahul's and Priya's perspective, the money moved instantly.

---

## 2. Network Layer Flow

### Understanding the Network Topology

**First, a critical point for beginners:** UPI does NOT use regular internet connections between banks and NPCI. Banks connect to NPCI via:
- Dedicated leased lines
- MPLS (Multiprotocol Label Switching) private circuits
- Or through NPCI's certified network service providers

This is different from your home internet. These are private, dedicated circuits that only carry UPI traffic. Think of it like a private highway versus a public road.

**The internet IS used for:**
- User's phone to PSP (PhonePe/GPay) servers
- PSP servers to NPCI (also via dedicated links or secured VPN over internet)

---

### DNS Resolution for the User-Facing Layer

When Rahul's PhonePe app contacts PhonePe's servers:

```
Rahul's Phone
    |
    | [Step 1: DNS Query]
    |
    v
Phone's configured DNS (e.g., 8.8.8.8 or carrier DNS)
    |
    | Query: "api.phonepe.com → what IP?"
    v
Recursive Resolver (ISP / Google / Cloudflare)
    |
    | Doesn't know → asks root nameservers
    v
Root Nameserver (.)
    |
    | "Ask .com nameservers"
    v
.com TLD Nameserver
    |
    | "Ask PhonePe's nameserver: ns1.phonepe.com"
    v
PhonePe's Authoritative Nameserver (ns1.phonepe.com)
    |
    | Returns: A record → 103.195.201.42 (example IP)
    | TTL: 300 seconds (5 minutes)
    v
Recursive Resolver caches this for 5 minutes
    |
    v
Rahul's Phone gets: "api.phonepe.com = 103.195.201.42"
```

**What is TTL (Time To Live)?** It's how long the answer is cached. PhonePe uses a short TTL (300s = 5 minutes) so if they need to switch traffic to a different data center, phones pick up the new IP within 5 minutes.

**DNS Failure mode:** If PhonePe's nameserver is down, DNS fails, and the app can't connect. This is why production systems have multiple nameservers and often use anycast DNS (the same IP is advertised from multiple locations worldwide, and users automatically connect to the nearest one).

---

### TCP 3-Way Handshake

Once Rahul's phone has the IP (103.195.201.42), it needs to establish a connection:

```
Rahul's Phone                              PhonePe Server
(IP: 49.36.xx.yy)                         (IP: 103.195.201.42)
        |                                          |
        |  SYN [seq=100, "I want to connect"]     |
        | ---------------------------------------->|
        |                                          |
        |  SYN-ACK [seq=500, ack=101,             |
        |            "OK, let's connect"]          |
        | <----------------------------------------|
        |                                          |
        |  ACK [ack=501, "Got it, let's go"]       |
        | ---------------------------------------->|
        |                                          |
        |  [Connection established]                 |
        |  [Now TLS handshake begins]              |
```

**For complete beginners:** Think of SYN-ACK like a handshake:
- SYN = "Hi, can we talk?" (you extend your hand)
- SYN-ACK = "Yes, let's talk!" (other person grabs your hand)
- ACK = "Great!" (you complete the handshake)

**Timing:** This takes 1 RTT (Round Trip Time). On a 4G mobile connection in India, RTT is typically 30-80ms. So the TCP handshake adds 30-80ms to every new connection.

**HTTP/2 multiplexing:** PhonePe's app uses HTTP/2, which reuses a single TCP connection for multiple requests. So the VPA resolution and payment initiation don't each need their own TCP connection — they share one, amortizing the handshake cost.

---

### TLS Handshake

After TCP, TLS (Transport Layer Security) creates an encrypted channel:

```
Rahul's Phone                              PhonePe Server
        |                                          |
        |  ClientHello                             |
        |  "I support TLS 1.3"                    |
        |  "Here's my random number (nonce)"       |
        |  "I support these cipher suites:"        |
        |  "TLS_AES_256_GCM_SHA384"                |
        |  "TLS_CHACHA20_POLY1305_SHA256"          |
        | ---------------------------------------->|
        |                                          |
        |  ServerHello                             |
        |  "Let's use TLS_AES_256_GCM_SHA384"     |
        |  "Here's my certificate (signed by CA)" |
        |  "Here's my nonce"                       |
        |  "Here's my Diffie-Hellman public key"  |
        |  {Encrypted extensions}                  |
        |  {Certificate Verify: proves I own key} |
        |  {Finished}                              |
        | <----------------------------------------|
        |                                          |
        |  [Phone verifies: is cert valid?         |
        |   Is it signed by a trusted CA?          |
        |   Does hostname match?]                  |
        |                                          |
        |  {Finished}                              |
        |  [Application data can now flow]         |
        | ---------------------------------------->|
```

**What is AES-256-GCM?** It's the encryption algorithm. AES-256 means the key is 256 bits long (so strong that breaking it would take longer than the age of the universe). GCM means Galois/Counter Mode — it both encrypts AND verifies integrity (so an attacker can't tamper with data without it being detected).

**What is a Certificate?** Think of it as a digital ID card:
- It says "I am api.phonepe.com"
- It's signed by a Certificate Authority (CA) — like DigiCert or Let's Encrypt — which acts like a government notary
- Your phone has a list of trusted CAs pre-installed
- If the certificate is signed by one of these trusted CAs AND matches the hostname, the phone trusts the connection

**TLS 1.3 vs 1.2:** TLS 1.3 (used by all modern apps including PhonePe) is faster (1 round-trip instead of 2) and more secure (removes weak algorithms that TLS 1.2 still supports).

**After TLS:** All data is encrypted. If Airtel (Rahul's mobile carrier) tries to read his payment data, they see only gibberish.

---

### The Internal Network: Bank ↔ NPCI

The PhonePe-to-NPCI and bank-to-NPCI links use different security mechanisms:

```
PhonePe Data Center                        NPCI Data Center
+------------------+                       +----------------+
|  PhonePe UPI     |  Leased Line /        |  UPI Switch    |
|  Application     |  MPLS VPN / IPsec     |  (NPCI Core)   |
|  Server          | ===================== |                |
+------------------+  Dedicated Private    +----------------+
                       Circuit                     |
                                                   | Internal Private Network
                       HDFC Data Center            |
                       +------------------+        |
                       |  HDFC UPI Server |========|
                       |  + HSM           |        |
                       +------------------+        |
                                                   |
                       SBI Data Center             |
                       +------------------+        |
                       |  SBI UPI Server  |========|
                       |  + HSM           |
                       +------------------+
```

**HSM (Hardware Security Module):** A specialized, tamper-proof hardware device that stores cryptographic keys and performs encryption/decryption. If someone physically tries to break into an HSM, it self-destructs its keys. Banks use HSMs specifically for PIN handling — the PIN is never in software/memory in plaintext. Ever.

---

### Full Network Flow — ASCII Diagram

```
RAHUL'S PHONE                    PSP (PhonePe)              NPCI SWITCH        HDFC (Payer Bank)    SBI (Payee Bank)
       |                              |                           |                      |                    |
  [Open App]                          |                           |                      |                    |
       |                              |                           |                      |                    |
  DNS: api.phonepe.com                |                           |                      |                    |
  -->[DNS Resolver]---> IP            |                           |                      |                    |
       |                              |                           |                      |                    |
  TCP SYN/SYN-ACK/ACK ─────────────> |                           |                      |                    |
  TLS ClientHello/ServerHello ──────> |                           |                      |                    |
  [Encrypted channel established]     |                           |                      |                    |
       |                              |                           |                      |                    |
  POST /upi/vpa/resolve               |                           |                      |                    |
  {vpa: "priya@oksbi"} ─────────────> |                           |                      |                    |
       |                              | ReqValAdd ───────────────>|                      |                    |
       |                              |                           |──ValAdd──────────────────────────────────>|
       |                              |                           |<──RespValAdd─────────────────────────────|
       |                              |<── RespValAdd ────────────|                      |                    |
  <── "Priya Sharma | SBI" ───────── |                           |                      |                    |
       |                              |                           |                      |                    |
  [User types PIN in secure overlay]  |                           |                      |                    |
  [PIN encrypted on-device with bank public key]                  |                      |                    |
       |                              |                           |                      |                    |
  POST /upi/pay                       |                           |                      |                    |
  {payerVPA, payeeVPA, amt,           |                           |                      |                    |
   encryptedPIN, deviceFP} ─────────>|                           |                      |                    |
       |                              | ReqPay ──────────────────>|                      |                    |
       |                              |                           |──Debit Req ─────────>|                    |
       |                              |                           |   [HSM decrypts PIN] |                    |
       |                              |                           |   [Balance check]    |                    |
       |                              |                           |   [Fraud check]      |                    |
       |                              |                           |   [Debit ₹500]       |                    |
       |                              |                           |<──Debit OK ──────────|                    |
       |                              |                           |──Credit Req ────────────────────────────>|
       |                              |                           |   [Credit ₹500]      |                    |
       |                              |                           |<──Credit OK ─────────────────────────────|
       |                              |                           |                      |                    |
       |                              |<── RespPay SUCCESS ───────|                      |                    |
  <── "Payment Successful ✓" ──────── |                           |                      |                    |
       |                              |                           |                      |                    |
  [Priya gets notification]          |                           |                      |                    |
  [on her phone via SBI/GPay]        |                           |                      |──Push notification─>|
                                                                                         (Priya's PSP notifies her)
```

### Where Latency Occurs

| Step | Typical Latency | Common Failure |
|---|---|---|
| DNS resolution | 10–50ms | DNS server overloaded |
| TCP handshake (phone to PSP) | 30–80ms (4G RTT) | Network congestion |
| TLS handshake | 30–80ms | Certificate validation issues |
| VPA resolution (NPCI roundtrip) | 200–800ms | NPCI overloaded |
| HDFC debit processing | 100–500ms | HDFC server overloaded |
| SBI credit processing | 100–500ms | SBI server unavailable |
| **Total (excluding PIN entry)** | **500ms–2s** | Various |

---

## 3. Application Layer Flow

### The UPI API Message Format

UPI uses a specific message format based on ISO 20022 financial messaging standards, wrapped in XML. Let's look at what an actual payment request looks like at different layers.

**Layer 1: What PhonePe app sends to PhonePe servers (HTTPS/JSON):**

```http
POST /api/v2/upi/pay HTTP/2
Host: api.phonepe.com
Content-Type: application/json
Authorization: Bearer eyJhbGci...
X-Request-ID: txn-20241115-abc123
X-Device-ID: sha256-device-fingerprint-hash
X-App-Version: 4.1.2

{
  "merchantId": "PHONEPE_SELF",
  "transactionId": "TXN2024111503045001",
  "amount": 50000,
  "currency": "INR",
  "payerVPA": "rahul@okhdfcbank",
  "payeeVPA": "priya@oksbi",
  "payeeType": "PERSON",
  "remarks": "Coffee",
  "encryptedUPIBlock": "BASE64_ENCODED_ENCRYPTED_BLOB",
  "deviceFingerprint": "3d4e5f..."
}
```

**Note on amount:** UPI amounts are always in paise (1/100th of a rupee). So ₹500 = 50000 paise. This avoids floating point arithmetic errors — a very important design decision. Never use floating point for money.

---

**Layer 2: What PhonePe servers send to NPCI (HTTPS/XML over TLS):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<upi:ReqPay xmlns:upi="http://www.npci.org.in/upi/schema/">
  <Head
    ver="2.0"
    ts="2024-11-15T10:30:45.123+05:30"
    orgId="PHONEPE"
    msgId="PhonePe20241115103045001"
  />
  <Txn
    id="TXN2024111503045001"
    type="PAY"
    refId="PhonePe20241115103045001"
    refUrl="https://phonepe.com"
    note="Coffee"
    initChannel="USRAPP"
    payType="PERSON"
    ts="2024-11-15T10:30:45.123+05:30"
  />
  <Payer
    addr="rahul@okhdfcbank"
    seqNum="1"
    type="PERSON"
    code="HDFC"
  >
    <Device>
      <Tag name="MOBILE" value="9876543210"/>
      <Tag name="GEOCODE" value="19.0760,72.8777"/>
      <Tag name="IMEI" value="HASH_OF_IMEI"/>
      <Tag name="OS" value="ANDROID_14"/>
      <Tag name="CAPABILITY" value="100"/>
    </Device>
    <Amount value="500.00" curr="INR"/>
    <Creds>
      <Cred type="PIN" subType="MPIN">
        <Data code="NPCI" ki="HDFC0000001" encryptedBase64="BASE64_ENCRYPTED_PIN_BLOCK"/>
      </Cred>
    </Creds>
  </Payer>
  <Payees>
    <Payee
      addr="priya@oksbi"
      seqNum="2"
      type="PERSON"
      code="SBI"
      name="Priya Sharma"
    >
      <Amount value="500.00" curr="INR"/>
    </Payee>
  </Payees>
</upi:ReqPay>
```

**Why XML?** Financial messaging has historically used XML because it's self-describing, extensible, and has strong schema validation. NPCI's UPI protocol was designed to interoperate with existing banking systems that already use XML. Modern systems often add a JSON wrapper on top, but the core financial messages remain XML.

---

**Layer 3: NPCI to Bank — ISO 8583 or proprietary format**

The actual bank-to-NPCI communication often uses ISO 8583 (a financial messaging standard) or proprietary XML defined by NPCI. For UPI specifically, it's NPCI's defined XML schema transmitted over TLS.

---

### HTTP Request Lifecycle — Detailed

**On the user-facing layer (Phone → PhonePe):**

1. **Request built by PhonePe app:**
   - JWT token retrieved from secure storage
   - Request body encrypted (application-level encryption on top of TLS)
   - Request signed with device private key
   - HTTP/2 HEADERS frame sent

2. **nginx (PhonePe's load balancer) receives:**
   - Validates TLS certificate (mutual TLS if required)
   - Routes to appropriate API server based on path
   - Adds `X-Real-IP` and `X-Forwarded-For` headers
   - Rate limiting check (per device, per user)

3. **PhonePe API server parses:**
   ```python
   def parse_payment_request(request):
       # JWT validation
       claims = validate_jwt(request.headers['Authorization'])
       user_id = claims['sub']

       # Body parsing
       body = json.loads(request.body)

       # Input validation
       validate_vpa_format(body['payerVPA'])   # must match pattern
       validate_vpa_format(body['payeeVPA'])
       validate_amount(body['amount'])         # positive integer, within limits
       validate_currency(body['currency'])     # must be "INR"

       # Device validation
       validate_device_fingerprint(
           body['deviceFingerprint'],
           user_id,
           request.headers['X-Device-ID']
       )

       return validated_payment_request
   ```

4. **PhonePe constructs UPI XML** and sends to NPCI via their dedicated link.

---

### Parameter Parsing — Security Critical Points

**VPA (Virtual Payment Address) format:**
```
Format: localpart@bankhandle
Example: rahul@okhdfcbank
         priya@oksbi
         merchant.store123@icici

Validation:
- localpart: alphanumeric + dots + hyphens, 3-50 chars
- @ separator: exactly one
- bankhandle: registered with NPCI, max 50 chars
- Total length: max 100 characters
```

**Why strict VPA validation matters:** If VPA format is not validated, an attacker could inject values that cause downstream XML injection in the NPCI message, or cause unexpected routing behavior.

**Amount validation:**
```python
def validate_amount(amount):
    # Must be integer (paise)
    assert isinstance(amount, int)
    # Must be positive
    assert amount > 0
    # Per-transaction limit: ₹1 lakh = 100,000 rupees = 10,000,000 paise
    assert amount <= 10_000_000
    # Must not be zero
    assert amount >= 100  # minimum ₹1
```

---

### Response Construction

**Success response (PhonePe → User app):**
```json
{
  "code": "SUCCESS",
  "message": "Transaction Successful",
  "data": {
    "merchantTransactionId": "TXN2024111503045001",
    "transactionId": "NPCI20241115103048001",
    "amount": 50000,
    "state": "COMPLETED",
    "responseCode": "00",
    "paymentInstrument": {
      "type": "UPI",
      "utr": "411522987654"
    }
  }
}
```

**UTR (Unique Transaction Reference):** Every UPI transaction gets a UTR number. This is the equivalent of a bank reference number and is used for disputes, reconciliation, and customer support. It's 12 digits and universally unique across all UPI transactions.

**Failure response:**
```json
{
  "code": "PAYMENT_ERROR",
  "message": "Transaction Failed",
  "data": {
    "merchantTransactionId": "TXN2024111503045001",
    "transactionId": "NPCI20241115103048001",
    "state": "FAILED",
    "responseCode": "U30",
    "responseCodeDescription": "Debit Failed - Insufficient Balance"
  }
}
```

**Common UPI response codes:**
- `00` → Success
- `U02` → VPA not found
- `U30` → Insufficient balance
- `U69` → Transaction limit exceeded
- `RB` → Reverted / Reversed
- `Z9` → Payee's bank unavailable
- `U16` → Risk threshold exceeded (fraud suspected)

---

## 4. Backend Architecture

### The Three-Layer Architecture

```
Layer 1: User-Facing (Rahul's Phone → PSP)
+------------------------------------------+
|  PhonePe's Infrastructure                |
|  - Load balancers (nginx/HAProxy)         |
|  - API Servers (payment service)          |
|  - Session service                        |
|  - Device fingerprint service             |
|  - Rate limiting (Redis-based)            |
|  - Idempotency service                    |
+------------------------------------------+
              |
              | (Private leased line / VPN)
              |
Layer 2: NPCI UPI Switch
+------------------------------------------+
|  NPCI Core Infrastructure                |
|  - VPA routing table (maps handle → bank)|
|  - Transaction router                    |
|  - Fraud scoring engine                  |
|  - Audit log (immutable ledger)          |
|  - Settlement engine                     |
|  - Notification dispatcher               |
+------------------------------------------+
              |
              | (Private MPLS circuits)
              |
Layer 3: Bank Infrastructure
+------------------------------------------+
|  Each Bank's CBS (Core Banking System)   |
|  - UPI adapter (speaks NPCI protocol)    |
|  - Core banking system (account records) |
|  - HSM (PIN decryption)                  |
|  - Fraud engine                          |
|  - Real-time notifications               |
+------------------------------------------+
```

---

### NPCI UPI Switch — The Heart of the System

The UPI Switch is the central brain. Let's understand each component:

**VPA Routing Table:**
A lookup table that maps bank handles to bank systems:
```
@okhdfcbank  → HDFC Bank UPI Server (IP: 10.x.x.x, Port: 8443)
@oksbi       → SBI UPI Server (IP: 10.y.y.y, Port: 8443)
@paytm       → Paytm Payments Bank UPI Server
@upi         → NPCI direct (used for BHIM app)
...and ~100 more handles
```

This table has ~300,000+ VPA registrations updated in real-time as users link bank accounts.

**Transaction Router:**
- Receives `ReqPay` from PSP
- Looks up payer's bank from payer VPA
- Looks up payee's bank from payee VPA
- Routes debit to payer's bank
- On debit success, routes credit to payee's bank
- Manages timeouts: if bank doesn't respond in 30 seconds, marks as pending

**Fraud Scoring Engine (Integrated at NPCI):**
- Velocity checks: is Rahul trying to send more than normal?
- Network graph: are transactions forming unusual patterns?
- Device risk: is this a known fraudulent device?
- Returns a risk score that can BLOCK or FLAG a transaction

---

### Synchronous vs Asynchronous Flows

**Synchronous (user is waiting for these):**
- VPA resolution (must complete before user can proceed)
- PIN validation (must complete in real-time)
- Debit authorization (must happen before declaring success)
- Credit confirmation (must happen before showing "success")

**Asynchronous (happens after user sees result):**
- Settlement netting (batch, multiple times per day)
- Dispute processing
- Fraud analysis (ML models running on transaction patterns)
- Notification delivery (SMS/push notification to payee)
- Reconciliation reports to banks
- Transaction MIS (Management Information System) reporting to RBI

---

### Database Architecture

**At PhonePe (PSP level):**

```sql
-- Transaction master table
CREATE TABLE upi_transactions (
  id UUID PRIMARY KEY,
  txn_id VARCHAR(50) UNIQUE NOT NULL,  -- PhonePe's internal ID
  npci_txn_id VARCHAR(50),             -- NPCI's assigned ID
  utr VARCHAR(20) UNIQUE,              -- UTR after success
  payer_vpa VARCHAR(100) NOT NULL,
  payee_vpa VARCHAR(100) NOT NULL,
  amount_paise BIGINT NOT NULL,        -- Always store in paise
  currency CHAR(3) DEFAULT 'INR',
  status VARCHAR(20) NOT NULL,         -- PENDING, SUCCESS, FAILED, TIMEOUT
  initiated_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  failure_reason VARCHAR(200),
  response_code VARCHAR(10),
  device_fingerprint_hash VARCHAR(64), -- SHA-256 hash, never raw
  is_idempotent BOOLEAN DEFAULT FALSE, -- Was this a retry?
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Immutable audit log
CREATE TABLE transaction_events (
  id BIGSERIAL PRIMARY KEY,
  txn_id VARCHAR(50) NOT NULL,
  event_type VARCHAR(50) NOT NULL,   -- INITIATED, NPCI_SENT, DEBIT_SUCCESS, etc.
  event_data JSONB,
  happened_at TIMESTAMPTZ DEFAULT NOW()
);
-- This table never has UPDATEs or DELETEs -- append-only
```

**At NPCI (Switch level):**
NPCI maintains a distributed ledger of all transactions with full details for audit, dispute, and settlement purposes. Specifics are not public, but it involves:
- Distributed transaction log (consistent, replicated across multiple data centers)
- Real-time balance ledger for settlement netting
- Audit records retained for 8 years (RBI mandate)

---

### Caching Strategy

**PhonePe's Redis cache:**

```
Cache 1: VPA Resolution Cache
  Key: "vpa_cache:{vpa}"
  Value: {name, bank, account_type, is_active}
  TTL: 60 seconds (short — VPAs can change)
  Purpose: Avoid hitting NPCI for every VPA lookup

Cache 2: Session Token Cache
  Key: "session:{user_id}:{device_id}"
  Value: {jwt_claims, device_binding, last_activity}
  TTL: 1 hour (sliding)
  Purpose: Validate session without hitting DB

Cache 3: Daily Limit Tracker
  Key: "daily_limit:{user_id}:{date}"
  Value: {amount_sent, txn_count}
  TTL: 24 hours
  Purpose: Enforce per-user daily limits in real-time

Cache 4: Idempotency Store
  Key: "idem:{txn_id}"
  Value: {status, response}
  TTL: 24 hours
  Purpose: Return same response on retry without re-processing
```

**Why Redis for idempotency?** If Rahul's app retries a payment (network glitch), we must not charge him twice. We store the first transaction's result in Redis. On retry with the same `txn_id`, we return the cached result instantly. The TTL ensures stale keys are cleaned up.

---

## 5. Authentication & Authorization Flow

### The Multi-Layer Authentication Model

UPI has one of the most sophisticated authentication chains in consumer finance. Let me explain each layer:

```
Layer 1: App Authentication (device + user)
  What: "Is this request coming from a legitimate PhonePe installation on a known device?"
  How: Device binding, app signature verification

Layer 2: User Authentication (session)
  What: "Is this request from the actual account owner?"
  How: JWT session token (from login with OTP/password)

Layer 3: Bank Authentication (UPI PIN)
  What: "Does the account holder authorize this specific transaction?"
  How: UPI PIN, encrypted on-device with bank's public key

Layer 4: Device Binding Verification
  What: "Is the UPI-linked SIM card present in this phone?"
  How: Device fingerprint verification (IMEI, SIM, app signature)
```

---

### Device Registration Flow (One-time, at UPI Setup)

Before Rahul can ever use UPI, he goes through a one-time registration:

```
1. Rahul installs PhonePe
2. Enters mobile number: 9876543210
3. PhonePe sends OTP to 9876543210 (SMS)
4. Rahul enters OTP → PhonePe verifies
5. PhonePe reads SIM details silently (to confirm SIM is in phone)
6. PhonePe generates a unique Device Fingerprint:
   DeviceFP = HASH(IMEI + SIM_Serial + App_Signature + Android_ID)
7. PhonePe sends registration request to NPCI:
   {mobile: "9876543210", device_fp: "...", psp: "PHONEPE"}
8. NPCI registers this mobile-device-PSP combination
9. Rahul selects his bank: HDFC
10. PhonePe calls HDFC: "Link this mobile to UPI"
11. HDFC verifies Rahul has an account with this mobile
12. HDFC issues a "VPA": rahul@okhdfcbank
13. HDFC sends its public key to Rahul's phone (for PIN encryption)
14. Rahul sets UPI PIN (encrypted immediately, sent to HDFC, stored in HSM)
15. DONE — Rahul can now make UPI payments
```

**The crucial security property:** After step 13, HDFC's public key is stored in the PhonePe app. When Rahul enters his PIN later, it's encrypted using this public key ON THE DEVICE, before the data ever leaves the phone. PhonePe cannot see the raw PIN. NPCI cannot see it. Only HDFC's HSM can decrypt it.

---

### JWT (Session Token) Flow

When Rahul logs into PhonePe:

```python
# At login (after OTP verification):
jwt_payload = {
    "sub": "user_id_abc123",         # User identifier
    "device_id": "device_fp_hash",  # Which device
    "iss": "phonepe.com",            # Issuer
    "iat": 1700000000,               # Issued at (Unix timestamp)
    "exp": 1700003600,               # Expires in 1 hour
    "scope": ["upi_pay", "view_history"],
    "risk_level": "LOW"
}

# JWT is signed with PhonePe's private key (RS256 algorithm)
# RS256 = RSA signature with SHA-256
# PhonePe's API servers can verify with the corresponding public key
# PhonePe's servers never need to store all session data — it's all in the JWT
```

**On each payment request:**
```python
def validate_payment_request(request):
    token = request.headers['Authorization'].split(' ')[1]

    # 1. Verify JWT signature (using PhonePe's public key)
    claims = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])

    # 2. Check expiry
    assert claims['exp'] > time.time(), "Token expired"

    # 3. Check device matches
    device_id = request.headers['X-Device-ID']
    assert claims['device_id'] == hash(device_id), "Device mismatch"

    # 4. Check scope includes payment permission
    assert 'upi_pay' in claims['scope'], "Insufficient permissions"

    return claims
```

---

### UPI PIN Encryption — The Critical Security Detail

This deserves a deep dive because it's what makes UPI secure.

```
HDFC generates RSA key pair:
  Private Key → stored in HDFC's HSM (hardware, never exposed)
  Public Key  → published and distributed to NPCI

When Rahul links his bank, HDFC's public key is downloaded to the PhonePe app.

At payment time:
  1. User types PIN: 1 2 3 4
  2. On-device SDK converts: "1234" → binary representation
  3. Generates random IV (Initialization Vector) for this transaction
  4. Encrypts: ENCRYPTED_BLOCK = RSA_OAEP_ENCRYPT("1234", HDFC_PUBLIC_KEY)
     + XOR with session-specific nonce from NPCI
  5. The encrypted block is BASE64 encoded
  6. Sent to NPCI and forwarded to HDFC

At HDFC's HSM:
  1. Receives ENCRYPTED_BLOCK
  2. Decrypts using private key (operation happens inside HSM hardware)
  3. PIN value is verified against stored PIN hash
  4. "VERIFIED" or "WRONG PIN" response — the PIN value never leaves the HSM

The PIN itself never touches:
  - PhonePe's servers (they see only the encrypted blob)
  - NPCI's servers (they forward the blob without knowing its content)
  - Any log file anywhere in the chain
```

---

### Trust Boundaries in Authentication

```
TRUST ZONE 1: Rahul's Device (Lowest Trust)
  - Controls: App signature verification, device binding, certificate pinning
  - Threats: Rooted device, modified app, screen recorder
  - Assumption: Device might be compromised; use defense-in-depth

TRUST ZONE 2: PhonePe's Servers (Medium Trust)
  - Controls: JWT validation, rate limiting, fraud checks
  - Threats: SSRF, injection, compromised credentials
  - Assumption: Perimeter is defended; insider threat possible

TRUST ZONE 3: NPCI (High Trust — Regulated)
  - Controls: Audited by CERT-In, RBI; penetration tested quarterly
  - Threats: Nation-state attacks, insider at NPCI
  - Assumption: Extremely hardened; multiple layers of access control

TRUST ZONE 4: Bank's HSM (Highest Trust — Tamper-proof Hardware)
  - Controls: Physical security, hardware tamper detection
  - Threats: Physical theft, power analysis attacks
  - Assumption: If HSM is compromised, game over — but this is extremely hard
```

---

## 6. Data Flow

### What Data Flows and Where

**Data that flows freely:**
- VPA (address like `rahul@okhdfcbank`) — this is public by design
- Transaction amount — visible to PSP, NPCI, both banks
- Transaction status — visible to all parties
- UTR number — shared for reference
- Payee name — visible to payer for confirmation

**Data that has restricted access:**
- Actual bank account number — only payee's bank knows; masked as `XXXXX1234` elsewhere
- IFSC code — only routing bank knows
- Account balance — only payer's bank and account holder

**Data that NEVER travels in plaintext:**
- UPI PIN — always RSA-encrypted before leaving device
- Device IMEI/SIM serial — hashed before transmission

---

### Serialization Formats at Each Layer

```
Phone App → PhonePe Server:
  Protocol: HTTPS with TLS 1.3
  Format: JSON
  Why: Standard for mobile apps, easy to parse, human-readable

PhonePe Server → NPCI:
  Protocol: HTTPS with Mutual TLS (mTLS)
  Format: XML (NPCI UPI schema)
  Why: Financial industry standard, strong schema validation

NPCI → Bank:
  Protocol: HTTPS with mTLS / dedicated leased line
  Format: XML (NPCI-defined schema) or ISO 8583
  Why: Banks have existing ISO 8583 infrastructure; NPCI-XML for UPI

Settlement Reports:
  Format: SFTP-delivered flat files (CSV/fixed-width)
  Why: Banks have batch processing systems built for this format
```

---

### Data Transformation Pipeline

```
User Input (JSON from app)
    |
    v [Validate & Sanitize in PhonePe API]
    |  - VPA format check
    |  - Amount range check
    |  - Device fingerprint validation
    v
PhonePe Internal Model (Java/Go object)
    |
    v [Map to NPCI message format]
    |  - JSON → XML
    |  - Add required NPCI headers
    |  - Sign with PhonePe's certificate (mutual TLS)
    v
NPCI XML Message (ReqPay)
    |
    v [NPCI routing + enrichment]
    |  - Add NPCI transaction ID
    |  - Add routing information
    |  - Add fraud score
    v
Bank-facing message (to HDFC, then SBI)
    |
    v [Bank processing]
    |  - HSM decryption of PIN
    |  - Core banking system debit/credit
    |  - CBS response
    v
Response back up the chain (RespPay)
    |
    v [PhonePe processes response]
    |  - XML → JSON
    |  - Map response codes
    |  - Update DB
    v
JSON response to mobile app
    |
    v [App displays to user]
    |  - "Payment Successful" ✓ or error message
    v
Final State
```

---

### Where Data Is Validated

| Layer | Validation | Why |
|---|---|---|
| PhonePe App (client) | VPA format, amount positive | Quick UX feedback (not security) |
| PhonePe Server | JWT, device binding, rate limits, amount vs daily limit | First security gate |
| NPCI | VPA exists in registry, fraud score | Central validation |
| Payer Bank (HDFC) | PIN correct, balance sufficient, account active | Financial authorization |
| Payee Bank (SBI) | Account can receive funds, not blocked | Credit-side validation |

**Security principle:** Never trust client-side validation. Server must always re-validate everything.

---

## 7. Security Controls

### Encryption — Layer by Layer

**In Transit:**

```
Phone → PhonePe:
  TLS 1.3 with AES-256-GCM
  Certificate pinned in app (rejects certificates not matching expected fingerprint)
  HTTP Public Key Pinning (HPKP) or Trust Kit library
  Result: Even if attacker intercepts the network, they see gibberish

PhonePe → NPCI:
  Mutual TLS (both sides present certificates)
  PhonePe's certificate: issued by NPCI-approved CA
  NPCI's certificate: issued by its own CA
  Plus: dedicated MPLS circuit (traffic doesn't traverse public internet)
  Result: Both sides verified; man-in-middle is essentially impossible

NPCI → Bank:
  Mutual TLS on dedicated circuits
  Plus: message-level signing (XML Digital Signature)
  Result: Even if circuit is somehow tapped, message integrity is verified
```

**At Rest:**

```
PhonePe's Database:
  - Full disk encryption (AES-256)
  - Database-level TDE (Transparent Data Encryption)
  - No raw sensitive data stored (PINs never reach here)
  - User mobile numbers: stored as HMAC-SHA256 hash for indexing,
    full number encrypted with application-layer key

Bank's Database:
  - Same as above, plus stricter access controls
  - Account balances in core banking system behind multiple auth layers
  - Audit logs encrypted and signed

NPCI's Systems:
  - Classified; known to use HSMs and encrypted storage per RBI audit requirements
```

---

### Application-Level Security Controls

**Certificate Pinning in the App:**
```java
// Android TrustKit configuration
// This rejects any TLS certificate not matching the expected pin
// Prevents MITM attacks even if attacker installs root CA on phone
TrustKit.initializeWithNetworkSecurityConfiguration(this);

// In network_security_config.xml:
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.phonepe.com</domain>
        <pin-set expiration="2025-01-01">
            <pin digest="SHA-256">base64_of_cert_public_key_hash</pin>
            <pin digest="SHA-256">backup_pin_hash</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Why backup pin?** If the main certificate expires and PhonePe rotates to a new certificate, the backup pin ensures the app continues to work with the new certificate while the new pin is rolled out in an app update.

**Rate Limiting:**
```python
# Per-user rate limits
DAILY_TRANSACTION_LIMIT = 10_000_000  # ₹1 lakh in paise
DAILY_TRANSACTION_COUNT = 20          # max 20 transactions per day
PER_TRANSACTION_LIMIT = 10_000_000   # ₹1 lakh per transaction

# Per-device rate limits (fraud prevention)
MAX_DEVICES_PER_USER = 5
MAX_FAILED_PIN_ATTEMPTS = 3           # Account blocked after 3 wrong PINs

# Rate limiting implementation using Redis
def check_rate_limit(user_id, amount_paise):
    today = date.today().isoformat()

    # Atomic increment and check
    daily_count = redis.incr(f"txn_count:{user_id}:{today}")
    if daily_count == 1:
        redis.expire(f"txn_count:{user_id}:{today}", 86400)  # Expire at end of day

    if daily_count > DAILY_TRANSACTION_COUNT:
        raise RateLimitExceeded("Daily transaction count exceeded")

    daily_amount = redis.incrby(f"txn_amount:{user_id}:{today}", amount_paise)
    if daily_amount > DAILY_TRANSACTION_LIMIT:
        raise RateLimitExceeded("Daily transaction limit exceeded")
```

**Input Sanitization for XML Injection:**

Since PhonePe builds XML messages for NPCI, any user input that ends up in XML must be escaped:

```python
import xml.sax.saxutils as saxutils

def sanitize_for_xml(value):
    # Converts: < → &lt;  > → &gt;  & → &amp;  ' → &apos;  " → &quot;
    return saxutils.escape(value)

# Usage:
note = sanitize_for_xml(user_provided_note)
# If user types: <script>alert('hack')</script>
# Becomes: &lt;script&gt;alert('hack')&lt;/script&gt;
# XML parser treats it as text, not markup
```

---

### Secrets Handling

**What secrets exist in the UPI system:**

| Secret | Who Holds It | Storage | Rotation |
|---|---|---|---|
| UPI PIN | User (memorized) + Bank HSM | HSM, hardware-protected | User can change anytime |
| Bank's RSA Private Key | Bank's HSM | Hardware-protected | Annually or on compromise |
| PhonePe's mTLS Private Key | PhonePe's servers | HSM or Vault | Annually |
| NPCI-PhonePe Shared Key | Both parties | HSM | Quarterly |
| JWT Signing Key | PhonePe | AWS KMS or Vault | On rotation schedule |
| Database Encryption Keys | PhonePe | KMS | Annually |
| Stripe API Keys (if used) | PhonePe | Secrets Manager | On rotation or compromise |

**Secrets management in practice:**

```python
# WRONG — never do this:
stripe_key = "sk_live_abcdef..."  # Hardcoded = terrible

# WRONG — slightly better but still bad:
stripe_key = os.environ.get("STRIPE_KEY")  # Visible in process list, CI logs

# CORRECT:
import boto3
secrets = boto3.client("secretsmanager", region_name="ap-south-1")

def get_npci_api_key():
    response = secrets.get_secret_value(SecretId="prod/phonepe/npci_api_key")
    return response["SecretString"]
    # Key is fetched at runtime, not stored in code or environment
```

---

## 8. Attack Surface Mapping

### External Attack Surface

```
ATTACKABLE FROM THE INTERNET:
====================================================

[A1] PhonePe Mobile App
     Attack surface: The APK/IPA itself
     Vulnerabilities possible:
     - Reverse engineering to extract hardcoded secrets
     - Certificate pinning bypass (on rooted phones)
     - Hooking PIN entry SDK to capture PIN
     - Screen recording at PIN entry time

[A2] PhonePe API (api.phonepe.com)
     Attack surface: HTTPS endpoints
     Endpoints:
     - POST /api/v2/upi/pay       ← Payment initiation
     - POST /api/v2/upi/vpa/resolve ← VPA resolution
     - GET /api/v2/txn/{id}       ← Transaction status
     Vulnerabilities possible:
     - Brute force (mitigated by rate limiting)
     - JWT bypass (malformed tokens)
     - Parameter tampering (amount manipulation)
     - Replay attacks (same request replayed)

[A3] Webhook Endpoints
     Attack surface: HTTPS endpoints that Stripe/payment partners call back
     - POST /webhooks/payment_status
     Vulnerabilities: Forged webhooks without signature validation

[A4] Social Engineering
     Not a technical attack surface but the most common:
     - Phishing pages that mimic UPI apps
     - SIM swap attacks
     - Fake UPI collect requests (requesting money instead of paying)
```

---

### Internal Attack Surface

```
ATTACKABLE FROM WITHIN THE SYSTEM:
====================================================

[I1] PSP (PhonePe) Internal Networks
     - Compromised employee laptop
     - Malicious insider
     - Lateral movement from compromised web server

[I2] NPCI Internal Networks
     - Access to transaction routing tables
     - Ability to modify VPA mappings
     - Access to all transaction logs

[I3] Bank Internal Networks
     - Access to core banking systems
     - HSM management interfaces
     - Ability to modify account balances directly

[I4] Communication Channels
     - MPLS circuit tapping (carrier-level)
     - BGP hijacking (to redirect traffic)
```

---

### Attack Surface Diagram

```
                        ┌─────────────────────────────────────────┐
                        │           EXTERNAL ATTACK SURFACE        │
                        │                                          │
                        │  [A1]        [A2]          [A3]         │
                        │ Mobile App  API Server  Webhook          │
                        └──────┬──────────┬─────────────┬─────────┘
                               │          │             │
                        INTERNET (Untrusted)            │
                               │          │             │
                        ┌──────▼──────────▼─────────────▼─────────┐
                        │         PhonePe Infrastructure           │
    ┌───────────────────┤  [TB-1]                                  ├─────────────────┐
    │   Rate Limiting   │  nginx → API Servers → Business Logic    │   Auth Layer    │
    │   WAF             │                                          │   JWT Validate  │
    └───────────────────┤  Database  Cache  Queue                  ├─────────────────┘
                        └──────────────────┬───────────────────────┘
                                           │
                              [TB-2] Private Leased Line
                              (mTLS + dedicated circuit)
                                           │
                        ┌──────────────────▼───────────────────────┐
                        │         NPCI UPI Switch (HIGH TRUST)     │
    ┌───────────────────┤  [TB-3]                                  │
    │   All 300+ banks  │  Routing + Fraud + Settlement + Audit    │
    │   connected here  │                                          │
    └───────────────────┴──────┬─────────────────────────┬─────────┘
                               │                         │
                    [TB-4] Private MPLS           [TB-4] Private MPLS
                               │                         │
                        ┌──────▼──────┐           ┌──────▼──────┐
                        │  HDFC Bank  │           │   SBI Bank  │
                        │  [I3]       │           │   [I3]      │
                        │  CBS + HSM  │           │  CBS + HSM  │
                        └─────────────┘           └─────────────┘

TRUST BOUNDARIES:
  [TB-1] Internet → PhonePe: ZERO TRUST. Full validation.
  [TB-2] PhonePe → NPCI: HIGH TRUST. mTLS + dedicated circuit.
  [TB-3] NPCI ← Banks: HIGH TRUST. mTLS + dedicated circuit.
  [TB-4] NPCI → Banks: HIGH TRUST. mTLS + dedicated circuit.
  [I3] Banks: CRITICAL. Multiple physical + logical access controls.
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — Fake UPI Collect Request Scam (Most Common Attack)

**Background for beginners:** UPI has two modes:
- **Pay:** Sender initiates (Rahul pushes money to Priya)
- **Collect/Request:** Receiver initiates (Priya asks Rahul to send money)

Scammers exploit the "Collect" mode.

**Attacker Assumptions:**
- Attacker knows Rahul's phone number or UPI ID (easily found via social media, business cards)
- Attacker poses as a bank, government agency, or person needing urgent help
- No technical hacking required — this is social engineering via the UPI protocol

**Step-by-Step Execution:**

1. Scammer calls Rahul: "I'm from HDFC Bank. Your account needs verification. Please approve the UPI request we sent."

2. Scammer sends a UPI Collect Request to `rahul@okhdfcbank`:
   ```
   "Razorpay Pvt Ltd requests ₹5,000 from you"
   Note: "HDFC Bank KYC Verification"
   ```

3. Rahul sees a legitimate-looking UPI notification on his PhonePe app saying "Approve payment of ₹5,000."

4. The notification says "APPROVE" or "DECLINE" — Rahul, thinking he's verifying his account (not paying), clicks "APPROVE."

5. PhonePe asks for UPI PIN. The attacker on the phone says "Enter your UPI PIN to complete verification."

6. Rahul enters PIN → ₹5,000 leaves his account.

**Why This Works:**
- The UPI collect flow is designed for legitimate use (splitting bills, receiving payments)
- The notification UI says "Approve" which sounds like verification, not payment
- Rahul doesn't know that entering PIN in a collect request means he's PAYING

**Where Detection Could Happen:**
- PhonePe's app could (and sometimes does) show a more prominent warning: "⚠️ You are PAYING ₹5,000 to an unknown merchant"
- HDFC's fraud system: unusual amount, first time transacting with this VPA
- PhonePe's ML model: collect request to multiple users simultaneously = scam pattern

**Prevention:**
- NPCI mandate: UPI apps must show "YOU ARE PAYING" prominently for collect requests
- Never enter UPI PIN for a collect request from unknown parties
- UPI PIN is ONLY for outgoing payments, not for "verification"

---

### 9.2 — SIM Swap Attack

**Attacker Assumptions:**
- Attacker knows target's: full name, date of birth, and Aadhaar/PAN number (obtained from data breach or social engineering)
- Attacker's goal: take over the target's mobile number and UPI account

**Step-by-Step Execution:**

1. Attacker visits a mobile operator retail store (Airtel/Jio/BSNL) with a new blank SIM card.

2. Attacker presents fake documents claiming to be the victim (Rahul), says: "I lost my SIM, need a replacement."

3. Operator verifies with ID proof (which attacker has, either forged or obtained via fraud).

4. Operator ports Rahul's number to the new SIM. Rahul's SIM stops working.

5. Attacker can now receive OTPs sent to Rahul's number: "Your SIM swap for 9876543210 is complete."

6. Attacker downloads PhonePe on a fresh phone, registers with Rahul's number.

7. PhonePe sends OTP to 9876543210 → attacker's new SIM receives it.

8. Attacker logs into Rahul's PhonePe account (OTP received).

9. BUT: Attacker can't see UPI transactions or move money without the UPI PIN.
   - If the PIN is unknown to attacker: they can initiate a "Forgot PIN" / PIN reset
   - PIN reset requires bank account verification: attacker uses the last 6 digits of Rahul's debit card (which they may have obtained)
   - If reset succeeds: attacker sets a new PIN and drains the account

**Why This Works:**
- Mobile number portability in India can be done with minimal verification
- OTP-based authentication is vulnerable to SIM swap
- "Forgot PIN" flows may rely on information that can be socially engineered

**Where Detection Could Happen:**
- Jio/Airtel should send OTP to existing number before swap (they often do)
- PhonePe detects: new device registration for an existing user
- Bank detects: PIN reset request from a device that was never linked before
- NPCI fraud: sudden registration change + PIN reset = high risk flag

**Mitigation:**
- Enable SIM swap alerts with your carrier
- Use a separate number for financial transactions
- Banks should require in-branch PIN reset for SIM swap scenarios
- PhonePe could require biometric re-verification for PIN reset

---

### 9.3 — Man-in-the-Middle Attack Attempt (And Why It Fails)

**Attacker Assumptions:**
- Attacker controls the local WiFi network (coffee shop, public WiFi)
- Attacker runs Burp Suite or mitmproxy on the network
- Attacker wants to see and modify UPI payment data

**Step-by-Step Execution (What the Attacker Tries):**

1. Victim connects to attacker's WiFi hotspot.

2. Attacker runs an SSL stripping attack: when victim's phone connects to api.phonepe.com, attacker intercepts and serves their own certificate.

3. **Where it fails — Certificate Pinning:**
   PhonePe's app has the server's certificate fingerprint hardcoded:
   ```java
   // In PhonePe app code:
   EXPECTED_PIN = "sha256/AbCdEf1234..."
   
   // On receiving server certificate:
   received_pin = sha256(server_cert.public_key)
   if received_pin != EXPECTED_PIN:
       connection.abort()  // ATTACKER'S CERT REJECTED
   ```
   
   The app refuses to connect because the certificate fingerprint doesn't match.

4. The app shows: "Connection security error. This app cannot verify the server."

5. Payment cannot proceed. Attacker sees nothing.

**Why Certificate Pinning Defeats This:**
- Normal TLS: "I trust any certificate signed by a trusted CA"
- Certificate Pinning: "I only trust THIS specific certificate, no matter what"
- Even if attacker somehow gets a fraudulent certificate signed by a CA, the app rejects it because the fingerprint doesn't match the hardcoded expectation

**What Attacker CAN See (Even Without Decryption):**
- The IP address being contacted: 103.195.201.42
- The timing of requests (can infer transaction is happening)
- Size of responses (can very roughly infer transaction type)
- But NOT: the transaction details, amounts, VPAs, or PIN (all encrypted)

---

### 9.4 — Transaction Replay Attack (And Why It Fails)

**Attacker Assumptions:**
- Attacker has captured a valid UPI transaction message (somehow)
- Attacker wants to replay it to make the same payment again (double spend)

**Step-by-Step Execution (What the Attacker Tries):**

1. Somehow attacker captures this exact HTTP request Rahul made:
   ```
   POST /upi/pay
   {txnId: "TXN20241115001", amount: 50000, encryptedPIN: "BASE64..."}
   ```

2. Attacker replays this exact request to PhonePe.

3. **Where it fails — Idempotency:**
   ```python
   # PhonePe checks:
   existing = redis.get(f"idem:{body['txnId']}")
   if existing:
       return existing  # Return cached result, don't process again
   ```
   Same `txnId` → returns same response without processing → no second debit.

4. **Where it fails — NPCI timestamps:**
   NPCI rejects any message with a timestamp older than 5 minutes.
   ```xml
   <Txn ts="2024-11-15T10:30:45.123+05:30"/>
   ```
   If replayed 10 minutes later: NPCI sees timestamp is stale → rejects.

5. **Where it fails — Encrypted PIN session nonce:**
   The encrypted PIN block includes a one-time nonce from NPCI:
   ```
   ENCRYPTED_PIN = RSA_ENCRYPT(PIN, BANK_PUBLIC_KEY) XOR ONE_TIME_NONCE
   ```
   NPCI invalidates the nonce after first use. The decrypted PIN will be garbage on replay.

**Why Replay Attacks Fail on UPI:**
Defense is layered:
1. Idempotency key (application layer)
2. Timestamp validation (NPCI layer)
3. One-time nonce in PIN encryption (cryptographic layer)

---

### 9.5 — Compromised PSP Internal System

**Attacker Assumptions:**
- Attacker (insider or external hacker) has compromised PhonePe's internal API server
- Attacker has database read access
- Attacker wants to move money fraudulently

**What Can the Attacker Access?**
- Transaction history (VPAs, amounts, times)
- User phone numbers (encrypted, but may be decryptable with internal keys)
- Device fingerprints (hashed)

**What Can the Attacker NOT Access?**
- UPI PINs (never stored at PhonePe; encrypted on-device sent to bank)
- Bank account numbers (not stored; only the Stripe-like token/VPA)
- Ability to initiate transactions without a valid device session

**For a Fraudulent Transaction, Attacker Needs:**
1. Valid JWT session token (expires in 1 hour; stored only on device)
2. Valid device fingerprint (unique to the physical device)
3. The user's UPI PIN (never at PhonePe)
4. To be on the linked device (device binding check)

**Conclusion:** Even with full database access, attacker cannot initiate UPI transactions. The UPI PIN is the final gate, and it's only on the user's device and the bank's HSM.

**What the attacker CAN do:**
- Read transaction history (privacy breach)
- Potentially modify rate limit counters in Redis (allow more transactions through, but still can't initiate without PIN)
- Internal account takeover (if employee credential is compromised)

**Detection:**
- Database access patterns monitored (SIEM alerts on bulk reads)
- Unusual API calls from internal IPs
- Privileged access management alerts

---

### 9.6 — Fraudulent Merchant UPI ID (QR Code Swap)

**Attacker Assumptions:**
- Physical world attack: attacker goes to a real shop
- Shop has a UPI QR code: `merchant_rahulstore@icici`
- Attacker replaces QR code sticker with their own: `attacker@oksbi`

**Step-by-Step Execution:**

1. Attacker prints a QR code for their VPA (`attacker@oksbi`) and sticks it over the merchant's QR code.

2. Customer scans the QR code, sees: "Attacker Sharma | SBI" — not the expected merchant name.

3. BUT: Many customers don't check the name carefully if the amount is small (₹50 for a chai).

4. Customer enters PIN → money goes to attacker, not the merchant.

**Why This Works:**
- No technical hacking required
- Exploits customer habit of not verifying payee name
- UPI doesn't require merchants to have "merchant" type accounts (anyone can receive payments)

**Where Detection Could Happen:**
- UPI apps now show a prominent display of payee name — user must read it
- For merchants, UPI apps can verify against merchant registry (UPI mandates this for higher amounts)
- Merchant notices payment not received → alerts bank

**Prevention:**
- Always verify payee name before entering PIN
- Merchant should use dynamic QR codes (generated fresh per transaction, includes amount — can't be swapped)
- UPI apps showing "VERIFY MERCHANT" for first-time payees

---

## 10. Failure Points

### Under Load

**NPCI UPI Switch Load:**

NPCI processes 13+ billion transactions per month = ~5,000 transactions per second average, with peaks during festivals/paydays reaching 100,000+ TPS.

**What fails first under load:**

1. **NPCI's VPA Resolution service:**
   - Every transaction starts with VPA resolution
   - At peak, this service gets overwhelmed
   - Result: VPA resolution takes 5–10 seconds instead of 0.5 seconds
   - UPI apps show "Please wait, processing..."

2. **Bank UPI adapters:**
   - Each bank's UPI server has a finite TPS capacity
   - SBI might process 2,000 UPI credits/second normally
   - On festival day: 10,000/second → queue builds up
   - Result: Transactions succeed but take 10–30 seconds (technically within NPCI's SLA)

3. **Settlement database:**
   - NPCI must record every transaction for audit
   - DB write throughput becomes the bottleneck
   - Mitigation: Multiple write replicas, partitioned tables, write-behind caching

**Historical example:** On Diwali 2023, UPI processed 500+ million transactions in a single day — more than double a normal day. Several apps showed increased latency (2–5s per transaction) but the system didn't fail.

---

### Common Failure Types

**Timeout cascade:**
```
User initiates payment
→ PhonePe sends to NPCI (OK, 50ms)
→ NPCI sends to HDFC (OK, 100ms)
→ HDFC sends to SBI (OK, 200ms)
→ SBI takes 40 seconds (overloaded)
→ NPCI times out at 30 seconds
→ NPCI sends TIMEOUT to PhonePe
→ PhonePe shows "Transaction Pending"
→ Money may be debited from Rahul (HDFC debited)
→ But NOT credited to Priya (SBI didn't complete)
→ This is called a "PENDING" transaction
→ Automatic reversal must happen
```

**The PENDING state is the worst user experience in UPI.** Money leaves the sender's account, doesn't reach the receiver. Automatic reversal happens within 30 minutes to 3 business days depending on the failure scenario.

---

### Under Attack

**DDoS on NPCI:**
- NPCI is protected by multiple ISP-level DDoS mitigation
- As a critical national infrastructure, it's one of the most protected systems in India
- Even so, volumetric attacks can cause latency increases

**Coordinated bot attacks:**
- Thousands of devices simultaneously initiating transactions
- Result: Rate limits trigger, legitimate users see 429 errors
- NPCI has bot detection based on transaction pattern signatures

---

### Common Misconfigurations

| Misconfiguration | Impact | Fix |
|---|---|---|
| Certificate pinning disabled | MITM possible | Never disable in production |
| Idempotency not implemented | Double charges on retry | Always implement idempotency key check |
| Timestamp not validated | Replay attacks possible | Reject messages older than 5 minutes |
| Debug mode in production | Leaks internal paths, sometimes sensitive data | Strict environment-based config |
| Rate limits too loose | Fraudsters run scripts | Conservative limits, monitor for abuse |
| Plain-text logging of amounts | Privacy leak, data regulations | Log transaction IDs only, not amounts in plain logs |
| Session token not expiring | Stolen token usable forever | Short TTL (1 hour) + refresh mechanism |
| VPA not validated before resolving | Server-side injection | Strict format validation before any processing |

---

## 11. Mitigations

### Defense-in-Depth Strategy

Think of security as an onion — many layers, each protecting against different attacks:

```
Layer 1: Regulatory Compliance (Outermost)
  - RBI regulations mandate specific security controls
  - NPCI certification required for PSPs
  - Regular audits by CERT-In (India's cybersecurity agency)
  - Failure to comply = loss of UPI license

Layer 2: Network Security
  - Dedicated private circuits (not public internet) for NPCI-bank communication
  - DDoS protection at ISP level
  - WAF (Web Application Firewall) for API endpoints
  - Network segmentation (payment servers in isolated VPCs)

Layer 3: Application Security
  - Certificate pinning in mobile apps
  - mTLS between all server-to-server communication
  - JWT with short expiry + device binding
  - Input validation at every layer
  - Idempotency for all payment mutations

Layer 4: Cryptographic Security
  - UPI PIN encrypted on-device, never travels in plaintext
  - RSA-OAEP for PIN encryption (resists chosen-ciphertext attacks)
  - HSMs for key storage (physical tamper protection)
  - Key rotation on schedule

Layer 5: Fraud Detection (Innermost)
  - Real-time ML models at PSP level
  - NPCI's central fraud scoring
  - Bank-level fraud engines
  - Behavioral analysis (is this how this user normally transacts?)

Layer 6: Human Controls
  - UPI PIN — only the user knows it
  - Mandatory user confirmation before payment
  - Payee name shown prominently
  - NEVER enter PIN to "receive" money (education campaign)
```

---

### Concrete Fixes for Each Attack

| Attack | Fix | Engineering Cost |
|---|---|---|
| Fake collect requests | Prominently label "YOU ARE PAYING" in UI | Low |
| SIM swap | Require biometric + extra verification for new device + PIN reset | Medium |
| MITM | Certificate pinning + HSTS | Low |
| Replay attacks | Idempotency keys + timestamp validation + one-time nonces | Medium |
| QR code swap | Dynamic QR codes with embedded amount + merchant verification | High |
| DDoS | Cloud-based DDoS mitigation + rate limiting | Medium |
| Phishing | Google Safe Browsing integration + user education | Low |

---

### Engineering Tradeoffs

| Security Control | Security Benefit | Engineering Cost | UX Impact |
|---|---|---|---|
| Certificate pinning | Prevents MITM | Medium (must update with cert) | None normally; breakage on cert rotation if mishandled |
| Short session tokens (1hr) | Limits stolen token damage | Low | Users must re-authenticate more often |
| Device binding | Prevents account takeover from new device | Medium | Hassle when changing phones |
| 3-wrong-PIN lockout | Prevents brute force | Low | Frustrating if user genuinely forgets PIN |
| Mandatory VPA name display | Prevents misdirected payments | Low | Slight extra step for user |
| Biometric + PIN (2FA) | Defense in depth | Medium | Slight friction |

---

## 12. Observability

### What to Log

**PhonePe PSP Logging:**

```json
// Transaction initiated
{
  "timestamp": "2024-11-15T10:30:45.123Z",
  "event": "upi.transaction.initiated",
  "txn_id": "TXN2024111503045001",
  "payer_vpa_hash": "sha256:a1b2c3...",       // NEVER log plain VPA
  "payee_vpa_hash": "sha256:d4e5f6...",
  "amount_paise": 50000,
  "currency": "INR",
  "device_fp_hash": "sha256:789abc...",
  "ip_hash": "sha256:def012...",
  "ip_geo": "IN-MH-Mumbai",
  "channel": "USRAPP",
  "request_id": "req-abc-123",
  "duration_ms": null                         // Filled when response received
}

// Transaction completed
{
  "timestamp": "2024-11-15T10:30:47.456Z",
  "event": "upi.transaction.completed",
  "txn_id": "TXN2024111503045001",
  "status": "SUCCESS",
  "npci_txn_id": "NPCI20241115103047001",
  "utr": "411522987654",
  "duration_ms": 2333,
  "response_code": "00"
}

// Security event
{
  "timestamp": "2024-11-15T10:31:00.000Z",
  "event": "upi.security.pin_failure",
  "txn_id": "TXN2024111503045001",
  "user_id_hash": "sha256:xxx...",
  "attempt_number": 2,
  "device_fp_hash": "sha256:789abc...",
  "ip_hash": "sha256:def012...",
  "severity": "HIGH"
}
```

**What NEVER appears in logs:**
- Plain UPI PIN (would be a critical security violation)
- Plain mobile numbers or VPAs (only hashed)
- Encrypted PIN blocks (no operational need to log these)
- Bank account numbers
- User's full name in high-volume logs (PII minimization)

---

### Metrics to Track

```
Business Metrics:
  upi.transactions.count{status="SUCCESS|FAILED|PENDING"}
  upi.transactions.amount_paise{currency="INR"}
  upi.transactions.success_rate         # Target: >98%
  upi.vpa.resolution.duration_ms        # p50, p95, p99
  upi.payment.e2e_duration_ms           # p50, p95, p99

Technical Metrics:
  upi.npci.api.latency_ms               # How long NPCI takes
  upi.bank.debit.latency_ms{bank="HDFC|SBI|..."}
  upi.bank.credit.latency_ms{bank="HDFC|SBI|..."}
  upi.redis.idempotency.hit_rate        # Are retries happening?

Security Metrics:
  upi.security.pin_failures_per_user    # Alert if user has 2+ failures
  upi.security.new_device_registrations # Alert on spike
  upi.security.collect_requests.count   # Fraud indicator if high
  upi.rate_limit.exceeded_count{endpoint}
  upi.auth.jwt_failures                 # Potential token theft attempts
  upi.fraud.score_distribution          # Monitor fraud ML output

Infrastructure Metrics:
  upi.db.connection_pool.utilization    # Alert at 80%
  upi.redis.memory_used_bytes
  upi.api.http_errors{code="4xx|5xx"}
  upi.api.request_rate
```

---

### Distributed Tracing

```
Complete trace for a ₹500 UPI payment:

Trace: txn-20241115-abc123 [Total: 2,333ms]
  ├── PhonePe App → API [Network: 45ms]
  ├── JWT Validation [2ms]
  ├── Rate Limit Check (Redis) [1ms]
  ├── Idempotency Check (Redis) [1ms]
  ├── VPA Resolution [342ms]
  │     ├── PhonePe → NPCI [50ms]
  │     ├── NPCI → SBI [150ms]
  │     └── SBI lookup + response [142ms]
  ├── Payment Initiation
  │     ├── PhonePe → NPCI [48ms]           [1,942ms total]
  │     ├── NPCI → HDFC (debit) [312ms]
  │     │     ├── HSM PIN decryption [15ms]
  │     │     ├── Balance check [25ms]
  │     │     ├── Fraud engine [50ms]
  │     │     └── CBS debit [222ms]
  │     ├── NPCI → SBI (credit) [280ms]
  │     │     ├── Account lookup [30ms]
  │     │     └── CBS credit [250ms]
  │     └── NPCI settlement record [50ms]
  ├── DB Update (PhonePe) [8ms]
  └── Response to app [Network: 45ms]
```

This trace shows exactly where time is spent. If `HDFC CBS debit` suddenly takes 2 seconds instead of 200ms, we know HDFC is the bottleneck.

---

### Alerting Rules

| Condition | Severity | Action |
|---|---|---|
| Success rate drops below 95% | CRITICAL | Page on-call engineer immediately |
| p99 transaction latency > 10s | HIGH | Alert team |
| NPCI connection drops | CRITICAL | Escalate to NPCI and on-call |
| Pin failure 3x for same user | HIGH | Flag account, notify user |
| 100+ new device registrations in 1 minute | HIGH | Fraud team alert |
| Collect request spike (>2x normal) | MEDIUM | Review for scam campaign |
| Redis memory >80% | HIGH | Scale up before OOM |
| Any 5xx error rate >1% | HIGH | Engineering alert |
| JWT validation failures spike | HIGH | Possible token theft attempt |
| Single user exceeds ₹50,000 in 1 hour | MEDIUM | Fraud review |
| Normal transactions within p95 latency | No alert | Expected |
| Individual failed transaction | No alert | Expected (wrong PIN, etc.) |

---

## 13. Scaling Considerations

### The Scale Challenge

UPI is one of the world's largest real-time payment systems. The numbers are staggering:
- ~500 million active users
- 13 billion transactions per month
- Peak: 500+ million transactions per day (Diwali)
- Average: 5,000+ TPS (transactions per second)
- Peak: 50,000+ TPS

For context, Visa processes ~24,000 transactions per second globally. UPI is approaching that scale for a single country's payment system.

---

### Bottlenecks

**Bottleneck 1: NPCI's Central Switch**

NPCI is the single routing hub for ALL UPI transactions in India. This is a design decision (centralized control for a country's financial infrastructure) but creates a potential single point of failure.

**How NPCI solves this:**
- Multiple active-active data centers (at least 2 confirmed: Mumbai and Hyderabad)
- Each data center can handle the full load independently
- Synchronous replication between data centers
- If one DC fails: traffic shifts to the other DC within minutes (not seconds — this is a painful failover)

**Bottleneck 2: Bank UPI Adapters**

Each bank operates their own UPI adapter. Legacy banks (old core banking systems on AS/400 or mainframes) can only handle limited TPS.

**How banks solve this:**
- Queue incoming UPI requests and process at the rate the CBS can handle
- Add more UPI adapter instances (horizontal scaling of the middleware layer)
- CBS upgrade programs (expensive, multi-year projects)

**Bottleneck 3: Real-Time Settlement Database**

NPCI must record every transaction atomically. At 50,000 TPS, that's 50,000 DB writes per second.

**How NPCI solves this:**
- Sharded database (partition by transaction ID hash)
- Write-ahead logging (WAL) for durability with batched commits
- In-memory settlement ledger with async persistence
- Separate OLTP (transaction processing) and OLAP (analytics/reporting) systems

---

### Horizontal vs Vertical Scaling

| Component | Scaling Strategy | Notes |
|---|---|---|
| PhonePe API servers | Horizontal (stateless, scale out) | Add more EC2/pod instances |
| PhonePe Redis (idempotency) | Redis Cluster (shard by user_id) | Multiple nodes |
| PhonePe Database | Read replicas + vertical primary | Write path is not shardable easily |
| NPCI Switch | Active-active multi-DC | Not public; assumed sophisticated |
| Bank UPI Adapters | Horizontal (multiple adapter instances) | Constrained by CBS throughput |
| Bank CBS | Vertical (upgrade mainframe capacity) | Expensive, slow |

---

### Consistency Tradeoffs

**The fundamental tension in UPI:**

For money movement, you need strong consistency (the debit and credit must BOTH succeed, or BOTH fail). But strong consistency conflicts with high availability and low latency (you can't spread across many servers and keep everything perfectly consistent at high speed).

**How UPI resolves this:**

```
Step 1: HDFC debits Rahul (strongly consistent within HDFC)
Step 2: SBI credits Priya (strongly consistent within SBI)
Step 3: NPCI records both (audit log)

What if Step 2 fails after Step 1 succeeds?
→ NPCI's reversal mechanism:
  - Within 30 seconds: automatic retry of credit
  - After 3 failed retries: initiate reversal of debit
  - Reversal: credit back to Rahul from HDFC
  - This results in a "Pending/Failed" transaction
  - Both parties get SMS: "Transaction reversed. Amount returned."

The system is NOT perfectly consistent in all failure scenarios.
It is designed for "eventual consistency with guaranteed resolution."
Money is never permanently lost — either the credit happens or the debit is reversed.
```

**The "Zombie Transaction" Problem:**

Sometimes NPCI times out waiting for a bank response, but the bank actually processed the transaction. This leads to:
- NPCI records: FAILED
- HDFC records: DEBITED
- SBI records: CREDITED

Both Rahul and Priya see "FAILED" but money has actually moved. This happens rarely (~0.01% of transactions) and is resolved via the bank-to-bank reconciliation process that happens nightly.

---

### Database Partitioning Strategy at Scale

**PhonePe's transaction table (simplified):**

```sql
-- Partition by date (most queries are time-bounded)
CREATE TABLE upi_transactions (
  -- same as before
) PARTITION BY RANGE (initiated_at);

CREATE TABLE upi_transactions_2024_11
  PARTITION OF upi_transactions
  FOR VALUES FROM ('2024-11-01') TO ('2024-12-01');

-- Each partition has its own index
-- Old partitions (>6 months) can be moved to cheaper storage
-- Queries on recent data are extremely fast (small partition scanned)

-- For user-specific queries, add: index on (user_id, initiated_at)
CREATE INDEX idx_txn_user_date ON upi_transactions (user_id, initiated_at DESC);
```

**Sharding by user ID (for very high scale):**
```
Shard 0: Users with user_id % 10 == 0 → DB Server 0
Shard 1: Users with user_id % 10 == 1 → DB Server 1
...
Shard 9: Users with user_id % 10 == 9 → DB Server 9
```

Challenge: Cross-shard transactions (Rahul's data is on shard 3, Priya's data is on shard 7 — a transaction between them must write to both shards). This is solved by saga patterns and eventual consistency (write to each shard independently, with compensation logic on failure).

---

## 14. Interview Questions

### Q1: "Why does UPI use VPAs instead of directly using bank account numbers? What problem does this solve?"

**Answer:**

VPAs (Virtual Payment Addresses) solve several critical problems:

**Security:** Bank account numbers are permanent identifiers. If you expose your account number to every person you transact with, you're exposing something that can't be changed if compromised. VPAs are aliases — if a VPA is compromised, you can delete it and create a new one without changing your actual bank account.

**Usability:** Bank account numbers are 9-18 digits, and you also need an IFSC code (11 characters). Together, this is 20-29 characters that must be entered correctly. VPAs are human-readable (`rahul@okhdfcbank`) and include an implicit bank identifier (the handle determines the bank). Much less error-prone.

**Portability:** You can switch banks but keep the same VPA by updating the VPA-to-account mapping at the new bank. Your VPA (`rahul@okhdfcbank`) stays the same even if you open a new HDFC account.

**Multiple accounts:** One person can have multiple VPAs pointing to different accounts (personal, business, etc.) without sharing their account numbers.

**What if the VPA resolution service fails?** Without VPA resolution, UPI payments cannot be initiated. This is a critical single point of failure. NPCI mitigates this with:
- VPA caching at PSP level (60-second TTL)
- Multiple redundant VPA resolution servers
- Active-active deployment across data centers

---

### Q2: "Explain why UPI PIN is encrypted on-device. What would happen if it were encrypted server-side?"

**Answer:**

**If encryption happened on PhonePe's server:**

```
Rahul's phone → (PIN in plaintext) → PhonePe server → (PIN encrypted) → Bank
                    ↑
             PROBLEM: PIN travels
             unencrypted from phone
             to PhonePe's server!
```

In this model:
- Anyone intercepting the connection between Rahul's phone and PhonePe's server would see the PIN (mitigated by TLS, but TLS can be MITM'd on compromised devices or rooted phones)
- PhonePe's server process would have the PIN in memory — a PhonePe insider or a compromised PhonePe server could log/steal PINs
- A PhonePe employee could extract PINs from logs if logging is misconfigured

**On-device encryption:**
```
Rahul's phone → (PIN encrypted with bank's public key) → PhonePe server → Bank
                    ↑
             PhonePe server NEVER
             sees the plaintext PIN
```

Even if:
- PhonePe is hacked → attacker gets encrypted blobs, useless without bank's private key
- NPCI is hacked → same thing, encrypted blobs only
- PhonePe employee monitors traffic → encrypted blobs only

Only the bank's HSM (which holds the private key) can ever see the plaintext PIN. The HSM has physical tamper protection — if someone tries to break into it, it destroys the keys.

**What if → you use RSA without a session nonce?**

Without the one-time session nonce, the same PIN always produces the same encrypted output. An attacker could:
1. See the encrypted block for a successful transaction
2. Replay the same encrypted block to initiate a new transaction

The XOR with a one-time nonce from NPCI means: `ENCRYPTED_PIN = RSA(PIN, PubKey) XOR NONCE`

Even if the PIN is the same, a different nonce each time produces a different encrypted blob. Replay attack defeated.

---

### Q3: "What is the 'Pending' state in UPI and why is it the hardest problem in the system?"

**Answer:**

A UPI transaction enters "Pending" when:
- The debit succeeds at the payer's bank
- But the credit at the payee's bank either fails or times out
- Or NPCI times out waiting for either bank's response

**Why it's hard:**

**The ACID problem:** Traditional database transactions are atomic — either everything happens or nothing. But here you have two separate databases (HDFC and SBI) controlled by two separate organizations, connected by a network that can fail. There's no distributed transaction coordinator that can guarantee atomicity across them.

**The reversal challenge:** NPCI must automatically reverse the debit if credit fails. But what if:
- The reversal request to HDFC also times out?
- HDFC's system is down for 2 hours?
- The debit succeeded but NPCI's record of it is corrupted?

**How NPCI handles it:**
1. Each successful debit has a "debit reference number"
2. NPCI stores this with the transaction state
3. If credit fails after successful debit: NPCI sends reversal to payer's bank with the debit reference
4. Bank reverses the specific debit
5. Maximum time for automatic reversal: 30 minutes to 3 business days (depends on the bank's system availability)
6. If auto-reversal fails: manual intervention via bank's dispute team

**Why users hate Pending:**
- Sender sees money gone from account
- Receiver sees nothing received
- Neither party knows what happened
- WhatsApp messages fly: "Did you get the money?"

**The fix from a product perspective:** UPI apps now show Pending transactions prominently with estimated resolution time and a "Check Status" button that re-queries NPCI.

---

### Q4: "How does NPCI prevent a single PSP (like PhonePe) from taking down the entire UPI network?"

**Answer:**

NPCI implements **per-PSP rate limiting and circuit breakers:**

**Rate limiting:**
- Each PSP has a maximum TPS allocation based on their infrastructure capacity and historical volume
- PhonePe might be allowed 10,000 TPS, Paytm 8,000 TPS, BHIM 2,000 TPS
- If PhonePe sends 50,000 TPS (a bug, or a DDoS using PhonePe's infrastructure), NPCI's ingress layer drops the excess requests with a 429 response

**Circuit breaker pattern:**
```
If PSP X has >10% error rate in last 60 seconds:
  → Mark PSP X's connection as DEGRADED
  → Reduce traffic acceptance from PSP X to 50%
  → Alert NPCI and PSP X operations teams
  → If error rate persists >5 minutes: further reduce to 10%
  → This prevents one PSP's flood from overwhelming NPCI's bank connections
```

**Separate connection pools:**
- NPCI maintains separate connection pools to each bank for each PSP
- PhonePe's transactions to HDFC use Pool A
- Paytm's transactions to HDFC use Pool B
- A PhonePe flood can exhaust Pool A but doesn't affect Pool B

**Admission control:**
- During NPCI's own high load (festival days), NPCI can throttle lower-priority transaction types (bulk payments, API integrations) to protect capacity for P2P transactions
- Real-time P2P payments get highest priority

---

### Q5: "If you were designing UPI from scratch in 2024, what would you do differently?"

**Answer — This tests understanding of tradeoffs:**

**What UPI got right (keep):**
- VPA abstraction — brilliant usability decision
- On-device PIN encryption — correct security architecture
- Real-time processing (not batch like NEFT) — critical for usability
- Standardized protocol across all banks — network effect enabled mass adoption

**What I'd improve:**

1. **Phishing-resistant authentication (FIDO2):**
   Currently UPI PIN can be phished (you can be tricked into entering it on a fake page). FIDO2/WebAuthn uses cryptographic binding to the origin — your phone signs a challenge that proves you're on the real UPI/bank site. Cannot be phished. However, this requires all banks to support FIDO2, a complex coordination problem.

2. **Better pending state handling:**
   Adopt a saga pattern with compensating transactions formally specified. Currently, the reversal logic is ad-hoc per bank. A formalized saga would reduce the "pending for 3 days" problem.

3. **End-to-end encryption for transaction metadata:**
   Currently, NPCI can see all transaction details (who paid whom, how much). In 2024, with privacy regulations, I'd explore a zero-knowledge proof system where NPCI can verify a transaction is valid without knowing the payer, payee, or amount. Technically complex but privacy-preserving.

4. **Native offline support:**
   UPI requires internet connectivity. In rural India, connectivity is unreliable. NPCI is working on UPI Lite (offline small-value payments), but I'd make this a first-class feature, not an afterthought.

5. **Better fraud feedback loop:**
   Currently, fraud reported by users takes days to propagate to block lists. Real-time fraud graph propagation (if VPA X scammed 10 users in 1 hour, block immediately) would significantly reduce scam impact.

---

### Q6: "What happens to a UPI transaction at exactly 11:59 PM on December 31?"

**Answer — Tests understanding of settlement and operational aspects:**

The transaction itself processes normally — UPI is 24x7x365. The banking system doesn't stop at midnight for calendar events.

However, several things change:

**Settlement cycle:**
- UPI transactions settle multiple times per day (6-8 settlement cycles, every 3-4 hours)
- A transaction at 11:59 PM on Dec 31 will settle in the first cycle of the new year (perhaps 2 AM on Jan 1)
- Settlement debit/credit dates in bank statements show Jan 1, not Dec 31

**Business date change:**
- Banks use a "business date" for accounting — this typically rolls over at midnight
- A debit authorized at 11:59 PM Dec 31 and settled at 2 AM Jan 1 will show as Jan 1 on bank statements

**Year-end batch processing:**
- Banks run year-end financial reconciliation, which can cause:
  - Slower response times (CBS busy with year-end reports)
  - Higher transaction latency (acceptable) or failures (rare)

**Daily limits reset:**
- UPI per-day limits (₹1 lakh/day) reset at midnight based on the PSP's definition of "day"
- This is a business logic decision at the PSP level

**Interesting edge case:** What if a user hit their daily limit at 11:59 PM and the transaction is "Pending"? If the transaction completes after midnight, it counts against the new day's limit. But if it fails and reversed, it's treated as Dec 31's activity. Race conditions in limit accounting are a real operational headache.

---

### Q7: "How would you design the fraud detection system for UPI? What signals would you use?"

**Answer:**

**Signal categories:**

```
Device signals:
  - Is this a known device for this user?
  - Is the device rooted/jailbroken? (higher fraud risk)
  - Device age: brand new device + new VPA = suspicious
  - Device fingerprint matches historical patterns?

Behavioral signals (per user):
  - Typical transaction size (is ₹50,000 unusual for this user?)
  - Typical recipients (first time paying this VPA?)
  - Time of day (payment at 3 AM unusual for this user?)
  - Location (is this tower/GPS usual for this user?)
  - Transaction frequency (100 transactions in 1 hour = unusual)

Network signals (across users):
  - Is this payee VPA receiving money from many users in short time? (scam)
  - Is this device registered for multiple users? (mule account)
  - Graph analysis: Is this part of a money-laundering ring?

Transaction signals:
  - Is this a collect request from an unknown VPA? (scam risk)
  - Round amounts (₹50,000 exactly) are more fraud-prone than organic amounts (₹47,523)
  - Splitting large amounts into multiple smaller ones (structuring)
```

**Architecture:**

```
Transaction initiated
    ↓
[Real-time feature extraction] (<5ms)
  - Device score (cached)
  - User velocity (Redis counter)
  - Payee reputation score (pre-computed)
    ↓
[ML model inference] (<20ms)
  - XGBoost model: simple, fast, explainable
  - Trained on historical fraud labels
  - Output: risk score 0-100
    ↓
Risk score < 30: Allow (green)
Risk score 30-70: Allow with monitoring (yellow) 
Risk score 70-90: Step-up authentication (biometric confirmation)
Risk score > 90: Block + manual review

[Async batch analysis] (after transaction)
  - Graph neural network for network fraud
  - Deep anomaly detection
  - Updates future risk scores
```

**The challenge:** False positives (blocking legitimate transactions) are very costly — you lose trust. False negatives (allowing fraud) are financially costly and reputationally damaging. The sweet spot is tuning for a very low false positive rate (<0.1%) even if it means some fraud slips through initially, then catching it in the async analysis layer.

---

### Q8: "Explain mTLS. Why does NPCI require it between PSPs and itself?"

**Answer (for all levels):**

**Regular TLS (one-way):**
```
Client says: "I want to connect to api.npci.org.in"
Server presents: "Here's my certificate proving I'm NPCI"
Client verifies: "Yes, that's a valid certificate for NPCI. I'll trust this."
Client authenticates with: Username/password or API key in the request body
```

Problem: The server knows it's talking to a trusted client only because of the API key. API keys can be stolen.

**Mutual TLS (mTLS — two-way):**
```
Client says: "I want to connect. Here's MY certificate proving I'm PhonePe."
Server presents: "Here's MY certificate proving I'm NPCI."
Both sides verify each other's certificates.
Connection established only if both certificates are valid.
```

**Why NPCI requires mTLS:**

1. **Identity proof at connection time:** The moment a connection is established, NPCI knows exactly which PSP is connecting (by the certificate subject: "PhonePe Digital Payments"). No API key can be stolen from this — the private key corresponding to PhonePe's certificate never leaves PhonePe's servers.

2. **Regulation:** RBI mandates mutual authentication for payment system participants.

3. **Defense against insider threats:** Even if a PhonePe employee tries to connect to NPCI from a personal machine, they don't have the PhonePe mTLS private key. They'd need access to PhonePe's HSM or key management system.

4. **Non-repudiation:** Every request is cryptographically signed by the connecting party. There's irrefutable proof of who sent what.

**How certificate management works at this scale:**
- NPCI operates as a Certificate Authority (CA) for UPI participants
- Each PSP gets a certificate signed by NPCI's CA
- Certificate validity: 1 year (shorter = more secure, but operational overhead)
- Revocation: NPCI can revoke a PSP's certificate instantly (e.g., if the PSP is suspended)
- Private key: Stored in PSP's HSM, never exposed; NPCI sees only the public certificate

---

### Q9: "What is the significance of the UTR number and how would you reconstruct a dispute if a UTR exists but no record in your DB?"

**Answer:**

**What UTR is:**
UTR = Unique Transaction Reference. It's a 12-digit number assigned by NPCI when a transaction successfully completes. Format varies slightly but typically: `{bank_code}{date}{sequence}`.

Example: `411522987654`
- `4115` → Bank code (HDFC in this example)
- `22` → Day of month
- `987654` → Sequence number at the bank

**Significance:**
- UTR is the universal reference for the transaction across all systems
- If Rahul calls HDFC's customer service: "My UTR is 411522987654, where is my money?"
- HDFC can look up this UTR in their records and trace exactly what happened
- NPCI can look it up in their settlement records
- SBI can look it up in Priya's credit records

**The scenario: UTR exists but no DB record at PhonePe:**

This can happen when:
- PhonePe's server crashed after receiving the NPCI success response but before writing to DB
- A bug caused the DB write to fail silently
- The response was received by the app but the DB update job failed

**Reconstruction process:**

```python
def reconstruct_from_utr(utr: str):
    # Step 1: Query NPCI's transaction API with UTR
    npci_record = npci_api.get_transaction_by_utr(utr)
    # Returns: payer_vpa, payee_vpa, amount, status, timestamp

    # Step 2: Query payer's bank (HDFC)
    hdfc_record = hdfc_api.get_debit_by_utr(utr)
    # Returns: debit status, amount, account reference

    # Step 3: Query payee's bank (SBI)
    sbi_record = sbi_api.get_credit_by_utr(utr)
    # Returns: credit status, amount, account reference

    # Step 4: Reconstruct the transaction
    if npci_record.status == "SUCCESS" and hdfc_record.status == "DEBITED" and sbi_record.status == "CREDITED":
        # Money actually moved. Create the missing DB record.
        create_transaction_record(
            utr=utr,
            payer_vpa=npci_record.payer_vpa,
            payee_vpa=npci_record.payee_vpa,
            amount_paise=npci_record.amount_paise,
            status="SUCCESS",
            is_reconstructed=True,
            reconstruction_timestamp=now()
        )
        # Trigger fulfillment if not done
        # Send receipt to user
```

**This is why you should never use PhonePe's DB as the single source of truth for financial data.** The UTR + NPCI record + bank records together are the ground truth. PhonePe's DB is an operational cache.

---

### Q10: "How does UPI handle the case where HDFC debits ₹500 but NPCI never receives confirmation, and then Rahul tries to make another payment?"

**Answer — Tests understanding of the PENDING state and real-world operational complexity:**

**The scenario:**
```
1. NPCI sends debit request to HDFC
2. HDFC successfully debits ₹500 from Rahul
3. HDFC sends "DEBIT_SUCCESS" response
4. Network hiccup: response never reaches NPCI
5. NPCI waits 30 seconds → timeout
6. NPCI records transaction as: UNKNOWN/PENDING
7. Rahul's account: shows ₹500 gone
8. Priya's account: no credit received
9. Rahul opens PhonePe: shows "Processing" / "Pending"
10. 5 minutes later, Rahul tries another payment
```

**What happens to the second payment:**

The second payment CAN go through because:
- Rahul's balance is (say) ₹2,000 − ₹500 debited = ₹1,500 available
- HDFC doesn't know the transaction is "pending" at NPCI — HDFC's record says "completed"
- Rahul's daily limit: ₹500 already counted toward ₹1 lakh limit

If Rahul tries to pay ₹1,000 in the second payment:
- HDFC allows it (₹1,500 available, ₹1,000 requested)
- Second transaction succeeds

**Simultaneously, NPCI's recovery process for the first transaction:**

```
NPCI's automatic recovery daemon:
1. Every 2 minutes: scan for PENDING transactions older than 5 minutes
2. Found: TXN2024111503045001 is PENDING, 8 minutes old
3. Query HDFC: "Did you process TXN2024111503045001?"
4. HDFC: "Yes, debited at 10:30:47, reference HDFC20241115103046789"
5. NPCI: "OK, now send credit to SBI"
6. SBI: "₹500 credited to priya@oksbi"
7. NPCI: Transaction marked COMPLETE. UTR assigned.
8. PhonePe: Receives "COMPLETE" webhook
9. PhonePe updates DB, sends notification to Rahul: "Your ₹500 payment to Priya Sharma is complete."
```

**Total recovery time: 8–15 minutes in this case**

**The nightmare scenario:**
- NPCI recovery daemon queries HDFC but HDFC is down for 2 hours (rare but happens)
- NPCI waits, retries every 5 minutes
- After 2 hours, HDFC responds, recovery proceeds
- Total time: 2–3 hours
- During this time, Rahul has ₹500 missing with no explanation

This is why UPI apps show "Transaction in Progress. Do not retry." with an estimated time — to prevent users from panicking and trying again (which would cause a genuine double payment).

---

### Q11: "What would you improve about UPI's observability stack to detect the next large-scale attack faster?"

**Answer:**

**Current gaps (publicly known limitations):**

1. **Distributed tracing across organizations:** PhonePe can trace from user to their server to NPCI. But NPCI's internal traces are not shared with PSPs. When HDFC is slow, PhonePe sees "timeout" but not "HDFC's CBS queue depth is 10,000." Real cross-organization observability requires a shared telemetry standard (like OpenTelemetry) adopted by all participants.

2. **Real-time anomaly detection on transaction graphs:** Current fraud detection is largely per-transaction. Network-level fraud (money mule rings, layered transactions) requires graph analysis that runs with minutes/hours of delay. Real-time graph streaming analysis (Apache Flink + graph algorithms) would detect complex fraud patterns in seconds.

**What I'd add:**

```
1. Centralized UPI Health Dashboard (NPCI-operated):
   - Real-time TPS per bank
   - p99 latency per bank
   - Pending transaction counts per bank
   - Available to all PSPs via read-only API
   - Purpose: PSPs can detect HDFC slowdown before users report it

2. Synthetic transactions (canary payments):
   - Every 30 seconds: automated system makes a real ₹1 payment
     from a monitoring account to another monitoring account
   - Measures: end-to-end latency, success rate
   - Alert if: latency > 5s or success rate < 100% in last 5 minutes
   - Purpose: catch degradation before users do

3. Anomaly detection on velocity:
   - Real-time streaming: track average TPS per bank pair (HDFC→SBI) in last 5 minutes
   - Alert if: current TPS is 3x the 7-day average for that time slot
   - Could indicate: bot attack, system generating spurious transactions, legitimate viral event

4. Cross-PSP fraud signal sharing:
   - If PhonePe marks VPA X as fraudulent: share (with privacy controls) with all PSPs via NPCI
   - Currently, each PSP has its own fraud signals; sharing would block scammers faster
   - Privacy concern: balance fraud prevention vs. competitive sensitivity

5. UPI packet-level anomaly detection:
   - At NPCI's ingress: ML model on the XML message features
   - Detect: unusual XML structure, unusual field values, injection attempts
   - Real-time, before routing to banks
```

---

*Document version: 1.0 | Classification: Internal Engineering | Author: Engineering Team*  
*This document describes UPI architecture as publicly documented by NPCI and industry sources.*  
*Actual NPCI internal implementation details are not public and are inferred from behavior, regulatory filings, and industry publications.*  
*For official UPI documentation, refer to NPCI's website: https://www.npci.org.in/what-we-do/upi/product-overview*

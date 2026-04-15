# CRYPTOGRAPHY STUDY MATERIAL (BASIC → PRACTICAL)
Version: April 2026
Audience: beginner/intermediate security learner; wants strong fundamentals + practical intuition
Prereqs (recommended): networking + OS basics from [cybersecurity_fundamentals_study_material.md](cybersecurity_fundamentals_study_material.md)


## Generated Table of Contents
- [HOW TO USE THIS DOCUMENT](#how-to-use-this-document)
- [- Read in order. Crypto concepts build on each other.](#read-in-order-crypto-concepts-build-on-each-other)
- [C0) The 5 security goals (what crypto is actually for)](#c0-the-5-security-goals-what-crypto-is-actually-for)
- [1) Confidentiality](#1-confidentiality)
- [C0A) The most common confusions (with clear examples)](#c0a-the-most-common-confusions-with-clear-examples)
- [Confusion 1: “Hashing encrypts data”](#confusion-1-hashing-encrypts-data)
- [C1) Threat models and attacker capabilities](#c1-threat-models-and-attacker-capabilities)
- [You cannot choose crypto without a threat model.](#you-cannot-choose-crypto-without-a-threat-model)
- [C1A) CPA/CCA in plain language (why you should care)](#c1a-cpacca-in-plain-language-why-you-should-care)
- [CPA (chosen-plaintext) intuition](#cpa-chosen-plaintext-intuition)
- [C2) Math basics (only what you need)](#c2-math-basics-only-what-you-need)
- [You do not need advanced math for practical crypto, but you must understand:](#you-do-not-need-advanced-math-for-practical-crypto-but-you-must-understand)
  - [2.1 Modular arithmetic](#21-modular-arithmetic)
  - [2.2 Groups (intuition)](#22-groups-intuition)
  - [2.3 One-way functions (intuition)](#23-one-way-functions-intuition)
  - [2.4 Randomness](#24-randomness)
- [C2A) Entropy and randomness (practical detail)](#c2a-entropy-and-randomness-practical-detail)
- [Entropy intuition](#entropy-intuition)
- [C3) Symmetric cryptography](#c3-symmetric-cryptography)
- [Symmetric crypto uses ONE shared secret key.](#symmetric-crypto-uses-one-shared-secret-key)
  - [3.1 Block ciphers vs stream ciphers](#31-block-ciphers-vs-stream-ciphers)
  - [3.2 AES (what to know)](#32-aes-what-to-know)
  - [3.3 Modes (critical)](#33-modes-critical)
  - [3.4 Stream cipher pitfall (must memorize)](#34-stream-cipher-pitfall-must-memorize)
  - [3.5 What you should use in practice](#35-what-you-should-use-in-practice)
  - [3.6 What AEAD means (clear and practical)](#36-what-aead-means-clear-and-practical)
  - [3.7 Nonces/IVs (how to not break AEAD)](#37-noncesivs-how-to-not-break-aead)
  - [3.8 If you can’t use AEAD](#38-if-you-cant-use-aead)
  - [3.9 Symmetric encryption checklist](#39-symmetric-encryption-checklist)
- [C4) Hash functions and message authentication](#c4-hash-functions-and-message-authentication)
- [4.1 Hash functions](#41-hash-functions)
  - [4.2 Common hashes](#42-common-hashes)
  - [4.3 MACs (Message Authentication Codes)](#43-macs-message-authentication-codes)
  - [4.4 Why plain hash is not a MAC](#44-why-plain-hash-is-not-a-mac)
  - [4.6 KDFs (Key Derivation Functions) and HKDF (brief primer)](#46-kdfs-key-derivation-functions-and-hkdf-brief-primer)
  - [4.5 AEAD vs “Encrypt + MAC”](#45-aead-vs-encrypt-mac)
- [C5) Password hashing (different from hashing)](#c5-password-hashing-different-from-hashing)
- [Passwords are low-entropy; attackers brute force them.](#passwords-are-low-entropy-attackers-brute-force-them)
  - [5.1 Use slow password hashes](#51-use-slow-password-hashes)
  - [5.4 Verification and side-channel hygiene](#54-verification-and-side-channel-hygiene)
  - [5.2 Salt and pepper](#52-salt-and-pepper)
  - [5.3 What NOT to do](#53-what-not-to-do)
- [C6) Public-key cryptography (asymmetric)](#c6-public-key-cryptography-asymmetric)
- [Asymmetric crypto uses a key pair:](#asymmetric-crypto-uses-a-key-pair)
  - [6.1 What it enables](#61-what-it-enables)
  - [6.2 RSA (high-level)](#62-rsa-high-level)
  - [6.3 Elliptic curves (high-level)](#63-elliptic-curves-high-level)
- [C7) Key exchange and forward secrecy](#c7-key-exchange-and-forward-secrecy)
- [7.1 Diffie–Hellman (DH) intuition](#71-diffiehellman-dh-intuition)
  - [7.2 Forward secrecy](#72-forward-secrecy)
- [C8) Digital signatures](#c8-digital-signatures)
- [8.1 What signatures provide](#81-what-signatures-provide)
  - [8.2 Common algorithms](#82-common-algorithms)
  - [8.3 Signature pitfalls](#83-signature-pitfalls)
- [C9) PKI, certificates, and trust](#c9-pki-certificates-and-trust)
- [9.1 Certificates](#91-certificates)
  - [9.2 Chain of trust](#92-chain-of-trust)
  - [9.3 Certificate validation (what matters)](#93-certificate-validation-what-matters)
  - [9.4 Practical mistakes](#94-practical-mistakes)
- [C10) TLS (why HTTPS works)](#c10-tls-why-https-works)
- [10.1 What TLS does](#101-what-tls-does)
  - [10.2 Handshake (conceptual)](#102-handshake-conceptual)
  - [10.3 What to remember for security work](#103-what-to-remember-for-security-work)
  - [10.4 Practical checks](#104-practical-checks)
- [C11) Randomness, nonces, IVs (the silent killer)](#c11-randomness-nonces-ivs-the-silent-killer)
- [11.1 Nonce vs IV vs salt](#111-nonce-vs-iv-vs-salt)
  - [11.2 Rules you must memorize](#112-rules-you-must-memorize)
  - [11.3 Quick cheat rules (nonce/IV/salt)](#113-quick-cheat-rules-nonceivsalt)
  - [11.4 Randomness in VMs/containers (awareness)](#114-randomness-in-vmscontainers-awareness)
- [C12) Common cryptographic mistakes (real-world)](#c12-common-cryptographic-mistakes-real-world)
- [1) Using encryption without integrity](#1-using-encryption-without-integrity)
- [C13) Key management (what matters in industry)](#c13-key-management-what-matters-in-industry)
- [13.1 Key lifecycle](#131-key-lifecycle)
  - [13.2 Where keys should live](#132-where-keys-should-live)
  - [13.3 Separation](#133-separation)
  - [13.4 Envelope encryption (industry standard)](#134-envelope-encryption-industry-standard)
- [C14) Practical exercises and mini-labs (safe)](#c14-practical-exercises-and-mini-labs-safe)
- [E1) Hashing and HMAC](#e1-hashing-and-hmac)
- [C15) Minimal crypto API guidance (Python and Java)](#c15-minimal-crypto-api-guidance-python-and-java)
- [Goal: know what to reach for; not full code.](#goal-know-what-to-reach-for-not-full-code)
- [C16) Resource index (high-quality and beginner-friendly)](#c16-resource-index-high-quality-and-beginner-friendly)
- [Free courses / lecture series](#free-courses-lecture-series)
- [C17) Quick checklist (what you should be able to explain)](#c17-quick-checklist-what-you-should-be-able-to-explain)
- [- [ ] Why encryption without integrity is dangerous](#why-encryption-without-integrity-is-dangerous)

---

## HOW TO USE THIS DOCUMENT
## - Read in order. Crypto concepts build on each other.
- After each module:
  1) do the exercises (paper + small code)
  2) write a 1-page “cheat sheet” summary
  3) add 10 flashcards

Important rule
- Do not “roll your own crypto” in real systems.
- Learn crypto to (a) choose the right primitives, (b) use libraries safely, (c) avoid common mistakes.


## C0) The 5 security goals (what crypto is actually for)
## 1) Confidentiality
- Keep data secret from unauthorized parties.
- Achieved with encryption.

2) Integrity
- Detect modification.
- Achieved with MACs, hashes (for some use cases), AEAD, signatures.

3) Authenticity
- Prove who created a message.
- Achieved with MACs (shared key) or signatures (public key).

4) Non-repudiation (limited, nuanced)
- A signer cannot plausibly deny signing (in a legal/operational sense).
- Achieved with digital signatures + good key management + audit.

5) Freshness / anti-replay
- Ensure a message is not a replay of an old valid message.
- Achieved with nonces, timestamps, sequence numbers, and protocols.

Big idea
- Encryption alone does NOT guarantee integrity or authenticity.


## C0A) The most common confusions (with clear examples)
## Confusion 1: “Hashing encrypts data”
- Hashing is one-way. You cannot get the original message back.
- Use case: integrity checks, fingerprints, indexing, some protocol building blocks.

Example
- You download a file + its SHA-256 checksum.
- You hash the file locally; if it matches, it likely wasn’t modified.

Confusion 2: “Base64 is encryption”
- Base64 is only encoding (binary → text). It provides zero secrecy.

Example
- base64("secret") = "c2VjcmV0". Anyone can decode it.

Confusion 3: “Encryption proves who sent the message”
- Encryption (alone) does not prove sender identity.
- To prove integrity/authenticity you need:
  - a MAC (shared secret)
  - a digital signature (public key)
  - or AEAD (encryption + integrity)

Confusion 4: “If it’s HTTPS, the application is secure”
- TLS secures the connection.
- App-level bugs (IDOR, injection, SSRF, auth bypass) still exist.

Mini-check
- If you can explain hash vs MAC vs signature with one real example each, you’re ready for most practical crypto decisions.


## C1) Threat models and attacker capabilities
## You cannot choose crypto without a threat model.

Common models
- Passive eavesdropper: can read traffic.
- Active attacker: can modify/inject/drop/replay messages.
- Chosen-plaintext attacker (CPA): can ask to encrypt chosen messages.
- Chosen-ciphertext attacker (CCA): can ask to decrypt chosen ciphertexts.
- Insider: has some keys or some access.

Practical mapping
- Web traffic: assume active attacker (MITM) unless TLS is correct.
- Storage encryption: assume attacker may steal disk/snapshot; keys must be separate.


## C1A) CPA/CCA in plain language (why you should care)
## CPA (chosen-plaintext) intuition
- Attacker can ask the system to encrypt attacker-chosen messages.
- Many real systems do this naturally (APIs encrypt user data, cookies, tokens).

CCA (chosen-ciphertext) intuition
- Attacker can submit ciphertexts and learn something from how the system reacts.
- Even without a direct decryption API, differences in error messages or timing can act like a decryption oracle.

Classic example: padding oracle (high-level)
- System decrypts AES-CBC, then checks padding.
- If it returns different errors (or different timing) for “bad padding” vs “bad MAC/parse”, attacker can iteratively learn plaintext.

Practical takeaway
- Prefer AEAD (AES-GCM, ChaCha20-Poly1305).
- Don’t leak detailed decryption/parse failures.

Exercises
- Explain how “different error messages” can leak secret information.
- In your own words: why does AEAD reduce oracle-style failures?


## C2) Math basics (only what you need)
## You do not need advanced math for practical crypto, but you must understand:

### 2.1 Modular arithmetic
- “mod n” means wrap-around arithmetic.
- Example: 17 mod 5 = 2.

### 2.2 Groups (intuition)
- A set with an operation (like addition mod p).
- Some groups make “hard problems” (discrete log) that enable public-key crypto.

### 2.3 One-way functions (intuition)
- Easy to compute, hard to invert.

### 2.4 Randomness
- Security often collapses if randomness is weak.
- Use a cryptographic RNG (CSPRNG).

Exercises
- Compute a few modular additions/multiplications.
- Explain why “random()” in many languages is not for crypto.


## C2A) Entropy and randomness (practical detail)
## Entropy intuition
- Entropy is a measure of unpredictability.
- Keys must be unpredictable to attackers.

Rules of thumb
- Passwords and human secrets are low-entropy.
- Random keys (e.g., 128-bit and above) are high-entropy.

Where randomness should come from
- Operating system CSPRNG.
- High-level APIs:
  - Python: secrets (token_bytes, token_urlsafe)
  - Java: SecureRandom

Nonce vs IV vs salt (previews; details later)
- Nonce: “number used once” (usually must be unique; not necessarily secret)
- IV: initialization vector (often must be unpredictable in CBC)
- Salt: random value stored with a password hash

Common failure patterns
- Predictable seeds (time-based) → predictable outputs.
- Reusing nonces in AEAD/CTR.
- Generating keys at early boot in low-entropy environments (rare on modern systems but still worth awareness).


## C3) Symmetric cryptography
## Symmetric crypto uses ONE shared secret key.

### 3.1 Block ciphers vs stream ciphers
- Block cipher: encrypts fixed-size blocks (e.g., AES: 128-bit blocks).
- Stream cipher: generates a keystream XORed with plaintext (e.g., ChaCha20).

### 3.2 AES (what to know)
- AES is a block cipher standard.
- Security depends on key length and correct mode.
- AES itself is not “a mode”; you must choose a mode.

### 3.3 Modes (critical)
- ECB (bad): identical plaintext blocks → identical ciphertext blocks.
- CBC: needs random IV; encryption provides confidentiality but NOT integrity.
- CTR: turns block cipher into stream cipher; never reuse nonce/IV.
- GCM (AEAD): provides confidentiality + integrity when used correctly.

### 3.4 Stream cipher pitfall (must memorize)
- Never reuse a nonce with the same key in CTR/ChaCha20.
- Reuse leaks relationships between plaintexts.

### 3.5 What you should use in practice
- Prefer AEAD:
  - AES-GCM (widely supported)
  - ChaCha20-Poly1305 (great on many CPUs/mobile)

### 3.6 What AEAD means (clear and practical)
AEAD = Authenticated Encryption with Associated Data
- Encrypts plaintext and authenticates it.
- Optionally authenticates additional metadata (AAD) without encrypting it.

AAD (Associated Data) example
- You transmit: version, userId, timestamp, ciphertext.
- You might keep version/userId readable, but you must prevent tampering.
- Put version/userId/timestamp in AAD.

### 3.7 Nonces/IVs (how to not break AEAD)
- AEAD modes require a nonce (often 12 bytes for AES-GCM / ChaCha20-Poly1305).
- Requirement: nonce must be UNIQUE for each message under the same key.

Nonce strategy (practical)
- Generate a fresh random nonce per message using OS CSPRNG.
- Store/transmit the nonce alongside ciphertext (nonce is typically not secret).

Catastrophic failure to memorize
- Reusing an AES-GCM nonce with the same key can completely break confidentiality and integrity.

### 3.8 If you can’t use AEAD
- If forced to use CBC/CTR for compatibility, pair encryption with a MAC.
- Composition rule: Encrypt-then-MAC.

### 3.9 Symmetric encryption checklist
- [ ] AEAD chosen (AES-GCM or ChaCha20-Poly1305)
- [ ] Unique nonce per message
- [ ] Nonce stored with ciphertext
- [ ] AAD authenticates important headers/metadata
- [ ] No detailed decryption error leakage

Exercises
- Explain why ECB leaks patterns.
- Explain why “encrypt-then-MAC” is a safe composition (historically).


## C4) Hash functions and message authentication
## 4.1 Hash functions
- Map arbitrary input → fixed-length output.
- Properties (idealized):
  - preimage resistance
  - second-preimage resistance
  - collision resistance

### 4.2 Common hashes
- SHA-256 (good)
- SHA-3 (good)
- MD5/SHA-1 (broken for collisions; do not use for security)

### 4.3 MACs (Message Authentication Codes)
- Provide integrity + authenticity with a shared secret.
- HMAC-SHA-256 is standard.

### 4.4 Why plain hash is not a MAC
- Hash(message) is not authenticated.
- Hash(key || message) can be broken depending on construction (length extension for Merkle–Damgård hashes like SHA-256).

4.4A Length extension (clear explanation)
Many hashes (SHA-256 included) are built so that if you know:
- message
- hash(message)
you can sometimes compute:
- hash(message || padding || extra)
without knowing the original internal state.

So if you do a naive MAC like:
- tag = SHA256(key || message)
an attacker might forge a valid tag for:
- message || padding || attacker_controlled
without knowing the key.

4.4B Why HMAC is the standard MAC
- HMAC wraps the hash in a construction that prevents length extension.
- It is widely analyzed and safe when used correctly.

### 4.6 KDFs (Key Derivation Functions) and HKDF (brief primer)
KDFs derive one or more keys from some initial secret.

Why you need a KDF
- After key exchange (DH/ECDH), you get a shared secret.
- You should derive separate keys for separate purposes:
  - encryption key
  - authentication key
  - other context-specific keys

HKDF (HMAC-based Key Derivation Function)
- Two phases: Extract (compress entropy) + Expand (generate keys)
- Built from HMAC with an "info/context" input
- Keys are bound to their purpose via the info parameter
- Safe for deriving multiple keys from one secret
- NOT for passwords (no iteration/memory hardness)

Python example (using cryptography library):
```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

# Derive a 256-bit key from shared secret
shared_secret = os.urandom(32)  # e.g., from DH/ECDH
salt = os.urandom(16)  # random, can be public
info = b"encryption-key-v1"  # context/purpose label

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=info
)
derived_key = hkdf.derive(shared_secret)

# Derive a separate MAC key with different info
hkdf_mac = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=b"mac-key-v1"  # different purpose = different key
)
mac_key = hkdf_mac.derive(shared_secret)
```

Rule
- Never reuse the same raw secret across different protocols or purposes; derive purpose-specific keys.

### 4.5 AEAD vs “Encrypt + MAC”
- AEAD (GCM/ChaCha20-Poly1305) gives you encryption + integrity in one.
- If you do separate encryption and MAC, use Encrypt-then-MAC.

Exercises
- Given a scenario (API request signing), choose HMAC vs signatures.


## C5) Password hashing (different from hashing)
## Passwords are low-entropy; attackers brute force them.

### 5.1 Use slow password hashes
- Argon2id (preferred)
- bcrypt
- scrypt

5.1A PBKDF2 (common in legacy/enterprise systems)
- PBKDF2 is widely available (especially in Java).
- It is not memory-hard like Argon2, but still used.
- If you must use PBKDF2:
  - use a modern PRF (HMAC-SHA-256)
  - use a unique random salt
  - use a sufficiently high iteration count per current guidance

5.1B Parameters matter (why “just bcrypt” is not enough)
- These algorithms have tunable cost parameters.
- The goal is to make offline guessing expensive.
- You should be able to explain what the parameter does:
  - bcrypt: cost factor
  - Argon2id: memory, iterations, parallelism

### 5.4 Verification and side-channel hygiene
- Use constant-time comparisons for hashes/tags where applicable.
- Avoid user enumeration:
  - don’t reveal “user exists” via different messages
  - be careful about timing differences

### 5.2 Salt and pepper
- Salt: per-password random value stored with the hash; stops rainbow tables.
- Pepper: secret value stored separately (e.g., in KMS/secret store); optional defense.

### 5.3 What NOT to do
- Never store passwords with SHA-256/MD5.
- Never “encrypt passwords” and store reversible form.

Exercises
- Explain why salts must be unique.


## C6) Public-key cryptography (asymmetric)
## Asymmetric crypto uses a key pair:
- public key (share)
- private key (protect)

### 6.1 What it enables
- Key exchange (establish shared secrets)
- Digital signatures
- Identity without pre-shared secrets

### 6.2 RSA (high-level)
- Based on difficulty of factoring large integers.
- Common mistakes are padding/usage errors (don’t implement yourself).

6.2A RSA used correctly (what to remember)
- Encryption: use RSA-OAEP (not “raw RSA”).
- Signatures: use RSA-PSS.
- Padding is not a detail; it’s part of the security.

6.2B Hybrid encryption (how it’s done in real systems)
Public-key crypto is slow and limited in message size.
So systems typically:
1) generate a random symmetric key (DEK)
2) encrypt data with AEAD using that DEK
3) encrypt (wrap) the DEK with the recipient’s public key (or with a KMS key)

This pattern appears in TLS and in envelope encryption for storage.

### 6.3 Elliptic curves (high-level)
- ECDH for key agreement.
- ECDSA/EdDSA for signatures.
- Modern recommendation: X25519 (key agreement) and Ed25519 (signatures).


## C7) Key exchange and forward secrecy
## 7.1 Diffie–Hellman (DH) intuition
- Two parties establish a shared secret over an insecure channel.
- Must authenticate to prevent MITM.

7.1A What “authenticate DH” means
- You must bind the key exchange to an identity.
- Common methods:
  - certificates (TLS)
  - pre-shared keys (PSK)
  - signing the handshake transcript

If you don’t authenticate
- MITM performs two handshakes and relays traffic.

### 7.2 Forward secrecy
- If long-term key is later stolen, past sessions remain secure.
- Achieved using ephemeral DH (DHE/ECDHE).

Exercises
- Explain why DH without authentication is vulnerable to MITM.


## C8) Digital signatures
## 8.1 What signatures provide
- Integrity + authenticity + (often) non-repudiation.

### 8.2 Common algorithms
- RSA-PSS
- ECDSA
- Ed25519

### 8.3 Signature pitfalls
- Reusing nonce in ECDSA can leak private key.
- Verify the right data (context binding matters).

Exercises
- Describe when you should use signatures instead of HMAC.


## C9) PKI, certificates, and trust
## 9.1 Certificates
- A certificate binds a public key to an identity.
- Issued by a CA.

### 9.2 Chain of trust
- Root CA → Intermediate CA → Leaf cert.

### 9.3 Certificate validation (what matters)
- hostname matches
- validity period
- key usage
- revocation is complicated; operational controls matter

### 9.4 Practical mistakes
- accepting invalid certs (“ignore TLS errors”)
- not validating hostname
- using self-signed certs incorrectly in production


## C10) TLS (why HTTPS works)
## 10.1 What TLS does
- Negotiates keys and secures a channel.
- Provides confidentiality + integrity.

### 10.2 Handshake (conceptual)
- ClientHello / ServerHello
- certificate presented
- key agreement (ECDHE)
- derive session keys

10.2A TLS 1.2 vs TLS 1.3 (what changes in practice)
TLS 1.3
- Removes many legacy/weak options.
- Strong forward secrecy is standard.
- Simpler ciphersuite selection.

You will see these terms in tooling
- SNI (Server Name Indication): the hostname can be visible to network observers (unless using ECH).
- ALPN: negotiates application protocol (HTTP/2 vs HTTP/1.1).
- Session resumption: faster connections; still must be implemented safely.
- 0-RTT (TLS 1.3): can be replayed; avoid for state-changing requests.

10.2B mTLS (mutual TLS) in one paragraph
- Client also presents a certificate.
- Useful for service-to-service authentication.
- Still requires authorization (mTLS answers “who are you?”, not “what are you allowed to do?”).

### 10.3 What to remember for security work
- Most breakages are not “TLS is broken”; they are:
  - misconfiguration
  - weak ciphers allowed
  - certificate validation mistakes
  - downgrade issues

### 10.4 Practical checks
- HSTS for web apps.
- Remove legacy protocols.

10.4A Practical TLS checks (security mindset)
- Never disable cert validation in production.
- Prefer modern TLS versions and ciphersuites.
- Ensure hostname validation is correct.
- Watch for “TLS termination” points (load balancers, proxies) and ensure traffic remains protected to the next hop where required.


## C11) Randomness, nonces, IVs (the silent killer)
## 11.1 Nonce vs IV vs salt
- Nonce: number used once (often does not need to be secret).
- IV: initialization vector (often must be unpredictable for some modes like CBC).
- Salt: random value stored with password hash.

### 11.2 Rules you must memorize
- Never reuse a nonce with the same key in GCM/CTR/ChaCha20.
- Always use CSPRNG for keys and nonces.

### 11.3 Quick cheat rules (nonce/IV/salt)
- AES-GCM / ChaCha20-Poly1305: nonce must be unique per key (often 12 bytes).
- AES-CBC: IV should be random/unpredictable.
- Password hashing: salt must be unique + random; it is stored with the hash.

### 11.4 Randomness in VMs/containers (awareness)
- Modern OSs handle this well, but early-boot entropy issues can exist in some environments.
- Practical takeaway: don’t invent RNG; use OS-backed APIs.


## C12) Common cryptographic mistakes (real-world)
## 1) Using encryption without integrity
- Example: AES-CBC without MAC → padding oracle class of problems.

2) Reusing nonces
- Example: AES-GCM nonce reuse breaks confidentiality and can break integrity.

3) Rolling your own crypto
- Custom algorithms and homegrown protocols fail.

4) Wrong primitive for job
- Example: using SHA-256 to store passwords.

5) Key management ignored
- Keys in source code, keys never rotated, shared keys across environments.

6) Confusing encoding with encryption
- Base64 is not encryption.

7) Broken randomness
- Using non-crypto PRNG for keys.

8) Side channels (awareness)
- Timing differences, error messages, padding errors.


## C13) Key management (what matters in industry)
## 13.1 Key lifecycle
- generation
- storage
- rotation
- revocation
- backup
- destruction

### 13.2 Where keys should live
- KMS/HSM for sensitive keys.
- App should not embed long-term master keys.

### 13.3 Separation
- Separate dev/test/prod keys.
- Separate signing keys from encryption keys.

### 13.4 Envelope encryption (industry standard)
- Use a master key in KMS to wrap data keys.


## C14) Practical exercises and mini-labs (safe)
## E1) Hashing and HMAC
- Compute SHA-256 of a file.
- Compute HMAC of a message and show verification fails after a byte flip.

Suggested Python practice
- Use hmac + hashlib.
- Verify using constant-time compare (hmac.compare_digest).

E2) Password hashing
- Hash a password with Argon2id (or bcrypt) and verify.

Suggested practice
- Store: algorithm + parameters + salt + hash.
- Verify: recompute with same parameters and compare in constant-time.

E3) AEAD encryption
- Encrypt and decrypt a message with AES-GCM or ChaCha20-Poly1305.
- Show that modifying ciphertext causes verification failure.

Suggested storage format
- nonce || ciphertext || tag (some libraries return ciphertext+tag together)
- nonce is not secret; it must be unique.

E4) TLS observation
- Use your browser dev tools or Wireshark to observe TLS handshake fields.
- Identify certificate chain.

Extra tasks
- Identify the TLS version negotiated.
- Identify issuer/subject and SAN.
- Check whether HSTS is set for the site.

E5) Common mistake simulation (education)
- Demonstrate why ECB leaks patterns using a toy example.

E6) Nonce reuse demonstration (education)
- In a toy CTR-like scheme: encrypt two different plaintexts with same key+nonce.
- Observe that XOR(ciphertexts) = XOR(plaintexts).

E7) “Encrypt without integrity” demonstration (education)
- In a toy scheme, flip bits in ciphertext and observe controlled plaintext changes.
- Connect this to why AEAD is required.


## C15) Minimal crypto API guidance (Python and Java)
## Goal: know what to reach for; not full code.

Python
- Use the “cryptography” package.
- Prefer:
  - AESGCM / ChaCha20Poly1305 for AEAD
  - HMAC for request signing (shared secret)
  - Argon2/bcrypt for password hashing (via dedicated libs)
- Use secrets module for random tokens.

Java
- Use modern JCA/JCE APIs and well-reviewed libraries.
- Prefer:
  - AES/GCM/NoPadding
  - PBKDF2 (built-in) or bcrypt/argon2 via vetted libs
  - Signature with RSA-PSS or Ed25519 (depending on platform)

Library hygiene
- Don’t disable certificate validation.
- Don’t reuse nonces.
- Don’t invent serialization formats for signed data; use established formats.


## C16) Resource index (high-quality and beginner-friendly)
## Free courses / lecture series
- Dan Boneh (Stanford) Cryptography I (classic): [https://crypto.stanford.edu/~dabo/courses/OnlineCrypto/](https://crypto.stanford.edu/~dabo/courses/OnlineCrypto/)
- MIT OpenCourseWare (crypto-related courses): [https://ocw.mit.edu/](https://ocw.mit.edu/)

Beginner-friendly references
- Crypto 101 (free book): [https://crypto101.io/](https://crypto101.io/)

Practice (high ROI)
- CryptoPals challenges: [https://cryptopals.com/](https://cryptopals.com/)

Books (excellent)
- Serious Cryptography (Jean-Philippe Aumasson)
- Cryptography Engineering (Ferguson, Schneier, Kohno)
- Real-World Cryptography (David Wong)

Standards / references
- NIST Crypto standards landing: [https://csrc.nist.gov/](https://csrc.nist.gov/)
- RFC Editor (TLS, JWT, etc.): [https://www.rfc-editor.org/](https://www.rfc-editor.org/)

Useful NIST references (for deeper understanding)
- SP 800-38D (GCM): [https://csrc.nist.gov/publications/detail/sp/800-38d/final](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- SP 800-132 (password-based key derivation guidance): [https://csrc.nist.gov/publications/detail/sp/800-132/final](https://csrc.nist.gov/publications/detail/sp/800-132/final)

Web/app crypto best practices
- OWASP Cryptographic Storage Cheat Sheet: [https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- OWASP Password Storage Cheat Sheet: [https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

Library docs (learn safe-by-default APIs)
- Python cryptography docs: [https://cryptography.io/en/latest/](https://cryptography.io/en/latest/)
- libsodium docs: [https://doc.libsodium.org/](https://doc.libsodium.org/)
- Google Tink: [https://developers.google.com/tink](https://developers.google.com/tink)

Tools
- OpenSSL (reference tool, not a library recommendation): [https://www.openssl.org/](https://www.openssl.org/)

YouTube (good reinforcement)
- Computerphile (intuitive explanations): [https://www.youtube.com/user/Computerphile](https://www.youtube.com/user/Computerphile)


## C17) Quick checklist (what you should be able to explain)
## - [ ] Why encryption without integrity is dangerous
- [ ] Difference: hash vs MAC vs signature
- [ ] Why nonces/IVs matter and when reuse breaks security
- [ ] What AEAD is and why it’s preferred
- [ ] How password hashing differs from hashing
- [ ] What PKI is and how TLS uses certificates
- [ ] What forward secrecy means
- [ ] Why key management is as important as algorithms

---

# CRYPTOGRAPHY DEEP DIVE ADDENDUM

## CD1) Post-Quantum Cryptography Awareness

### CD1.1 Why This Matters Now

**The Threat:**
- Quantum computers (when sufficiently powerful) can break:
  - RSA (factoring)
  - ECDSA/ECDH (discrete log)
  - Diffie-Hellman
- They CANNOT easily break:
  - AES (but may need larger keys: AES-256)
  - SHA-256/SHA-3 (need larger outputs for same security)

**"Harvest Now, Decrypt Later" Attack:**
```
Today: Attacker captures encrypted traffic
Future: Quantum computer decrypts the captured data

This is a real threat for data that must remain secret for decades:
- Government secrets
- Medical records
- Long-term business secrets
```

### CD1.2 NIST Post-Quantum Standards (2024)

NIST has standardized post-quantum algorithms:

**For Key Encapsulation (replacing RSA/ECDH for key exchange):**
- **ML-KEM (CRYSTALS-Kyber)** - Primary recommendation
  - Based on lattice problems
  - Relatively small keys and ciphertexts
  - Already being deployed in Chrome, Cloudflare, etc.

**For Digital Signatures (replacing RSA/ECDSA):**
- **ML-DSA (CRYSTALS-Dilithium)** - Primary recommendation
- **SLH-DSA (SPHINCS+)** - Stateless hash-based (conservative choice)

### CD1.3 What You Need to Know (Practical)

**Current State (2026):**
```
1. Hybrid deployments are starting
   - TLS 1.3 with X25519 + ML-KEM
   - Provides protection even if one algorithm breaks

2. Migration is happening gradually
   - Large organizations are inventorying crypto usage
   - Critical systems are being upgraded first

3. You probably don't need to implement PQC yourself
   - Use updated libraries that handle it
   - Focus on crypto agility (easy algorithm switching)
```

**What to do today:**
```python
# Crypto agility pattern
class CryptoConfig:
    """Centralize crypto choices for easy migration."""
    
    # Easy to change when standards update
    SYMMETRIC_ALGORITHM = "AES-256-GCM"
    HASH_ALGORITHM = "SHA-256"  # Consider SHA-3 for new systems
    KEY_EXCHANGE = "X25519"  # Will migrate to hybrid X25519+ML-KEM
    SIGNATURE = "Ed25519"  # Will migrate to ML-DSA
    
    @classmethod
    def get_kex_algorithm(cls):
        """Returns current key exchange algorithm."""
        return cls.KEY_EXCHANGE
```

### CD1.4 Timeline and Recommendations

```
2024-2026: Awareness and planning
  - Inventory your crypto usage
  - Update libraries to latest versions
  - Enable hybrid modes where available

2026-2030: Migration begins
  - Critical systems adopt PQC
  - Browsers/TLS widely support hybrid
  - Old algorithms deprecated

2030+: Post-quantum becomes standard
  - Pure PQC for new systems
  - Legacy systems upgraded or isolated
```

**Key Takeaway:** You don't need to become a PQC expert, but you should:
1. Know it's coming
2. Keep your crypto libraries updated
3. Design systems for crypto agility


## CD2) Real-World Crypto Failures (Case Studies)

### CD2.1 Case Study: WEP (Why Bad Crypto Breaks)

**What went wrong:**
```
1. Weak IV (24 bits) → collisions after ~5000 packets
2. IV transmitted in cleartext → attacker knows part of keystream
3. Linear combination attack on RC4 → key recovery possible
4. No integrity protection → packet injection possible
```

**Lesson:** Even "strong" algorithms fail with bad protocol design.

### CD2.2 Case Study: Heartbleed (Implementation Failure)

**What went wrong:**
```
1. OpenSSL's TLS heartbeat extension didn't validate length field
2. Attacker could request more data than was sent
3. Server returned adjacent memory (keys, passwords, session data)
```

**Lesson:** Crypto is only as strong as its implementation.

### CD2.3 Case Study: Padding Oracle (CBC Mode Attacks)

**What went wrong:**
```
1. Server decrypts CBC ciphertext
2. Server checks padding BEFORE checking MAC
3. Different errors for "bad padding" vs "bad MAC"
4. Attacker uses timing/error differences to decrypt byte-by-byte
```

**Lesson:** This is why AEAD (encrypt-then-MAC built-in) is required.

```python
# VULNERABLE pattern
def vulnerable_decrypt(ciphertext, key):
    plaintext = aes_cbc_decrypt(ciphertext, key)
    if not valid_padding(plaintext):  # Reveals information!
        raise PaddingError()
    if not valid_mac(plaintext):
        raise MacError()
    return plaintext

# SECURE pattern (use AEAD)
def secure_decrypt(ciphertext, key, nonce):
    try:
        return aes_gcm_decrypt(ciphertext, key, nonce)  # Single operation
    except:
        raise DecryptionError()  # Same error for any failure
```

### CD2.4 Case Study: JWT alg=none

**What went wrong:**
```
1. JWT libraries supported "alg": "none" (no signature)
2. Attackers changed algorithm from HS256 to none
3. Removed signature entirely
4. Servers accepted unsigned tokens
```

**Lesson:** Always use allowlists for algorithms.

```python
# VULNERABLE
decoded = jwt.decode(token, key)  # Accepts any algorithm!

# SECURE
decoded = jwt.decode(token, key, algorithms=["HS256"])  # Allowlist!
```


## CD3) Crypto in Different Contexts

### CD3.1 Crypto for Web Applications

**Session Tokens:**
```python
import secrets

# Generate cryptographically secure session token
session_token = secrets.token_urlsafe(32)  # 256 bits of entropy
```

**Password Storage:**
```python
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=4       # threads
)

# Store
hash = ph.hash(password)

# Verify
try:
    ph.verify(hash, password)
except:
    return False
```

**API Request Signing:**
```python
import hmac
import hashlib
import time

def sign_request(api_key, method, path, body, timestamp):
    """Sign API request with HMAC-SHA256."""
    message = f"{timestamp}\n{method}\n{path}\n{body}"
    signature = hmac.new(
        api_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature
```

### CD3.2 Crypto for Data at Rest

**Envelope Encryption Pattern:**
```
1. Generate a unique Data Encryption Key (DEK) for each file/record
2. Encrypt data with DEK (AES-256-GCM)
3. Encrypt DEK with Key Encryption Key (KEK) from KMS
4. Store: encrypted_data + encrypted_DEK

Benefits:
- Fast (symmetric encryption for data)
- Secure (KEK protected by HSM)
- Scalable (can rotate KEK without re-encrypting data)
```

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def envelope_encrypt(plaintext, kek_encrypt_func):
    """Envelope encryption pattern."""
    # Generate unique DEK
    dek = os.urandom(32)  # 256-bit key
    nonce = os.urandom(12)
    
    # Encrypt data with DEK
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Encrypt DEK with KEK (via KMS)
    encrypted_dek = kek_encrypt_func(dek)
    
    return {
        "encrypted_dek": encrypted_dek,
        "nonce": nonce,
        "ciphertext": ciphertext
    }
```

### CD3.3 Crypto for Communication

**TLS Configuration (Server):**
```yaml
# Modern TLS configuration (2026)
tls:
  minimum_version: TLS1.3  # Or TLS1.2 with careful cipher selection
  
  # TLS 1.3 cipher suites (ordered by preference)
  ciphersuites:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
    - TLS_AES_128_GCM_SHA256
  
  # Enable HSTS
  headers:
    Strict-Transport-Security: "max-age=31536000; includeSubDomains"
```


## CD4) Crypto Anti-Patterns Checklist

Use this checklist to review code for crypto issues:

```yaml
crypto_review_checklist:
  
  algorithm_issues:
    - [ ] Using MD5 or SHA-1 for security purposes
    - [ ] Using DES or 3DES (should be AES)
    - [ ] Using ECB mode (should be GCM/CTR)
    - [ ] Using CBC without proper IV handling
    - [ ] Rolling your own encryption/hashing
    
  key_issues:
    - [ ] Hardcoded keys in source code
    - [ ] Keys derived from predictable values
    - [ ] Same key used across environments
    - [ ] No key rotation mechanism
    - [ ] Keys stored in plaintext logs/configs
    
  randomness_issues:
    - [ ] Using Math.random() / random() for security
    - [ ] Predictable seeds
    - [ ] Reusing nonces/IVs
    - [ ] Insufficient entropy at boot time
    
  password_issues:
    - [ ] Using fast hashes (SHA-256) for passwords
    - [ ] Missing or weak salts
    - [ ] Insufficient work factor
    - [ ] Not using constant-time comparison
    
  protocol_issues:
    - [ ] Encryption without authentication (no AEAD)
    - [ ] MAC-then-encrypt instead of encrypt-then-MAC
    - [ ] Missing certificate validation
    - [ ] Accepting any TLS version/cipher
    
  implementation_issues:
    - [ ] Side-channel leaks (timing, errors)
    - [ ] Partial decryption/verification
    - [ ] Not clearing sensitive data from memory
```


## CD5) Practical Crypto Exercises (Extended)

### Exercise: Implement Secure Password Reset

```python
"""
Secure password reset flow implementation.
Study the security properties of each step.
"""
import secrets
import hashlib
import time
from datetime import datetime, timedelta

class SecurePasswordReset:
    def __init__(self):
        self.reset_tokens = {}  # In production: use database
        self.TOKEN_VALIDITY_MINUTES = 15
    
    def request_reset(self, user_email: str) -> dict:
        """
        Generate secure reset token.
        Security properties:
        - Unpredictable (256 bits of entropy)
        - Time-limited
        - One-time use (consumed on use)
        - Bound to specific user
        """
        # Generate unpredictable token
        token = secrets.token_urlsafe(32)
        
        # Hash for storage (don't store raw token)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Store with metadata
        self.reset_tokens[token_hash] = {
            "email": user_email,
            "created": datetime.utcnow(),
            "used": False
        }
        
        # Return token (send via email, not in response!)
        return {"token": token, "expires_in": self.TOKEN_VALIDITY_MINUTES}
    
    def validate_and_consume_token(self, token: str) -> dict:
        """
        Validate reset token with constant-time comparison.
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        if token_hash not in self.reset_tokens:
            # Don't reveal whether token existed
            time.sleep(0.1)  # Constant time
            return {"valid": False, "reason": "Invalid or expired token"}
        
        record = self.reset_tokens[token_hash]
        
        # Check expiration
        age = datetime.utcnow() - record["created"]
        if age > timedelta(minutes=self.TOKEN_VALIDITY_MINUTES):
            del self.reset_tokens[token_hash]
            return {"valid": False, "reason": "Invalid or expired token"}
        
        # Check not already used
        if record["used"]:
            return {"valid": False, "reason": "Invalid or expired token"}
        
        # Mark as used (consume)
        record["used"] = True
        
        return {"valid": True, "email": record["email"]}

# Test it
reset = SecurePasswordReset()
result = reset.request_reset("user@example.com")
print(f"Reset token: {result['token'][:20]}...")

validation = reset.validate_and_consume_token(result['token'])
print(f"Validation: {validation}")

# Second use should fail
validation2 = reset.validate_and_consume_token(result['token'])
print(f"Second use: {validation2}")
```

END OF CRYPTOGRAPHY STUDY MATERIAL

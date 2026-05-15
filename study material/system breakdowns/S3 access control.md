# Amazon S3 Access Control and Data Flow — Deep Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Reference
> **Audience:** Engineers, Security Reviewers, Cloud Architects, Interview Candidates
> **Scope:** Full-stack, packet-level, access-control-complete breakdown of Amazon S3

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
9. [Attack Scenarios](#9-attack-scenarios)
10. [Failure Points](#10-failure-points)
11. [Mitigations](#11-mitigations)
12. [Observability](#12-observability)
13. [Scaling Considerations](#13-scaling-considerations)
14. [Interview Questions](#14-interview-questions)

---

## 1. User Journey (Narrative)

### Scenario A: Authenticated IAM User Uploads a File via AWS CLI

This traces every real event from the moment a developer runs `aws s3 cp` to the moment the object is durably stored and accessible.

---

### T=0ms — Developer runs:
```bash
aws s3 cp ./report.pdf s3://company-data-bucket/reports/2024/report.pdf
```

**What the user sees:** A progress bar, then `upload: ./report.pdf to s3://company-data-bucket/reports/2024/report.pdf`
**What actually happens:**

1. The AWS CLI reads `~/.aws/credentials` or environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` if using temporary credentials).
2. The CLI determines the bucket's region by calling `s3.amazonaws.com` with a `HeadBucket` or by reading a cached region from `~/.aws/config`.
3. The CLI constructs a `PUT` request for `https://company-data-bucket.s3.us-east-1.amazonaws.com/reports/2024/report.pdf`.
4. The CLI **signs the request** using AWS Signature Version 4 (SigV4). This is not optional — every AWS API call must be signed. The signing process involves the current UTC timestamp, the request body hash, and the secret access key (details in Section 5).
5. DNS resolution is performed for `company-data-bucket.s3.us-east-1.amazonaws.com`.
6. TCP connection to S3's IP, then TLS handshake.
7. The HTTP `PUT` request is sent with the signed headers.
8. S3 receives the request and begins the authorization pipeline.

---

### T=~50–300ms — S3 Authorization Pipeline

**What actually happens (invisible to the developer):**

1. S3 receives the `PUT` request at an S3 frontend (load balancing layer).
2. S3 **re-derives** the expected signature using the same algorithm, the request headers, and the secret key (retrieved from IAM). If the computed signature doesn't match the provided signature, `403 SignatureDoesNotMatch` is returned immediately.
3. S3 checks the **request timestamp** — if the signed timestamp is more than 15 minutes old, `403 RequestTimeTooSkewed` is returned. This prevents replay attacks.
4. S3 runs the **policy evaluation engine** (described in detail in Section 5). It evaluates:
   - Identity-based policies attached to the IAM user/role.
   - Bucket policy (resource-based policy on the bucket).
   - Bucket ACLs (legacy, if applicable).
   - S3 Block Public Access settings.
   - AWS Organizations Service Control Policies (SCPs) if applicable.
5. If any explicit `Deny` is found at any policy layer, the request is denied regardless of any `Allow`.
6. If no explicit `Allow` is found (implicit deny), the request is also denied.
7. If an explicit `Allow` is found with no explicit `Deny`: the request proceeds.

---

### T=~300ms–1s — Object Write Pipeline

**What actually happens:**

1. S3 accepts the object data stream.
2. For objects ≤ 5GB: single `PUT`. The request body (file bytes) is streamed to S3 storage nodes.
3. S3 computes the MD5 (or CRC32C/SHA-256 depending on checksum mode) of the uploaded data and compares it to the `Content-MD5` header if provided. If they don't match: `400 BadDigest`.
4. S3 writes the object to **multiple storage nodes** across at least 3 Availability Zones synchronously before returning `200 OK`. This is the source of S3's "eleven nines" (99.999999999%) durability.
5. If server-side encryption is enabled (SSE-S3, SSE-KMS, or SSE-C): the data is encrypted before writing to the physical storage layer.
6. S3 stores metadata: key name, size, ETag (MD5 of the content, or a construction for multipart uploads), content type, user-defined metadata, storage class, version ID (if versioning enabled).
7. S3 returns `200 OK` with `ETag` header.

---

### T=~1s — Response

**What the user sees:** Upload complete. `ETag` printed if `--debug` flag used.
**What actually happens:**
- The CLI receives the `200 OK` and prints the success message.
- The object is now durably stored. S3 provides **strong read-after-write consistency** (since December 2020) — an immediate `GET` will return the new object.

---

### Scenario B: Pre-Signed URL Access (Anonymous Browser Download)

A user clicks a download link in a web app. The link is a pre-signed S3 URL.

1. Web app backend generates: `https://bucket.s3.region.amazonaws.com/file.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...&X-Amz-Date=...&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=...`
2. User's browser makes a `GET` request to this URL. No AWS credentials needed — the signature embedded in the URL vouches for the request.
3. S3 validates the pre-signed URL signature against the signing principal's credentials.
4. S3 checks whether the signing principal *currently* has permission to `s3:GetObject`. If the IAM role that signed the URL has been revoked, the pre-signed URL is also revoked.
5. S3 returns the object bytes with appropriate `Content-Type` and `Content-Disposition` headers.

---

## 2. Network Layer Flow

### 2.1 DNS Resolution for S3

S3 uses **virtual-hosted-style** URLs (preferred) and path-style URLs (deprecated):

- Virtual-hosted: `company-data-bucket.s3.us-east-1.amazonaws.com`
- Path-style (deprecated): `s3.us-east-1.amazonaws.com/company-data-bucket/key`

```
AWS CLI / Application
  │
  ├── Check OS DNS cache
  │     HIT → IP returned
  │     MISS →
  │
  ├── OS Resolver → /etc/hosts → Configured recursive resolver
  │
  ├── Recursive Resolver
  │     │
  │     ├── Root NS: "Who handles .com?"
  │     │   └── Returns .com TLD NS (Verisign)
  │     │
  │     ├── .com TLD NS: "Who handles amazonaws.com?"
  │     │   └── Returns amazonaws.com authoritative NS
  │     │       (AWS Route 53 / internal AWS NS)
  │     │
  │     └── amazonaws.com Authoritative NS:
  │           "company-data-bucket.s3.us-east-1.amazonaws.com?"
  │           └── Returns: one or more IPs from S3's frontend fleet
  │               These are anycast IPs routing to the nearest S3 PoP
  │               TTL is typically 60s (short for fast failover)
  │
  └── Resolver returns IP to client
```

**Key S3 DNS mechanics:**
- AWS S3 uses **Route 53** for DNS. The bucket subdomain is part of `s3.amazonaws.com` — a wildcard DNS entry maps `*.s3.us-east-1.amazonaws.com` to S3 frontend IP pools.
- The returned IP routes to an S3 **frontend server** in the nearest AWS edge location for the specified region.
- S3 does not expose individual storage node IPs. All access goes through frontend servers.
- **DNS rebinding risk:** Because the bucket name becomes a subdomain, a bucket named after a known service (e.g., `company-internal-api.s3.amazonaws.com`) is still served by S3, not the real service — but confusingly named buckets can trick developers.

---

### 2.2 TCP Handshake to S3

```
Client (AWS CLI / Application)            S3 Frontend (:443)
  │                                              │
  ├── SYN (seq=x) ──────────────────────────────►│
  │                                              │  S3 frontend servers run
  │◄─────────────────────── SYN-ACK (seq=y) ─────┤  on high-performance AWS
  │                                              │  hyperplane networking
  ├── ACK (ack=y+1) ───────────────────────────►│
  │                                              │
  │         [TCP ESTABLISHED]                    │
```

- S3 exclusively uses port **443** (HTTPS). HTTP (port 80) to S3 endpoints redirects or is blocked depending on configuration.
- AWS recommends using **HTTP keep-alive** (persistent connections) for the S3 client. The AWS SDK does this by default — reusing TCP connections for multiple S3 API calls to avoid repeated handshake overhead.
- **Connection latency** to S3 depends on the AWS region. From within the same AWS region (e.g., EC2 in us-east-1 to S3 us-east-1): ~1–5ms. From a developer's laptop in a different geography: 20–200ms.

---

### 2.3 TLS Handshake to S3

S3 supports TLS 1.2 and TLS 1.3. The certificate is issued to `*.s3.amazonaws.com` or region-specific wildcard certs.

```
Client                                    S3 Frontend
  │                                           │
  │── ClientHello ──────────────────────────►│
  │   - TLS 1.3 preferred                    │
  │   - Cipher suites offered:               │
  │     TLS_AES_256_GCM_SHA384               │
  │     TLS_AES_128_GCM_SHA256               │
  │     TLS_CHACHA20_POLY1305_SHA256         │
  │   - SNI: company-data-bucket             │
  │          .s3.us-east-1.amazonaws.com     │
  │   - Client ECDH key share (X25519)       │
  │                                          │
  │◄─ ServerHello ───────────────────────────┤
  │   - Selected: TLS_AES_256_GCM_SHA384     │
  │   - Server ECDH key share               │
  │   [Both derive session keys from ECDH]   │
  │                                          │
  │◄─ {Certificate} ─────────────────────────┤
  │   CN: *.s3.amazonaws.com                 │
  │   Issuer: Amazon RSA 2048 M01            │
  │   SAN: *.s3.amazonaws.com,               │
  │        *.s3.us-east-1.amazonaws.com      │
  │                                          │
  │◄─ {CertificateVerify} ───────────────────┤
  │◄─ {Finished} ────────────────────────────┤
  │── {Finished} ──────────────────────────►│
  │                                          │
  │═══ Encrypted HTTP PUT/GET ═════════════►│
```

**S3 TLS specifics:**
- The certificate covers both the regional endpoint and the bucket subdomain via wildcard SANs.
- AWS Certificate Manager (ACM) handles certificate issuance and rotation automatically for AWS-managed endpoints.
- **FIPS 140-2 compliant TLS endpoints** exist for government/regulated workloads: `s3-fips.us-east-1.amazonaws.com` — restricted to FIPS-approved ciphers.
- Within AWS (EC2 to S3 in the same region): traffic travels over AWS's internal network backbone and does NOT leave the AWS network, but is still TLS-encrypted. Using a **VPC Endpoint (Gateway type)** for S3 routes traffic entirely within AWS's private network, never touching the public internet.

---

### 2.4 Full Network Diagram

```
  DEVELOPER WORKSTATION / EC2 INSTANCE
  ┌──────────────────────────────────────┐
  │  AWS CLI / SDK                       │
  │  ┌──────────────────────────────┐    │
  │  │ SigV4 Signer                 │    │
  │  │ Credential Provider Chain    │    │
  │  │ HTTP Client (keep-alive)     │    │
  │  └──────────────────────────────┘    │
  └──────────────────┬───────────────────┘
                     │ TLS 1.3 / Port 443
                     │
         ┌───────────┴──────────────────────────┐
         │  PATH A: Public Internet              │
         │  ISP → Internet backbone → AWS PoP    │
         │                                       │
         │  PATH B: VPC Gateway Endpoint         │
         │  Stays on AWS backbone, no public IP  │
         │  No data transfer charges             │
         └───────────┬──────────────────────────┘
                     │
  AWS EDGE / REGIONAL NETWORK
  ┌──────────────────▼───────────────────┐
  │  AWS Network / CloudFront PoP        │
  │  (TLS terminates at edge for CF)     │
  │  (TLS terminates at S3 frontend      │
  │   for direct S3 access)              │
  └──────────────────┬───────────────────┘
                     │
  S3 FRONTEND LAYER (per region)
  ┌──────────────────▼───────────────────┐
  │  S3 Frontend Servers (fleet)         │
  │  - TLS termination                   │
  │  - Request parsing                   │
  │  - SigV4 verification                │
  │  - Authorization (IAM policy eval)   │
  │  - Request routing to storage layer  │
  └──────────────────┬───────────────────┘
                     │
  S3 STORAGE LAYER (internal, not publicly routable)
  ┌─────────────────────────────────────────────────────┐
  │  Availability Zone A   AZ B         AZ C            │
  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
  │  │ Storage Node│  │ Storage Node│  │ Storage Node│ │
  │  │ (replica 1) │  │ (replica 2) │  │ (replica 3) │ │
  │  └─────────────┘  └─────────────┘  └─────────────┘ │
  │  Writes to all 3 AZs before 200 OK returned         │
  └─────────────────────────────────────────────────────┘
```

---

### 2.5 Latency Budget

| Step | Typical Duration (same-region EC2) | From External Internet |
|------|------------------------------------|----------------------|
| DNS resolution | <1ms (cached) / 5–20ms (cold) | 20–100ms |
| TCP handshake | 1–5ms | 20–200ms |
| TLS 1.3 handshake | 1–5ms | 20–200ms |
| SigV4 signing (local CPU) | <1ms | <1ms |
| S3 authorization pipeline | 5–20ms | 5–20ms |
| Object write (small file) | 5–50ms | 5–50ms |
| **Total PUT (1MB file)** | **~15–100ms** | **~100–500ms** |

---

## 3. Application Layer Flow

### 3.1 S3 REST API — HTTP Request Structure

S3 exposes a REST API. Every operation is an HTTP request.

**PUT Object:**
```
PUT /reports/2024/report.pdf HTTP/1.1
Host: company-data-bucket.s3.us-east-1.amazonaws.com
Content-Type: application/pdf
Content-Length: 1048576
Content-MD5: base64(MD5(body))
x-amz-date: 20240115T102345Z
x-amz-content-sha256: hexdigest(SHA256(body))
x-amz-server-side-encryption: aws:kms
x-amz-server-side-encryption-aws-kms-key-id: arn:aws:kms:us-east-1:123456789:key/abc-123
x-amz-storage-class: STANDARD
x-amz-meta-uploader: john@example.com
Authorization: AWS4-HMAC-SHA256
  Credential=AKIAIOSFODNN7EXAMPLE/20240115/us-east-1/s3/aws4_request,
  SignedHeaders=content-md5;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption,
  Signature=calculated_hex_signature

[1048576 bytes of PDF content]
```

**Header-by-header breakdown:**

- `Host`: Required. Used in the signature. With virtual-hosted style, the bucket name is in the host header, not the path. This matters for signature validation.
- `x-amz-date`: ISO 8601 UTC timestamp. Must match the timestamp used in the signature. S3 rejects requests where this deviates more than 15 minutes from S3's clock.
- `x-amz-content-sha256`: SHA-256 hex digest of the request body. Required for S3 (unlike some other AWS services). Can also be the literal string `UNSIGNED-PAYLOAD` for streaming uploads, or `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` for chunked uploads.
- `Authorization`: The SigV4 authorization header. Contains the credential scope (access key, date, region, service), the list of signed headers, and the computed signature.
- `x-amz-server-side-encryption` + `x-amz-server-side-encryption-aws-kms-key-id`: Instructs S3 to encrypt with the specified KMS key. S3 will call KMS to generate a data encryption key before writing.
- `x-amz-storage-class`: `STANDARD`, `STANDARD_IA`, `GLACIER`, `INTELLIGENT_TIERING`, etc. Determines cost, durability characteristics, and retrieval latency.
- `x-amz-meta-*`: User-defined metadata. Stored as object metadata, returned in GET response headers. Max 2KB total.

**GET Object:**
```
GET /reports/2024/report.pdf HTTP/1.1
Host: company-data-bucket.s3.us-east-1.amazonaws.com
Range: bytes=0-1048575       (optional: for range requests)
If-None-Match: "abc123etag"  (optional: conditional GET)
x-amz-date: 20240115T102345Z
x-amz-content-sha256: e3b0c44298fc1c149afb (SHA256 of empty body)
Authorization: AWS4-HMAC-SHA256 Credential=...
```

**Range requests:** S3 fully supports HTTP Range requests. This is fundamental to large file downloads, multipart parallel downloads, and video streaming. S3 returns `206 Partial Content` with `Content-Range: bytes 0-1048575/5242880`.

**Conditional requests:** `If-None-Match` with the ETag allows cache validation. S3 returns `304 Not Modified` if the ETag matches, saving bandwidth.

---

### 3.2 Multipart Upload — HTTP Lifecycle

For files > 5GB or for performance with large files, S3 requires (>5GB) or recommends (>100MB) multipart upload:

```
Step 1: Initiate
POST /large-file.zip?uploads HTTP/1.1
Host: bucket.s3.region.amazonaws.com
← Response: <UploadId>VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA</UploadId>

Step 2: Upload Parts (parallel, any order)
PUT /large-file.zip?partNumber=1&uploadId=VXBsb...  [5MB chunk]
PUT /large-file.zip?partNumber=2&uploadId=VXBsb...  [5MB chunk]
PUT /large-file.zip?partNumber=N&uploadId=VXBsb...  [remaining bytes]
← Each returns ETag for that part

Step 3: Complete
POST /large-file.zip?uploadId=VXBsb...
Body: <CompleteMultipartUpload>
        <Part><PartNumber>1</PartNumber><ETag>etag1</ETag></Part>
        <Part><PartNumber>2</PartNumber><ETag>etag2</ETag></Part>
      </CompleteMultipartUpload>
← Response: final ETag (not MD5 of whole file — it's MD5(concat(part_etags))-N)

Step 4 (if needed): Abort
DELETE /large-file.zip?uploadId=VXBsb...
```

**Critical detail:** Incomplete multipart uploads consume storage and incur costs. If Step 3 never happens (e.g., client crash), the parts remain in S3 storage indefinitely until explicitly aborted or cleaned up by an S3 Lifecycle rule (`AbortIncompleteMultipartUpload`).

---

### 3.3 Response Construction

**Successful PUT:**
```
HTTP/1.1 200 OK
x-amz-id-2: extended request ID (for AWS support)
x-amz-request-id: unique request ID
Date: Mon, 15 Jan 2024 10:23:45 GMT
ETag: "d41d8cd98f00b204e9800998ecf8427e"
x-amz-server-side-encryption: aws:kms
x-amz-server-side-encryption-aws-kms-key-id: arn:aws:kms:...
x-amz-version-id: BYabcXYZ (if versioning enabled)
Content-Length: 0
Server: AmazonS3
```

**403 Forbidden (access denied):**
```
HTTP/1.1 403 Forbidden
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>ABCDEF1234567890</RequestId>
  <HostId>extended/host/id/base64</HostId>
</Error>
```

**Critical security note:** S3 deliberately returns the same `403 AccessDenied` response whether the bucket exists or not (for buckets the caller cannot access). This prevents bucket enumeration by unauthenticated callers. However, if the bucket doesn't exist at all, `NoSuchBucket` is returned — which leaks information that the bucket name is available.

---

## 4. Backend Architecture

### 4.1 S3 Internal Architecture (Publicly Known Details)

AWS does not publish the full S3 internals, but from public papers (the 2023 S3 SOSP paper "S3: A Universal Object Store") and re:Invent talks, the following is known:

```
S3 FRONTEND LAYER
┌─────────────────────────────────────────────────────────────────┐
│  Authentication Server                                          │
│  - SigV4 verification                                           │
│  - IAM policy evaluation (calls IAM service internally)        │
│  ├─ Credential validation (is this access key valid and active?)│
│  ├─ Request signature verification                              │
│  └─ Policy resolution (identity + resource + SCPs)             │
│                                                                 │
│  Request Router                                                 │
│  - Determines which storage partition owns this object          │
│  - Based on bucket + key hash                                   │
│  - Routes to appropriate storage node cluster                   │
└─────────────────────────────────────────────────────────────────┘
                              │
S3 METADATA LAYER
┌─────────────────────────────────────────────────────────────────┐
│  Metadata Service                                               │
│  - Stores: key name, size, ETag, storage class, ACLs,          │
│    version history, object tags, legal hold status             │
│  - Distributed database (sharded by bucket+key prefix)         │
│  - This is where the LIST operation reads from                  │
│  - Strong consistency guaranteed (as of Dec 2020):             │
│    metadata writes are durable before PUT returns 200 OK        │
└─────────────────────────────────────────────────────────────────┘
                              │
S3 STORAGE LAYER
┌─────────────────────────────────────────────────────────────────┐
│  Chunk Store (distributed across AZs)                           │
│  - Objects split into chunks                                    │
│  - Each chunk stored with erasure coding or replication         │
│  - At least 3 AZs in every AWS region (for STANDARD class)     │
│  - Physical storage: custom AWS hardware with HDD/SSD          │
│                                                                 │
│  Durability mechanism:                                          │
│  - Not simple 3x replication                                    │
│  - Reed-Solomon erasure coding for large objects               │
│  - Continuous data scrubbing (bit-rot detection)               │
│  - Cross-region replication (CRR) available for additional      │
│    geographic durability                                        │
└─────────────────────────────────────────────────────────────────┘
```

---

### 4.2 S3 Event Notifications — Async Flows

S3 can trigger downstream systems asynchronously on object events:

```
S3 Object PUT/DELETE/RESTORE
        │
        ├──► S3 Event Notification
        │
        │    Delivery targets:
        │    ├── Amazon SQS (queue for polling workers)
        │    │     └── Worker: Lambda, EC2, ECS consumer
        │    │           → image resize, virus scan, ETL
        │    │
        │    ├── Amazon SNS (fan-out to multiple subscribers)
        │    │     └── Multiple Lambda functions, HTTP endpoints
        │    │
        │    ├── AWS Lambda (direct invocation)
        │    │     → synchronous-ish: Lambda triggered per event
        │    │
        │    └── Amazon EventBridge (advanced routing)
        │          → Route by object prefix, suffix, size
        │            → multiple downstream services

Delivery guarantee: at-least-once. Design consumers idempotently.
Typical latency: seconds (not milliseconds).
```

**S3 Object Lambda:** Intercepts GET requests to transform data on the fly before returning to the requester. E.g., redact PII from a CSV before it reaches the caller.

---

### 4.3 S3 Replication

```
Source Bucket (us-east-1)          Destination Bucket (eu-west-1)
┌──────────────────────┐           ┌──────────────────────┐
│  Object PUT          │           │                      │
│  └── Replication     │           │                      │
│      Queue           │───────────►  Replicated Object   │
│      (internal       │  Async    │  (same data, new     │
│       S3 mechanism)  │  ~minutes │   metadata)          │
└──────────────────────┘           └──────────────────────┘

Cross-Region Replication (CRR): between different AWS regions
Same-Region Replication (SRR): within same region, different buckets

Replication does NOT happen for:
- Objects already in the bucket before replication rule was enabled
- Objects encrypted with SSE-C (customer-provided keys)
- Delete markers (configurable)
- Objects in GLACIER/DEEP_ARCHIVE storage class (unless explicitly configured)
```

---

### 4.4 Caching Layers

S3 itself is not a caching service, but multiple caching mechanisms exist:

**CloudFront (CDN in front of S3):**
- CloudFront caches S3 objects at 400+ PoPs worldwide.
- `Cache-Control: max-age=86400` header on the S3 object controls CloudFront TTL.
- Cache invalidation: `aws cloudfront create-invalidation --paths "/reports/*"`.
- CloudFront Origin Access Control (OAC) allows making S3 bucket private while serving through CloudFront.

**S3 Transfer Acceleration:**
- Routes uploads through CloudFront's edge network for faster global uploads.
- Uses a separate endpoint: `bucket.s3-accelerate.amazonaws.com`.
- Adds ~15–50% to cost but can improve throughput from distant regions by 50–500%.

**Application-level caching:**
- Applications typically cache S3 object metadata (ETag, last modified) in Redis/Memcached to avoid repeated HEAD requests.
- Pre-signed URL caching: generate once, cache the URL for its lifetime (up to 7 days for IAM role-signed URLs, up to 12 hours for IAM user credentials in some SDKs).

---

## 5. Authentication & Authorization Flow

### 5.1 AWS Signature Version 4 (SigV4) — Mechanics

SigV4 is the authentication mechanism for every S3 request. It is a keyed-HMAC scheme, not a bearer token. The signature proves that the sender holds the secret access key **without transmitting the key**.

**Step 1: Create a Canonical Request**
```
PUT\n
/reports/2024/report.pdf\n
\n
content-md5:base64md5\n
content-type:application/pdf\n
host:company-data-bucket.s3.us-east-1.amazonaws.com\n
x-amz-content-sha256:hexsha256ofbody\n
x-amz-date:20240115T102345Z\n
\n
content-md5;content-type;host;x-amz-content-sha256;x-amz-date\n
hexsha256ofbody
```

This is: `HTTPMethod\nCanonicalURI\nCanonicalQueryString\nCanonicalHeaders\nSignedHeaders\nHexEncode(Hash(RequestPayload))`

**Step 2: Create a String to Sign**
```
AWS4-HMAC-SHA256\n
20240115T102345Z\n
20240115/us-east-1/s3/aws4_request\n
hexencode(sha256(canonical_request))
```

**Step 3: Calculate the Signing Key**
```python
kSecret  = "AWS4" + secret_access_key
kDate    = HMAC-SHA256(kSecret,   "20240115")
kRegion  = HMAC-SHA256(kDate,     "us-east-1")
kService = HMAC-SHA256(kRegion,   "s3")
kSigning = HMAC-SHA256(kService,  "aws4_request")
```

**Step 4: Calculate the Signature**
```python
signature = hexencode(HMAC-SHA256(kSigning, string_to_sign))
```

**Why this design:**
- The secret key is never transmitted.
- The signature covers the specific request (method, path, headers, body hash) — changing any signed component invalidates the signature.
- The 15-minute clock window prevents replay attacks.
- The credential scope (date/region/service) prevents a valid S3 signature from being used against an EC2 API, or a valid us-east-1 signature from being used against eu-west-1.

**S3 verifies the signature by re-deriving it:**
- S3 looks up the secret key associated with the provided access key ID (from the IAM service, via an internal call).
- S3 runs the same algorithm.
- If `computed_signature == provided_signature`: authentic.

---

### 5.2 IAM Policy Evaluation Engine — Decision Logic

This is the most critical and complex part of S3 access control.

```
For every S3 API call, IAM evaluates:

1. Is there an explicit DENY in any applicable policy?
   │  YES → DENY (stops evaluation, cannot be overridden)
   │  NO →
   ▼
2. Is this a cross-account request?
   │  YES → BOTH the identity policy (caller's account) AND
   │         the resource policy (bucket policy) must have explicit ALLOW
   │  NO (same account) →
   ▼
3. Is there an explicit ALLOW in any identity-based policy
   OR in the resource-based policy?
   │  YES → ALLOW
   │  NO → implicit DENY
```

**Policies that can affect an S3 request:**

```
┌──────────────────────────────────────────────────────────────────┐
│  Layer 1: AWS Organizations SCPs                                 │
│  - Applied to entire AWS accounts or OUs                         │
│  - Establishes the maximum permissions boundary for all IAM      │
│    principals in the account                                     │
│  - A SCP DENY cannot be overridden by any identity or bucket     │
│    policy                                                        │
└──────────────────────────────────────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 2: IAM Permission Boundaries                              │
│  - Optional boundary attached to a specific IAM user or role     │
│  - Defines the maximum permissions that entity can have          │
│  - Effective permissions = intersection of identity policies     │
│    AND permission boundary                                       │
└──────────────────────────────────────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 3: Identity-Based Policies (on the calling principal)     │
│  - IAM user policies (inline or managed)                         │
│  - IAM group policies (inline or managed)                        │
│  - IAM role policies (if assuming a role)                        │
│  - Define what actions this principal can perform on what         │
│    resources                                                     │
└──────────────────────────────────────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 4: Resource-Based Policies (on the S3 bucket)             │
│  - Bucket Policy: JSON policy attached to the bucket              │
│  - Can grant access to other AWS accounts, federated identities,  │
│    AWS services (e.g., allow CloudFront to read)                 │
│  - Can also DENY access (overrides any ALLOW)                    │
└──────────────────────────────────────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 5: S3 Block Public Access                                 │
│  - 4 separate settings at account level and bucket level:        │
│    - BlockPublicAcls: prevents setting public ACLs               │
│    - IgnorePublicAcls: ignores existing public ACLs              │
│    - BlockPublicPolicy: prevents attaching a public bucket policy │
│    - RestrictPublicBuckets: restricts access to bucket to only   │
│      AWS principals + bucket owner                               │
│  - These override bucket policies and ACLs                       │
└──────────────────────────────────────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 6: S3 ACLs (Legacy — avoid for new systems)               │
│  - Object-level and bucket-level ACLs                            │
│  - Pre-date IAM; less expressive than bucket policies            │
│  - AWS recommends disabling ACLs (Object Ownership = BucketOwnerEnforced)│
└──────────────────────────────────────────────────────────────────┘
```

---

### 5.3 IAM Credential Types and Their Trust Properties

| Credential Type | Components | Lifespan | Where Used |
|----------------|-----------|----------|------------|
| Long-term IAM user keys | Access Key ID + Secret Access Key | Indefinite (until rotated/deleted) | Legacy; CLI, server apps |
| IAM Role temporary credentials | Access Key ID + Secret Access Key + **Session Token** | 15 min – 12 hours | EC2, Lambda, ECS, cross-account |
| EC2 Instance Profile | Same as role temporary creds | Auto-rotated by EC2 metadata service | EC2 instances |
| Web Identity Federation | Temporary, from STS AssumeRoleWithWebIdentity | Short-lived | Mobile apps, OIDC (Cognito, Google) |
| Pre-signed URLs | Embedded SigV4 in URL | Up to 7 days (role-signed) | Browser downloads, temporary access |

**Critical: EC2 Instance Metadata Service (IMDS):**
- EC2 instances automatically have access to IAM role credentials via `http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName`
- IMDSv1: Accessible via simple HTTP GET from any process on the EC2 instance — vulnerable to SSRF attacks.
- IMDSv2: Requires a PUT request to get a session token first, then uses the token for subsequent metadata requests. Session token is limited to the EC2 instance (hop limit = 1 on TTL, prevents routing). SSRF exploits typically cannot follow a redirect to complete the two-step IMDSv2 flow.
- **Always enforce IMDSv2.** This is one of the highest-impact security configurations on EC2.

---

### 5.4 Pre-Signed URLs — Mechanics

Pre-signed URLs embed the SigV4 signature in the URL query string rather than an Authorization header:

```
https://bucket.s3.us-east-1.amazonaws.com/private/file.pdf
  ?X-Amz-Algorithm=AWS4-HMAC-SHA256
  &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20240115%2Fus-east-1%2Fs3%2Faws4_request
  &X-Amz-Date=20240115T102345Z
  &X-Amz-Expires=3600
  &X-Amz-SignedHeaders=host
  &X-Amz-Signature=computed_hex_signature
```

**Security properties:**
- Valid for the signing principal's current permissions. If the IAM role is revoked after signing, the URL is also invalidated.
- `X-Amz-Expires` sets the TTL in seconds (max 604800 = 7 days for STS role credentials; effectively unlimited for IAM user credentials, constrained only by credential validity).
- The URL can be used by anyone who has it — there's no per-user binding. Treat it like a capability token.
- If the URL is logged (CloudFront logs, server access logs, browser history), the signature is exposed. Attackers who obtain the URL can use it until expiry.
- S3 does NOT support pre-signed URL revocation. To revoke: rotate the IAM credentials used for signing (this invalidates all pre-signed URLs signed with those credentials).

---

### 5.5 Bucket Policy Example (Annotated)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonTLSAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::company-data-bucket",
        "arn:aws:s3:::company-data-bucket/*"
      ],
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
      // Denies ALL requests over HTTP (non-TLS)
      // Effect: Deny + Principal: * = applies to everyone including bucket owner
      // This is defense against HTTP downgrade
    },
    {
      "Sid": "AllowAppRoleReadWrite",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/AppServerRole"
      },
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::company-data-bucket/app-data/*"
      // Only allows the AppServerRole to read/write under the app-data/ prefix
      // Does NOT allow s3:DeleteObject — explicit allowlist of actions
    },
    {
      "Sid": "DenyPutWithoutKMSEncryption",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::company-data-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
      // Denies any PUT that does not specify KMS encryption
      // Ensures all objects are encrypted at rest with KMS
      // The "Deny" makes this enforceable — the app CANNOT skip encryption
    },
    {
      "Sid": "AllowCrossAccountAuditRead",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::987654321098:role/AuditRole"
      },
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::company-data-bucket",
        "arn:aws:s3:::company-data-bucket/audit-logs/*"
      ]
      // Grants a role in a DIFFERENT AWS account (987654321098) read access
      // The AuditRole's own account must also have identity policies allowing this
      // Both sides of the trust must exist for cross-account access
    }
  ]
}
```

---

## 6. Data Flow

### 6.1 Object Write Path — Data Transformation

```
Application
  │
  │  Raw bytes: PDF content (binary)
  │
  ▼
AWS SDK (Client-Side)
  ├── Optional: Client-Side Encryption (CSE)
  │     - Application encrypts data before sending
  │     - S3 stores ciphertext; cannot decrypt without app key
  │     - Use: AWS Encryption SDK, S3 client-side encryption helper
  │
  ├── SigV4 signing: SHA-256 hash of body computed
  │
  ├── Chunked encoding (for large files, streaming)
  │
  └── HTTP PUT with signed headers
  │
  ▼
S3 Frontend
  ├── TLS decryption (data is now plaintext within AWS network)
  ├── SigV4 verification
  ├── Authorization check
  ├── MD5 / CRC32 / SHA-256 integrity check (if Content-MD5 provided)
  │
  └── If SSE-KMS requested:
        ├── Call AWS KMS: GenerateDataKey(KeyId=arn:...)
        │     Returns: {Plaintext: DEK, CiphertextBlob: encrypted_DEK}
        ├── Encrypt object data with DEK (AES-256-GCM)
        ├── Store encrypted_DEK alongside object metadata
        └── Discard plaintext DEK from memory
  │
  ▼
S3 Storage Layer
  ├── Erasure encode object into chunks
  ├── Distribute chunks across 3+ AZs
  └── Each chunk written with integrity metadata (checksum)
  │
  ▼
S3 Metadata Service
  ├── Record: key, bucket, ETag, size, version_id, encryption_config,
  │           storage_class, tags, legal_hold, ACL, timestamp
  └── Strong consistency: metadata write is atomic with data write
  │
  ▼
Response: 200 OK, ETag, version_id
```

### 6.2 Object Read Path — Data Transformation

```
Request: GET /key
  │
  ▼
S3 Frontend
  ├── SigV4 verification (or pre-signed URL validation)
  ├── Authorization check
  │
  └── If SSE-KMS:
        ├── Retrieve encrypted_DEK from object metadata
        ├── Call AWS KMS: Decrypt(CiphertextBlob=encrypted_DEK)
        │     Returns: Plaintext DEK
        │     NOTE: every GET of a KMS-encrypted object = 1 KMS API call
        │     KMS has limits (default 50,000 req/sec per region)
        │     This can become a bottleneck at high GET rates
        ├── Decrypt object data with DEK (AES-256-GCM)
        └── Discard DEK from memory after streaming response
  │
  ▼
S3 Storage Layer
  ├── Retrieve chunks from storage nodes
  ├── Decode erasure-coded chunks into object data
  └── Verify chunk integrity (detect bit rot)
  │
  ▼
HTTP Response stream to caller
  ├── Content-Type: application/pdf
  ├── ETag: object checksum
  ├── x-amz-server-side-encryption: aws:kms (indicates encryption used)
  └── Object bytes (decrypted if SSE-KMS/SSE-S3, encrypted if SSE-C)
```

### 6.3 Serialization Formats

| Context | Format | Notes |
|---------|--------|-------|
| S3 API request/response bodies | XML | S3 uses XML for all list responses, error responses, multipart operations |
| S3 object data | Arbitrary bytes | S3 is object storage; content is opaque to S3 |
| Bucket/object metadata | Key-value pairs in HTTP headers | `x-amz-meta-*` for user metadata |
| Object tags | XML (in API), URL-encoded query string | Max 10 tags per object |
| S3 Select / S3 Glacier Select | SQL | Query CSV, JSON, Parquet objects without full retrieval |
| S3 inventory reports | CSV or Apache ORC / Parquet | Periodic inventory of bucket contents |
| S3 server access logs | Space-delimited text | Not JSON; schema defined in AWS docs |
| CloudTrail logs for S3 | JSON | Every API call logged to CloudTrail; stored as gzipped JSON in S3 |

---

## 7. Security Controls

### 7.1 Encryption in Transit

- All S3 endpoints enforce HTTPS. The SDK defaults to HTTPS.
- Use bucket policy `Deny` on `aws:SecureTransport: false` to **enforce** HTTPS — without this policy, HTTP PUT would succeed if a misconfigured client tries it.
- Within AWS internal network (EC2 to S3 same region): traffic is on AWS's isolated backbone, not the public internet, but still TLS-encrypted.
- VPC Endpoint (Gateway type): traffic from VPC to S3 never leaves AWS's network. Free of data transfer charges. Can add a VPC Endpoint Policy to further restrict which buckets/operations are allowed.

### 7.2 Encryption at Rest

Three server-side encryption modes:

**SSE-S3 (Server-Side Encryption with S3-managed keys):**
- S3 manages keys entirely. Transparent to the caller.
- Each object encrypted with a unique key. The key itself is encrypted with a rotating master key.
- AES-256.
- Use `x-amz-server-side-encryption: AES256` header or bucket default encryption.
- No additional cost beyond S3 storage.
- Lowest operational burden. Appropriate for non-sensitive data.

**SSE-KMS (Server-Side Encryption with AWS KMS-managed keys):**
- S3 calls KMS to generate and encrypt a data encryption key (DEK) per object.
- Provides key audit trail in CloudTrail: every encrypt/decrypt operation is logged.
- Allows separate IAM policies on the KMS key (key policy) — different from bucket policy. A principal needs permission in BOTH the bucket policy AND the KMS key policy to read KMS-encrypted objects.
- Can use AWS-managed key (`aws/s3`) or customer-managed key (CMK).
- **KMS request rates:** High-throughput S3 GET workloads can exhaust KMS quota (default 50K req/sec per region). Use `GenerateDataKeyWithoutPlaintext` + DEK caching at the application layer, or request KMS quota increase.
- Use CMKs for data subject to regulatory requirements (HIPAA, PCI-DSS) where you need key control.

**SSE-C (Server-Side Encryption with Customer-Provided Keys):**
- Caller provides the AES-256 key in every PUT and GET request.
- S3 uses the key to encrypt/decrypt, then immediately discards it.
- S3 stores an HMAC of the key (to verify the correct key is provided on GET).
- AWS never stores the key. If you lose it, your data is permanently unrecoverable.
- Requires HTTPS (S3 rejects SSE-C over HTTP).
- Not supported in the console — API/CLI/SDK only.

**Client-Side Encryption (CSE):**
- Encrypt before upload. S3 stores ciphertext.
- S3 has zero knowledge of the plaintext or the key.
- Highest security; highest operational complexity.
- Use AWS Encryption SDK or S3 client-side encryption helper library.

### 7.3 Access Control — Defense in Depth

```
Defense layers for a sensitive bucket:

Layer 1: Block Public Access (all 4 settings = ON)
  → Prevents any public exposure regardless of policy errors

Layer 2: Bucket Policy with explicit Deny for non-HTTPS
  → Ensures all traffic is encrypted in transit

Layer 3: Bucket Policy restricting to specific IAM roles/accounts
  → Principle of least privilege

Layer 4: IAM Permission Boundaries on roles
  → Even if a role's policy is misconfigured, boundary limits damage

Layer 5: S3 Access Analyzer
  → Continuously analyzes and alerts on buckets accessible outside account

Layer 6: AWS Organizations SCP
  → "Deny s3:PutBucketPublicAccessBlock: False" — prevents any account
    in the org from disabling Block Public Access

Layer 7: SSE-KMS with separate CMK policy
  → Data readable only by principals with both bucket AND KMS permissions

Layer 8: CloudTrail logging of all S3 data events
  → All GET/PUT/DELETE logged for forensics
```

### 7.4 S3 Object Lock (WORM — Write Once Read Many)

- Objects cannot be deleted or overwritten for a specified duration.
- Two modes:
  - **Governance mode:** Can be bypassed by users with `s3:BypassGovernanceRetention` permission. For internal protection.
  - **Compliance mode:** Cannot be bypassed by anyone, including the root account. Even AWS Support cannot override. For regulatory requirements.
- Legal hold: indefinite lock independent of retention period. Can only be removed by authorized principals.
- Use for: audit logs, compliance records, ransomware protection.

### 7.5 Secrets Handling

- IAM role credentials for EC2/Lambda/ECS: automatically rotated by the metadata service. Applications should not cache credentials for more than their TTL.
- SSE-C keys: never log them, never put them in application code. Use AWS Secrets Manager or KMS to store and retrieve.
- S3 pre-signed URL signing credentials: should be short-lived role credentials, not long-term IAM user keys.
- **Never commit AWS access keys to source code.** GitHub's secret scanning and AWS's own credential scanning (via GuardDuty) will detect exposed keys.

---

## 8. Attack Surface Mapping

### 8.1 External Attack Surface

```
PUBLIC INTERNET ATTACK SURFACE
═══════════════════════════════════════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────┐
  │  PUBLIC BUCKET (if misconfigured — Block Public Access OFF)  │
  │                                                             │
  │  https://bucket.s3.amazonaws.com/                           │
  │  ├── LIST: enumerate all object keys                        │
  │  │     Attack: data discovery, targeted download            │
  │  ├── GET any object: unauthenticated download               │
  │  │     Attack: data exfiltration of all stored data         │
  │  └── PUT (if public write enabled — rare but catastrophic)  │
  │        Attack: malware hosting, content injection           │
  └─────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────┐
  │  AUTHENTICATED SURFACE                                      │
  │                                                             │
  │  All S3 API endpoints for the bucket region:                │
  │  https://<bucket>.s3.<region>.amazonaws.com/               │
  │                                                             │
  │  Entry points by operation:                                 │
  │  ├── GET /key        → data exfiltration if overAuth'd      │
  │  ├── PUT /key        → data injection, overwrite            │
  │  ├── DELETE /key     → data destruction                     │
  │  ├── GET /?list-type=2 → bucket enumeration                 │
  │  ├── PUT /?acl       → ACL modification, public exposure    │
  │  ├── PUT /?policy    → policy replacement, privilege escalation│
  │  ├── PUT /?versioning → disable versioning, remove rollback  │
  │  ├── PUT /?logging   → disable logging, blind attackers     │
  │  └── POST /key?uploads → initiate multipart, orphaned parts │
  └─────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────┐
  │  PRE-SIGNED URL SURFACE                                     │
  │                                                             │
  │  Any URL of the form:                                       │
  │  https://bucket.s3.amazonaws.com/key?X-Amz-Signature=...   │
  │                                                             │
  │  Attack: URL leakage via logs, Referer header, browser      │
  │          history, URL shorteners                            │
  └─────────────────────────────────────────────────────────────┘
```

### 8.2 Trust Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│  COMPLETELY UNTRUSTED                                                    │
│                                                                          │
│  ┌──────────────────────────────┐  ┌──────────────────────────────┐     │
│  │  Anonymous Internet Users    │  │  Unauthenticated S3 Requests │     │
│  │  (no AWS credentials)        │  │  (bucket name guessing)      │     │
│  └──────────────────────────────┘  └──────────────────────────────┘     │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │  TRUST BOUNDARY 1: SigV4 Auth
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  AUTHENTICATED AWS PRINCIPALS (partially trusted)                        │
│                                                                          │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐               │
│  │  IAM Users    │  │  IAM Roles    │  │  Federated    │               │
│  │  (long-term   │  │  (temp creds) │  │  Identities   │               │
│  │   keys)       │  │               │  │  (OIDC/SAML)  │               │
│  └───────────────┘  └───────────────┘  └───────────────┘               │
│  These are authenticated but may NOT be authorized for a specific bucket │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │  TRUST BOUNDARY 2: IAM Policy Evaluation
                                      │  (identity + resource + SCP + boundary)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED PRINCIPALS (trusted for specific operations)                 │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  AWS Account Owner (root)  ← TRUST BOUNDARY 3: Object Lock      │   │
│  │  Account Admins                (Compliance mode: even root denied)│   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │  TRUST BOUNDARY 4: KMS key policy
                                      │  (additional gate for SSE-KMS data)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  INTERNAL S3 SYSTEMS (AWS-managed, not customer-accessible)             │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                 │
│  │ S3 Frontend  │  │ S3 Metadata  │  │ S3 Storage   │                 │
│  │ Servers      │  │ Service      │  │ Nodes (AZs)  │                 │
│  └──────────────┘  └──────────────┘  └──────────────┘                 │
│                                                                          │
│  TRUST BOUNDARY 5: AWS physical/logical isolation                        │
│  Customer cannot access these systems directly                           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Attack Scenarios

### Attack 1: Public Bucket Data Exfiltration

**Category:** Misconfiguration-based exposure
**Attacker assumptions:** No AWS credentials. Just knowledge of the bucket name (or willingness to enumerate).

**Step-by-step execution:**

1. Attacker guesses or discovers a bucket name. Common sources:
   - JavaScript in the web app: `fetch("https://company-uploads.s3.amazonaws.com/...")`
   - HTML source code: image tags, links
   - GitHub code search: `s3.amazonaws.com` in public repos
   - Certificate Transparency logs (bucket names in SAN fields if using custom domains)
   - DNS zone files / passive DNS

2. Attacker probes: `curl https://company-uploads.s3.amazonaws.com/`
   - If `ListBucket` is public: receives XML listing of all object keys
   - If not listable but `GetObject` is public: must guess key names (but many apps use predictable paths)

3. If listing works:
   ```bash
   aws s3 ls s3://company-uploads --no-sign-request --recursive
   ```
   Returns all keys. Attacker downloads everything:
   ```bash
   aws s3 sync s3://company-uploads . --no-sign-request
   ```

4. Data is now exfiltrated.

**Why this works:** S3 Block Public Access was introduced in 2018 but is not retroactively enforced. Older buckets created before 2018 may have public ACLs or bucket policies. Developers enabling public access "temporarily" forget to revert. IaC templates with `acl: "public-read"` get copy-pasted without review.

**Where detection could happen:**
- S3 server access logs: anonymous GETs with no authorization signature.
- CloudTrail: `ListBucket` and `GetObject` with `userIdentity.type: Anonymous`.
- AWS Trusted Advisor / Security Hub: flags public buckets.
- AWS Config rule: `s3-bucket-public-read-prohibited`.
- GuardDuty: `S3/AnonymousAccessGranted` finding.

**Detection lag:** S3 access logs have delivery latency of minutes to hours. Near-real-time detection requires CloudTrail + EventBridge + Lambda pipeline. By the time an alert fires, exfiltration may be complete.

---

### Attack 2: SSRF to IMDS → S3 Bucket Access

**Category:** SSRF chained with credential theft, leading to S3 exfiltration
**Attacker assumptions:** Found an SSRF vulnerability in a web application running on EC2. The EC2 instance has an IAM role with S3 read access.

**Step-by-step execution:**

1. Attacker finds SSRF: `https://app.example.com/fetch?url=http://169.254.169.254/latest/meta-data/`
2. With IMDSv1 (no hop-limit protection): single GET returns metadata.
3. Attacker requests: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   - Response: `AppServerRole` (the name of the IAM role)
4. Attacker requests: `http://169.254.169.254/latest/meta-data/iam/security-credentials/AppServerRole`
   - Response:
     ```json
     {
       "Code": "Success",
       "Type": "AWS-HMAC",
       "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
       "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
       "Token": "AQoDYXdzEJr...",
       "Expiration": "2024-01-15T11:23:45Z"
     }
     ```
5. Attacker exports these as environment variables on their own machine:
   ```bash
   export AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE
   export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   export AWS_SESSION_TOKEN=AQoDYXdzEJr...
   ```
6. Attacker now runs: `aws s3 sync s3://company-data-bucket . --region us-east-1`
7. All data the EC2 role can access is exfiltrated.

**Why this works:** IMDSv1 has no CSRF protection. Any HTTP client that can reach 169.254.169.254 gets credentials. The EC2 role's trust policy only requires the EC2 instance to be the caller — it doesn't verify which process on the EC2 is making the call.

**Where detection could happen:**
- GuardDuty: `CredentialAccess:EC2/MetadataDNSRebind` or `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — triggered when the stolen credentials are used from an IP outside AWS.
- CloudTrail: `GetObject` calls from an IP that is not the EC2 instance's IP (API calls will use attacker's IP, not EC2 IP).
- S3 Access Logs: unusual access patterns (large `ListBucket` + `GetObject` volume).

**Mitigation:** Enforce IMDSv2. Scope IAM role to only the specific S3 buckets and operations needed (not `s3:*`). Add a bucket policy `Condition` requiring requests to come from the VPC (`aws:SourceVpc`).

---

### Attack 3: Confused Deputy / Cross-Account Policy Misconfiguration

**Category:** Logic flaw in bucket policy allowing unintended cross-account access
**Attacker assumptions:** Attacker controls an AWS account. Target bucket has a policy that allows a broad principal condition.

**Step-by-step execution:**

The vulnerable bucket policy:
```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "*"},
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::company-data-bucket/*",
  "Condition": {
    "StringEquals": {
      "aws:PrincipalOrgID": "o-xxxxxxxxxx"
    }
  }
}
```

This policy intends to allow any principal within the AWS Organization. But:

1. An attacker who is a vendor/contractor gets a role in a member account of the organization — they legitimately satisfy `PrincipalOrgID`.
2. They use that role to access the bucket: `aws s3 cp s3://company-data-bucket/sensitive.zip .`
3. The policy allows it — the organization condition is met.

More subtle variant:
```json
{
  "Principal": {"AWS": "arn:aws:iam::*:role/DataAccessRole"}
}
```
This allows ANY AWS account's `DataAccessRole` to access the bucket — including the attacker's account if they create a role named `DataAccessRole`.

**Why this works:** The wildcard in the account ID portion of the ARN means the condition matches any account with that role name — not just accounts in your organization.

**Where detection could happen:**
- S3 Access Analyzer: will flag the bucket as accessible from external principals.
- CloudTrail: `GetObject` calls from unexpected account IDs.

---

### Attack 4: Ransomware via S3 — Delete and Ransom

**Category:** Data destruction / ransomware
**Attacker assumptions:** Has obtained IAM credentials (via SSRF, leaked keys, compromised developer machine) with S3 write/delete permissions.

**Step-by-step execution:**

1. Attacker enumerates all buckets: `aws s3 ls`
2. For each bucket, attacker:
   a. Downloads all data (exfiltration + leverage for ransom).
   b. Re-uploads all data encrypted with their own key: `aws s3 cp s3://bucket/key s3://bucket/key --sse-c --sse-c-key <attacker_key> --metadata-directive REPLACE`
   c. Or: deletes all objects: `aws s3 rm s3://bucket --recursive`
3. Attacker contacts victim: "pay to get decryption key / get your data back."

**If versioning is disabled:** Deletion is permanent. No recovery without backups.
**If versioning is enabled:** Objects are "deleted" with a delete marker, but previous versions persist. Recovery is possible: `aws s3api list-object-versions` + remove delete markers.
**If Object Lock (Compliance mode) is enabled:** Attacker cannot delete or overwrite locked objects — ransomware fails.

**Why this works:** S3 `DeleteObject` is a normal API operation. There is no "are you sure?" step. A single AWS CLI command deletes an entire bucket's contents.

**Where detection could happen:**
- CloudTrail: volume of `DeleteObject` operations in a short window.
- EventBridge rule: alert on `s3:DeleteObject` for protected buckets.
- GuardDuty: `Execution:S3/MaliciousFile` (if malicious uploads), `Discovery:S3/BucketEnumeration`.
- AWS Backup: if S3 backup is configured, recovery is possible independent of versioning.

---

### Attack 5: Pre-Signed URL Abuse via URL Leakage

**Category:** Access control bypass via leaked capability token
**Attacker assumptions:** Has access to server logs, browser history, or a proxy that logs URLs.

**Step-by-step execution:**

1. Web application generates a 7-day pre-signed URL for a user to download `s3://company-bucket/invoices/customer-12345/invoice.pdf`.
2. The pre-signed URL is included in an email to the customer.
3. The customer's email client prefetches URLs (common in mobile email clients). The customer forwards the email — the URL is now in a third party's email.
4. Attacker who received the forwarded email extracts the URL.
5. Attacker GETs the URL — no credentials needed. The PDF is returned.
6. Attacker can also share the URL publicly until it expires (7 days).

**Alternatively:** Web application logs all URLs for debugging. Log aggregation system (Splunk, ELK) is accessible to a wider audience than intended. Internal attacker reads the pre-signed URL from logs.

**Why this works:** Pre-signed URLs are unforgeable but fully shareable. The URL IS the authorization. There is no per-user binding. S3 cannot distinguish between the intended recipient and someone who received a forwarded copy.

**Where detection could happen:**
- S3 access logs: same pre-signed URL accessed from multiple distinct IPs.
- Generating a unique URL per user/per-download and correlating IP addresses.

**Mitigation:** Short expiry times (minutes, not days). Generate URLs on-demand when the user actually requests the download, not days in advance. Add Lambda@Edge or CloudFront signed URLs (which support more granular revocation). Log pre-signed URL generation events with the requesting user's identity.

---

### Attack 6: S3 Bucket Policy Injection via Terraform State Tampering

**Category:** Supply chain / IaC attack
**Attacker assumptions:** Has write access to the S3 bucket storing Terraform state, or can intercept Terraform plan/apply operations.

**Step-by-step execution:**

1. Terraform state is stored in `s3://company-terraform-state/prod/terraform.tfstate` (common pattern).
2. The state file contains the current bucket policy as a JSON string in the state.
3. Attacker with write access to the state bucket modifies the Terraform state to include a backdoor in the bucket policy:
   ```json
   {
     "Effect": "Allow",
     "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"},
     "Action": ["s3:GetObject", "s3:ListBucket"],
     "Resource": ["arn:aws:s3:::company-data-bucket", "arn:aws:s3:::company-data-bucket/*"]
   }
   ```
4. When Terraform next runs `apply`, it diffs against the (now-modified) state and applies the malicious policy to the actual bucket.
5. Attacker's account now has read access to `company-data-bucket`.

**Why this works:** Terraform state is not just a record — it drives `plan` and `apply` decisions. The state bucket is often less well-guarded than production data buckets. IaC automation (CI/CD pipelines) applies changes without human review of the diff.

**Where detection could happen:**
- CloudTrail: `PutBucketPolicy` event with modified policy — alert on any bucket policy change.
- S3 Access Analyzer: immediately detects the new cross-account access.
- AWS Config: `s3-bucket-policy-grantee-check` rule.
- Terraform state lock (DynamoDB) logs unexpected lock acquisitions.

---

## 10. Failure Points

### 10.1 Failures Under Load

| Component | Failure Mode | Trigger | Symptom |
|-----------|-------------|---------|---------|
| KMS (SSE-KMS) | ThrottlingException | > 50K req/sec per region (default) | 503 errors on S3 GET for KMS-encrypted objects |
| S3 prefix throughput | 503 SlowDown | > 5,500 GET/sec or > 3,500 PUT/sec on same prefix | Random 503 errors on hot prefixes |
| Multipart upload | Orphaned parts accumulating | Client crashes during upload | Unexpected storage costs; no visible objects |
| S3 event notifications | Notification delivery failures | SQS/SNS/Lambda throttling | Silent failure; events lost (at-least-once, not guaranteed order) |
| Pre-signed URL generation | N/A (CPU-bound local operation) | Millions of URLs/sec | CPU saturation on signing service |
| Cross-region replication | Replication lag | Very high PUT rates into source | Destination lags minutes to hours behind source |

**S3 Prefix Throughput — Critical Detail:**
S3 historically limited throughput per prefix. Modern S3 (post-2018) scales automatically:
- **3,500 PUT/COPY/POST/DELETE per second per prefix**
- **5,500 GET/HEAD per second per prefix**

A "prefix" is the portion of the key before any `/` or any arbitrary string. Adding randomness to prefixes (e.g., hash prefix before the date) distributes load:
- Bad: `2024/01/15/file1.jpg`, `2024/01/15/file2.jpg` — all in same prefix, hot spot.
- Good: `a3f2/2024/01/15/file1.jpg`, `b7c1/2024/01/15/file2.jpg` — distributed across prefixes.

### 10.2 Failures Under Attack

| Attack | Failure Mode |
|--------|-------------|
| Credential brute force | AWS rate-limits authentication failures; but valid credentials from leaked keys are indistinguishable from legitimate access |
| SigV4 replay within 15-min window | Valid requests can be replayed within the 15-minute clock skew window; idempotency must be handled at the application layer |
| ListBucket enumeration | CPU/network cost is on the attacker, not S3; S3 returns paginated results efficiently |
| Large object DoS (PUT huge files) | S3 accepts them; cost is charged to the bucket owner; set bucket lifecycle rules + max object size in WAF if using CloudFront |
| Bucket policy modification | A single `PutBucketPolicy` API call can change all access controls for the bucket instantly |

### 10.3 Common Misconfigurations

1. **Block Public Access not enabled at account level.** Per-bucket settings can be overridden by developers. Account-level settings cannot be overridden by bucket-level settings.

2. **Bucket policy allows `s3:*` on `Resource: *`.** Grants all S3 operations on all resources, including `DeleteBucket`, `PutBucketPolicy` (privilege escalation), `PutBucketAcl`.

3. **No S3 server access logging or CloudTrail data events.** Makes forensic investigation after an incident nearly impossible.

4. **Versioning disabled.** Accidental deletes and ransomware attacks have no recovery path.

5. **No lifecycle rules for incomplete multipart uploads.** Orphaned parts silently accumulate storage costs.

6. **IAM role with `s3:*` on `*` (all buckets).** Violates least privilege. Compromise of this role = compromise of all buckets.

7. **Pre-signed URLs with 7-day expiry containing sensitive data.** Leaked in logs, emails, or Referer headers.

8. **IMDSv1 allowed on EC2 instances with S3-access roles.** One SSRF vulnerability = credential theft = S3 exfiltration.

9. **No CMK rotation.** KMS automatic key rotation should be enabled. Manual CMKs should be rotated on a schedule.

10. **Terraform state in an unencrypted, non-versioned S3 bucket.** State contains all infrastructure secrets, resource configurations, and potentially outputs like passwords.

11. **CloudFront + S3 without Origin Access Control.** If S3 bucket is also publicly accessible, CloudFront's security (signed URLs, geo-blocking) can be bypassed by hitting S3 directly.

12. **Object tags used for access control in application code.** Object tags are metadata S3 doesn't enforce — access control via tags requires careful condition syntax in bucket policies. Bugs in tag-based policy logic can allow bypasses.

---

## 11. Mitigations

### 11.1 Foundational Controls (Apply to Every S3 Bucket)

| Control | Implementation | Why |
|---------|---------------|-----|
| Block Public Access | Enable all 4 settings at account AND bucket level | Defense in depth; account-level cannot be overridden by bucket-level config |
| Versioning | Enable on all buckets containing important data | Recovery from accidental deletes, ransomware |
| Object Lock (Compliance mode for logs) | Enable on audit log buckets | Ransomware cannot delete logs; required for some compliance frameworks |
| Default SSE | SSE-KMS with CMK for sensitive data; SSE-S3 minimum for all buckets | Encrypt at rest regardless of access control correctness |
| CloudTrail data events | Enable for all S3 operations (Read + Write) | Every API call logged for forensics |
| S3 Access Analyzer | Enable at account and organization level | Continuous detection of unintended public/cross-account access |
| Bucket policy HTTPS enforce | `Deny` on `aws:SecureTransport: false` | Forces TLS for all access |
| No ACLs | `ObjectOwnership: BucketOwnerEnforced` | Disables ACLs; all access via bucket policy |

### 11.2 IAM Controls

| Control | Implementation | Tradeoff |
|---------|---------------|----------|
| Least privilege | Grant only specific actions on specific prefixes | Requires discipline; can slow development if permissions too narrow |
| No long-term keys | Use IAM roles everywhere; rotate any remaining IAM user keys | Operationally simpler with roles; long-term keys are persistent compromise |
| Permission boundaries | Attach to all roles created by developers | Prevents privilege escalation via self-modification of policies |
| IMDSv2 enforcement | Set `HttpTokens: required` on all EC2 instances | Breaks some legacy software that uses IMDSv1; test before enforcing |
| SCPs | Org-level deny for `s3:PutBucketPublicAccessBlock: false` | Cannot be overridden; protects against insider mistakes |

### 11.3 Defense-in-Depth Architecture

```
GOAL: Sensitive bucket with PII/financial data

LAYER 1: Account-Level Block Public Access = ON
  "Even if every bucket policy is wrong, no public access"

LAYER 2: Bucket Policy
  - Deny non-HTTPS
  - Deny missing KMS encryption on PUT
  - Allow only specific IAM roles (not *, not account root)
  - Deny access outside specific VPC (aws:SourceVpc condition)
  - Deny access outside business hours for batch roles (aws:RequestedRegion, aws:CurrentTime)

LAYER 3: CMK with Separate Key Policy
  - IAM role needs BOTH bucket policy Allow AND KMS key policy Allow
  - KMS key rotation: automatic (annual)
  - KMS CloudTrail: every Decrypt operation logged

LAYER 4: S3 Object Lock (Governance mode for data, Compliance mode for logs)
  "Cannot be deleted without privileged permission"

LAYER 5: VPC Endpoint (Gateway)
  - All EC2/Lambda access via private endpoint
  - VPC Endpoint policy restricts to only this bucket

LAYER 6: Versioning + MFA Delete
  - Versions cannot be permanently deleted without MFA
  - Recovery from ransomware / accidents

LAYER 7: Replication to separate account
  - Cross-account CRR to an isolated backup account
  - Backup account's bucket has Object Lock
  - Even full compromise of production account → data recoverable

LAYER 8: Monitoring + Alerting
  - CloudTrail → EventBridge → Lambda → PagerDuty
  - Alert on: PutBucketPolicy, DeleteBucket, GetObject from external IP,
    large-volume ListBucket, DeleteObject spikes
```

---

## 12. Observability

### 12.1 Logging Types

**S3 Server Access Logging:**
- Enables: per-request logs delivered to a separate logging bucket.
- Format: space-delimited text (not JSON).
- Delivery: best-effort, minutes-to-hours latency, not real-time.
- Contains: requester IP, requester identity, operation, key name, response code, bytes transferred, referrer, user-agent.
- **Critical:** The logging bucket must be in the same region, and the log delivery principal must have write permission on the logging bucket.

```
Log example (parsed):
79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be
  company-data-bucket [15/Jan/2024:10:23:45 +0000]
  203.0.113.1 arn:aws:iam::123456789012:user/john
  3E57427F33A59F07 REST.PUT.OBJECT reports/2024/report.pdf
  "PUT /reports/2024/report.pdf HTTP/1.1" 200 - 1048576 1048576
  156 98 "-" "aws-cli/2.15.0 Python/3.11.6 Darwin/23.0.0"
  - - - - SigV4 TLS_AES_256_GCM_SHA384 - company-data-bucket.s3.us-east-1.amazonaws.com TLSv1.3
```

**CloudTrail (Management Events — free, always on):**
- Logs all S3 control plane operations: `CreateBucket`, `DeleteBucket`, `PutBucketPolicy`, `PutBucketAcl`, etc.
- Does NOT log data plane operations (GET, PUT, DELETE of objects) by default.

**CloudTrail (Data Events — additional cost):**
- Logs every S3 data event: `GetObject`, `PutObject`, `DeleteObject`, `SelectObjectContent`.
- Essential for security monitoring.
- Cost: $0.10 per 100K events. For high-throughput buckets, this can be significant.
- Can be filtered by bucket prefix to reduce cost.

### 12.2 Metrics (CloudWatch)

| Metric | Namespace | Alert Threshold |
|--------|-----------|----------------|
| `4xxErrors` | AWS/S3 | Spike > 5% of requests = auth misconfiguration or attack |
| `5xxErrors` | AWS/S3 | Any > 0 sustained = internal S3 issue or KMS throttling |
| `TotalRequestLatency` | AWS/S3 | P99 > 500ms = KMS throttling, prefix hotspot |
| `FirstByteLatency` | AWS/S3 | P99 > 200ms (large objects) = storage layer issues |
| `BucketSizeBytes` | AWS/S3 | Unexpected rapid growth = data injection or runaway process |
| `NumberOfObjects` | AWS/S3 | Unexpected growth = test data not cleaned up; unexpected shrink = ransomware |
| `KMS DecryptionsPerSecond` | AWS/KMS | > 40K/sec = approaching throttle limit (default 50K) |
| `ReplicationLatency` | AWS/S3 | Growing lag = source PUT rate > replication throughput |

### 12.3 CloudTrail Query Patterns (Athena)

**Detect bulk exfiltration:**
```sql
SELECT useridentity.arn, count(*) as get_count, sum(cast(json_extract_scalar(requestparameters, '$.x-amz-request-payer') as bigint)) as bytes
FROM cloudtrail_s3_logs
WHERE eventname = 'GetObject'
  AND eventtime > '2024-01-15T00:00:00Z'
GROUP BY useridentity.arn
HAVING count(*) > 10000
ORDER BY get_count DESC;
```

**Detect policy changes:**
```sql
SELECT eventtime, useridentity.arn, requestparameters
FROM cloudtrail_s3_logs
WHERE eventname IN ('PutBucketPolicy', 'PutBucketAcl', 'DeleteBucketPolicy',
                    'PutPublicAccessBlock', 'DeletePublicAccessBlock')
ORDER BY eventtime DESC;
```

**Detect cross-account access:**
```sql
SELECT eventtime, useridentity.accountid, useridentity.arn, eventname, requestparameters
FROM cloudtrail_s3_logs
WHERE useridentity.accountid != '123456789012'  -- your account ID
  AND errorcode IS NULL
ORDER BY eventtime DESC;
```

### 12.4 Alert vs No-Alert

**Alert on:**
- Any `PutBucketPolicy` or `PutBucketAcl` on production buckets.
- `GetObject` requests with `errorCode: AccessDenied` from production roles (misconfiguration).
- `DeleteObject` volume spike (> 100 deletes/minute on a bucket that normally has < 10).
- `GetObject` from external IPs on buckets that should only be accessed from within VPC.
- `CreateBucket` in unexpected regions.
- Any `s3:PutBucketPublicAccessBlock` that DISABLES public access protection.
- Pre-signed URL access from multiple distinct IPs within a short window.

**Do not alert on:**
- Normal `GetObject` 403s for probe requests on the default S3 bucket URL structure (bots constantly probe `s3.amazonaws.com`).
- Single `4xx` errors from legitimate clients experiencing transient auth issues.
- `HeadObject` from CloudFront (normal cache behavior).
- Lifecycle rule deletions (scheduled; expected).

---

## 13. Scaling Considerations

### 13.1 S3 Throughput Scaling

S3 is designed for massive scale, but specific patterns can cause bottlenecks:

**Read throughput (per prefix):**
- 5,500 GET/HEAD requests per second per prefix.
- A "prefix" is somewhat abstract — S3 partitions its keyspace internally based on the first few characters of the key. Adding randomness to key prefixes forces distribution across internal partitions.
- For read-heavy workloads: place CloudFront in front of S3. CloudFront serves from cache; S3 only serves cache misses. Effectively unlimited read throughput for hot objects.

**Write throughput (per prefix):**
- 3,500 PUT/COPY/DELETE per second per prefix.
- For high-ingest workloads (IoT, logs): use timestamp-randomized keys: `{sha256(deviceId)[:4]}/{deviceId}/{timestamp}/{filename}`.
- S3 will automatically partition hot prefixes — but this takes minutes to hours after the hot pattern starts. Pre-shard if you know the pattern in advance.

**Large object throughput:**
- Use multipart upload for objects > 100MB.
- Optimal part size: 8–16MB (balance between parallelism and overhead).
- Upload parts in parallel (8–16 concurrent part uploads).
- A single multipart upload can saturate a 10Gbps network link for large objects.

### 13.2 Horizontal vs Vertical Scaling for S3-Backed Applications

| Application Layer | Horizontal Scaling | Vertical Scaling |
|------------------|-------------------|-----------------|
| Upload API servers | ✅ Stateless; add more servers | Limited by single server bandwidth |
| S3 throughput itself | ✅ Automatic (S3 scales internally) | N/A (AWS-managed) |
| KMS throughput | ✅ Request quota increase | N/A (AWS-managed service) |
| CloudFront edge caching | ✅ Automatic | N/A |
| S3 event processing (Lambda) | ✅ Lambda scales automatically | N/A |
| Terraform/IaC pipeline | ✅ Multiple pipelines with state locks | N/A |

### 13.3 Consistency Tradeoffs

S3's consistency model (as of December 2020):
- **Strong consistency for all operations:** PUT-then-GET returns the new object. DELETE-then-GET returns 404. LIST reflects recent PUTs/DELETEs.
- This replaced the previous eventual consistency model (where a GET after PUT could return the old version for a short time).

**Remaining consistency caveats:**
- **Concurrent writes to the same key:** Last writer wins. S3 does not support conditional writes natively (no compare-and-swap). Two writers uploading different content to the same key simultaneously — one will overwrite the other with no error.
  - Mitigation: use versioning + check `x-amz-copy-source-if-match` (ETag-conditional copy).
- **Bucket listings during rapid key creation:** `ListObjectsV2` may not immediately reflect objects just written. In practice, strong consistency makes this rare — but applications should not depend on list-then-read patterns as the list reflecting all concurrent writes.
- **Replication lag (CRR/SRR):** Cross-region replicas are eventually consistent with the source. Replication latency can be minutes under normal conditions, longer during regional incidents. Applications reading from a replicated bucket can see stale state.
- **S3 Inventory accuracy:** S3 inventory reports are generated once daily or weekly. Not a real-time view of bucket contents.

### 13.4 Cost Scaling Considerations

At scale, S3 costs have unexpected drivers:
- **KMS API calls:** Every SSE-KMS GET = 1 KMS call. At $0.03 per 10K KMS calls, 1 billion GETs/month = $3,000 in KMS fees alone, plus S3 GET fees.
- **CloudTrail data events:** $0.10 per 100K events. 1 billion events/month = $1,000 in CloudTrail fees.
- **Data transfer out:** First 100GB/month free; then $0.09/GB. Moving 10TB out = $921.
- **S3 Transfer Acceleration:** ~$0.04–0.08/GB additional on top of standard transfer costs.
- Mitigation: use VPC endpoints for internal traffic (free), CloudFront for external distribution (lower per-GB cost than S3 direct), S3 Intelligent-Tiering for infrequently accessed objects.

---

## 14. Interview Questions

### Q1: Explain how S3 signature validation works and what prevents a captured request from being replayed.

**Answer:** SigV4 signature validation involves two sides re-deriving the same HMAC signature from the request canonical form (method, URI, headers, body hash) and a derived signing key (chained HMAC of: `"AWS4" + secret_key → date → region → service → "aws4_request"`). The secret key is never transmitted. S3 fetches the secret key associated with the access key ID from the IAM service internally and re-derives the expected signature. If they match, the request is authentic.

Replay prevention: The `x-amz-date` header is required and must be within 15 minutes of S3's current clock. If the request is captured and replayed after 15 minutes, `403 RequestTimeTooSkewed` is returned. Within the 15-minute window, a captured request could theoretically be replayed — this is why idempotency (PutObject is idempotent by key) mitigates the risk, and why sensitive state-changing operations should have application-level idempotency tokens. Additionally, the credential scope ties the signature to a specific region and service — a valid S3 us-east-1 signature cannot be replayed against S3 eu-west-1.

**What if:** What if someone sets their system clock 14 minutes ahead before signing? The request would be valid for 29 minutes total (15 minutes before S3's "now" is still acceptable, plus the 15 minutes of the window). This is a known edge case; the 15-minute window is generous to accommodate clock drift.

---

### Q2: Describe the exact sequence of policy evaluations S3 performs for a cross-account request. What must be true for the request to succeed?

**Answer:** For a cross-account request (principal in Account A accessing a bucket in Account B), **both** of the following must grant access:

1. **Identity-based policy in Account A** must grant the principal permission to perform the action on the specific S3 resource (the bucket ARN in Account B). Without this, even if Account B's bucket policy explicitly invites Account A, Account A's IAM system won't allow the principal to make the request.

2. **Bucket policy in Account B** must explicitly grant `Allow` to the specific principal (or role, or account) from Account A.

An explicit `Deny` in either stops the request regardless. The order of evaluation: SCPs (account-level ceiling) → Permission Boundaries (principal-level ceiling) → Identity policies → Resource policies (bucket policy). Any explicit Deny at any layer = Deny. No explicit Allow found anywhere = implicit Deny.

**What if:** What if the bucket policy has `Principal: "*"` (any principal) with an `Allow`? Within the same account, `Principal: "*"` in a bucket policy with Block Public Access disabled would grant access to anyone, including unauthenticated users. From a cross-account principal's perspective, `Principal: "*"` satisfies the resource-policy side, but the identity-policy side in the calling account still needs to permit the action. Cross-account requests always need both sides, even with wildcard principals — unless the request is from an unauthenticated (anonymous) caller.

---

### Q3: What is the difference between SSE-S3, SSE-KMS, and SSE-C? When would you choose each?

**Answer:**

**SSE-S3:** S3 manages the entire key hierarchy. S3 has an AES-256 key per object, and that key is itself encrypted by a regularly rotated master key. You have no visibility into keys, no key management burden, and no additional API calls or cost. Choose for: non-sensitive data, high-throughput workloads where KMS call rates would be a bottleneck, or when simplicity is the priority.

**SSE-KMS:** S3 calls AWS KMS for a data encryption key (DEK) per object operation. You control the KMS key: can set a separate key policy, use CloudTrail to audit every encryption/decryption, rotate keys manually or automatically, and revoke key access independently of bucket policy. The KMS key policy is a separate authorization gate — a principal needs both bucket permission AND KMS key permission to read. Choose for: PII, financial data, HIPAA/PCI/FedRAMP workloads, any data requiring key audit trails or cross-service permission boundaries. Watch for: KMS request rate limits (50K req/sec by default per region); at very high GET rates, this becomes a throttling bottleneck.

**SSE-C:** You provide a 256-bit key in every PUT and GET request. S3 uses it to encrypt/decrypt, then discards it. S3 stores only an HMAC of the key to verify future requests. AWS never stores your key — you are solely responsible for key management. If you lose the key, the data is unrecoverable. Choose for: workloads where you cannot trust AWS to hold even the encrypted key (e.g., extreme threat models), or regulatory requirements mandating customer-controlled keys with zero cloud-provider access. In practice, SSE-C is operationally complex and rarely used over AWS-managed KMS CMKs.

---

### Q4: How does S3 Block Public Access work at a technical level? What exactly does each of the four settings do?

**Answer:**

1. **`BlockPublicAcls`:** Prevents setting a public ACL on the bucket or any new object. API calls to `PutBucketAcl` or `PutObjectAcl` that would grant public access return a `403 AccessDenied`. Objects already with public ACLs are NOT affected; only new operations are blocked.

2. **`IgnorePublicAcls`:** Makes S3 ignore all public ACLs when evaluating access. Even if an object has a public-read ACL, S3 will not honor it. This retroactively neutralizes existing public ACLs without modifying them. The ACL data is still stored; it's just ignored during authorization.

3. **`BlockPublicPolicy`:** Prevents setting a bucket policy that grants public access (grants to anonymous/all principals). `PutBucketPolicy` API calls that would create a public policy return `403 InvalidBucketAclWithObjectOwnership` or `Access Denied`. Existing public policies are NOT retroactively blocked; only new `PutBucketPolicy` calls are rejected.

4. **`RestrictPublicBuckets`:** Restricts access to buckets that currently have a public policy. Even if a public bucket policy exists, only the bucket owner's AWS account and AWS service principals can access the bucket. Cross-account access and anonymous access are denied regardless of what the bucket policy says.

**Why set all 4?** They cover different scenarios:
- `BlockPublicAcls` + `BlockPublicPolicy`: preventive (stops new mistakes).
- `IgnorePublicAcls` + `RestrictPublicBuckets`: corrective (neutralizes existing mistakes).
- Account-level settings override bucket-level settings. Setting them at the account level is a stronger control.

---

### Q5: A developer reports S3 requests suddenly failing with 503 SlowDown. What is happening and how do you fix it?

**Answer:** `503 SlowDown` (also `503 Service Unavailable` with code `SlowDown`) means the request rate to a specific S3 prefix has exceeded S3's internal partition throughput (3,500 PUT/sec or 5,500 GET/sec for that prefix). S3 responds with 503 and a `Retry-After` header.

**Diagnosis:**
1. Identify which prefix is hot — look at the key pattern in CloudWatch Request Metrics filtered by prefix.
2. Check if it's reads (GET), writes (PUT), or both.
3. Check if there's an external event driving the traffic (marketing campaign, batch job, new feature launch).

**Fixes:**
- **Immediate:** Implement exponential backoff with jitter in the client (AWS SDK does this by default). The 503 is S3 telling the client to slow down; retry will succeed.
- **Structural (writes):** Randomize key prefixes. Instead of `images/2024/01/15/{filename}`, use `{sha256(filename)[:4]}/images/2024/01/15/{filename}`. S3 uses the first characters of the key to partition — randomizing them distributes writes.
- **Structural (reads):** Put CloudFront in front of S3 for high-read workloads. CloudFront serves cached copies; S3 only sees cache misses.
- **Structural (listings):** If the hotspot is from `ListObjects` on a dense prefix, redesign the key structure or cache the listing results.

**What if:** What if the workload legitimately needs > 5,500 GET/sec to the same key (one single object)? Use CloudFront (caches the single object at edge), S3 Transfer Acceleration, or place multiple copies under different keys and round-robin.

---

### Q6: Explain the SSRF → IMDS → S3 attack chain and how IMDSv2 prevents it.

**Answer:** The attack chain: SSRF vulnerability in web app → request to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → retrieves AWS temporary credentials → uses credentials from attacker's machine to access S3.

**IMDSv1:** Any HTTP GET to `169.254.169.254` from within the EC2 instance returns the metadata. An SSRF vulnerability allows an attacker to have the web application server make this request on their behalf, and the response is returned to the attacker.

**IMDSv2 (session-oriented):**
Step 1: Client must make a `PUT` request to `http://169.254.169.254/latest/api/token` with a TTL header to get a session token:
```
PUT /latest/api/token HTTP/1.1
X-aws-ec2-metadata-token-ttl-seconds: 21600
```
Response: `AQAAANj...session-token`

Step 2: Use the session token in subsequent metadata requests:
```
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
X-aws-ec2-metadata-token: AQAAANj...session-token
```

**Why this defeats SSRF:** Classic SSRF vulnerabilities (e.g., `fetch(userSuppliedUrl)`) can make GET requests to arbitrary URLs, including the metadata endpoint. However, most SSRF implementations:
1. Cannot make `PUT` requests (they follow redirects but can't initiate PUTs).
2. Cannot set custom headers like `X-aws-ec2-metadata-token`.
3. Even if they can make the initial PUT, the session token from the PUT response must be extracted and included in a second request — most SSRF primitives don't allow this multi-step interaction.

Additionally, the IMDSv2 token response has `X-Forwarded-For` awareness — if there's a proxy in the path (common in SSRF), the request is rejected (TTL hop limit = 1, implemented at the network level so the metadata service only responds to direct requests from the EC2 network interface, not through any router/proxy).

---

### Q7: How does S3 achieve 11 nines of durability? What would it take to lose an object?

**Answer:** S3's design for durability:
1. **Synchronous writes to multiple AZs:** Before returning 200 OK, S3 has written the object (or its erasure-coded chunks) to storage nodes across at least 3 separate Availability Zones. Each AZ is a physically separate data center (separate power, networking, cooling).

2. **Erasure coding:** Large objects are not stored as 3 full copies (that would be 3× storage cost). They are erasure-coded (Reed-Solomon or similar) — the object is split into N data chunks + M parity chunks. Any M chunks can be lost and the object is fully recoverable. AWS hasn't published the exact encoding parameters, but industry-standard erasure codes for 11-nines durability with 3-AZ redundancy use schemes like 6+3 (6 data chunks, 3 parity — can lose any 3, still reconstruct).

3. **Continuous data scrubbing:** S3 continuously verifies checksums of stored data. If bit rot is detected on a chunk, it's repaired from other chunks before the corruption spreads.

4. **What it would take to lose an object:**
   - Simultaneous failure of all N+M erasure code chunks — essentially impossible given AZ-level redundancy.
   - A correlated failure destroying all 3 AZs simultaneously (regional catastrophe beyond the design basis).
   - A bug in S3 itself (has happened — AWS has published incident RCAs for rare durability events affecting fractions of a percent of objects).
   - Accidental or malicious deletion via the API — this is NOT a durability failure; the data is intentionally removed. Versioning + MFA Delete protects against this.

**11 nines in practice:** 99.999999999% durability means that for 10 million objects stored for 10,000 years, you'd expect to lose one object. It's designed to make hardware failures the non-limiting factor — the remaining risk is operational (accidental deletion, software bugs, regional catastrophes).

---

### Q8: What happens when you generate a pre-signed URL with a role that expires before the URL's expiry? Can you invalidate a pre-signed URL?

**Answer:**
**Role expiry vs. URL expiry:** Pre-signed URLs are signed with the temporary credentials (access key ID + secret + session token) of the IAM role at the time of signing. The URL's `X-Amz-Expires` parameter sets the maximum age of the URL. However, the URL also becomes invalid when the underlying credentials expire — specifically, when the role's session token expires (the `Expiration` timestamp in the credentials). So the effective expiry is `min(X-Amz-Expires duration, role credential expiry)`.

Example: Role credentials expire in 1 hour. URL is generated with `X-Amz-Expires=86400` (24 hours). The URL is only valid for 1 hour (credential expiry wins).

This is why pre-signed URLs generated from short-lived role credentials (Lambda, EC2 instance profile) may have shorter-than-expected effective lifespans. To generate long-lived pre-signed URLs, use long-lived IAM user credentials (not recommended) or extend the role's `MaxSessionDuration`.

**Invalidating pre-signed URLs:** S3 does not support direct pre-signed URL revocation. To invalidate:
1. **Rotate the credentials used for signing:** If the URL was signed with IAM user credentials, rotate (delete + recreate) the access key. If signed with a role, you can't directly rotate role credentials — but you can delete the role or remove its S3 permissions, which invalidates all pre-signed URLs signed by that role.
2. **Update the bucket policy:** Add a `Deny` statement for the specific object key or the signing principal.
3. **Use CloudFront Signed URLs instead:** CloudFront has a key group mechanism where you can invalidate signer key pairs. Combined with an Origin Access Control on S3 (so the object is only accessible via CloudFront), you can revoke access by rotating the CloudFront signing key.

---

### Q9: Your application makes 100,000 S3 GET requests per minute to KMS-encrypted objects. What happens, and how do you fix it?

**Answer:** 100,000 GET/minute = ~1,667 GET/second. Each GET of a KMS-encrypted object requires a KMS `Decrypt` API call to get the plaintext DEK. 1,667 KMS calls/second approaches the default KMS limit of 50,000 calls/second per region — but consider that this may be one of many applications in your account/region sharing the KMS quota.

At higher rates (or with many applications), this causes KMS throttling: `KMSThrottlingException`, which surfaces as S3 returning `503` or errors wrapping the KMS failure.

**Fixes:**
1. **Request KMS quota increase:** Via AWS Support. Appropriate when your workload is legitimately this large.

2. **DEK caching (most impactful):** Use the AWS Encryption SDK with a caching cryptographic materials manager. The plaintext DEK is cached locally (in memory) for a configurable period. Instead of 1,667 KMS calls/second, you might make 1 KMS call/second (cache TTL = 60s, cache hits = 1,666/sec). The cache is bounded by object count and time.
   - Risk: a compromised process has access to the cached DEK in memory.
   - Mitigation: set tight cache TTL and message/bytes limits.

3. **S3 Bucket Keys:** Enable S3 Bucket Key for the bucket. Instead of S3 calling KMS once per object operation, S3 generates a bucket-level data key (refreshed periodically) and uses it to generate per-object keys locally. This reduces KMS API calls by up to 99% for typical workloads with many objects in the same bucket. Minimal code change: enable it on the bucket or at upload time with `x-amz-server-side-encryption-bucket-key-enabled: true`.

4. **Switch hot objects to SSE-S3:** Objects that are read extremely frequently but not subject to KMS audit/key policy requirements can be stored with SSE-S3 (no KMS call needed).

---

### Q10: How would you design an S3-based system where files uploaded by users in Account A are automatically accessible to an analytics service in Account B, but individual users in Account A cannot read other users' files?

**Answer:** This requires careful multi-layer policy design:

**Architecture:**
```
Account A (user uploads)          Account B (analytics)
├── Upload bucket                 └── Analytics Role
│   ├── Block Public Access ON
│   ├── Versioning ON
│   └── Bucket Policy:
│       ├── Allow: s3:PutObject for authenticated
│       │         Account A users to their own prefix only
│       │         Condition: s3:prefix matches user's ID
│       ├── Deny: s3:GetObject for Account A users
│       │         (users cannot read each other's files)
│       └── Allow: s3:GetObject + s3:ListBucket for
│                 Account B AnalyticsRole
```

**User-scoped write access (Account A bucket policy):**
```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::ACCOUNT_A:root"},
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::upload-bucket/${aws:PrincipalTag/UserId}/*",
  "Condition": {
    "StringEquals": {
      "s3:x-amz-server-side-encryption": "aws:kms"
    }
  }
}
```

The `${aws:PrincipalTag/UserId}` variable inserts the user's IAM tag value into the resource ARN condition — each user can only write to their own prefix.

**Prevent cross-user reads (bucket policy):**
```json
{
  "Effect": "Deny",
  "Principal": {"AWS": "arn:aws:iam::ACCOUNT_A:root"},
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::upload-bucket/*",
  "Condition": {
    "StringNotLike": {
      "s3:prefix": "${aws:PrincipalTag/UserId}/*"
    }
  }
}
```

**Cross-account analytics access (Account B identity policy + Account A bucket policy):**
Both sides must allow:
- Account A bucket policy: `Allow s3:GetObject, s3:ListBucket` for `arn:aws:iam::ACCOUNT_B:role/AnalyticsRole`
- Account B identity policy on AnalyticsRole: `Allow s3:GetObject, s3:ListBucket` on `arn:aws:s3:::upload-bucket/*`

**Operational consideration:** The `PrincipalTag` approach requires that every IAM identity in Account A has the `UserId` tag set. Use IAM tag policies or a centralized identity provider (Cognito) to ensure tags are always present.

---

### Q11: What is the significance of the ETag for S3 objects? When is it NOT the MD5 of the object?

**Answer:** The ETag is an HTTP response header used for cache validation and object integrity verification. For simple (non-multipart) uploads of unencrypted or SSE-S3 encrypted objects, the ETag is the MD5 hex digest of the object content. This allows clients to verify data integrity after download.

**When the ETag is NOT the MD5:**

1. **Multipart uploads:** ETag = `md5(concat(part_etags))-{num_parts}`. E.g., `d41d8cd98f00b204e9800998ecf8427e-3` for a 3-part upload. This is not the MD5 of the complete object — you cannot verify the full object by computing its MD5 and comparing to the ETag.

2. **SSE-KMS encrypted objects:** The ETag is the MD5 of the ciphertext, not the plaintext. Since the ciphertext is different from the plaintext, the ETag does not match the MD5 of the data the client receives (which is the decrypted plaintext).

3. **SSE-C encrypted objects:** Same as SSE-KMS — ETag is MD5 of ciphertext.

4. **Objects with additional checksums:** If you specify a checksum algorithm (CRC32, CRC32C, SHA1, SHA256) at upload time, the checksum is stored separately. S3 returns the checksum in `x-amz-checksum-*` headers. The ETag is still MD5-based.

**Practical implication:** Don't use ETag as a reliable integrity check for multipart-uploaded or KMS-encrypted objects. Use the `x-amz-checksum-sha256` (or other algorithm) response header if you need end-to-end integrity verification. Alternatively, compute and store your own content hash as object metadata at upload time.

---

### Q12: Explain S3 Object Lambda. How does it work mechanically, and what are the security implications?

**Answer:** S3 Object Lambda intercepts S3 `GetObject` calls and allows a Lambda function to transform the object data before it's returned to the caller. The caller makes a GET to a special "Object Lambda access point" endpoint; S3 invokes the Lambda with a pre-signed URL for the original object; Lambda fetches the original, transforms it, and writes the transformed response.

**Mechanical flow:**
```
Caller → GET s3-object-lambda.amazonaws.com/object-lambda-ap/key
S3 Object Lambda AP → invoke Lambda(event={getObjectContext: {inputS3Url: presigned_url, outputRoute, outputToken}})
Lambda:
  1. fetch(inputS3Url) → original object bytes
  2. transform(bytes) → modified bytes (redact PII, resize image, convert format, etc.)
  3. write_get_object_response(Body=modified_bytes, RequestRoute=outputRoute, RequestToken=outputToken)
Caller receives modified bytes
```

**Security implications:**

1. **Lambda execution role:** The Lambda function runs with an IAM role. This role must have `s3:GetObject` on the source bucket (to fetch via the pre-signed URL) and `s3-object-lambda:WriteGetObjectResponse`. If this role is overprivileged, a compromised Lambda could read arbitrary objects.

2. **Transformation trust boundary:** The Lambda is now in the data path. A bug in the transformation logic could expose data that should be redacted, modify data incorrectly, or fail to transform (returning the original data when it shouldn't).

3. **The pre-signed URL in the Lambda invocation event is sensitive:** It grants time-limited access to the original object. If the Lambda event is logged (e.g., full event to CloudWatch Logs), the pre-signed URL appears in logs. This URL could be used to access the unredacted original if extracted within its validity period.

4. **Denial of service via transformation:** An expensive transformation (e.g., ML inference on every image GET) can be triggered by any caller with access to the Object Lambda access point. Rate limit the access point and monitor Lambda invocation counts.

5. **Audit:** CloudTrail records the Object Lambda invocation as a `GetObject` event on the Lambda access point, NOT on the underlying bucket. The source bucket's server access logs show the Lambda's role accessing the object, not the original caller's identity. This can create gaps in audit trails if both are not monitored.

---

*End of document. This breakdown represents a production-grade S3 security and architecture reference at the level expected of a senior cloud security / distributed systems engineer.*

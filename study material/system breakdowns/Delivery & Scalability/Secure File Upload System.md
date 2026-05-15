# Secure File Upload System — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** All Engineers (Beginner to Senior), Security Engineers, Platform Architects  
**Scope:** Complete breakdown of a production-grade secure file upload system — from browser drag-and-drop to permanent cloud storage — covering every layer of security, performance, and reliability  
**System Context:** A SaaS document management platform where authenticated users upload files (PDFs, images, Office documents, videos) that are stored in S3, scanned for malware, processed (thumbnails, text extraction), and served securely to authorized parties

---

## A Beginner's Orientation: What "Secure File Upload" Really Means

**Why file uploads are uniquely dangerous:**

File upload is one of the most attack-prone features in any application. Unlike a text input where you know the data is a string, a file can contain:
- Executable code disguised as a PDF
- An HTML file that executes JavaScript when rendered
- A ZIP bomb (tiny upload that expands to terabytes)
- A file with a malicious filename that causes path traversal on the server
- An image that exploits a parsing vulnerability in the image library
- A file that contains macros, scripts, or embedded objects

**What makes an upload system "secure":**
1. **Identity verification:** Confirm who is uploading before accepting any bytes
2. **Input validation:** Verify the file is what it claims to be (not just the extension)
3. **Content isolation:** Never execute or render uploaded content in your main application context
4. **Malware scanning:** Check every file before making it accessible to other users
5. **Access control:** Ensure only authorized parties can download specific files
6. **Audit trail:** Log every upload, scan result, access, and deletion

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

### The Scenario

Alice is a project manager at a consulting firm. She needs to upload a 47MB PDF contract to a shared project workspace in the company's document management SaaS platform. Her colleague Bob will later download and review the document.

---

### Phase 1: Pre-Upload (T+0ms to T+~500ms)

Alice navigates to her project workspace and clicks "Upload Document."

**What Alice sees:** A file picker dialog opens. She selects `contract_final.pdf` (47MB).

**What actually happens before a single byte uploads:**

**T+0ms:** Alice's browser fires a `change` event on the `<input type="file">` element.

**T+10ms:** The JavaScript checks the file client-side:
```javascript
const file = event.target.files[0];

// Client-side validation (UX only, not security)
if (file.size > 100 * 1024 * 1024) {  // 100MB limit
  showError("File too large");
  return;
}

const allowedTypes = ['application/pdf', 'image/jpeg', ...];
if (!allowedTypes.includes(file.type)) {
  showError("File type not allowed");
  return;
}
```

**IMPORTANT:** Client-side validation is UX-only. An attacker can bypass it entirely by making a direct API call. The server must never trust client-side validation.

**T+50ms:** The frontend makes a request to get a **pre-signed upload URL**. This is the critical architectural decision that separates a naive upload (upload to your API server) from a production-grade one (upload directly to S3 via a pre-signed URL).

```http
POST /api/v1/uploads/initiate HTTP/2
Host: app.example.com
Authorization: Bearer eyJhbGci...
Content-Type: application/json

{
  "filename": "contract_final.pdf",
  "content_type": "application/pdf",
  "size_bytes": 49283072,
  "project_id": "proj_abc123",
  "folder_id": "folder_xyz789"
}
```

**T+60ms:** The API server processes this initiation request:
1. Validates Alice's JWT token
2. Confirms Alice has `write` permission on `proj_abc123`
3. Validates the claimed filename and content type
4. Generates a unique file ID: `file_01HNXYZ456789ABCDEF`
5. Creates a pre-signed S3 URL with conditions:
   - Maximum file size: 100MB
   - Required content type: `application/pdf`
   - Expiry: 15 minutes
   - Destination: `s3://company-uploads-raw/uploads/proj_abc123/file_01HNXYZ456789ABCDEF`
6. Inserts a database record: `{file_id, status: "pending_upload", user_id, project_id, ...}`

**T+80ms:** API server responds:

```json
{
  "upload_id": "file_01HNXYZ456789ABCDEF",
  "presigned_url": "https://company-uploads-raw.s3.amazonaws.com/uploads/proj_abc123/file_01HNXYZ456789ABCDEF?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...&X-Amz-Signature=...",
  "upload_conditions": {
    "max_size_bytes": 104857600,
    "required_content_type": "application/pdf",
    "expires_at": "2024-11-15T10:45:00Z"
  },
  "chunk_upload": {
    "enabled": true,
    "part_size_bytes": 10485760,
    "multipart_upload_id": "VXBsb2FkSWQ..."
  }
}
```

---

### Phase 2: The Upload (T+500ms to T+~30s)

Alice's 47MB file is uploaded directly to S3 (not through the API server). For large files, multipart upload is used.

**What Alice sees:** A progress bar gradually filling. "Uploading... 34%"

**What actually happens:** The frontend splits the 47MB file into 5 parts (each ~10MB) and uploads them in parallel directly to S3 using the pre-signed URLs.

```javascript
// Multipart upload
const parts = [];
const PART_SIZE = 10 * 1024 * 1024;  // 10MB

for (let i = 0; i < Math.ceil(file.size / PART_SIZE); i++) {
  const start = i * PART_SIZE;
  const end = Math.min(start + PART_SIZE, file.size);
  const part = file.slice(start, end);

  const response = await fetch(presignedPartUrls[i], {
    method: 'PUT',
    body: part,
    headers: { 'Content-Type': file.type }
  });

  parts.push({
    PartNumber: i + 1,
    ETag: response.headers.get('ETag')
  });
}
```

**Why upload directly to S3 (not through the API server)?**
- The API server doesn't handle 47MB of data → lower memory/CPU usage
- S3 handles the actual bytes → better throughput and reliability
- The pre-signed URL enforces size and content type at S3 level → server-side enforcement without server involvement
- The API server is freed for other requests during the upload duration

**T+~30s:** Upload completes. Frontend notifies the API server:

```http
POST /api/v1/uploads/file_01HNXYZ456789ABCDEF/complete HTTP/2
Authorization: Bearer eyJhbGci...

{
  "parts": [
    {"part_number": 1, "etag": "\"abc123\""},
    {"part_number": 2, "etag": "\"def456\""},
    {"part_number": 3, "etag": "\"ghi789\""},
    {"part_number": 4, "etag": "\"jkl012\""},
    {"part_number": 5, "etag": "\"mno345\""}
  ]
}
```

---

### Phase 3: Async Processing (T+30s to T+~3 minutes)

**What Alice sees:** "Upload complete! Processing your document..."

**What actually happens (all asynchronous, Alice doesn't wait):**

**T+30s:** API server:
1. Calls S3 to complete the multipart upload (assembles the parts)
2. Updates database: `{status: "processing"}`
3. Publishes a message to SQS queue: `{file_id, bucket, key, user_id, project_id}`
4. Returns `202 Accepted` to Alice's browser

**T+31s to T+~3 minutes — Background workers process:**

**Worker 1: Malware Scanner**
- Downloads the file from `s3://company-uploads-raw/` (the quarantine bucket)
- Sends to ClamAV or cloud antivirus API (AWS GuardDuty Malware Protection)
- Records result in database

**Worker 2: Content Validator**
- Reads first 512 bytes: detects actual file type via magic bytes
- `PDF: 25 50 44 46` (hexadecimal for `%PDF`)
- Compares with claimed content type
- Runs PDF-specific validation

**Worker 3: Metadata Extractor**
- If clean and valid: extract metadata (page count, author, creation date)
- Generate thumbnail (first page as JPEG for preview)
- Extract text content (for search indexing)

**Worker 4: Storage Mover**
- If all checks pass: move file from quarantine bucket to permanent bucket
- Apply server-side encryption (SSE-KMS)
- Update database: `{status: "available", permanent_key, metadata}`

**T+~3 minutes:** File is available. Alice's browser polling or WebSocket receives the update: "Your document is ready!"

---

### Phase 4: Download (Later)

Bob receives a notification that Alice has uploaded a contract. He clicks to view it.

**The download flow:**
1. Bob's request to `GET /api/v1/files/file_01HNXYZ456789ABCDEF`
2. API validates Bob's session and his permissions on `proj_abc123`
3. API generates a **time-limited pre-signed download URL** (expires in 60 seconds)
4. API returns the pre-signed URL to Bob's browser
5. Bob's browser follows the URL → S3 serves the file directly
6. URL expires after 60 seconds — even if Bob shares the URL, it won't work

**What Bob sees:** The PDF opens in his browser.

---

## 2. Network Layer Flow

### DNS Resolution

Two distinct DNS lookups occur in the upload flow:

**Lookup 1: Application server**
```
app.example.com
  → Browser cache → OS cache → ISP recursive resolver
  → Root NS → .com TLD NS → example.com authoritative NS
  → Returns: 203.0.113.42 (ALB/CDN IP)
  → TTL: 300 seconds
```

**Lookup 2: S3 bucket endpoint**
```
company-uploads-raw.s3.amazonaws.com
  → Browser cache → ISP recursive resolver
  → Amazon Route53 authoritative NS
  → Returns: 52.218.x.x (S3 edge IP, varies by region)
  → TTL: 60 seconds (short — allows S3 to route to nearest edge)
```

AWS S3 uses **anycast** for its endpoints: the same hostname resolves to different IPs based on the geographic location of the requester. A user in Frankfurt resolves to an S3 edge node in Frankfurt; a user in Tokyo resolves to Tokyo. This is automatic via BGP routing — the "same" IP is announced from multiple locations, and your traffic goes to the nearest announcement.

**Why does S3 use such short TTLs (60s)?** If S3 needs to drain traffic from an edge node for maintenance, the short TTL ensures clients pick up the new IP within 60 seconds. With a 5-minute TTL, traffic would continue hitting the drained node for up to 5 minutes.

---

### TCP Connection Establishment

**Browser to Application Server:**
```
Browser (10.1.2.3:54321)              ALB (203.0.113.42:443)
         |                                      |
         | SYN [seq=x, MSS=1460, SACK, WS=128] |
         |------------------------------------->|
         |                                      |
         | SYN-ACK [seq=y, ack=x+1]            |
         |<-------------------------------------|
         |                                      |
         | ACK [ack=y+1]                        |
         |------------------------------------->|
         | [TCP established — 1 RTT]            |
         | [TLS handshake begins]               |
```

**Browser to S3 (for the actual file upload):**

A separate TCP connection is established to S3. This connection handles the high-throughput upload. HTTP/2 allows multiplexing the 5 parallel part uploads over fewer TCP connections (or even one connection with multiple streams).

**Connection reuse for multipart upload:** After the first TCP+TLS handshake to S3 (cost: ~2 RTTs), subsequent part uploads reuse the same connection. Only one handshake paid for 5 part uploads.

---

### TLS 1.3 Handshake

**For the application server connection:**
```
Browser                                    ALB (203.0.113.42:443)
   |                                              |
   | ClientHello                                  |
   | - TLS 1.3                                    |
   | - cipher_suites:                             |
   |     TLS_AES_256_GCM_SHA384                  |
   |     TLS_CHACHA20_POLY1305_SHA256            |
   | - key_share: X25519 ephemeral pub key       |
   | - SNI: "app.example.com"                    |
   |--------------------------------------------->|
   |                                              |
   | ServerHello + {Certificate} + {Finished}    |
   | - Selected: TLS_AES_256_GCM_SHA384          |
   | - Certificate: app.example.com cert         |
   |   (SAN: *.example.com)                      |
   |   (OCSP staple)                             |
   | - ECDH key share                            |
   |<---------------------------------------------|
   |                                              |
   | {Finished} + [HTTP/2 PREFACE]               |
   |--------------------------------------------->|
   | [Encrypted channel established]             |
```

**Why HSTS matters here:** The browser stores `Strict-Transport-Security: max-age=63072000; includeSubDomains` after the first visit. For the next 2 years, the browser will never attempt HTTP to any subdomain of example.com. This prevents SSL stripping attacks.

**Certificate pinning for mobile apps:** If this system has a mobile app, it should pin the certificate or CA. A mobile app that pins `app.example.com`'s certificate will refuse to connect if the certificate changes — defeating MITM attacks that install rogue CA certificates on enterprise devices.

---

### Full Network Flow Diagram

```
ALICE'S BROWSER          APP SERVER (ALB)       API SERVER       S3           SQS     WORKER
      |                        |                     |            |              |         |
  [DNS: app.example.com]       |                     |            |              |         |
  [DNS: s3.amazonaws.com]      |                     |            |              |         |
      |                        |                     |            |              |         |
  TCP+TLS → ALB               |                     |            |              |         |
      |                        |                     |            |              |         |
  POST /uploads/initiate       |                     |            |              |         |
  {filename, size, type} ─────>|── proxy ──────────>|            |              |         |
      |                        |                     | [Validate JWT]            |         |
      |                        |                     | [Check permissions]       |         |
      |                        |                     | [Generate presigned URL]  |         |
      |                        |                     | [DB: INSERT file record]  |         |
      |                        |<── 200 presigned ───|            |              |         |
      |<── presigned_url ───── |                     |            |              |         |
      |                        |                     |            |              |         |
  TCP+TLS → S3                |                     |            |              |         |
  PUT /uploads/.../part1 ─────────────────────────────────────>  |              |         |
  [47MB file in chunks]        |                     |            |              |         |
  PUT /uploads/.../part2 ─────────────────────────────────────>  |              |         |
  PUT /uploads/.../part3 ─────────────────────────────────────>  |              |         |
  [parts upload in parallel]   |                     |            |              |         |
      |                        |                     |            | [Parts stored|         |
      |                        |                     |            |  in quarantine         |
      |                        |                     |            |  bucket]     |         |
  POST /uploads/{id}/complete  |                     |            |              |         |
  {parts, etags} ─────────────>|── proxy ──────────>|            |              |         |
      |                        |                     | [Complete multipart]      |         |
      |                        |                     | [DB: status=processing]   |         |
      |                        |                     | [Publish to SQS] ─────────────────> |
      |                        |<─── 202 Accepted ───|            |              |         |
      |<─── 202 Accepted ───── |                     |            |              |[SQS msg]|
      |                        |                     |            |              |── msg ─>|
      |                        |                     |            |<── Download  |         |
      |                        |                     |            |   file ──────────────  |
      |                        |                     |            | [AV scan]    |         |
      |                        |                     |            | [Validate]   |         |
      |                        |                     |            | [Extract meta|         |
      |                        |                     |            | [Move to permanent]    |
      |                        |                     | [DB: status=available]    |         |
      |                        |                     |            |              |         |
  [WebSocket/Poll: file ready] |                     |            |              |         |
      |                        |                     |            |              |         |
  GET /files/{id}              |                     |            |              |         |
  [Download request] ─────────>|── proxy ──────────>|            |              |         |
      |                        |                     | [Check permission]        |         |
      |                        |                     | [Generate presigned download URL]   |
      |                        |<── 302/presigned ───|            |              |         |
      |                        |                     |            |              |         |
  [Follow to S3]               |                     |            |              |         |
  GET s3://...presigned ──────────────────────────────────────>  |              |         |
      |                        |                     |            | [File served]|         |
      |<── PDF file bytes ─────────────────────────────────────  |              |         |
```

---

### Packet-Level Considerations

**During file upload (PUT to S3):**

A 47MB file in a 10MB part creates approximately:
```
10MB part = 10,485,760 bytes
MTU = 1,500 bytes
TCP payload per segment ≈ 1,460 bytes (MSS = MTU - 40 bytes headers)

Segments needed = 10,485,760 / 1,460 ≈ 7,181 TCP segments

With TCP congestion window starting at 10 MSS (14,600 bytes):
  First RTT: sends 14,600 bytes
  Second RTT: sends 29,200 bytes (slow start: doubles)
  Third RTT: sends 58,400 bytes
  ...
  Ramp-up takes ~20-30 RTTs to reach wire speed

At 50ms RTT (typical internet):
  1 RTT = 50ms, 20 RTTs = 1 second just for ramp-up
  Then full speed: ~10MB/s on a 100Mbps connection
```

**Why this matters:** For 47MB uploads over a typical home broadband connection, the TCP slow-start phase is noticeable. This is why multipart upload with parallel parts is important — each part has its own TCP stream that ramps up, but they ramp up in parallel, effectively multiplying throughput.

---

## 3. Application Layer Flow

### The Upload Initiation Request

```http
POST /api/v1/uploads/initiate HTTP/2
Host: app.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0yMDI0LTAxIn0.eyJzdWIiOiJ1c2VyX2FsaWNlXzEyMyIsInByb2plY3RzIjpbInByb2pfYWJjMTIzIl0sInJvbGUiOiJtZW1iZXIifQ.SIGNATURE
Content-Type: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
Origin: https://app.example.com
Content-Length: 156

{
  "filename": "contract_final.pdf",
  "content_type": "application/pdf",
  "size_bytes": 49283072,
  "project_id": "proj_abc123",
  "folder_id": "folder_xyz789"
}
```

**How the server parses and validates this request:**

```python
class UploadInitiateHandler:
    def handle(self, request):
        # 1. Parse body
        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return Response(400, {"error": "Invalid JSON"})

        # 2. Validate required fields
        required_fields = ["filename", "content_type", "size_bytes", "project_id"]
        for field in required_fields:
            if field not in body:
                return Response(400, {"error": f"Missing required field: {field}"})

        # 3. Validate filename
        filename = body["filename"]
        if len(filename) > 255:
            return Response(400, {"error": "Filename too long"})
        if not re.match(r'^[\w\-. ()]+$', filename):
            return Response(400, {"error": "Filename contains invalid characters"})
        # Check for path traversal attempts
        if '..' in filename or '/' in filename or '\\' in filename:
            return Response(400, {"error": "Invalid filename"})

        # 4. Validate content type against allowlist (NOT blocklist)
        ALLOWED_CONTENT_TYPES = {
            'application/pdf',
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/plain',
            'text/csv',
        }
        if body["content_type"] not in ALLOWED_CONTENT_TYPES:
            return Response(400, {"error": "Content type not allowed"})

        # 5. Validate file size
        if body["size_bytes"] <= 0:
            return Response(400, {"error": "Invalid file size"})
        if body["size_bytes"] > MAX_FILE_SIZE:  # 100MB
            return Response(413, {"error": "File too large"})

        # 6. Validate project access (done after validating inputs to avoid DB calls on invalid requests)
        project = db.get_project(body["project_id"])
        if not project:
            return Response(404, {"error": "Project not found"})
        if not has_permission(request.user, project, "write"):
            return Response(403, {"error": "Insufficient permissions"})

        # 7. Generate file ID and pre-signed URL
        file_id = generate_ulid()  # Universally unique lexicographically sortable ID
        s3_key = f"uploads/{body['project_id']}/{file_id}"
        presigned_url = generate_presigned_put_url(
            bucket=QUARANTINE_BUCKET,
            key=s3_key,
            content_type=body["content_type"],
            max_size=body["size_bytes"],
            expires_in=900  # 15 minutes
        )

        # 8. Create database record
        db.create_file_record({
            "id": file_id,
            "filename": filename,
            "content_type": body["content_type"],
            "size_bytes": body["size_bytes"],
            "project_id": body["project_id"],
            "folder_id": body.get("folder_id"),
            "uploaded_by": request.user.id,
            "status": "pending_upload",
            "s3_key": s3_key,
            "created_at": now()
        })

        return Response(200, {
            "upload_id": file_id,
            "presigned_url": presigned_url,
            ...
        })
```

**Critical: Allowlist vs. Blocklist for content types**

```python
# WRONG — blocklist approach:
BLOCKED_TYPES = {'application/x-executable', 'application/x-msdownload', ...}
if content_type not in BLOCKED_TYPES:
    allow()  # What about 'application/x-php'? 'text/html'? etc.

# RIGHT — allowlist approach:
ALLOWED_TYPES = {'application/pdf', 'image/jpeg', ...}
if content_type not in ALLOWED_TYPES:
    reject()  # Everything not explicitly allowed is denied
```

---

### S3 Pre-Signed URL Mechanics

```python
import boto3
from botocore.config import Config

def generate_presigned_put_url(bucket, key, content_type, max_size, expires_in):
    s3 = boto3.client('s3',
        config=Config(signature_version='s3v4')
    )

    # For simple upload (< 5MB):
    url = s3.generate_presigned_url(
        'put_object',
        Params={
            'Bucket': bucket,
            'Key': key,
            'ContentType': content_type,  # S3 enforces this
        },
        ExpiresIn=expires_in
    )
    return url

def generate_presigned_post_url(bucket, key, content_type, max_size, expires_in):
    """
    Presigned POST allows enforcing conditions at S3:
    - Max content length
    - Required content type
    - Required key prefix
    """
    fields = {
        'Content-Type': content_type,
    }
    conditions = [
        {'Content-Type': content_type},
        ['content-length-range', 1, max_size],  # 1 byte to max_size
        {'key': key},
        {'bucket': bucket},
    ]

    result = s3.generate_presigned_post(
        Bucket=bucket,
        Key=key,
        Fields=fields,
        Conditions=conditions,
        ExpiresIn=expires_in
    )
    return result
```

**The S3 signature verification process:**

When a browser uploads using the pre-signed URL, S3 verifies:
1. The signature is valid (computed using AWS credentials that only your server has)
2. The signature hasn't expired (timestamp embedded in URL)
3. The Content-Type header matches what was signed
4. The content length matches the signed conditions (for POST conditions)
5. The key matches exactly

If any of these checks fail, S3 rejects the upload with a 403 Forbidden — WITHOUT any involvement from your API server. The API server doesn't need to be on the upload path at all.

---

### Response Construction

**202 Accepted (after upload completion notification):**

```http
HTTP/2 202 Accepted
Content-Type: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
Retry-After: 30

{
  "file_id": "file_01HNXYZ456789ABCDEF",
  "status": "processing",
  "message": "Your file has been received and is being processed",
  "status_url": "/api/v1/uploads/file_01HNXYZ456789ABCDEF/status",
  "estimated_completion_seconds": 30
}
```

**Why 202 instead of 200 or 201?**
- 201 Created: The resource has been created and is available
- 202 Accepted: The request has been accepted for processing but not yet completed
- File upload with async processing: the file record exists but isn't "available" until processing completes → 202 is correct

---

## 4. Backend Architecture

### Complete Service Topology

```
                          ┌──────────────────────────────────────────────────────────┐
                          │                  UPLOAD FLOW                             │
                          │                                                          │
    Browser               │  CDN / ALB     API Server      S3 Quarantine            │
       ├── initiate ────────────────────> ──────────────> [Generate presigned URL]   │
       ├── upload ────────────────────────────────────────────────────> [Store file] │
       └── complete ──────────────────> ──────────────> [Assemble multipart]        │
                          │                    │                                     │
                          │           ┌────────┴──────────────────────────────────┐  │
                          │           │         Processing Pipeline               │  │
                          │           │   SQS Queue ──> Workers                   │  │
                          │           │                  ├── Malware Scanner       │  │
                          │           │                  ├── Content Validator     │  │
                          │           │                  ├── Metadata Extractor    │  │
                          │           │                  └── Storage Mover         │  │
                          │           │                       └── S3 Permanent    │  │
                          │           └────────────────────────────────────────────┘  │
                          │                                                          │
                          └──────────────────────────────────────────────────────────┘

                          ┌──────────────────────────────────────────────────────────┐
                          │                 DOWNLOAD FLOW                            │
                          │                                                          │
    Browser               │  CDN / ALB     API Server      S3 Permanent             │
       └── GET /file/id ────────────────> ──────────────> [Generate presigned GET]  │
                          │                    │                                     │
       └── Follow URL ──────────────────────────────────────────────────> [Serve]   │
                          └──────────────────────────────────────────────────────────┘
```

---

### Database Schema (PostgreSQL)

```sql
-- Core file record
CREATE TABLE files (
  id                VARCHAR(26) PRIMARY KEY,   -- ULID: sortable, unique
  filename          VARCHAR(255) NOT NULL,
  display_name      VARCHAR(255),              -- User-editable display name
  content_type      VARCHAR(100) NOT NULL,
  size_bytes        BIGINT NOT NULL,
  project_id        VARCHAR(26) NOT NULL REFERENCES projects(id),
  folder_id         VARCHAR(26) REFERENCES folders(id),
  uploaded_by       VARCHAR(26) NOT NULL REFERENCES users(id),

  -- Storage
  s3_bucket         VARCHAR(255),             -- Which bucket (quarantine vs permanent)
  s3_key            VARCHAR(1024),            -- Full S3 object key
  s3_etag           VARCHAR(64),              -- S3 ETag (MD5 hash of upload)
  sha256_hash       VARCHAR(64),              -- Content hash (computed during processing)

  -- Status lifecycle
  status            VARCHAR(30) NOT NULL DEFAULT 'pending_upload',
  -- Enum: pending_upload, uploaded, scanning, processing, available,
  --       scan_failed, processing_failed, deleted

  -- Security
  scan_status       VARCHAR(30),              -- clean, infected, error, pending
  scan_completed_at TIMESTAMPTZ,
  scan_result_detail TEXT,                   -- What threat was found (if any)

  -- Metadata
  metadata          JSONB,                    -- page_count, dimensions, author, etc.
  thumbnail_key     VARCHAR(1024),            -- S3 key for thumbnail

  -- Audit
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at        TIMESTAMPTZ,             -- Soft delete

  -- Constraints
  CONSTRAINT valid_status CHECK (status IN (
    'pending_upload', 'uploaded', 'scanning', 'processing',
    'available', 'scan_failed', 'processing_failed', 'deleted'
  ))
);

-- Immutable audit log (append-only, never UPDATE or DELETE)
CREATE TABLE file_events (
  id         BIGSERIAL PRIMARY KEY,
  file_id    VARCHAR(26) NOT NULL,
  event_type VARCHAR(50) NOT NULL,   -- uploaded, downloaded, deleted, scanned, shared
  actor_id   VARCHAR(26),            -- User who triggered the event (null for system)
  actor_ip   VARCHAR(45),            -- IP address at event time
  detail     JSONB,                  -- Event-specific data
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- This table has no foreign key to files — even deleted files need events

-- Access control
CREATE TABLE file_permissions (
  file_id     VARCHAR(26) NOT NULL,
  principal_type VARCHAR(20) NOT NULL,  -- 'user', 'team', 'project'
  principal_id   VARCHAR(26) NOT NULL,
  permission  VARCHAR(20) NOT NULL,     -- 'read', 'write', 'delete', 'admin'
  granted_by  VARCHAR(26) NOT NULL,
  granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ,
  PRIMARY KEY (file_id, principal_type, principal_id)
);

CREATE INDEX idx_files_project_id ON files(project_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_files_status ON files(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_file_events_file_id ON file_events(file_id);
CREATE INDEX idx_file_events_actor_id ON file_events(actor_id);
```

---

### Worker Architecture

```python
class FileProcessingWorker:
    """Processes files from the SQS queue after upload completion."""

    def __init__(self):
        self.sqs = boto3.client('sqs')
        self.s3 = boto3.client('s3')
        self.db = DatabasePool()
        self.av_scanner = AntivirusScanner()

    def run(self):
        while True:
            messages = self.sqs.receive_message(
                QueueUrl=PROCESSING_QUEUE_URL,
                MaxNumberOfMessages=1,         # Process one at a time (memory-intensive)
                WaitTimeSeconds=20,            # Long polling — wait up to 20s for messages
                VisibilityTimeout=300          # 5 minutes to process before another worker can claim
            )

            for message in messages.get('Messages', []):
                try:
                    self.process_message(message)
                    self.sqs.delete_message(...)  # Only delete on success
                except Exception as e:
                    logger.error("Processing failed", file_id=..., error=e)
                    # Message becomes visible again after VisibilityTimeout
                    # SQS dead-letter queue receives message after N failures

    def process_message(self, message):
        payload = json.loads(message['Body'])
        file_id = payload['file_id']
        s3_key = payload['s3_key']

        # Step 1: Download from quarantine to temp storage
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            self.s3.download_fileobj(QUARANTINE_BUCKET, s3_key, tmp)
            tmp_path = tmp.name

        try:
            # Step 2: Validate actual file type via magic bytes
            self.validate_file_type(tmp_path, payload['claimed_content_type'])

            # Step 3: Malware scan
            self.db.update_file_status(file_id, 'scanning')
            scan_result = self.av_scanner.scan(tmp_path)

            if scan_result.infected:
                self.db.update_file_status(file_id, 'scan_failed',
                    scan_result_detail=scan_result.threat_name)
                self.s3.delete_object(Bucket=QUARANTINE_BUCKET, Key=s3_key)
                self.notify_user_of_rejection(file_id, reason="malware_detected")
                return  # Stop processing — don't move to permanent storage

            # Step 4: Extract metadata
            metadata = self.extract_metadata(tmp_path, payload['content_type'])

            # Step 5: Generate thumbnail (for PDFs and images)
            thumbnail_key = None
            if payload['content_type'] in THUMBNAIL_SUPPORTED_TYPES:
                thumbnail_key = self.generate_thumbnail(tmp_path, file_id)

            # Step 6: Move to permanent storage with encryption
            permanent_key = f"files/{payload['project_id']}/{file_id}"
            self.s3.copy_object(
                CopySource={'Bucket': QUARANTINE_BUCKET, 'Key': s3_key},
                Bucket=PERMANENT_BUCKET,
                Key=permanent_key,
                ServerSideEncryption='aws:kms',
                SSEKMSKeyId=KMS_KEY_ARN,
                StorageClass='STANDARD_IA'  # Infrequently accessed, cheaper
            )

            # Step 7: Delete from quarantine
            self.s3.delete_object(Bucket=QUARANTINE_BUCKET, Key=s3_key)

            # Step 8: Update database
            sha256 = self.compute_sha256(tmp_path)
            self.db.update_file_available(file_id, {
                's3_bucket': PERMANENT_BUCKET,
                's3_key': permanent_key,
                'sha256_hash': sha256,
                'metadata': metadata,
                'thumbnail_key': thumbnail_key,
                'status': 'available',
                'scan_status': 'clean'
            })

            # Step 9: Index for search
            self.search_indexer.index_file(file_id, metadata)

        finally:
            os.unlink(tmp_path)  # Always clean up temp file

    def validate_file_type(self, path, claimed_type):
        """Validate actual file type via magic bytes — not just extension or MIME."""
        import magic  # python-magic library (wrapper for libmagic)

        detected_mime = magic.from_file(path, mime=True)

        # For PDFs: claimed application/pdf, detected must be application/pdf
        VALID_COMBINATIONS = {
            'application/pdf': {'application/pdf'},
            'image/jpeg': {'image/jpeg'},
            'image/png': {'image/png'},
            # Note: 'image/gif' files CAN be disguised as other things
            # GIF89a magic bytes are trivially forged
        }

        allowed_detected = VALID_COMBINATIONS.get(claimed_type, set())
        if detected_mime not in allowed_detected:
            raise InvalidFileTypeError(
                f"Claimed {claimed_type} but detected {detected_mime}"
            )
```

---

### Caching Architecture

```
Layer 1: CDN (CloudFront)
  - Caches: File download responses (Content-Disposition headers)
  - Cache key: Presigned URL (each URL is unique per user per time window)
  - TTL: Presigned URL TTL (60s) — file itself cached longer at edge
  - DOES NOT cache: Upload initiation responses
  - Signed URLs: CloudFront can generate signed URLs instead of S3 presigned URLs

Layer 2: Redis (Application Cache)
  - Key: "file_meta:{file_id}" → serialized file record
  - TTL: 300 seconds
  - Invalidated: When file status changes or permissions updated
  - Key: "user_permissions:{user_id}:{project_id}" → permission set
  - TTL: 60 seconds (short — permission changes need fast propagation)
  - Key: "presigned_url:{file_id}:{user_id}" → cached presigned URL
  - TTL: 45 seconds (URL expires in 60s, cache for 45s with margin)

Layer 3: Database Connection Pool (PgBouncer)
  - Not traditional caching but reduces connection overhead
  - Connection pool: 20 connections to PostgreSQL from API servers

What is NOT cached:
  - File content (too large, served from S3 directly)
  - Audit log entries (must be written immediately, never cached)
  - Scan results (security-critical, must be fresh from database)
```

---

## 5. Authentication & Authorization Flow

### JWT Structure for File Access

```json
{
  "sub": "user_alice_123",
  "iss": "https://auth.example.com",
  "aud": ["https://app.example.com"],
  "exp": 1700003600,
  "iat": 1700000000,
  "jti": "unique-token-id-abc",
  "projects": ["proj_abc123", "proj_def456"],
  "org_id": "org_xyz789",
  "roles": ["member"],
  "storage_quota_bytes": 107374182400  // 100GB
}
```

**Access control model:**

```
Permission hierarchy:
  Organization Admin → can access ALL files in org
  Project Admin → can access ALL files in project
  Project Member → can access files they own or that are shared with them
  Guest → read-only access to specific shared files

File-level permissions (file_permissions table):
  Overrides project-level permissions when more restrictive or permissive
  Example: A project member can be given explicit "delete" permission on a specific file
  Example: An org admin can be explicitly DENIED access to a confidential file
```

**The permission check cascade:**

```python
def can_user_access_file(user_id, file_id, action):
    """
    action: 'read', 'write', 'delete', 'share', 'admin'
    Returns: (allowed: bool, reason: str)
    """
    file = db.get_file(file_id)
    if not file:
        return False, "file_not_found"

    if file.status == 'deleted':
        return False, "file_deleted"

    if file.status not in ('available', 'processing'):
        # File not yet ready or was rejected
        # Only uploader can see pending files
        if file.uploaded_by == user_id:
            return True, "uploader"
        return False, "file_unavailable"

    # Check file-level explicit permissions first
    file_perm = db.get_file_permission(file_id, user_id)
    if file_perm:
        if file_perm.explicitly_denied:
            return False, "explicitly_denied"
        if action in file_perm.permissions:
            return True, "explicit_file_permission"

    # Check project membership
    project = db.get_project(file.project_id)
    user_role = db.get_user_project_role(user_id, file.project_id)

    if not user_role:
        return False, "not_project_member"

    # Map role to permissions
    ROLE_PERMISSIONS = {
        'admin': {'read', 'write', 'delete', 'share', 'admin'},
        'member': {'read', 'write'},
        'viewer': {'read'},
    }

    allowed_actions = ROLE_PERMISSIONS.get(user_role, set())
    if action in allowed_actions:
        return True, f"project_role_{user_role}"

    return False, "insufficient_permission"
```

---

### Pre-Signed URL as Authentication Token

**The pre-signed URL IS the authentication for the S3 upload/download:**

```
Upload URL structure:
https://bucket.s3.amazonaws.com/key
  ?X-Amz-Algorithm=AWS4-HMAC-SHA256
  &X-Amz-Credential=AKID/20241115/us-east-1/s3/aws4_request
  &X-Amz-Date=20241115T103000Z
  &X-Amz-Expires=900              ← 15 minutes
  &X-Amz-Security-Token=...       ← If using temporary credentials
  &X-Amz-Signature=abc123...      ← HMAC-SHA256 of canonical request

This signature is computed using:
  - Your AWS credentials (access key ID + secret access key)
  - The request parameters (bucket, key, headers, conditions)
  - The current timestamp
  - The expiry time

S3 verification:
  1. Recomputes the expected signature using the same algorithm
  2. Compares with the submitted signature (timing-safe comparison)
  3. Checks timestamp hasn't expired
  4. Verifies the conditions match (content type, size)
```

**Expiry strategy:**

```
Upload URL TTL: 15 minutes
  Why: Long enough for a user to select files and begin uploading
       Short enough to limit window if URL is leaked

Download URL TTL: 60 seconds
  Why: User immediately follows the URL (redirect); 60s is generous
       Short enough that shared/leaked URLs quickly become useless

Streaming URL TTL: 30 minutes
  Why: Video must stream continuously for 30 min
       Must balance security vs usability

Thumbnail URL TTL: 1 hour
  Why: Thumbnails are loaded by browser when navigating folder
       Browser caches them; refreshed every hour
```

---

### Trust Boundaries in the Upload Flow

```
ZONE 1: Client (Untrusted)
  - Browser, mobile app
  - Controls: NOTHING we trust
  - Provides: Filename, claimed content type, file bytes
  - We validate: Everything server-side

ZONE 2: CDN / Edge (Low-Medium Trust)
  - Terminates TLS, provides DDoS protection
  - We trust: That requests from CDN are properly forwarded
  - We verify: CDN-specific headers (CF-Connecting-IP, etc.)

ZONE 3: API Server (High Trust)
  - Validates JWTs, manages permissions
  - Generates pre-signed URLs (only this tier can sign with AWS credentials)
  - We trust: Code running here has been reviewed and deployed securely

ZONE 4: S3 Quarantine Bucket (High Trust)
  - Accepts untrusted file bytes but via signed URL
  - CANNOT be accessed by any Lambda or service directly
  - Access: Processing workers ONLY (via IAM policy)
  - Files here: NEVER served to users directly

ZONE 5: Processing Workers (High Trust)
  - Downloads from quarantine, scans, validates
  - Only writes to permanent bucket after passing all checks
  - IAM role: can read quarantine, write permanent, delete quarantine

ZONE 6: S3 Permanent Bucket (High Trust)
  - Contains only clean, validated, processed files
  - Access: Only via pre-signed URLs from API server
  - Public access: BLOCKED at bucket policy level
  - Bucket policy: DENY * unless specific conditions met
```

---

## 6. Data Flow

### File Data Transformation Pipeline

```
Original File (bytes at source)
    │
    │ TLS encryption in transit
    │
    ▼
S3 Quarantine Bucket
    - No encryption key accessible to application code
    - Files stored but cannot be served to users
    - Bucket policy: DENY GetObject from any principal
    │
    │ Worker downloads (IAM role authentication)
    │
    ▼
Worker Temp Storage (ephemeral EBS)
    - Encrypted EBS volume
    - Files exist only during processing
    - Automatically cleaned up after processing
    │
    │ Malware scan → metadata extraction → thumbnail generation
    │
    ▼
S3 Permanent Bucket (if clean and valid)
    - SSE-KMS encryption
    - KMS key managed by customer (BYOK option)
    - Bucket versioning enabled (protect against accidental delete)
    - Access logging enabled (who accessed which file, when)
    - S3 Object Lock (optional: WORM - Write Once Read Many for compliance)
    │
    │ Pre-signed URL (time-limited, user-specific)
    │
    ▼
Client (via CloudFront or direct S3)
    - Content served with:
      Content-Disposition: attachment; filename="contract_final.pdf"
      Content-Type: application/pdf
      Cache-Control: private, no-store   (don't cache sensitive files)
      X-Content-Type-Options: nosniff
```

### What Data Is Stored Where

| Data Type | Location | Retention | Encryption |
|---|---|---|---|
| Raw uploaded file | S3 Quarantine → S3 Permanent | 7 years | AES-256 (SSE-KMS) |
| File metadata | PostgreSQL | 7 years | Column encryption for PII |
| Thumbnails | S3 Permanent/thumbnails/ | As long as file exists | AES-256 |
| Extracted text (search) | Elasticsearch | As long as file exists | AES-256 at rest |
| Audit events | PostgreSQL (append-only) | 7 years minimum | DB-level encryption |
| Access logs | S3 Access Logs bucket | 1 year | AES-256 |
| Temp processing files | Worker EBS (deleted after use) | Minutes | EBS encryption |
| API keys / tokens | Redis + DB | Session duration | Redis encryption at rest |

---

### Serialization Formats

| Interface | Format | Encoding | Notes |
|---|---|---|---|
| API request bodies | JSON | UTF-8 | All inputs validated against schema |
| Database records | PostgreSQL native types | Binary protocol | ULID for IDs, not UUIDs |
| Worker queue messages | JSON | UTF-8 | Published to SQS |
| File events (audit) | JSONB in PostgreSQL | Binary JSON | Immutable after insert |
| File metadata | JSONB | Binary JSON | Schema-less but validated |
| Search index | Elasticsearch JSON | UTF-8 | Tokenized and indexed |
| S3 object metadata | HTTP headers | ASCII | Limited to printable ASCII |
| Thumbnails | JPEG | Binary | Quality 75%, max 800px |

---

## 7. Security Controls

### Upload Security Controls

**1. File type validation via magic bytes:**

```python
# Magic byte signatures for common file types
MAGIC_BYTES = {
    'application/pdf': [(0, b'%PDF')],
    'image/jpeg': [(0, b'\xff\xd8\xff')],
    'image/png': [(0, b'\x89PNG\r\n\x1a\n')],
    'image/gif': [(0, b'GIF87a'), (0, b'GIF89a')],
    'application/zip': [
        (0, b'PK\x03\x04'),   # Regular ZIP
        (0, b'PK\x05\x06'),   # Empty ZIP
        (0, b'PK\x07\x08'),   # Spanning ZIP
    ],
    # DOCX, XLSX, PPTX are ZIP files — need additional checks
}

def validate_magic_bytes(filepath, claimed_mime):
    with open(filepath, 'rb') as f:
        header = f.read(512)  # Read first 512 bytes

    expected_signatures = MAGIC_BYTES.get(claimed_mime, [])
    if not expected_signatures:
        # Unknown claimed type — reject
        raise InvalidFileTypeError(f"Unknown MIME type: {claimed_mime}")

    for offset, signature in expected_signatures:
        if header[offset:offset+len(signature)] == signature:
            return True

    raise InvalidFileTypeError(
        f"File does not match claimed type {claimed_mime}"
    )
```

**Why magic bytes can be fooled — and additional defenses:**

```
Magic bytes are necessary but NOT sufficient:
  - A JPEG file with an embedded JavaScript payload has valid JPEG magic bytes
  - A PDF can contain embedded JavaScript (and often does — legitimate PDFs use it)
  - A GIF89a header can be prepended to PHP code (PHP header bypass)

Additional defenses needed:
  1. Content-aware parsing: Parse the file as the claimed type
     - For PDFs: use a PDF parser, check for JavaScript objects
     - For images: re-encode the image (strips metadata and embedded code)
     - For archives: recursively scan contents

  2. Format-specific validators:
     - PDF: pdfinfo, pdf2txt to detect anomalies
     - Office: Open and re-save in a sandbox
     - Images: Re-encode using PIL/Pillow (strips EXIF, embedded payloads)
```

**2. Content Disarm and Reconstruction (CDR):**

```python
class ImageSanitizer:
    """Re-encodes images to strip any embedded content."""

    def sanitize(self, input_path, output_path):
        from PIL import Image

        try:
            # Open original
            img = Image.open(input_path)

            # Verify it's actually a valid image
            img.verify()  # Raises exception if not a valid image

            # Reopen (verify closes the image)
            img = Image.open(input_path)

            # Strip EXIF data by converting to RGB and re-saving
            # This removes: GPS location, device info, embedded thumbnails,
            # and any malicious EXIF data that could exploit parsing vulnerabilities
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGBA')
            else:
                img = img.convert('RGB')

            # Save as new image — no embedded data survives
            img.save(output_path, format='JPEG', quality=85, optimize=True)

        except Exception as e:
            raise SanitizationError(f"Image sanitization failed: {e}")
```

**3. Antivirus / Malware Scanning:**

```python
class AntivirusScanner:
    def scan(self, filepath):
        # Option 1: ClamAV (open source, self-hosted)
        result = subprocess.run(
            ['clamdscan', '--no-summary', filepath],
            capture_output=True,
            timeout=120,  # 2 minutes max
            user='clamav'  # Run as restricted user
        )
        if result.returncode == 0:
            return ScanResult(infected=False)
        elif result.returncode == 1:
            threat = self.parse_threat_name(result.stdout)
            return ScanResult(infected=True, threat_name=threat)
        else:
            raise ScanError(f"Scanner error: {result.stderr}")

    # Option 2: AWS GuardDuty Malware Protection
    # Automatically scans S3 objects when they're added
    # No additional code needed — attach to bucket via EventBridge
    # Results delivered via SNS/EventBridge events

    # Option 3: Third-party API (VirusTotal, OPSWAT)
    def scan_via_api(self, file_hash):
        response = requests.post(
            'https://www.virustotal.com/api/v3/files',
            headers={'x-apikey': self.api_key},
            files={'file': open(filepath, 'rb')}
        )
        # Poll for results — usually 1-5 minutes
```

---

### Download Security Controls

**Pre-signed URL generation:**

```python
def generate_download_url(file_id, user_id, request_ip):
    file = db.get_file(file_id)

    # Log the download attempt
    db.create_file_event({
        'file_id': file_id,
        'event_type': 'download_url_generated',
        'actor_id': user_id,
        'actor_ip': request_ip,
        'detail': {'expires_in': 60}
    })

    # Generate presigned URL
    url = s3.generate_presigned_url(
        'get_object',
        Params={
            'Bucket': PERMANENT_BUCKET,
            'Key': file.s3_key,
            'ResponseContentDisposition':
                f'attachment; filename="{quote(file.filename)}"',
            'ResponseContentType': file.content_type,
        },
        ExpiresIn=60  # 60 seconds
    )

    return url
```

**What happens if the download URL is shared with an unauthorized party:**

1. The URL expires in 60 seconds — if they receive it too late, it doesn't work
2. The URL has Alice's user context embedded in the signed parameters — if auditing is needed, the URL can be traced back to Alice
3. The URL grants download of exactly one specific file — no scope creep
4. The URL cannot be modified (signature would break)

---

### Secrets Management for the Upload System

```
Secrets used in this system:

1. AWS Credentials (for generating pre-signed URLs)
   Storage: IAM Role (EC2/ECS instance profile — no static credentials)
   Rotation: Temporary credentials rotate every 1-6 hours automatically
   Never stored: In code, environment variables, or config files

2. Database Password
   Storage: AWS Secrets Manager
   Rotation: Every 90 days (automated by Secrets Manager + Lambda)
   Accessed via: SecretsManager API at runtime, cached in memory

3. ClamAV Freshclam Config (for virus definitions)
   Storage: Not a secret — definitions are public
   Updated: Every 4 hours

4. KMS Key ARN (for S3 SSE-KMS)
   Storage: Environment variable (the ARN is not sensitive — it's a reference)
   The actual key: Managed by AWS KMS, never accessible to application code

5. JWT Signing Keys (RS256 private key)
   Storage: AWS Secrets Manager
   Access: Auth service only (other services only have public key for verification)
   Rotation: Quarterly, with overlap period for in-flight tokens

6. Elasticsearch API Key
   Storage: AWS Secrets Manager
   Rotation: When team members leave or on compromise

WHAT NEVER APPEARS IN CODE, CONFIG, OR LOGS:
  - AWS access key ID and secret access key (use IAM roles)
  - Database passwords
  - JWT private keys
  - Any credentials of any kind
```

---

## 8. Attack Surface Mapping

### All Entry Points

```
EXTERNAL ENTRY POINTS:
────────────────────────────────────────────────────────────────────────

[E1] Upload Initiation Endpoint
  POST /api/v1/uploads/initiate
  Input: filename, content_type, size_bytes, project_id
  Attack surface: Filename injection, content type bypass, quota evasion

[E2] Upload Completion Endpoint
  POST /api/v1/uploads/{id}/complete
  Input: part ETags, file_id
  Attack surface: ETag manipulation, IDOR (complete other user's upload)

[E3] Download URL Generation
  GET /api/v1/files/{id}
  Input: file_id (path parameter)
  Attack surface: IDOR, path traversal in file_id

[E4] File Status Polling
  GET /api/v1/uploads/{id}/status
  Attack surface: Information disclosure about other users' uploads

[E5] Direct S3 Upload (via pre-signed URL)
  PUT https://bucket.s3.amazonaws.com/key?...
  Input: Raw file bytes
  Attack surface: Content bypass (the signed URL enforces conditions but not content)

[E6] File Delete / Rename Endpoints
  DELETE /api/v1/files/{id}
  PATCH /api/v1/files/{id}
  Attack surface: IDOR, authorization bypass for destructive operations

[E7] Shared File Access (external recipients)
  GET /share/{share_token}
  Attack surface: Token brute force, token replay after expiry

INTERNAL ENTRY POINTS:
────────────────────────────────────────────────────────────────────────

[I1] SQS Processing Queue
  Attack surface: If attacker can write to queue, inject fake processing jobs

[I2] ClamAV/AV Scanner
  Attack surface: Zip bombs, scanner bypass techniques, resource exhaustion

[I3] Database (PostgreSQL)
  Attack surface: SQL injection (parameterized queries mitigate), privilege escalation

[I4] S3 Quarantine Bucket (internal)
  Attack surface: S3 bucket misconfiguration → public access → serve malware

[I5] S3 Permanent Bucket (internal)
  Attack surface: Misconfigured bucket policy → public access → serve all files

[I6] Elasticsearch (search index)
  Attack surface: Injection in search queries, information disclosure
```

### Attack Surface Diagram

```
                         ┌───────────────────────────────────────────────────┐
                         │           EXTERNAL ATTACK SURFACE                 │
                         │  [E1]Initiate [E2]Complete [E3]Download           │
                         │  [E4]Status   [E5]S3Upload  [E6]Delete/Rename     │
                         │  [E7]Shared Links                                 │
                         └─────────────────────────┬─────────────────────────┘
                                                   │ Internet
                         ┌─────────────────────────▼─────────────────────────┐
                         │  CDN / WAF [TB-1]                                 │
                         │  WAF: block common exploits (SQLi, XSS, etc.)     │
                         │  Rate limiting: per IP, per user                   │
                         │  File upload rate: max N uploads per user per hour │
                         └─────────────────────────┬─────────────────────────┘
                                                   │
                         ┌─────────────────────────▼─────────────────────────┐
                         │  API Server [TB-2]                                │
                         │  JWT validation, permission checks                 │
                         │  Input validation, rate limiting                   │
                         │  Pre-signed URL generation (uses AWS creds)       │
                         └──────┬──────────────────────────────────┬──────────┘
                                │                                  │
                         ┌──────▼──────────────────┐    ┌──────────▼──────────┐
                         │  S3 Quarantine [TB-3]   │    │  S3 Permanent [TB-4]│
                         │  Accepts: Signed uploads │    │  Serves: Signed GETs│
                         │  NEVER serves: GetObject │    │  NEVER: Public access│
                         │  Access: Workers ONLY    │    │  Access: Presigned   │
                         └──────┬──────────────────┘    └─────────────────────┘
                                │
                         ┌──────▼──────────────────────────────────────────────┐
                         │  Processing Workers [TB-5]                          │
                         │  [I2]AV Scanner  [I3]DB  [I1]SQS  [I6]Search      │
                         │  Sandboxed execution, restricted IAM permissions   │
                         └─────────────────────────────────────────────────────┘

TRUST BOUNDARIES:
  [TB-1] Internet → CDN: Zero trust, WAF, rate limiting
  [TB-2] CDN → API Server: JWT validation, all input untrusted
  [TB-3] Client → S3 Quarantine: Pre-signed URL enforces conditions; content untrusted
  [TB-4] Client → S3 Permanent: Pre-signed URL, content validated before reaching here
  [TB-5] SQS → Workers: Internal; IAM controls what workers can access
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — Malicious File Upload (Bypassing Content Type)

**Background for beginners:** An attacker wants to upload a PHP webshell (a file that, when executed by a web server, gives the attacker control over the server) disguised as a legitimate file.

**Attacker Assumptions:**
- Attacker has a legitimate account on the platform
- They've observed that PDF uploads are allowed
- Target: Get a PHP file executed by the server

**Step-by-Step Execution:**

1. Attacker creates a file that starts with valid PDF magic bytes but contains PHP code:
   ```
   %PDF-1.4
   <?php system($_GET['cmd']); ?>
   ```

2. Saves as `document.pdf` (or even `document.pdf.php` hoping for path traversal)

3. Makes the upload initiation request with `"content_type": "application/pdf"`

4. API server generates a pre-signed URL for `application/pdf`

5. Attacker uploads the file directly to S3 with `Content-Type: application/pdf`

6. The pre-signed URL verification at S3 passes: the Content-Type header matches the signed value

7. The file is stored in the quarantine bucket

**What happens next (where the defenses kick in):**

8. Processing worker downloads the file and runs magic byte validation:
   ```python
   with open(file_path, 'rb') as f:
       header = f.read(512)
   # header starts with %PDF — passes FIRST check
   # But: deep PDF parsing reveals no valid PDF structure objects
   ```

9. Worker runs through PDF parser (pdfinfo):
   ```
   Error: Not a valid PDF file (no cross-reference table)
   ```

10. Worker marks file as `processing_failed` — NOT moved to permanent bucket

11. User receives notification: "Your file could not be processed. Please upload a valid PDF."

12. Audit log records: file rejected due to invalid PDF structure, attacker's user ID logged

**Escalation attempt — what if they upload a real PDF that ALSO contains PHP?**

1. Attacker takes a legitimate PDF and appends PHP code at the end
2. Magic bytes check: PASSES (starts with `%PDF`)
3. PDF parser: PASSES (valid PDF structure, PHP at end is ignored by PDF parsers)
4. Antivirus scan: detects the PHP code as potentially malicious (ClamAV has signatures for webshell patterns)
5. If AV scan passes (AV isn't perfect), the file reaches permanent storage
6. BUT: PHP files are only dangerous if executed by PHP-FPM. Since this file is served directly from S3 with `Content-Type: application/pdf`, the browser renders it as a PDF, not as PHP. The embedded PHP code is harmless.

**Key insight:** The file never touches a PHP execution environment. S3 serves it as bytes with the declared content type. The attacker's code never runs.

**Where Detection Could Happen:**
- Antivirus scan result logged: `{file_id, scan_status: "infected", threat: "PHP.Shell"}`
- Alert: Any file scan returning "infected" → security team notification
- Alert: A user uploading files that consistently fail validation

---

### 9.2 — Zip Bomb (Algorithmic Complexity Attack)

**Background:** A Zip bomb is a tiny file (e.g., 42KB) that expands to an enormous size when extracted (e.g., 4.5 petabytes). The famous `42.zip` expands 42KB → 4.5PB through nested compression.

**Attacker Assumptions:**
- The upload system accepts ZIP files
- Processing workers extract or scan ZIP contents
- Target: Exhaust the processing worker's disk space or memory

**Step-by-Step Execution:**

1. Attacker creates a zip bomb:
   ```
   Outer file: 42.zip (42KB)
   Contains: 16 ZIP files, each 2KB
   Each of those contains: 16 ZIPs, each 2KB
   ...5 levels deep...
   Final level: Each file is 4.3GB of zero bytes (highly compressible)
   Total uncompressed: 4.5 petabytes
   ```

2. Attacker uploads `documents.zip` (42KB) — well within the 100MB limit

3. API validates: 42KB < 100MB, valid ZIP magic bytes (`PK\x03\x04`), passes

4. Processing worker receives the job and begins extracting...

**Where the defense must be:**

```python
class ZipExtractor:
    MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500MB limit
    MAX_FILES = 1000
    MAX_NESTING_DEPTH = 3

    def safe_extract(self, zip_path, output_dir):
        import zipfile

        total_bytes = 0
        file_count = 0

        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                # Check compressed size (from ZIP header)
                file_count += 1
                if file_count > self.MAX_FILES:
                    raise ZipBombError(f"Too many files in archive: {file_count}")

                # Check uncompressed size claim (from ZIP header — can be spoofed)
                if info.file_size > self.MAX_UNCOMPRESSED_BYTES:
                    raise ZipBombError(f"File too large when uncompressed: {info.file_size}")

                # Actually track bytes as we extract
                with zf.open(info) as source:
                    bytes_read = 0
                    while chunk := source.read(65536):
                        bytes_read += len(chunk)
                        total_bytes += len(chunk)

                        # Check both per-file and total limits
                        if bytes_read > self.MAX_UNCOMPRESSED_BYTES:
                            raise ZipBombError("File expansion limit exceeded")
                        if total_bytes > self.MAX_UNCOMPRESSED_BYTES:
                            raise ZipBombError("Total extraction limit exceeded")

                        # Write chunk to output
                        # ...

        return True

    def check_compression_ratio(self, compressed_size, uncompressed_size):
        if compressed_size == 0:
            return
        ratio = uncompressed_size / compressed_size
        if ratio > 100:  # 100:1 compression is suspicious
            raise ZipBombError(f"Suspicious compression ratio: {ratio}:1")
```

**Where Detection Could Happen:**
- Alert: Processing worker disk usage exceeds 80% → investigate active jobs
- Log: `{file_id, event: "zip_bomb_detected", compression_ratio: 107374182400}`
- Alert: Any file that triggers the ZipBombError exception
- Monitor: Worker process memory usage spikes

**Defense layers:**
1. Check compression ratio before extracting (ZIP headers contain claimed sizes)
2. Byte counting during extraction with hard limits
3. Timeout on extraction worker (max 60 seconds)
4. Run extraction in an isolated container with limited disk quota (e.g., 1GB max)

---

### 9.3 — IDOR (Insecure Direct Object Reference) on File Download

**Attacker Assumptions:**
- Attacker (Charlie) has a legitimate account
- Charlie has observed that file IDs are predictable or can be guessed
- Target: Download Alice's confidential contract

**Step-by-Step Execution:**

1. Charlie uploads his own file and notes the ID: `file_01HNXYZ456789ABCDE`

2. Charlie guesses adjacent IDs: `file_01HNXYZ456789ABCDF`, `file_01HNXYZ456789ABCDG`

3. Charlie makes a request: `GET /api/v1/files/file_01HNXYZ456789ABCDF`

4. **Vulnerable implementation:**
   ```python
   def get_file(file_id):
       file = db.get_file(file_id)
       if file:
           return generate_presigned_url(file.s3_key)  # BUG: No permission check!
       return 404
   ```

5. Server generates a presigned URL for Alice's contract and returns it to Charlie

**Where the defense must be:**

```python
def get_file(file_id, requesting_user_id):
    file = db.get_file(file_id)
    if not file:
        return 404

    # CRITICAL: Check permission before generating URL
    allowed, reason = can_user_access_file(
        requesting_user_id, file_id, 'read'
    )

    if not allowed:
        # Return 404 instead of 403 to avoid confirming file existence
        return 404  # Don't reveal: "file exists but you can't access it"

    url = generate_presigned_url(file.s3_key)
    log_download_url_generated(file_id, requesting_user_id)
    return 200, {"url": url}
```

**Why return 404 instead of 403?**

403 confirms the file exists but is forbidden. This is an information leak:
- Attacker knows the file ID is valid
- Attacker can infer: "someone has a file with this ID, it's probably valuable"
- Attacker can use this to map out which IDs are active

404 reveals nothing — the attacker doesn't know if the file doesn't exist or if they're not authorized.

**Why ULID instead of sequential integers reduces (but doesn't eliminate) IDOR risk:**

```
Sequential: file_00001, file_00002... → trivially guessable
UUID: 550e8400-e29b-41d4-a716-446655440000 → 2^122 possibilities, not guessable
ULID: 01HNXYZ456789ABCDEF → time-sortable UUID equivalent

But: Even with random IDs, you MUST check permissions server-side.
"Security through obscurity" (unpredictable IDs) is NOT access control.
It's just an additional layer that slows down IDOR exploitation.
```

**Where Detection Could Happen:**
- Alert: User making many requests to non-existent or unauthorized file IDs
- Log: `{user_id: charlie, file_id: alice_file, result: "not_found/unauthorized", ip: ...}`
- Alert: Same IP or user hitting 10+ "not found" file IDs in 5 minutes → possible enumeration

---

### 9.4 — Server-Side Request Forgery (SSRF) via File URL

**Attacker Assumptions:**
- The platform has a feature to import files from external URLs
- Target: Make the server fetch internal AWS metadata endpoint

**Step-by-Step Execution:**

1. Attacker finds the "Import from URL" feature:
   ```
   POST /api/v1/uploads/import-url
   {"url": "https://example.com/document.pdf"}
   ```

2. The server fetches this URL and stores the content as a file upload.

3. Attacker substitutes a malicious URL:
   ```json
   {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"}
   ```

4. The AWS metadata endpoint (169.254.169.254) is accessible from within EC2 instances.

5. The server fetches the URL and receives AWS IAM temporary credentials:
   ```json
   {
     "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
     "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
     "Token": "...",
     "Expiration": "2024-11-15T13:00:00Z"
   }
   ```

6. Attacker now has temporary AWS credentials — can access all S3 buckets this role can access.

**Mitigation:**

```python
def validate_import_url(url):
    import ipaddress, socket
    from urllib.parse import urlparse

    parsed = urlparse(url)

    # 1. Only allow HTTPS (not HTTP, not file://, not ftp://)
    if parsed.scheme != 'https':
        raise ValueError("Only HTTPS URLs allowed")

    # 2. Resolve the hostname
    try:
        ip_str = socket.gethostbyname(parsed.hostname)
        ip = ipaddress.ip_address(ip_str)
    except socket.gaierror:
        raise ValueError("Cannot resolve hostname")

    # 3. Block private/internal IP ranges
    if ip.is_private:
        raise ValueError("Private IP ranges not allowed")
    if ip.is_loopback:
        raise ValueError("Loopback addresses not allowed")
    if ip.is_link_local:  # 169.254.0.0/16 — AWS metadata
        raise ValueError("Link-local addresses not allowed")
    if ip.is_reserved:
        raise ValueError("Reserved addresses not allowed")

    # 4. Re-resolve after redirect (if any) — DNS rebinding protection
    # Some servers use DNS rebinding: first resolve to a public IP,
    # then after validation, resolve to a private IP
    # Mitigation: Re-validate IP after each redirect

    return True
```

**Where Detection Could Happen:**
- Alert: Any import URL request to IP ranges 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
- Log: All external URLs that the server fetches (with resolved IPs)
- Alert: HTTP response from server side that looks like AWS metadata (contains "AccessKeyId")

---

### 9.5 — Malware That Passes AV Scan (Zero-Day)

**Attacker Assumptions:**
- Attacker has a novel malware sample not yet in AV databases
- Attacker is targeting employees who download files from the platform
- Target: Infect Bob's machine when he downloads what he thinks is Alice's contract

**Why This Is Hard to Prevent Completely:**

Antivirus uses signature-based detection primarily. A zero-day malware (or custom malware not in the signature database) will pass the AV scan.

**Defense layers beyond AV:**

```
Layer 1: File type restriction
  - Don't allow executable file types: .exe, .dll, .bat, .ps1, .vbs, .jar
  - Don't allow script types: .py, .rb, .js (as downloads)
  - This removes the most dangerous vectors

Layer 2: Content type enforcement in serving
  - S3 serves with correct Content-Type
  - Browser honors Content-Type and handles file appropriately
  - A PDF served as application/pdf won't be executed
  - Add: Content-Disposition: attachment (forces download, not execution)

Layer 3: Multiple AV engines
  - ClamAV + commercial AV API (e.g., OPSWAT MetaScan)
  - Different engines have different signature databases
  - Attacker must bypass ALL engines

Layer 4: Behavioral analysis (sandboxing)
  - Run suspicious files in an isolated VM
  - Observe behavior: Does it make network calls? Write to registry? Self-replicate?
  - Tools: Cuckoo Sandbox (open source), cloud sandbox services
  - Cost: $0.05-0.50 per file, 2-10 minutes per file

Layer 5: File reputation
  - Check file hash against VirusTotal (database of 1.2 billion files)
  - If hash is known-malicious → block
  - If hash is unknown → might warrant additional scrutiny

Layer 6: User education and endpoint security
  - Users should have endpoint protection on their devices
  - Enterprise MDM with security policies
  - This is the last line of defense — assume some malware will get through
```

---

## 10. Failure Points

### Under Load

**Upload initiation endpoint overwhelmed:**

```
At 1000 uploads/second:
  Each initiation: 1 DB write + 1 S3 API call (presigned URL generation)
  DB write: ~5ms
  Presigned URL generation: ~1ms (local computation using AWS SDK)
  Response time: ~10ms total

At 10,000 uploads/second:
  DB becomes the bottleneck (write throughput)
  Connection pool exhaustion on PostgreSQL
  → Requests queue → latency spikes → timeouts → 503 errors

Mitigation:
  - Horizontal scaling of API servers
  - PgBouncer connection pooling
  - For presigned URL generation: pure computation, no DB needed if you cache file metadata
```

**Processing queue backup:**

```
Upload rate: 1,000 files/hour
Processing rate: 100 files/hour (AV scanning is slow: ~30s per file)

Queue grows: 900 files/hour backlog
In 8 hours: 7,200 files waiting
Users see: "Processing..." for hours

Mitigation:
  - Auto-scale processing workers based on SQS queue depth
  - Priority queue: prioritize smaller files, important users
  - AV scanning timeout: max 60 seconds per file, then fail safely
  - Horizontal scaling: 100 workers instead of 10 = 10x throughput
```

**S3 prefix hotspot:**

```
Bad key structure: "uploads/2024/1115/file001.pdf"
                   "uploads/2024/1115/file002.pdf"
                   ...many files with same prefix

S3 partitioning is based on key prefix.
Many keys with same prefix → same partition → hot partition → throttling

Good key structure: "uploads/{project_id}/{file_id}"
  project_id is randomly distributed → balanced S3 partitioning
  
Or: Add a random prefix: "uploads/{hash(project_id)[:2]}/{project_id}/{file_id}"
  The 2-char hex prefix (00-ff) = 256 buckets → highly distributed
```

---

### Under Attack

**Upload endpoint DDoS (even with rate limiting):**

```
Attack: 10,000 IPs each sending one upload initiation request/minute

Impact: 10,000 DB write transactions per minute
  = 167 writes/second
  = PostgreSQL primary write throughput is stressed
  
Even with rate limiting:
  Per-IP: 5 uploads/minute → 10,000 IPs = 50,000 initiation attempts/minute
  
Mitigation:
  - CAPTCHA for upload initiation (may not be practical for API-first platforms)
  - Require verified email for upload permissions (adds friction for bulk fake accounts)
  - Anomaly detection: flag accounts created in bulk
  - Strict per-account rate limiting (not per-IP)
```

**Malware scanner resource exhaustion:**

```
Attacker uploads 1000 files simultaneously, each crafted to:
  - Have valid ZIP magic bytes (passes initial check)
  - Contain 10,000 small files each (exhausts ZIP iteration)
  - Each small file requires AV signature checking

Result:
  - AV scanner CPU: 100%
  - All 1000 workers busy scanning these files
  - Legitimate files queue up waiting for workers
  - Platform effectively down for all users

Mitigation:
  - Per-file processing timeout (max 120 seconds)
  - Maximum number of files per archive (max 1000 files inside a ZIP)
  - Maximum total uncompressed size (500MB)
  - Separate worker pools: one for large/complex files, one for simple files
  - Rate limit: max N files in processing queue per user
```

---

### Common Misconfigurations

| Misconfiguration | Impact | Fix |
|---|---|---|
| S3 bucket public access not blocked | All uploaded files publicly accessible | S3 Block Public Access at account level + bucket policy DENY |
| Pre-signed URLs without content type enforcement | Upload any content type | Use pre-signed POST with conditions, not pre-signed PUT |
| AV scanning happens after moving to permanent bucket | Malware served to users before scan completes | Always scan in quarantine, never serve from quarantine |
| Temp files not cleaned up after worker crash | Disk exhaustion, data leakage | Use try/finally, or a separate cleanup job that scans for stale temp files |
| Processing worker has same IAM permissions as API server | Compromise of worker = access to credential generation | Separate IAM roles with minimum required permissions |
| S3 quarantine bucket can serve objects (no GetObject deny) | Attacker uploads malware, tricks admin into accessing it via quarantine URL | Bucket policy: explicit DENY on s3:GetObject for quarantine bucket |
| No file size check at S3 level | 10GB file uploaded (only API-level check bypassed) | Use pre-signed POST with content-length-range condition |
| Missing Content-Disposition header on downloads | Browser may execute downloaded HTML/JS instead of downloading | Always include Content-Disposition: attachment |
| EXIF data not stripped from images | GPS location, device info leaked | Re-encode all images through PIL/Pillow to strip metadata |
| ClamAV database not updated | New malware bypasses scanner | Freshclam scheduled update every 4 hours, alert if update fails |

---

## 11. Mitigations

### Defense-in-Depth Architecture

```
DEPTH 1: Access Prevention (stop before upload)
  → Authentication: valid session required to initiate upload
  → Authorization: must have write permission on the project
  → Rate limiting: max N uploads per user per hour
  → File type allowlist: reject unknown content types at initiation

DEPTH 2: Input Restriction (limit what can be uploaded)
  → Maximum file size enforced at S3 level (content-length-range condition)
  → Content type enforced at S3 level (Content-Type must match signed value)
  → Filename sanitization: remove path separators, length limit
  → Pre-signed URL expiry: upload must start within 15 minutes

DEPTH 3: Quarantine (contain the danger)
  → Files land in quarantine bucket: no public access, no application access
  → Quarantine bucket cannot serve files to users (bucket policy DENY GetObject)
  → Quarantine bucket not mounted in any web server path

DEPTH 4: Inspection (verify content)
  → Magic bytes verification: actual file type matches claimed type
  → Antivirus scan: ClamAV + commercial AV API
  → PDF structure validation: pdfinfo parser
  → ZIP/archive depth and size limits
  → Image re-encoding (strips embedded content)

DEPTH 5: Isolation (contain the processing)
  → Workers run in isolated containers with restricted permissions
  → Limited network access (only S3, AV API, DB)
  → Limited disk quota (1GB per worker)
  → Processing timeout (120 seconds max per file)
  → No browser/web context in workers (can't execute JavaScript)

DEPTH 6: Access Control (limit who gets clean files)
  → Files only accessible via API server (never direct bucket access)
  → API checks permissions before generating presigned URL
  → Presigned URLs expire quickly (60 seconds for downloads)
  → All access logged in audit trail

DEPTH 7: Monitoring (detect and respond)
  → Alert on any malware detection
  → Alert on unusual upload patterns
  → Alert on permission denied events (possible probing)
  → Alert on scanner failures
```

---

## 12. Observability

### Structured Logging

```json
// Upload initiated
{
  "timestamp": "2024-11-15T10:30:00.000Z",
  "event": "upload.initiated",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "user_alice_123",
  "project_id": "proj_abc123",
  "file_id": "file_01HNXYZ456789ABCDEF",
  "filename_hash": "sha256:abc123...",   // NEVER log actual filename (PII risk)
  "content_type": "application/pdf",
  "size_bytes": 49283072,
  "ip_hash": "sha256:def456...",
  "duration_ms": 45
}

// File scan completed
{
  "event": "file.scan.completed",
  "file_id": "file_01HNXYZ456789ABCDEF",
  "scan_engine": "clamav-1.0.3",
  "scan_result": "clean",             // or "infected" or "error"
  "threat_name": null,               // Populated if infected
  "scan_duration_ms": 1234,
  "file_size_bytes": 49283072
}

// File scan INFECTED (always alert on this)
{
  "event": "file.scan.infected",
  "level": "SECURITY",
  "file_id": "file_01HNXYZ456789ABCDEF",
  "user_id": "user_alice_123",
  "threat_name": "PHP.Webshell.Generic",
  "scan_engine": "clamav-1.0.3",
  "action_taken": "file_quarantined_deleted"
}

// Download URL generated
{
  "event": "file.download.url_generated",
  "file_id": "file_01HNXYZ456789ABCDEF",
  "user_id": "user_bob_456",
  "project_id": "proj_abc123",
  "url_expires_in_seconds": 60,
  "ip_hash": "sha256:..."
}

// IDOR attempt detected
{
  "event": "file.access.denied",
  "level": "WARN",
  "file_id": "file_01HNXYZ456789ABCDE",  // Note: different from user's file
  "requesting_user_id": "user_charlie_789",
  "reason": "not_project_member",
  "consecutive_denied_requests": 5,       // Incremented for same user
  "ip_hash": "sha256:..."
}

// What NEVER appears in logs:
// - Actual filenames (PII)
// - File content (obviously)
// - Presigned URLs (they're credentials)
// - User IP addresses in plaintext (GDPR: use hashed IPs)
// - AWS credentials
```

---

### Metrics

```
# Upload funnel metrics
upload_initiated_total{project_tier, content_type}
upload_completed_total{result="success|timeout|client_abort"}
upload_file_size_bytes{} # histogram
upload_duration_seconds{phase="initiation|transfer|completion"} # histogram

# Processing pipeline metrics
processing_queue_depth{queue="main|priority"}
processing_duration_seconds{stage="download|scan|validate|extract|move"} # histogram
processing_result_total{result="success|scan_failed|invalid_type|processing_error"}

# Security metrics (ALERT on these)
malware_detected_total{scanner="clamav|commercial"}
invalid_content_type_total{claimed_type, detected_type}
zip_bomb_detected_total{}
upload_size_limit_exceeded_total{}

# Download metrics
download_url_generated_total{file_status="available|deleted"}
download_presigned_url_expiry_remaining_seconds{} # histogram: how far in advance URLs are used
unauthorized_download_attempt_total{reason} # ALERT: spikes indicate IDOR probing

# Storage metrics
s3_quarantine_object_count{}  # Should be low (files move quickly to permanent)
s3_permanent_object_count{}
s3_permanent_storage_bytes{}
worker_temp_disk_usage_bytes{worker_id}  # ALERT if approaching limit

# Performance metrics
api_latency_seconds{endpoint="/uploads/initiate|/uploads/{id}/complete|/files/{id}"} # histogram
s3_upload_throughput_bytes_per_second{}
worker_processing_throughput_files_per_minute{}
```

---

### Alerting Rules

| Metric / Condition | Severity | Threshold | Action |
|---|---|---|---|
| `malware_detected_total` > 0 | CRITICAL | Any detection | Security team + user notification |
| `zip_bomb_detected_total` > 0 | HIGH | Any detection | Security + investigate user account |
| `invalid_content_type_total` per user > 3 in 1 hour | HIGH | 3 incidents | Flag account for review |
| `unauthorized_download_attempt_total` per user > 5 in 5 min | HIGH | 5 attempts | Rate limit + security alert |
| `processing_queue_depth` > 1000 | MEDIUM | 1000 jobs | Auto-scale workers |
| `upload_completed_total{result="timeout"}` > 5% | MEDIUM | 5% rate | Infrastructure investigation |
| `s3_quarantine_object_count` > 10,000 | HIGH | 10,000 objects | Processing worker stuck |
| `malware_scan_error_total` > 0 sustained | HIGH | Sustained errors | Scanner health check |
| `worker_temp_disk_usage_bytes` > 80% | HIGH | 80% of quota | Alert + expand quota |
| `download_presigned_url_expiry_remaining_seconds` p99 > 55s | LOW | 55s | URL generation timing (informational) |
| Normal upload initiation traffic | No alert | — | Expected |
| Normal AV scan "clean" results | No alert | — | Expected |
| Failed upload due to file size (client error) | No alert | — | Expected user error |

---

## 13. Scaling Considerations

### Upload Throughput Scaling

**Bottlenecks by phase:**

```
Phase 1: Upload Initiation (API server)
  Bottleneck: Database write throughput
  Solution: Write to primary, read from replica; connection pooling (PgBouncer)
  Scale: Horizontal (stateless API servers)
  Ceiling: PostgreSQL write throughput (~10,000 writes/second per primary)

Phase 2: File Transfer (S3)
  Bottleneck: S3 has essentially unlimited throughput per bucket
  S3 rate limits: 3,500 PUT requests/second per prefix, 5,500 GET requests/second
  Solution: Randomize key prefixes to avoid hitting per-prefix limits
  Scale: No application changes needed — S3 auto-scales

Phase 3: Processing (Workers)
  Bottleneck: AV scanning is CPU-intensive (~1-5 seconds per small file, 30s for large)
  Scale: Horizontal (add more worker instances)
  Auto-scale: CloudWatch metric → SQS queue depth → ASG scale-out
  Ceiling: ClamAV database loading time (~5 seconds per worker restart)
    Solution: Keep workers warm (don't scale to zero), or use Fargate spot instances

Phase 4: Download URL Generation (API server)
  Bottleneck: Database read for permission check
  Solution: Redis cache for permissions (60s TTL)
  Scale: Horizontal
```

**Multipart upload configuration by file size:**

```python
def get_upload_config(size_bytes):
    if size_bytes < 5 * 1024 * 1024:      # < 5MB
        return {
            "type": "simple",
            "max_parts": 1
        }
    elif size_bytes < 100 * 1024 * 1024:  # 5MB - 100MB
        return {
            "type": "multipart",
            "part_size": 10 * 1024 * 1024,  # 10MB parts
            "max_parallelism": 5
        }
    elif size_bytes < 1 * 1024 * 1024 * 1024:  # 100MB - 1GB
        return {
            "type": "multipart",
            "part_size": 50 * 1024 * 1024,  # 50MB parts
            "max_parallelism": 10
        }
    else:  # > 1GB (video files, etc.)
        return {
            "type": "multipart",
            "part_size": 100 * 1024 * 1024,  # 100MB parts
            "max_parallelism": 15
        }
```

---

### Storage Scaling

**S3 storage classes for cost optimization:**

```
Upload pipeline:
  Quarantine bucket: S3 Standard (need fast access for processing)
  Cost: $0.023/GB/month

After processing:
  Permanent bucket: S3 Standard-IA (files read infrequently)
  Cost: $0.0125/GB/month (46% cheaper)

After 90 days:
  Move to S3 Glacier Instant Retrieval (millisecond access)
  Cost: $0.004/GB/month (83% cheaper)

After 1 year:
  Move to S3 Glacier Deep Archive
  Cost: $0.00099/GB/month (96% cheaper)
  Access time: 12 hours (acceptable for compliance archival)

Lifecycle policy (S3 automatically transitions objects):
  Day 0: Standard
  Day 30: Standard-IA
  Day 90: Glacier Instant
  Day 365: Glacier Deep Archive
```

**Database scaling:**

```
Current: Single PostgreSQL primary + 1 read replica
  Handles: ~10,000 uploads/day, 100,000 download URL generations/day

At 10x scale (100,000 uploads/day):
  Solution: 3 read replicas for download URL generation (permission checks)
  Primary: Only writes (upload initiation, file status updates)
  Read traffic: Distributed across replicas
  Potential: Citus (PostgreSQL sharding) for multi-tenant scenarios

At 100x scale (1,000,000 uploads/day):
  Solution: Partition files table by project_id
  Each partition on a separate physical disk
  Or: Move to DynamoDB for file metadata (high throughput, automatically scalable)
  Keep PostgreSQL for: audit logs, permissions, complex queries
```

---

### Consistency Tradeoffs

**File status consistency:**

```
Problem: User polls for file status. Worker updates status to "available."
         API server reads from replica (has 100ms replication lag).
         User keeps seeing "processing" for 100ms after file is available.

Options:
  A. Read from primary for status checks (consistent, but higher primary load)
  B. Accept 100ms lag (eventual consistency — usually fine)
  C. Use Redis pub/sub to push status updates to API servers immediately
     (workers publish to Redis channel, API servers subscribe)
  D. WebSocket push from API server to browser when status changes

Recommended: Redis pub/sub (Option C)
  Worker updates DB status
  Worker publishes to Redis: PUBLISH file_status_updates file_01HNXYZ:available
  API server subscribed to Redis: immediately updates in-memory cache
  Browser receives WebSocket update within ~50ms of status change
```

**Pre-signed URL consistency:**

```
Scenario: Alice's permissions are revoked while she has a download URL in hand.

The URL was generated before revocation → URL is still valid for its TTL.

With 60-second TTL:
  Worst case: Alice can download for 59 seconds after losing permissions
  Usually acceptable

For higher security requirements:
  Include a token in the URL that is validated server-side each use
  Cost: Extra server call on each chunk of each download
  Benefit: Permission changes are effective immediately

Solution: S3 Object Lambda (intercepts S3 GET calls, validates permissions)
  Every download goes through Lambda → Lambda checks permissions → serves or denies
  Cost: Lambda invocation per part download (fraction of a cent)
  Benefit: Real-time permission enforcement on every byte served
```

---

## 14. Interview Questions

### Q1: "Why upload files directly to S3 via pre-signed URLs rather than through your API server?"

**Answer:**

**The naive approach (upload through API server):**

```
Client → API Server → S3

Problems:
1. The API server receives every byte of the file (47MB × 1000 simultaneous users = 47GB in memory)
2. API server becomes the bottleneck for upload throughput
3. If the API server restarts mid-upload, the upload is lost
4. API servers are expensive compute; S3 transfer is cheap storage
5. API servers typically have request body size limits (nginx default: 1MB)
```

**The correct approach (direct to S3 via pre-signed URL):**

```
Client → API Server → (gets pre-signed URL)
Client → S3 directly (47MB of bytes bypass the API server entirely)
Client → API Server → (notifies upload complete)

Benefits:
1. API server handles only tiny JSON payloads (<1KB)
2. S3 handles unlimited concurrent uploads at full bandwidth
3. If API server restarts: upload continues to S3; just re-notify when done
4. S3's PUT endpoint can handle 3,500 requests/second per prefix
5. Pre-signed URL enforces size limit and content type at S3 level
6. Multipart upload is built into S3: pause, resume, parallel parts
```

**What if → The pre-signed URL is intercepted (MITM)?**

The URL is transmitted over TLS — MITM requires breaking TLS. If TLS is broken, the MITM can see the URL. But:
- The URL is scoped to one specific bucket + key
- The URL expires in 15 minutes
- The URL is usable only for PUT (upload), not GET (download)
- Even if someone intercepts and uses the URL, they can only upload to the designated location — they can't access any other files

---

### Q2: "How do you validate that an uploaded file is actually the type it claims to be? Why is file extension checking insufficient?"

**Answer:**

**Why extension is useless:**

```python
# Attacker renames malware.exe to document.pdf
# Extension: .pdf → PASSES extension check
# But it's still malware

# Attacker does the same for MIME type in the request:
"Content-Type: application/pdf"  # attacker sets this header
# Header check: application/pdf → PASSES MIME check
# But the server trusts the client... never do this
```

**The correct hierarchy of checks:**

**Level 1: Client-side validation (UX only, not security)**
- Check file extension, MIME type from browser's `file.type`
- Purpose: Immediate user feedback, not security
- Can be bypassed: trivially

**Level 2: API-level allowlist validation**
- Server checks the claimed content type against an allowlist
- Prevents clearly wrong content types
- Still trusting the client's claim, but limits the damage

**Level 3: Magic byte verification**
- Read the first 512 bytes of the actual file
- Compare against known signatures in a database (libmagic)
- Example: PDF starts with `%PDF` (25 50 44 46 in hex)
- Much harder to bypass: attacker must understand file format internals

**Level 4: Full structural validation**
- Parse the file as the claimed type using a proper parser
- For PDF: use pdfinfo, check for valid cross-reference table, object structure
- For ZIP: verify the central directory, check file count, verify checksums
- A file with valid PDF magic bytes but invalid PDF structure fails this check

**Level 5: Content sanitization (not just validation)**
- For images: re-encode through PIL/Pillow (strips anything that isn't valid image data)
- For PDFs: some environments use LibreOffice to re-render PDFs (strips embedded JavaScript)
- For Office documents: extract content and re-create document

**Why multiple levels?**

```
Level 3 (magic bytes) catches: renamed executables, trivially wrong files
Level 4 (structural) catches: files with valid headers but invalid bodies
Level 5 (sanitization) catches: valid files with embedded malicious content
Antivirus catches: known malware signatures

No single check catches everything. Defense in depth.
```

---

### Q3: "Explain the quarantine bucket pattern. Why not just scan files in place and serve them from the same bucket?"

**Answer:**

**The problem with scan-in-place:**

```
Scenario without quarantine:
  Upload → S3 bucket → Start AV scan (async)
  
  Between upload and scan completion (30 seconds), the file is in S3.
  If someone generates a download URL during this window:
    → User downloads unscanned file
    → File might be malware
    → Attacker's goal achieved: serve malware to users
    
  Even with careful coding to "not serve until scanned":
    Race condition: scan completes "clean" while attacker swaps the file (S3 versioning bypass)
    Bug in status check: "available" status set before scan completes
    Lambda timing: scan timeout → file marked clean by default
```

**The quarantine bucket pattern:**

```
Quarantine bucket:
  - Accepts: Signed PUT uploads (files land here)
  - Denies: ALL GetObject requests (bucket policy: explicit DENY)
  - Files here: NEVER accessible to users under any circumstances
  - Workers: Can download for scanning
  
  S3 Bucket Policy:
  {
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::company-quarantine/*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalArn": "arn:aws:iam::123456789:role/processing-worker-role"
      }
    }
  }
  
  This Deny even overrides admin credentials. No human can download from quarantine.

Permanent bucket:
  - Only receives files that have passed ALL checks
  - Accepts: Signed GET requests (download URLs from API server)
  - Files here: Guaranteed clean, validated, processed

The guarantee: It is architecturally impossible to serve files from quarantine.
The only path to permanent bucket requires passing the scanning gauntlet.
```

---

### Q4: "How would you handle a user uploading a 10GB video file? What changes in your architecture?"

**Answer:**

**What changes for large files:**

**1. Pre-signed URL changes:**
```python
# For large files, use multipart upload
# Minimum part size: 5MB (S3 requirement)
# Maximum part size: 5GB
# Maximum parts: 10,000
# Max file size: 5TB

def initiate_large_upload(file_size, content_type, s3_key):
    response = s3.create_multipart_upload(
        Bucket=QUARANTINE_BUCKET,
        Key=s3_key,
        ContentType=content_type,
        ServerSideEncryption='AES256'
    )
    upload_id = response['UploadId']
    
    # Generate presigned URL for each part
    num_parts = math.ceil(file_size / PART_SIZE)  # PART_SIZE = 100MB for video
    part_urls = []
    for part_number in range(1, num_parts + 1):
        url = s3.generate_presigned_url(
            'upload_part',
            Params={
                'Bucket': QUARANTINE_BUCKET,
                'Key': s3_key,
                'UploadId': upload_id,
                'PartNumber': part_number,
            },
            ExpiresIn=3600  # 1 hour for large files
        )
        part_urls.append({'part_number': part_number, 'url': url})
    
    return {'upload_id': upload_id, 'parts': part_urls}
```

**2. Processing changes:**
```
10GB video cannot fit in Lambda memory (max 10GB) or container ephemeral storage.

Solutions:
  Option A: Stream-scan
    - Don't download entire file; stream through AV scanner in chunks
    - ClamAV supports streaming: send chunks via clamdscan --stream
    - Never need full file on disk
    
  Option B: Dedicated large-file worker
    - EC2 instance with 100GB+ attached EBS volume
    - Download, scan, process, then delete from EBS
    - Auto-terminated after processing
    
  Option C: Process in S3 directly
    - AWS Rekognition Video for content moderation (no download needed)
    - AWS Transcribe for audio content
    - Lambda can stream-process from S3 in chunks

Timeout concerns:
  10GB at 100MB/s = 100 seconds to download
  AV scan: ClamAV at 10MB/s = 1000 seconds
  
  SQS message visibility timeout: must be > total processing time
  Set VisibilityTimeout to 3600 (1 hour) for video files
```

**3. UX changes:**
```
"Your video is being processed. This may take up to 15 minutes."

Frontend polling:
  Every 10 seconds: GET /api/v1/uploads/{id}/status
  Response: {status: "processing", progress: {stage: "scanning", percent: 45}}
  
Worker updates progress:
  db.update_file_progress(file_id, stage="scanning", percent=45)
  redis.publish("file_progress", json.dumps({file_id, stage, percent}))
```

---

### Q5: "What would you change if this system needed to comply with HIPAA (health data) or PCI DSS (payment data)?"

**Answer:**

**HIPAA (Health Insurance Portability and Accountability Act):**

The system already has many controls, but HIPAA requires specific additions:

```
1. Encryption changes:
   Current: SSE-KMS (adequate for most)
   HIPAA: Customer-managed KMS key (CMEK) with documented key management procedures
   Also: Client-side encryption before uploading (encrypt before it leaves your network)
   
2. Access control changes:
   Current: Role-based permissions at project level
   HIPAA: Minimum necessary access standard → users can only access PHI files they need for their job
   Add: Access justification required for sensitive file access ("clinical need")
   
3. Audit trail changes:
   Current: Event log in database
   HIPAA: Audit logs must be tamper-evident, retained 6+ years
   Add: Write audit logs to immutable S3 (S3 Object Lock: WORM) + CloudTrail
   Add: Log every access attempt (even failed ones)
   
4. Breach notification:
   HIPAA requires notifying affected individuals within 60 days of breach discovery
   System must detect and alert on potential breaches:
   → Alert: Any malware detection (infected file might have exfiltrated data)
   → Alert: Unusual bulk download patterns (potential exfiltration)
   → Alert: Access from unauthorized locations

5. Business Associate Agreement:
   AWS, antivirus vendors, all third parties must sign a BAA
   This is a legal requirement, not technical

6. De-identification:
   Consider stripping PHI from file metadata before processing
   EXIF stripping already done for images (good for HIPAA)
```

**PCI DSS (Payment Card Industry Data Security Standard):**

PCI is less about file storage and more about cardholder data:

```
1. Don't store PAN (Primary Account Number) in files:
   If files contain card numbers, they must be:
   → Truncated (show only last 4 digits)
   → Tokenized (replaced with tokens)
   → Or stored with strict controls (PCI scope)
   
2. File scanning for card numbers:
   Before storing any file, scan for card number patterns
   regex: \b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|...)\b
   If found: reject upload or trigger compliance review
   
3. Quarterly vulnerability scans:
   Any system that could touch payment data must be scanned quarterly
   The upload pipeline likely needs to be included in PCI scope assessment

4. Penetration testing:
   Annual pen test required for PCI environments
   Upload functionality is a primary target (file upload exploits are common)
```

---

### Q6: "How would you design the pre-signed URL system to support download resumption for large files?"

**Answer:**

**The problem:** A user downloads a 5GB video file. At 80% completion (4GB received), their connection drops. Without resumption, they must restart the entire 5GB download.

**HTTP Range requests:** The solution already exists at the protocol level.

```
S3 supports byte-range GET requests natively.
Browser/client can request:
  Range: bytes=4294967296-  (start from byte 4GB)
  
S3 responds:
  HTTP/1.1 206 Partial Content
  Content-Range: bytes 4294967296-5368709119/5368709120
  [remaining 1GB of bytes]
```

**How to support this in the pre-signed URL:**

```python
def generate_resumable_download_url(file_id, user_id):
    file = db.get_file(file_id)

    # Generate presigned URL that supports range requests
    url = s3.generate_presigned_url(
        'get_object',
        Params={
            'Bucket': PERMANENT_BUCKET,
            'Key': file.s3_key,
            'ResponseContentDisposition': f'attachment; filename="{file.filename}"',
        },
        ExpiresIn=3600  # 1 hour (longer for large files)
    )

    return {
        "url": url,
        "file_size_bytes": file.size_bytes,
        "supports_range_requests": True,
        "expires_at": "2024-11-15T11:30:00Z"
    }

# On the client (JavaScript/mobile):
async function resumableDownload(url, fileSize, localPath) {
    const existingBytes = await getExistingFileSize(localPath);

    const headers = {};
    if (existingBytes > 0) {
        headers['Range'] = `bytes=${existingBytes}-`;
    }

    const response = await fetch(url, { headers });

    if (response.status === 206) {  // Partial Content
        // Append to existing file
        await appendToFile(localPath, response.body);
    } else if (response.status === 200) {
        // Full download (no Range support, or file changed)
        await saveFile(localPath, response.body);
    }
}
```

**What if the presigned URL expires before the download completes?**

For very large files, the URL might expire during download:

```python
# Solution: Refresh URL approach
# 1. API generates URL with long TTL (1 hour for 5GB video)
# 2. Client downloads the file
# 3. If download takes > 55 minutes, client requests a new URL
#    GET /api/v1/files/{id}/download-url
# 4. API checks permissions (still authorized?), generates new URL
# 5. Client continues download from current byte position with new URL

# Server-side: Track download start time, alert if same user needs many URL refreshes
# (might indicate they're proxying the file to many users)
```

---

*Document version: 1.0 | Classification: Internal Engineering | Author: Security Engineering Team*  
*This document covers production-grade secure file upload system architecture. Adapt to your specific cloud provider, compliance requirements, and threat model.*

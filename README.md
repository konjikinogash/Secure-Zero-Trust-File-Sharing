# Secure Zero-Trust File Sharing System

A client-server web application prototype implementing the **Zero-Trust security model** for file upload, sharing, and integrity verification. Designed for local classroom demonstration on Windows laptops.

Built exclusively with Node.js standard library modules (`node:http`, `node:https`, `node:crypto`, `node:fs`, `node:path`, `node:stream`). Requires no external npm packages or installations.

---

## 1. Zero-Trust Security Architecture

In accordance with Zero-Trust principles (**"Never Trust, Always Verify"** and **"Default Deny"**):

1. **Authentication != File Authorization:** A successful login verifies user identity only. It grants **zero** implicit access to stored files.
2. **Per-Request Authorization:** Every single operation (`upload`, `list`, `share`, `revoke`, `download`, `integrity-demo`) is verified on the server against the file's ownership and explicit sharing ACLs before any file bytes are read or decrypted.
3. **Encryption at Rest:** Plaintext files are never written to disk. Files are encrypted with **AES-256-GCM** using a fresh, random 96-bit Initialization Vector (IV) for each file.
4. **Dual-Layer Integrity Verification:**
   - **Server-side:** Server checks the AES-GCM authentication tag upon decryption, recomputes the SHA-256 digest, and validates it against the pre-encryption digest recorded in metadata. Downloads are rejected with HTTP 409 if any mismatch occurs.
   - **Client-side:** The browser recomputes the SHA-256 digest using the Web Cryptography API (`crypto.subtle.digest`) upon receiving the downloaded bytes and independently verifies the match.
5. **Auditing & Monitoring:** The server terminal and web interface record concise structured events: `[ALLOW]`, `[DENY]`, and `[INTEGRITY-FAIL]`. Passwords, bearer tokens, and plaintext file contents are never logged.

---

## 2. Demo User Accounts

The prototype comes pre-seeded with four demonstration accounts:

| Username | Password | Role | Zero-Trust Access Rights |
| :--- | :--- | :--- | :--- |
| **`asha`** | `asha123` | **Student** | Can upload private files. Can download own files or files explicitly shared with her. Cannot access other students' or faculty's unshared files. |
| **`rao`** | `rao123` | **Faculty** | Can upload private files. Can download files explicitly shared with him by students, faculty, or Admin. Has no automatic access to unshared student files. |
| **`ravi`** | `ravi123` | **Student** | Can upload private files. Can download own files or files explicitly shared with him. Cannot access Asha's or Rao's unshared files. |
| **`admin`** | `admin123` | **Admin** | Full zero-trust oversight. Can view, download, share, and revoke all files on the system for auditing and administrative review. |

> **Note on Credentials:** Clearly labeled as demo credentials. Passwords are stored in `storage/metadata.json` as per-user salted **scrypt** hashes (`N=16384, r=8, p=1`, 64-byte key length). Passwords are never stored or logged in plaintext.

---

## 3. How Authentication and Sessions Work

1. **Login Flow:**
   - The user submits `username` and `password` via `POST /api/login`.
   - The server retrieves the user's unique 16-byte random salt and expected scrypt hash.
   - The password hash is recomputed and compared using `crypto.timingSafeEqual` to prevent timing attacks.
   - Upon success, the server generates a cryptographically secure 256-bit random token (`crypto.randomBytes(32).toString('hex')`) and records the session in memory.
   - The client receives the bearer token, username, and role.
2. **Session Lifecycle:**
   - Each request sends the token in the HTTP `Authorization: Bearer <token>` header.
   - Sessions are memory-bound. Restarting the server instantly invalidates all active sessions.

---

## 4. Required File Flows

### A. Upload
1. Validates authenticated session. Enforces a 10 MB maximum file size limit.
2. Generates an opaque server-side file ID (`crypto.randomUUID()`) and sanitizes the displayed filename against path traversal and control characters.
3. Computes the original file's pre-encryption SHA-256 digest.
4. Generates a fresh, random 12-byte IV (`crypto.randomBytes(12)`).
5. Encrypts plaintext bytes using `aes-256-gcm`.
6. Writes only ciphertext to `storage/<file-id>.aes`. Stores IV, GCM authentication tag, owner, SHA-256, and metadata in `storage/metadata.json`.
7. Logs `[ALLOW] upload ...`.

### B. Share and Revoke
1. Only the file owner or Admin can modify file access. Unauthorized attempts log `[DENY] share` or `[DENY] revoke` and return HTTP 403.
2. **Share:** Adds the chosen user to the file's `sharedWith` list in metadata. Logs `[ALLOW] share`.
3. **Revoke:** Removes the chosen user from `sharedWith`. Logs `[ALLOW] revoke`. The revoked user immediately loses download access.

### C. Download and Integrity Verification
1. Server verifies authentication and checks permissions under default-deny. Unauthorized requests return HTTP 403 Forbidden.
2. Server reads ciphertext from disk and decrypts using AES-256-GCM. If the file bytes were corrupted on disk, the GCM auth tag check fails, logging `[INTEGRITY-FAIL]` and returning HTTP 409.
3. Server recomputes the SHA-256 digest of decrypted bytes and compares it with the saved digest using `crypto.timingSafeEqual`. If mismatched, server logs `[INTEGRITY-FAIL]` and returns HTTP 409.
4. If valid, server logs `[ALLOW] download ...` and returns base64 content along with expected SHA-256.
5. The browser decodes the bytes, recomputes SHA-256 using the browser's Web Crypto API, verifies that the client hash matches the server digest, and prompts the file download.

### D. Integrity Demo (Simulated Checksum Mismatch)
- The UI includes an **"Integrity Demo"** button for file owners/Admin.
- Clicking **"Simulate Hash Mismatch"** alters the recorded expected SHA-256 digest in metadata to simulate checksum mismatch, **without** modifying the encrypted file on disk.
- Attempting to download the file triggers a server-side rejection (HTTP 409 Conflict) and logs `[INTEGRITY-FAIL]`.
- Clicking **"Restore Valid Hash"** restores the recorded hash and re-enables normal downloads.

---

## 5. Quick Start Instructions (Windows)

### Prerequisites
- Windows 10/11
- Node.js v18 or later installed (`node --version`)

### Starting the Server
1. Double-click **`start-demo.bat`** (or open PowerShell in this directory and run `node server.js`).
2. A server console window will open, display the demo credentials, and automatically launch your browser to:
   ```
   http://127.0.0.1:4173
   ```
3. Keep the console window open to observe live `[ALLOW]`, `[DENY]`, and `[INTEGRITY-FAIL]` log messages.

### Stopping the Server
- Press `Ctrl + C` in the server console window.

### Running Automated Verification
To run the automated 9-point security test suite:
```powershell
node verify-zero-trust.js
```

### Resetting Demo Files
To wipe uploaded demo files and reset storage while keeping demo accounts:
- Double-click **`reset-demo.bat`**

---

## 6. Transport & Prototype Limitations

- **Transport:** The server binds strictly to `127.0.0.1` (loopback) over HTTP. The UI displays **LOCAL ONLY · HTTP 127.0.0.1:4173** to make it explicit that traffic is not encrypted in transit. Do not expose this prototype to an external network or use real confidential data.
- **Optional HTTPS Support:** `server.js` contains built-in HTTPS support. If you place `cert.pem` and `key.pem` into the `storage/` directory and run:
  ```powershell
  $env:USE_HTTPS="true"; node server.js
  ```
  The server will initialize an HTTPS listener. Because self-signed certificates trigger browser security warnings (`NET::ERR_CERT_AUTHORITY_INVALID`), HTTP on `127.0.0.1` is used as the default for clean demonstration.
- **Key Storage:** The master AES key is stored in `storage/.master-key`. In a production deployment, keys would be managed via a dedicated Hardware Security Module (HSM) or Key Management Service (KMS) rather than a local file.
- **Sessions & Database:** Sessions and audit logs are stored in memory; file metadata is stored in a JSON file for classroom portability. Production systems require persistent databases with token rotation and rate limiting.

---

## 7. Automated Test Verification Results

All 9 required checks have been implemented and verified via `verify-zero-trust.js`:

| # | Check Case | Result | Observation |
| :-: | :--- | :-: | :--- |
| **1** | Wrong password is rejected | **PASS** | HTTP 401 received. Error: "Incorrect username or password". No token issued. Logged `[DENY]`. |
| **2** | Asha uploads and downloads own file | **PASS** | File encrypted with AES-256-GCM. HTTP 200 download. Decrypted bytes match original. SHA-256 verified. Logged `[ALLOW]`. |
| **3** | Ravi cannot download Asha's unshared file | **PASS** | Ravi (Student) denied access. HTTP 403 Forbidden. Logged `[DENY]`. |
| **4** | Asha shares with Rao, Rao downloads | **PASS** | Share updated metadata. Rao (Faculty) downloaded file with HTTP 200. Logged `[ALLOW]`. |
| **5** | Revoked access stops working | **PASS** | Asha revoked access. Rao subsequent download returned HTTP 403 Forbidden. Logged `[DENY]`. |
| **6** | Tampered / mismatched file is rejected | **PASS** | Simulated SHA-256 mismatch rejected with HTTP 409. Bit-tampered ciphertext rejected with HTTP 409 (AES-GCM tag check). Restoring valid hash restores HTTP 200. Logged `[INTEGRITY-FAIL]`. |
| **7** | Stored file bytes are ciphertext | **PASS** | Inspected `storage/*.aes`. Plaintext string absent. Stored file is AES-256-GCM ciphertext. |
| **8** | Server & browser SHA-256 match | **PASS** | Client-computed SHA-256 matches server digest and original pre-encryption hash bit-for-bit. |
| **9** | HTTPS works, if implemented | **PASS** | Built-in HTTPS handler supported. Local demo default binds strictly to `127.0.0.1` with explicit transport banner. |

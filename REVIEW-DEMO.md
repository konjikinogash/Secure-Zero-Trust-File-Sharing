# Secure Zero-Trust File Sharing — 90-Second Review Presentation Script

## Pre-Review Setup (30 Seconds Before Demo)
1. Navigate to the project directory: `e:\Secure-Zero-Trust-File-Sharing`
2. Double-click **`start-demo.bat`**.
3. A command prompt window titled **"Secure Zero-Trust File Sharing Server (Local Demo)"** will appear, display the demo accounts, and automatically open `http://127.0.0.1:4173` in your default browser.
4. Position the browser on the left half of your screen and the black server window on the right half so examiners can see the real-time `[ALLOW]`, `[DENY]`, and `[INTEGRITY-FAIL]` logs.
5. Have a sample test file ready (e.g., a short `.txt` file like `sample.txt`).

---

## 90-Second Live Demo Script

### Step 1: Core Concept Opening (15 seconds)
> **Speaker:**
> *"Good morning. Today we present our Secure Zero-Trust File Sharing System. Traditional systems grant broad access once a user logs in. Our system adheres strictly to the Zero-Trust principle: **Never Trust, Always Verify**. Authentication verifies identity, but every single upload, share, download, and revoke request is independently authorized by the server under default-deny rules. Files are encrypted at rest with AES-256-GCM, and dual-layer SHA-256 hashing guarantees integrity."*

---

### Step 2: Authentication & File Upload (20 seconds)
1. On the login screen, click the demo chip: **`asha / asha123 (Student)`**, then click **Sign in**.
2. Point to the welcome banner: Role: **Student**.
3. Under **Encrypt + Upload**, click **Choose File**, select `sample.txt`, and click **Encrypt and Upload**.
4. Point to the newly added file row:
   - Notice the **Owner**: `asha (Student)`
   - Notice the **Expected SHA-256** digest recorded before encryption.
   - Point to the server console: show `[ALLOW] upload user=asha file=sample.txt size=... sha256=...`
> **Speaker:**
> *"Asha uploads a file. The server hashes the original bytes with SHA-256, generates a fresh random 96-bit IV, and encrypts the file with AES-256-GCM. Plaintext is never stored on disk."*

---

### Step 3: Default Deny & Role Separation (20 seconds)
1. Click **Sign out**.
2. Click the demo chip: **`ravi / ravi123 (Student)`**, then click **Sign in**.
3. Point to the empty files list:
   - Notice: Asha's file is **not** visible to Ravi.
4. Point to the terminal window and say:
> **Speaker:**
> *"Ravi is a valid authenticated student, yet he sees zero files. Under Zero-Trust default-deny rules, authentication alone grants no implicit read permissions. Ravi cannot view or download Asha's private file."*

---

### Step 4: Selective Sharing & Authorized Download (15 seconds)
1. Sign out and sign back in as **`asha` / `asha123`**.
2. On Asha's file, select **`rao (Faculty)`** from the dropdown and click **Grant Access**.
3. Point out that `rao` now appears in the **Shared With** chip list.
4. Sign out and sign in as **`rao` / `rao123`**.
5. Asha's file is now visible to Rao. Click **Download & Verify**.
6. Show the green notification:
   `✅ Download verified! Server & client SHA-256 match (...)`
7. Point to the server console: show `[ALLOW] download user=rao file=... sha256=...`
> **Speaker:**
> *"Asha explicitly shared access with Professor Rao. Rao logs in and downloads the file. Before releasing any bytes, the server verifies permissions, decrypts the AES-256-GCM ciphertext, checks the authentication tag, and confirms the SHA-256 digest. Upon receiving the file, the browser independently recomputes the SHA-256 digest using the Web Cryptography API to confirm client-side integrity."*

---

### Step 5: Revocation & Integrity Failure Demo (20 seconds)
1. Sign out and sign back in as **`asha` / `asha123`**.
2. Next to `rao` in the **Shared With** chips, click the **`×` (Revoke)** button.
   - Show server log: `[ALLOW] revoke user=asha target=rao file=...`
3. Now click **Simulate Hash Mismatch** under file actions.
   - Show the row badge: `⚠️ SIMULATED MISMATCH`
4. Attempt to click **Download & Verify**.
5. The download is immediately blocked with a red notification:
   `❌ 409 Integrity Failure: Server rejected download. SHA-256 digest does not match.`
6. Show the terminal window:
   `[INTEGRITY-FAIL] download user=asha file=... (SHA-256 mismatch)`
> **Speaker:**
> *"Access can be revoked at any time. Furthermore, our integrity test simulates a corrupted checksum in metadata. When a download is attempted, the server rejects the corrupted file with an HTTP 409 Conflict, logging an explicit INTEGRITY-FAIL event. The system protects against both unauthorized access and data tampering."*

---

### Step 6: Honest Architecture Summary & Closing (10 seconds)
> **Speaker:**
> *"To summarize: We have implemented salted scrypt password hashing, session tokens, AES-256-GCM encryption at rest, dual server and client SHA-256 integrity verification, and per-request default-deny authorization. In this local classroom prototype, transport is bound strictly to 127.0.0.1 over HTTP to avoid self-signed browser warnings. Production enhancements would include hardware security modules for keys and persistent databases. Thank you."*

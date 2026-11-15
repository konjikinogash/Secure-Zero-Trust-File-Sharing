const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = __dirname;
const STORE = path.join(ROOT, 'storage');
const META = path.join(STORE, 'metadata.json');
const KEY_FILE = path.join(STORE, '.master-key');
const PORT = Number(process.env.PORT || 4173);
const HOST = '127.0.0.1';

fs.mkdirSync(STORE, { recursive: true });

// AES-256 key management (stored separately from encrypted file blobs)
const key = fs.existsSync(KEY_FILE) ? fs.readFileSync(KEY_FILE) : crypto.randomBytes(32);
if (!fs.existsSync(KEY_FILE)) {
  fs.writeFileSync(KEY_FILE, key, { mode: 0o600 });
}

// In-memory sessions and audit log buffer
const sessions = new Map();
const auditLogs = [];

function logEvent(type, action, details) {
  const line = `[${type}] ${action} ${details}`.trim();
  console.log(line);
  auditLogs.push({
    id: crypto.randomUUID(),
    time: new Date().toLocaleTimeString(),
    type,
    action,
    details
  });
  if (auditLogs.length > 50) auditLogs.shift();
}

// Database initialization
let db = { users: {}, files: {} };
if (fs.existsSync(META)) {
  try {
    db = JSON.parse(fs.readFileSync(META, 'utf8'));
  } catch {
    db = { users: {}, files: {} };
  }
}

function persist() {
  fs.writeFileSync(META, JSON.stringify(db, null, 2), 'utf8');
}

function seedUser(username, password, role) {
  const userKey = username.toLowerCase();
  if (!db.users[userKey]) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    db.users[userKey] = { salt, hash, role };
  }
}

// Seed the 4 required demo accounts with salted scrypt hashes
seedUser('asha', 'asha123', 'Student');
seedUser('rao', 'rao123', 'Faculty');
seedUser('ravi', 'ravi123', 'Student');
seedUser('admin', 'admin123', 'Admin');
persist();

function send(res, status, data, type = 'application/json; charset=utf-8') {
  const body = type.startsWith('application/json') ? JSON.stringify(data) : data;
  res.writeHead(status, {
    'content-type': type,
    'content-length': Buffer.byteLength(body),
    'x-content-type-options': 'nosniff',
    'cache-control': 'no-store'
  });
  res.end(body);
}

function fail(res, status, message) {
  send(res, status, { error: message });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 15_000_000) {
        reject(new Error('Request exceeds maximum allowed size (10 MB file limit).'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('Invalid JSON payload.'));
      }
    });
    req.on('error', reject);
  });
}

function userFor(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  const username = session.username;
  const userRecord = db.users[username];
  if (!userRecord) return null;
  return { username, role: userRecord.role };
}

// ZERO-TRUST AUTHORIZATION: Default Deny
function allowed(user, file, action) {
  if (!user || !file) return false;
  // Admin can list and access all files
  if (user.role === 'Admin') return true;
  // Owner can perform all operations on their file
  if (file.owner === user.username) return true;
  // Explicitly shared users have read (download) access only
  if (action === 'read' && Array.isArray(file.sharedWith) && file.sharedWith.includes(user.username)) {
    return true;
  }
  return false;
}

function cleanName(name) {
  return path.basename(String(name || 'file'))
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, '_')
    .slice(0, 120) || 'file';
}

function encrypt(plainBuffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  return {
    iv: iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    data: encrypted
  };
}

function decrypt(record) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(record.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(record.tag, 'hex'));
  const filePath = path.join(STORE, record.diskName);
  const cipherData = fs.readFileSync(filePath);
  return Buffer.concat([decipher.update(cipherData), decipher.final()]);
}

function listFiles(user) {
  return Object.values(db.files)
    .filter(f => allowed(user, f, 'read') || user.role === 'Admin')
    .map(f => ({
      id: f.id,
      name: f.name,
      owner: f.owner,
      ownerRole: f.ownerRole,
      sharedWith: Array.isArray(f.sharedWith) ? f.sharedWith : [],
      size: f.size,
      sha256: f.sha256,
      createdAt: f.createdAt,
      canShare: user.role === 'Admin' || f.owner === user.username,
      isOwner: f.owner === user.username,
      tampered: Boolean(f.tampered)
    }));
}

const requestHandler = async (req, res) => {
  const protocol = req.socket.encrypted ? 'https' : 'http';
  const url = new URL(req.url, `${protocol}://${req.headers.host || '127.0.0.1'}`);

  try {
    // Static assets
    if (req.method === 'GET' && url.pathname === '/') {
      return send(res, 200, fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8'), 'text/html; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/app.js') {
      return send(res, 200, fs.readFileSync(path.join(ROOT, 'app.js'), 'utf8'), 'text/javascript; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/style.css') {
      return send(res, 200, fs.readFileSync(path.join(ROOT, 'style.css'), 'utf8'), 'text/css; charset=utf-8');
    }

    // Authentication: Login
    if (req.method === 'POST' && url.pathname === '/api/login') {
      const { username, password } = await readBody(req);
      const cleanUsername = String(username || '').trim().toLowerCase();
      const record = db.users[cleanUsername];

      if (!record) {
        logEvent('DENY', 'login', `user=${cleanUsername || 'anonymous'} (user not found)`);
        return fail(res, 401, 'Incorrect username or password.');
      }

      const inputHash = crypto.scryptSync(String(password || ''), record.salt, 64);
      const expectedHash = Buffer.from(record.hash, 'hex');

      if (!crypto.timingSafeEqual(inputHash, expectedHash)) {
        logEvent('DENY', 'login', `user=${cleanUsername} (invalid password)`);
        return fail(res, 401, 'Incorrect username or password.');
      }

      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, { username: cleanUsername, role: record.role, loginTime: Date.now() });
      logEvent('ALLOW', 'login', `user=${cleanUsername} role=${record.role}`);
      return send(res, 200, { token, username: cleanUsername, role: record.role });
    }

    // Authentication: Register new user
    if (req.method === 'POST' && url.pathname === '/api/register') {
      const { username, password, role } = await readBody(req);
      const cleanUsername = String(username || '').trim().toLowerCase();
      const cleanRole = String(role || 'Student').trim();

      if (!cleanUsername || cleanUsername.length < 2 || cleanUsername.length > 30) {
        return fail(res, 400, 'Username must be between 2 and 30 characters.');
      }
      if (!/^[a-z0-9_.-]+$/i.test(cleanUsername)) {
        return fail(res, 400, 'Username may only contain letters, numbers, dots, and hyphens.');
      }
      if (!password || String(password).length < 4) {
        return fail(res, 400, 'Password must be at least 4 characters long.');
      }
      const allowedRoles = ['Student', 'Faculty', 'Admin'];
      const assignedRole = allowedRoles.find(r => r.toLowerCase() === cleanRole.toLowerCase()) || 'Student';

      if (db.users[cleanUsername]) {
        logEvent('DENY', 'register', `user=${cleanUsername} (already exists)`);
        return fail(res, 400, `Username '${cleanUsername}' is already taken.`);
      }

      const salt = crypto.randomBytes(16).toString('hex');
      const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
      db.users[cleanUsername] = { salt, hash, role: assignedRole };
      persist();

      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, { username: cleanUsername, role: assignedRole, loginTime: Date.now() });

      logEvent('ALLOW', 'register', `user=${cleanUsername} role=${assignedRole}`);
      return send(res, 201, {
        token,
        username: cleanUsername,
        role: assignedRole,
        message: `Account created successfully for ${cleanUsername}.`
      });
    }

    // Live activity log (for UI audit feed)
    if (req.method === 'GET' && url.pathname === '/api/activity') {
      return send(res, 200, { logs: auditLogs.slice(-25) });
    }

    // Transport info
    if (req.method === 'GET' && url.pathname === '/api/transport') {
      return send(res, 200, {
        protocol,
        isTls: Boolean(req.socket.encrypted),
        host: HOST,
        port: PORT
      });
    }

    // Require authentication for all subsequent /api routes
    const user = userFor(req);
    if (!user) {
      if (url.pathname.startsWith('/api/')) {
        logEvent('DENY', 'unauthenticated', `method=${req.method} path=${url.pathname}`);
        return fail(res, 401, 'Please log in first.');
      }
      return fail(res, 404, 'Not found.');
    }

    // Logout
    if (req.method === 'POST' && url.pathname === '/api/logout') {
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
      sessions.delete(token);
      logEvent('ALLOW', 'logout', `user=${user.username}`);
      return send(res, 200, { ok: true });
    }

    // Current user info
    if (req.method === 'GET' && url.pathname === '/api/me') {
      return send(res, 200, { username: user.username, role: user.role });
    }

    // List available files and directory of users
    if (req.method === 'GET' && url.pathname === '/api/files') {
      const visibleFiles = listFiles(user);
      const allUsers = Object.entries(db.users).map(([uname, u]) => ({
        username: uname,
        role: u.role
      }));
      logEvent('ALLOW', 'list-files', `user=${user.username} visible=${visibleFiles.length}`);
      return send(res, 200, { files: visibleFiles, users: allUsers });
    }

    // Upload file
    if (req.method === 'POST' && url.pathname === '/api/files') {
      const { name, content } = await readBody(req);
      if (!name || typeof content !== 'string') {
        return fail(res, 400, 'Filename and base64 file content are required.');
      }
      const plain = Buffer.from(content, 'base64');
      if (plain.length === 0) {
        return fail(res, 400, 'Cannot upload an empty file.');
      }
      if (plain.length > 10 * 1024 * 1024) {
        return fail(res, 400, 'File exceeds maximum size limit of 10 MB.');
      }

      // Compute original file digest before encryption
      const sha256 = crypto.createHash('sha256').update(plain).digest('hex');
      const id = crypto.randomUUID();
      const diskName = `${id}.aes`;

      // Encrypt bytes using AES-256-GCM with fresh random IV
      const sealed = encrypt(plain);
      fs.writeFileSync(path.join(STORE, diskName), sealed.data);

      const record = {
        id,
        name: cleanName(name),
        diskName,
        iv: sealed.iv,
        tag: sealed.tag,
        owner: user.username,
        ownerRole: user.role,
        sharedWith: [],
        size: plain.length,
        sha256,
        originalSha256: sha256,
        createdAt: new Date().toISOString(),
        tampered: false
      };

      db.files[id] = record;
      persist();

      logEvent('ALLOW', 'upload', `user=${user.username} file=${record.name} size=${plain.length}B sha256=${sha256}`);
      return send(res, 201, { file: listFiles(user).find(f => f.id === id) });
    }

    // File-specific operations: share, revoke, download, tamper-demo
    const fileRoute = url.pathname.match(/^\/api\/files\/([\w-]+)(?:\/(share|revoke|download|tamper-demo))?$/);
    if (fileRoute) {
      const [, id, action] = fileRoute;
      const file = db.files[id];
      if (!file) {
        return fail(res, 404, 'File not found.');
      }

      // Share file
      if (action === 'share' && req.method === 'POST') {
        if (user.role !== 'Admin' && file.owner !== user.username) {
          logEvent('DENY', 'share', `user=${user.username} file=${file.name} (not owner or admin)`);
          return fail(res, 403, 'Only the owner or Admin can share this file.');
        }

        const { username } = await readBody(req);
        const target = String(username || '').trim().toLowerCase();
        if (!db.users[target]) {
          logEvent('DENY', 'share', `user=${user.username} target=${target} (target user not found)`);
          return fail(res, 400, 'Selected user does not exist.');
        }
        if (target === file.owner) {
          return fail(res, 400, 'User is already the owner of this file.');
        }
        if (!Array.isArray(file.sharedWith)) file.sharedWith = [];
        if (!file.sharedWith.includes(target)) {
          file.sharedWith.push(target);
          persist();
        }

        logEvent('ALLOW', 'share', `user=${user.username} target=${target} file=${file.name}`);
        return send(res, 200, { ok: true, files: listFiles(user) });
      }

      // Revoke file access
      if (action === 'revoke' && req.method === 'POST') {
        if (user.role !== 'Admin' && file.owner !== user.username) {
          logEvent('DENY', 'revoke', `user=${user.username} file=${file.name} (not owner or admin)`);
          return fail(res, 403, 'Only the owner or Admin can revoke access to this file.');
        }

        const { username } = await readBody(req);
        const target = String(username || '').trim().toLowerCase();
        if (!Array.isArray(file.sharedWith) || !file.sharedWith.includes(target)) {
          logEvent('DENY', 'revoke', `user=${user.username} target=${target} (user not in shared list)`);
          return fail(res, 400, 'User is not currently granted access to this file.');
        }

        file.sharedWith = file.sharedWith.filter(u => u !== target);
        persist();

        logEvent('ALLOW', 'revoke', `user=${user.username} target=${target} file=${file.name}`);
        return send(res, 200, { ok: true, files: listFiles(user) });
      }

      // Integrity Demo: Simulate or restore checksum mismatch
      if (action === 'tamper-demo' && req.method === 'POST') {
        if (user.role !== 'Admin' && file.owner !== user.username) {
          logEvent('DENY', 'tamper-demo', `user=${user.username} file=${file.name} (not owner or admin)`);
          return fail(res, 403, 'Only the owner or Admin can run the integrity demo.');
        }

        const body = await readBody(req);
        const shouldRestore = body.action === 'restore' || (file.tampered && body.action !== 'tamper');

        if (shouldRestore) {
          file.sha256 = file.originalSha256 || file.sha256;
          file.tampered = false;
          persist();
          logEvent('ALLOW', 'restore-checksum', `user=${user.username} file=${file.name} restored_sha256=${file.sha256}`);
          return send(res, 200, { ok: true, tampered: false, sha256: file.sha256, files: listFiles(user) });
        } else {
          file.originalSha256 = file.originalSha256 || file.sha256;
          file.sha256 = '0'.repeat(64);
          file.tampered = true;
          persist();
          logEvent('DEMO', 'tamper-demo', `user=${user.username} file=${file.name} (simulated checksum mismatch: expected SHA-256 set to 000...)`);
          return send(res, 200, { ok: true, tampered: true, sha256: file.sha256, files: listFiles(user) });
        }
      }

      // Download file and verify integrity
      if (action === 'download' && req.method === 'GET') {
        // Zero-Trust check: verify permission before decrypting or touching bytes
        if (!allowed(user, file, 'read')) {
          logEvent('DENY', 'download', `user=${user.username} file=${file.name} (access denied)`);
          return fail(res, 403, 'Access denied: this file was not shared with you.');
        }

        let plain;
        try {
          plain = decrypt(file);
        } catch {
          logEvent('INTEGRITY-FAIL', 'download', `user=${user.username} file=${file.name} (AES-GCM authentication tag invalid)`);
          return fail(res, 409, 'Integrity check failed: encrypted file authentication tag invalid or data corrupted. File rejected.');
        }

        // Recompute SHA-256 and compare with saved digest
        const actual = crypto.createHash('sha256').update(plain).digest('hex');
        const expected = file.sha256;

        if (actual.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'))) {
          logEvent('INTEGRITY-FAIL', 'download', `user=${user.username} file=${file.name} (SHA-256 mismatch: expected ${expected.slice(0, 10)}... actual ${actual.slice(0, 10)}...)`);
          return fail(res, 409, 'Integrity check failed: SHA-256 digest does not match. File has been modified or corrupted. File rejected.');
        }

        logEvent('ALLOW', 'download', `user=${user.username} file=${file.name} sha256=${actual}`);
        return send(res, 200, {
          name: file.name,
          content: plain.toString('base64'),
          sha256: actual
        });
      }
    }

    return fail(res, 404, 'Endpoint not found.');
  } catch (error) {
    console.error('[SERVER-ERROR]', error);
    return fail(res, 500, error.message || 'Internal server error.');
  }
};

// Transport configuration: default HTTP on 127.0.0.1; optional HTTPS if certs provided
const USE_HTTPS = process.env.USE_HTTPS === 'true' || process.env.HTTPS === 'true';
const CERT_FILE = process.env.SSL_CERT || path.join(STORE, 'cert.pem');
const SSL_KEY_FILE = process.env.SSL_KEY || path.join(STORE, 'key.pem');

let server;
let protocol = 'http';

if (USE_HTTPS && fs.existsSync(CERT_FILE) && fs.existsSync(SSL_KEY_FILE)) {
  const httpsOptions = {
    key: fs.readFileSync(SSL_KEY_FILE),
    cert: fs.readFileSync(CERT_FILE)
  };
  server = https.createServer(httpsOptions, requestHandler);
  protocol = 'https';
} else {
  server = http.createServer(requestHandler);
}

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`=======================================================`);
    console.log(`Secure Zero-Trust File Sharing running at ${protocol}://${HOST}:${PORT}`);
    console.log(`Access Rules: DEFAULT DENY (Checked on every operation)`);
    console.log(`Demo Users: asha (Student), rao (Faculty), ravi (Student), admin (Admin)`);
    console.log(`Log format: [ALLOW] [DENY] [INTEGRITY-FAIL]`);
    console.log(`=======================================================`);
  });
}

module.exports = {
  server,
  requestHandler,
  db,
  sessions,
  persist,
  seedUser,
  encrypt,
  decrypt,
  cleanName,
  allowed,
  HOST,
  PORT,
  STORE,
  META,
  KEY_FILE
};

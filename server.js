require("dotenv").config();

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const { rateLimit } = require("express-rate-limit");
const nodemailer = require("nodemailer");

const app = express();
const port = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";
const dataDir = process.env.DB_DIR || path.join(__dirname, "data");

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("Set SESSION_SECRET in .env to a random value of at least 32 characters.");
}

fs.mkdirSync(dataDir, { recursive: true });

const sqlite = new Database(path.join(dataDir, "nshieldops.sqlite"));
sqlite.pragma("journal_mode = WAL");
sqlite.pragma("foreign_keys = ON");

// ---------- schema ----------
sqlite.exec(`
  CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    project_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user ON password_reset_tokens(user_id);

  CREATE TABLE IF NOT EXISTS assets (
    asset_id    TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    type        TEXT,
    os          TEXT,
    owner       TEXT,
    project_id  TEXT,
    user_id     TEXT,
    hostname    TEXT,
    mac         TEXT,
    cpu         REAL,
    mem         REAL,
    disk        REAL,
    uptime      INTEGER,
    status      TEXT NOT NULL DEFAULT 'pending',
    token_hash  TEXT,
    created_at  TEXT NOT NULL,
    enrolled_at TEXT,
    last_seen   TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_assets_token ON assets(token_hash);

  CREATE TABLE IF NOT EXISTS enroll_sessions (
    session_id  TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    claimed_at  TEXT,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS asset_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL,
    ts       TEXT NOT NULL,
    type     TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail   TEXT,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
  );
`);

app.use(express.json({ limit: "10kb" }));

app.use(session({
  name: "nshieldops.sid",
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: isProduction, maxAge: 8 * 60 * 60 * 1000 }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, message: { error: "Too many attempts." } });
const resetLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, message: { error: "Too many reset attempts." } });

const smtpIsConfigured = process.env.SMTP_HOST && process.env.SMTP_FROM && process.env.SMTP_HOST !== "smtp.example.com";
const mailer = smtpIsConfigured ? nodemailer.createTransport({
  host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT) || 587,
  secure: String(process.env.SMTP_SECURE || "false") === "true",
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
}) : null;

const sha256 = s => crypto.createHash("sha256").update(s).digest("hex");
const nowIso = () => new Date().toISOString();
const baseUrl = () => process.env.APP_BASE_URL || `http://localhost:${port}`;

function requireUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Sign in first." });
  req.userId = req.session.userId;
  next();
}

function requireAssetToken(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/);
  if (!m) return res.status(401).json({ error: "missing bearer token" });
  const row = sqlite.prepare(`SELECT * FROM assets WHERE token_hash = ?`).get(sha256(m[1]));
  if (!row) return res.status(401).json({ error: "invalid token" });
  req.asset = row;
  next();
}

// ============================================================
// AUTH ROUTES
// ============================================================
app.post("/api/auth/signup", async (req, res, next) => {
  try {
    const { name, email, password, project_id } = req.body;
    if (!name || !email || password.length < 12) throw new Error("Invalid input");
    
    const id = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 12);
    
    sqlite.prepare(`INSERT INTO users (id, name, email, password_hash, project_id) VALUES (?, ?, ?, ?, ?)`)
      .run(id, name, email, passwordHash, project_id || null);
      
    req.session.userId = id;
    res.status(201).json({ user: { id, name, email, project_id } });
  } catch (e) {
    if (e.code === "SQLITE_CONSTRAINT_UNIQUE") return res.status(409).json({ error: "Email already exists." });
    next(e); 
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = sqlite.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    req.session.userId = user.id;
    res.json({ user: { id: user.id, name: user.name, email: user.email, project_id: user.project_id } });
  } catch (e) { next(e); }
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not signed in." });
  const user = sqlite.prepare(`SELECT id, name, email, project_id FROM users WHERE id = ?`).get(req.session.userId);
  if (!user) return res.status(401).json({ error: "Not signed in." });
  res.json({ user });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => res.status(204).end());
});

// --- PASSWORD RESET ---
app.post("/api/auth/forgot-password", resetLimiter, async (req, res) => {
  const genericResponse = { message: "If an account exists for that email, password reset instructions will be sent." };
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  
  const user = sqlite.prepare(`SELECT id, name, email FROM users WHERE email = ?`).get(email);
  if (!user) return res.status(202).json(genericResponse);

  try {
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = sha256(rawToken);
    const now = Date.now();
    const expiresAt = now + 30 * 60 * 1000;
    const resetUrl = new URL(`/?token=${encodeURIComponent(rawToken)}`, baseUrl()).toString();

    sqlite.prepare(`UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL`).run(now, user.id);
    sqlite.prepare(`INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`)
      .run(crypto.randomUUID(), user.id, tokenHash, expiresAt, now);

    if (mailer) {
      await mailer.sendMail({
        from: process.env.SMTP_FROM,
        to: user.email,
        subject: "Reset your NShieldOps password",
        text: `Use this link within 30 minutes to reset your NShieldOps password:\n\n${resetUrl}\n\nIf you did not request this, you can ignore this email.`
      });
    } else if (!isProduction) {
      // Dev mode: print to terminal
      console.log("\n============================================================");
      console.log(`🔑 PASSWORD RESET LINK FOR: ${user.email}`);
      console.log(`${resetUrl}`);
      console.log("============================================================\n");
    }
  } catch (error) {
    console.error("Could not process password reset request:", error);
  }

  res.status(202).json(genericResponse);
});

app.post("/api/auth/reset-password", resetLimiter, async (req, res, next) => {
  try {
    const token = typeof req.body.token === "string" ? req.body.token : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";

    if (!/^[a-f0-9]{64}$/i.test(token)) return res.status(400).json({ error: "Invalid or expired link." });
    if (password.length < 12 || password.length > 128) return res.status(400).json({ error: "Password must be 12–128 characters." });

    const tokenHash = sha256(token);
    const passwordHash = await bcrypt.hash(password, 12);
    const now = Date.now();

    const resetPassword = sqlite.transaction(() => {
      const record = sqlite.prepare(`SELECT id, user_id FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`)
        .get(tokenHash, now);
      if (!record) return false;

      sqlite.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).run(passwordHash, record.user_id);
      sqlite.prepare(`UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL`).run(now, record.user_id);
      return true;
    });

    if (!resetPassword()) return res.status(400).json({ error: "Invalid or expired link." });
    res.json({ message: "Password reset successfully. You can now sign in." });
  } catch (error) { return next(error); }
});

// ============================================================
// USER ROUTES
// ============================================================
app.get("/api/users", requireUser, (req, res) => {
  const user = sqlite.prepare(`SELECT * FROM users WHERE id = ?`).get(req.userId);
  if (!user.project_id) {
    return res.json(sqlite.prepare(`SELECT id, name, email, project_id FROM users ORDER BY created_at ASC`).all());
  }
  res.json(sqlite.prepare(`SELECT id, name, email, project_id FROM users WHERE project_id = ?`).all(user.project_id));
});

app.delete("/api/users/:id", requireUser, (req, res) => {
  if (req.params.id === req.userId) return res.status(400).json({ error: "Cannot delete yourself." });
  sqlite.prepare(`DELETE FROM users WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

// ============================================================
// PROJECT ROUTES
// ============================================================
app.get("/api/projects", requireUser, (req, res) => {
  const user = sqlite.prepare(`SELECT project_id FROM users WHERE id = ?`).get(req.userId);
  if (user.project_id) {
    const p = sqlite.prepare(`SELECT * FROM projects WHERE id = ?`).get(user.project_id);
    return res.json(p ? [p] : []);
  }
  res.json(sqlite.prepare(`SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC`).all(req.userId));
});

app.post("/api/projects", requireUser, (req, res) => {
  const { name, type } = req.body;
  if (!name) return res.status(400).json({ error: "Project name required" });
  const id = crypto.randomUUID();
  sqlite.prepare(`INSERT INTO projects (id, user_id, name, type, created_at) VALUES (?, ?, ?, ?, ?)`)
    .run(id, req.userId, name, type || "Security operations", nowIso());
  res.json({ id, name, type });
});

// ============================================================
// ASSET ENROLLMENT + HEARTBEAT
// ============================================================
app.post("/api/enroll/sessions", requireUser, (req, res) => {
  const { name, type, os, project_id } = req.body;
  const asset_id = crypto.randomUUID();
  const session_id = crypto.randomBytes(18).toString("hex");
  const created = new Date();
  const expires = new Date(created.getTime() + 30 * 60 * 1000);

  sqlite.prepare(`INSERT INTO assets (asset_id, name, type, os, project_id, user_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`)
    .run(asset_id, name, type || null, os || null, project_id || null, req.userId, created.toISOString());

  sqlite.prepare(`INSERT INTO enroll_sessions (session_id, asset_id, created_at, expires_at) VALUES (?, ?, ?, ?)`)
    .run(session_id, asset_id, created.toISOString(), expires.toISOString());

  const enrollUrl = `${baseUrl()}/enroll/${session_id}`;
  res.json({ asset_id, enroll_url: enrollUrl, command: `python agent.py --enroll ${enrollUrl}` });
});

app.get("/enroll/:session_id", (req, res) => {
  const s = sqlite.prepare(`SELECT * FROM enroll_sessions WHERE session_id = ?`).get(req.params.session_id);
  if (!s) return res.status(404).send("Invalid link");
  const cmd = `python agent.py --enroll ${baseUrl()}/enroll/${req.params.session_id}`;
  res.send(`<body style="background:#0b1220;color:#fff;font-family:sans-serif;padding:40px;"><h1>Enroll this laptop</h1><pre>${cmd}</pre></body>`);
});

app.post("/api/enroll/:session_id/claim", (req, res) => {
  const { token, fingerprint } = req.body;
  const s = sqlite.prepare(`SELECT * FROM enroll_sessions WHERE session_id = ?`).get(req.params.session_id);
  if (!s || s.claimed_at) return res.status(409).json({ error: "invalid session" });

  const claim = sqlite.transaction(() => {
    sqlite.prepare(`UPDATE enroll_sessions SET claimed_at = ? WHERE session_id = ?`).run(nowIso(), req.params.session_id);
    sqlite.prepare(`UPDATE assets SET status = 'enrolled', token_hash = ?, hostname = ?, mac = ?, os = ?, enrolled_at = ? WHERE asset_id = ?`)
      .run(sha256(token), fingerprint.hostname, fingerprint.mac, fingerprint.os, nowIso(), s.asset_id);
  });
  claim();
  res.json({ ok: true, asset_id: s.asset_id });
});

app.post("/api/heartbeat", requireAssetToken, (req, res) => {
  const b = req.body;
  sqlite.prepare(`UPDATE assets SET status = 'online', last_seen = ?, cpu = ?, mem = ?, disk = ?, uptime = ? WHERE asset_id = ?`)
    .run(nowIso(), b.cpu, b.mem, b.disk, b.uptime, req.asset.asset_id);
  if (b.cpu > 80 || b.mem > 80) {
    sqlite.prepare(`INSERT INTO asset_events (asset_id, ts, type, severity, detail) VALUES (?, ?, 'high_usage', 'medium', ?)`)
      .run(req.asset.asset_id, nowIso(), `CPU: ${b.cpu}%, RAM: ${b.mem}%`);
  }
  res.json({ ok: true });
});

// ============================================================
// DASHBOARD DATA
// ============================================================
app.get("/api/dashboard/assets", requireUser, (req, res) => {
  const user = sqlite.prepare(`SELECT project_id FROM users WHERE id = ?`).get(req.userId);
  let rows;
  if (user.project_id) {
    rows = sqlite.prepare(`SELECT * FROM assets WHERE project_id = ? ORDER BY created_at DESC`).all(user.project_id);
  } else {
    rows = sqlite.prepare(`SELECT * FROM assets WHERE user_id = ? ORDER BY created_at DESC`).all(req.userId);
  }
  const now = Date.now();
  res.json(rows.map(r => ({ ...r, online: r.last_seen && (now - new Date(r.last_seen).getTime()) < 90000 })));
});

app.delete("/api/assets/:id", requireUser, (req, res) => {
  sqlite.prepare(`DELETE FROM assets WHERE asset_id = ? AND user_id = ?`).run(req.params.id, req.userId);
  res.json({ ok: true });
});

app.get("/api/dashboard/events", requireUser, (req, res) => {
  const rows = sqlite.prepare(`
    SELECT e.*, a.name as asset_name FROM asset_events e
    JOIN assets a ON e.asset_id = a.asset_id
    WHERE a.user_id = ?
    ORDER BY e.id DESC LIMIT 10
  `).all(req.userId);
  res.json(rows);
});

app.post("/api/dashboard/cleanup", requireUser, (req, res) => {
  sqlite.prepare(`DELETE FROM assets WHERE user_id = ?`).run(req.userId);
  sqlite.prepare(`DELETE FROM projects WHERE user_id = ?`).run(req.userId);
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  return res.status(500).json({ error: "Something went wrong." });
});

app.listen(port, () => console.log(`Running at http://localhost:${port}`));
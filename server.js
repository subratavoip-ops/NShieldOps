require("dotenv").config();

const crypto = require("node:crypto");
const path = require("node:path");
const express = require("express");
const { createClient } = require("@libsql/client");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const { rateLimit } = require("express-rate-limit");
const nodemailer = require("nodemailer");

const app = express();
const port = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("Set SESSION_SECRET in .env to a random value of at least 32 characters.");
}

if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
  throw new Error("Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in .env");
}

// Turso Setup
const sqlite = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Initialize Schema
async function initDb() {
  await sqlite.execute(`
    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT,
      created_at TEXT NOT NULL
    );
  `);
  
  await sqlite.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      project_id TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await sqlite.execute(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at INTEGER NOT NULL,
      used_at INTEGER,
      created_at INTEGER NOT NULL
    );
  `);

  await sqlite.execute(`
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
      last_seen   TEXT
    );
  `);

  await sqlite.execute(`
    CREATE TABLE IF NOT EXISTS enroll_sessions (
      session_id  TEXT PRIMARY KEY,
      asset_id    TEXT NOT NULL,
      created_at  TEXT NOT NULL,
      expires_at  TEXT NOT NULL,
      claimed_at  TEXT
    );
  `);

  await sqlite.execute(`
    CREATE TABLE IF NOT EXISTS asset_events (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_id TEXT NOT NULL,
      ts       TEXT NOT NULL,
      type     TEXT NOT NULL,
      severity TEXT NOT NULL,
      detail   TEXT
    );
  `);
}
initDb().catch(console.error);

app.use(express.json({ limit: "10kb" }));

// ============================================================
// CUSTOM TURSO SESSION STORE
// ============================================================
const { Store } = require("express-session");

class TursoSessionStore extends Store {
  constructor(options) {
    super(options);
    this.client = options.client;
    this.tableName = options.tableName || "sessions";
    this.initTable().catch(console.error);
  }

  async initTable() {
    await this.client.execute(`
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        sid TEXT PRIMARY KEY,
        sess TEXT NOT NULL,
        expire INTEGER NOT NULL
      );
    `);
  }

  async get(sid, callback) {
    try {
      const result = await this.client.execute({
        sql: `SELECT sess FROM ${this.tableName} WHERE sid = ? AND expire > ?`,
        args: [sid, Date.now()]
      });
      if (!result.rows[0]) return callback(null, null);
      callback(null, JSON.parse(result.rows[0].sess));
    } catch (err) {
      callback(err);
    }
  }

  async set(sid, sessionData, callback) {
    try {
      const expire = sessionData.cookie.expires ? new Date(sessionData.cookie.expires).getTime() : Date.now() + 86400000;
      await this.client.execute({
        sql: `INSERT INTO ${this.tableName} (sid, sess, expire) VALUES (?, ?, ?)
              ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expire = excluded.expire`,
        args: [sid, JSON.stringify(sessionData), expire]
      });
      callback(null);
    } catch (err) {
      callback(err);
    }
  }

  async destroy(sid, callback) {
    try {
      await this.client.execute({ sql: `DELETE FROM ${this.tableName} WHERE sid = ?`, args: [sid] });
      callback(null);
    } catch (err) {
      callback(err);
    }
  }
}

app.use(session({
  name: "nshieldops.sid",
  store: new TursoSessionStore({ client: sqlite }), 
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

async function requireAssetToken(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/);
  if (!m) return res.status(401).json({ error: "missing bearer token" });
  
  const result = await sqlite.execute({ sql: "SELECT * FROM assets WHERE token_hash = ?", args: [sha256(m[1])] });
  const row = result.rows[0];
  
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
    
    await sqlite.execute({
      sql: `INSERT INTO users (id, name, email, password_hash, project_id) VALUES (?, ?, ?, ?, ?)`,
      args: [id, name, email, passwordHash, project_id || null]
    });
      
    req.session.userId = id;
    res.status(201).json({ user: { id, name, email, project_id } });
  } catch (e) {
    if (e.message && e.message.includes("UNIQUE constraint failed")) return res.status(409).json({ error: "Email already exists." });
    next(e); 
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const result = await sqlite.execute({ sql: "SELECT * FROM users WHERE email = ?", args: [email] });
    const user = result.rows[0];
    
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    req.session.userId = user.id;
    res.json({ user: { id: user.id, name: user.name, email: user.email, project_id: user.project_id } });
  } catch (e) { next(e); }
});

app.get("/api/auth/me", async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not signed in." });
  const result = await sqlite.execute({ sql: "SELECT id, name, email, project_id FROM users WHERE id = ?", args: [req.session.userId] });
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: "Not signed in." });
  res.json({ user });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => res.status(204).end());
});

app.post("/api/auth/forgot-password", resetLimiter, async (req, res) => {
  const genericResponse = { message: "If an account exists for that email, password reset instructions will be sent." };
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  
  const result = await sqlite.execute({ sql: "SELECT id, name, email FROM users WHERE email = ?", args: [email] });
  const user = result.rows[0];
  
  if (!user) return res.status(202).json(genericResponse);

  try {
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = sha256(rawToken);
    const now = Date.now();
    const expiresAt = now + 30 * 60 * 1000;
    const resetUrl = new URL(`/?token=${encodeURIComponent(rawToken)}`, baseUrl()).toString();

    await sqlite.execute({ sql: "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL", args: [now, user.id] });
    await sqlite.execute({
      sql: "INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
      args: [crypto.randomUUID(), user.id, tokenHash, expiresAt, now]
    });

    if (mailer) {
      await mailer.sendMail({
        from: process.env.SMTP_FROM,
        to: user.email,
        subject: "Reset your NShieldOps password",
        text: `Use this link within 30 minutes to reset your NShieldOps password:\n\n${resetUrl}\n\nIf you did not request this, you can ignore this email.`
      });
    } else if (!isProduction) {
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

    const recordRes = await sqlite.execute({
      sql: "SELECT id, user_id FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
      args: [tokenHash, now]
    });
    const record = recordRes.rows[0];

    if (!record) return res.status(400).json({ error: "Invalid or expired link." });

    await sqlite.batch([
      { sql: "UPDATE users SET password_hash = ? WHERE id = ?", args: [passwordHash, record.user_id] },
      { sql: "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL", args: [now, record.user_id] }
    ]);

    res.json({ message: "Password reset successfully. You can now sign in." });
  } catch (error) { return next(error); }
});

// ============================================================
// USER ROUTES
// ============================================================
app.get("/api/users", requireUser, async (req, res) => {
  const userRes = await sqlite.execute({ sql: "SELECT * FROM users WHERE id = ?", args: [req.userId] });
  const user = userRes.rows[0];
  
  if (!user.project_id) {
    const allRes = await sqlite.execute("SELECT id, name, email, project_id FROM users ORDER BY created_at ASC");
    return res.json(allRes.rows);
  }
  const projRes = await sqlite.execute({ sql: "SELECT id, name, email, project_id FROM users WHERE project_id = ?", args: [user.project_id] });
  res.json(projRes.rows);
});

app.delete("/api/users/:id", requireUser, async (req, res) => {
  if (req.params.id === req.userId) return res.status(400).json({ error: "Cannot delete yourself." });
  await sqlite.execute({ sql: "DELETE FROM users WHERE id = ?", args: [req.params.id] });
  res.json({ ok: true });
});

// ============================================================
// PROJECT ROUTES
// ============================================================
app.get("/api/projects", requireUser, async (req, res) => {
  const userRes = await sqlite.execute({ sql: "SELECT project_id FROM users WHERE id = ?", args: [req.userId] });
  const user = userRes.rows[0];
  
  if (user.project_id) {
    const pRes = await sqlite.execute({ sql: "SELECT * FROM projects WHERE id = ?", args: [user.project_id] });
    return res.json(pRes.rows);
  }
  const allRes = await sqlite.execute({ sql: "SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC", args: [req.userId] });
  res.json(allRes.rows);
});

app.post("/api/projects", requireUser, async (req, res) => {
  const { name, type } = req.body;
  if (!name) return res.status(400).json({ error: "Project name required" });
  const id = crypto.randomUUID();
  await sqlite.execute({
    sql: "INSERT INTO projects (id, user_id, name, type, created_at) VALUES (?, ?, ?, ?, ?)",
    args: [id, req.userId, name, type || "Security operations", nowIso()]
  });
  res.json({ id, name, type });
});

// ============================================================
// ASSET ENROLLMENT + HEARTBEAT
// ============================================================
app.post("/api/enroll/sessions", requireUser, async (req, res) => {
  const { name, type, os, project_id } = req.body;
  const asset_id = crypto.randomUUID();
  const session_id = crypto.randomBytes(18).toString("hex");
  const created = new Date();
  const expires = new Date(created.getTime() + 30 * 60 * 1000);

  await sqlite.batch([
    {
      sql: "INSERT INTO assets (asset_id, name, type, os, project_id, user_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
      args: [asset_id, name, type || null, os || null, project_id || null, req.userId, created.toISOString()]
    },
    {
      sql: "INSERT INTO enroll_sessions (session_id, asset_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
      args: [session_id, asset_id, created.toISOString(), expires.toISOString()]
    }
  ]);

  const enrollUrl = `${baseUrl()}/enroll/${session_id}`;
  res.json({ asset_id, enroll_url: enrollUrl, command: `python agent.py --enroll ${enrollUrl}` });
});

app.get("/enroll/:session_id", async (req, res) => {
  const sRes = await sqlite.execute({ sql: "SELECT * FROM enroll_sessions WHERE session_id = ?", args: [req.params.session_id] });
  const s = sRes.rows[0];
  if (!s) return res.status(404).send("Invalid link");
  
  const cmd = `python agent.py --enroll ${baseUrl()}/enroll/${req.params.session_id}`;
  res.send(`<body style="background:#0b1220;color:#fff;font-family:sans-serif;padding:40px;"><h1>Enroll this laptop</h1><pre>${cmd}</pre></body>`);
});

app.post("/api/enroll/:session_id/claim", async (req, res) => {
  const { token, fingerprint } = req.body;
  const sRes = await sqlite.execute({ sql: "SELECT * FROM enroll_sessions WHERE session_id = ?", args: [req.params.session_id] });
  const s = sRes.rows[0];
  
  if (!s || s.claimed_at) return res.status(409).json({ error: "invalid session" });

  await sqlite.batch([
    { sql: "UPDATE enroll_sessions SET claimed_at = ? WHERE session_id = ?", args: [nowIso(), req.params.session_id] },
    {
      sql: "UPDATE assets SET status = 'enrolled', token_hash = ?, hostname = ?, mac = ?, os = ?, enrolled_at = ? WHERE asset_id = ?",
      args: [sha256(token), fingerprint.hostname, fingerprint.mac, fingerprint.os, nowIso(), s.asset_id]
    }
  ]);
  
  res.json({ ok: true, asset_id: s.asset_id });
});

app.post("/api/heartbeat", requireAssetToken, async (req, res) => {
  const b = req.body;
  await sqlite.execute({
    sql: "UPDATE assets SET status = 'online', last_seen = ?, cpu = ?, mem = ?, disk = ?, uptime = ? WHERE asset_id = ?",
    args: [nowIso(), b.cpu, b.mem, b.disk, b.uptime, req.asset.asset_id]
  });

  if (b.cpu > 80 || b.mem > 80) {
    await sqlite.execute({
      sql: "INSERT INTO asset_events (asset_id, ts, type, severity, detail) VALUES (?, ?, 'high_usage', 'medium', ?)",
      args: [req.asset.asset_id, nowIso(), `CPU: ${b.cpu}%, RAM: ${b.mem}%`]
    });
  }
  res.json({ ok: true });
});

// ============================================================
// DASHBOARD DATA
// ============================================================
app.get("/api/dashboard/assets", requireUser, async (req, res) => {
  const userRes = await sqlite.execute({ sql: "SELECT project_id FROM users WHERE id = ?", args: [req.userId] });
  const user = userRes.rows[0];
  
  let rows;
  if (user.project_id) {
    const assetRes = await sqlite.execute({ sql: "SELECT * FROM assets WHERE project_id = ? ORDER BY created_at DESC", args: [user.project_id] });
    rows = assetRes.rows;
  } else {
    const assetRes = await sqlite.execute({ sql: "SELECT * FROM assets WHERE user_id = ? ORDER BY created_at DESC", args: [req.userId] });
    rows = assetRes.rows;
  }
  
  const now = Date.now();
  res.json(rows.map(r => ({ ...r, online: r.last_seen && (now - new Date(r.last_seen).getTime()) < 90000 })));
});

app.delete("/api/assets/:id", requireUser, async (req, res) => {
  await sqlite.execute({ sql: "DELETE FROM assets WHERE asset_id = ? AND user_id = ?", args: [req.params.id, req.userId] });
  res.json({ ok: true });
});

app.get("/api/dashboard/events", requireUser, async (req, res) => {
  const rowsRes = await sqlite.execute({
    sql: `SELECT e.*, a.name as asset_name FROM asset_events e
          JOIN assets a ON e.asset_id = a.asset_id
          WHERE a.user_id = ?
          ORDER BY e.id DESC LIMIT 10`,
    args: [req.userId]
  });
  res.json(rowsRes.rows);
});

app.post("/api/dashboard/cleanup", requireUser, async (req, res) => {
  await sqlite.batch([
    { sql: "DELETE FROM assets WHERE user_id = ?", args: [req.userId] },
    { sql: "DELETE FROM projects WHERE user_id = ?", args: [req.userId] }
  ]);
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  return res.status(500).json({ error: "Something went wrong." });
});

app.listen(port, () => console.log(`Running at http://localhost:${port}`));
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
const dataDir = path.join(__dirname, "data");

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("Set SESSION_SECRET in .env to a random value of at least 32 characters.");
}

fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, "nshieldops.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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

  CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user
  ON password_reset_tokens(user_id);
`);

app.use(express.json({ limit: "10kb" }));

app.use(session({
  name: "nshieldops.sid",
  store: new SQLiteStore({
    db: "sessions.sqlite",
    dir: dataDir
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Please wait and try again." }
});

const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many reset attempts. Please wait and try again." }
});

const smtpIsConfigured =
  process.env.SMTP_HOST &&
  process.env.SMTP_FROM &&
  process.env.SMTP_HOST !== "smtp.example.com";

const mailer = smtpIsConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT) || 587,
      secure: String(process.env.SMTP_SECURE || "false") === "true",
      auth: process.env.SMTP_USER
        ? {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
          }
        : undefined
    })
  : null;

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(error => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(error => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function isValidEmail(email) {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.post("/api/auth/signup", authLimiter, async (req, res, next) => {
  try {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const email = typeof req.body.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";

    if (!name || name.length > 100) {
      return res.status(400).json({ error: "Enter a name of up to 100 characters." });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }

    if (password.length < 12 || password.length > 128) {
      return res.status(400).json({ error: "Password must be 12–128 characters." });
    }

    const id = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 12);

    db.prepare(`
      INSERT INTO users (id, name, email, password_hash)
      VALUES (?, ?, ?, ?)
    `).run(id, name, email, passwordHash);

    await regenerateSession(req);
    req.session.userId = id;
    await saveSession(req);

    return res.status(201).json({
      user: { id, name, email }
    });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "An account with that email already exists." });
    }
    return next(error);
  }
});

app.post("/api/auth/login", authLimiter, async (req, res, next) => {
  try {
    const email = typeof req.body.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";

    const user = db.prepare(`
      SELECT id, name, email, password_hash
      FROM users
      WHERE email = ?
    `).get(email);

    const passwordMatches = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!passwordMatches) {
      return res.status(401).json({ error: "Email or password is incorrect." });
    }

    await regenerateSession(req);
    req.session.userId = user.id;
    await saveSession(req);

    return res.json({
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not signed in." });
  }

  const user = db.prepare(`
    SELECT id, name, email
    FROM users
    WHERE id = ?
  `).get(req.session.userId);

  if (!user) {
    return res.status(401).json({ error: "Not signed in." });
  }

  return res.json({ user });
});

app.post("/api/auth/logout", (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);

    res.clearCookie("nshieldops.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction
    });

    return res.status(204).end();
  });
});

app.post("/api/auth/forgot-password", resetLimiter, async (req, res) => {
  const genericResponse = {
    message: "If an account exists for that email, password reset instructions will be sent."
  };

  const email = typeof req.body.email === "string"
    ? req.body.email.trim().toLowerCase()
    : "";

  if (!isValidEmail(email)) {
    return res.status(202).json(genericResponse);
  }

  const user = db.prepare(`
    SELECT id, name, email
    FROM users
    WHERE email = ?
  `).get(email);

  // Return the same response whether or not the account exists.
  if (!user) {
    return res.status(202).json(genericResponse);
  }

  try {
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const now = Date.now();
    const expiresAt = now + 30 * 60 * 1000;
    const baseUrl = process.env.APP_BASE_URL || `http://localhost:${port}`;
    const resetUrl = new URL(
      `/?token=${encodeURIComponent(rawToken)}`,
      baseUrl
    ).toString();

    db.prepare(`
      UPDATE password_reset_tokens
      SET used_at = ?
      WHERE user_id = ? AND used_at IS NULL
    `).run(now, user.id);

    db.prepare(`
      INSERT INTO password_reset_tokens
        (id, user_id, token_hash, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(crypto.randomUUID(), user.id, tokenHash, expiresAt, now);

    if (mailer) {
      await mailer.sendMail({
        from: process.env.SMTP_FROM,
        to: user.email,
        subject: "Reset your NShieldOps password",
        text:
          `Use this link within 30 minutes to reset your NShieldOps password:\n\n${resetUrl}\n\n` +
          "If you did not request this, you can ignore this email."
      });
    } else if (!isProduction) {
      console.log(`Password reset link for ${user.email}: ${resetUrl}`);
    } else {
      console.error("Password reset email is not configured.");
    }
  } catch (error) {
    // Don't reveal account or email-delivery details in the response.
    console.error("Could not process password reset request:", error);
  }

  return res.status(202).json(genericResponse);
});

app.post("/api/auth/reset-password", resetLimiter, async (req, res, next) => {
  try {
    const token = typeof req.body.token === "string" ? req.body.token : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";

    if (!/^[a-f0-9]{64}$/i.test(token)) {
      return res.status(400).json({ error: "This reset link is invalid or expired." });
    }

    if (password.length < 12 || password.length > 128) {
      return res.status(400).json({ error: "Password must be 12–128 characters." });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const passwordHash = await bcrypt.hash(password, 12);
    const now = Date.now();

    const resetPassword = db.transaction(() => {
      const record = db.prepare(`
        SELECT id, user_id
        FROM password_reset_tokens
        WHERE token_hash = ?
          AND used_at IS NULL
          AND expires_at > ?
      `).get(tokenHash, now);

      if (!record) return false;

      db.prepare(`
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
      `).run(passwordHash, record.user_id);

      db.prepare(`
        UPDATE password_reset_tokens
        SET used_at = ?
        WHERE user_id = ? AND used_at IS NULL
      `).run(now, record.user_id);

      return true;
    });

    if (!resetPassword()) {
      return res.status(400).json({ error: "This reset link is invalid or expired." });
    }

    return res.json({
      message: "Password reset successfully. You can now sign in."
    });
  } catch (error) {
    return next(error);
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  return res.status(500).json({ error: "Something went wrong." });
});

app.listen(port, () => {
  console.log(`NShieldOps is running at http://localhost:${port}`);
});
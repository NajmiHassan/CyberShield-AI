import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.DB_PATH || path.join(__dirname, "..", "data", "cybershield.db");
const dbDirectory = path.dirname(dbPath);

fs.mkdirSync(dbDirectory, { recursive: true });

const db = new Database(dbPath);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS search_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    search_text TEXT NOT NULL,
    threat_type TEXT,
    risk_score INTEGER,
    confidence INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(user_id)
  );

  CREATE INDEX IF NOT EXISTS idx_search_history_user_id ON search_history(user_id);
`);

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function sanitizeUser(user) {
  return {
    user_id: user.user_id,
    name: user.name,
    email: user.email,
    created_at: user.created_at
  };
}

export function registerUser({ name, email, password }) {
  const trimmedName = (name || "").trim();
  const trimmedEmail = (email || "").trim().toLowerCase();
  const trimmedPassword = (password || "").trim();

  if (!trimmedName || !trimmedEmail || !trimmedPassword) {
    return { ok: false, error: "name, email, and password are required" };
  }

  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(trimmedEmail);
  if (existing) {
    return { ok: false, error: "email already registered" };
  }

  const userId = `USR-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
  const insert = db.prepare(
    "INSERT INTO users (user_id, name, email, password) VALUES (?, ?, ?, ?)"
  );
  insert.run(userId, trimmedName, trimmedEmail, hashPassword(trimmedPassword));

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(trimmedEmail);
  return { ok: true, user: sanitizeUser(user), message: "Account created successfully" };
}

export function loginUser({ email, password }) {
  const trimmedEmail = (email || "").trim().toLowerCase();
  const trimmedPassword = (password || "").trim();

  if (!trimmedEmail || !trimmedPassword) {
    return { ok: false, error: "email and password are required" };
  }

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(trimmedEmail);
  if (!user) {
    return { ok: false, error: "invalid credentials" };
  }

  if (user.password !== hashPassword(trimmedPassword)) {
    return { ok: false, error: "invalid credentials" };
  }

  return { ok: true, user: sanitizeUser(user), message: "Signed in successfully" };
}

export function saveSearchHistory({ userId, searchText, threatType, riskScore, confidence }) {
  const trimmedUserId = (userId || "").trim();
  const trimmedText = (searchText || "").trim();

  if (!trimmedUserId || !trimmedText) {
    return { ok: false, error: "user_id and search_text are required" };
  }

  const user = db.prepare("SELECT user_id FROM users WHERE user_id = ?").get(trimmedUserId);
  if (!user) {
    return { ok: false, error: "user not found" };
  }

  db.prepare(
    "INSERT INTO search_history (user_id, search_text, threat_type, risk_score, confidence) VALUES (?, ?, ?, ?, ?)"
  ).run(trimmedUserId, trimmedText, threatType || null, riskScore ?? null, confidence ?? null);

  return { ok: true };
}

export function getUserHistory(userId) {
  const trimmedUserId = (userId || "").trim();
  if (!trimmedUserId) {
    return [];
  }

  return db.prepare(
    "SELECT id, user_id, search_text, threat_type, risk_score, confidence, created_at FROM search_history WHERE user_id = ? ORDER BY created_at DESC"
  ).all(trimmedUserId);
}

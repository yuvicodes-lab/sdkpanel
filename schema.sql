-- YUVI SDK — Cloudflare D1 schema (SDK WORKER, alag zip)
-- Apply: wrangler d1 execute DB --file=./schema.sql

CREATE TABLE IF NOT EXISTS panels (
  panel_code TEXT PRIMARY KEY,
  is_active INTEGER DEFAULT 1,
  expires_at TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT DEFAULT 'OWNER',
  balance INTEGER DEFAULT 0,
  panel_code TEXT DEFAULT 'YUVI_001',
  device_fingerprint TEXT,
  last_login TEXT,
  last_reset TEXT,
  is_blocked INTEGER DEFAULT 0,
  panel_expiry TEXT
);

CREATE TABLE IF NOT EXISTS mundo_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  panel_code TEXT NOT NULL,
  sdk_key TEXT NOT NULL,
  duration_days INTEGER DEFAULT 30,
  pkg_limit INTEGER DEFAULT 1,
  app_limit INTEGER DEFAULT 1,
  feature1 INTEGER DEFAULT 0,
  feature2 INTEGER DEFAULT 0,
  is_blocked INTEGER DEFAULT 0,
  created_by INTEGER,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(panel_code, sdk_key)
);

CREATE TABLE IF NOT EXISTS mundo_key_bindings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sdk_key_id INTEGER NOT NULL,
  pkg_name TEXT NOT NULL,
  app_name TEXT NOT NULL,
  is_blocked INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mundo_bind ON mundo_key_bindings(sdk_key_id);

CREATE TABLE IF NOT EXISTS bcore_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  panel_code TEXT NOT NULL,
  sdk_key TEXT NOT NULL,
  duration_days INTEGER DEFAULT 30,
  pkg_limit INTEGER DEFAULT 1,
  app_limit INTEGER DEFAULT 1,
  feature1 INTEGER DEFAULT 0,
  feature2 INTEGER DEFAULT 0,
  is_blocked INTEGER DEFAULT 0,
  created_by INTEGER,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(panel_code, sdk_key)
);

CREATE TABLE IF NOT EXISTS bcore_key_bindings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sdk_key_id INTEGER NOT NULL,
  pkg_name TEXT NOT NULL,
  app_name TEXT NOT NULL,
  is_blocked INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_bcore_bind ON bcore_key_bindings(sdk_key_id);

CREATE TABLE IF NOT EXISTS sdk_server_status (
  panel_code TEXT NOT NULL,
  engine TEXT NOT NULL,
  maintenance_mode INTEGER DEFAULT 0,
  maintenance_message TEXT,
  PRIMARY KEY(panel_code, engine)
);

CREATE TABLE IF NOT EXISTS sdk_hash_vault (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  panel_code TEXT NOT NULL,
  engine TEXT NOT NULL,
  hash_type TEXT DEFAULT 'lib_signature',
  hash_label TEXT NOT NULL,
  hash_value TEXT NOT NULL,
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hash_panel ON sdk_hash_vault(panel_code, engine);

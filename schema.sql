-- Pairing table for idempotency
CREATE TABLE IF NOT EXISTS pairings (
  fub_id TEXT PRIMARY KEY,
  cal_uid TEXT UNIQUE,
  created_at INTEGER,
  updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS mapping (
  key TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  event_type_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  last_error TEXT,
  created_at INTEGER,
  updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS logs (
  id TEXT PRIMARY KEY,
  ts INTEGER,
  direction TEXT,
  action TEXT,
  message TEXT
);

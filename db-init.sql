-- Membuat tabel users
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  totp_secret TEXT,
  is_verified INTEGER DEFAULT 0,
  reset_token TEXT,
  reset_expiry INTEGER
);

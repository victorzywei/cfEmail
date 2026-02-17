CREATE TABLE IF NOT EXISTS sent_emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  sender TEXT NOT NULL,
  to_list TEXT NOT NULL,
  cc_list TEXT NOT NULL DEFAULT '',
  bcc_list TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL,
  body_text TEXT NOT NULL,
  provider_id TEXT,
  sent_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_sent_user_sent_at
ON sent_emails (user_id, sent_at DESC);

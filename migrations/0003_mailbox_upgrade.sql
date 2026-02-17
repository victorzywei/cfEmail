ALTER TABLE inbound_emails ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0;
ALTER TABLE inbound_emails ADD COLUMN is_starred INTEGER NOT NULL DEFAULT 0;
ALTER TABLE inbound_emails ADD COLUMN folder TEXT NOT NULL DEFAULT 'inbox';
ALTER TABLE inbound_emails ADD COLUMN snippet TEXT NOT NULL DEFAULT '';

ALTER TABLE sent_emails ADD COLUMN is_starred INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS drafts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  to_list TEXT NOT NULL DEFAULT '',
  cc_list TEXT NOT NULL DEFAULT '',
  bcc_list TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  body_text TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_inbound_folder_state
ON inbound_emails (recipient, folder, is_read, is_starred, received_at DESC);

CREATE INDEX IF NOT EXISTS idx_sent_user_starred
ON sent_emails (user_id, is_starred, sent_at DESC);

CREATE INDEX IF NOT EXISTS idx_drafts_user_updated
ON drafts (user_id, updated_at DESC);

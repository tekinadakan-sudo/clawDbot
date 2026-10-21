CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  identity_sign_pub BLOB NOT NULL UNIQUE CHECK(length(identity_sign_pub)=32),
  identity_dh_pub   BLOB NOT NULL UNIQUE CHECK(length(identity_dh_pub)=32),
  identity_bind_sig BLOB NOT NULL CHECK(length(identity_bind_sig)=64),
  created_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS signed_prekeys (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL, pub BLOB NOT NULL CHECK(length(pub)=32),
  sig BLOB NOT NULL CHECK(length(sig)=64), created_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, key_id)) STRICT;
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL, pub BLOB NOT NULL CHECK(length(pub)=32), UNIQUE(user_id, key_id)) STRICT;
CREATE INDEX IF NOT EXISTS opk_user_id ON one_time_prekeys(user_id, id);
CREATE TABLE IF NOT EXISTS consumed_opks (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, key_id INTEGER NOT NULL,
  claimed_at INTEGER NOT NULL, PRIMARY KEY(user_id, key_id)) STRICT;
CREATE TABLE IF NOT EXISTS auth_nonces (
  nonce_hash BLOB PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE,
  expires_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS sessions (
  token_hash BLOB PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, msg_id BLOB NOT NULL UNIQUE,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_id INTEGER NOT NULL, sender_username TEXT NOT NULL,
  envelope BLOB NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS messages_recipient ON messages(recipient_id, id);
CREATE INDEX IF NOT EXISTS messages_sender_recipient ON messages(recipient_id, sender_id);
CREATE INDEX IF NOT EXISTS messages_expires ON messages(expires_at);
CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY CHECK(length(id)=32), owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS attachments_expires ON attachments(expires_at);
CREATE TABLE IF NOT EXISTS push_tokens (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id TEXT NOT NULL,
  token TEXT NOT NULL, env TEXT NOT NULL CHECK(env IN ('sandbox','production')), updated_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, device_id)) STRICT;

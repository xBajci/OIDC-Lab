import type { Database } from "bun:sqlite";

export function migrate(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL COLLATE NOCASE,
      password TEXT NOT NULL,
      email TEXT,
      name TEXT,
      roles TEXT NOT NULL DEFAULT '["user"]',
      email_verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS oidc_documents (
      key TEXT NOT NULL,
      model TEXT NOT NULL,
      payload TEXT NOT NULL,
      expires_at INTEGER,
      consumed_at INTEGER,
      user_code TEXT,
      uid TEXT,
      grant_id TEXT,
      PRIMARY KEY (key, model)
    );
    CREATE INDEX IF NOT EXISTS idx_oidc_user_code ON oidc_documents(user_code) WHERE user_code IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_oidc_uid ON oidc_documents(uid) WHERE uid IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_oidc_grant_id ON oidc_documents(grant_id) WHERE grant_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_oidc_expires ON oidc_documents(expires_at) WHERE expires_at IS NOT NULL;

    CREATE TABLE IF NOT EXISTS client_credentials (
      client_id TEXT PRIMARY KEY,
      client_secret TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS flow_configs (
      id TEXT PRIMARY KEY,
      issuer TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_secret TEXT,
      response_type TEXT NOT NULL,
      scope TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      pkce_enabled INTEGER NOT NULL DEFAULT 0,
      state_enabled INTEGER NOT NULL DEFAULT 0,
      nonce_enabled INTEGER NOT NULL DEFAULT 0,
      extra_params TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_flow_configs_created ON flow_configs(created_at DESC);
  `);
}

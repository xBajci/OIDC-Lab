import type { Database } from "bun:sqlite";

export interface OidcDocument {
  key: string;
  model: string;
  payload: Record<string, unknown>;
  expiresAt: number | null;
  consumedAt: number | null;
  userCode: string | null;
  uid: string | null;
  grantId: string | null;
}

interface OidcDocumentRow {
  key: string;
  model: string;
  payload: string;
  expires_at: number | null;
  consumed_at: number | null;
  user_code: string | null;
  uid: string | null;
  grant_id: string | null;
}

function rowToDocument(row: OidcDocumentRow): OidcDocument {
  return {
    key: row.key,
    model: row.model,
    payload: JSON.parse(row.payload),
    expiresAt: row.expires_at,
    consumedAt: row.consumed_at,
    userCode: row.user_code,
    uid: row.uid,
    grantId: row.grant_id,
  };
}

function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

export function upsertDocument(
  db: Database,
  doc: {
    key: string;
    model: string;
    payload: Record<string, unknown>;
    expiresAt?: number;
    userCode?: string;
    uid?: string;
    grantId?: string;
  },
): void {
  db.query(
    `INSERT OR REPLACE INTO oidc_documents (key, model, payload, expires_at, user_code, uid, grant_id)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    doc.key,
    doc.model,
    JSON.stringify(doc.payload),
    doc.expiresAt ?? null,
    doc.userCode ?? null,
    doc.uid ?? null,
    doc.grantId ?? null,
  );
}

export function findDocument(
  db: Database,
  key: string,
  model: string,
): OidcDocument | null {
  const row = db
    .query("SELECT * FROM oidc_documents WHERE key = ? AND model = ?")
    .get(key, model) as OidcDocumentRow | null;

  if (!row) return null;
  if (row.expires_at !== null && row.expires_at < nowUnix()) return null;

  return rowToDocument(row);
}

export function findByUserCode(
  db: Database,
  userCode: string,
  model: string,
): OidcDocument | null {
  const row = db
    .query("SELECT * FROM oidc_documents WHERE user_code = ? AND model = ?")
    .get(userCode, model) as OidcDocumentRow | null;

  if (!row) return null;
  if (row.expires_at !== null && row.expires_at < nowUnix()) return null;

  return rowToDocument(row);
}

export function findByUid(
  db: Database,
  uid: string,
  model: string,
): OidcDocument | null {
  const row = db
    .query("SELECT * FROM oidc_documents WHERE uid = ? AND model = ?")
    .get(uid, model) as OidcDocumentRow | null;

  if (!row) return null;
  if (row.expires_at !== null && row.expires_at < nowUnix()) return null;

  return rowToDocument(row);
}

export function consumeDocument(
  db: Database,
  key: string,
  model: string,
): void {
  db.query(
    "UPDATE oidc_documents SET consumed_at = ? WHERE key = ? AND model = ?",
  ).run(nowUnix(), key, model);
}

export function destroyDocument(
  db: Database,
  key: string,
  model: string,
): void {
  db.query(
    "DELETE FROM oidc_documents WHERE key = ? AND model = ?",
  ).run(key, model);
}

export function revokeByGrantId(db: Database, grantId: string): void {
  db.query(
    "DELETE FROM oidc_documents WHERE grant_id = ?",
  ).run(grantId);
}

export function cleanupExpired(db: Database): void {
  db.query(
    "DELETE FROM oidc_documents WHERE expires_at IS NOT NULL AND expires_at < ?",
  ).run(nowUnix());
}

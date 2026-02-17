import type { Database } from "bun:sqlite";

export interface ClientCredential {
  clientId: string;
  clientSecret: string;
  createdAt: string;
}

interface ClientCredentialRow {
  client_id: string;
  client_secret: string;
  created_at: string;
}

function rowToCredential(row: ClientCredentialRow): ClientCredential {
  return {
    clientId: row.client_id,
    clientSecret: row.client_secret,
    createdAt: row.created_at,
  };
}

export function upsertCredentials(
  db: Database,
  clientId: string,
  clientSecret: string,
): void {
  db.query(
    `INSERT OR REPLACE INTO client_credentials (client_id, client_secret)
     VALUES (?, ?)`,
  ).run(clientId, clientSecret);
}

export function findCredentials(
  db: Database,
  clientId: string,
): ClientCredential | null {
  const row = db
    .query("SELECT * FROM client_credentials WHERE client_id = ?")
    .get(clientId) as ClientCredentialRow | null;
  return row ? rowToCredential(row) : null;
}

export function listCredentials(db: Database): ClientCredential[] {
  const rows = db
    .query("SELECT * FROM client_credentials")
    .all() as ClientCredentialRow[];
  return rows.map(rowToCredential);
}

export function deleteCredentials(db: Database, clientId: string): void {
  db.query(
    "DELETE FROM client_credentials WHERE client_id = ?",
  ).run(clientId);
}

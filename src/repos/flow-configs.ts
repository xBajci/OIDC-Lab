import type { Database } from "bun:sqlite";

export interface FlowConfig {
  id: string;
  issuer: string;
  clientId: string;
  clientSecret: string | null;
  responseType: string;
  scope: string;
  redirectUri: string;
  pkceEnabled: boolean;
  stateEnabled: boolean;
  nonceEnabled: boolean;
  extraParams: Record<string, string> | null;
  createdAt: string;
}

interface FlowConfigRow {
  id: string;
  issuer: string;
  client_id: string;
  client_secret: string | null;
  response_type: string;
  scope: string;
  redirect_uri: string;
  pkce_enabled: number;
  state_enabled: number;
  nonce_enabled: number;
  extra_params: string | null;
  created_at: string;
}

function rowToFlowConfig(row: FlowConfigRow): FlowConfig {
  return {
    id: row.id,
    issuer: row.issuer,
    clientId: row.client_id,
    clientSecret: row.client_secret,
    responseType: row.response_type,
    scope: row.scope,
    redirectUri: row.redirect_uri,
    pkceEnabled: row.pkce_enabled === 1,
    stateEnabled: row.state_enabled === 1,
    nonceEnabled: row.nonce_enabled === 1,
    extraParams: row.extra_params ? JSON.parse(row.extra_params) : null,
    createdAt: row.created_at,
  };
}

export function createFlowConfig(
  db: Database,
  data: {
    issuer: string;
    clientId: string;
    clientSecret?: string;
    responseType: string;
    scope: string;
    redirectUri: string;
    pkceEnabled: boolean;
    stateEnabled: boolean;
    nonceEnabled: boolean;
    extraParams?: Record<string, string>;
  },
): FlowConfig {
  const id = crypto.randomUUID();

  const insertAndRead = db.transaction(() => {
    db.query(
      `INSERT INTO flow_configs (id, issuer, client_id, client_secret, response_type, scope, redirect_uri, pkce_enabled, state_enabled, nonce_enabled, extra_params)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      data.issuer,
      data.clientId,
      data.clientSecret ?? null,
      data.responseType,
      data.scope,
      data.redirectUri,
      data.pkceEnabled ? 1 : 0,
      data.stateEnabled ? 1 : 0,
      data.nonceEnabled ? 1 : 0,
      data.extraParams ? JSON.stringify(data.extraParams) : null,
    );

    const row = db
      .query("SELECT * FROM flow_configs WHERE id = ?")
      .get(id) as FlowConfigRow | null;
    if (!row) throw new Error("Failed to retrieve created flow config");
    return rowToFlowConfig(row);
  });

  return insertAndRead();
}

export function findFlowConfigById(
  db: Database,
  id: string,
): FlowConfig | null {
  const row = db
    .query("SELECT * FROM flow_configs WHERE id = ?")
    .get(id) as FlowConfigRow | null;
  return row ? rowToFlowConfig(row) : null;
}

export function listRecentFlowConfigs(
  db: Database,
  limit: number,
): FlowConfig[] {
  const rows = db
    .query("SELECT * FROM flow_configs ORDER BY created_at DESC LIMIT ?")
    .all(limit) as FlowConfigRow[];
  return rows.map(rowToFlowConfig);
}

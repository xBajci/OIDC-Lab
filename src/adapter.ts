import { getDb } from "./db.js";
import * as oidcRepo from "./repos/oidc-documents.js";

/**
 * SQLite adapter for oidc-provider
 * Wraps the oidc-documents repo
 */
export class SqliteAdapter {
  private model: string;

  constructor(model: string) {
    this.model = model;
  }

  /**
   * Update or create a payload in the database
   */
  async upsert(id: string, payload: Record<string, unknown>, expiresIn: number): Promise<void> {
    const expiresAt = expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : undefined;

    oidcRepo.upsertDocument(getDb(), {
      key: id,
      model: this.model,
      payload,
      expiresAt,
      userCode: payload.userCode as string | undefined,
      uid: payload.uid as string | undefined,
      grantId: payload.grantId as string | undefined,
    });
  }

  /**
   * Find a payload by id
   */
  async find(id: string): Promise<Record<string, unknown> | undefined> {
    const doc = oidcRepo.findDocument(getDb(), id, this.model);

    if (!doc) {
      return undefined;
    }

    return {
      ...doc.payload,
      ...(doc.consumedAt ? { consumed: doc.consumedAt } : {}),
    };
  }

  /**
   * Find by userCode (for device flow)
   */
  async findByUserCode(userCode: string): Promise<Record<string, unknown> | undefined> {
    const doc = oidcRepo.findByUserCode(getDb(), userCode, this.model);

    if (!doc) {
      return undefined;
    }

    return {
      ...doc.payload,
      ...(doc.consumedAt ? { consumed: doc.consumedAt } : {}),
    };
  }

  /**
   * Find by uid (for interactions)
   */
  async findByUid(uid: string): Promise<Record<string, unknown> | undefined> {
    const doc = oidcRepo.findByUid(getDb(), uid, this.model);

    if (!doc) {
      return undefined;
    }

    return {
      ...doc.payload,
      ...(doc.consumedAt ? { consumed: doc.consumedAt } : {}),
    };
  }

  /**
   * Mark a token as consumed
   */
  async consume(id: string): Promise<void> {
    oidcRepo.consumeDocument(getDb(), id, this.model);
  }

  /**
   * Delete a payload by id
   */
  async destroy(id: string): Promise<void> {
    oidcRepo.destroyDocument(getDb(), id, this.model);
  }

  /**
   * Revoke all tokens associated with a grantId
   */
  async revokeByGrantId(grantId: string): Promise<void> {
    oidcRepo.revokeByGrantId(getDb(), grantId);
  }
}

export default SqliteAdapter;

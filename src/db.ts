import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import path from "node:path";

let db: Database | null = null;

export function getDb(): Database {
  if (db) return db;

  const dbPath =
    process.env.SQLITE_PATH ||
    path.join(process.cwd(), "data/oidc-lab.sqlite");

  mkdirSync(path.dirname(dbPath), { recursive: true });

  db = new Database(dbPath, { create: true });
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");

  return db;
}

export function closeDb(): void {
  if (db) {
    db.close();
    db = null;
  }
}

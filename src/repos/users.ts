import type { Database } from "bun:sqlite";

export interface User {
  id: string;
  username: string;
  password: string;
  email: string | null;
  name: string | null;
  roles: string[];
  emailVerified: boolean;
  createdAt: string;
  updatedAt: string;
}

interface UserRow {
  id: string;
  username: string;
  password: string;
  email: string | null;
  name: string | null;
  roles: string;
  email_verified: number;
  created_at: string;
  updated_at: string;
}

function rowToUser(row: UserRow): User {
  return {
    id: row.id,
    username: row.username,
    password: row.password,
    email: row.email,
    name: row.name,
    roles: JSON.parse(row.roles),
    emailVerified: row.email_verified === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function createUser(
  db: Database,
  data: {
    username: string;
    password: string;
    email?: string;
    name?: string;
    roles?: string[];
    emailVerified?: boolean;
  },
): Promise<User> {
  const id = crypto.randomUUID();
  const hashedPassword = await Bun.password.hash(data.password);
  const username = data.username.toLowerCase().trim();
  const roles = JSON.stringify(data.roles ?? ["user"]);
  const emailVerified = data.emailVerified ? 1 : 0;

  const insertAndRead = db.transaction(() => {
    try {
      db.query(
        `INSERT INTO users (id, username, password, email, name, roles, email_verified)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        id,
        username,
        hashedPassword,
        data.email ?? null,
        data.name ?? null,
        roles,
        emailVerified,
      );
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        err.message.includes("UNIQUE constraint failed")
      ) {
        throw new Error(`Username "${username}" is already taken`);
      }
      throw err;
    }

    const row = db
      .query("SELECT * FROM users WHERE id = ?")
      .get(id) as UserRow | null;
    if (!row) throw new Error("Failed to retrieve created user");
    return rowToUser(row);
  });

  return insertAndRead();
}

export function findUserById(db: Database, id: string): User | null {
  const row = db
    .query("SELECT * FROM users WHERE id = ?")
    .get(id) as UserRow | null;
  return row ? rowToUser(row) : null;
}

export function findUserByUsername(
  db: Database,
  username: string,
): User | null {
  const row = db
    .query("SELECT * FROM users WHERE username = ?")
    .get(username.toLowerCase().trim()) as UserRow | null;
  return row ? rowToUser(row) : null;
}

export async function updateUser(
  db: Database,
  id: string,
  data: {
    username?: string;
    password?: string;
    email?: string;
    name?: string;
    roles?: string[];
    emailVerified?: boolean;
  },
): Promise<User | null> {
  type SQLBindable = string | number | null;
  const setClauses: string[] = [];
  const params: SQLBindable[] = [];

  if (data.username !== undefined) {
    setClauses.push("username = ?");
    params.push(data.username.toLowerCase().trim());
  }
  if (data.password !== undefined) {
    setClauses.push("password = ?");
    params.push(await Bun.password.hash(data.password));
  }
  if (data.email !== undefined) {
    setClauses.push("email = ?");
    params.push(data.email);
  }
  if (data.name !== undefined) {
    setClauses.push("name = ?");
    params.push(data.name);
  }
  if (data.roles !== undefined) {
    setClauses.push("roles = ?");
    params.push(JSON.stringify(data.roles));
  }
  if (data.emailVerified !== undefined) {
    setClauses.push("email_verified = ?");
    params.push(data.emailVerified ? 1 : 0);
  }

  if (setClauses.length === 0) {
    return findUserById(db, id);
  }

  setClauses.push("updated_at = datetime('now')");
  params.push(id);

  db.query(
    `UPDATE users SET ${setClauses.join(", ")} WHERE id = ?`,
  ).run(...params);

  return findUserById(db, id);
}

export function deleteUser(db: Database, id: string): boolean {
  const result = db.query("DELETE FROM users WHERE id = ?").run(id);
  return result.changes > 0;
}

export function listUsers(db: Database): User[] {
  const rows = db
    .query("SELECT * FROM users ORDER BY created_at DESC")
    .all() as UserRow[];
  return rows.map(rowToUser);
}

export function countUsers(db: Database): number {
  const row = db
    .query("SELECT COUNT(*) as count FROM users")
    .get() as { count: number };
  return row.count;
}

export async function comparePassword(
  db: Database,
  userId: string,
  candidate: string,
): Promise<boolean> {
  const user = findUserById(db, userId);
  if (!user) return false;
  return Bun.password.verify(candidate, user.password);
}

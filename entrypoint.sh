#!/bin/sh
set -e

export SQLITE_PATH="${SQLITE_PATH:-/app/data/oidc-lab.sqlite}"

# --- Auto-seed logic ---
# On first run (empty DB), seed automatically.
# SEED=true forces re-seed. SEED_CLEAN=true drops all tables first.

if [ "$SEED_CLEAN" = "true" ]; then
  echo "[entrypoint] Running seed --clean (drop + recreate all tables)..."
  bun run seed:clean
elif [ "$SEED" = "true" ]; then
  echo "[entrypoint] Running seed (forced via SEED=true)..."
  bun run seed
else
  NEEDS_SEED=$(bun -e "
    import { getDb } from './src/db.ts';
    import { migrate } from './src/migrate.ts';
    const db = getDb();
    migrate(db);
    try {
      const row = db.query('SELECT COUNT(*) as n FROM users').get();
      process.exit(row.n > 0 ? 0 : 1);
    } catch {
      process.exit(1);
    }
  " 2>/dev/null && echo "no" || echo "yes")

  if [ "$NEEDS_SEED" = "yes" ]; then
    echo "[entrypoint] Empty database detected — running seed..."
    bun run seed
  else
    echo "[entrypoint] Database already seeded, skipping."
  fi
fi

echo "[entrypoint] Starting OIDC Lab (port ${PORT:-3000})..."
exec bun run start

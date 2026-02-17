# OIDC Lab

## Project Overview

OpenID Connect learning platform - single Express app with OIDC provider, admin dashboard, and flow starter.

## Tech Stack

- **Runtime:** Bun (runs TypeScript directly, no build step)
- **Framework:** Express 4 + express-handlebars (`.hbs` templates in `src/views/`)
- **OIDC:** oidc-provider v9 (provider), openid-client v6 (flow starter)
- **Database:** SQLite via `bun:sqlite` (native, no external package)
- **Auth:** `Bun.password.hash()` / `Bun.password.verify()` (not bcrypt)

## Commands

- `bun run dev` - Start app (:3000) with watch mode
- `bun run seed` - Seed database (admin/password, test-client/test-secret)
- `bun run seed:clean` - Drop all tables and re-seed

## Architecture

- **Single app:** One Express server on one port
- **Repository pattern:** All DB access in `src/repos/*.ts`
- **DB singleton:** `src/db.ts` - use `getDb()`
- **Schema migrations:** `src/migrate.ts` - idempotent `CREATE TABLE IF NOT EXISTS`
- **Statement caching:** Use `db.query()` (not `db.prepare()`) for automatic caching
- **Transactions:** Wrap multi-statement writes in `db.transaction()`

## Routes

- `/admin/*` - Admin dashboard (users, clients management)
- `/flow/*` - Flow Starter (test OIDC flows against the provider)
- `/interaction/*` - Login/consent UI (used by oidc-provider)
- OIDC endpoints at root (/.well-known/*, /token, /authorization, etc.)

## Database

- SQLite file at `data/oidc-lab.sqlite` (configurable via `SQLITE_PATH` env var)
- WAL mode enabled, foreign keys enforced
- Tables: `users`, `oidc_documents`, `client_credentials`, `flow_configs`

## Key Patterns

- No test suite exists - this is a learning/demo tool
- JWKS auto-generated to `.jwks.json` on first run
- Environment config via `.env` (see `.env.example`)
- Docker entrypoint auto-seeds on empty database
- Design docs in `docs/plans/`

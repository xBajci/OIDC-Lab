# OIDC Lab

[![Deploy to DO](https://www.deploytodo.com/do-btn-blue.svg)](https://cloud.digitalocean.com/apps/new?repo=https://github.com/xBajci/OIDC-Lab/tree/main)

An OpenID Connect playground for learning and testing OAuth 2.0 / OIDC flows. Includes a fully configured OIDC Provider, admin dashboard, and flow starter — all in a single app, no external services required.

## Features

- **Authorization Code** flow (with and without PKCE)
- **Implicit** flow (`id_token`, `id_token token`)
- **Device Authorization Grant** (RFC 8628)
- **Dynamic Client Registration** with management API
- **Token Introspection** and **Revocation**
- **Admin Dashboard** for managing users and clients
- **Flow Starter** — test OIDC flows with one-click presets

## Built With

- [oidc-provider](https://github.com/panva/node-oidc-provider) — certified OpenID Connect Provider for Node.js
- [openid-client](https://github.com/panva/node-openid-client) — OpenID Connect Relying Party (client) for Node.js

## Quick Start

### Prerequisites

- [Bun](https://bun.sh) >= 1.0

### Setup

```bash
# Install dependencies
bun install

# Copy environment config
cp .env.example .env

# Seed the database
bun run seed

# Start the app
bun run dev
```

- **App:** <http://localhost:3000>
- **Admin:** <http://localhost:3000/admin>
- **Flow Starter:** <http://localhost:3000/flow>
- **Discovery:** <http://localhost:3000/.well-known/openid-configuration>

### Default Credentials

| Type   | ID            | Secret        |
|--------|---------------|---------------|
| User   | `admin`       | `password`    |
| Client | `test-client` | `test-secret` |

## Docker

```bash
docker build -t oidc-lab .
docker run -p 3000:3000 oidc-lab
```

The database is auto-seeded on first run.

## Project Structure

```
src/
  index.ts         # Entry point (Express app)
  db.ts            # SQLite singleton
  migrate.ts       # Schema migrations
  seed.ts          # Database seeding
  adapter.ts       # oidc-provider SQLite adapter
  config/          # OIDC provider configuration & keys
  repos/           # Database repositories (users, clients, etc.)
  routes/          # Express routers (admin, interaction, flow)
  views/           # Handlebars templates
```

## Configuration

See [.env.example](.env.example) for available environment variables:

| Variable         | Default                | Description                     |
|------------------|------------------------|---------------------------------|
| `SQLITE_PATH`    | `data/oidc-lab.sqlite` | Database file location          |
| `PORT`           | `3000`                 | App port                        |
| `SESSION_SECRET` | `dev-secret-change-me` | Cookie signing secret           |
| `ISSUER`         | —                      | Override app URL (deploy only)  |

## Commands

| Command              | Description                     |
|----------------------|---------------------------------|
| `bun run dev`        | Start app with watch mode       |
| `bun run seed`       | Seed database with default data |
| `bun run seed:clean` | Drop all tables and re-seed     |

---
name: CSV Profiler monorepo setup
description: Port assignments, workflow layout, and key quirks discovered when getting this project running on Replit.
---

# CSV Profiler monorepo setup

## Port assignments (dev)
- Frontend (Vite): port 5000 — served by `Start application` workflow via `dev:ui` script
- API server (Express): port 8080 — served by `artifacts/api-server: API Server` workflow
- Artifact preview (csv-profiler): port 20792 — served by `artifacts/csv-profiler: web` (artifact-managed, PORT env var set in artifact.toml)
- Mockup sandbox: port 8081

## Key quirk: artifact.toml is immutable
Direct edits to `.replit-artifact/artifact.toml` are blocked. A temp-file replacement API was hinted at in the error message but no such callback exists in CodeExecution. The csv-profiler artifact's `run` still calls the full `dev` script (which spawns the API server) — it fails with EADDRINUSE 8080 but the Vite part still starts, so the workflow stays "running."

**Why:** artifact.toml is platform-managed; the only way to change it is through the Replit artifact UI or a platform-side API not yet exposed to agents.

## dev scripts in csv-profiler
- `dev` — starts BOTH API server (port 8080) and Vite; use only if running standalone (no dedicated API workflow)
- `dev:ui` — Vite only; used by `Start application` and should be used by the artifact run command

## Vite proxy
Vite proxies `/api` → `http://localhost:8080`. Do not change back to 3001.

## Database
Replit-managed PostgreSQL is provisioned and reachable. Drizzle schema already applied (no migrations needed on first setup). Uses `DATABASE_URL` runtime-managed env var — do not set manually.

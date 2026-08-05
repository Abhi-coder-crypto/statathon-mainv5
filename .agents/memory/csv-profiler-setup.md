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
Direct edits to `.replit-artifact/artifact.toml` are blocked. The csv-profiler artifact's `run` calls the full `dev` script (which also spawns the API server) — this causes EADDRINUSE 8080 when the dedicated API Server artifact workflow is already running, but Vite still starts on 20792, so the workflow stays "running."

**Why:** artifact.toml is platform-managed; the only way to change it is through the Replit artifact UI or a platform-side API not yet exposed to agents.

## Port conflict rule
Never run the API server from two workflows simultaneously. The `Start application` workflow must only run `dev:ui` (Vite, port 5000); the `artifacts/api-server: API Server` workflow owns port 8080 exclusively. The `artifacts/csv-profiler: web` artifact workflow also tries to start the API — accept the EADDRINUSE noise there as unavoidable.

## Static file serving — production-only gate
`artifacts/api-server/src/app.ts` serves the built frontend from `csv-profiler/dist/public`. This is gated on `NODE_ENV === "production"` to avoid ENOENT errors in dev (the built output doesn't exist during development; Vite serves the frontend directly).

## Deterministic encryption salt
Deterministic exports must use a stable empty export salt when none is supplied; random exports retain a fresh CSPRNG salt.

**Why:** The export salt participates in seed/PBKDF2 derivation and cell keystream generation, so a fresh salt makes repeated exports differ even when the input and key settings are identical.

**How to apply:** Keep `exportSalt` overridable for file decryption and advanced callers, but select the stable default only when `deterministic` is enabled.

## dev scripts in csv-profiler
- `dev` — starts BOTH API server (port 8080) and Vite; use only if running standalone (no dedicated API workflow)
- `dev:ui` — Vite only; used by `Start application` and should be used by the artifact run command

## Vite proxy
Vite proxies `/api` → `http://localhost:8080`. Do not change back to 3001.

## Database
Replit-managed PostgreSQL is provisioned and reachable. Drizzle schema already applied (no migrations needed on first setup). Uses `DATABASE_URL` runtime-managed env var — do not set manually.

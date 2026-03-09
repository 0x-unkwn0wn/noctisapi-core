# NoctisAPI Core

NoctisAPI Core is a compact deception platform that exposes a realistic public API surface and an internal admin panel for observing, scoring, and grouping attacker behavior. It is designed for safe, non-executing interaction while providing rich telemetry for analysis.

## What is included
- Public honeypot API with staged behavior and consistent synthetic data
- Internal/admin decoys
- GeoIP flags (MaxMind GeoLite2)
- Availability monitoring
- Admin panel: actors, sessions, API health
- Admin panel: environment settings + diagnostics
- Basic scoring and stages
- Bulk actor management
- Retention pruning and backup script
- Docker + Traefik deploy
- Trusted proxy IP resolution, reverse-proxy URL handling, TLS/proxy-aware egress checks, request timeout middleware, and structured logging support

## Repository layout
- `app/` core services (public API, admin panel, monitor, health)
- `templates/`, `static/` UI and assets
- `migrations/` Alembic schema
- `compose/` dev/prod Docker Compose
- `ops/` deployment scripts and utilities
- `documentation/` detailed docs and runbooks

## Quick start (dev)
```bash
cp .env.prod.example .env.dev
docker compose -f compose/docker-compose.dev.yml up --build
```

Open:
- Public API: `http://127.0.0.1:8000/docs`
- Admin panel: `http://127.0.0.1:9001`

Notes:
- The dev stack runs a one-shot migrator before starting services.
- SQLite is stored in the `hp_dev_data` volume.
- The database file (`/data/honeypot.db`) is created automatically on first migration/startup.

## Production
See `documentation/ops/vps/RUNBOOK.md` for a step-by-step VPS deployment with Traefik + ACME and GHCR.

## Notes
- Do not commit real secrets or GeoLite2 database files.
- Use `.env.prod` on the server and keep it out of Git.
- For the public API download URLs, set `HP_PUBLIC_BASE_URL=https://<public-domain>`.
- For admin views and availability monitoring, set `HONEYPOT_PUBLIC_BASE_URL=https://<public-domain>` and `HONEYPOT_MONITOR_BASE_URL=http://traefik:8081`.
- Set `HP_MONITOR_SECRET` to a random secret shared with Traefik (injected as `x-internal-monitor` header) so internal healthcheck traffic is not logged as actor activity.

## License
Apache-2.0

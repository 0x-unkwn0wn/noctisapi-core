Quick usage

- Build and run (docker-compose):

```bash
docker compose build --no-cache
docker compose up -d
```

- Open panel (SSH tunnel or local): http://127.0.0.1:9001/

Sessions
- View sessions for actor:
  curl "http://127.0.0.1:8080/dashboard/actors/<actor_id>/sessions"
- Open session UI at:
  http://127.0.0.1:8080/dashboard/sessions/<session_id>

Validation steps are in documentation/VALIDATION.md

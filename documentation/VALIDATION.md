NoctisAPI Core validation checklist

1) Ensure schema applied

Run in Python REPL or sqlite3:

sqlite3 /data/honeypot.db "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"

2) Generate activity

Trigger events by calling the public API endpoints multiple times from the same client.

3) Verify sessions

- Open an actor in the admin panel.
- Confirm sessions and steps are listed.

4) API health

- Visit the API Health page in the admin panel.
- Confirm endpoints are checked and status is shown.


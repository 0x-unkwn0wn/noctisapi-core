"""Core database schema for NoctisAPI Core."""

from alembic import op

revision = "20260208_01_core_schema"
down_revision = None
branch_labels = None
depends_on = None


SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS actors (
      actor_id TEXT PRIMARY KEY,
      first_seen TEXT NOT NULL,
      last_seen  TEXT NOT NULL,
      score      INTEGER NOT NULL DEFAULT 0,
      err_total  INTEGER NOT NULL DEFAULT 0,
      err_consecutive INTEGER NOT NULL DEFAULT 0,
      last_status INTEGER,
      last_error_ts TEXT,
      lifecycle_state TEXT DEFAULT 'active',
      is_archived INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      path TEXT,
      method TEXT,
      ip TEXT,
      ua TEXT,
      status INTEGER,
      body_sample TEXT,
      token TEXT,
      extra_json TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id TEXT NOT NULL,
      token TEXT NOT NULL,
      created_ts TEXT NOT NULL,
      stage INTEGER NOT NULL DEFAULT 0,
      gift_type TEXT NOT NULL DEFAULT 'standard',
      used_count INTEGER NOT NULL DEFAULT 0,
      last_used_ts TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS issued_secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      value TEXT NOT NULL,
      created_ts TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      started_at TEXT NOT NULL,
      ended_at TEXT,
      stage_max INTEGER,
      summary TEXT,
      fingerprint TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS session_steps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      seq INTEGER NOT NULL,
      ts TEXT NOT NULL,
      method TEXT,
      path TEXT,
      query_json TEXT,
      headers_json TEXT,
      body_json TEXT,
      response_status INTEGER,
      response_json TEXT,
      stage_before INTEGER,
      stage_after INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS actor_fingerprints (
      actor_id TEXT PRIMARY KEY,
      fp_json TEXT,
      updated_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS honeypot_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      ok INTEGER NOT NULL,
      status_code INTEGER,
      latency_ms INTEGER,
      error TEXT,
      endpoint TEXT NOT NULL DEFAULT '/health'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS honeypot_jobs (
      job_id TEXT PRIMARY KEY,
      created_ts TEXT NOT NULL,
      updated_ts TEXT,
      actor_id TEXT,
      kind TEXT,
      status TEXT,
      payload_json TEXT
    )
    """,
]

INDEX_STATEMENTS = [
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_issued_actor_kind ON issued_secrets(actor_id, kind)",
    "CREATE INDEX IF NOT EXISTS idx_issued_value ON issued_secrets(value)",
    "CREATE INDEX IF NOT EXISTS idx_events_actor_id ON events(actor_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_path ON events(path)",
    "CREATE INDEX IF NOT EXISTS idx_tokens_actor_id ON tokens(actor_id)",
    "CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token)",
    "CREATE INDEX IF NOT EXISTS idx_actors_score ON actors(score)",
    "CREATE INDEX IF NOT EXISTS idx_actors_last_seen ON actors(last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_actor_id ON sessions(actor_id)",
    "CREATE INDEX IF NOT EXISTS idx_session_steps_session_id ON session_steps(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_honeypot_checks_ts ON honeypot_checks(ts)",
    "CREATE INDEX IF NOT EXISTS idx_honeypot_checks_ok_ts ON honeypot_checks(ok, ts)",
    "CREATE INDEX IF NOT EXISTS idx_honeypot_checks_endpoint_ts ON honeypot_checks(endpoint, ts)",
    "CREATE INDEX IF NOT EXISTS idx_hp_jobs_created ON honeypot_jobs(created_ts)",
]


def upgrade() -> None:
    for statement in SCHEMA_STATEMENTS + INDEX_STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    for statement in (
        "DROP TABLE IF EXISTS honeypot_jobs",
        "DROP TABLE IF EXISTS honeypot_checks",
        "DROP TABLE IF EXISTS session_steps",
        "DROP TABLE IF EXISTS sessions",
        "DROP TABLE IF EXISTS issued_secrets",
        "DROP TABLE IF EXISTS tokens",
        "DROP TABLE IF EXISTS events",
        "DROP TABLE IF EXISTS actor_fingerprints",
        "DROP TABLE IF EXISTS actors",
    ):
        op.execute(statement)

# panel_mvp.py (sin auth, solo protegido por SSH tunnel)
import os
import time
import threading
import json
import sqlite3
from collections import Counter
from statistics import median
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional

from app import status_checks
from app.honeypot_monitor import HoneypotAvailabilityMonitor, get_history as hp_get_history, get_summary as hp_get_summary

APP_NAME = "noctisapi-panel"
DB_PATH = os.getenv("HP_DB_PATH", "/data/honeypot.db")
HP_GEOIP_DB = os.getenv("HP_GEOIP_DB", "/data/GeoLite2-Country.mmdb")

app = FastAPI(title=APP_NAME)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")



def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso(ts: str):
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
    except Exception:
        return None


def _env_int(name: str, default: int, min_value: Optional[int] = None) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        val = int(raw)
    except Exception:
        return default
    if min_value is not None and val < min_value:
        return min_value
    return val


def _env_float(name: str, default: float, min_value: Optional[float] = None) -> float:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        val = float(raw)
    except Exception:
        return default
    if min_value is not None and val < min_value:
        return min_value
    return val


def _is_cache_fresh(cache_ts: str, last_seen: str) -> bool:
    cache_dt = _parse_iso(cache_ts)
    last_dt = _parse_iso(last_seen)
    if not cache_dt or not last_dt:
        return False
    return cache_dt >= last_dt


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("SELECT version_num FROM alembic_version LIMIT 1")
    except sqlite3.Error as exc:
        raise RuntimeError(
            "Database schema missing Alembic migrations. Run `alembic upgrade head` before launching the admin panel."
        ) from exc


honeypot_monitor = HoneypotAvailabilityMonitor(db)


# --- Internal Health Endpoints -------------------------------------------------


@app.on_event("startup")
def _start_background_tasks():
    honeypot_monitor.start()


@app.on_event("shutdown")
def _stop_background_tasks():
    honeypot_monitor.stop()


@app.get("/health", tags=["Health"], response_class=PlainTextResponse)
def internal_health():
    try:
        status_checks.basic_health()
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"status": "error", "reason": str(exc)})
    return PlainTextResponse("OK")


@app.get("/ready", tags=["Health"])
def internal_ready():
    try:
        state = status_checks.ensure_ready()
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"status": "error", "reason": str(exc)})
    return JSONResponse(state)


def _honeypot_snapshot(conn: sqlite3.Connection, limit: int = 20) -> dict:
    summary = hp_get_summary(
        conn,
        honeypot_monitor.display_base_url,
        honeypot_monitor.endpoints,
        limit=limit,
    )
    processed = []
    for endpoint_summary in summary.get("endpoints") or []:
        history = endpoint_summary.get("history") or []
        for item in history:
            item["ts_fmt"] = fmt_ts(item.get("ts") or "")
            item["status_label"] = "UP" if int(item.get("ok") or 0) else "DOWN"
        last = endpoint_summary.get("last") or {}
        if last:
            last["ts_fmt"] = fmt_ts(last.get("ts") or "")
            last["status_label"] = "UP" if int(last.get("ok") or 0) else "DOWN"
            last["status_class"] = "status-ok" if int(last.get("ok") or 0) else "status-fail"
        endpoint_summary["history"] = history
        endpoint_summary["last"] = last or None
        processed.append(endpoint_summary)
    summary["endpoints"] = processed
    summary["configured"] = bool(summary.get("base_url") and honeypot_monitor.endpoints)
    summary["interval_seconds"] = honeypot_monitor.interval
    summary["timeout_seconds"] = honeypot_monitor.timeout
    summary["endpoints_count"] = len(processed)
    return summary


@app.get("/dashboard/honeypot", response_class=HTMLResponse)
def honeypot_availability_page(request: Request, limit: int = 20):
    conn = db()
    try:
        snapshot = _honeypot_snapshot(conn, limit=max(1, min(limit, 200)))
    finally:
        conn.close()
    return templates.TemplateResponse(
        "honeypot_availability.html",
        {"request": request, "availability": snapshot},
    )


@app.get("/admin/health/honeypot")
def honeypot_health(limit: int = 20):
    conn = db()
    try:
        snapshot = _honeypot_snapshot(conn, limit=max(1, min(limit, 200)))
    finally:
        conn.close()
    return snapshot


@app.post("/admin/health/honeypot/recheck")
def honeypot_recheck(endpoint: Optional[str] = None):
    if not honeypot_monitor.configured:
        raise HTTPException(status_code=400, detail="HONEYPOT_MONITOR_BASE_URL is not configured")
    try:
        result = honeypot_monitor.run_check(endpoint=endpoint)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"result": result}


@app.get("/admin/health/honeypot/history")
def honeypot_history(endpoint: Optional[str] = None, limit: int = 20):
    target = endpoint or (honeypot_monitor.endpoints[0] if honeypot_monitor.endpoints else None)
    if not target:
        raise HTTPException(status_code=400, detail="endpoint is required")
    conn = db()
    try:
        rows = hp_get_history(conn, endpoint=target, limit=max(1, min(limit, 200)))
    finally:
        conn.close()
    for row in rows:
        row["ts_fmt"] = fmt_ts(row.get("ts") or "")
        row["status_label"] = "UP" if int(row.get("ok") or 0) else "DOWN"
    return {"endpoint": target, "history": rows}


# ensure schema on startup for panel
ensure_schema(db())


def short_id(actor_id: str) -> str:
    return actor_id[:8] + "..." if actor_id and len(actor_id) > 9 else actor_id


def stage_from_score(score: int) -> int:
    if score < 10:
        return 0
    if score < 20:
        return 1
    if score < 32:
        return 2
    if score < 48:
        return 3
    if score < 68:
        return 4
    if score < 92:
        return 5
    if score < 120:
        return 6
    if score < 155:
        return 7
    return 8


def fmt_ts(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.isoformat(timespec="seconds")
    except Exception:
        return iso


def _flag_emoji_from_iso2(iso2: str) -> str:
    """Convierte un código ISO2 de país a emoji bandera"""
    if not iso2 or len(iso2) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso2.upper())


def parse_geo_from_extra(extra_json: str):
    """
    Espera algo como:
      {"geo":{"country_iso2":"US","country_name":"United States","flag":"🇺🇸"}, ...}
    """
    try:
        obj = json.loads(extra_json or "{}")
        geo = obj.get("geo") or {}
        iso2 = geo.get("country_iso2") or ""
        flag = geo.get("flag") or _flag_emoji_from_iso2(iso2)
        return {
            "geo_flag": flag,
            "geo_iso2": iso2,
            "geo_name": (geo.get("country_name") or ""),
        }
    except Exception:
        return {"geo_flag": "", "geo_iso2": "", "geo_name": ""}


def _normalize_path(path: str) -> str:
    clean = (path or "/").split("?")[0].strip().lower()
    return clean or "/"


def _path_ngrams(paths):
    grams = []
    if not paths:
        return grams
    for n in (3, 2):
        if len(paths) >= n:
            for i in range(len(paths) - n + 1):
                grams.append(" > ".join(paths[i : i + n]))
    if not grams:
        grams = paths[:]
    return grams[:20]


def _timing_bucket(deltas):
    if not deltas:
        return "unknown"
    med = median(deltas)
    if med < 1:
        return "burst"
    if med < 5:
        return "steady"
    return "slow"


def _stage_flow(stages):
    if not stages:
        return ""
    cleaned = []
    last = None
    for stage in stages:
        if stage is None:
            continue
        try:
            val = int(stage)
        except Exception:
            continue
        if last is None or val != last:
            cleaned.append(f"S{val}")
            last = val
    if not cleaned:
        return ""
    return "-".join(cleaned[:15])


def _sanitize_stage_flow(value: str) -> str:
    if not value:
        return ""
    if any(ch.isdigit() for ch in value):
        return value
    return ""






def _parse_step_ts(ts: str):
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
    except Exception:
        return None


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            WITH last_events AS (
              SELECT e.*
              FROM events e
              JOIN (
                SELECT actor_id, MAX(id) AS max_id
                FROM events
                GROUP BY actor_id
              ) m ON e.actor_id = m.actor_id AND e.id = m.max_id
            )
            SELECT
              a.actor_id, a.first_seen, a.last_seen, a.score,
              a.err_total, a.err_consecutive, a.last_status, a.last_error_ts,
              le.ip AS last_ip,
              le.ua AS last_ua,
              le.extra_json AS last_extra_json,
              (SELECT e.extra_json FROM events e WHERE e.actor_id = a.actor_id AND e.extra_json LIKE '%country_iso2%' ORDER BY e.id DESC LIMIT 1) AS last_geo_extra_json,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND e.kind = 'token_used') AS token_used_count,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND e.kind = 'unknown_token') AS unknown_token_count
            FROM actors a
            LEFT JOIN last_events le ON le.actor_id = a.actor_id
            WHERE COALESCE(a.lifecycle_state, 'active') != 'deleted'
              AND EXISTS (SELECT 1 FROM events e WHERE e.actor_id = a.actor_id)
            ORDER BY a.last_seen DESC
            LIMIT 200
            """
        )
        actors = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT COALESCE(MAX(stage_max), 0) AS max_stage FROM sessions")
        max_stage_row = cur.fetchone()
        max_stage = int(max_stage_row["max_stage"] or 0) if max_stage_row else 0

        for a in actors:
            a["short"] = short_id(a["actor_id"])
            a["stage"] = stage_from_score(int(a.get("score") or 0))
            a["last_seen_fmt"] = fmt_ts(a["last_seen"])

            geo = parse_geo_from_extra(a.get("last_extra_json") or "")
            if not geo.get("geo_iso2"):
                geo = parse_geo_from_extra(a.get("last_geo_extra_json") or "")
            a.update(geo)

            # Si no hay flag pero tenemos IP, intentar resolver la geolocalización
            if not a.get("geo_iso2") and a.get("last_ip"):
                try:
                    import geoip2.database
                    if os.path.exists(HP_GEOIP_DB):
                        reader = geoip2.database.Reader(HP_GEOIP_DB)
                        try:
                            resp = reader.country(a["last_ip"])
                            iso = (resp.country.iso_code or "").strip().upper()
                            name = (resp.country.name or "").strip()
                            if iso:
                                a["geo_iso2"] = iso
                                a["geo_name"] = name
                                a["geo_flag"] = _flag_emoji_from_iso2(iso)
                        finally:
                            reader.close()
                except Exception:
                    pass

            a["badges"] = []
            if int(a.get("token_used_count") or 0) > 0:
                a["badges"].append(f"token_used×{a['token_used_count']}")
            if int(a.get("unknown_token_count") or 0) > 0:
                a["badges"].append(f"unknown_token×{a['unknown_token_count']}")

            # errores (desde tabla actors)
            err_total = int(a.get("err_total") or 0)
            err_consec = int(a.get("err_consecutive") or 0)
            a["err_total"] = err_total
            a["err_consecutive"] = err_consec
            a["err_badge"] = f"err×{err_total}" if err_total > 0 else ""

        return templates.TemplateResponse(
            "dashboard.html",
            {"request": request, "actors": actors, "max_stage": max_stage},
        )
    finally:
        conn.close()


# -------- Dashboard management endpoints: Cases / Sessions / Campaigns --------











@app.post("/dashboard/actors/{actor_id}/archive")
def archive_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET is_archived=1 WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/unarchive")
def unarchive_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET is_archived=0 WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/trash")
def trash_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET lifecycle_state='deleted' WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/restore")
def restore_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET lifecycle_state='active' WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/purge")
def purge_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        _purge_actor_data(cur, actor_id)
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/purge_bulk")
async def purge_actors_bulk(request: Request):
    data = None
    try:
        data = await request.json()
    except Exception:
        data = None
    actor_ids: List[str] = []
    try:
        payload = data if isinstance(data, dict) else {}
    except Exception:
        payload = {}
    if payload:
        actor_ids = payload.get("actor_ids") or []
    if not actor_ids:
        raw = (request.query_params.get("actor_ids") or "").strip()
        if raw:
            actor_ids = [a.strip() for a in raw.split(",") if a.strip()]
    if not actor_ids:
        raise HTTPException(status_code=400, detail="actor_ids required")

    conn = db()
    try:
        cur = conn.cursor()
        for actor_id in actor_ids:
            _purge_actor_data(cur, actor_id)
        conn.commit()
        return {"ok": True, "count": len(actor_ids)}
    finally:
        conn.close()


def _purge_actor_data(cur: sqlite3.Cursor, actor_id: str) -> None:
    cur.execute("DELETE FROM tokens WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM issued_secrets WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM events WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM actor_fingerprints WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM actors WHERE actor_id=?", (actor_id,))


@app.get("/dashboard/actors/deleted", response_class=HTMLResponse)
def deleted_actors(request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT actor_id, first_seen, last_seen, score
            FROM actors
            WHERE COALESCE(lifecycle_state, 'active') = 'deleted'
            ORDER BY last_seen DESC
            LIMIT 500
            """
        )
        rows = [dict(r) for r in cur.fetchall()]
        for a in rows:
            a["short"] = short_id(a["actor_id"])
            a["stage"] = stage_from_score(int(a.get("score") or 0))
            a["last_seen_fmt"] = fmt_ts(a["last_seen"])
            a["first_seen_fmt"] = fmt_ts(a["first_seen"])
        return templates.TemplateResponse(
            "actors_deleted.html", {"request": request, "actors": rows}
        )
    finally:
        conn.close()


@app.get("/dashboard/actors/{actor_id}/sessions", response_class=HTMLResponse)
def actor_sessions(actor_id: str, request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT actor_id, last_seen, score FROM actors WHERE actor_id=?", (actor_id,))
        actor_row = cur.fetchone()
        if not actor_row:
            raise HTTPException(status_code=404)
        actor = dict(actor_row)
        actor["short"] = short_id(actor["actor_id"])
        actor["last_seen_fmt"] = fmt_ts(actor.get("last_seen") or "")

        cur.execute("SELECT COUNT(*) as cnt FROM events WHERE actor_id=?", (actor_id,))
        event_count = cur.fetchone()["cnt"]

        cur.execute(
            "SELECT session_id, started_at, ended_at, stage_max, summary FROM sessions WHERE actor_id=? ORDER BY started_at DESC",
            (actor_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["started_fmt"] = fmt_ts(r.get("started_at") or "")
            r["ended_fmt"] = fmt_ts(r.get("ended_at")) if r.get("ended_at") else None

        context = {
            "request": request,
            "actor": actor,
            "sessions": rows,
            "debug": {"event_count": event_count, "sessions_count": len(rows)},
        }
                        return templates.TemplateResponse("actor_sessions.html", context)
    finally:
        conn.close()


@app.get("/dashboard/sessions/{session_id}", response_class=HTMLResponse)
def session_detail(session_id: str, request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,))
        s = cur.fetchone()
        if not s:
            raise HTTPException(status_code=404)
        sess = dict(s)
        sess["started_fmt"] = fmt_ts(sess.get("started_at") or "")
        sess["ended_fmt"] = fmt_ts(sess.get("ended_at")) if sess.get("ended_at") else "-"
        if sess.get("started_at") and sess.get("ended_at"):
            try:
                start_dt = datetime.fromisoformat(sess["started_at"].replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(sess["ended_at"].replace("Z", "+00:00"))
                sess["duration_seconds"] = max(0, int((end_dt - start_dt).total_seconds()))
            except Exception:
                sess["duration_seconds"] = None
        else:
            sess["duration_seconds"] = None
        cur.execute("SELECT * FROM session_steps WHERE session_id=? ORDER BY seq ASC", (session_id,))
        steps = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse(
            "session_detail.html",
            {"request": request, "session": sess, "steps": steps},
        )
    finally:
        conn.close()





@app.get("/dashboard/debug/db")
def debug_db():
    conn = db()
    try:
        cur = conn.cursor()
        
        # check actors
        cur.execute("SELECT COUNT(*) as cnt FROM actors")
        actor_count = cur.fetchone()['cnt']
        
        # check events
        cur.execute("SELECT COUNT(*) as cnt FROM events")
        event_count = cur.fetchone()['cnt']
        
        # check sessions
        cur.execute("SELECT COUNT(*) as cnt FROM sessions")
        session_count = cur.fetchone()['cnt']
        
        # check steps
        cur.execute("SELECT COUNT(*) as cnt FROM session_steps")
        step_count = cur.fetchone()['cnt']
        
        # get first actor with events
        cur.execute("SELECT a.actor_id, COUNT(e.id) as event_count FROM actors a LEFT JOIN events e ON a.actor_id=e.actor_id GROUP BY a.actor_id ORDER BY event_count DESC LIMIT 1")
        top_actor = cur.fetchone()
        
        return {
            "actors": actor_count,
            "events": event_count,
            "sessions": session_count,
            "session_steps": step_count,
            "top_actor": dict(top_actor) if top_actor else None
        }
    finally:
        conn.close()




@app.get("/actor/{actor_id}", response_class=HTMLResponse)
def actor(actor_id: str, request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404)

        a = dict(row)
        a["short"] = short_id(a["actor_id"])
        a["stage"] = stage_from_score(int(a.get("score") or 0))
        a["first_seen_fmt"] = fmt_ts(a["first_seen"])
        a["last_seen_fmt"] = fmt_ts(a["last_seen"])

        cur.execute(
            """
            SELECT token, created_ts, stage, gift_type, used_count, last_used_ts
            FROM tokens
            WHERE actor_id=?
            ORDER BY created_ts DESC
            LIMIT 300
            """,
            (actor_id,),
        )
        tokens = [dict(r) for r in cur.fetchall()]
        for t in tokens:
            t["created_fmt"] = fmt_ts(t["created_ts"])
            t["last_used_fmt"] = fmt_ts(t["last_used_ts"]) if t.get("last_used_ts") else None

        cur.execute(
            """
            SELECT id, ts, kind, path, method, ip, ua, body_sample, token, extra_json
            FROM events
            WHERE actor_id=?
            ORDER BY id DESC
            LIMIT 300
            """,
            (actor_id,),
        )
        events = [dict(r) for r in cur.fetchall()]

        geo_reader = None
        try:
            import geoip2.database
            if os.path.exists(HP_GEOIP_DB):
                geo_reader = geoip2.database.Reader(HP_GEOIP_DB)
        except Exception:
            geo_reader = None

        icons = {
            "probe": "\N{RIGHT-POINTING MAGNIFYING GLASS}",
            "health": "\N{GREEN HEART}",
            "token_used": "\N{WHITE HEAVY CHECK MARK}",
            "unknown_token": "\N{BLACK QUESTION MARK ORNAMENT}",
            "keys_issued": "\N{KEY}",
            "internal_config": "\N{GEAR}",
            "backup_list": "\N{FILE CABINET}",
            "backup_download": "\N{DOWNWARDS BLACK ARROW}",
            "admin_secrets": "\N{BRAIN}",
            "infra_vault": "\N{CLASSICAL BUILDING}",
            "cloud_metadata": "\N{CLOUD}",
            "root_console": "\N{CROWN}",
        }
        recon_icon = icons["probe"]

        for e in events:
            e["ts_fmt"] = fmt_ts(e["ts"])
            kind = e.get("kind") or ""
            if kind.startswith("recon_"):
                e["icon"] = recon_icon
            else:
                e["icon"] = icons.get(kind, "\N{BULLET}")
            geo = parse_geo_from_extra(e.get("extra_json") or "")
            if not geo.get("geo_iso2") and e.get("ip") and geo_reader:
                try:
                    resp = geo_reader.country(e["ip"])
                    iso = (resp.country.iso_code or "").strip().upper()
                    name = (resp.country.name or "").strip()
                    if iso:
                        geo["geo_iso2"] = iso
                        geo["geo_name"] = name
                        geo["geo_flag"] = _flag_emoji_from_iso2(iso)
                except Exception:
                    pass
            e.update(geo)

        if geo_reader:
            try:
                geo_reader.close()
            except Exception:
                pass

        cur.execute(
            "SELECT session_id, started_at, stage_max FROM sessions WHERE actor_id=? ORDER BY started_at DESC LIMIT 1",
            (actor_id,),
        )
        latest_session_row = cur.fetchone()
        actor_replay = None
        if latest_session_row:
            actor_replay = dict(latest_session_row)
            actor_replay["started_fmt"] = fmt_ts(actor_replay.get("started_at") or "")
            actor_replay["stage_max"] = actor_replay.get("stage_max") or 0
            a["latest_session_id"] = actor_replay["session_id"]
            a["latest_session_started_fmt"] = actor_replay["started_fmt"]
            a["latest_session_stage"] = actor_replay["stage_max"]

        return templates.TemplateResponse(
            "actor.html",
            {
                "request": request,
                "actor": a,
                "tokens": tokens,
                "events": events,
                "actor_replay": actor_replay,
                
            },
        )
    finally:
        conn.close()

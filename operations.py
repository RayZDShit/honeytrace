"""Analyst authentication, incident workflow and operational health."""
from __future__ import annotations

import csv
import base64
import hashlib
import hmac
import io
import os
import secrets
import time
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from threading import Lock

from flask import Blueprint, Response, jsonify, redirect, render_template, request, session
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

from config import INSTANCE_DIR
from db import connect, utc_now


DASHBOARD_KEY_PATH = INSTANCE_DIR / "dashboard.key"


def create_analyst(username: str, password: str) -> None:
    if not username.strip() or len(username) > 80 or len(password) < 12:
        raise ValueError("Use a username of 1–80 characters and a password of at least 12 characters.")
    with connect() as conn:
        conn.execute(
            """INSERT INTO analysts VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET
               password_hash=excluded.password_hash,auth_version=excluded.auth_version""",
            (username.strip(), generate_password_hash(password), secrets.token_hex(16)),
        )


def _dashboard_key() -> str:
    if not DASHBOARD_KEY_PATH.exists():
        try:
            with DASHBOARD_KEY_PATH.open("x") as handle:
                handle.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    return DASHBOARD_KEY_PATH.read_text().strip()


def _settings_cipher() -> Fernet:
    digest = hashlib.sha256(_dashboard_key().encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _valid_discord_webhook(value: str) -> bool:
    if not value:
        return False
    parsed = urlparse(value)
    return (parsed.scheme == "https" and parsed.hostname in {"discord.com", "discordapp.com"}
            and parsed.path.startswith("/api/webhooks/") and not parsed.username and not parsed.password)


def _discord_webhook() -> str | None:
    try:
        with connect(readonly=True) as conn:
            row = conn.execute(
                "SELECT encrypted_value FROM system_settings WHERE setting_key='discord_webhook'").fetchone()
    except Exception:
        return None
    if not row:
        return None
    try:
        value = _settings_cipher().decrypt(row["encrypted_value"].encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError):
        return None
    return value if _valid_discord_webhook(value) else None


def _deliver_discord_alert(alert_id: int) -> None:
    webhook = _discord_webhook()
    if not webhook:
        return
    with connect(readonly=True) as conn:
        alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not alert or alert["discord_status"] == "sent":
        return
    source = alert["src_ip"]
    titles = {"new": "New security incident", "escalated": "Incident escalated", "reopened": "Incident reopened"}
    payload = {
        "username": "HoneyTrace",
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": titles.get(alert["alert_type"], "HoneyTrace alert"),
            "color": 15158332 if alert["severity"] == "critical" else 16030307,
            "fields": [
                {"name": "Severity", "value": alert["severity"].upper(), "inline": True},
                {"name": "Category", "value": alert["category"].replace("_", " ").title(), "inline": True},
                {"name": "Sensor", "value": alert["sensor"], "inline": True},
                {"name": "Source", "value": source or "Unknown", "inline": True},
                {"name": "Incident", "value": f"#{alert['incident_id']}", "inline": True},
            ],
            "timestamp": alert["created_at"],
            "footer": {"text": "Open HoneyTrace to review and acknowledge"},
        }],
    }
    status, sent_at, error = "failed", None, None
    try:
        request_data = json.dumps(payload).encode("utf-8")
        request_object = Request(webhook, data=request_data, headers={"Content-Type": "application/json", "User-Agent": "HoneyTrace/1.0"}, method="POST")
        with urlopen(request_object, timeout=5) as response:
            if response.status not in {200, 204}:
                raise RuntimeError(f"Discord returned HTTP {response.status}")
        status, sent_at = "sent", utc_now()
    except (HTTPError, URLError, OSError, RuntimeError) as exc:
        error = f"{type(exc).__name__}: {exc}"[:500]
    with connect() as conn:
        conn.execute("UPDATE alerts SET discord_status=?,discord_sent_at=?,discord_error=? WHERE id=?",
                     (status, sent_at, error, alert_id))


def sync_incidents(session_ids: list[int]) -> None:
    alert_ids: list[int] = []
    with connect() as conn:
        for session_id in session_ids:
            row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not row:
                continue
            exists = conn.execute("SELECT * FROM incidents WHERE session_key=?", (row["session_key"],)).fetchone()
            if row["threat_level"] not in {"high", "critical"} and not exists:
                continue
            conn.execute(
                """INSERT INTO incidents(session_key,session_id,sensor,src_ip,category,severity,
                   first_seen,last_seen,event_count,reason,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(session_key) DO UPDATE SET session_id=excluded.session_id,
                   category=excluded.category,severity=excluded.severity,last_seen=excluded.last_seen,
                   event_count=excluded.event_count,reason=excluded.reason,updated_at=excluded.updated_at,
                   status=CASE WHEN incidents.status='Resolved' AND excluded.last_seen>incidents.last_seen
                               THEN 'New' ELSE incidents.status END""",
                (row["session_key"], row["id"], row["source_name"], row["src_ip"],
                 row["final_label"], row["threat_level"], row["first_seen"], row["last_seen"],
                 row["event_count"], row["rule_reason"] or "", utc_now()),
            )
            incident = conn.execute("SELECT * FROM incidents WHERE session_key=?", (row["session_key"],)).fetchone()
            alert_type = None
            if not exists and row["threat_level"] in {"high", "critical"}:
                alert_type = "new"
            elif exists and exists["severity"] == "high" and row["threat_level"] == "critical":
                alert_type = "escalated"
            elif exists and exists["status"] == "Resolved" and row["last_seen"] > exists["last_seen"]:
                alert_type = "reopened"
            if alert_type:
                suffix = row["last_seen"] if alert_type == "reopened" else row["threat_level"]
                alert_key = f"{row['session_key']}:{alert_type}:{suffix}"
                cursor = conn.execute(
                    """INSERT OR IGNORE INTO alerts(alert_key,incident_id,session_key,alert_type,severity,
                       category,sensor,src_ip,created_at,discord_status) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (alert_key, incident["id"], row["session_key"], alert_type, row["threat_level"],
                     row["final_label"], row["source_name"], row["src_ip"], utc_now(),
                     "pending" if _discord_webhook() else "disabled"),
                )
                if cursor.rowcount:
                    alert_ids.append(cursor.lastrowid)
    for alert_id in alert_ids:
        _deliver_discord_alert(alert_id)


def operational_status():
    now = datetime.now(timezone.utc)
    with connect(readonly=True) as conn:
        sensors = [dict(row) for row in conn.execute("SELECT * FROM sensors ORDER BY name")]
        active = [dict(row) for row in conn.execute(
            """SELECT a.* FROM active_connections a JOIN sensors s ON s.name=a.sensor
               WHERE s.heartbeat>=? AND s.status='online' ORDER BY opened_at DESC LIMIT 100""",
            ((now - timedelta(seconds=15)).isoformat(),),
        )]
        cutoff = (now - timedelta(minutes=15)).isoformat()
        timeline = [dict(row) for row in conn.execute(
            """SELECT substr(timestamp,1,16) AS minute,COUNT(*) AS count FROM events
               WHERE timestamp>=? GROUP BY minute ORDER BY minute""", (cutoff,))]
    for sensor in sensors:
        sensor["online"] = sensor["status"] == "online" and (
            now - datetime.fromisoformat(sensor["heartbeat"])).total_seconds() < 15
        if not sensor["online"]:
            sensor["active_connections"] = 0
    return {"sensors": sensors, "active_connections": active, "timeline": timeline}


def install_operations(app):
    app.secret_key = _dashboard_key()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.getenv("HONEYTRACE_HTTPS", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=16384,
    )
    bp = Blueprint("operations", __name__)
    failures = OrderedDict()
    lock = Lock()
    dummy_hash = generate_password_hash(secrets.token_hex(20))

    def token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(32)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = token

    @app.before_request
    def protect():
        if request.endpoint in {"static", "health"}:
            return None
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            if not session.get("csrf") or not hmac.compare_digest(supplied, session["csrf"]):
                return jsonify(error="Session expired. Reload and try again."), 403
        if request.endpoint == "operations.login":
            return None
        with connect(readonly=True) as conn:
            analyst = conn.execute("SELECT auth_version FROM analysts WHERE username=?",
                                   (session.get("analyst", ""),)).fetchone()
        if not analyst or analyst["auth_version"] != session.get("auth_version"):
            if request.path.startswith("/api/"):
                return jsonify(error="Sign in required"), 401
            return redirect("/login")

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    @bp.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        code = 200
        if request.method == "POST":
            address = request.remote_addr or "unknown"
            now = time.monotonic()
            with lock:
                attempts = [t for t in failures.get(address, []) if now - t < 300]
                blocked = len(attempts) >= 5
                failures[address] = (attempts + [now])[-6:]
                failures.move_to_end(address)
                while len(failures) > 4096:
                    failures.popitem(last=False)
            if blocked:
                error, code = "Too many attempts. Try again in five minutes.", 429
            else:
                username = request.form.get("username", "").strip()
                with connect(readonly=True) as conn:
                    row = conn.execute("SELECT * FROM analysts WHERE username=?", (username,)).fetchone()
                valid = check_password_hash(row["password_hash"] if row else dummy_hash,
                                            request.form.get("password", ""))
                if row and valid:
                    with lock:
                        failures.pop(address, None)
                    session.clear()
                    session.update(analyst=username, auth_version=row["auth_version"])
                    session.permanent = True
                    token()
                    return redirect("/")
                error, code = "Username or password is incorrect.", 401
        return render_template("login.html", error=error), code

    @bp.post("/logout")
    def logout():
        session.clear()
        return redirect("/login")

    @bp.get("/api/incidents")
    def incidents():
        status = request.args.get("status", "")
        severity = request.args.get("severity", "")
        clauses, values = [], []
        for column, value in (("status", status), ("severity", severity)):
            if value:
                clauses.append(f"{column}=?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with connect(readonly=True) as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM incidents" + where + " ORDER BY updated_at DESC LIMIT 200", values)]
        return jsonify(rows)

    @bp.get("/api/alerts")
    def alerts():
        limit = min(max(request.args.get("limit", 50, type=int), 10), 200)
        with connect(readonly=True) as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))]
            unread = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged_at IS NULL").fetchone()[0]
        for row in rows:
            row.pop("alert_key", None)
            row.pop("session_key", None)
            row.pop("discord_error", None)
        return jsonify(alerts=rows, unread=unread, discord_configured=bool(_discord_webhook()))

    @bp.route("/api/settings/discord", methods=["GET", "PUT", "DELETE"])
    def discord_settings():
        if request.method == "GET":
            with connect(readonly=True) as conn:
                row = conn.execute(
                    "SELECT updated_at,updated_by FROM system_settings WHERE setting_key='discord_webhook'").fetchone()
            configured = bool(row and _discord_webhook())
            return jsonify(configured=configured,
                           updated_at=row["updated_at"] if configured else None,
                           updated_by=row["updated_by"] if configured else None)
        if request.method == "DELETE":
            with connect() as conn:
                conn.execute("DELETE FROM system_settings WHERE setting_key='discord_webhook'")
            return jsonify(ok=True, configured=False)
        data = request.get_json(silent=True) or {}
        webhook = data.get("webhook", "") if isinstance(data, dict) else ""
        if not isinstance(webhook, str) or len(webhook) > 2000 or not _valid_discord_webhook(webhook.strip()):
            return jsonify(error="Enter a valid Discord webhook URL"), 400
        encrypted = _settings_cipher().encrypt(webhook.strip().encode("utf-8")).decode("ascii")
        with connect() as conn:
            conn.execute(
                """INSERT INTO system_settings(setting_key,encrypted_value,updated_at,updated_by)
                   VALUES('discord_webhook',?,?,?) ON CONFLICT(setting_key) DO UPDATE SET
                   encrypted_value=excluded.encrypted_value,updated_at=excluded.updated_at,
                   updated_by=excluded.updated_by""",
                (encrypted, utc_now(), session["analyst"]),
            )
        return jsonify(ok=True, configured=True)

    @bp.patch("/api/alerts/<int:alert_id>")
    def acknowledge_alert(alert_id):
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or data.get("acknowledged") not in {True, False}:
            return jsonify(error="Expected an acknowledged boolean"), 400
        acknowledged = data["acknowledged"]
        with connect() as conn:
            exists = conn.execute("SELECT id FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if not exists:
                return jsonify(error="Alert not found"), 404
            conn.execute("UPDATE alerts SET acknowledged_by=?,acknowledged_at=? WHERE id=?",
                         (session["analyst"] if acknowledged else None, utc_now() if acknowledged else None, alert_id))
        return jsonify(ok=True)

    @bp.post("/api/alerts/acknowledge-all")
    def acknowledge_all_alerts():
        with connect() as conn:
            conn.execute("UPDATE alerts SET acknowledged_by=?,acknowledged_at=? WHERE acknowledged_at IS NULL",
                         (session["analyst"], utc_now()))
        return jsonify(ok=True)

    @bp.route("/api/incidents/<int:incident_id>", methods=["GET", "PATCH"])
    def incident(incident_id):
        with connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not row:
                return jsonify(error="Incident not found"), 404
            if request.method == "PATCH":
                data = request.get_json(silent=True) or {}
                if not isinstance(data, dict):
                    return jsonify(error="Expected a JSON object"), 400
                status = data.get("status", row["status"])
                note = data.get("note", "")
                if not isinstance(status, str) or status not in {"New", "Investigating", "Resolved"} or not isinstance(note, str) or len(note) > 4000:
                    return jsonify(error="Invalid status or note (maximum 4000 characters)"), 400
                audit = []
                if status != row["status"]:
                    audit.append(f"Status: {row['status']} → {status}")
                if note.strip():
                    audit.append(note.strip())
                if audit:
                    conn.execute("INSERT INTO incident_notes(incident_id,author,body,created_at) VALUES(?,?,?,?)",
                                 (incident_id, session["analyst"], "\n".join(audit), utc_now()))
                    conn.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=?", (status, utc_now(), incident_id))
                row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            notes = [dict(r) for r in conn.execute(
                "SELECT author,body,created_at FROM incident_notes WHERE incident_id=? ORDER BY id", (incident_id,))]
        item = dict(row)
        return jsonify(incident=item, notes=notes)

    @bp.get("/api/incidents/<int:incident_id>/export.csv")
    def export(incident_id):
        with connect(readonly=True) as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not row:
                return jsonify(error="Incident not found"), 404
            events = conn.execute(
                """SELECT timestamp,event_id,message,command FROM events
                   WHERE analysis_session_id=? ORDER BY timestamp LIMIT 5000""", (row["session_id"],)).fetchall()
            notes = conn.execute("SELECT author,body,created_at FROM incident_notes WHERE incident_id=? ORDER BY id",
                                 (incident_id,)).fetchall()
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        def safe(value):
            value = str(value or "")
            return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")) else value
        writer.writerow(["HoneyTrace incident", incident_id])
        for key in ("sensor", "src_ip", "category", "severity", "status", "first_seen", "last_seen", "event_count", "reason"):
            writer.writerow([key, safe(row[key])])
        writer.writerow(["Evidence (maximum 5000 events)", "event", "summary", "command"])
        for event in events:
            summary = "Credential value redacted" if ".login." in event["event_id"] else event["message"]
            writer.writerow([safe(event["timestamp"]), safe(event["event_id"]), safe(summary), safe(event["command"])])
        writer.writerow(["Analyst", "Note", "Time"])
        for note in notes:
            writer.writerow([safe(note["author"]), safe(note["body"]), safe(note["created_at"])])
        return Response(stream.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="honeytrace-incident-{incident_id}.csv"'})

    app.register_blueprint(bp)

"""Analyst authentication, incident workflow and operational health."""
from __future__ import annotations

import csv
import hmac
import io
import os
import secrets
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from threading import Lock

from flask import Blueprint, Response, jsonify, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from config import INSTANCE_DIR, MASK_IPS
from db import connect, utc_now
from privacy import mask_ip


def create_analyst(username: str, password: str) -> None:
    if not username.strip() or len(username) > 80 or len(password) < 12:
        raise ValueError("Use a username of 1–80 characters and a password of at least 12 characters.")
    with connect() as conn:
        conn.execute(
            """INSERT INTO analysts VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET
               password_hash=excluded.password_hash,auth_version=excluded.auth_version""",
            (username.strip(), generate_password_hash(password), secrets.token_hex(16)),
        )


def sync_incidents(session_ids: list[int]) -> None:
    with connect() as conn:
        for session_id in session_ids:
            row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not row:
                continue
            exists = conn.execute("SELECT id FROM incidents WHERE session_key=?", (row["session_key"],)).fetchone()
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
    for item in active:
        if MASK_IPS:
            item["src_ip"] = mask_ip(item["src_ip"])
    return {"sensors": sensors, "active_connections": active, "timeline": timeline}


def install_operations(app):
    secret_path = INSTANCE_DIR / "dashboard.key"
    if not secret_path.exists():
        try:
            with secret_path.open("x") as handle:
                handle.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    app.secret_key = secret_path.read_text().strip()
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
        if request.method in {"POST", "PATCH", "DELETE"}:
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
        for row in rows:
            if MASK_IPS:
                row["src_ip"] = mask_ip(row["src_ip"])
        return jsonify(rows)

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
        if MASK_IPS:
            item["src_ip"] = mask_ip(item["src_ip"])
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
            if MASK_IPS:
                import re
                value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lambda m: mask_ip(m[0]) or "", value)
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

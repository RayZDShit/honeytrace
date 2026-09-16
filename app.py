"""Read-only Flask dashboard API."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, render_template, request

from db import connect, init_db
from operations import install_operations
from live_api import install_live


def create_app() -> Flask:
    init_db()
    app = Flask(__name__)
    install_operations(app)
    cache: dict[str, tuple[float, object]] = {}

    def cached(seconds: int = 20):
        def decorator(function):
            @wraps(function)
            def wrapper(*args, **kwargs):
                key = request.full_path
                item = cache.get(key)
                now = time.monotonic()
                if item and now - item[0] < seconds:
                    return item[1]
                value = function(*args, **kwargs)
                cache[key] = (now, value)
                return value
            return wrapper
        return decorator

    def display_ip(value):
        return value

    def safe_message(event_id, message):
        if not message:
            return message
        fixed = {
            "cowrie.login.failed": "Authentication attempt failed; credential value redacted",
            "nisec.login.failed": "Authentication attempt failed; credential value redacted",
            "cowrie.login.success": "Authentication succeeded in the source honeypot; credential value redacted",
            "nisec.login.success": "Authentication succeeded in the source honeypot; credential value redacted",
            "cowrie.session.connect": "Connection opened",
            "nisec.session.connect": "Connection opened",
            "cowrie.session.closed": "Connection closed",
            "nisec.session.closed": "Connection closed",
            "cowrie.command.input": "Command input recorded",
        }
        if event_id == "nisec.command.input":
            return "Command input recorded"
        if event_id in fixed:
            return fixed[event_id]
        return message

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/overview")
    @cached(15)
    def overview():
        conn = connect(readonly=True)
        stats = {
            "events": conn.execute("SELECT COUNT(1) FROM events").fetchone()[0],
            "sessions": conn.execute("SELECT COUNT(1) FROM sessions").fetchone()[0],
            "unique_ips": conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip IS NOT NULL").fetchone()[0],
            "sources": conn.execute("SELECT COUNT(DISTINCT source_name) FROM events").fetchone()[0],
            "high_risk": conn.execute("SELECT COUNT(1) FROM sessions WHERE threat_level IN ('high','critical')").fetchone()[0],
            "last_event": conn.execute("SELECT MAX(timestamp) FROM events").fetchone()[0],
        }
        stats["labels"] = [dict(row) for row in conn.execute(
            "SELECT final_label AS label,COUNT(1) AS count FROM sessions GROUP BY final_label ORDER BY count DESC"
        )]
        stats["threats"] = [dict(row) for row in conn.execute(
            "SELECT threat_level AS level,COUNT(1) AS count FROM sessions GROUP BY threat_level ORDER BY count DESC"
        )]
        stats["recent"] = []
        for row in conn.execute(
                """SELECT e.timestamp,e.src_ip,e.source_name,e.event_id,e.message
                   FROM events e ORDER BY e.timestamp DESC LIMIT 20"""
            ):
            item = dict(row)
            item["src_ip"] = display_ip(item["src_ip"])
            item["message"] = safe_message(item["event_id"], item["message"])
            stats["recent"].append(item)
        conn.close()
        return jsonify(stats)

    @app.get("/api/timeline")
    @cached(30)
    def timeline():
        conn = connect(readonly=True)
        rows = [dict(row) for row in conn.execute(
            """SELECT substr(first_seen,1,10) AS day,COUNT(1) AS sessions,
               SUM(CASE WHEN threat_level IN ('high','critical') THEN 1 ELSE 0 END) AS high_risk
               FROM sessions GROUP BY day ORDER BY day"""
        )]
        conn.close()
        return jsonify(rows)

    install_live(app, display_ip, safe_message)

    @app.get("/api/sessions")
    def sessions():
        page = max(request.args.get("page", 1, type=int), 1)
        per_page = min(max(request.args.get("per_page", 50, type=int), 10), 200)
        clauses, params = [], []
        for field, column in (("label", "final_label"), ("threat", "threat_level"), ("source", "source_name")):
            value = request.args.get(field, "").strip()
            if value:
                clauses.append(f"{column}=?")
                params.append(value)
        search = request.args.get("search", "").strip()
        if search:
            clauses.append("src_ip LIKE ?")
            params.append(f"%{search}%")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        conn = connect(readonly=True)
        total = conn.execute(f"SELECT COUNT(1) FROM sessions {where}", params).fetchone()[0]
        rows = conn.execute(
            f"""SELECT id,source_type,source_name,src_ip,first_seen,last_seen,event_count,
                login_failures,login_successes,command_count,download_count,rule_label,
                predicted_label,prediction_confidence,final_label,threat_level,rule_reason
                FROM sessions {where} ORDER BY first_seen DESC LIMIT ? OFFSET ?""",
            (*params, per_page, (page - 1) * per_page),
        ).fetchall()
        payload = []
        for row in rows:
            item = dict(row)
            item["src_ip"] = display_ip(item["src_ip"])
            payload.append(item)
        conn.close()
        return jsonify({"sessions": payload, "total": total, "page": page, "per_page": per_page})

    @app.get("/api/sessions/<int:session_id>")
    def session_detail(session_id: int):
        conn = connect(readonly=True)
        session = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if session is None:
            conn.close()
            return jsonify({"error": "session not found"}), 404
        feature_row = conn.execute("SELECT feature_json FROM session_features WHERE session_id=?", (session_id,)).fetchone()
        events = [dict(row) for row in conn.execute(
            """SELECT timestamp,event_id,source_name,src_ip,username,credential_preview,
               command,url,outfile,sha256,client_version,message
               FROM events WHERE analysis_session_id=? ORDER BY timestamp LIMIT 500""",
            (session_id,),
        )]
        conn.close()
        item = dict(session)
        item["src_ip"] = display_ip(item["src_ip"])
        for event in events:
            event["src_ip"] = display_ip(event["src_ip"])
            event["message"] = safe_message(event["event_id"], event["message"])
        return jsonify({
            "session": item,
            "features": json.loads(feature_row["feature_json"]) if feature_row else {},
            "events": events,
            "events_limited": len(events) == 500,
        })

    @app.get("/api/model")
    @cached(30)
    def model_info():
        conn = connect(readonly=True)
        row = conn.execute("SELECT * FROM model_runs ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        if row is None:
            return jsonify({"available": False})
        data = dict(row)
        for key in ("feature_columns_json", "classes_json", "metrics_json", "feature_importance_json"):
            data[key.removesuffix("_json")] = json.loads(data.pop(key))
        data["available"] = True
        return jsonify(data)

    @app.get("/api/sources")
    @cached(30)
    def sources():
        conn = connect(readonly=True)
        rows = [dict(row) for row in conn.execute(
            """SELECT source_name,source_type,COUNT(1) AS sessions,
               SUM(event_count) AS events,SUM(login_failures) AS failed_logins,
               SUM(login_successes) AS successful_logins,SUM(command_count) AS commands,
               SUM(download_count) AS downloads,
               SUM(CASE WHEN threat_level IN ('high','critical') THEN 1 ELSE 0 END) AS high_risk
               FROM sessions GROUP BY source_name,source_type ORDER BY events DESC"""
        )]
        conn.close()
        return jsonify(rows)

    @app.get("/api/imports")
    def imports():
        conn = connect(readonly=True)
        rows = [dict(row) for row in conn.execute(
            "SELECT * FROM imports ORDER BY id DESC LIMIT 200"
        )]
        conn.close()
        return jsonify(rows)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

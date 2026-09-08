"""Bounded change feed: event cursors and session revisions are independent."""
from datetime import datetime, timedelta, timezone
from flask import jsonify, request
from db import connect
from operations import operational_status


def install_live(app, display_ip, safe_message):
    @app.get("/api/live")
    def live_monitor():
        event_cursor = max(request.args.get("after_event_id", 0, type=int), 0)
        revision = max(request.args.get("after_revision", 0, type=int), 0)
        initial = request.args.get("initial", "false") == "true"
        limit = min(max(request.args.get("limit", 100, type=int), 10), 200)
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(minutes=5)).isoformat()
        since = request.args.get("since", cutoff)
        # Clamp the analyst's window to at most 24 hours.
        try:
            parsed = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError()
            since = max(parsed.astimezone(timezone.utc), now - timedelta(hours=24)).isoformat()
        except ValueError:
            return jsonify(error="Invalid time window"), 400
        source, threat = request.args.get("source", ""), request.args.get("threat", "")
        with connect(readonly=True) as conn:
            conn.execute("BEGIN")
            max_event = conn.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
            max_revision = conn.execute("SELECT COALESCE(MAX(revision),0) FROM session_changes").fetchone()[0]
            reset = event_cursor > max_event or revision > max_revision
            initial = initial or reset
            if initial:
                events = conn.execute(
                    "SELECT * FROM events WHERE timestamp>=? AND (?='' OR source_name=?) ORDER BY timestamp DESC,id DESC LIMIT ?",
                    (since, source, source, limit)).fetchall()[::-1]
                detections = conn.execute(
                    "SELECT * FROM sessions WHERE last_seen>=? AND (?='' OR source_name=?) AND (?='' OR threat_level=?) ORDER BY last_seen DESC,id DESC LIMIT ?",
                    (since, source, source, threat, threat, limit)).fetchall()[::-1]
                next_event, next_revision = max_event, max_revision
            else:
                events = conn.execute("SELECT * FROM events WHERE id>? ORDER BY id LIMIT ?", (event_cursor, limit)).fetchall()
                changes = conn.execute(
                    "SELECT revision,session_id FROM session_changes WHERE revision>? ORDER BY revision LIMIT ?",
                    (revision, limit)).fetchall()
                next_event = events[-1]["id"] if events else event_cursor
                next_revision = changes[-1]["revision"] if changes else revision
                detections = []
                for sid in dict.fromkeys(row["session_id"] for row in changes):
                    row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
                    if row:
                        detections.append(row)
            clauses, values = ["timestamp>=?"], [cutoff]
            if source:
                clauses.append("source_name=?")
                values.append(source)
            stats = dict(conn.execute(
                "SELECT COUNT(*) AS events_5m,COUNT(DISTINCT src_ip) AS sources_5m FROM events WHERE " +
                " AND ".join(clauses), values).fetchone())
            stats.update(dict(conn.execute(
                """SELECT COUNT(*) AS detections_5m,
                   COALESCE(SUM(threat_level IN ('high','critical')),0) AS high_risk_5m
                   FROM sessions WHERE last_seen>=? AND (?='' OR source_name=?)""",
                (cutoff, source, source)).fetchone()))
        event_payload, detection_payload = [], []
        for row in events:
            if row["timestamp"] < since or (source and row["source_name"] != source):
                continue
            event_payload.append(dict(id=row["id"], timestamp=row["timestamp"], source_name=row["source_name"],
                                      src_ip=display_ip(row["src_ip"]), event_id=row["event_id"],
                                      message=safe_message(row["event_id"], row["message"])))
        for row in detections:
            if row["last_seen"] < since or (source and row["source_name"] != source):
                continue
            item = {key: row[key] for key in ("id", "source_name", "last_seen", "event_count", "final_label",
                                             "threat_level", "prediction_confidence", "rule_reason")}
            item["src_ip"] = display_ip(row["src_ip"])
            # A changed detection no longer matching the filter must disappear.
            item["hidden"] = bool(threat and row["threat_level"] != threat)
            detection_payload.append(item)
        response = dict(
            generated_at=now.isoformat(), stats=stats, events=event_payload, detections=detection_payload,
            event_cursor=next_event, revision=next_revision, reset=reset,
            has_more=next_event < max_event or next_revision < max_revision,
        )
        response.update(operational_status())
        return jsonify(response)

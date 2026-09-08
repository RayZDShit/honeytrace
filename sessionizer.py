"""Group network events into cross-connection behavioral sessions."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

from config import SESSION_GAP_SECONDS
from db import connect, init_db
from feature_engineering import extract_features, parse_timestamp
from labeling import classify


def _chunks(values: list[int], size: int = 500):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _persist(conn, events: list[dict]) -> int:
    features = extract_features(events)
    decision = classify(features)
    first = events[0]
    last = events[-1]
    session_key_text = f"{first['source_type']}|{first['source_name']}|{first['src_ip']}|{first['timestamp']}"
    session_key = hashlib.sha256(session_key_text.encode()).hexdigest()
    cursor = conn.execute(
        """INSERT INTO sessions(
            session_key,source_type,source_name,src_ip,first_seen,last_seen,duration_seconds,
            native_session_count,event_count,login_failures,login_successes,command_count,
            download_count,rule_label,rule_reason,final_label,threat_level)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(session_key) DO UPDATE SET
             last_seen=excluded.last_seen,duration_seconds=excluded.duration_seconds,
             native_session_count=excluded.native_session_count,event_count=excluded.event_count,
             login_failures=excluded.login_failures,login_successes=excluded.login_successes,
             command_count=excluded.command_count,download_count=excluded.download_count,
             rule_label=excluded.rule_label,rule_reason=excluded.rule_reason,
             final_label=excluded.final_label,threat_level=excluded.threat_level,
             predicted_label=NULL,prediction_confidence=NULL,model_version=NULL
           RETURNING id""",
        (
            session_key, first["source_type"], first["source_name"], first["src_ip"],
            first["timestamp"], last["timestamp"], features["duration_seconds"],
            int(features["native_session_count"]), int(features["event_count"]),
            int(features["login_failures"]), int(features["login_successes"]),
            int(features["command_count"]), int(features["download_count"]),
            decision.label, decision.reason, decision.label, decision.threat_level,
        ),
    )
    session_id = cursor.fetchone()[0]
    conn.execute(
        """INSERT INTO session_features(session_id,feature_json) VALUES(?,?)
           ON CONFLICT(session_id) DO UPDATE SET feature_json=excluded.feature_json""",
        (session_id, json.dumps(features, sort_keys=True, separators=(",", ":"))),
    )
    event_ids = [int(event["id"]) for event in events]
    for chunk in _chunks(event_ids):
        conn.execute(
            f"UPDATE events SET analysis_session_id=? WHERE id IN ({','.join('?' for _ in chunk)})",
            (session_id, *chunk),
        )
    return session_id


def rebuild_sessions(
    *,
    gap_seconds: int = SESSION_GAP_SECONDS,
    progress: Callable[[str], None] = print,
) -> int:
    init_db()
    conn = connect()
    conn.execute("UPDATE events SET analysis_session_id=NULL")
    conn.execute("DELETE FROM session_features")
    conn.execute("DELETE FROM sessions")
    conn.commit()

    cursor = conn.execute(
        """SELECT * FROM events WHERE src_ip IS NOT NULL
           ORDER BY source_type,source_name,src_ip,timestamp,id"""
    )
    current: list[dict] = []
    current_identity: tuple[str, str, str] | None = None
    count = 0

    for row in cursor:
        event = dict(row)
        identity = (event["source_type"], event["source_name"], event["src_ip"])
        split = identity != current_identity
        if current and not split:
            gap = (parse_timestamp(event["timestamp"]) - parse_timestamp(current[-1]["timestamp"])).total_seconds()
            split = gap > gap_seconds
        if current and split:
            _persist(conn, current)
            count += 1
            if count % 1000 == 0:
                conn.commit()
                progress(f"Built {count:,} behavioral sessions")
            current = []
        current.append(event)
        current_identity = identity

    if current:
        _persist(conn, current)
        count += 1
    conn.commit()
    conn.close()
    progress(f"Session build complete: {count:,} sessions")
    return count


def rebuild_identity(source_type: str, source_name: str, src_ip: str, *, gap_seconds: int = SESSION_GAP_SECONDS) -> list[int]:
    """Rebuild only one source identity; used by the live custom sensor."""
    init_db()
    conn = connect()
    latest = conn.execute(
        """SELECT first_seen FROM sessions WHERE source_type=? AND source_name=? AND src_ip=?
           ORDER BY first_seen DESC LIMIT 1""",
        (source_type, source_name, src_ip),
    ).fetchone()

    rows = [dict(row) for row in conn.execute(
        """SELECT * FROM events WHERE source_type=? AND source_name=? AND src_ip=? AND timestamp>=?
           ORDER BY timestamp,id""",
        (source_type, source_name, src_ip, latest["first_seen"] if latest else ""),
    )]
    session_ids: list[int] = []
    current: list[dict] = []
    for event in rows:
        if current:
            gap = (parse_timestamp(event["timestamp"]) - parse_timestamp(current[-1]["timestamp"])).total_seconds()
            if gap > gap_seconds:
                session_ids.append(_persist(conn, current))
                current = []
        current.append(event)
    if current:
        session_ids.append(_persist(conn, current))
    conn.commit()
    conn.close()
    return session_ids

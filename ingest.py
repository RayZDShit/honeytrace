"""Event normalization shared by Cowrie import and the custom SSH sensor."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from privacy import (
    COMMON_PASSWORDS,
    COMMON_USERNAMES,
    fingerprint_secret,
    masked_secret,
    shannon_entropy,
)


EVENT_COLUMNS = (
    "event_key", "source_type", "source_name", "native_session_id", "event_id",
    "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "username", "credential_fingerprint", "credential_preview", "credential_length",
    "credential_entropy", "common_username", "common_password", "command", "url",
    "outfile", "sha256", "client_version", "hassh", "duration", "message",
)

EVENT_INSERT_SQL = f"""
INSERT OR IGNORE INTO events ({','.join(EVENT_COLUMNS)})
VALUES ({','.join('?' for _ in EVENT_COLUMNS)})
"""


def safe_text(value: Any, limit: int = 4000) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)[:limit]


def normalize_timestamp(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return value


def normalize_event(raw: dict[str, Any], source_type: str, source_name: str) -> tuple:
    event_id = safe_text(raw.get("eventid") or raw.get("event_id") or "unknown", 160) or "unknown"
    timestamp = normalize_timestamp(safe_text(raw.get("timestamp"), 80))
    native_session = safe_text(raw.get("session") or raw.get("native_session_id"), 160)
    src_ip = safe_text(raw.get("src_ip"), 128)
    username = safe_text(raw.get("username"), 512)
    password = safe_text(raw.get("password"), 1024)
    command = safe_text(raw.get("input") or raw.get("command"), 4000)
    message = safe_text(raw.get("message"), 2000)
    url = safe_text(raw.get("url"), 2000)
    outfile = safe_text(raw.get("outfile"), 1000)
    sha256 = safe_text(raw.get("shasum") or raw.get("sha256"), 256)
    client_version = safe_text(raw.get("version"), 1000)
    hassh = safe_text(raw.get("hassh"), 256)

    # Cowrie login messages repeat the submitted password in plaintext. Preserve
    # the event semantics without retaining that duplicate secret-bearing text.
    if event_id in {"cowrie.login.failed", "nisec.login.failed"}:
        message = "Authentication attempt failed; credential value redacted"
    elif event_id in {"cowrie.login.success", "nisec.login.success"}:
        message = "Authentication succeeded in the source honeypot; credential value redacted"
    elif event_id in {"cowrie.session.connect", "nisec.session.connect"}:
        message = "Connection opened"
    elif event_id in {"cowrie.session.closed", "nisec.session.closed"}:
        message = "Connection closed"
    elif event_id in {"cowrie.command.input", "nisec.command.input"}:
        message = "Command input recorded"
    elif event_id in {"cowrie.session.file_download", "cowrie.session.file_upload"}:
        message = "File-transfer event recorded"

    identity = json.dumps(
        [source_type, source_name, native_session, event_id, timestamp, src_ip,
         raw.get("src_port"), command, url, message],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    event_key = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()

    duration = raw.get("duration")
    try:
        duration = float(duration) if duration is not None else None
    except (TypeError, ValueError):
        duration = None

    return (
        event_key,
        source_type,
        source_name,
        native_session,
        event_id,
        timestamp,
        src_ip,
        raw.get("src_port") if isinstance(raw.get("src_port"), int) else None,
        safe_text(raw.get("dst_ip"), 128),
        raw.get("dst_port") if isinstance(raw.get("dst_port"), int) else None,
        safe_text(raw.get("protocol"), 64),
        username,
        fingerprint_secret(password),
        masked_secret(password),
        len(password) if password is not None else None,
        round(shannon_entropy(password), 6) if password is not None else None,
        int(bool(username and username.strip().lower() in COMMON_USERNAMES)),
        int(bool(password is not None and password.lower() in COMMON_PASSWORDS)),
        command,
        url,
        outfile,
        sha256,
        client_version,
        hassh,
        duration,
        message,
    )


def insert_normalized_event(conn, raw: dict[str, Any], source_type: str, source_name: str) -> bool:
    before = conn.total_changes
    conn.execute(EVENT_INSERT_SQL, normalize_event(raw, source_type, source_name))
    return conn.total_changes > before

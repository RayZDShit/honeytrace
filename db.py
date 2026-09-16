"""SQLite schema and connection helpers."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from config import DB_PATH, ensure_directories


SCHEMA = """
CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_key TEXT NOT NULL UNIQUE,
    container_path TEXT NOT NULL,
    member_path TEXT NOT NULL,
    source_name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    imported_at TEXT NOT NULL,
    lines_seen INTEGER NOT NULL DEFAULT 0,
    events_inserted INTEGER NOT NULL DEFAULT 0,
    duplicates_skipped INTEGER NOT NULL DEFAULT 0,
    invalid_lines INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL UNIQUE,
    source_type TEXT NOT NULL,
    source_name TEXT NOT NULL,
    native_session_id TEXT,
    analysis_session_id INTEGER,
    event_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    username TEXT,
    credential_fingerprint TEXT,
    credential_preview TEXT,
    credential_length INTEGER,
    credential_entropy REAL,
    common_username INTEGER NOT NULL DEFAULT 0,
    common_password INTEGER NOT NULL DEFAULT 0,
    command TEXT,
    url TEXT,
    outfile TEXT,
    sha256 TEXT,
    client_version TEXT,
    hassh TEXT,
    duration REAL,
    message TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_key TEXT NOT NULL UNIQUE,
    source_type TEXT NOT NULL,
    source_name TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    duration_seconds REAL NOT NULL DEFAULT 0,
    native_session_count INTEGER NOT NULL DEFAULT 0,
    event_count INTEGER NOT NULL DEFAULT 0,
    login_failures INTEGER NOT NULL DEFAULT 0,
    login_successes INTEGER NOT NULL DEFAULT 0,
    command_count INTEGER NOT NULL DEFAULT 0,
    download_count INTEGER NOT NULL DEFAULT 0,
    rule_label TEXT NOT NULL DEFAULT 'unknown',
    rule_reason TEXT,
    predicted_label TEXT,
    prediction_confidence REAL,
    final_label TEXT NOT NULL DEFAULT 'unknown',
    threat_level TEXT NOT NULL DEFAULT 'low',
    model_version TEXT
);

CREATE TABLE IF NOT EXISTS session_features (
    session_id INTEGER PRIMARY KEY,
    feature_json TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS model_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_version TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    feature_columns_json TEXT NOT NULL,
    classes_json TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    feature_importance_json TEXT NOT NULL,
    train_samples INTEGER NOT NULL,
    test_samples INTEGER NOT NULL,
    dataset_fingerprint TEXT NOT NULL,
    label_provenance TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_source_ip_time ON events(source_name, src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_analysis_session ON events(analysis_session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_first_seen ON sessions(first_seen);
CREATE INDEX IF NOT EXISTS idx_sessions_final_label ON sessions(final_label);
CREATE INDEX IF NOT EXISTS idx_sessions_threat ON sessions(threat_level);
CREATE INDEX IF NOT EXISTS idx_sessions_source ON sessions(source_name);
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen);

CREATE TABLE IF NOT EXISTS session_changes (
    revision INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS session_insert_change AFTER INSERT ON sessions
BEGIN INSERT INTO session_changes(session_id) VALUES(NEW.id); END;
CREATE TRIGGER IF NOT EXISTS session_update_change AFTER UPDATE ON sessions
BEGIN INSERT INTO session_changes(session_id) VALUES(NEW.id); END;

CREATE TABLE IF NOT EXISTS sensors (
    name TEXT PRIMARY KEY, heartbeat TEXT NOT NULL, status TEXT NOT NULL,
    bind_address TEXT NOT NULL, port INTEGER NOT NULL,
    active_connections INTEGER NOT NULL DEFAULT 0,
    backlog INTEGER NOT NULL DEFAULT 0, dropped_events INTEGER NOT NULL DEFAULT 0,
    processing_ms REAL NOT NULL DEFAULT 0, error TEXT
);
CREATE TABLE IF NOT EXISTS active_connections (
    native_id TEXT PRIMARY KEY, sensor TEXT NOT NULL, src_ip TEXT NOT NULL,
    opened_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analysts (
    username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
    auth_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_key TEXT NOT NULL UNIQUE, session_id INTEGER NOT NULL,
    sensor TEXT NOT NULL, src_ip TEXT NOT NULL, category TEXT NOT NULL,
    severity TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    event_count INTEGER NOT NULL, reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New', updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
    author TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key TEXT NOT NULL UNIQUE,
    incident_id INTEGER NOT NULL,
    session_key TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    sensor TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    created_at TEXT NOT NULL,
    acknowledged_by TEXT,
    acknowledged_at TEXT,
    discord_status TEXT NOT NULL DEFAULT 'disabled',
    discord_sent_at TEXT,
    discord_error TEXT,
    FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged_at);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ManagedConnection(sqlite3.Connection):
    """Commit/rollback and close on context exit (SQLite alone does not close)."""
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect(*, readonly: bool = False) -> sqlite3.Connection:
    ensure_directories()
    if readonly:
        uri = f"file:{DB_PATH.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=30, factory=ManagedConnection)
    else:
        conn = sqlite3.connect(DB_PATH, timeout=60, factory=ManagedConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    if not readonly:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


@contextmanager
def transaction():
    conn = connect()
    try:
        conn.execute("BEGIN")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

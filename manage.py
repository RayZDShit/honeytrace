"""Single command-line entry point for setup and operation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from config import BASE_DIR, DB_PATH, MODEL_PATH, SESSION_GAP_SECONDS
from db import connect, init_db


def command_init(_args) -> None:
    init_db()
    print(f"Database initialized: {DB_PATH}")


def command_import(args) -> None:
    from import_cowrie import import_path
    totals = import_path(
        args.path, max_files=args.max_files, max_lines_per_file=args.max_lines_per_file
    )
    print(json.dumps(totals, indent=2))


def command_sessions(args) -> None:
    from sessionizer import rebuild_sessions
    rebuild_sessions(gap_seconds=args.gap)


def command_train(_args) -> None:
    from model_service import train_model
    metrics = train_model()
    print(json.dumps({
        "version": metrics["version"],
        "algorithm": metrics["algorithm"],
        "balanced_accuracy": metrics["balanced_accuracy"],
        "macro_f1": metrics["macro_f1"],
        "accuracy": metrics["accuracy"],
    }, indent=2))


def command_apply(_args) -> None:
    from model_service import apply_model
    print(f"Updated {apply_model():,} sessions")


def command_sanitize(_args) -> None:
    """Remove duplicate plaintext credentials from legacy Cowrie message text."""
    init_db()
    conn = connect()
    replacements = {
        "cowrie.login.failed": "Authentication attempt failed; credential value redacted",
        "nisec.login.failed": "Authentication attempt failed; credential value redacted",
        "cowrie.login.success": "Authentication succeeded in the source honeypot; credential value redacted",
        "nisec.login.success": "Authentication succeeded in the source honeypot; credential value redacted",
        "cowrie.session.connect": "Connection opened",
        "nisec.session.connect": "Connection opened",
        "cowrie.session.closed": "Connection closed",
        "nisec.session.closed": "Connection closed",
        "cowrie.command.input": "Command input recorded",
        "cowrie.session.file_download": "File-transfer event recorded",
        "cowrie.session.file_upload": "File-transfer event recorded",
    }
    changed = 0
    for event_id, message in replacements.items():
        cursor = conn.execute("UPDATE events SET message=? WHERE event_id=?", (message, event_id))
        changed += cursor.rowcount
    conn.commit()
    conn.close()
    print(f"Sanitized {changed:,} stored event messages")


def command_all(args) -> None:
    command_init(args)
    command_import(args)
    command_sessions(args)
    command_train(args)


def command_status(_args) -> None:
    init_db()
    conn = connect(readonly=True)
    values = {
        "database": str(DB_PATH),
        "database_exists": DB_PATH.exists(),
        "database_bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0,
        "events": conn.execute("SELECT COUNT(1) FROM events").fetchone()[0],
        "sessions": conn.execute("SELECT COUNT(1) FROM sessions").fetchone()[0],
        "imports_complete": conn.execute("SELECT COUNT(1) FROM imports WHERE status='complete'").fetchone()[0],
        "sources": conn.execute("SELECT COUNT(DISTINCT source_name) FROM events").fetchone()[0],
        "model": str(MODEL_PATH),
        "model_exists": MODEL_PATH.exists(),
        "label_distribution": {
            row["rule_label"]: row["count"] for row in conn.execute(
                "SELECT rule_label,COUNT(1) AS count FROM sessions GROUP BY rule_label ORDER BY count DESC"
            )
        },
        "distinct_sources_per_label": {
            row["rule_label"]: row["count"] for row in conn.execute(
                "SELECT rule_label,COUNT(DISTINCT src_ip) AS count FROM sessions GROUP BY rule_label ORDER BY count DESC"
            )
        },
    }
    latest = conn.execute("SELECT model_version,algorithm,metrics_json FROM model_runs ORDER BY id DESC LIMIT 1").fetchone()
    if latest:
        metrics = json.loads(latest["metrics_json"])
        values["latest_model"] = {
            "version": latest["model_version"], "algorithm": latest["algorithm"],
            "balanced_accuracy": metrics["balanced_accuracy"], "macro_f1": metrics["macro_f1"],
        }
    conn.close()
    print(json.dumps(values, indent=2))


def command_dashboard(args) -> None:
    from app import app
    if args.dev:
        app.run(host=args.host, port=args.port, debug=False)
    else:
        from waitress import serve
        print(f"Dashboard: http://{args.host}:{args.port}")
        serve(app, host=args.host, port=args.port, threads=8)


def command_honeypot(args) -> None:
    from ssh_honeypot import run_honeypot
    run_honeypot(host=args.host, port=args.port)


def command_analyst(args) -> None:
    from getpass import getpass
    from operations import create_analyst
    init_db()
    username = args.username or input("Analyst username: ").strip()
    password = getpass("New password (12+ characters): ")
    if password != getpass("Confirm password: "):
        raise SystemExit("Passwords did not match.")
    create_analyst(username, password)
    print("Analyst account saved. Sign in at the dashboard.")


def build_parser() -> argparse.ArgumentParser:
    default_logs = BASE_DIR / "archive.zip"
    parser = argparse.ArgumentParser(description="NISec honeypot project manager")
    sub = parser.add_subparsers(dest="command", required=True)
    analyst = sub.add_parser("analyst", help="Create or reset a local analyst account")
    analyst.add_argument("--username")
    analyst.set_defaults(func=command_analyst)
    sub.add_parser("init", help="Create the database schema").set_defaults(func=command_init)

    def add_import_arguments(target):
        target.add_argument("--path", default=str(default_logs), help="Cowrie log directory, JSON file, or ZIP archive")
        target.add_argument("--max-files", type=int, help="Optional file limit for a small validation run")
        target.add_argument("--max-lines-per-file", type=int, help="Optional per-file line limit for validation")

    importer = sub.add_parser("import", help="Stream and deduplicate Cowrie logs")
    add_import_arguments(importer)
    importer.set_defaults(func=command_import)

    sessions = sub.add_parser("sessions", help="Build timed behavioral sessions and rule labels")
    sessions.add_argument("--gap", type=int, default=SESSION_GAP_SECONDS, help="Seconds separating behavioral sessions")
    sessions.set_defaults(func=command_sessions)

    sub.add_parser("train", help="Train and evaluate the behavioral model").set_defaults(func=command_train)
    sub.add_parser("apply-model", help="Apply the saved model to all sessions").set_defaults(func=command_apply)
    sub.add_parser("sanitize", help="Remove duplicate secrets from legacy event messages").set_defaults(func=command_sanitize)

    all_command = sub.add_parser("all", help="Initialize, import, sessionize, train, and apply")
    add_import_arguments(all_command)
    all_command.add_argument("--gap", type=int, default=SESSION_GAP_SECONDS)
    all_command.set_defaults(func=command_all)

    sub.add_parser("status", help="Show database and model status").set_defaults(func=command_status)

    dashboard = sub.add_parser("dashboard", help="Run the read-only dashboard")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=5000)
    dashboard.add_argument("--dev", action="store_true", help="Use Flask's local server instead of Waitress")
    dashboard.set_defaults(func=command_dashboard)

    honeypot = sub.add_parser("honeypot", help="Run the contained SSHv2 sensor")
    honeypot.add_argument("--host", default="127.0.0.1")
    honeypot.add_argument("--port", type=int, default=2222)
    honeypot.set_defaults(func=command_honeypot)
    return parser


if __name__ == "__main__":
    arguments = build_parser().parse_args()
    arguments.func(arguments)

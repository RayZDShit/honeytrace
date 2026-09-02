"""Session-level behavioral feature extraction."""

from __future__ import annotations

import math
import statistics
from datetime import datetime, timezone


FEATURE_COLUMNS = [
    "event_count", "native_session_count", "duration_seconds", "connection_count",
    "login_failures", "login_successes", "login_attempts", "success_ratio",
    "unique_usernames", "unique_passwords", "unique_pairs", "unique_pair_ratio",
    "common_username_ratio", "common_password_ratio", "avg_password_length",
    "avg_password_entropy", "avg_login_interval", "min_login_interval",
    "max_login_interval", "std_login_interval", "attempts_per_minute",
    "command_count", "unique_command_count", "recon_command_count",
    "recon_command_ratio", "download_keyword_count", "miner_keyword_count",
    "botnet_keyword_count", "download_count", "client_version_count", "hassh_count",
]

RECON_WORDS = {
    "uname", "whoami", "id", "pwd", "ls", "cat", "find", "ps", "ifconfig",
    "ip a", "netstat", "ss ", "w ", "uptime", "hostname", "lscpu", "free ",
}
DOWNLOAD_WORDS = {"wget", "curl", "tftp", "ftp ", "scp ", "sftp ", "powershell"}
MINER_WORDS = {"xmrig", "minerd", "cryptonight", "stratum+tcp", "monero", "kdevtmpfsi"}
BOTNET_WORDS = {"mirai", "mozi", "botnet", "ddos", "hajime", "gafgyt", "tsunami"}


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _keyword_hits(command: str, words: set[str]) -> int:
    lowered = command.lower()
    return sum(1 for word in words if word in lowered)


def extract_features(events: list[dict]) -> dict[str, float]:
    if not events:
        raise ValueError("Cannot extract features from an empty session")
    events = sorted(events, key=lambda row: row["timestamp"])
    timestamps = [parse_timestamp(row["timestamp"]) for row in events]
    duration = max((timestamps[-1] - timestamps[0]).total_seconds(), 0.0)

    failed = [row for row in events if row["event_id"] == "cowrie.login.failed" or row["event_id"] == "nisec.login.failed"]
    succeeded = [row for row in events if row["event_id"] == "cowrie.login.success" or row["event_id"] == "nisec.login.success"]
    login_events = sorted(failed + succeeded, key=lambda row: row["timestamp"])
    login_times = [parse_timestamp(row["timestamp"]) for row in login_events]
    intervals = [max((login_times[i] - login_times[i - 1]).total_seconds(), 0.0) for i in range(1, len(login_times))]

    usernames = [str(row["username"]) for row in login_events if row.get("username")]
    passwords = [str(row["credential_fingerprint"]) for row in login_events if row.get("credential_fingerprint")]
    pairs = {
        (str(row.get("username") or ""), str(row.get("credential_fingerprint") or ""))
        for row in login_events if row.get("username") or row.get("credential_fingerprint")
    }
    credential_rows = [row for row in login_events if row.get("credential_length") is not None]

    commands = [str(row["command"]) for row in events if row.get("command")]
    recon_hits = sum(1 for command in commands if _keyword_hits(command, RECON_WORDS) > 0)
    download_hits = sum(_keyword_hits(command, DOWNLOAD_WORDS) for command in commands)
    miner_hits = sum(_keyword_hits(command, MINER_WORDS) for command in commands)
    botnet_hits = sum(_keyword_hits(command, BOTNET_WORDS) for command in commands)
    downloads = [row for row in events if row["event_id"] in {"cowrie.session.file_download", "cowrie.session.file_upload"}]

    login_attempts = len(login_events)
    return {
        "event_count": float(len(events)),
        "native_session_count": float(len({row.get("native_session_id") for row in events if row.get("native_session_id")})),
        "duration_seconds": round(duration, 6),
        "connection_count": float(sum(1 for row in events if row["event_id"] in {"cowrie.session.connect", "nisec.session.connect"})),
        "login_failures": float(len(failed)),
        "login_successes": float(len(succeeded)),
        "login_attempts": float(login_attempts),
        "success_ratio": round(len(succeeded) / login_attempts, 6) if login_attempts else 0.0,
        "unique_usernames": float(len(set(usernames))),
        "unique_passwords": float(len(set(passwords))),
        "unique_pairs": float(len(pairs)),
        "unique_pair_ratio": round(len(pairs) / login_attempts, 6) if login_attempts else 0.0,
        "common_username_ratio": round(sum(int(row.get("common_username") or 0) for row in login_events) / login_attempts, 6) if login_attempts else 0.0,
        "common_password_ratio": round(sum(int(row.get("common_password") or 0) for row in login_events) / login_attempts, 6) if login_attempts else 0.0,
        "avg_password_length": round(statistics.fmean(float(row["credential_length"]) for row in credential_rows), 6) if credential_rows else 0.0,
        "avg_password_entropy": round(statistics.fmean(float(row["credential_entropy"]) for row in credential_rows), 6) if credential_rows else 0.0,
        "avg_login_interval": round(statistics.fmean(intervals), 6) if intervals else 0.0,
        "min_login_interval": round(min(intervals), 6) if intervals else 0.0,
        "max_login_interval": round(max(intervals), 6) if intervals else 0.0,
        "std_login_interval": round(statistics.pstdev(intervals), 6) if len(intervals) > 1 else 0.0,
        "attempts_per_minute": round(login_attempts / max(duration / 60.0, 1 / 60.0), 6) if login_attempts else 0.0,
        "command_count": float(len(commands)),
        "unique_command_count": float(len(set(commands))),
        "recon_command_count": float(recon_hits),
        "recon_command_ratio": round(recon_hits / len(commands), 6) if commands else 0.0,
        "download_keyword_count": float(download_hits),
        "miner_keyword_count": float(miner_hits),
        "botnet_keyword_count": float(botnet_hits),
        "download_count": float(len(downloads)),
        "client_version_count": float(len({row.get("client_version") for row in events if row.get("client_version")})),
        "hassh_count": float(len({row.get("hassh") for row in events if row.get("hassh")})),
    }


def feature_vector(features: dict[str, float]) -> list[float]:
    values = [float(features.get(name, 0.0)) for name in FEATURE_COLUMNS]
    if not all(math.isfinite(value) for value in values):
        raise ValueError("Feature vector contains non-finite values")
    return values

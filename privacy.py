"""Privacy helpers for credential fingerprints and dashboard-safe values."""

from __future__ import annotations

import hashlib
import hmac
import math
import os
from collections import Counter

from config import SECRET_KEY_PATH, ensure_directories


COMMON_USERNAMES = {
    "admin", "administrator", "root", "user", "test", "guest", "support",
    "oracle", "postgres", "mysql", "ubuntu", "pi", "ftpuser",
}
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "admin", "root", "letmein", "welcome",
    "qwerty", "abc123", "toor", "guest", "test", "changeme", "1234",
}


def _credential_key() -> bytes:
    ensure_directories()
    if not SECRET_KEY_PATH.exists():
        SECRET_KEY_PATH.write_bytes(os.urandom(32))
    return SECRET_KEY_PATH.read_bytes()


def fingerprint_secret(secret: str | None) -> str | None:
    if secret is None:
        return None
    return hmac.new(_credential_key(), secret.encode("utf-8", errors="replace"), hashlib.sha256).hexdigest()


def shannon_entropy(value: str | None) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def masked_secret(secret: str | None) -> str | None:
    if secret is None:
        return None
    if not secret:
        return "(empty)"
    return f"{secret[0]}{'*' * min(max(len(secret) - 1, 3), 12)} ({len(secret)} chars)"


def mask_ip(value: str | None) -> str | None:
    if not value:
        return value
    if ":" in value:
        parts = value.split(":")
        return ":".join(parts[:2]) + ":…"
    parts = value.split(".")
    if len(parts) == 4:
        return ".".join(parts[:2] + ["x", "x"])
    return value

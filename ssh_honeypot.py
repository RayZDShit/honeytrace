"""Contained low-interaction SSH-style sensor.

This is intentionally not a real SSH implementation. It exposes no shell,
filesystem, authentication backend, or command execution path.
"""

from __future__ import annotations

import socket
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from config import MAX_HONEYPOT_WORKERS, MAX_INPUT_BYTES
from db import connect, init_db
from ingest import insert_normalized_event
from model_service import apply_model, load_artifact
from sessionizer import rebuild_identity


BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
LOGIN_PROMPT = b"login: "
PASSWORD_PROMPT = b"password: "
DENIED = b"Permission denied.\r\n"
SOURCE_NAME = "custom-ssh"
SESSION_UPDATE_LOCK = threading.Lock()


def _read_line(conn: socket.socket, limit: int = MAX_INPUT_BYTES) -> str:
    buffer = bytearray()
    while len(buffer) < limit:
        value = conn.recv(1)
        if not value or value in {b"\r", b"\n"}:
            break
        if value in {b"\x08", b"\x7f"}:
            if buffer:
                buffer.pop()
        else:
            buffer.extend(value)
    return buffer.decode("utf-8", errors="replace")


def _record(raw: dict) -> None:
    with connect() as conn:
        insert_normalized_event(conn, raw, "custom_ssh", SOURCE_NAME)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def handle_client(conn: socket.socket, address) -> None:
    src_ip, src_port = address[0], address[1]
    session = uuid.uuid4().hex[:16]
    start = datetime.now(timezone.utc)
    try:
        conn.settimeout(15)
        _record({
            "eventid": "nisec.session.connect", "session": session, "timestamp": _timestamp(),
            "src_ip": src_ip, "src_port": src_port, "protocol": "ssh-style",
            "message": "Connection accepted by contained low-interaction sensor",
        })
        conn.sendall(BANNER + LOGIN_PROMPT)
        username = _read_line(conn)
        conn.sendall(PASSWORD_PROMPT)
        password = _read_line(conn)
        _record({
            "eventid": "nisec.login.failed", "session": session, "timestamp": _timestamp(),
            "src_ip": src_ip, "src_port": src_port, "protocol": "ssh-style",
            "username": username, "password": password,
            "message": "Authentication denied by design",
        })
        conn.sendall(DENIED)
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        duration = (datetime.now(timezone.utc) - start).total_seconds()
        try:
            _record({
                "eventid": "nisec.session.closed", "session": session, "timestamp": _timestamp(),
                "src_ip": src_ip, "src_port": src_port, "protocol": "ssh-style",
                "duration": duration, "message": "Connection closed",
            })
        finally:
            try:
                conn.close()
            except OSError:
                pass
        with SESSION_UPDATE_LOCK:
            session_ids = rebuild_identity("custom_ssh", SOURCE_NAME, src_ip)
            if session_ids and load_artifact() is not None:
                apply_model(session_ids=session_ids, progress=lambda _message: None)


def run_honeypot(host: str = "127.0.0.1", port: int = 2222) -> None:
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(100)
    capacity = threading.BoundedSemaphore(MAX_HONEYPOT_WORKERS * 2)
    print(f"Contained SSH-style sensor listening on {host}:{port}")
    print("No real authentication, shell, filesystem, or command execution is available.")
    with ThreadPoolExecutor(max_workers=MAX_HONEYPOT_WORKERS, thread_name_prefix="sensor") as pool:
        try:
            while True:
                conn, address = server.accept()
                if not capacity.acquire(blocking=False):
                    conn.close()
                    continue
                future = pool.submit(handle_client, conn, address)
                future.add_done_callback(lambda _future: capacity.release())
        except KeyboardInterrupt:
            print("Stopping sensor.")
        finally:
            server.close()


if __name__ == "__main__":
    run_honeypot()

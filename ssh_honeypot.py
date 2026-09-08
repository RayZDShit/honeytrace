"""HoneyTrace SSHv2 sensor with a contained virtual terminal."""
from __future__ import annotations
import asyncio
import hmac
import logging
import os
import time
import uuid
import asyncssh

from config import INSTANCE_DIR, MAX_HONEYPOT_WORKERS, MAX_INPUT_BYTES
from db import connect, init_db, utc_now
from ingest import insert_normalized_event
from model_service import apply_model
from operations import sync_incidents
from sessionizer import rebuild_identity
from virtual_shell import VirtualShell

SOURCE_NAME = "custom-ssh"
LOG = logging.getLogger("honeytrace.sensor")


def persist_batch(events):
    with connect() as conn:
        for event in events:
            insert_normalized_event(conn, event, "custom_ssh", SOURCE_NAME)
            if event["eventid"] == "nisec.session.connect":
                conn.execute("INSERT OR REPLACE INTO active_connections VALUES(?,?,?,?)",
                             (event["session"], SOURCE_NAME, event["src_ip"], event["timestamp"]))
            elif event["eventid"] == "nisec.session.closed":
                conn.execute("DELETE FROM active_connections WHERE native_id=?", (event["session"],))
    for address in {event["src_ip"] for event in events}:
        ids = rebuild_identity("custom_ssh", SOURCE_NAME, address)
        try:
            apply_model(session_ids=ids, progress=lambda _: None)
        except FileNotFoundError:
            pass
        sync_incidents(ids)


class SensorRuntime:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.queue = asyncio.Queue(maxsize=4000)
        self.connections = set()
        self.dropped = 0
        self.processing_ms = 0
        self.error = None

    def emit(self, owner, event_id, **fields):
        event = dict(eventid=event_id, timestamp=utc_now(), session=owner.native_id,
                     src_ip=owner.address, src_port=owner.port, protocol="ssh", **fields)
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1
            self.error = "Telemetry queue full"
            owner.conn.close()

    async def worker(self):
        while True:
            batch = [await self.queue.get()]
            while len(batch) < 100 and not self.queue.empty():
                batch.append(self.queue.get_nowait())
            start = time.monotonic()
            try:
                for attempt in range(3):
                    try:
                        await asyncio.to_thread(persist_batch, batch)
                        break
                    except Exception:
                        if attempt == 2:
                            raise
                        await asyncio.sleep(.25 * (attempt + 1))
                self.processing_ms = round((time.monotonic() - start) * 1000, 1)
                self.error = None
            except Exception:
                self.dropped += len(batch)
                self.error = "Analysis failed; inspect sensor log and run sessions/apply-model recovery"
                LOG.exception("Telemetry processing failed")
            finally:
                for _ in batch:
                    self.queue.task_done()

    def save_health(self, status):
        with connect() as conn:
            conn.execute(
                """INSERT INTO sensors VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(name) DO UPDATE SET heartbeat=excluded.heartbeat,status=excluded.status,
                   bind_address=excluded.bind_address,port=excluded.port,
                   active_connections=excluded.active_connections,backlog=excluded.backlog,
                   dropped_events=excluded.dropped_events,processing_ms=excluded.processing_ms,error=excluded.error""",
                (SOURCE_NAME, utc_now(), status, self.host, self.port, len(self.connections),
                 self.queue.qsize(), self.dropped, self.processing_ms, self.error))
            if status == "offline":
                conn.execute("DELETE FROM active_connections WHERE sensor=?", (SOURCE_NAME,))

    async def heartbeat(self):
        while True:
            try:
                await asyncio.to_thread(self.save_health, "online")
            except Exception:
                LOG.exception("Sensor heartbeat failed")
            await asyncio.sleep(3)


class HoneySSH(asyncssh.SSHServer):
    def __init__(self, runtime):
        self.runtime = runtime
        self.native_id = uuid.uuid4().hex
        self.username = ""
        self.admitted = False
        self.channels = 0

    def connection_made(self, conn):
        self.conn = conn
        self.address, self.port = conn.get_extra_info("peername")[:2]
        if len(self.runtime.connections) >= MAX_HONEYPOT_WORKERS:
            conn.close()
            return
        self.admitted = True
        self.runtime.connections.add(self)
        self.timer = asyncio.get_running_loop().call_later(300, conn.close)
        self.runtime.emit(self, "nisec.session.connect", message="Connection opened")

    def connection_lost(self, exc):
        if self.admitted:
            self.timer.cancel()
            self.runtime.connections.discard(self)
            self.runtime.emit(self, "nisec.session.closed", message="Connection closed")

    def begin_auth(self, username):
        self.username = username[:128]
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        expected = os.getenv("HONEYTRACE_DECOY_PASSWORD", "honeytrace-lab")
        accepted = username == "root" and hmac.compare_digest(password.encode(), expected.encode())
        self.runtime.emit(self, "nisec.login.success" if accepted else "nisec.login.failed",
                          username=username, password=password, message="Authentication recorded")
        return accepted

    def session_requested(self):
        if self.channels >= 4:
            return False
        self.channels += 1
        return HoneyTerminal(self)

    def connection_requested(self, *args):
        return False

    def server_requested(self, *args):
        return False


class HoneyTerminal(asyncssh.SSHServerSession):
    def __init__(self, owner):
        self.owner = owner
        self.shell = VirtualShell()
        self.buffer = ""
        self.command = None
        self.count = 0
        self.pty = False
        self.after_cr = False

    def connection_made(self, chan):
        self.chan = chan

    def pty_requested(self, *args):
        self.pty = True
        return True

    def shell_requested(self):
        return True

    def exec_requested(self, command):
        if len(command.encode()) > MAX_INPUT_BYTES:
            return False
        self.command = command
        return True

    def subsystem_requested(self, subsystem):
        return False

    def session_started(self):
        if self.command is not None:
            status = self.run(self.command)
            self.chan.exit(status)
        else:
            self.chan.write("Ubuntu 22.04 LTS\r\nroot@edge-node:~# ")

    def run(self, command):
        self.count += 1
        if self.count > 100:
            self.chan.exit(1)
            return 1
        self.owner.runtime.emit(self.owner, "nisec.command.input", input=command,
                                username=self.owner.username, message="Command input recorded")
        output, status = self.shell.execute(command)
        self.chan.write(output)
        return status

    def data_received(self, data, datatype):
        for char in data:
            if char == "\n" and self.after_cr:
                self.after_cr = False
                continue
            self.after_cr = char == "\r"
            if char in {"\r", "\n"}:
                if self.pty:
                    self.chan.write("\r\n")
                line, self.buffer = self.buffer, ""
                if line.strip() in {"exit", "logout"}:
                    self.chan.exit(0)
                    return
                self.run(line)
                self.chan.write(f"root@edge-node:{self.shell.cwd}# ")
            elif char in {"\x08", "\x7f"}:
                if self.pty and self.buffer:
                    self.chan.write("\b \b")
                self.buffer = self.buffer[:-1]
            else:
                if not char.isprintable():
                    continue
                self.buffer += char
                if len(self.buffer.encode()) > MAX_INPUT_BYTES:
                    self.chan.exit(1)
                    return
                if self.pty:
                    self.chan.write(char)

    def eof_received(self):
        self.chan.exit(0)
        return False


async def serve(host="127.0.0.1", port=2222):
    init_db()
    key_path = INSTANCE_DIR / "ssh_host_key"
    if not key_path.exists():
        key = asyncssh.generate_private_key("ssh-ed25519")
        with key_path.open("xb") as handle:
            handle.write(key.export_private_key())
    runtime = SensorRuntime(host, port)
    server = await asyncssh.create_server(
        lambda: HoneySSH(runtime), host, port, server_host_keys=[str(key_path)],
        server_version="OpenSSH_8.9p1", login_timeout=30, line_editor=False,
        encoding="utf-8", errors="replace", allow_pty=True,
        agent_forwarding=False, x11_forwarding=False,
    )
    with connect() as conn:
        conn.execute("DELETE FROM active_connections WHERE sensor=?", (SOURCE_NAME,))
    worker = asyncio.create_task(runtime.worker())
    heartbeat = asyncio.create_task(runtime.heartbeat())
    print(f"HoneyTrace SSHv2 sensor listening on {host}:{port}", flush=True)
    print("Virtual terminal only. File transfers and forwarding are disabled.", flush=True)
    try:
        await server.wait_closed()
    finally:
        server.close()
        for connection in list(runtime.connections):
            connection.conn.close()
        await asyncio.sleep(0.1)
        try:
            await asyncio.wait_for(runtime.queue.join(), 15)
        except asyncio.TimeoutError:
            runtime.error = "Shutdown timed out while draining telemetry"
        heartbeat.cancel()
        worker.cancel()
        await asyncio.gather(heartbeat, worker, return_exceptions=True)
        await asyncio.to_thread(runtime.save_health, "offline")


def run_honeypot(host="127.0.0.1", port=2222):
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(serve(host, port))
    except KeyboardInterrupt:
        print("Sensor stopped.")


if __name__ == "__main__":
    run_honeypot()

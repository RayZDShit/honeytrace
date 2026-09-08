"""Isolated integration checks; never write to the user's telemetry database."""
import asyncio
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
temporary = tempfile.TemporaryDirectory(prefix="honeytrace-tests-")
os.environ["NISEC_INSTANCE_DIR"] = temporary.name
os.environ["NISEC_MODEL_DIR"] = str(Path(temporary.name) / "model")
os.environ["NISEC_DB_PATH"] = str(Path(temporary.name) / "test.db")
os.environ["NISEC_SECRET_KEY_PATH"] = str(Path(temporary.name) / "credential.key")
os.environ["NISEC_MODEL_PATH"] = str(Path(temporary.name) / "missing.joblib")
os.environ["NISEC_MASK_IPS"] = "true"
os.environ["HONEYTRACE_DECOY_PASSWORD"] = "integration-decoy"

import asyncssh
from app import app
from db import connect, utc_now
from operations import create_analyst, sync_incidents
from ssh_honeypot import HoneySSH, SensorRuntime, persist_batch
from virtual_shell import VirtualShell


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        create_analyst("reviewer", "integration-password-123")

    def signed_in(self):
        client = app.test_client()
        client.get("/login")
        with client.session_transaction() as session:
            token = session["csrf"]
        response = client.post("/login", data={"csrf_token": token, "username": "reviewer",
                                               "password": "integration-password-123"})
        self.assertEqual(response.status_code, 302)
        return client

    def test_authentication_and_csrf(self):
        client = app.test_client()
        self.assertEqual(client.get("/api/live").status_code, 401)
        self.assertEqual(client.get("/").status_code, 302)
        self.assertEqual(client.post("/login", data={}).status_code, 403)
        signed = self.signed_in()
        self.assertEqual(signed.get("/").status_code, 200)
        self.assertEqual(signed.get("/api/live?initial=true").status_code, 200)
        self.assertEqual(signed.post("/logout").status_code, 403)

    def test_stable_session_revision_and_incident_workflow(self):
        client = self.signed_in()
        def event(kind, **kwargs):
            return dict(eventid=kind, timestamp=utc_now(), session="stable-session",
                        src_ip="192.0.2.55", src_port=45678, protocol="ssh", **kwargs)
        persist_batch([event("nisec.login.success", username="root", password="sensitive-test"),
                       event("nisec.command.input", input="whoami", message="Command")])
        with connect() as conn:
            original = conn.execute("SELECT * FROM sessions WHERE src_ip='192.0.2.55'").fetchone()
            iid = conn.execute("SELECT id FROM incidents WHERE session_id=?", (original["id"],)).fetchone()[0]
        snapshot = client.get("/api/live?initial=true").get_json()
        persist_batch([event("nisec.command.input", input="pwd")])
        with connect() as conn:
            current = conn.execute("SELECT * FROM sessions WHERE src_ip='192.0.2.55'").fetchone()
            self.assertEqual(current["id"], original["id"])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM incidents WHERE session_id=?", (original["id"],)).fetchone()[0], 1)
            conn.execute("UPDATE sessions SET predicted_label='reconnaissance',prediction_confidence=.91 WHERE id=?",
                         (original["id"],))
        update = client.get("/api/live", query_string={
            "after_event_id": snapshot["event_cursor"], "after_revision": snapshot["revision"]}).get_json()
        scored = next(d for d in update["detections"] if d["id"] == original["id"])
        self.assertEqual(scored["prediction_confidence"], .91)
        self.assertEqual(scored["src_ip"], "192.0.x.x")
        with client.session_transaction() as session:
            token = session["csrf"]
        headers = {"X-CSRF-Token": token}
        self.assertEqual(client.patch(f"/api/incidents/{iid}", headers=headers,
                                      json={"status": []}).status_code, 400)
        self.assertEqual(client.patch(f"/api/incidents/{iid}", json={"status": "Resolved"}).status_code, 403)
        result = client.patch(f"/api/incidents/{iid}", headers=headers,
                              json={"status": "Investigating", "note": "=unsafe spreadsheet formula"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.get_json()["incident"]["status"], "Investigating")
        exported = client.get(f"/api/incidents/{iid}/export.csv").get_data(as_text=True)
        self.assertIn("=unsafe spreadsheet formula", exported)
        # A standalone note beginning with '=' must be escaped as a CSV cell.
        client.patch(f"/api/incidents/{iid}", headers=headers, json={"note": "=1+1"})
        self.assertIn("'=1+1", client.get(f"/api/incidents/{iid}/export.csv").get_data(as_text=True))
        self.assertNotIn("sensitive-test", exported)
        self.assertNotIn("192.0.2.55", exported)
        client.patch(f"/api/incidents/{iid}", headers=headers, json={"status": "Resolved"})
        persist_batch([event("nisec.command.input", input="id")])
        self.assertEqual(client.get(f"/api/incidents/{iid}").get_json()["incident"]["status"], "New")

    def test_heartbeat_offline_and_filter(self):
        client = self.signed_in()
        runtime = SensorRuntime("127.0.0.1", 2222)
        runtime.save_health("online")
        self.assertTrue(client.get("/api/live?initial=true").get_json()["sensors"][0]["online"])
        with connect() as conn:
            conn.execute("UPDATE sensors SET heartbeat='2000-01-01T00:00:00+00:00'")
        self.assertFalse(client.get("/api/live?initial=true").get_json()["sensors"][0]["online"])
        self.assertEqual(client.get("/api/live?initial=true&source=absent").get_json()["events"], [])
        self.assertEqual(client.get("/api/live?since=invalid").status_code, 400)

    def test_virtual_shell_containment(self):
        shell = VirtualShell()
        self.assertEqual(shell.execute("whoami")[0], "root\n")
        self.assertEqual(shell.execute("cd /etc")[1], 0)
        self.assertIn("Ubuntu", shell.execute("cat os-release")[0])
        self.assertNotIn("HONEYTRACE", shell.execute("cat ../../config.py")[0])
        self.assertNotEqual(shell.execute("python -c dangerous")[1], 0)
        self.assertNotEqual(shell.execute("curl http://example.invalid")[1], 0)


class SSHTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_ssh_terminal_and_forwarding_denied(self):
        runtime = SensorRuntime("127.0.0.1", 0)
        key = asyncssh.generate_private_key("ssh-ed25519")
        server = await asyncssh.create_server(
            lambda: HoneySSH(runtime), "127.0.0.1", 0, server_host_keys=[key],
            line_editor=False, encoding="utf-8", login_timeout=5,
            agent_forwarding=False, x11_forwarding=False)
        port = server.get_port()
        worker = asyncio.create_task(runtime.worker())
        known = asyncssh.import_known_hosts(
            "[127.0.0.1]:" + str(port) + " " + key.export_public_key().decode())
        try:
            with self.assertRaises(asyncssh.PermissionDenied):
                async with asyncssh.connect("127.0.0.1", port, username="root", password="wrong",
                                            known_hosts=known, client_keys=[]):
                    pass
            async with asyncssh.connect("127.0.0.1", port, username="root", password="integration-decoy",
                                        known_hosts=known, client_keys=[]) as conn:
                result = await conn.run("whoami", timeout=5)
                self.assertEqual(result.stdout, "root\n")
                self.assertEqual((await conn.run("pwd", timeout=5)).stdout, "/root\n")
                async with conn.create_process(term_type="xterm") as terminal:
                    await asyncio.wait_for(terminal.stdout.readuntil("# "), 5)
                    terminal.stdin.write("whoami\r")
                    output = await asyncio.wait_for(terminal.stdout.readuntil("# "), 5)
                    self.assertIn("root", output)
                    terminal.stdin.write("pwd\r\n")
                    output = await asyncio.wait_for(terminal.stdout.readuntil("# "), 5)
                    self.assertIn("/root", output)
                    terminal.stdin.write("exit\r")
                    await asyncio.wait_for(terminal.wait(), 5)
                with self.assertRaises(asyncssh.ChannelOpenError):
                    await conn.open_connection("127.0.0.1", 80)
                with self.assertRaises(asyncssh.ChannelOpenError):
                    await conn.start_sftp_client()
            await asyncio.sleep(.1)
            await asyncio.wait_for(runtime.queue.join(), 10)
            self.assertIsNone(runtime.error)
            with connect(readonly=True) as db:
                self.assertGreater(db.execute("SELECT COUNT(*) FROM events WHERE event_id='nisec.command.input'").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM active_connections").fetchone()[0], 0)
                self.assertGreater(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0)
        finally:
            server.close()
            await server.wait_closed()
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Temporary, localhost-only analyst UI fixture for visual QA."""
import os
from pathlib import Path
import secrets
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
preview_dir = tempfile.TemporaryDirectory(prefix="honeytrace-preview-")
os.environ["NISEC_INSTANCE_DIR"] = preview_dir.name
os.environ["NISEC_DB_PATH"] = str(Path(preview_dir.name) / "preview.db")
os.environ["NISEC_MODEL_DIR"] = str(Path(preview_dir.name) / "model")
os.environ["NISEC_MODEL_PATH"] = str(Path(preview_dir.name) / "missing.joblib")
os.environ["NISEC_SECRET_KEY_PATH"] = str(Path(preview_dir.name) / "credential.key")

from app import app
from db import utc_now
from operations import create_analyst
from ssh_honeypot import persist_batch
from waitress import serve

password = secrets.token_urlsafe(18)
create_analyst("preview", password)
persist_batch([
    dict(eventid="nisec.login.success", timestamp=utc_now(), session="qa-fixture",
         src_ip="192.0.2.1", username="root", password="fixture-only"),
    dict(eventid="nisec.command.input", timestamp=utc_now(), session="qa-fixture",
         src_ip="192.0.2.1", input="whoami"),
])
print("Temporary QA account: preview / " + password, flush=True)
print("Fixture-only dashboard: http://127.0.0.1:5002", flush=True)
serve(app, host="127.0.0.1", port=5002)

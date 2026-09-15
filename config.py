"""Central configuration for the NISec honeypot project."""

from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = Path(os.getenv("NISEC_INSTANCE_DIR", BASE_DIR / "instance"))
MODEL_DIR = Path(os.getenv("NISEC_MODEL_DIR", BASE_DIR / "model"))
DB_PATH = Path(os.getenv("NISEC_DB_PATH", INSTANCE_DIR / "nisec.db"))
MODEL_PATH = Path(os.getenv("NISEC_MODEL_PATH", MODEL_DIR / "behavior_model.joblib"))
SECRET_KEY_PATH = Path(os.getenv("NISEC_SECRET_KEY_PATH", INSTANCE_DIR / "credential.key"))

SESSION_GAP_SECONDS = int(os.getenv("NISEC_SESSION_GAP_SECONDS", "120"))
IMPORT_BATCH_SIZE = int(os.getenv("NISEC_IMPORT_BATCH_SIZE", "2000"))
MAX_INPUT_BYTES = int(os.getenv("NISEC_MAX_INPUT_BYTES", "256"))
MAX_HONEYPOT_WORKERS = int(os.getenv("NISEC_MAX_HONEYPOT_WORKERS", "50"))
MODEL_MIN_CLASS_SAMPLES = int(os.getenv("NISEC_MODEL_MIN_CLASS_SAMPLES", "40"))
MODEL_MAX_CLASS_SAMPLES = int(os.getenv("NISEC_MODEL_MAX_CLASS_SAMPLES", "15000"))

# Analysts need the complete source address for investigation and correlation.
# Privacy masking remains available as an explicit deployment option.
MASK_IPS = os.getenv("NISEC_MASK_IPS", "false").lower() not in {"0", "false", "no"}


def ensure_directories() -> None:
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

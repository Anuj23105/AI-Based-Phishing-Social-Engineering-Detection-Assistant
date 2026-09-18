"""Runtime configuration for the ML service."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ML_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_DIR = Path(os.getenv("PHISHGUARD_ARTIFACTS", ML_ROOT / "artifacts"))
DATA_DIR = Path(os.getenv("PHISHGUARD_DATA", ML_ROOT / "training" / "datasets"))

MESSAGE_MODEL_PATH = ARTIFACT_DIR / "message_model.joblib"
URL_MODEL_PATH = ARTIFACT_DIR / "url_model.joblib"
MESSAGE_METRICS_PATH = ARTIFACT_DIR / "message_metrics.json"
URL_METRICS_PATH = ARTIFACT_DIR / "url_metrics.json"

HOST = os.getenv("ML_HOST", "127.0.0.1")
PORT = int(os.getenv("ML_PORT", "8000"))

# Maximum characters accepted for a single message prediction.
MAX_TEXT_LENGTH = int(os.getenv("ML_MAX_TEXT_LENGTH", "20000"))

# Probability above which the service labels a sample "phishing".
DECISION_THRESHOLD = float(os.getenv("ML_DECISION_THRESHOLD", "0.5"))

# Number of explanation tokens/features returned per prediction.
TOP_FEATURES = int(os.getenv("ML_TOP_FEATURES", "8"))

RANDOM_SEED = int(os.getenv("ML_RANDOM_SEED", "42"))

ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

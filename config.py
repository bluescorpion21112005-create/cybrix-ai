"""
config.py — Application configuration loaded entirely from environment variables.
Never hardcode secrets here. Use .env for local dev, real env vars in production.
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# ── Security ──────────────────────────────────────────────────────────────────
# REQUIRED in production. Will raise at startup if missing and not in dev mode.
_secret = os.environ.get("SECRET_KEY", "")
if not _secret:
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("SECRET_KEY environment variable is required in production.")
    _secret = secrets.token_hex(32)   # safe random key for local dev only

SECRET_KEY = _secret

# ── Database ──────────────────────────────────────────────────────────────────
_db_url = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'siteguard.db'}")
# Heroku / Render ship postgres:// — SQLAlchemy needs postgresql://
if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)
# sqlite:///siteguard.db → absolute path so Flask doesn't redirect to instance/
if _db_url.startswith("sqlite:///") and not _db_url.startswith("sqlite:////"):
    rel = _db_url[len("sqlite:///"):]
    if not os.path.isabs(rel):
        _db_url = f"sqlite:///{BASE_DIR / rel}"

SQLALCHEMY_DATABASE_URI = _db_url
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_pre_ping": True,          # detect stale connections
    "pool_recycle": 300,            # recycle every 5 min
}

# ── File uploads ──────────────────────────────────────────────────────────────
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 8 * 1024 * 1024))  # 8 MB

# ── ML model paths ────────────────────────────────────────────────────────────
MODEL_DIR = str(BASE_DIR / "models")
MODEL_PATH = str(BASE_DIR / "models" / "sql_error_model.joblib")
VECTORIZER_PATH = str(BASE_DIR / "models" / "vectorizer.joblib")

# ── Export paths ──────────────────────────────────────────────────────────────
EXPORT_DIR = str(BASE_DIR / "exports")
EXPORT_HISTORY_CSV = str(BASE_DIR / "exports" / "scan_history.csv")
EXPORT_LAB_CSV = str(BASE_DIR / "exports" / "lab_case_results.csv")
EXPORT_LAST_REPORT_JSON = str(BASE_DIR / "exports" / "last_lab_report.json")
EXPORT_CSV_PATH = EXPORT_HISTORY_CSV
EXPORT_JSON_PATH = EXPORT_LAST_REPORT_JSON

# ── App behaviour ─────────────────────────────────────────────────────────────
MAX_HISTORY = int(os.environ.get("MAX_HISTORY", 25))
PREVIEW_LIMIT = 4000

# ── Email ─────────────────────────────────────────────────────────────────────
MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
MAIL_USE_TLS = True
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
ENABLE_EMAIL = os.environ.get("ENABLE_EMAIL", "false").lower() == "true"

# ── Admin ─────────────────────────────────────────────────────────────────────
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")

# ── Google OAuth ──────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

# ── OpenAI ────────────────────────────────────────────────────────────────────
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

# ── VirusTotal (optional) ─────────────────────────────────────────────────────
VT_API_KEY = os.environ.get("VT_API_KEY", "")

# ── Rate limiting ─────────────────────────────────────────────────────────────
RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200 per day;50 per hour")
RATELIMIT_STORAGE_URL = os.environ.get("REDIS_URL", "memory://")

# ── Ensure directories exist ──────────────────────────────────────────────────
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)

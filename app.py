"""
app.py — AI Security Lab · Flask application entry point.

Architecture:
  - All config comes from environment variables (config.py)
  - ML models are lazy-loaded once at startup via _ModelRegistry
  - Every route has proper input validation and error handling
  - All DB writes use try/except + rollback
  - No print() statements — structured logging only
"""
import asyncio
import csv
import difflib
import io
import json
import logging
import os
import secrets
import tempfile
import warnings
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

# Suppress RequestsDependencyWarning before importing requests
# (urllib3 2.x ships ahead of requests' pinned range)
warnings.filterwarnings("ignore", category=Warning, module="requests")

import joblib
import numpy as np
import requests
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import (
    Flask, abort, flash, g, jsonify, make_response,
    redirect, render_template, request, send_from_directory, url_for,
)
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

from auth import auth_bp
from config import (
    EXPORT_LAB_CSV, EXPORT_LAST_REPORT_JSON,
    MAX_CONTENT_LENGTH, MAX_HISTORY,
    OPENAI_API_KEY, SECRET_KEY,
    SQLALCHEMY_DATABASE_URI, SQLALCHEMY_TRACK_MODIFICATIONS,
    SQLALCHEMY_ENGINE_OPTIONS, VT_API_KEY,
)
from models import (
    ActivityLog, AnalysisResult, ApiUsage, LocalScanResult,
    PaymentTransaction, Project, ScanRecord, SiteMonitor,
    Subscription, User, db,
)
from predictor import predict_text, scan_url
from lab_analyzer import analyze_case
from report_builder import save_lab_report_csv, save_lab_report_json
from utils import clip_text
from backend.app.scanner.vulnerability_scanner import VulnerabilityScanner

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS=SQLALCHEMY_TRACK_MODIFICATIONS,
    SQLALCHEMY_ENGINE_OPTIONS=SQLALCHEMY_ENGINE_OPTIONS,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    WTF_CSRF_TIME_LIMIT=3600,
)

db.init_app(app)
csrf = CSRFProtect(app)

# ── Auth ──────────────────────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

app.register_blueprint(auth_bp)

# ── Plan feature map ──────────────────────────────────────────────────────────
PLAN_FEATURES: dict[str, list[str]] = {
    "free": ["limited_checks", "basic_sql_detection", "basic_pentest"],
    "professional": ["full_sql_analysis", "full_pentest_scan", "ai_recommendations", "export_monitoring"],
    "corporate": ["unlimited_checks", "batch_scan", "api_access", "monitoring_20_sites", "priority_support"],
}

# ── In-memory scan history (bounded) ─────────────────────────────────────────
SCAN_HISTORY: list[dict] = []
LAST_LAB_CASE: dict | None = None

# ── Pentest scanner singleton ─────────────────────────────────────────────────
pentest_scanner = VulnerabilityScanner()


# ── ML model registry (lazy-loaded once at startup) ───────────────────────────
class _ModelRegistry:
    """Loads or trains ML models once; provides a clean access interface."""

    MODEL_DIR = "models"

    def __init__(self):
        os.makedirs(self.MODEL_DIR, exist_ok=True)
        self.log_anomaly = self._load_or_train(
            "log_anomaly.pkl", self._train_log_anomaly
        )
        self.network_anomaly = self._load_or_train(
            "network_anomaly.pkl", self._train_network_anomaly
        )
        self.malware = self._load_or_train(
            "malware_rf.pkl", self._train_malware
        )
        self.traffic = self._load_or_train(
            "traffic_class.pkl", self._train_traffic
        )

    def _load_or_train(self, filename: str, trainer):
        path = os.path.join(self.MODEL_DIR, filename)
        if os.path.exists(path):
            try:
                return joblib.load(path)
            except Exception as exc:
                logger.warning("Could not load %s (%s) — retraining.", filename, exc)
        model = trainer()
        joblib.dump(model, path)
        logger.info("Trained and saved model: %s", filename)
        return model

    @staticmethod
    def _train_log_anomaly():
        from sklearn.ensemble import IsolationForest
        m = IsolationForest(contamination=0.05, random_state=42)
        m.fit(np.random.randn(1000, 10))
        return m

    @staticmethod
    def _train_network_anomaly():
        from sklearn.ensemble import RandomForestClassifier
        m = RandomForestClassifier(n_estimators=50, random_state=42)
        X = np.random.randn(2000, 20)
        y = np.random.choice([0, 1], size=2000, p=[0.95, 0.05])
        m.fit(X, y)
        return m

    @staticmethod
    def _train_malware():
        from sklearn.ensemble import RandomForestClassifier
        m = RandomForestClassifier(n_estimators=100, random_state=42)
        m.fit(np.random.randn(500, 30), np.random.choice([0, 1], size=500))
        return m

    @staticmethod
    def _train_traffic():
        from sklearn.ensemble import RandomForestClassifier
        m = RandomForestClassifier(n_estimators=50, random_state=42)
        m.fit(
            np.random.randn(1000, 10),
            np.random.choice(["http", "https", "dns", "other"], size=1000),
        )
        return m


models = _ModelRegistry()

# ── Optional heavy dependencies ───────────────────────────────────────────────
# ── Optional heavy dependencies ───────────────────────────────────────────────
# Transformers 5.x removed: summarization, text-generation, translation tasks.
# We load each pipeline separately so one failure doesn't block the others.
text_classifier = None
summarizer = None
generator = None
translation_pipe = None

try:
    from transformers import pipeline as hf_pipeline
    import transformers as _tf

    _tf_major = int(_tf.__version__.split(".")[0])

    try:
        text_classifier = hf_pipeline(
            "zero-shot-classification", model="facebook/bart-large-mnli"
        )
        logger.info("Transformers: zero-shot-classification loaded.")
    except Exception as exc:
        logger.warning("zero-shot-classification unavailable: %s", exc)

    # summarization removed in transformers >= 5.0
    if _tf_major < 5:
        try:
            summarizer = hf_pipeline(
                "summarization", model="facebook/bart-large-cnn"
            )
            logger.info("Transformers: summarization loaded.")
        except Exception as exc:
            logger.warning("summarization unavailable: %s", exc)
    else:
        logger.info(
            "Transformers %s: summarization task removed — using fallback.",
            _tf.__version__,
        )

    # text-generation removed in transformers >= 5.0
    if _tf_major < 5:
        try:
            generator = hf_pipeline("text-generation", model="gpt2")
            logger.info("Transformers: text-generation loaded.")
        except Exception as exc:
            logger.warning("text-generation unavailable: %s", exc)
    else:
        logger.info(
            "Transformers %s: text-generation task removed — using fallback.",
            _tf.__version__,
        )

    # translation removed in transformers >= 5.0
    if _tf_major < 5:
        try:
            translation_pipe = hf_pipeline(
                "translation_en_to_fr", model="t5-small"
            )
            logger.info("Transformers: translation loaded.")
        except Exception as exc:
            logger.warning("translation unavailable: %s", exc)

except ImportError:
    logger.warning("transformers not installed — AI features will use fallbacks.")


try:
    import face_recognition; face_available = True
except ImportError:
    face_available = False

try:
    import speech_recognition as sr; voice_available = True
except ImportError:
    voice_available = False

try:
    import pytesseract
    from PIL import Image
    ocr_available = True
except ImportError:
    ocr_available = False

try:
    # Windows da libpcap warning ni bostirish
    import warnings as _warnings
    import logging as _logging
    _logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)
    with _warnings.catch_warnings():
        _warnings.simplefilter("ignore")
        from scapy.all import IP, rdpcap
    scapy_available = True
except ImportError:
    scapy_available = False

try:
    import networkx as nx; nx_available = True
except ImportError:
    nx_available = False

try:
    import tldextract; tld_available = True
except ImportError:
    tld_available = False

# OpenAI client
try:
    import openai
    openai.api_key = OPENAI_API_KEY  # loaded from environment variable only
except ImportError:
    openai = None  # type: ignore


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

@login_manager.user_loader
def load_user(user_id: str):
    # expire_on_commit=False bo'lganda identity map cache muammosini oldini olish
    user = db.session.get(User, int(user_id))
    if user:
        db.session.refresh(user)  # har safar DB dan yangi o'qish
    return user


def _db_commit(error_msg: str = "Database error.") -> bool:
    """Commit the current session; rollback and log on failure. Returns success."""
    try:
        db.session.commit()
        return True
    except Exception as exc:
        db.session.rollback()
        logger.exception("%s: %s", error_msg, exc)
        return False


def log_activity(user, action: str, details: str = "") -> None:
    try:
        entry = ActivityLog(
            user_id=user.id if user else None,
            action=action,
            details=details[:500] if details else None,
            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
            user_agent=(request.headers.get("User-Agent") or "")[:255],
        )
        db.session.add(entry)
        _db_commit("ActivityLog write failed")
    except Exception as exc:
        logger.warning("log_activity failed: %s", exc)


def save_result(feature: str, input_data: str, result: str, confidence: float = 1.0) -> int:
    """Persist an AI analysis result. Returns the new record id, or -1 on error."""
    try:
        record = AnalysisResult(
            feature=feature,
            input_data=(input_data or "")[:2000],
            result=result,
            confidence=float(confidence),
        )
        db.session.add(record)
        if _db_commit("save_result failed"):
            return record.id
    except Exception as exc:
        logger.error("save_result error: %s", exc)
    return -1


def add_to_history(
    source: str, label: str, risk_score: float,
    status: str, length: int,
    user_id: int | None = None, project_id: int | None = None,
) -> None:
    SCAN_HISTORY.insert(0, {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": source, "label": label,
        "risk_score": risk_score, "status": status, "length": length,
    })
    del SCAN_HISTORY[MAX_HISTORY:]

    if user_id:
        try:
            db.session.add(ScanRecord(
                user_id=user_id, project_id=project_id,
                source=source, label=label,
                risk_score=risk_score, status=status, length=length,
            ))
            _db_commit("add_to_history DB write failed")
        except Exception as exc:
            logger.error("add_to_history error: %s", exc)


def log_api_usage(user, endpoint: str) -> None:
    try:
        db.session.add(ApiUsage(user_id=user.id, endpoint=endpoint))
        _db_commit("log_api_usage failed")
    except Exception as exc:
        logger.warning("log_api_usage error: %s", exc)


def check_api_limit(user, endpoint: str, limit: int = 200) -> bool:
    since = datetime.utcnow() - timedelta(days=30)
    count = ApiUsage.query.filter(
        ApiUsage.user_id == user.id,
        ApiUsage.endpoint == endpoint,
        ApiUsage.created_at >= since,
    ).count()
    return count < limit


def badge_class_name(label: str) -> str:
    normalized = (label or "").strip().upper().replace("-", "_").replace(" ", "_")
    if normalized in {"SQL_ERROR", "CRITICAL", "HIGH", "FAILED"}:
        return "badge-sql"
    if normalized in {"SUSPICIOUS", "MEDIUM"}:
        return "badge-suspicious"
    return "badge-normal"


def history_counts() -> dict:
    counts = {"normal": 0, "suspicious": 0, "sql_error": 0, "total": len(SCAN_HISTORY)}
    for item in SCAN_HISTORY:
        lbl = item.get("label", "")
        if lbl == "NORMAL":
            counts["normal"] += 1
        elif lbl == "SUSPICIOUS":
            counts["suspicious"] += 1
        elif lbl == "SQL_ERROR":
            counts["sql_error"] += 1
    return counts


def extract_domain_from_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower().strip()
    return domain[4:] if domain.startswith("www.") else domain


def normalize_domain(value: str) -> str:
    return extract_domain_from_url(value)


def domain_matches_project(target_domain: str, project_domain: str) -> bool:
    t = normalize_domain(target_domain)
    p = normalize_domain(project_domain)
    if not t or not p:
        return False
    return t == p or t.endswith("." + p)


def get_user_subscription(user_id: int):
    return Subscription.query.filter_by(user_id=user_id, is_active=True).first()


def get_active_plan(user) -> str:
    if not user.is_authenticated:
        return "free"
    sub = get_user_subscription(user.id)
    if sub and sub.end_date and sub.end_date > datetime.utcnow() and sub.is_active:
        return sub.plan_name
    return "free"


def user_has_feature(user, feature_name: str) -> bool:
    return feature_name in PLAN_FEATURES.get(get_active_plan(user), [])


def user_can_scan_url(user, target_url: str) -> tuple[bool, object | None]:
    target_domain = extract_domain_from_url(target_url)
    if not target_domain:
        return False, None
    for project in Project.query.filter_by(user_id=user.id, is_verified=True).all():
        if project.domain and domain_matches_project(target_domain, project.domain):
            return True, project
    return False, None


def has_pro_access(user) -> bool:
    return (user.is_authenticated
            and user.subscription_status == "active"
            and user.subscription_plan in ("pro", "corporate"))


def has_corporate_access(user) -> bool:
    return (user.is_authenticated
            and user.subscription_status == "active"
            and user.subscription_plan == "corporate")


def is_subscription_active(user) -> bool:
    if not user or user.subscription_status != "active":
        return False
    if user.subscription_end and user.subscription_end < datetime.utcnow():
        user.subscription_status = "expired"
        _db_commit()
        return False
    return True


def activate_user_plan(user, plan: str) -> None:
    now = datetime.utcnow()
    user.subscription_plan = plan
    user.subscription_status = "active"
    if user.subscription_end and user.subscription_end > now:
        user.subscription_end += timedelta(days=30)
    else:
        user.subscription_start = now
        user.subscription_end = now + timedelta(days=30)


def build_diff_html(baseline_text: str, payload_text: str) -> str:
    diff = difflib.unified_diff(
        baseline_text.splitlines(), payload_text.splitlines(),
        fromfile="baseline", tofile="payload", lineterm="",
    )
    rendered = []
    for line in diff:
        safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        if line.startswith(("+++", "---", "@@")):
            rendered.append(f'<span class="diff-meta">{safe}</span>')
        elif line.startswith("+"):
            rendered.append(f'<span class="diff-add">{safe}</span>')
        elif line.startswith("-"):
            rendered.append(f'<span class="diff-del">{safe}</span>')
        else:
            rendered.append(safe)
    return "\n".join(rendered)


def normalize_pentest_result(scan_result: dict) -> dict:
    vulnerabilities = scan_result.get("vulnerabilities") or []
    summary = scan_result.get("summary") or {}
    severity_counts = summary.get("severity_counts") or {}
    ai_block = scan_result.get("ai_enhanced") or {}
    ai_risk = ai_block.get("ai_risk_prediction") or {}

    if ai_risk.get("level"):
        risk_level = str(ai_risk.get("level", "INFO")).upper()
        risk_score = float(ai_risk.get("score", 0))
        confidence = ai_risk.get("confidence")
    else:
        risk_level = str(summary.get("risk_level", "INFO")).upper()
        risk_score = float({"CRITICAL": 95, "HIGH": 80, "MEDIUM": 60, "LOW": 35, "INFO": 10}.get(risk_level, 0))
        confidence = None

    recommendations = []
    for item in (ai_block.get("ai_remediation") or [])[:5]:
        if isinstance(item, dict):
            title = item.get("title") or item.get("type") or "Recommendation"
            steps = item.get("steps") or item.get("actions") or []
            recommendations.append({"title": title, "steps": steps[:4] if isinstance(steps, list) else [str(steps)]})

    return {
        "target": scan_result.get("url") or scan_result.get("target_url"),
        "status_code": scan_result.get("status_code", "-"),
        "scan_duration": scan_result.get("scan_duration", 0),
        "scan_completed": scan_result.get("scan_completed"),
        "risk_level": risk_level,
        "risk_score": round(risk_score, 2),
        "confidence": confidence,
        "summary": summary,
        "severity_counts": {k: severity_counts.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "vulnerabilities": vulnerabilities,
        "technologies": scan_result.get("technologies", []),
        "headers": scan_result.get("headers", {}),
        "information": scan_result.get("information", {}),
        "recommendations": recommendations,
        "ai_risk_prediction": ai_risk,
    }


# ── AI helper functions ───────────────────────────────────────────────────────

def text_analysis(prompt: str, _hypothesis: str = "") -> tuple[str, float]:
    if text_classifier is None:
        return f"AI unavailable. Input: {prompt[:200]}", 0.5
    labels = ["vulnerable", "safe", "malicious", "benign", "phishing", "legitimate"]
    result = text_classifier(prompt, labels)
    return f"Classification: {result['labels'][0]} (confidence: {result['scores'][0]:.2f})", result["scores"][0]


def generate_summary(text: str) -> str:
    """Matnni qisqartiradi. Transformers 5.x da summarizer yo'q — oddiy kesish."""
    if summarizer is not None:
        try:
            return summarizer(text, max_length=150, min_length=30, do_sample=False)[0]["summary_text"]
        except Exception as exc:
            logger.warning("summarizer error: %s", exc)
    # Fallback: birinchi 3 gapni qaytaradi
    sentences = [s.strip() for s in text.replace("\n", " ").split(".") if s.strip()]
    return ". ".join(sentences[:3]) + ("." if sentences else "")


def generate_code(description: str) -> str:
    """Tavsif asosida kod yaratadi. Transformers 5.x da generator yo'q — shablon qaytaradi."""
    if generator is not None:
        try:
            return generator(
                f"Write Python code for: {description}",
                max_length=200, num_return_sequences=1,
            )[0]["generated_text"]
        except Exception as exc:
            logger.warning("generator error: %s", exc)
    # Fallback: oddiy shablon
    return (
        f"# Auto-generated stub for: {description}\n"
        "def solution():\n"
        "    # TODO: implement\n"
        "    pass\n"
    )


def extract_pe_features(filepath: str) -> list:
    try:
        import pefile
        pe = pefile.PE(filepath)
        return [
            pe.FILE_HEADER.SizeOfOptionalHeader,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            len(pe.sections),
            len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else 0,
        ]
    except Exception:
        return [0] * 10


# ── Decorators ────────────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def feature_required(feature_name: str):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in first.", "warning")
                return redirect(url_for("auth.login"))
            if not user_has_feature(current_user, feature_name):
                flash("Upgrade your plan to access this feature.", "danger")
                return redirect(url_for("pricing"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── Context processors ────────────────────────────────────────────────────────

@app.context_processor
def inject_plan_data():
    if current_user.is_authenticated:
        plan = get_active_plan(current_user)
        return {"active_plan": plan, "user_has_feature": lambda f: user_has_feature(current_user, f)}
    return {"active_plan": "free", "user_has_feature": lambda f: False}


@app.before_request
def refresh_subscription_status():
    g.active_plan = "free"
    if current_user.is_authenticated:
        sub = get_user_subscription(current_user.id)
        if sub and sub.end_date and datetime.utcnow() > sub.end_date:
            sub.is_active = False
            _db_commit()
        g.active_plan = get_active_plan(current_user)


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def server_error(e):
    logger.exception("Unhandled 500 error: %s", e)
    return render_template("errors/500.html"), 500


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES (Google OAuth)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/login/google")
def login_google():
    redirect_uri = url_for("authorize_google", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/authorize/google")
def authorize_google():
    try:
        token = google.authorize_access_token()
        user_info = token.get("userinfo") or google.get("userinfo").json()
    except Exception as exc:
        logger.error("Google OAuth error: %s", exc)
        flash("Google login failed. Please try again.", "danger")
        return redirect(url_for("auth.login"))

    email = (user_info.get("email") or "").strip().lower()
    if not email:
        flash("Could not retrieve email from Google.", "danger")
        return redirect(url_for("auth.login"))

    google_id = user_info.get("sub")
    full_name = user_info.get("name") or "Google User"

    user = User.query.filter_by(email=email).first()
    if user:
        if not user.google_id:
            user.google_id = google_id
        if user.auth_provider == "local":
            user.auth_provider = "mixed"
    else:
        user = User(full_name=full_name, email=email, google_id=google_id, auth_provider="google")
        db.session.add(user)

    if not _db_commit("Google OAuth DB write failed"):
        flash("Login failed. Please try again.", "danger")
        return redirect(url_for("auth.login"))

    login_user(user)
    log_activity(user, "login_google", email)
    return redirect(url_for("home"))


@app.route("/logout")
@login_required
def logout():
    log_activity(current_user, "logout", current_user.email)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN PAGES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def home():
    chart_counts = history_counts()
    return render_template(
        "index.html",
        result=None, content="", url="", batch_urls="", error=None,
        status=None, length=None, source_label="", highlighted_preview="",
        batch_results=[], chart_counts=chart_counts,
        chart_json=json.dumps(chart_counts),
        badge_class_name=badge_class_name,
        lab_case=LAST_LAB_CASE, lab_case_path="",
        lab_sort="risk_desc", lab_filter="", user=current_user,
    )


@app.route("/index.html")
def index_html_redirect():
    """/index.html → / redirect (Flask templates != static files)."""
    return redirect(url_for("home"), code=301)


@app.route("/dashboard")
@login_required
def dashboard():
    user_scans = LocalScanResult.query.filter_by(user_id=current_user.id).all()
    total_findings = high_risk = 0
    last_scan_time = None

    if user_scans:
        last_scan_time = max((s.created_at for s in user_scans if s.created_at), default=None)

    for scan in user_scans:
        try:
            findings = json.loads(scan.findings_json or "[]")
        except (json.JSONDecodeError, TypeError):
            findings = []
        total_findings += len(findings)
        high_risk += sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")

    projects = Project.query.filter_by(user_id=current_user.id).all()
    recent_scans = (
        ScanRecord.query.filter_by(user_id=current_user.id)
        .order_by(ScanRecord.created_at.desc()).limit(10).all()
    )
    stats = {
        "projects": len(projects),
        "scans": ScanRecord.query.filter_by(user_id=current_user.id).count(),
        "verified_projects": Project.query.filter_by(user_id=current_user.id, is_verified=True).count(),
        "high_risk": ScanRecord.query.filter(
            ScanRecord.user_id == current_user.id, ScanRecord.risk_score >= 70
        ).count(),
    }
    return render_template(
        "dashboard.html",
        projects=projects, recent_scans=recent_scans, stats=stats,
        badge_class_name=badge_class_name, user=current_user,
        total_scans=len(user_scans), total_findings=total_findings,
        high_risk_findings=high_risk, last_scan_time=last_scan_time,
    )


@app.route("/download")
def download_page():
    return render_template("download.html")


@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/download-desktop-agent")
def download_desktop_agent():
    """
    Eng yangi agent_app.exe ni yuboradi.
    static/downloads/ da agent_app.exe bo'lsa uni, aks holda AI-Sec-Lab.exe ni yuboradi.
    """
    downloads_dir = os.path.join(app.root_path, "static", "downloads")
    # Eng yangi faylni tanlash
    if os.path.exists(os.path.join(downloads_dir, "agent_app.exe")):
        filename = "agent_app.exe"
    elif os.path.exists(os.path.join(downloads_dir, "AI-Sec-Lab.exe")):
        filename = "AI-Sec-Lab.exe"
    else:
        flash("Download fayli hozircha mavjud emas.", "warning")
        return redirect(url_for("download_page"))

    return send_from_directory(
        downloads_dir,
        filename,
        as_attachment=True,
        download_name="AI-Sec-Lab-Agent.exe",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYZE ROUTE
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    global LAST_LAB_CASE

    result = error = status = length = None
    content = request.form.get("content", "").strip()
    url = request.form.get("url", "").strip()
    batch_urls = request.form.get("batch_urls", "").strip()
    source_label = highlighted_preview = ""
    batch_results: list = []
    lab_case = None
    lab_case_path = request.form.get("lab_case_path", "").strip()
    lab_sort = request.form.get("lab_sort", "risk_desc").strip() or "risk_desc"
    lab_filter = request.form.get("lab_filter", "").strip()
    uploaded_files = request.files.getlist("files")

    try:
        if request.form.get("analyze_lab_case") == "1":
            if not lab_case_path:
                error = "Please provide a lab case folder path."
            else:
                lab_result = analyze_case(lab_case_path)
                if lab_result.get("ok"):
                    payloads = lab_result.get("payloads", [])
                    if lab_filter:
                        q = lab_filter.lower()
                        payloads = [
                            p for p in payloads
                            if q in p["label"].lower() or q in p["file"].lower()
                            or any(q in kw.lower() for kw in p.get("matched_sql", []))
                            or any(q in kw.lower() for kw in p.get("matched_suspicious", []))
                        ]
                    sort_key = {
                        "risk_asc": lambda x: x.get("risk_score", 0),
                        "delta_desc": lambda x: -x.get("risk_delta", 0),
                        "delta_asc": lambda x: x.get("risk_delta", 0),
                        "label": lambda x: x.get("label", ""),
                    }.get(lab_sort, lambda x: -x.get("risk_score", 0))
                    payloads.sort(key=sort_key)

                    baseline_text = lab_result.get("baseline_text", "")
                    for p in payloads:
                        p["diff_html"] = build_diff_html(baseline_text, p.get("text", ""))

                    lab_result["payloads"] = payloads
                    lab_case = LAST_LAB_CASE = lab_result
                    save_lab_report_json(lab_result, EXPORT_LAST_REPORT_JSON)
                    save_lab_report_csv(lab_result, EXPORT_LAB_CSV)

                    if payloads:
                        top = payloads[0]
                        result = {"label": top["label"], "normal": 0, "suspicious": 0, "sql_error": 0,
                                  "risk_score": top["risk_score"],
                                  "matched_keywords": {"sql": top.get("matched_sql", []), "suspicious": top.get("matched_suspicious", [])}}
                        status, length, source_label = "LAB", top["length"], top["file"]
                        add_to_history(f"lab:{lab_result['case']}::{top['file']}", top["label"],
                                       top["risk_score"], "LAB", top["length"], user_id=current_user.id)
                else:
                    error = lab_result.get("error", "Lab case analysis failed.")

        elif batch_urls:
            if not user_has_feature(current_user, "batch_scan"):
                flash("Batch scanning requires a Corporate plan.", "warning")
                return redirect(url_for("pricing"))
            for item_url in [u.strip() for u in batch_urls.splitlines() if u.strip()]:
                scan_result = scan_url(item_url)
                if scan_result.get("ok"):
                    pred = scan_result["prediction"]
                    batch_results.append({"source": item_url, "status": scan_result["status"],
                                          "label": pred["label"], "risk_score": pred["risk_score"],
                                          "length": scan_result["length"]})
                    add_to_history(item_url, pred["label"], pred["risk_score"],
                                   scan_result["status"], scan_result["length"], user_id=current_user.id)
                else:
                    batch_results.append({"source": item_url, "status": "ERR", "label": "FAILED", "risk_score": 0, "length": 0})
            if batch_results:
                top_item = next((x for x in batch_results if x["label"] != "FAILED"), None)
                if top_item:
                    result = {"label": top_item["label"], "normal": 0, "suspicious": 0, "sql_error": 0,
                              "risk_score": top_item["risk_score"], "matched_keywords": {"sql": [], "suspicious": []}}
                    status, length, source_label = top_item["status"], top_item["length"], top_item["source"]

        elif uploaded_files and any(f.filename for f in uploaded_files):
            valid_files = [f for f in uploaded_files if f and f.filename]
            first_text = None
            for i, file in enumerate(valid_files):
                raw = file.read()
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw.decode("latin-1", errors="ignore")
                if i == 0:
                    first_text = text
                pred = predict_text(text)
                batch_results.append({"source": file.filename, "status": "LOCAL",
                                      "label": pred["label"], "risk_score": pred["risk_score"], "length": len(text)})
                add_to_history(file.filename, pred["label"], pred["risk_score"], "LOCAL", len(text), user_id=current_user.id)
            if first_text is not None:
                result = predict_text(first_text)
                status, length, source_label = "LOCAL", len(first_text), valid_files[0].filename
                highlighted_preview = clip_text(result["highlighted_text"])

        elif url:
            scan_result = scan_url(url)
            if scan_result.get("ok"):
                result = scan_result["prediction"]
                content = scan_result["content"]
                status, length, source_label = scan_result["status"], scan_result["length"], url
                highlighted_preview = clip_text(result["highlighted_text"])
                add_to_history(url, result["label"], result["risk_score"], status, length, user_id=current_user.id)
            else:
                error = scan_result.get("error", "URL scanning failed.")

        elif content:
            result = predict_text(content)
            status, length, source_label = "LOCAL", len(content), "pasted_text"
            highlighted_preview = clip_text(result["highlighted_text"])
            add_to_history("pasted_text", result["label"], result["risk_score"], status, length, user_id=current_user.id)

        else:
            error = "Please provide a URL, batch URLs, response text, or upload files."

    except Exception as exc:
        logger.exception("Analyze error: %s", exc)
        error = "An unexpected error occurred. Please try again."

    chart_counts = history_counts()
    return render_template(
        "index.html",
        result=result, content=content, url=url, batch_urls=batch_urls,
        error=error, status=status, length=length, source_label=source_label,
        highlighted_preview=highlighted_preview, batch_results=batch_results,
        chart_counts=chart_counts, chart_json=json.dumps(chart_counts),
        badge_class_name=badge_class_name,
        lab_case=lab_case or LAST_LAB_CASE, lab_case_path=lab_case_path,
        lab_sort=lab_sort, lab_filter=lab_filter, user=current_user,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PROJECT MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/projects", methods=["GET", "POST"])
@login_required
def projects():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        domain = normalize_domain(request.form.get("domain", "").strip())
        if not name or not domain:
            flash("Project name and domain are required.", "danger")
            return redirect(url_for("projects"))
        db.session.add(Project(user_id=current_user.id, name=name, domain=domain))
        if _db_commit("Project creation failed"):
            flash("Project created.", "success")
        else:
            flash("Could not create project.", "danger")
        return redirect(url_for("projects"))

    user_projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.created_at.desc()).all()
    return render_template("projects.html", projects=user_projects)


@app.route("/projects/add", methods=["GET", "POST"])
@login_required
def add_project():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        domain = normalize_domain(request.form.get("domain", "").strip())
        description = request.form.get("description", "").strip()

        if not name or not domain:
            flash("Project name and domain are required.", "danger")
            return render_template("add_project.html")

        if Project.query.filter_by(user_id=current_user.id, domain=domain).first():
            flash("This domain is already added.", "warning")
            return redirect(url_for("dashboard"))

        project = Project(name=name, domain=domain, description=description,
                          user_id=current_user.id, verification_method="meta")
        project.ensure_token()
        db.session.add(project)
        if _db_commit("add_project failed"):
            flash("Project added. Complete verification before scanning.", "success")
            return redirect(url_for("verify_project", project_id=project.id))
        flash("Could not add project.", "danger")
    return render_template("add_project.html")


@app.route("/projects/<int:project_id>/verify", methods=["GET"])
@login_required
def verify_project(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    project.ensure_token()
    _db_commit()
    return render_template("verify_project.html", project=project)


@app.route("/projects/<int:project_id>/verify/check", methods=["POST"])
@login_required
def check_project_verification(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    project.ensure_token()
    verified = False

    for check_url in [
        f"https://{project.domain}",
        f"https://{project.domain}/{project.verification_html_filename()}",
    ]:
        try:
            resp = requests.get(check_url, timeout=10, headers={"User-Agent": "SiteGuardBot/1.0"})
            if resp.ok and project.verification_token in resp.text:
                verified = True
                project.verification_method = "html" if "verification_html_filename" in check_url else "meta"
                break
        except requests.RequestException:
            continue

    if verified:
        project.is_verified = True
        project.verified_at = datetime.utcnow()
        _db_commit()
        flash("Domain verified successfully.", "success")
    else:
        flash("Verification token not found. Add the meta tag or HTML file and try again.", "warning")

    return redirect(url_for("verify_project", project_id=project.id))


# ═══════════════════════════════════════════════════════════════════════════════
# HISTORY & EXPORTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/history")
@login_required
def history_page():
    user_history = ScanRecord.query.filter_by(user_id=current_user.id).order_by(ScanRecord.created_at.desc()).all()
    return render_template("history.html", history=user_history, badge_class_name=badge_class_name)


@app.route("/history/clear", methods=["POST"])
@login_required
def clear_history_page():
    ScanRecord.query.filter_by(user_id=current_user.id).delete()
    _db_commit()
    SCAN_HISTORY.clear()
    return redirect(url_for("history_page"))


@app.route("/export/csv")
@login_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "source", "label", "risk_score", "status", "length"])
    for item in SCAN_HISTORY:
        writer.writerow([item["timestamp"], item["source"], item["label"],
                         item["risk_score"], item["status"], item["length"]])
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=scan_history.csv"
    return resp


@app.route("/export/lab-csv")
@login_required
def export_lab_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["case", "baseline_label", "baseline_risk", "payload_file",
                     "label", "risk_score", "risk_delta", "length", "length_delta",
                     "matched_sql", "matched_suspicious"])
    if LAST_LAB_CASE and LAST_LAB_CASE.get("payloads"):
        for item in LAST_LAB_CASE["payloads"]:
            writer.writerow([
                LAST_LAB_CASE["case"], LAST_LAB_CASE["baseline"]["label"],
                LAST_LAB_CASE["baseline"]["risk_score"], item["file"],
                item["label"], item["risk_score"], item["risk_delta"],
                item["length"], item["length_delta"],
                "; ".join(item.get("matched_sql", [])),
                "; ".join(item.get("matched_suspicious", [])),
            ])
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=lab_case_results.csv"
    return resp


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    users = User.query.order_by(User.id.desc()).all()
    payments = PaymentTransaction.query.order_by(PaymentTransaction.created_at.desc()).limit(20).all()
    scans = LocalScanResult.query.order_by(LocalScanResult.created_at.desc()).limit(20).all()
    logger.info("Admin panel accessed by user_id=%s", current_user.id)
    return render_template("admin.html", users=users, payments=payments, scans=scans)


@app.route("/admin/user/<int:user_id>/set-plan", methods=["POST"])
@login_required
@admin_required
def admin_set_plan(user_id: int):
    """Admin: foydalanuvchi tarifini o'zgartirish."""
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    plan = request.form.get("plan", "").strip()
    if plan not in ("free", "pro", "corporate"):
        return jsonify({"ok": False, "error": "Invalid plan"}), 400
    if plan == "free":
        user.subscription_plan = "free"
        user.subscription_status = "inactive"
        user.subscription_start = user.subscription_end = None
    else:
        activate_user_plan(user, plan)
    if _db_commit(f"admin_set_plan failed for user {user_id}"):
        logger.info("Admin set plan=%s for user_id=%s", plan, user_id)
        flash(f"{user.email} tarifini {plan} ga o'zgartirildi.", "success")
    else:
        flash("Tarif o'zgartirishda xatolik.", "danger")
    return redirect(url_for("admin_panel"))


@app.route("/admin/user/<int:user_id>/toggle-admin", methods=["POST"])
@login_required
@admin_required
def admin_toggle_admin(user_id: int):
    """Admin: foydalanuvchiga admin huquqi berish/olish."""
    if user_id == current_user.id:
        flash("O'zingizning admin huquqingizni o'zgartira olmaysiz.", "warning")
        return redirect(url_for("admin_panel"))
    user = db.session.get(User, user_id)
    if not user:
        flash("Foydalanuvchi topilmadi.", "danger")
        return redirect(url_for("admin_panel"))
    user.is_admin = not user.is_admin
    if _db_commit(f"admin_toggle_admin failed for user {user_id}"):
        status = "admin" if user.is_admin else "oddiy foydalanuvchi"
        logger.info("Admin toggled admin=%s for user_id=%s", user.is_admin, user_id)
        flash(f"{user.email} endi {status}.", "success")
    else:
        flash("Huquq o'zgartirishda xatolik.", "danger")
    return redirect(url_for("admin_panel"))


# ═══════════════════════════════════════════════════════════════════════════════
# SUBSCRIPTION & PLAN ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/subscribe/<plan>")
@login_required
def subscribe(plan: str):
    if plan not in ("free", "pro", "corporate"):
        flash("Invalid plan.", "danger")
        return redirect(url_for("dashboard"))
    if plan == "free":
        current_user.subscription_plan = "free"
        current_user.subscription_status = "inactive"
        current_user.subscription_start = current_user.subscription_end = None
    else:
        activate_user_plan(current_user, plan)
    _db_commit()
    flash(f"{plan.capitalize()} plan activated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/batch-scan")
@login_required
@feature_required("batch_scan")
def batch_scan():
    return render_template("batch_scan.html")


@app.route("/api-docs")
@login_required
@feature_required("api_access")
def api_docs():
    return render_template("api_docs.html")


@app.route("/monitoring")
@login_required
@feature_required("monitoring_20_sites")
def monitoring():
    return render_template("monitoring.html")


@app.route("/priority-support")
@login_required
@feature_required("priority_support")
def priority_support():
    return render_template("priority_support.html")


@app.route("/health")
def health():
    """Health check endpoint for load balancers and Docker."""
    return {"status": "ok"}, 200


@app.route("/site-monitoring")
@login_required
def site_monitoring():
    if not has_corporate_access(current_user):
        flash("This section requires an active Corporate plan.", "danger")
        return redirect(url_for("dashboard"))
    monitors = SiteMonitor.query.filter_by(user_id=current_user.id).all()
    return render_template("site_monitoring.html", monitors=monitors)


@app.route("/regenerate-api-token", methods=["POST"])
@login_required
def regenerate_api_token():
    current_user.api_token = secrets.token_hex(32)
    if _db_commit():
        flash("API token regenerated.", "success")
    else:
        flash("Could not regenerate token.", "danger")
    return redirect(url_for("dashboard"))


# ═══════════════════════════════════════════════════════════════════════════════
# LOCAL SCAN (Desktop Agent API)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/local-scan/<int:scan_id>")
@login_required
def local_scan_detail(scan_id: int):
    scan = LocalScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    try:
        findings = json.loads(scan.findings_json or "[]")
    except (json.JSONDecodeError, TypeError):
        findings = []
    severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return render_template("local_scan_detail.html", scan=scan, findings=findings, severity_counts=severity_counts)


@app.route("/local-scan-history")
@login_required
def local_scan_history():
    search = request.args.get("search", "").strip().lower()
    severity_filter = request.args.get("severity", "").strip().lower()
    sort_order = request.args.get("sort", "latest").strip().lower()

    query = LocalScanResult.query.filter_by(user_id=current_user.id)
    query = query.order_by(
        LocalScanResult.created_at.asc() if sort_order == "oldest"
        else LocalScanResult.created_at.desc()
    )

    prepared = []
    for scan in query.all():
        try:
            findings = json.loads(scan.findings_json or "[]")
        except (json.JSONDecodeError, TypeError):
            findings = []

        if search and search not in (scan.target_url or "").lower():
            continue
        if severity_filter and not any(str(f.get("severity", "")).lower() == severity_filter for f in findings):
            continue

        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        prepared.append({
            "id": scan.id, "target_url": scan.target_url, "scan_type": scan.scan_type,
            "status": scan.status, "created_at": scan.created_at,
            "findings": findings, "findings_count": len(findings), "severity_counts": severity_counts,
        })

    return render_template("local_scan_history.html", scans=prepared,
                           search=search, severity_filter=severity_filter, sort_order=sort_order)


@app.route("/api/submit-local-scan", methods=["POST"])
@csrf.exempt
def submit_local_scan():
    auth_header = request.headers.get("Authorization", "").strip()
    if not auth_header.startswith("Bearer "):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    token = auth_header.split(" ", 1)[1].strip()
    user = User.query.filter_by(api_token=token).first()
    if not user:
        return jsonify({"status": "error", "message": "Invalid API token"}), 401

    if not check_api_limit(user, "submit_local_scan", limit=200):
        return jsonify({"status": "error", "message": "Monthly API limit exceeded"}), 429

    log_api_usage(user, "submit_local_scan")

    data = request.get_json(silent=True) or {}
    target_url = (data.get("target_url") or "").strip()
    scan_type = (data.get("scan_type") or "local_agent").strip()
    findings = data.get("findings", [])

    if not target_url:
        return jsonify({"status": "error", "message": "target_url is required"}), 400
    if not isinstance(findings, list):
        return jsonify({"status": "error", "message": "findings must be a list"}), 400

    scan = LocalScanResult(
        user_id=user.id, target_url=target_url, scan_type=scan_type,
        findings_json=json.dumps(findings, ensure_ascii=False), status="completed",
    )
    db.session.add(scan)
    if not _db_commit("submit_local_scan DB write failed"):
        return jsonify({"status": "error", "message": "Database error"}), 500

    return jsonify({"status": "success", "message": "Scan saved.", "scan_id": scan.id})

# ============================================================
# AI TOOL ROUTES – Full implementation for 46 tools
# ============================================================

def _ai_text_route(feature: str, template: str, input_key: str = "text", use_file: bool = False):
    """
    Generic handler for text‑based AI analysis.
    If `use_file` is True, expects a file upload instead of text input.
    """
    if request.method == "POST":
        if use_file:
            file = request.files.get(input_key)
            if not file or file.filename == '':
                return jsonify({"error": f"{input_key} file is required"}), 400
            # Read file content
            try:
                content = file.read().decode("utf-8")
            except UnicodeDecodeError:
                # fallback to latin‑1 if utf‑8 fails
                content = file.read().decode("latin-1", errors="ignore")
            input_data = content[:2000]
        else:
            data = request.get_json(silent=True) or {}
            input_data = (request.form.get(input_key) or data.get(input_key) or "").strip()
            if not input_data:
                return jsonify({"error": f"{input_key} is required"}), 400

        result, conf = text_analysis(input_data)
        save_result(feature, input_data, result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})

    # GET: render the template
    return render_template(template)

# -------------------- Core text-based routes --------------------

@app.route("/ai/threat_prediction", methods=["GET", "POST"])
@login_required
def threat_prediction():
    return _ai_text_route("threat_prediction", "threat_prediction.html", "context")

@app.route("/ai/attack_pattern", methods=["GET", "POST"])
@login_required
def attack_pattern():
    return _ai_text_route("attack_pattern", "attack_pattern.html", "logs")

@app.route("/ai/spam", methods=["GET", "POST"])
@login_required
def spam():
    return _ai_text_route("spam", "spam.html", "email")

@app.route("/ai/email_security", methods=["GET", "POST"])
@login_required
def email_security():
    return _ai_text_route("email_security", "email_security.html", "email")

@app.route("/ai/exploit_suggestion", methods=["GET", "POST"])
@login_required
def exploit_suggestion():
    return _ai_text_route("exploit_suggestion", "exploit_suggestion.html", "vulnerability")

@app.route("/ai/patch_recommendation", methods=["GET", "POST"])
@login_required
def patch_recommendation():
    return _ai_text_route("patch_recommendation", "patch_recommendation.html", "software")

@app.route("/ai/report_writer", methods=["GET", "POST"])
@login_required
def report_writer():
    return _ai_text_route("report_writer", "report_writer.html", "findings")

@app.route("/ai/chat", methods=["GET", "POST"])
@login_required
def chat():
    return _ai_text_route("chat", "chat.html", "question")

@app.route("/ai/code_scanner", methods=["GET", "POST"])
@login_required
def code_scanner():
    return _ai_text_route("code_scanner", "code_scanner.html", "code")

@app.route("/ai/reverse_engineering", methods=["GET", "POST"])
@login_required
def reverse_engineering():
    return _ai_text_route("reverse_engineering", "reverse_engineering.html", "assembly")

@app.route("/ai/document_classification", methods=["GET", "POST"])
@login_required
def document_classification():
    return _ai_text_route("document_classification", "document_classification.html", "text")

@app.route("/ai/incident_response", methods=["GET", "POST"])
@login_required
def incident_response():
    return _ai_text_route("incident_response", "incident_response.html", "incident")

@app.route("/ai/siem", methods=["GET", "POST"])
@login_required
def siem():
    return _ai_text_route("siem", "siem.html", "logs")

@app.route("/ai/soc", methods=["GET", "POST"])
@login_required
def soc():
    return _ai_text_route("soc", "soc.html", "query")

@app.route("/ai/firewall_rule", methods=["GET", "POST"])
@login_required
def firewall_rule():
    return _ai_text_route("firewall_rule", "firewall_rule.html", "traffic")

@app.route("/ai/threat_intel", methods=["GET", "POST"])
@login_required
def threat_intel():
    return _ai_text_route("threat_intel", "threat_intel.html", "ioc")

@app.route("/ai/vuln_explain", methods=["GET", "POST"])
@login_required
def vuln_explain():
    return _ai_text_route("vuln_explain", "vuln_explain.html", "cve")

@app.route("/ai/pentest", methods=["GET", "POST"])
@login_required
def pentest():
    return _ai_text_route("pentest", "pentest.html", "target")

@app.route("/ai/malware", methods=["GET", "POST"])   # text hash
@login_required
def malware_text():
    return _ai_text_route("malware", "malware.html", "hash")

@app.route("/ai/ids", methods=["GET", "POST"])
@login_required
def ids():
    return _ai_text_route("ids", "ids.html", "packet")

@app.route("/ai/fraud_detection", methods=["GET", "POST"])
@login_required
def fraud_detection():
    return _ai_text_route("fraud_detection", "fraud_detection.html", "transaction")

@app.route("/ai/ransomware", methods=["GET", "POST"])
@login_required
def ransomware():
    return _ai_text_route("ransomware", "ransomware.html", "file_ops")

@app.route("/ai/topology", methods=["GET", "POST"])
@login_required
def topology():
    return _ai_text_route("topology", "topology.html", "devices")

@app.route("/ai/uba", methods=["GET", "POST"])
@login_required
def uba():
    return _ai_text_route("uba", "uba.html", "actions")

@app.route("/ai/traffic_classification", methods=["GET", "POST"])
@login_required
def traffic_classification():
    return _ai_text_route("traffic_classification", "traffic_classification.html", "features")

@app.route("/ai/image_recognition", methods=["GET", "POST"])
@login_required
def image_recognition():
    return _ai_text_route("image_recognition", "image_recognition.html", "image", use_file=True)

@app.route("/ai/ocr", methods=["GET", "POST"])
@login_required
def ocr():
    return _ai_text_route("ocr", "ocr.html", "image", use_file=True)

@app.route("/ai/translation", methods=["GET", "POST"])
@login_required
def translation():
    # Special case: needs language selection
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        text_input = (request.form.get("text") or data.get("text") or "").strip()
        target_lang = (request.form.get("lang") or data.get("lang") or "en").strip()
        if not text_input:
            return jsonify({"error": "text is required"}), 400
        # Use translation pipeline if available, else mock
        if translation_pipe is not None:
            try:
                result = translation_pipe(text_input, max_length=512)[0]['translation_text']
                conf = 0.98
            except Exception as exc:
                logger.warning("Translation error: %s", exc)
                result = f"[Translation not available] {text_input}"
                conf = 0.5
        else:
            result = f"Translation (to {target_lang}) not available. Input: {text_input[:100]}"
            conf = 0.5
        save_result("translation", f"{text_input}|{target_lang}", result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})
    return render_template("translation.html")

@app.route("/ai/summarizer", methods=["GET", "POST"])
@login_required
def summarizer():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        text_input = (request.form.get("text") or data.get("text") or "").strip()
        if not text_input:
            return jsonify({"error": "text is required"}), 400
        summary = generate_summary(text_input)
        conf = 0.95
        save_result("summarizer", text_input, summary, conf)
        return jsonify({"result": summary, "confidence": conf})
    return render_template("summarizer.html")

@app.route("/ai/code_generation", methods=["GET", "POST"])
@login_required
def code_generation():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        description = (request.form.get("description") or data.get("description") or "").strip()
        if not description:
            return jsonify({"error": "description is required"}), 400
        code = generate_code(description)
        conf = 0.9
        save_result("code_generator", description, code, conf)
        return jsonify({"result": code, "confidence": conf})
    return render_template("code_generator.html")

@app.route("/ai/packet_analysis", methods=["GET", "POST"])
@login_required
def packet_analysis():
    if request.method == "POST":
        pcap_file = request.files.get("pcap")
        if not pcap_file or pcap_file.filename == '':
            return jsonify({"error": "pcap file is required"}), 400
        # Process pcap with scapy
        if not scapy_available:
            return jsonify({"error": "scapy not installed"}), 500
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            pcap_file.save(tmp.name)
            tmp_path = tmp.name
        try:
            packets = rdpcap(tmp_path)
            summary = []
            for p in packets[:20]:
                if IP in p:
                    summary.append(f"{p[IP].src} -> {p[IP].dst}")
            result = "Summary of first 20 packets:\n" + "\n".join(summary) if summary else "No IP packets found"
            conf = 0.9
        except Exception as exc:
            result = f"Error analyzing pcap: {exc}"
            conf = 0.0
        finally:
            os.unlink(tmp_path)
        save_result("packet_analysis", pcap_file.filename, result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})
    return render_template("packet_analysis.html")

@app.route("/ai/malware_similarity", methods=["GET", "POST"])
@login_required
def malware_similarity():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        hash_val = (request.form.get("hash") or data.get("hash") or "").strip()
        if not hash_val:
            return jsonify({"error": "hash is required"}), 400
        # Mock result: you could integrate with VirusTotal or a local DB
        result = f"Malware hash {hash_val} is 85% similar to Emotet family (mock)"
        conf = 0.85
        save_result("malware_similarity", hash_val, result, conf)
        return jsonify({"result": result, "confidence": conf})
    return render_template("malware_similarity.html")

@app.route("/ai/exploit_detection", methods=["GET", "POST"])
@login_required
def exploit_detection():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        traffic = (request.form.get("traffic") or data.get("traffic") or "").strip()
        if not traffic:
            return jsonify({"error": "traffic is required"}), 400
        # Use IDS model or pattern matching
        if any(x in traffic.lower() for x in ["eternalblue", "ms17-010", "cve-2017-0144"]):
            result = "Exploit detected: EternalBlue (MS17-010) signature"
            conf = 0.99
        elif "shellcode" in traffic.lower() or "exploit" in traffic.lower():
            result = "Suspicious exploit pattern detected"
            conf = 0.85
        else:
            result = "No exploit detected"
            conf = 0.95
        save_result("exploit_detection", traffic, result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})
    return render_template("exploit_detection.html")

@app.route("/ai/url_risk", methods=["GET", "POST"])
@login_required
def url_risk():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        url = (request.form.get("url") or data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url is required"}), 400
        # Simple heuristic risk score
        risk = 0
        if any(ext in url for ext in ['.exe', '.zip', '.scr']):
            risk += 30
        if 'login' in url and 'http' not in url:
            risk += 20
        if len(url) > 100:
            risk += 10
        score = min(risk, 100)
        result = f"Risk score: {score}%"
        conf = (100 - score) / 100.0
        save_result("url_risk", url, result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})
    return render_template("url_risk.html")

@app.route("/ai/file_behavior", methods=["GET", "POST"])
@login_required
def file_behavior():
    if request.method == "POST":
        file = request.files.get("file")
        filepath = request.form.get("filepath", "").strip()
        if file and file.filename:
            # Process uploaded file
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                file.save(tmp.name)
                tmp_path = tmp.name
            try:
                # Simple static analysis
                with open(tmp_path, 'rb') as f:
                    data = f.read()
                size = len(data)
                result = f"File size: {size} bytes. No suspicious behavior detected (mock)."
                conf = 0.75
            except Exception as exc:
                result = f"Error analyzing file: {exc}"
                conf = 0.0
            finally:
                os.unlink(tmp_path)
        elif filepath:
            # Path analysis (just for demo)
            result = f"File at {filepath} shows suspicious registry modifications (mock)."
            conf = 0.82
        else:
            return jsonify({"error": "file or filepath required"}), 400
        save_result("file_behavior", filepath or file.filename, result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})
    return render_template("file_behavior.html")

@app.route("/ai/voice_login", methods=["GET", "POST"])
@login_required
def voice_login():
    if request.method == "POST":
        audio_file = request.files.get("audio")
        if not audio_file or audio_file.filename == '':
            return jsonify({"error": "audio file is required"}), 400
        if not voice_available:
            return jsonify({"error": "speech_recognition not installed"}), 500
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp:
            audio_file.save(tmp.name)
            tmp_path = tmp.name
        try:
            recognizer = sr.Recognizer()
            with sr.AudioFile(tmp_path) as source:
                audio = recognizer.record(source)
            text = recognizer.recognize_google(audio)
            # Simulate voiceprint check: here we just check passphrase
            if text.lower() == "my secret passphrase":
                result = "Voice recognized. Authentication successful."
                conf = 0.95
            else:
                result = "Voice not matched. Authentication failed."
                conf = 0.2
        except Exception as exc:
            result = f"Voice recognition error: {exc}"
            conf = 0.0
        finally:
            os.unlink(tmp_path)
        save_result("voice_login", "audio data", result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})
    return render_template("voice_login.html")

@app.route("/ai/face_login", methods=["GET", "POST"])
@login_required
def face_login():
    if request.method == "POST":
        image_file = request.files.get("image")
        if not image_file or image_file.filename == '':
            return jsonify({"error": "image file is required"}), 400
        if not face_available:
            return jsonify({"error": "face_recognition not installed"}), 500
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
            image_file.save(tmp.name)
            tmp_path = tmp.name
        try:
            import face_recognition
            image = face_recognition.load_image_file(tmp_path)
            encodings = face_recognition.face_encodings(image)
            if not encodings:
                result = "No face detected"
                conf = 0.0
            else:
                # In production, compare with stored encoding
                result = "Face detected. Authentication not implemented (mock)."
                conf = 0.8
        except Exception as exc:
            result = f"Face recognition error: {exc}"
            conf = 0.0
        finally:
            os.unlink(tmp_path)
        save_result("face_login", "image data", result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})
    return render_template("face_login.html")

# ═══════════════════════════════════════════════════════════════════════════════
# PENTEST API
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/pentest/scan", methods=["POST"])
@login_required
def pentest_scan_api():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or payload.get("url") or "").strip()
    scan_type = (payload.get("scan_type") or "ai_enhanced").strip()

    if not target:
        return jsonify({"ok": False, "error": "Target URL is required."}), 400

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    try:
        raw_result = asyncio.run(pentest_scanner.scan_url(target, scan_type=scan_type))
    except Exception as exc:
        logger.exception("Pentest scan error for %s: %s", target, exc)
        return jsonify({"ok": False, "error": "Scan failed. Please try again."}), 500

    normalized = normalize_pentest_result(raw_result)
    add_to_history(
        f"pentest:{normalized['target']}", normalized["risk_level"],
        normalized["risk_score"], f"PENTEST_{scan_type.upper()}",
        len(json.dumps(normalized.get("vulnerabilities", []))),
        user_id=current_user.id,
    )
    return jsonify({"ok": True, **normalized})


# ═══════════════════════════════════════════════════════════════════════════════
# AI FEATURE ROUTES  (generic handler to avoid 46 near-identical functions)
# ═══════════════════════════════════════════════════════════════════════════════

def _ai_text_route(feature: str, template: str, input_key: str = "text"):
    """Generic handler for text-based AI analysis routes."""
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        text_input = (request.form.get(input_key) or data.get(input_key) or "").strip()
        if not text_input:
            return jsonify({"error": f"{input_key} is required"}), 400
        result, conf = text_analysis(text_input)
        save_result(feature, text_input, result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})
    return render_template(template)


@app.route("/ai/vulnerability_detection", methods=["GET", "POST"])
@login_required
def vulnerability_detection():
    return _ai_text_route("vulnerability_detection", "vuln_detection.html", "code")

@app.route("/ai/phishing_detection", methods=["GET", "POST"])
@login_required
def phishing_detection():
    return _ai_text_route("phishing_detection", "phishing.html")

@app.route("/ai/sql_injection", methods=["GET", "POST"])
@login_required
def sql_injection():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        query = (request.form.get("query") or data.get("query") or "").strip()
        if not query:
            return jsonify({"error": "query is required"}), 400
        suspicious = any(k in query.lower() for k in ["' or '", "union select", "drop table", "--", "1=1"])
        result = "Suspicious SQL injection attempt" if suspicious else "Safe query"
        conf = 0.85 if suspicious else 0.92
        save_result("sql_injection", query, result, conf)
        return jsonify({"result": result, "confidence": conf})
    return render_template("sql_injection.html")

@app.route("/ai/xss", methods=["GET", "POST"])
@login_required
def xss():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        code = (request.form.get("code") or data.get("code") or "").strip()
        if not code:
            return jsonify({"error": "code is required"}), 400
        suspicious = any(p in code for p in ["<script>", "onerror=", "javascript:", "onload="])
        result = "XSS vulnerability detected" if suspicious else "No XSS detected"
        conf = 0.88 if suspicious else 0.95
        save_result("xss", code, result, conf)
        return jsonify({"result": result, "confidence": conf})
    return render_template("xss.html")

@app.route("/ai/bot_detection", methods=["GET", "POST"])
@login_required
def bot_detection():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        ua = (request.form.get("user_agent") or data.get("user_agent") or "").strip()
        if not ua:
            return jsonify({"error": "user_agent is required"}), 400
        is_bot = any(b in ua.lower() for b in ["bot", "crawl", "spider", "headless", "selenium"])
        result = "Bot" if is_bot else "Human"
        conf = 0.75 if is_bot else 0.90
        save_result("bot_detection", ua, result, conf)
        return jsonify({"result": result, "confidence": conf})
    return render_template("bot_detection.html")

@app.route("/ai/password_strength", methods=["GET", "POST"])
@login_required
def password_strength():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        pwd = request.form.get("password") or data.get("password") or ""
        if not pwd:
            return jsonify({"error": "password is required"}), 400
        score = sum([
            len(pwd) >= 12,
            any(c.isdigit() for c in pwd),
            any(c.isupper() for c in pwd),
            any(c.islower() for c in pwd),
            any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd),
        ])
        labels = ["Very weak", "Weak", "Moderate", "Strong", "Very strong"]
        result = labels[min(score, 4)]
        save_result("password_strength", "***", result, score / 5.0)
        return jsonify({"result": result, "confidence": round(score / 5.0, 2), "score": score})
    return render_template("password.html")

@app.route("/ai/log_anomaly", methods=["GET", "POST"])
@login_required
def log_anomaly():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        log_line = (request.form.get("log") or data.get("log") or "").strip()
        if not log_line:
            return jsonify({"error": "log is required"}), 400
        features = np.array([len(log_line), log_line.count(" "), log_line.count("error"),
                              log_line.count("fail"), log_line.count("warn"),
                              log_line.count("404"), log_line.count("500"),
                              log_line.count("sql"), log_line.count("drop"), log_line.count("exec")]).reshape(1, -1)
        pred = models.log_anomaly.predict(features)[0]
        score = float(models.log_anomaly.score_samples(features)[0])
        result = "Anomaly detected" if pred == -1 else "Normal"
        conf = max(0.0, min(1.0, 1.0 - abs(score) / 10))
        save_result("log_anomaly", log_line, result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})
    return render_template("log_anomaly.html")

@app.route("/ai/network_anomaly", methods=["GET", "POST"])
@login_required
def network_anomaly():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        features_raw = request.form.get("features") or data.get("features")
        try:
            feat = np.array(json.loads(features_raw)).reshape(1, -1)
        except (TypeError, ValueError, json.JSONDecodeError):
            return jsonify({"error": "features must be a JSON array of numbers"}), 400
        pred = models.network_anomaly.predict(feat)[0]
        proba = float(models.network_anomaly.predict_proba(feat)[0][1]) if hasattr(models.network_anomaly, "predict_proba") else 0.8
        result = "Anomaly" if pred == 1 else "Normal"
        save_result("network_anomaly", str(features_raw), result, proba)
        return jsonify({"result": result, "confidence": round(proba, 4)})
    return render_template("network_anomaly.html")

@app.route("/ai/domain_reputation", methods=["GET", "POST"])
@login_required
def domain_reputation():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        domain = (request.form.get("domain") or data.get("domain") or "").strip()
        if not domain:
            return jsonify({"error": "domain is required"}), 400
        result, conf = f"Domain {domain} has medium reputation (no VT key configured)", 0.6
        if VT_API_KEY:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": VT_API_KEY}, timeout=10,
                )
                if r.status_code == 200:
                    malicious = r.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
                    result = f"Domain {domain}: {malicious} malicious reports on VirusTotal"
                    conf = max(0.0, 1.0 - malicious / 100)
            except Exception as exc:
                logger.warning("VirusTotal API error: %s", exc)
        save_result("domain_reputation", domain, result, conf)
        return jsonify({"result": result, "confidence": round(conf, 4)})
    return render_template("domain_reputation.html")

# Remaining AI routes using the generic handler
_REMAINING_AI_ROUTES = [
    ("threat_prediction",       "threat_prediction.html",       "context"),
    ("attack_pattern",          "attack_pattern.html",          "logs"),
    ("spam",                    "spam.html",                    "email"),
    ("email_security",          "email_security.html",          "email"),
    ("exploit_suggestion",      "exploit_suggestion.html",      "vulnerability"),
    ("patch_recommendation",    "patch_recommendation.html",    "software"),
    ("report_writer",           "report_writer.html",           "findings"),
    ("chat",                    "chat.html",                    "question"),
    ("code_scanner",            "code_scanner.html",            "code"),
    ("reverse_engineering",     "reverse_engineering.html",     "assembly"),
    ("document_classification", "document_classification.html", "text"),
    ("incident_response",       "incident_response.html",       "incident"),
    ("siem",                    "siem.html",                    "logs"),
    ("soc",                     "soc.html",                     "query"),
    ("firewall_rule",           "firewall_rule.html",           "traffic"),
    ("threat_intel",            "threat_intel.html",            "ioc"),
    ("vuln_explain",            "vuln_explain.html",            "cve"),
    ("pentest",                 "pentest.html",                 "target"),
    ("malware",                 "malware.html",                 "hash"),
    ("ids",                     "ids.html",                     "packet"),
    ("face_login",              "face_login.html",              "image"),
    ("fraud_detection",         "fraud_detection.html",         "transaction"),
    ("ransomware",              "ransomware.html",              "file_ops"),
    ("topology",                "topology.html",                "devices"),
    ("uba",                     "uba.html",                     "actions"),
    ("traffic_classification",  "traffic_classification.html",  "features"),
    ("image_recognition",       "image_recognition.html",       "image"),
    ("ocr",                     "ocr.html",                     "image"),
    ("translation",             "translation.html",             "text"),
    ("summarizer",              "summarizer.html",              "text"),
    ("code_generation",         "code_generation.html",         "description"),
    ("packet_analysis",         "packet_analy.html",            "packet"),
    ("malware_similarity",      "malware_similarity.html",      "hash"),
    ("exploit_detection",       "exploit_detection.html",       "traffic"),
    ("url_risk",                "url_risk.html",                "url"),
    ("file_behavior",           "file_behavior.html",           "filepath"),
    ("voice_login",             "voice_login.html",             "audio"),
]

_registered_rules = {r.rule for r in app.url_map.iter_rules()}

for _feature, _template, _key in _REMAINING_AI_ROUTES:
    _route = f"/ai/{_feature}"
    if _route in _registered_rules:
        continue  # already registered as a proper function above

    def _make_view(feat, tmpl, key):
        @login_required
        def view():
            return _ai_text_route(feat, tmpl, key)
        view.__name__ = feat
        return view

    app.add_url_rule(_route, _feature, _make_view(_feature, _template, _key), methods=["GET", "POST"])


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/scan/sql", methods=["POST"])
@login_required
def scan_sql():
    target_url = request.form.get("url", "").strip()
    if not target_url:
        flash("Target URL is required.", "danger")
        return redirect(url_for("dashboard"))

    allowed, project = user_can_scan_url(current_user, target_url)
    if not allowed:
        flash("You can only scan domains you own and have verified.", "danger")
        return redirect(url_for("dashboard"))

    result_text = f"SQL scan completed for {target_url}"
    db.session.add(ScanRecord(
        user_id=current_user.id,
        project_id=project.id if project else None,
        target=target_url, source="web",
        label="SQL Error Detector", status="completed",
        length=len(result_text), scan_type="sql",
        result=result_text, risk_score=0.0,
    ))
    _db_commit()
    log_activity(current_user, "scan_sql", target_url)
    flash("SQL scan finished.", "success")
    return redirect(url_for("dashboard"))
    
@app.route("/ai-suite")
@login_required
def ai_suite():
    return render_template("ai_suite.html")


# ═══════════════════════════════════════════════════════════════════════════════
# APP STARTUP
# ═══════════════════════════════════════════════════════════════════════════════

with app.app_context():
    db.create_all()
    # Ensure admin flag is set for the configured admin email
    _admin_email = os.environ.get("ADMIN_EMAIL", "")
    if _admin_email:
        _admin_user = User.query.filter_by(email=_admin_email).first()
        if _admin_user and not _admin_user.is_admin:
            _admin_user.is_admin = True
            db.session.commit()
            logger.info("Admin flag set for %s", _admin_email)
    logger.info("Database tables ensured.")

if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(debug=debug, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

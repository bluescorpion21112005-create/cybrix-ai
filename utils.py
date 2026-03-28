"""
utils.py — Shared utility helpers. No business logic here.
"""
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def read_text_file(path: str) -> str:
    """Read a file as text, falling back to latin-1 if not valid UTF-8."""
    raw = Path(path).read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="ignore")


def read_json_file(path: str) -> dict:
    """Read a JSON file; returns {} if the file does not exist."""
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read JSON file %s: %s", path, exc)
        return {}


def write_json_file(path: str, data: dict) -> None:
    """Write data to a JSON file, creating parent directories as needed."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def now_str() -> str:
    """Return current local time as a formatted string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def clip_text(text: str, limit: int = 4000) -> str:
    """Truncate text to *limit* characters."""
    return text[:limit]


def ensure_dir(path: str) -> None:
    """Create directory (and parents) if it does not already exist."""
    Path(path).mkdir(parents=True, exist_ok=True)

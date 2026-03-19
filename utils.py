from pathlib import Path
from datetime import datetime
import json
def read_text_file(path: str) -> str:
    raw = Path(path).read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="ignore")

def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def clip_text(text: str, limit: int = 4000) -> str:
    return text[:limit]

def clip_text(text: str, limit: int = 4000) -> str:
    return text[:limit]
from pathlib import Path
from datetime import datetime
import json


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def read_text_file(path: str) -> str:
    raw = Path(path).read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="ignore")


def read_json_file(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_file(path: str, data: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def clip_text(text: str, limit: int = 4000) -> str:
    return text[:limit]
from pathlib import Path
from datetime import datetime
import json
import csv


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
def save_lab_report_json(data, path):
    """
    Save lab analysis result to JSON file
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def save_lab_report_csv(data, path):
    """
    Save lab payload results to CSV
    """
    payloads = data.get("payloads", [])

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow([
            "payload_file",
            "label",
            "risk_score",
            "risk_delta",
            "length",
            "length_delta"
        ])

        for p in payloads:
            writer.writerow([
                p.get("file"),
                p.get("label"),
                p.get("risk_score"),
                p.get("risk_delta"),
                p.get("length"),
                p.get("length_delta"),
            ])
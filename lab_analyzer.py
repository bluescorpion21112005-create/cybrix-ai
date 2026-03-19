from pathlib import Path
from predictor import predict_text
from utils import read_json_file

def read_text(path: Path) -> str:
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="ignore")

def severity_from_score(score: float) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"

def analyze_case(case_dir: str):
    case_path = Path(case_dir)
    baseline_path = case_path / "baseline.html"
    metadata = read_json_file(str(case_path / "metadata.json"))

    if not baseline_path.exists():
        return {"ok": False, "error": "baseline.html not found"}

    baseline_text = read_text(baseline_path)
    baseline_result = predict_text(baseline_text)

    payload_results = []
    for file in sorted(case_path.glob("payload_*.html")):
        text = read_text(file)
        result = predict_text(text)

        length_delta = len(text) - len(baseline_text)
        risk_delta = round(result["risk_score"] - baseline_result["risk_score"], 1)

        payload_results.append({
            "file": file.name,
            "text": text,
            "label": result["label"],
            "risk_score": result["risk_score"],
            "severity": severity_from_score(result["risk_score"]),
            "length": len(text),
            "length_delta": length_delta,   
            "risk_delta": risk_delta,
            "matched_sql": result["matched_keywords"]["sql"],
            "matched_suspicious": result["matched_keywords"]["suspicious"],
            "sql_keyword_count": len(result["matched_keywords"]["sql"]),
            "suspicious_keyword_count": len(result["matched_keywords"]["suspicious"]),
        })

    payload_results.sort(key=lambda x: x["risk_score"], reverse=True)
    summary = {
            "total_payloads": len(payload_results),
            "sql_error_count": sum(1 for x in payload_results if x["label"] == "SQL_ERROR"),
            "suspicious_count": sum(1 for x in payload_results if x["label"] == "SUSPICIOUS"),
            "normal_count": sum(1 for x in payload_results if x["label"] == "NORMAL"),
            "high_count": sum(1 for x in payload_results if x["severity"] == "HIGH"),
            "medium_count": sum(1 for x in payload_results if x["severity"] == "MEDIUM"),
            "low_count": sum(1 for x in payload_results if x["severity"] == "LOW"),
            "avg_risk_score": round(
        sum(x["risk_score"] for x in payload_results) / len(payload_results), 2
    ) if payload_results else 0.0,
}

    return {
        "ok": True,
        "case": case_path.name,
        "baseline_text": baseline_text,
        "metadata": metadata,
        "summary": summary,
        "top_payload": payload_results[0] if payload_results else None,
        "baseline": {
            "label": baseline_result["label"],
            "risk_score": baseline_result["risk_score"],
            "severity": severity_from_score(baseline_result["risk_score"]),
            "length": len(baseline_text),
        },
        "top_payload": payload_results[0] if payload_results else None,
        "payload_count": len(payload_results),
        "payloads": payload_results,
    }
from joblib import load
import requests
import re

LABEL_NAMES = {
    0: "NORMAL",
    1: "SUSPICIOUS",
    2: "SQL_ERROR"
}

SQL_KEYWORDS = [
    "sql syntax",
    "mysql",
    "postgresql",
    "sqlite",
    "ora-",
    "quoted string not properly terminated",
    "odbc",
    "ole db",
    "database error",
    "query failed",
    "sqlstate",
    "syntax error",
    "mysql_fetch_array",
    "mysql_num_rows",
    "unclosed quotation mark",
    "warning:",
    "select * from",
]

SUSPICIOUS_KEYWORDS = [
    "internal server error",
    "unexpected condition",
    "processing failure",
    "application exception",
    "request could not be processed",
    "invalid input",
    "parameter validation failed",
    "malformed request",
    "stack trace",
    "exception",
    "traceback",
    "server error",
]

model = load("models/sql_error_model.joblib")


def keyword_boost(text: str, probs):
    lower_text = text.lower()
    boosted = list(probs)

    for kw in SQL_KEYWORDS:
        if kw in lower_text:
            boosted[2] += 0.12

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower_text:
            boosted[1] += 0.08

    total = sum(boosted)
    boosted = [x / total for x in boosted]
    return boosted


def calculate_risk_score(normal, suspicious, sql_error):
    score = (suspicious * 55) + (sql_error * 100) - (normal * 15)

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    return round(score, 1)


def find_matched_keywords(text: str):
    lower_text = text.lower()
    matched_sql = [kw for kw in SQL_KEYWORDS if kw in lower_text]
    matched_suspicious = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_text]

    return {
        "sql": matched_sql,
        "suspicious": matched_suspicious
    }


def highlight_keywords(text: str):
    highlighted = text

    all_keywords = sorted(SQL_KEYWORDS + SUSPICIOUS_KEYWORDS, key=len, reverse=True)

    for kw in all_keywords:
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        if kw in SQL_KEYWORDS:
            highlighted = pattern.sub(
                lambda m: f'<mark class="hl-sql">{m.group(0)}</mark>',
                highlighted
            )
        else:
            highlighted = pattern.sub(
                lambda m: f'<mark class="hl-suspicious">{m.group(0)}</mark>',
                highlighted
            )

    return highlighted


def predict_text(text: str):
    probs = model.predict_proba([text])[0]
    boosted_probs = keyword_boost(text, probs)

    pred_idx = boosted_probs.index(max(boosted_probs))
    label = LABEL_NAMES[pred_idx]

    normal = round(boosted_probs[0], 3)
    suspicious = round(boosted_probs[1], 3)
    sql_error = round(boosted_probs[2], 3)

    matched = find_matched_keywords(text)
    risk_score = calculate_risk_score(normal, suspicious, sql_error)

    return {
        "label": label,
        "normal": normal,
        "suspicious": suspicious,
        "sql_error": sql_error,
        "risk_score": risk_score,
        "matched_keywords": matched,
        "highlighted_text": highlight_keywords(text)
    }


def scan_url(url: str):
    try:
        response = requests.get(
            url,
            timeout=8,
            headers={
                "User-Agent": "AI-SQL-Error-Detector/1.0"
            }
        )

        text = response.text
        prediction = predict_text(text)

        return {
            "ok": True,
            "url": url,
            "status": response.status_code,
            "length": len(text),
            "content": text,
            "prediction": prediction
        }

    except Exception as e:
        return {
            "ok": False,
            "url": url,
            "error": str(e)
        }
"""
migrate_db.py — Add ALL missing columns to existing SQLite databases.
Run once: python migrate_db.py
"""
import os
import sqlite3

DATABASES = ["siteguard.db", "instance/site.db", "instance/siteguard.db"]

# (table, column_name, ALTER SQL)
MIGRATIONS = [
    # ── user table ────────────────────────────────────────────────────────────
    ("user", "google_id",             "ALTER TABLE user ADD COLUMN google_id VARCHAR(255)"),
    ("user", "auth_provider",         "ALTER TABLE user ADD COLUMN auth_provider VARCHAR(50) DEFAULT 'local'"),
    ("user", "telegram_chat_id",      "ALTER TABLE user ADD COLUMN telegram_chat_id VARCHAR(100)"),
    ("user", "telegram_username",     "ALTER TABLE user ADD COLUMN telegram_username VARCHAR(120)"),
    ("user", "telegram_connected_at", "ALTER TABLE user ADD COLUMN telegram_connected_at DATETIME"),
    ("user", "is_admin",              "ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0"),
    ("user", "password_hash",         "ALTER TABLE user ADD COLUMN password_hash VARCHAR(128)"),   # <--- QO‘SHILDI

    # ── project table ─────────────────────────────────────────────────────────
    ("project", "verification_method", "ALTER TABLE project ADD COLUMN verification_method VARCHAR(50)"),
    ("project", "verified_at",         "ALTER TABLE project ADD COLUMN verified_at DATETIME"),
    ("project", "updated_at",          "ALTER TABLE project ADD COLUMN updated_at DATETIME"),

    # ── scan_record table ─────────────────────────────────────────────────────
    ("scan_record", "target",     "ALTER TABLE scan_record ADD COLUMN target VARCHAR(500)"),
    ("scan_record", "source",     "ALTER TABLE scan_record ADD COLUMN source VARCHAR(100)"),
    ("scan_record", "label",      "ALTER TABLE scan_record ADD COLUMN label VARCHAR(100)"),
    ("scan_record", "length",     "ALTER TABLE scan_record ADD COLUMN length INTEGER"),
    ("scan_record", "scan_type",  "ALTER TABLE scan_record ADD COLUMN scan_type VARCHAR(50)"),
    ("scan_record", "result",     "ALTER TABLE scan_record ADD COLUMN result TEXT"),
    ("scan_record", "risk_score", "ALTER TABLE scan_record ADD COLUMN risk_score REAL DEFAULT 0"),

    # ── local_scan_result table ───────────────────────────────────────────────
    ("local_scan_result", "scan_type",     "ALTER TABLE local_scan_result ADD COLUMN scan_type VARCHAR(50) DEFAULT 'local_agent'"),
    ("local_scan_result", "findings_json", "ALTER TABLE local_scan_result ADD COLUMN findings_json TEXT DEFAULT '[]'"),
    ("local_scan_result", "status",        "ALTER TABLE local_scan_result ADD COLUMN status VARCHAR(50) DEFAULT 'completed'"),

    # ── api_usage table ───────────────────────────────────────────────────────
    ("api_usage", "endpoint",   "ALTER TABLE api_usage ADD COLUMN endpoint VARCHAR(200)"),
    ("api_usage", "created_at", "ALTER TABLE api_usage ADD COLUMN created_at DATETIME"),
]


def get_existing_columns(cur, table: str) -> set:
    cur.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}


def get_existing_tables(cur) -> set:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {row[0] for row in cur.fetchall()}


def migrate(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    tables = get_existing_tables(cur)
    print(f"\n{db_path}  (tables: {sorted(tables)})")

    for table, col_name, sql in MIGRATIONS:
        if table not in tables:
            print(f"  - Table '{table}' does not exist, skipping {col_name}")
            continue
        existing = get_existing_columns(cur, table)
        if col_name not in existing:
            try:
                cur.execute(sql)
                print(f"  + {table}.{col_name} added")
            except Exception as exc:
                print(f"  ! {table}.{col_name}: {exc}")
        else:
            print(f"  . {table}.{col_name} already exists")

    # Ensure admin flag (only if user table exists)
    if "user" in tables:
        admin_email = os.environ.get("ADMIN_EMAIL", "bluescorpion21112005@gmail.com")
        cur.execute("UPDATE user SET is_admin=1 WHERE email=?", (admin_email,))
        if cur.rowcount:
            print(f"  * Admin flag set for {admin_email}")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    for db_path in DATABASES:
        if os.path.exists(db_path):
            migrate(db_path)
        else:
            print(f"\n{db_path}: not found, skipping")
    print("\nMigration complete.")
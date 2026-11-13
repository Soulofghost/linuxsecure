import os
import sqlite3
from backend.app.config import DB_PATH

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cis_assessments (
        id TEXT PRIMARY KEY,
        target_host TEXT,
        score_percentage REAL,
        passed_rules INTEGER,
        failed_rules INTEGER,
        total_rules INTEGER,
        evaluated_at TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cis_findings (
        id TEXT PRIMARY KEY,
        assessment_id TEXT,
        rule_id TEXT,
        section TEXT,
        title TEXT,
        status TEXT,
        severity TEXT,
        actual_value TEXT,
        expected_value TEXT,
        remediation TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS remediation_scripts (
        assessment_id TEXT PRIMARY KEY,
        script_body TEXT,
        generated_at TEXT
    );
    """)

    conn.commit()
    conn.close()

init_db()

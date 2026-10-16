import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DATA_DIR = Path(os.getenv("IDO_DATA_DIR", "data")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "ido.sqlite3"

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','approver','analyst','viewer')),
 active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS datasets (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, source_name TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id),
 columns_json TEXT NOT NULL, rows_json TEXT NOT NULL, row_count INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS runs (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, left_dataset_id INTEGER NOT NULL REFERENCES datasets(id),
 right_dataset_id INTEGER NOT NULL REFERENCES datasets(id), config_json TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'draft', created_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, completed_at TEXT
);
CREATE TABLE IF NOT EXISTS results (
 id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
 left_index INTEGER, right_index INTEGER, status TEXT NOT NULL, score REAL NOT NULL,
 explanation TEXT NOT NULL, left_json TEXT, right_json TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
 id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL UNIQUE REFERENCES runs(id) ON DELETE CASCADE,
 requested_by INTEGER NOT NULL REFERENCES users(id), status TEXT NOT NULL DEFAULT 'pending',
 decided_by INTEGER REFERENCES users(id), comment TEXT, requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 decided_at TEXT
);
CREATE TABLE IF NOT EXISTS workflow_templates (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 config_json TEXT NOT NULL, created_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
 entity_type TEXT NOT NULL, entity_id INTEGER, details_json TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with connect() as db:
        db.executescript(SCHEMA)

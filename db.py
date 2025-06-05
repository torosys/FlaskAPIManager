import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / 'app.db'

SCHEMA_SQL = '''
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS environments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    base_url TEXT NOT NULL,
    port INTEGER,
    default_headers TEXT,
    default_params TEXT,
    auth_settings TEXT,
    meta TEXT,
    tags TEXT,
    is_default INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    http_method TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    headers TEXT,
    params TEXT,
    auth_type TEXT,
    body_template TEXT,
    extract_rule TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS global_params (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    gkey TEXT NOT NULL,
    gvalue TEXT,
    UNIQUE(user_id, gkey),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
'''


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.executescript(SCHEMA_SQL)
    # Pre-populate SUPER user
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", ("SUPER",))
    if cur.fetchone() is None:
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("SUPER", "SUPER"))
    conn.commit()
    conn.close()


if __name__ == '__main__':
    init_db()
    print("Database initialized.")
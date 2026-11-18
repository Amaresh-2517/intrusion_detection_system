"""
SQLite connection handling and schema initialization.

Design note: we use short-lived connections (one per operation) rather
than a single long-lived connection, because the sniffer and the Flask
dashboard run in different processes and SQLite connections aren't
safely shared across processes. WAL mode is enabled so the sniffer can
write while the dashboard reads concurrently without locking errors.
"""

import os
import sqlite3
from contextlib import contextmanager
from app.config import DB_PATH

TABLES_SQL = """
CREATE TABLE IF NOT EXISTS TrafficLog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    packet_size INTEGER
);

CREATE TABLE IF NOT EXISTS Alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_type TEXT NOT NULL,
    source_ip TEXT,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'Medium'
);
"""

# Index creation is kept separate from table creation and run *after*
# migration, because idx_alerts_severity references a column that may
# not exist yet on a database created before severity was added — see
# _migrate_existing_db().
INDICES_SQL = """
CREATE INDEX IF NOT EXISTS idx_traffic_src_ip ON TrafficLog(src_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON TrafficLog(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON Alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON Alerts(severity);
"""


def _migrate_existing_db(conn):
    """
    Add the severity column to an Alerts table created before this column
    existed. SQLite's CREATE TABLE IF NOT EXISTS won't retroactively add
    columns, so this handles upgrading a database from an earlier version
    of the schema without the person needing to delete their data.
    """
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(Alerts)")}
    if "severity" not in existing_cols:
        conn.execute("ALTER TABLE Alerts ADD COLUMN severity TEXT NOT NULL DEFAULT 'Medium'")


@contextmanager
def get_connection():
    """Context-managed SQLite connection with WAL mode + row access by name."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=10000;")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create tables/indices if they don't already exist. Safe to call repeatedly."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_connection() as conn:
        conn.executescript(TABLES_SQL)
        _migrate_existing_db(conn)
        conn.executescript(INDICES_SQL)


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")

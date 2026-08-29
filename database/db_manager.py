"""
database/db_manager.py

Handles all SQLite operations for the case database.

WHY THIS DESIGN: a single file has up to 4 timestamps (created/modified/
accessed/metadata-changed). We store each as its OWN ROW in
`timeline_events`, linked to `files` by file_id - not as 4 columns on one
row. This makes "everything that happened between 2pm-3pm" a single
ORDER BY query, instead of a UNION across 4 columns.
"""

import sqlite3
from contextlib import contextmanager


SCHEMA = """
CREATE TABLE IF NOT EXISTS case_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    case_name TEXT,
    examiner TEXT,
    target_path TEXT,
    scan_started_at TEXT,
    scan_completed_at TEXT
);

CREATE TABLE IF NOT EXISTS files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_path TEXT NOT NULL UNIQUE,
    file_name TEXT NOT NULL,
    parent_dir TEXT,
    extension TEXT,
    size_bytes INTEGER,
    is_directory INTEGER NOT NULL DEFAULT 0,
    owner TEXT,
    permissions TEXT,
    md5 TEXT,
    sha256 TEXT,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    ctime TEXT,
    mtime TEXT,
    atime TEXT,
    btime TEXT
);

CREATE TABLE IF NOT EXISTS timeline_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,     -- 'created' | 'modified' | 'accessed' | 'metadata_changed'
    event_timestamp TEXT NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(file_id)
);

CREATE TABLE IF NOT EXISTS anomalies (
    anomaly_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    anomaly_type TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,       -- 'low' | 'medium' | 'high' | 'critical'
    detected_at TEXT,
    FOREIGN KEY (file_id) REFERENCES files(file_id)
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON timeline_events(event_timestamp);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(full_path);
"""


class DBManager:
    def __init__(self, db_path: str = "ffstg_case.db"):
        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")  # OFF by default in SQLite
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ---------- case metadata ----------
    def set_case_info(self, case_name, examiner, target_path, scan_started_at):
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO case_metadata (id, case_name, examiner, target_path, scan_started_at)
                   VALUES (1, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       case_name=excluded.case_name,
                       examiner=excluded.examiner,
                       target_path=excluded.target_path,
                       scan_started_at=excluded.scan_started_at""",
                (case_name, examiner, target_path, scan_started_at),
            )

    def mark_scan_complete(self, completed_at):
        with self._connect() as conn:
            conn.execute(
                "UPDATE case_metadata SET scan_completed_at = ? WHERE id = 1",
                (completed_at,),
            )

    # ---------- files ----------
    def insert_file(self, record: dict) -> int:
        """Insert one file's metadata. Returns the new file_id."""
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT OR REPLACE INTO files
                   (full_path, file_name, parent_dir, extension, size_bytes,
                    is_directory, owner, permissions, md5, sha256, is_deleted,
                    ctime, mtime, atime, btime)
                   VALUES (:full_path, :file_name, :parent_dir, :extension, :size_bytes,
                           :is_directory, :owner, :permissions, :md5, :sha256, :is_deleted,
                           :ctime, :mtime, :atime, :btime)""",
                record,
            )
            return cur.lastrowid

    # ---------- timeline events ----------
    def insert_timeline_events_bulk(self, events: list[dict]):
        if not events:
            return
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO timeline_events (file_id, event_type, event_timestamp)
                   VALUES (:file_id, :event_type, :event_timestamp)""",
                events,
            )

    # ---------- anomalies (used from Day 4 onward) ----------
    def insert_anomaly(self, file_id, anomaly_type, description, severity, detected_at):
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO anomalies (file_id, anomaly_type, description, severity, detected_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (file_id, anomaly_type, description, severity, detected_at),
            )

    def get_anomalies(self):
        with self._connect() as conn:
            return conn.execute(
                """SELECT f.full_path, a.anomaly_type, a.description, a.severity, a.detected_at
                   FROM anomalies a JOIN files f ON f.file_id = a.file_id
                   ORDER BY a.severity DESC"""
            ).fetchall()

    # ---------- read helpers ----------
    def get_file_count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    def get_all_files(self):
        with self._connect() as conn:
            return conn.execute("SELECT * FROM files").fetchall()

    def get_timeline(self, limit=None):
        query = """
            SELECT f.full_path, f.file_name, t.event_type, t.event_timestamp
            FROM timeline_events t
            JOIN files f ON f.file_id = t.file_id
            ORDER BY t.event_timestamp ASC
        """
        if limit:
            query += f" LIMIT {int(limit)}"
        with self._connect() as conn:
            return conn.execute(query).fetchall()

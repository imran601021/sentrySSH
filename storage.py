import sqlite3
from datetime import datetime
from models import Incident
import os

DB_PATH = DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "incidents.db"
)


def init_db(db_path: str = DB_PATH) -> None:
    """Creates the incidents table if it doesn't already exist. Safe to call every startup."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            user TEXT,
            attempt_count INTEGER NOT NULL,
            window_seconds INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )
        """)
    conn.commit()
    conn.close()


def save_incident(incident: Incident, db_path: str = DB_PATH) -> None:
    """Writes one Incident to the database."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO incidents (ip, user, attempt_count, window_seconds, first_seen, last_seen, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident.ip,
            incident.user,
            incident.attempt_count,
            incident.window_seconds,
            incident.first_seen.isoformat(),
            incident.last_seen.isoformat(),
            datetime.now().isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def get_recent_incidents(limit: int = 50, db_path: str = DB_PATH) -> list[dict]:
    """Returns the most recent incidents, newest first, as plain dicts."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT * FROM incidents ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows
def prune_old_incidents(days: int = 30, db_path: str = DB_PATH) -> int:
    """Deletes incidents older than `days` days. Returns how many rows were removed."""
    conn = sqlite3.connect(db_path)
    cursor = conn.execute(
        "DELETE FROM incidents WHERE recorded_at < datetime('now', ?)",
        (f"-{days} days",),
    )
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted

if __name__ == "__main__":

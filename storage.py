import sqlite3
from datetime import datetime

from models import Incident

DB_PATH = "incidents.db"


def init_db(db_path: str = DB_PATH) -> None:
    """Creates the incidents table if it doesn't already exist. Safe to call every startup."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
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
        """
    )
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


if __name__ == "__main__":
    # Smoke test: fake incident, no live traffic needed
    from models import Incident

    init_db()
    fake = Incident(
        ip="203.0.113.5",
        user="admin",
        attempt_count=3,
        window_seconds=120,
        first_seen=datetime.now(),
        last_seen=datetime.now(),
    )
    save_incident(fake)
    print("Saved one test incident. Check with: sqlite3 incidents.db 'SELECT * FROM incidents;'")
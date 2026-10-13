"""
SQLite history of tested credentials.

It lets a session be interrupted and resumed without testing a password twice,
and keeps the results. Each domain has its own table.
"""

import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DATABASE_PATH = Path.home() / ".config" / "conpass" / "conpass.db"

# Values of the note column
NOTE_PREVIOUS = "previous"  # previous password (N-1 / N-2) of the account
NOTE_UNCONFIRMED = "unconfirmed"  # accepted over NTLM, may be the previous password
NOTE_RESTRICTED = "restricted"  # account that cannot be tested (Protected Users...)


class Database:
    """Tested credentials of one domain. Thread-safe."""

    def __init__(self, path: Path, domain: str):
        self.path = path
        self.table = self._table_name(domain)
        self._lock = threading.Lock()
        self._tested: set[tuple[str, str]] = set()
        self._connection = sqlite3.connect(str(path), check_same_thread=False)
        self._create_table()
        self._tested = {(username, password) for username, password, *_ in self._select()}

    @staticmethod
    def _table_name(domain: str) -> str:
        name = re.sub(r"[^a-zA-Z0-9_]", "_", domain)
        return name if name[0].isalpha() else f"domain_{name}"

    def _create_table(self) -> None:
        with self._connection:
            self._connection.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    note TEXT,
                    UNIQUE(username, password)
                )
            """)
            # Tables created by versions up to 0.2 have no note column
            columns = {row[1] for row in self._connection.execute(f"PRAGMA table_info({self.table})")}
            if "note" not in columns:
                self._connection.execute(f"ALTER TABLE {self.table} ADD COLUMN note TEXT")

    def _select(self, where: str = "1") -> list[tuple[str, str, bool, str | None]]:
        with self._lock:
            rows = self._connection.execute(
                f"SELECT username, password, success, note FROM {self.table} WHERE {where}"  # noqa: S608
            ).fetchall()
        return [(username, password, bool(success), note) for username, password, success, note in rows]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def is_tested(self, username: str, password: str) -> bool:
        with self._lock:
            return (username, password) in self._tested

    def record(self, username: str, password: str, success: bool, note: str | None = None) -> None:
        """Store the result of a test, replacing a previous result for the same pair."""
        with self._lock, self._connection:
            self._tested.add((username, password))
            self._connection.execute(
                f"INSERT INTO {self.table} (username, password, success, timestamp, note) "  # noqa: S608
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(username, password) "
                "DO UPDATE SET success = excluded.success, timestamp = excluded.timestamp, note = excluded.note",
                (username, password, int(success), datetime.now(timezone.utc).isoformat(), note),
            )

    def found_credentials(self) -> list[tuple[str, str, str | None]]:
        """Valid credentials, as (username, password, note)."""
        return [(username, password, note) for username, password, _, note in self._select("success = 1")]

    def previous_passwords(self) -> list[tuple[str, str]]:
        """Passwords identified as a previous password of their account."""
        return [(username, password) for username, password, *_ in self._select(f"note = '{NOTE_PREVIOUS}'")]

    def stats(self) -> tuple[int, int]:
        """(number of tests, number of valid credentials)."""
        rows = self._select()
        return len(rows), sum(success for _, _, success, _ in rows)

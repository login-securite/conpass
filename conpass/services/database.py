"""Database service for tracking tested credentials."""

import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


class DatabaseService:
    """Service for SQLite database operations to track tested credentials."""

    def __init__(self, db_path: Path, domain: str):
        self.db_path = db_path
        self.domain = domain
        self.table_name = self._sanitize_table_name(domain)
        self._connection: sqlite3.Connection | None = None
        self._cache: set[tuple[str, str]] = set()  # In-memory cache of tested credentials
        self._cache_lock = threading.Lock()  # Lock for thread-safe cache access
        self._write_lock = threading.Lock()  # Lock for serializing database writes
        self._history_candidates_cache: set[tuple[str, str]] = set()  # In-memory cache of n-1/n-2 history candidates
        self._history_cache_lock = threading.Lock()  # Lock for thread-safe history candidate cache access

    def connect(self) -> None:
        """
        Establish connection to SQLite database and create table if needed.
        Also loads all tested credentials into memory cache for fast lookups.

        Raises:
            sqlite3.Error: If unable to establish connection or create table
        """
        self._connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._create_table()
        self._load_cache()

    def close(self) -> None:
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None

    def _sanitize_table_name(self, domain: str) -> str:
        """
        Sanitize domain name to create a valid SQLite table name.

        Replace dots and special characters with underscores.
        """
        # Replace dots and non-alphanumeric characters with underscores
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', domain)
        # Ensure it starts with a letter (SQLite requirement)
        if not sanitized[0].isalpha():
            sanitized = f"domain_{sanitized}"
        return sanitized

    def _create_table(self) -> None:
        """Create table for storing tested credentials if it doesn't exist."""
        cursor = self._connection.cursor()
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                success INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                UNIQUE(username, password)
            )
        """)
        # Create index for faster lookups
        cursor.execute(f"""
            CREATE INDEX IF NOT EXISTS idx_{self.table_name}_username_password
            ON {self.table_name}(username, password)
        """)

        # Create table for n-1 / n-2 password history candidates
        # These are passwords that failed authentication without incrementing badPwdCount,
        # which indicates they may match one of the two most recently used historical passwords.
        history_table = f"{self.table_name}_history_candidates"
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {history_table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                UNIQUE(username, password)
            )
        """)
        cursor.execute(f"""
            CREATE INDEX IF NOT EXISTS idx_{history_table}_username_password
            ON {history_table}(username, password)
        """)
        self._connection.commit()

    def _load_cache(self) -> None:
        """Load all tested credentials and history candidates from database into memory cache."""
        if not self._connection:
            return

        cursor = self._connection.cursor()
        cursor.execute(f"SELECT username, password FROM {self.table_name}")
        with self._cache_lock:
            self._cache = {(row[0], row[1]) for row in cursor.fetchall()}

        # Load history candidates into cache
        history_table = f"{self.table_name}_history_candidates"
        try:
            cursor.execute(f"SELECT username, password FROM {history_table}")
            with self._history_cache_lock:
                self._history_candidates_cache = {(row[0], row[1]) for row in cursor.fetchall()}
        except sqlite3.OperationalError:
            # Table might not exist yet (older database)
            pass

    def is_already_tested(self, username: str, password: str) -> bool:
        """
        Check if a username/password combination has already been tested.
        Uses in-memory cache for O(1) lookup performance.

        Args:
            username: The username to check
            password: The password to check

        Returns:
            True if combination was already tested, False otherwise
        """
        with self._cache_lock:
            return (username, password) in self._cache

    def was_successful(self, username: str, password: str) -> bool | None:
        """
        Check if a previously tested combination was successful.

        Args:
            username: The username to check
            password: The password to check

        Returns:
            True if successful, False if failed, None if not tested yet
        """
        if not self._connection:
            return None

        cursor = self._connection.cursor()
        cursor.execute(
            f"SELECT success FROM {self.table_name} WHERE username = ? AND password = ? LIMIT 1",
            (username, password)
        )
        result = cursor.fetchone()
        return bool(result[0]) if result else None

    def record_test(self, username: str, password: str, success: bool) -> None:
        """
        Record a tested credential combination.
        Updates both database and in-memory cache.
        Uses write lock to serialize database writes and avoid SQLite contention.

        Args:
            username: The tested username
            password: The tested password
            success: Whether the authentication was successful
        """
        if not self._connection:
            return

        # Add to cache first (fast, lock-free for readers)
        with self._cache_lock:
            self._cache.add((username, password))

        # Serialize database writes to avoid SQLite contention
        with self._write_lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            cursor = self._connection.cursor()

            try:
                cursor.execute(
                    f"INSERT INTO {self.table_name} (username, password, success, timestamp) VALUES (?, ?, ?, ?)",
                    (username, password, int(success), timestamp)
                )
                self._connection.commit()
            except sqlite3.IntegrityError:
                # Already exists, update it
                cursor.execute(
                    f"UPDATE {self.table_name} SET success = ?, timestamp = ? WHERE username = ? AND password = ?",
                    (int(success), timestamp, username, password)
                )
                self._connection.commit()

    def record_history_candidate(self, username: str, password: str) -> None:
        """Record a potential n-1 / n-2 password history candidate.
        These are passwords that failed authentication without incrementing badPwdCount,
        suggesting they match one of the two most recently used historical passwords.

        Args:
            username: The username
            password: The potential history match password
        """
        if not self._connection:
            return

        # Add to cache first
        with self._history_cache_lock:
            self._history_candidates_cache.add((username, password))

        # Serialize database writes
        with self._write_lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            cursor = self._connection.cursor()
            history_table = f"{self.table_name}_history_candidates"

            try:
                cursor.execute(
                    f"INSERT INTO {history_table} (username, password, detected_at) VALUES (?, ?, ?)",
                    (username, password, timestamp)
                )
                self._connection.commit()
            except sqlite3.IntegrityError:
                # Already recorded, update timestamp
                cursor.execute(
                    f"UPDATE {history_table} SET detected_at = ? WHERE username = ? AND password = ?",
                    (timestamp, username, password)
                )
                self._connection.commit()

    def is_history_candidate(self, username: str, password: str) -> bool:
        """Check if a username/password combination is a known n-1 / n-2 history candidate.
        Uses in-memory cache for O(1) lookup performance.

        Args:
            username: The username to check
            password: The password to check

        Returns:
            True if the combination is a known history candidate
        """
        with self._history_cache_lock:
            return (username, password) in self._history_candidates_cache

    def get_history_candidates(self, username: str | None = None) -> list[tuple[str, str]]:
        """Get all n-1 / n-2 password history candidates, optionally filtered by username.

        Args:
            username: Optional username to filter by

        Returns:
            List of (username, password) tuples
        """
        with self._history_cache_lock:
            if username:
                return [(u, p) for u, p in self._history_candidates_cache if u == username]
            return list(self._history_candidates_cache)

    def get_tested_credentials(self) -> list[tuple[str, str, bool]]:
        """
        Get all tested credentials for this domain.

        Returns:
            List of tuples (username, password, success)
        """
        if not self._connection:
            return []

        cursor = self._connection.cursor()
        cursor.execute(f"SELECT username, password, success FROM {self.table_name}")
        return [(row[0], row[1], bool(row[2])) for row in cursor.fetchall()]

    def get_successful_credentials(self) -> list[tuple[str, str]]:
        """
        Get all successful credentials for this domain.

        Returns:
            List of tuples (username, password)
        """
        if not self._connection:
            return []

        cursor = self._connection.cursor()
        cursor.execute(f"SELECT username, password FROM {self.table_name} WHERE success = 1")
        return [(row[0], row[1]) for row in cursor.fetchall()]

    def get_stats(self) -> dict:
        """
        Get statistics about tested credentials.

        Returns:
            Dictionary with total, successful, and failed counts
        """
        if not self._connection:
            return {"total": 0, "successful": 0, "failed": 0}

        cursor = self._connection.cursor()
        cursor.execute(f"SELECT COUNT(*), SUM(success), SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) FROM {self.table_name}")
        row = cursor.fetchone()
        return {
            "total": row[0] or 0,
            "successful": row[1] or 0,
            "failed": row[2] or 0
        }

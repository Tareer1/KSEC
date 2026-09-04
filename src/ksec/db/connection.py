"""Persistence layer for KSEC (SQLite-backed)."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from ksec.core.errors import DatabaseError


class Database:
    """Thin, thread-safe wrapper around a SQLite connection.

    State lives in one authoritative SQLite file so that all five
    workspaces/sessions share the same data model (spec: Shared State).
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.RLock()

    def connect(self) -> "Database":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # autocommit=True: no implicit transactions; we manage
            # transactions explicitly via Database.transaction().
            # check_same_thread=False: the scheduler runs jobs on worker
            # threads; the RLock in this class serializes all access.
            conn = sqlite3.connect(
                str(self.path), timeout=10, autocommit=True, check_same_thread=False
            )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to open database {self.path}: {exc}") from exc
        conn.row_factory = sqlite3.Row
        with self._lock:
            try:
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute("PRAGMA journal_mode = WAL")
            except sqlite3.Error as exc:
                raise DatabaseError(f"Failed to configure database: {exc}") from exc
        self._conn = conn
        return self

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise DatabaseError("Database is not connected; call connect() first")
        return self._conn

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        try:
            with self._lock:
                return self.conn.execute(sql, params)
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQL execution failed: {exc}") from exc

    def executemany(self, sql: str, seq: Sequence[Sequence[Any]]) -> sqlite3.Cursor:
        try:
            with self._lock:
                return self.conn.executemany(sql, seq)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Bulk SQL execution failed: {exc}") from exc

    def query_all(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Explicit transaction. In autocommit mode the Python-level
        ``commit()``/``rollback()`` are no-ops, so transactions must be ended
        with SQL ``COMMIT``/``ROLLBACK``.
        """
        with self._lock:
            try:
                self.conn.execute("BEGIN")
                yield self.conn
                self.conn.execute("COMMIT")
            except Exception:
                try:
                    self.conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
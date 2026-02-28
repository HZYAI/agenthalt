"""Persistent state backends for guard trackers.

Provides a protocol for state persistence and implementations:
- InMemoryBackend (default, for testing)
- SQLiteBackend (production, zero external deps)
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class StateBackend(ABC):
    """Abstract protocol for persistent state storage.

    Guards use this to persist budget tracking, rate limits, deletion counts, etc.
    across process restarts.
    """

    @abstractmethod
    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        """Get a value from the store."""
        ...

    @abstractmethod
    def set(self, namespace: str, key: str, value: Any, ttl: float | None = None) -> None:
        """Set a value in the store. Optional TTL in seconds."""
        ...

    @abstractmethod
    def increment(self, namespace: str, key: str, amount: float = 1.0) -> float:
        """Atomically increment a numeric value. Returns the new value."""
        ...

    @abstractmethod
    def get_list(self, namespace: str, key: str, limit: int = 100) -> list[dict[str, Any]]:
        """Get a list of records (for history/audit)."""
        ...

    @abstractmethod
    def append_list(
        self, namespace: str, key: str, value: dict[str, Any], max_size: int = 10000
    ) -> None:
        """Append to a list, trimming to max_size."""
        ...

    @abstractmethod
    def clear_namespace(self, namespace: str) -> None:
        """Clear all keys in a namespace."""
        ...

    def close(self) -> None:  # noqa: B027
        """Clean up resources. Override in subclasses that need cleanup."""


class InMemoryBackend(StateBackend):
    """In-memory state backend for testing and development."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, Any]] = {}
        self._expiry: dict[str, dict[str, float]] = {}
        self._lists: dict[str, dict[str, list[dict[str, Any]]]] = {}

    def _full_key(self, namespace: str, key: str) -> tuple[str, str]:
        return namespace, key

    def _is_expired(self, namespace: str, key: str) -> bool:
        exp = self._expiry.get(namespace, {}).get(key)
        if exp is not None and time.time() > exp:
            self._data.get(namespace, {}).pop(key, None)
            self._expiry.get(namespace, {}).pop(key, None)
            return True
        return False

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        with self._lock:
            if self._is_expired(namespace, key):
                return default
            return self._data.get(namespace, {}).get(key, default)

    def set(self, namespace: str, key: str, value: Any, ttl: float | None = None) -> None:
        with self._lock:
            self._data.setdefault(namespace, {})[key] = value
            if ttl is not None:
                self._expiry.setdefault(namespace, {})[key] = time.time() + ttl

    def increment(self, namespace: str, key: str, amount: float = 1.0) -> float:
        with self._lock:
            if self._is_expired(namespace, key):
                self._data.setdefault(namespace, {})[key] = 0.0
            ns = self._data.setdefault(namespace, {})
            current = float(ns.get(key, 0.0))
            ns[key] = current + amount
            return ns[key]

    def get_list(self, namespace: str, key: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            items = self._lists.get(namespace, {}).get(key, [])
            return items[-limit:]

    def append_list(
        self, namespace: str, key: str, value: dict[str, Any], max_size: int = 10000
    ) -> None:
        with self._lock:
            ns = self._lists.setdefault(namespace, {})
            lst = ns.setdefault(key, [])
            lst.append(value)
            if len(lst) > max_size:
                ns[key] = lst[-max_size:]

    def clear_namespace(self, namespace: str) -> None:
        with self._lock:
            self._data.pop(namespace, None)
            self._expiry.pop(namespace, None)
            self._lists.pop(namespace, None)


class SQLiteBackend(StateBackend):
    """SQLite-based persistent state backend.

    Zero external dependencies. Data survives process restarts.
    Thread-safe via SQLite's built-in locking.

    Usage:
        backend = SQLiteBackend("agenthalt_state.db")
        engine = PolicyEngine()
        # Guards automatically use the backend when set
    """

    def __init__(self, db_path: str | Path = "agenthalt_state.db") -> None:
        self._db_path = str(db_path)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, timeout=10.0)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS kv_store (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                expires_at REAL,
                PRIMARY KEY (namespace, key)
            );

            CREATE TABLE IF NOT EXISTS list_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at REAL NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            CREATE INDEX IF NOT EXISTS idx_list_ns_key ON list_store(namespace, key);
            CREATE INDEX IF NOT EXISTS idx_list_created ON list_store(created_at);
            CREATE INDEX IF NOT EXISTS idx_kv_expires ON kv_store(expires_at);
        """)
        conn.commit()

    def _cleanup_expired(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "DELETE FROM kv_store WHERE expires_at IS NOT NULL AND expires_at < ?", (time.time(),)
        )

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        conn = self._get_conn()
        self._cleanup_expired(conn)
        row = conn.execute(
            "SELECT value FROM kv_store WHERE namespace = ? AND key = ?",
            (namespace, key),
        ).fetchone()
        if row is None:
            return default
        return json.loads(row[0])

    def set(self, namespace: str, key: str, value: Any, ttl: float | None = None) -> None:
        conn = self._get_conn()
        expires_at = (time.time() + ttl) if ttl else None
        conn.execute(
            "INSERT OR REPLACE INTO kv_store"
            " (namespace, key, value, expires_at) VALUES (?, ?, ?, ?)",
            (namespace, key, json.dumps(value), expires_at),
        )
        conn.commit()

    def increment(self, namespace: str, key: str, amount: float = 1.0) -> float:
        conn = self._get_conn()
        self._cleanup_expired(conn)
        row = conn.execute(
            "SELECT value FROM kv_store WHERE namespace = ? AND key = ?",
            (namespace, key),
        ).fetchone()
        current = json.loads(row[0]) if row else 0.0
        new_val = float(current) + amount
        conn.execute(
            "INSERT OR REPLACE INTO kv_store"
            " (namespace, key, value, expires_at) VALUES (?, ?, ?, NULL)",
            (namespace, key, json.dumps(new_val)),
        )
        conn.commit()
        return new_val

    def get_list(self, namespace: str, key: str, limit: int = 100) -> list[dict[str, Any]]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT value FROM list_store WHERE namespace = ? AND key = ? ORDER BY id DESC LIMIT ?",
            (namespace, key, limit),
        ).fetchall()
        return [json.loads(r[0]) for r in reversed(rows)]

    def append_list(
        self, namespace: str, key: str, value: dict[str, Any], max_size: int = 10000
    ) -> None:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO list_store (namespace, key, value, created_at) VALUES (?, ?, ?, ?)",
            (namespace, key, json.dumps(value), time.time()),
        )
        # Trim old entries
        count = conn.execute(
            "SELECT COUNT(*) FROM list_store WHERE namespace = ? AND key = ?",
            (namespace, key),
        ).fetchone()[0]
        if count > max_size:
            conn.execute(
                "DELETE FROM list_store WHERE id IN ("
                "  SELECT id FROM list_store"
                "  WHERE namespace = ? AND key = ? ORDER BY id ASC LIMIT ?"
                ")",
                (namespace, key, count - max_size),
            )
        conn.commit()

    def clear_namespace(self, namespace: str) -> None:
        conn = self._get_conn()
        conn.execute("DELETE FROM kv_store WHERE namespace = ?", (namespace,))
        conn.execute("DELETE FROM list_store WHERE namespace = ?", (namespace,))
        conn.commit()

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def get_stats(self) -> dict[str, Any]:
        """Get storage statistics for the dashboard."""
        conn = self._get_conn()
        kv_count = conn.execute("SELECT COUNT(*) FROM kv_store").fetchone()[0]
        list_count = conn.execute("SELECT COUNT(*) FROM list_store").fetchone()[0]
        namespaces = conn.execute("SELECT DISTINCT namespace FROM kv_store").fetchall()
        return {
            "kv_entries": kv_count,
            "list_entries": list_count,
            "namespaces": [r[0] for r in namespaces],
            "db_path": self._db_path,
        }

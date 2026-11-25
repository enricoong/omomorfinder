"""
Two-level cache: an in-memory LRU in front of a persistent SQLite store.

Every network result (HTTP bodies, DNS answers, RDAP/WHOIS records, API
responses) goes through this cache so that repeated scans of the same target
generate almost no traffic and frequently used data is served from RAM.
Values are stored as JSON metadata plus an optional binary blob; pickle is
deliberately avoided so a tampered cache file can never execute code.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

_MISSING = object()


class LRUCache:
    """
    Minimal thread-safe LRU cache with per-entry expiry.

    Args (constructor):
        capacity (int): Maximum number of entries kept in memory.
    """

    def __init__(self, capacity: int = 4096) -> None:
        """
        Create an empty LRU cache.

        Args:
            capacity (int): Maximum number of entries kept in memory.
        Returns:
            None
        """
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._capacity = capacity
        self._lock = threading.Lock()

    def get(self, key: str) -> Any:
        """
        Return a cached value, refreshing its LRU position.

        Args:
            key (str): Cache key.
        Returns:
            Any: The stored value, or the module sentinel `_MISSING` when the
            key is absent or expired.
        """
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return _MISSING
            expires, value = item
            if expires < time.time():
                del self._data[key]
                return _MISSING
            self._data.move_to_end(key)
            return value

    def set(self, key: str, value: Any, ttl: float) -> None:
        """
        Store a value, evicting the least recently used entry when full.

        Args:
            key (str): Cache key.
            value (Any): Value to keep in memory.
            ttl (float): Lifetime in seconds.
        Returns:
            None
        """
        with self._lock:
            self._data[key] = (time.time() + ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self._capacity:
                self._data.popitem(last=False)


class Cache:
    """
    Persistent JSON/blob cache backed by SQLite with an LRU front.

    Namespaces ("http", "dns", "rdap", ...) separate unrelated data. Keys are
    hashed, so arbitrary strings (URLs, queries) are accepted.

    Args (constructor):
        path (Path): SQLite database file.
        enabled (bool): When False, reads always miss (writes still happen,
            so a "--no-cache" run refreshes the cache).
    """

    def __init__(self, path: Path, enabled: bool = True) -> None:
        """
        Open (or create) the SQLite cache database.

        Args:
            path (Path): Location of the database file.
            enabled (bool): Whether reads are allowed to hit the cache.
        Returns:
            None
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.enabled = enabled
        self.memory = LRUCache(8192)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS kv ("
            " ns TEXT NOT NULL, key TEXT NOT NULL, meta TEXT, blob BLOB,"
            " expires REAL NOT NULL, PRIMARY KEY (ns, key))"
        )
        self.hits = 0
        self.misses = 0

    @staticmethod
    def make_key(*parts: Any) -> str:
        """
        Build a stable hashed key from arbitrary parts.

        Args:
            *parts (Any): Values that identify the cached item; they are
                converted with `repr` and joined.
        Returns:
            str: Hex SHA-256 digest usable as a cache key.
        """
        raw = "\x1f".join(repr(p) for p in parts)
        return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()

    def get(self, ns: str, key: str) -> tuple[Any, bytes | None] | None:
        """
        Fetch a cached entry from memory or disk.

        Args:
            ns (str): Namespace.
            key (str): Key produced by `make_key`.
        Returns:
            tuple[Any, bytes | None] | None: `(meta, blob)` where meta is the
            decoded JSON object, or None on miss / expiry / disabled cache.
        """
        if not self.enabled:
            self.misses += 1
            return None
        mem_key = f"{ns}:{key}"
        value = self.memory.get(mem_key)
        if value is not _MISSING:
            self.hits += 1
            return value
        with self._lock:
            row = self._db.execute(
                "SELECT meta, blob, expires FROM kv WHERE ns=? AND key=?", (ns, key)
            ).fetchone()
        if row is None or row[2] < time.time():
            self.misses += 1
            return None
        try:
            meta = json.loads(row[0]) if row[0] else None
        except json.JSONDecodeError:
            self.misses += 1
            return None
        value = (meta, row[1])
        self.memory.set(mem_key, value, max(1.0, row[2] - time.time()))
        self.hits += 1
        return value

    def set(self, ns: str, key: str, meta: Any, blob: bytes | None, ttl: float) -> None:
        """
        Store an entry in memory and on disk.

        Args:
            ns (str): Namespace.
            key (str): Key produced by `make_key`.
            meta (Any): JSON-serialisable metadata.
            blob (bytes | None): Optional binary payload (e.g. HTTP body).
            ttl (float): Lifetime in seconds.
        Returns:
            None
        """
        expires = time.time() + ttl
        self.memory.set(f"{ns}:{key}", (meta, blob), ttl)
        try:
            payload = json.dumps(meta, default=str)
        except (TypeError, ValueError):
            return
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO kv (ns, key, meta, blob, expires) VALUES (?,?,?,?,?)",
                (ns, key, payload, blob, expires),
            )

    def get_json(self, ns: str, key: str) -> Any:
        """
        Convenience wrapper returning only the JSON metadata.

        Args:
            ns (str): Namespace.
            key (str): Cache key.
        Returns:
            Any: Decoded metadata or None on miss.
        """
        hit = self.get(ns, key)
        return None if hit is None else hit[0]

    def set_json(self, ns: str, key: str, value: Any, ttl: float) -> None:
        """
        Convenience wrapper storing only JSON metadata.

        Args:
            ns (str): Namespace.
            key (str): Cache key.
            value (Any): JSON-serialisable value.
            ttl (float): Lifetime in seconds.
        Returns:
            None
        """
        self.set(ns, key, value, None, ttl)

    def purge_expired(self) -> int:
        """
        Delete expired rows from the disk store.

        Returns:
            int: Number of deleted rows.
        """
        with self._lock:
            cur = self._db.execute("DELETE FROM kv WHERE expires < ?", (time.time(),))
            return cur.rowcount

    def clear(self) -> None:
        """
        Remove every cached entry (memory and disk).

        Returns:
            None
        """
        with self._lock:
            self._db.execute("DELETE FROM kv")
        self.memory = LRUCache(8192)

    def close(self) -> None:
        """
        Close the SQLite connection after purging expired rows.

        Returns:
            None
        """
        try:
            self.purge_expired()
            self._db.close()
        except sqlite3.Error:
            pass

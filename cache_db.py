"""SQLite cache (cache.db) shared by the whole pipeline.

Two tables, both purely derived data (safe to delete at any time):

* ``function_map``  - advisory ID + package  ->  vulnerable functions
                      (so diffs are not re-fetched and the LLM is not re-called).
* ``library_graph`` - package + version      ->  static call graph of the library
                      (so popular packages are downloaded/parsed only once).
"""

from __future__ import annotations

import json
import re
import sqlite3
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = 1


def normalize_package(name: str) -> str:
    """PEP 503 normalisation so 'PyYAML', 'pyyaml' and 'Py_YAML' share a cache key."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CacheDB:
    """Thin wrapper around a local SQLite file."""

    def __init__(self, path: Path | str = "cache.db") -> None:
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self._init_schema()

    # ------------------------------------------------------------------ setup
    def _init_schema(self) -> None:
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, SCHEMA_VERSION):
            # Layout from another tool version. It is only a cache: start fresh.
            self.conn.executescript(
                "DROP TABLE IF EXISTS function_map; DROP TABLE IF EXISTS library_graph;"
            )
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS function_map (
                advisory_id TEXT NOT NULL,
                package     TEXT NOT NULL,
                record      TEXT NOT NULL,          -- JSON (see Resolution.to_dict)
                created_at  TEXT NOT NULL,
                PRIMARY KEY (advisory_id, package)
            );
            CREATE TABLE IF NOT EXISTS library_graph (
                package    TEXT NOT NULL,
                version    TEXT NOT NULL,
                graph      BLOB NOT NULL,           -- zlib-compressed JSON
                created_at TEXT NOT NULL,
                PRIMARY KEY (package, version)
            );
            """
        )
        self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.conn.commit()

    # ----------------------------------------------------------- function map
    def get_function_map(self, advisory_id: str, package: str) -> Optional[dict[str, Any]]:
        row = self.conn.execute(
            "SELECT record FROM function_map WHERE advisory_id = ? AND package = ?",
            (advisory_id, normalize_package(package)),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def put_function_map(self, advisory_id: str, package: str, record: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO function_map (advisory_id, package, record, created_at) "
            "VALUES (?, ?, ?, ?)",
            (advisory_id, normalize_package(package), json.dumps(record), _utc_now()),
        )
        self.conn.commit()

    # ---------------------------------------------------------- library graph
    def get_library_graph(self, package: str, version: str) -> Optional[dict[str, Any]]:
        row = self.conn.execute(
            "SELECT graph FROM library_graph WHERE package = ? AND version = ?",
            (normalize_package(package), version),
        ).fetchone()
        return json.loads(zlib.decompress(row[0]).decode("utf-8")) if row else None

    def put_library_graph(self, package: str, version: str, graph: dict[str, Any]) -> None:
        blob = zlib.compress(json.dumps(graph, separators=(",", ":")).encode("utf-8"), 6)
        self.conn.execute(
            "INSERT OR REPLACE INTO library_graph (package, version, graph, created_at) "
            "VALUES (?, ?, ?, ?)",
            (normalize_package(package), version, blob, _utc_now()),
        )
        self.conn.commit()

    # -------------------------------------------------------------- lifecycle
    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "CacheDB":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
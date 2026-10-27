from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from .models import FileEntry, SnapshotInfo

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    rel_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256 TEXT,
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_id, rel_path)
);
CREATE INDEX IF NOT EXISTS idx_entries_hash ON entries(snapshot_id, sha256);
"""

_COLS = "rel_path, size, mtime_ns, sha256, status, error"


def default_db_path() -> Path:
    return Path.home() / ".hashvault" / "vault.db"


class Vault:
    def __init__(self, path: str | Path):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Vault:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def create_snapshot(self, root: str, label: str = "") -> int:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        cur = self.conn.execute(
            "INSERT INTO snapshots (root, label, created_at) VALUES (?, ?, ?)",
            (root, label, now),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def add_entries(self, snapshot_id: int, entries: Iterable[FileEntry]) -> None:
        self.conn.executemany(
            f"INSERT OR REPLACE INTO entries (snapshot_id, {_COLS}) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                (snapshot_id, e.rel_path, e.size, e.mtime_ns, e.sha256, e.status, e.error)
                for e in entries
            ),
        )
        self.conn.commit()

    def delete_snapshot(self, snapshot_id: int) -> None:
        self.conn.execute("DELETE FROM snapshots WHERE id = ?", (snapshot_id,))
        self.conn.commit()

    def list_snapshots(self) -> list[SnapshotInfo]:
        return [self._info(r) for r in self.conn.execute(self._info_sql() + " ORDER BY s.id")]

    def get_snapshot(self, snapshot_id: int) -> SnapshotInfo:
        row = self.conn.execute(self._info_sql("WHERE s.id = ?"), (snapshot_id,)).fetchone()
        if row is None:
            raise KeyError(f"no snapshot with id {snapshot_id}")
        return self._info(row)

    def entries(self, snapshot_id: int) -> list[FileEntry]:
        self.get_snapshot(snapshot_id)
        rows = self.conn.execute(
            f"SELECT {_COLS} FROM entries WHERE snapshot_id = ? ORDER BY rel_path",
            (snapshot_id,),
        )
        return [FileEntry(*r) for r in rows]

    @staticmethod
    def _info_sql(where: str = "") -> str:
        return (
            "SELECT s.id, s.root, s.label, s.created_at, COUNT(e.rel_path),"
            " COALESCE(SUM(e.size), 0),"
            " COALESCE(SUM(e.status IN ('error', 'unstable')), 0)"
            " FROM snapshots s LEFT JOIN entries e ON e.snapshot_id = s.id"
            f" {where} GROUP BY s.id"
        )

    @staticmethod
    def _info(row) -> SnapshotInfo:
        return SnapshotInfo(*row)

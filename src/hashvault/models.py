from __future__ import annotations

from dataclasses import dataclass

STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_SYMLINK = "symlink"
STATUS_UNSTABLE = "unstable"


@dataclass(frozen=True)
class FileEntry:
    rel_path: str
    size: int
    mtime_ns: int
    sha256: str | None
    status: str
    error: str = ""


@dataclass(frozen=True)
class SnapshotInfo:
    id: int
    root: str
    label: str
    created_at: str
    file_count: int
    total_bytes: int
    error_count: int


@dataclass(frozen=True)
class Change:
    rel_path: str
    old: FileEntry | None
    new: FileEntry | None


@dataclass
class Comparison:
    added: list[Change]
    removed: list[Change]
    modified: list[Change]
    unchanged: list[Change]
    unverifiable: list[Change]

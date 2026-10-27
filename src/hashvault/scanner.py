from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .db import Vault
from .models import STATUS_ERROR, STATUS_OK, STATUS_SYMLINK, STATUS_UNSTABLE, FileEntry

CHUNK = 1024 * 1024
LARGE_FILE_COUNT = 10_000
LARGE_TOTAL_BYTES = 5 * 1024**3

# NTFS junctions show up as reparse points with this tag
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003

# progress(files_done, current_rel_path)
ProgressFn = Callable[[int, str], None]


class ScanCancelled(Exception):
    pass


@dataclass(frozen=True)
class Estimate:
    files: int
    total_bytes: int
    truncated: bool  # counting stopped early at the cap

    @property
    def is_large(self) -> bool:
        return (
            self.truncated
            or self.files >= LARGE_FILE_COUNT
            or self.total_bytes >= LARGE_TOTAL_BYTES
        )

    def describe(self) -> str:
        more = "+" if self.truncated else ""
        return f"{self.files}{more} files, {self.total_bytes / 1024**2:.1f}{more} MiB"


def _is_link(entry: os.DirEntry) -> bool:
    # DirEntry.is_symlink() is False for junctions on Windows
    if entry.is_symlink():
        return True
    st = entry.stat(follow_symlinks=False)
    return getattr(st, "st_reparse_tag", 0) == IO_REPARSE_TAG_MOUNT_POINT


def _walk(root: Path, cancel: threading.Event | None) -> Iterator[os.DirEntry | OSError]:
    # yields non-directories (links included, never followed) and OSErrors for unreadable dirs
    stack = [root]
    while stack:
        if cancel is not None and cancel.is_set():
            raise ScanCancelled
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                children = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            yield exc if exc.filename else OSError(exc.errno, exc.strerror, str(d))
            continue
        for child in children:
            try:
                if child.is_dir(follow_symlinks=False) and not _is_link(child):
                    stack.append(Path(child.path))
                else:
                    yield child
            except OSError as exc:
                yield OSError(exc.errno, exc.strerror, child.path)


def estimate(root: str | Path, cap: int | None = None) -> Estimate:
    cap = LARGE_FILE_COUNT if cap is None else cap
    files = total = 0
    for item in _walk(Path(root), None):
        if isinstance(item, OSError):
            continue
        try:
            st = item.stat(follow_symlinks=False)
        except OSError:
            continue
        files += 1
        total += st.st_size
        if files >= cap:
            return Estimate(files, total, truncated=True)
    return Estimate(files, total, truncated=False)


def hash_file(path: str | Path) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def _entry_for(item: os.DirEntry, rel: str) -> FileEntry:
    try:
        st = item.stat(follow_symlinks=False)
    except OSError as exc:  # vanished between listing and stat
        return FileEntry(rel, 0, 0, None, STATUS_ERROR, _fmt(exc))
    if _is_link(item):
        try:
            target = os.readlink(item.path)
        except OSError:
            target = ""
        return FileEntry(rel, 0, st.st_mtime_ns, None, STATUS_SYMLINK, f"-> {target}")
    if not item.is_file(follow_symlinks=False):
        return FileEntry(rel, st.st_size, st.st_mtime_ns, None, STATUS_ERROR, "not a regular file")
    try:
        digest, n = hash_file(item.path)
        after = os.stat(item.path, follow_symlinks=False)
    except OSError as exc:
        return FileEntry(rel, st.st_size, st.st_mtime_ns, None, STATUS_ERROR, _fmt(exc))
    if (after.st_size, after.st_mtime_ns) != (st.st_size, st.st_mtime_ns) or n != st.st_size:
        return FileEntry(
            rel,
            after.st_size,
            after.st_mtime_ns,
            None,
            STATUS_UNSTABLE,
            "file changed while being read",
        )
    return FileEntry(rel, st.st_size, st.st_mtime_ns, digest, STATUS_OK)


def _fmt(exc: OSError) -> str:
    return exc.strerror or type(exc).__name__


def scan(
    root: str | Path,
    vault: Vault,
    label: str = "",
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
) -> int:
    # a cancelled or failed scan deletes its partial snapshot
    root_path = Path(root)
    if not root_path.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    root_path = root_path.resolve()
    snap = vault.create_snapshot(str(root_path), label)
    batch: list[FileEntry] = []
    done = 0
    try:
        for item in _walk(root_path, cancel):
            if isinstance(item, OSError):
                rel = os.path.relpath(item.filename or str(root_path), root_path)
                entry = FileEntry(rel, 0, 0, None, STATUS_ERROR, _fmt(item))
            else:
                rel = os.path.relpath(item.path, root_path)
                entry = _entry_for(item, rel)
            batch.append(entry)
            done += 1
            if progress:
                progress(done, rel)
            if len(batch) >= 500:
                vault.add_entries(snap, batch)
                batch.clear()
        vault.add_entries(snap, batch)
    except BaseException:
        vault.delete_snapshot(snap)
        raise
    return snap

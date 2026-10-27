from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from .models import Comparison, FileEntry

ENTRY_FIELDS = ["rel_path", "size", "mtime_ns", "sha256", "status", "error"]
CATEGORIES = ("added", "removed", "modified", "unchanged", "unverifiable")


def _cell(value) -> str:
    # stop spreadsheets from running file names like =CMD(...)
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _write_csv(path: str | Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for row in rows:
            w.writerow([_cell(v) for v in row])


def _write_json(path: str | Path, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def export_entries(entries: list[FileEntry], path: str | Path, fmt: str) -> None:
    if fmt == "json":
        _write_json(path, [asdict(e) for e in entries])
    elif fmt == "csv":
        _write_csv(path, ENTRY_FIELDS, [[getattr(e, k) for k in ENTRY_FIELDS] for e in entries])
    else:
        raise ValueError(f"unknown format: {fmt!r} (use 'csv' or 'json')")


def export_duplicates(groups: dict[str, list[FileEntry]], path: str | Path, fmt: str) -> None:
    if fmt == "json":
        _write_json(
            path,
            [
                {"sha256": h, "count": len(g), "size": g[0].size, "paths": [e.rel_path for e in g]}
                for h, g in groups.items()
            ],
        )
    elif fmt == "csv":
        _write_csv(
            path,
            ["sha256", "size", "rel_path"],
            [[h, e.size, e.rel_path] for h, g in groups.items() for e in g],
        )
    else:
        raise ValueError(f"unknown format: {fmt!r} (use 'csv' or 'json')")


def export_comparison(cmp: Comparison, path: str | Path, fmt: str) -> None:
    def side(e: FileEntry | None) -> dict:
        return {"sha256": e.sha256, "size": e.size} if e else {"sha256": None, "size": None}

    flat = [
        (cat, c.rel_path, side(c.old), side(c.new)) for cat in CATEGORIES for c in getattr(cmp, cat)
    ]
    if fmt == "json":
        _write_json(
            path,
            {
                cat: [
                    {"rel_path": c.rel_path, "old": side(c.old), "new": side(c.new)}
                    for c in getattr(cmp, cat)
                ]
                for cat in CATEGORIES
            },
        )
    elif fmt == "csv":
        _write_csv(
            path,
            ["change", "rel_path", "old_sha256", "new_sha256", "old_size", "new_size"],
            [[cat, p, o["sha256"], n["sha256"], o["size"], n["size"]] for cat, p, o, n in flat],
        )
    else:
        raise ValueError(f"unknown format: {fmt!r} (use 'csv' or 'json')")

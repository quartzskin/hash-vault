from __future__ import annotations

from collections import defaultdict

from .models import STATUS_OK, Change, Comparison, FileEntry


def find_duplicates(entries: list[FileEntry], min_size: int = 1) -> dict[str, list[FileEntry]]:
    # empty files are skipped by default, they all share one hash
    groups: dict[str, list[FileEntry]] = defaultdict(list)
    for e in entries:
        if e.status == STATUS_OK and e.sha256 and e.size >= min_size:
            groups[e.sha256].append(e)
    return {h: g for h, g in sorted(groups.items()) if len(g) > 1}


def compare(old: list[FileEntry], new: list[FileEntry]) -> Comparison:
    # matches by relative path; no hash on either side means unverifiable
    a = {e.rel_path: e for e in old}
    b = {e.rel_path: e for e in new}
    result = Comparison([], [], [], [], [])
    for path in sorted(a.keys() | b.keys()):
        o, n = a.get(path), b.get(path)
        change = Change(path, o, n)
        if o is None:
            result.added.append(change)
        elif n is None:
            result.removed.append(change)
        elif o.sha256 is None or n.sha256 is None:
            same_meta = (o.status, o.size, o.mtime_ns) == (n.status, n.size, n.mtime_ns)
            if o.status == n.status and o.sha256 is None and n.sha256 is None and same_meta:
                result.unchanged.append(change)
            else:
                result.unverifiable.append(change)
        elif o.sha256 != n.sha256:
            result.modified.append(change)
        else:
            result.unchanged.append(change)
    return result

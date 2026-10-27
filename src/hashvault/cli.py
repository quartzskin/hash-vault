from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, scanner
from .analysis import compare, find_duplicates
from .db import Vault, default_db_path
from .export import export_comparison, export_duplicates, export_entries


def _fmt_for(path: str, force: bool = False) -> str:
    ext = Path(path).suffix.lower().lstrip(".")
    if ext not in ("csv", "json"):
        raise SystemExit(f"error: output file must end in .csv or .json (got {path!r})")
    if Path(path).exists() and not force:
        raise SystemExit(f"error: {path} already exists (use --force to overwrite)")
    return ext


def _confirm_large(root: str, assume_yes: bool) -> bool:
    est = scanner.estimate(root)
    if not est.is_large or assume_yes:
        return True
    print(
        f"Warning: {root} is large ({est.describe()}); hashing reads every file.", file=sys.stderr
    )
    if not sys.stdin.isatty():
        print("Refusing without confirmation; re-run with --yes.", file=sys.stderr)
        return False
    return input("Continue? [y/N] ").strip().lower() in ("y", "yes")


def _cmd_scan(args, vault: Vault) -> int:
    if not Path(args.directory).is_dir():
        print(f"error: not a directory: {args.directory}", file=sys.stderr)
        return 2
    if not _confirm_large(args.directory, args.yes):
        return 2
    snap = scanner.scan(args.directory, vault, args.label)
    info = vault.get_snapshot(snap)
    print(
        f"snapshot {info.id}: {info.file_count} entries, {info.total_bytes} bytes, "
        f"{info.error_count} errors"
    )
    return 0


def _cmd_list(args, vault: Vault) -> int:
    for s in vault.list_snapshots():
        print(
            f"{s.id}\t{s.created_at}\t{s.file_count} files\t{s.error_count} errors\t"
            f"{s.root}\t{s.label}"
        )
    return 0


def _cmd_duplicates(args, vault: Vault) -> int:
    fmt = _fmt_for(args.export, args.force) if args.export else None
    groups = find_duplicates(vault.entries(args.snapshot))
    for h, g in groups.items():
        print(f"{h}  ({len(g)} files, {g[0].size} bytes each)")
        for e in g:
            print(f"    {e.rel_path}")
    if not groups:
        print("no duplicates")
    if args.export:
        export_duplicates(groups, args.export, fmt)
    return 0


def _cmd_compare(args, vault: Vault) -> int:
    fmt = _fmt_for(args.export, args.force) if args.export else None
    cmp = compare(vault.entries(args.old), vault.entries(args.new))
    for cat in ("added", "removed", "modified", "unverifiable"):
        for c in getattr(cmp, cat):
            print(f"{cat.upper():<12} {c.rel_path}")
    print(
        f"added={len(cmp.added)} removed={len(cmp.removed)} modified={len(cmp.modified)} "
        f"unchanged={len(cmp.unchanged)} unverifiable={len(cmp.unverifiable)}"
    )
    if args.export:
        export_comparison(cmp, args.export, fmt)
    changed = cmp.added or cmp.removed or cmp.modified
    return 1 if changed and args.exit_code else 0


def _cmd_export(args, vault: Vault) -> int:
    fmt = _fmt_for(args.output, args.force)
    export_entries(vault.entries(args.snapshot), args.output, fmt)
    return 0


def _cmd_gui(args, vault: Vault) -> int:
    vault.close()
    from .ui.app import run

    return run(args.db)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hashvault", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--db", default=str(default_db_path()), help="SQLite database path")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="hash a directory into a new snapshot")
    s.add_argument("directory")
    s.add_argument("--label", default="")
    s.add_argument("--yes", action="store_true", help="skip the large-directory confirmation")
    s.set_defaults(func=_cmd_scan)

    sub.add_parser("list", help="list snapshots").set_defaults(func=_cmd_list)

    d = sub.add_parser("duplicates", help="show duplicate files in a snapshot")
    d.add_argument("snapshot", type=int)
    d.add_argument("--export", metavar="FILE", help=".csv or .json")
    d.add_argument("--force", action="store_true", help="overwrite an existing export file")
    d.set_defaults(func=_cmd_duplicates)

    c = sub.add_parser("compare", help="compare two snapshots")
    c.add_argument("old", type=int)
    c.add_argument("new", type=int)
    c.add_argument("--export", metavar="FILE", help=".csv or .json")
    c.add_argument("--force", action="store_true", help="overwrite an existing export file")
    c.add_argument("--exit-code", action="store_true", help="exit 1 if anything changed")
    c.set_defaults(func=_cmd_compare)

    e = sub.add_parser("export", help="export a snapshot")
    e.add_argument("snapshot", type=int)
    e.add_argument("output", help=".csv or .json")
    e.add_argument("--force", action="store_true", help="overwrite an existing file")
    e.set_defaults(func=_cmd_export)

    sub.add_parser("gui", help="launch the desktop GUI").set_defaults(func=_cmd_gui)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with Vault(args.db) as vault:
            return args.func(args, vault)
    except KeyError as exc:
        print(f"error: {exc.args[0]}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

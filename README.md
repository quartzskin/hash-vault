# Hash Vault

Small tool I wrote to keep track of what changed in a folder. It hashes every file
(SHA-256), saves the result as a snapshot in a SQLite file, and can then show
duplicates or diff two snapshots. There's a CLI and a basic PySide6 GUI.

It only reads the files it scans. The only things it writes are its own database and
any export file you ask for.

## Install

Needs Python 3.10+. I develop on Windows.

```
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

```
hashvault scan C:\some\dir --label before
hashvault scan C:\some\dir --label after
hashvault list
hashvault compare 1 2 --export changes.csv
hashvault duplicates 2 --export dups.json
hashvault export 2 snapshot.json
hashvault gui
```

The database lives in `~\.hashvault\vault.db` unless you pass `--db`. Exports are
CSV or JSON depending on the file extension, and won't overwrite an existing file
unless you add `--force`. `compare --exit-code` exits 1 if anything changed. Big
directories (10,000+ files or 5 GiB+) ask for confirmation first; pass `--yes` to skip it.

Symlinks and junctions are recorded as links and not followed. Unreadable files and
files that change while being hashed are recorded with a status instead of stopping
the scan.

## Tests

```
pytest -q
ruff check .
ruff format --check .
```

Set `QT_QPA_PLATFORM=offscreen` if you run the GUI test without a display.

## Limits

- Compare matches by path only, so a rename shows up as one removed and one added.
- Every scan rereads every file, no incremental rescans.
- The "is this big" check walks up to 10,000 files first, which is slow on huge trees.
- Junction detection only looks for NTFS mount points. Other reparse points and
  alternate data streams aren't handled specially.
- The database isn't signed, so this isn't tamper-proof.
- The GUI is bare bones.

## License

MIT

import csv
import json

import pytest

from hashvault import scanner
from hashvault.analysis import compare, find_duplicates
from hashvault.export import export_comparison, export_duplicates, export_entries
from hashvault.models import FileEntry


def test_unknown_snapshot_raises(vault):
    with pytest.raises(KeyError):
        vault.entries(999)
    with pytest.raises(KeyError):
        vault.get_snapshot(999)


def test_delete_snapshot_cascades(vault, tree):
    snap = scanner.scan(tree, vault)
    vault.delete_snapshot(snap)
    assert vault.list_snapshots() == []
    assert vault.conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0] == 0


def test_export_entries_roundtrip(vault, tree, tmp_path):
    snap = scanner.scan(tree, vault)
    entries = vault.entries(snap)
    export_entries(entries, tmp_path / "e.json", "json")
    data = json.loads((tmp_path / "e.json").read_text(encoding="utf-8"))
    assert {d["rel_path"] for d in data} == {e.rel_path for e in entries}
    export_entries(entries, tmp_path / "e.csv", "csv")
    rows = list(csv.DictReader((tmp_path / "e.csv").open(encoding="utf-8")))
    assert len(rows) == len(entries) and rows[0]["sha256"]


def test_export_bad_format(tmp_path):
    with pytest.raises(ValueError):
        export_entries([], tmp_path / "x.xml", "xml")


def test_csv_formula_injection_neutralised(tmp_path):
    e = FileEntry('=HYPERLINK("http://x")', 1, 1, "h", "ok")
    export_entries([e], tmp_path / "e.csv", "csv")
    row = next(csv.DictReader((tmp_path / "e.csv").open(encoding="utf-8")))
    assert row["rel_path"].startswith("'=")


def test_export_duplicates_and_comparison(vault, tree, tmp_path):
    s1 = scanner.scan(tree, vault)
    (tree / "a.txt").write_text("zzz")
    s2 = scanner.scan(tree, vault)
    export_duplicates(find_duplicates(vault.entries(s1)), tmp_path / "d.json", "json")
    d = json.loads((tmp_path / "d.json").read_text(encoding="utf-8"))
    assert d[0]["count"] == 2
    cmp = compare(vault.entries(s1), vault.entries(s2))
    export_comparison(cmp, tmp_path / "c.csv", "csv")
    rows = list(csv.DictReader((tmp_path / "c.csv").open(encoding="utf-8")))
    assert [r["change"] for r in rows].count("modified") == 1
    export_comparison(cmp, tmp_path / "c.json", "json")
    assert len(json.loads((tmp_path / "c.json").read_text(encoding="utf-8"))["modified"]) == 1

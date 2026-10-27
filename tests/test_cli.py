import json

from hashvault import cli


def run(db, *args):
    return cli.main(["--db", str(db), *args])


def test_scan_compare_export(tree, tmp_path, capsys):
    db = tmp_path / "v.db"
    assert run(db, "scan", str(tree)) == 0
    (tree / "a.txt").write_text("different")
    assert run(db, "scan", str(tree)) == 0
    assert run(db, "compare", "1", "2", "--exit-code", "--export", str(tmp_path / "c.json")) == 1
    out = capsys.readouterr().out
    assert "MODIFIED" in out and "modified=1" in out
    assert json.loads((tmp_path / "c.json").read_text(encoding="utf-8"))["modified"]
    assert run(db, "duplicates", "1") == 0
    assert run(db, "export", "2", str(tmp_path / "s.csv")) == 0
    assert run(db, "list") == 0


def test_scan_missing_dir(tmp_path, capsys):
    assert run(tmp_path / "v.db", "scan", str(tmp_path / "nope")) == 2
    assert "not a directory" in capsys.readouterr().err


def test_unknown_snapshot(tmp_path, capsys):
    assert run(tmp_path / "v.db", "compare", "1", "2") == 2
    assert "no snapshot" in capsys.readouterr().err


def test_bad_export_extension(tree, tmp_path):
    import pytest

    db = tmp_path / "v.db"
    run(db, "scan", str(tree))
    with pytest.raises(SystemExit):
        run(db, "export", "1", str(tmp_path / "x.txt"))


def test_large_scan_refused_without_yes(tree, tmp_path, monkeypatch, capsys):
    from hashvault import scanner

    monkeypatch.setattr(scanner, "LARGE_FILE_COUNT", 2)
    db = tmp_path / "v.db"
    assert run(db, "scan", str(tree)) == 2
    assert "Refusing" in capsys.readouterr().err
    assert run(db, "scan", str(tree), "--yes") == 0


def test_export_refuses_to_overwrite(tree, tmp_path, capsys):
    import pytest

    db = tmp_path / "v.db"
    run(db, "scan", str(tree))
    out = tmp_path / "s.json"
    out.write_text("keep me")
    with pytest.raises(SystemExit):
        run(db, "export", "1", str(out))
    assert out.read_text() == "keep me"
    with pytest.raises(SystemExit):
        run(db, "compare", "1", "1", "--export", str(out))
    with pytest.raises(SystemExit):
        run(db, "duplicates", "1", "--export", str(out))
    assert out.read_text() == "keep me"
    assert run(db, "export", "1", str(out), "--force") == 0
    assert out.read_text(encoding="utf-8") != "keep me"

import hashlib
import os
import subprocess
import sys
import threading

import pytest

from hashvault import scanner
from hashvault.models import STATUS_ERROR, STATUS_OK, STATUS_SYMLINK


def by_path(vault, snap):
    return {e.rel_path: e for e in vault.entries(snap)}


def test_scan_hashes_correctly(vault, tree):
    snap = scanner.scan(tree, vault)
    e = by_path(vault, snap)
    assert e["a.txt"].sha256 == hashlib.sha256(b"alpha").hexdigest()
    assert e[os.path.join("sub", "c.bin")].status == STATUS_OK
    assert e["empty1"].sha256 == hashlib.sha256(b"").hexdigest()
    assert len(e) == 5


def test_scan_does_not_modify_files(vault, tree):
    before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in tree.rglob("*") if p.is_file()}
    scanner.scan(tree, vault)
    after = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in tree.rglob("*") if p.is_file()}
    assert before == after
    assert {p.name for p in tree.rglob("*")} >= {"a.txt"}  # nothing created beside them


def test_not_a_directory(vault, tmp_path):
    with pytest.raises(NotADirectoryError):
        scanner.scan(tmp_path / "missing", vault)
    f = tmp_path / "f.txt"
    f.write_text("x")
    with pytest.raises(NotADirectoryError):
        scanner.scan(f, vault)


def test_symlink_not_followed(vault, tree, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s")
    try:
        os.symlink(outside, tree / "link_dir", target_is_directory=True)
        os.symlink(tree / "a.txt", tree / "link_file")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this system")
    e = by_path(vault, scanner.scan(tree, vault))
    assert e["link_dir"].status == STATUS_SYMLINK and e["link_dir"].sha256 is None
    assert e["link_file"].status == STATUS_SYMLINK
    assert not any("secret.txt" in p for p in e)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are Windows only")
def test_junction_not_followed(vault, tree, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s")
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(tree / "junc"), str(outside)], capture_output=True
    )
    if made.returncode != 0:
        pytest.skip("could not create a junction")
    e = by_path(vault, scanner.scan(tree, vault))
    assert e["junc"].status == STATUS_SYMLINK
    assert not any("secret.txt" in p for p in e)


def test_unreadable_file_recorded_not_fatal(vault, tree, monkeypatch):
    real = scanner.hash_file

    def flaky(path):
        if str(path).endswith("a.txt"):
            raise PermissionError(13, "Permission denied", str(path))
        return real(path)

    monkeypatch.setattr(scanner, "hash_file", flaky)
    e = by_path(vault, scanner.scan(tree, vault))
    assert e["a.txt"].status == STATUS_ERROR
    assert "denied" in e["a.txt"].error.lower()
    assert e["b.txt"].status == STATUS_OK
    assert vault.list_snapshots()[0].error_count == 1


def test_unreadable_directory_recorded(vault, tree, monkeypatch):
    real = os.scandir

    def fake(path):
        if str(path).endswith("sub"):
            raise PermissionError(13, "Permission denied", str(path))
        return real(path)

    monkeypatch.setattr(scanner.os, "scandir", fake)
    e = by_path(vault, scanner.scan(tree, vault))
    assert e["sub"].status == STATUS_ERROR
    assert "a.txt" in e


def test_vanishing_file(vault, tree, monkeypatch):
    real = scanner.hash_file

    def vanish(path):
        if str(path).endswith("b.txt"):
            os.remove(path)
        return real(path)

    monkeypatch.setattr(scanner, "hash_file", vanish)
    e = by_path(vault, scanner.scan(tree, vault))
    assert e["b.txt"].status == STATUS_ERROR
    assert e["a.txt"].status == STATUS_OK


def test_file_changing_during_read_is_unstable(vault, tree, monkeypatch):
    real = scanner.hash_file

    def grow(path):
        result = real(path)
        if str(path).endswith("a.txt"):
            with open(path, "ab") as f:
                f.write(b"more")
        return result

    monkeypatch.setattr(scanner, "hash_file", grow)
    e = by_path(vault, scanner.scan(tree, vault))
    assert e["a.txt"].status == "unstable" and e["a.txt"].sha256 is None


def test_cancel_discards_partial_snapshot(vault, tree):
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(scanner.ScanCancelled):
        scanner.scan(tree, vault, cancel=cancel)
    assert vault.list_snapshots() == []


def test_estimate_large_detection(tree):
    est = scanner.estimate(tree)
    assert est.files == 5 and not est.is_large
    capped = scanner.estimate(tree, cap=2)
    assert capped.truncated and capped.is_large


def test_hash_file_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        scanner.hash_file(tmp_path / "nope")

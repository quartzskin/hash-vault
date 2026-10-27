from hashvault import scanner
from hashvault.analysis import compare, find_duplicates
from hashvault.models import FileEntry


def test_duplicates(vault, tree):
    snap = scanner.scan(tree, vault)
    groups = find_duplicates(vault.entries(snap))
    assert len(groups) == 1  # empty files excluded by default
    assert sorted(e.rel_path for e in next(iter(groups.values()))) == ["a.txt", "b.txt"]
    with_empty = find_duplicates(vault.entries(snap), min_size=0)
    assert len(with_empty) == 2


def test_no_duplicates_on_empty_input():
    assert find_duplicates([]) == {}


def test_compare_all_categories(vault, tree):
    old = scanner.scan(tree, vault)
    (tree / "a.txt").write_text("changed!")
    (tree / "b.txt").unlink()
    (tree / "new.txt").write_text("fresh")
    new = scanner.scan(tree, vault)
    c = compare(vault.entries(old), vault.entries(new))
    assert [x.rel_path for x in c.added] == ["new.txt"]
    assert [x.rel_path for x in c.removed] == ["b.txt"]
    assert [x.rel_path for x in c.modified] == ["a.txt"]
    assert len(c.unchanged) == 3
    assert c.unverifiable == []


def test_compare_identical_and_empty():
    c = compare([], [])
    assert not (c.added or c.removed or c.modified or c.unchanged)


def test_touch_without_content_change_is_unchanged():
    a = FileEntry("f", 1, 100, "h", "ok")
    b = FileEntry("f", 1, 999, "h", "ok")
    assert len(compare([a], [b]).unchanged) == 1


def test_missing_hash_is_unverifiable_not_modified():
    ok = FileEntry("f", 1, 1, "h", "ok")
    bad = FileEntry("f", 1, 1, None, "error", "denied")
    c = compare([ok], [bad])
    assert len(c.unverifiable) == 1 and not c.modified

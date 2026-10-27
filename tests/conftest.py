import pytest

from hashvault.db import Vault


@pytest.fixture
def vault(tmp_path):
    with Vault(tmp_path / "vault.db") as v:
        yield v


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "data"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha")
    (root / "b.txt").write_text("alpha")  # duplicate of a.txt
    (root / "sub" / "c.bin").write_bytes(b"\x00\x01\x02")
    (root / "empty1").write_bytes(b"")
    (root / "empty2").write_bytes(b"")
    return root

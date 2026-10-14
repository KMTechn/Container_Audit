"""Facade effects remain fenced at their caller; exact backend bodies cannot hide writes."""
import shutil
from pathlib import Path

import pytest
from tests.test_container_writer_sink_inventory import _load_module, _write_minimal_inventory_fixture

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def atomic_inventory_root(tmp_path):
    inventory = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "pass\n")
    shutil.copyfile(ROOT / "atomic_replace.py", tmp_path / "atomic_replace.py")
    return inventory, tmp_path


def test_atomic_facade_does_not_grant_an_unfenced_caller_permission(atomic_inventory_root):
    inventory, root = atomic_inventory_root
    path = root / "publication_consumer.py"
    path.write_text('from atomic_replace import atomic_replace\ndef write(a,b):\n    atomic_replace(a,b)\nif __name__ == "__main__":\n    write("prepared","control")\n', encoding="utf-8")
    payload = inventory.derive_inventory(root)
    assert "publication_consumer.write" in {row["node"] for row in payload["uncovered_direct_mutation_functions"]}
    path.write_text('from atomic_replace import atomic_replace\nfrom writer_session_fence import writer_sink\n@writer_sink("auto_update_control")\ndef write(a,b):\n    atomic_replace(a,b)\nif __name__ == "__main__":\n    write("prepared","control")\n', encoding="utf-8")
    payload = inventory.derive_inventory(root)
    assert "publication_consumer.write" not in {row["node"] for row in payload["uncovered_direct_mutation_functions"]}
    assert any(row["caller"] == "publication_consumer.write" for row in payload["atomic_replacement_forwarding"])


@pytest.mark.parametrize("mutation", ["body", "non_call", "private_backend"])
def test_atomic_inventory_rejects_facade_drift_and_escaping_references(atomic_inventory_root, mutation):
    inventory, root = atomic_inventory_root
    if mutation == "body":
        path = root / "atomic_replace.py"
        path.write_text(path.read_text(encoding="utf-8") + '\ndef extra(a,b):\n    os.replace(a,b)\n', encoding="utf-8")
    elif mutation == "non_call":
        (root / "publication_consumer.py").write_text('from atomic_replace import atomic_replace\nleaked = atomic_replace\n', encoding="utf-8")
    else:
        (root / "publication_consumer.py").write_text('from atomic_replace import _replace_once\ndef write(a,b):\n    _replace_once(a,b,False)\n', encoding="utf-8")
    with pytest.raises(inventory.InventoryError):
        inventory.derive_inventory(root)

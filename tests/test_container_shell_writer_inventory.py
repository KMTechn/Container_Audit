"""Pinned shell delegation fails closed when either the kit or the CA guard drifts."""
import shutil
from pathlib import Path

import pytest

from tests.test_container_writer_sink_inventory import _load_module, _write_minimal_inventory_fixture

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def shell_inventory_root(tmp_path):
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "def main():\n    return 0\n")
    for name in [*module.SHELL_KIT_PYTHON_SHA256, "shell/SHELL-READY-v3.16.json", "ca_screen_bridge.py"]:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    return module, tmp_path


def test_pinned_shell_mutations_are_all_in_one_admitted_module(shell_inventory_root):
    module, root = shell_inventory_root
    payload = module.derive_inventory(root)
    descriptor = payload["shell_kit_delegated_fence"]
    assert descriptor["ready_version"] == "v3.16.2"
    assert descriptor["writer_source"] == "screen_shell_fileio"
    mutations = [row for row in payload["closure_direct_mutation_functions"] if row["file"].startswith("shell/")]
    assert mutations
    assert {row["file"] for row in mutations} == {"shell/shell_fileio.py"}
    assert {row["coverage_status"] for row in mutations} == {"covered"}
    assert {row["decorated_source"] for row in mutations} == {"screen_shell_fileio"}
    assert {row["node"].rsplit(".", 1)[1] for row in mutations} == set(module.SHELL_KIT_WRITE_SITES)


@pytest.mark.parametrize("drift", ["bytes", "extra", "missing", "installation", "admission", "ready", "marker_guard"])
def test_shell_delegation_rejects_kit_and_app_fence_drift(shell_inventory_root, drift):
    module, root = shell_inventory_root
    if drift == "bytes":
        path = root / "shell/shell_fileio.py"
        path.write_bytes(path.read_bytes() + b"\n# drift\n")
    elif drift == "extra":
        (root / "shell/extra.py").write_text("def write(path):\n    path.write_bytes(b'unsafe')\n", encoding="utf-8")
    elif drift == "missing":
        (root / "shell/sound.py").unlink()
    elif drift == "ready":
        path = root / "shell/SHELL-READY-v3.16.json"
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        path = root / "ca_screen_bridge.py"
        source = path.read_text(encoding="utf-8")
        if drift == "installation":
            changed = source.replace("write_guard=admission_write_guard", "write_guard=None")
        elif drift == "marker_guard":
            changed = source.replace("write_guard=admission_write_guard)\n                if not use_web:",
                                     "write_guard=None)\n                if not use_web:")
        else:
            changed = source.replace('return writer_admission("screen_shell_fileio")', "return None")
        assert changed != source
        path.write_text(changed, encoding="utf-8")
    with pytest.raises(module.InventoryError):
        module.derive_inventory(root)

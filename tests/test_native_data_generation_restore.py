"""Native code restore after actual isolated onboarding must retain new code."""
import json
from pathlib import Path

from tests.test_canonical_installation_callers import _distinct_replacement, _public_restore
from tests.test_canonical_portable_uninstall import (
    _assert_one_live_relay, _assert_preserved_and_released, _install,
    _launch_relay, _live_preimage, _setup, _tree,
)


def test_public_restore_after_data_open_retains_new_code_and_runtime(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    _distinct_replacement(source)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        replaced = _install(tmp_path, env, source, install)
        assert replaced.returncode == 0, replaced.stderr
        replacement = json.loads((tmp_path / "reinstall-audit.json").read_text(encoding="utf-8-sig"))["code_replacement"]
        receipt = Path(replacement["receipt_path"])
        receipt_before = receipt.read_bytes()
        new_code = _tree(install)
        registry_before = (tmp_path / "registry.json").read_bytes()
        _, runtime_before = _assert_one_live_relay(tmp_path, env)
        local = Path(env["LOCALAPPDATA"])
        markers = [local / "KMTech/ContainerAudit/data-generation.json",
                   *list((local / "KMTech/DirectSync/container_audit/control/writer-session/data-generation").glob("*.json"))]
        assert len(markers) == 2 and all(path.is_file() for path in markers)
        marker_before = {path: path.read_bytes() for path in markers}

        refused = _public_restore(tmp_path, env, source, install, receipt, replacement["receipt_sha256"])

        assert refused.returncode != 0
        assert "자료 판을 확인할 수 없어" in refused.stderr + refused.stdout
        assert _tree(install) == new_code and _tree(source) == before["source"]
        assert receipt.read_bytes() == receipt_before
        assert {path: path.read_bytes() for path in markers} == marker_before
        assert (tmp_path / "registry.json").read_bytes() == registry_before
        _assert_preserved_and_released(env, protected)
        launches, runtime = _assert_one_live_relay(tmp_path, env)
        assert runtime["CommandLine"] == runtime_before["CommandLine"]
        assert launches[-1]["fence_active"] is False

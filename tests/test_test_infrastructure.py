"""Exercise process/state isolation required by the ordinary repository test command."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import writer_session_fence as fence
from storage_policy import build_container_audit_storage_paths


def test_default_product_paths_are_per_test_and_writable(tmp_path):
    paths = build_container_audit_storage_paths(
        application_path=str(Path(__file__).resolve().parents[1])
    )
    assert paths.events_dir.is_relative_to(tmp_path)
    paths.events_dir.mkdir(parents=True)
    sentinel = paths.events_dir / "isolation.txt"
    sentinel.write_text("test-owned", encoding="utf-8")
    assert sentinel.read_text(encoding="utf-8") == "test-owned"
    assert Path(os.environ["TEMP"]).is_relative_to(tmp_path)


def test_canonical_writer_mutex_is_denied_before_native_acquisition():
    with pytest.raises(AssertionError, match="canonical writer-admission"):
        fence._acquire_named_mutex(fence.WRITER_MUTEX_NAME, 0)


def test_child_interpreter_observes_the_same_isolated_writer_contract(tmp_path):
    marker = tmp_path / "child-wrote.txt"
    command = """
import json, os
from pathlib import Path
import writer_session_fence as fence
root = fence.canonical_control_root()
name = fence.writer_admission_mutex_name(root)
assert name != fence.WRITER_MUTEX_NAME, 'child isolation hook missing'
assert name == os.environ['KMTECH_TEST_CA_WRITER_MUTEX']
@fence.writer_sink('test_infrastructure_child')
def write():
    Path(os.environ['CA_ISOLATION_MARKER']).write_text('child-owned', encoding='utf-8')
write()
print(json.dumps({'root': str(root), 'mutex': name}))
"""
    environment = dict(os.environ, CA_ISOLATION_MARKER=str(marker))
    child = subprocess.run(
        [sys.executable, "-B", "-c", command], env=environment,
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert child.returncode == 0, child.stderr
    assert not child.stderr
    observation = json.loads(child.stdout)
    assert Path(observation["root"]) == fence.canonical_control_root()
    assert observation["mutex"] == fence.writer_admission_mutex_name(fence.canonical_control_root())
    assert marker.read_text(encoding="utf-8") == "child-owned"

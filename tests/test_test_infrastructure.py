"""Exercise process/state isolation required by the ordinary repository test command."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

import writer_session_fence as fence
from storage_policy import build_container_audit_storage_paths
from tools import run_repository_tests as runner


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
    import tempfile
    with tempfile.TemporaryFile() as temporary:
        temporary.write(b"owned tempfile")
    assert Path(tempfile.gettempdir()).is_relative_to(tmp_path)


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


def _runner_probe(tmp_path, source, *, root_option="--task-root", extra_args=()):
    repository = Path(__file__).resolve().parents[1]
    (tmp_path / "conftest.py").write_text("from tests.conftest import *\n", encoding="utf-8")
    test = tmp_path / "test_probe.py"
    test.write_text(source, encoding="utf-8")
    # The runner budgets installer receipt leaves even for this small probe.
    # Own a short runner root independently of the outer pytest basetemp; an
    # enclosing runner's write boundary still takes precedence when present.
    task_root = Path(os.environ.get("KMTECH_TEST_CA_TASK_ROOT") or
                     os.environ.get("CONTAINER_AUDIT_TEST_TASK_ROOT") or
                     runner.DEFAULT_TASK_ROOT) / "r"
    environment = dict(os.environ, CONTAINER_AUDIT_TEST_TASK_ROOT=str(task_root),
                       PYTEST_ADDOPTS="--invalid-ambient-option",
                       CONTAINER_AUDIT_DATA_ROOT=str(tmp_path / "ambient-data"),
                       CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH=str(tmp_path / "ambient-profile.json"),
                       KM_LOGISTICS_PROFILE_PATH=str(tmp_path / "ambient-machine-profile.json"))
    command = [sys.executable, "-B", str(repository / "tools/run_repository_tests.py")]
    if root_option == "default":
        task_root = runner.DEFAULT_TASK_ROOT.resolve()
        environment.pop("CONTAINER_AUDIT_TEST_TASK_ROOT", None)
        environment.pop("KMTECH_TEST_CA_TASK_ROOT", None)
    elif root_option:
        command += [root_option, str(task_root)]
        environment["CONTAINER_AUDIT_TEST_TASK_ROOT"] = str(tmp_path / "unused-env-root")
    result = subprocess.run(
        [*command, str(test), *extra_args], cwd=repository, env=environment,
        capture_output=True, text=True, check=False, timeout=45,
    )
    assert result.stdout, result.stderr
    observation = json.loads(result.stdout)
    run = Path(observation["evidence_path"])
    assert run.parent == task_root
    assert observation["repository_unchanged"]
    assert observation["new_ignored_artifacts"] == []
    assert not result.stderr
    assert (run / "junit.xml").is_file()
    assert len(run.name) == 8 and int(run.name, 16) >= 0
    assert (run / "t").is_dir()
    record = json.loads((run / "result.json").read_text(encoding="utf-8"))
    assert Path(record["basetemp"]) == run / "p"
    assert record["source_before"] == record["source_after"]
    assert record["source_stable"]
    assert record["source_before"]["head_sha"] == subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
    assert record["source_before"]["dirty"] == bool(subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repository))
    assert record["source_before"]["file_sha256"]["tools/run_repository_tests.py"]
    from datetime import datetime
    assert datetime.fromisoformat(record["started_at_utc"]) <= datetime.fromisoformat(record["finished_at_utc"])
    isolation = json.loads((run / "isolation.json").read_text(encoding="utf-8"))
    assert isolation["remaining_threads"] == []
    return result, observation, run


@pytest.mark.parametrize("root_option", ["default", "--task-root", "--work-root", None])
def test_runner_owns_parent_child_state_and_outputs(tmp_path, root_option):
    source = '''
import os, subprocess, sys, tempfile
from pathlib import Path
from storage_policy import build_container_audit_storage_paths

def test_owned_state(tmp_path):
    root = Path(os.environ["KMTECH_TEST_CA_TASK_ROOT"])
    for name in ("TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "PSModuleAnalysisCachePath"):
        assert Path(os.environ[name]).is_relative_to(root), name
    paths = build_container_audit_storage_paths(application_path=__file__)
    assert paths.data_root.is_relative_to(root)
    assert Path(tempfile.gettempdir()).is_relative_to(tmp_path)
    code = "from tests.test_test_infrastructure import test_child_interpreter_observes_the_same_isolated_writer_contract as check; from pathlib import Path; import sys; check(Path(sys.argv[1]))"
    child = subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path)], capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stdout + child.stderr
'''
    result, observation, run = _runner_probe(
        tmp_path, source, root_option=root_option,
        extra_args=("--basetemp", str(tmp_path / "escaped-temp"),
                    "--junitxml", str(tmp_path / "escaped.xml")),
    )
    assert result.returncode == 0, (run / "stdout.txt").read_text(encoding="utf-8")
    assert observation["outside_write_attempts"] == 0
    assert not (tmp_path / "escaped-temp").exists()
    assert not (tmp_path / "escaped.xml").exists()


def test_runner_rejects_long_root_before_creating_output(tmp_path):
    task_root = tmp_path / ("long-root-" * 10)
    result = subprocess.run(
        [sys.executable, "-B", str(Path(runner.__file__)), "--task-root", str(task_root)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 2
    assert "longest fixture path" in result.stderr
    assert "release-" in result.stderr and "budget 240" in result.stderr
    assert "--task-root D:\\KMTech\\t\\ca" in result.stderr
    assert not task_root.exists()


def test_runner_source_fingerprint_detects_edits_with_unchanged_dirty_status(tmp_path):
    # Synthetic repository: never mutate the checkout while its tests are running.
    source = tmp_path / "fixture.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    for args in (("init",), ("add", "."),
                 ("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                  "-c", "commit.gpgsign=false", "commit", "-m", "synthetic baseline")):
        subprocess.run(["git", *args], cwd=tmp_path, env=env, capture_output=True, check=True)
    clean = runner._source_state(tmp_path, env, runner._repository_state(tmp_path, env)[0])
    source.write_text("VALUE = 2\n", encoding="utf-8")
    dirty = runner._source_state(tmp_path, env, runner._repository_state(tmp_path, env)[0])
    source.write_text("VALUE = 3\n", encoding="utf-8")
    changed = runner._source_state(tmp_path, env, runner._repository_state(tmp_path, env)[0])
    assert not clean["dirty"] and dirty["dirty"] and changed["dirty"]
    assert clean["head_sha"] == dirty["head_sha"] == changed["head_sha"]
    assert dirty["status"] == changed["status"]
    assert clean["file_sha256"] != dirty["file_sha256"] != changed["file_sha256"]
    assert dirty["diff_sha256"] != changed["diff_sha256"]

    # Exercise the result/exit verdict with a native Git write in this synthetic
    # checkout; the real repository and its write boundary are untouched.
    (tmp_path / "tools").mkdir()
    (tmp_path / "tests").mkdir()
    shutil.copyfile(runner.__file__, tmp_path / "tools/run_repository_tests.py")
    shutil.copyfile(Path(__file__).with_name("sitecustomize.py"), tmp_path / "tests/sitecustomize.py")
    (tmp_path / "tests/__init__.py").write_text("", encoding="utf-8")
    patch = "diff --git a/fixture.py b/fixture.py\n--- a/fixture.py\n+++ b/fixture.py\n@@ -1 +1 @@\n-VALUE = 3\n+VALUE = 4\n"
    probe = tmp_path / "tests/test_change.py"
    probe.write_text(
        "import subprocess\ndef test_change():\n"
        f"    subprocess.run(['git', 'apply'], input={patch!r}, text=True, check=True)\n",
        encoding="utf-8",
    )
    task_root = Path(os.environ.get("KMTECH_TEST_CA_TASK_ROOT") or
                     os.environ.get("CONTAINER_AUDIT_TEST_TASK_ROOT") or
                     runner.DEFAULT_TASK_ROOT) / "r"
    result = subprocess.run(
        [sys.executable, "-B", str(tmp_path / "tools/run_repository_tests.py"),
         "--task-root", str(task_root), str(probe)], cwd=tmp_path, env=env,
        capture_output=True, text=True, check=False, timeout=45,
    )
    assert result.stdout, result.stderr
    observation = json.loads(result.stdout)
    assert result.returncode == 1, result.stderr
    assert observation["pytest_exit_code"] == 0
    assert observation["evidence_status"] == "UNPROVEN"
    assert not observation["source_stable"] and not observation["repository_unchanged"]
    assert source.read_text(encoding="utf-8") == "VALUE = 4\n"


@pytest.mark.parametrize("operation", ["file", "sqlite", "sqlite_uri", "child"])
def test_runner_reports_denied_writes_even_when_test_catches_them(tmp_path, operation):
    outside = (Path(__file__).resolve().parents[1] / f".x14-{tmp_path.name}.txt"
               if operation == "file" else tmp_path / "outside.txt")
    assert not outside.exists()
    source = f'''
import subprocess, sys, sqlite3
from pathlib import Path
import pytest

def test_denied():
    target = {str(outside)!r}
    if {operation!r} == "child":
        child = subprocess.run([sys.executable, "-B", "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).mkdir()", target], capture_output=True, text=True, timeout=20)
        assert child.returncode != 0
        assert "test write outside task root" in child.stderr
    else:
        with pytest.raises(AssertionError, match="test write outside task root"):
            if {operation!r} == "sqlite":
                sqlite3.connect(target)
            elif {operation!r} == "sqlite_uri":
                sqlite3.connect(Path(target).as_uri() + "?mode=rwc", uri=True)
            else:
                Path(target).write_text("must not exist")
'''
    result, observation, run = _runner_probe(tmp_path, source)
    assert result.returncode == 1
    assert observation["outside_write_attempts"] == 1
    assert not outside.exists()
    assert "1 passed" in (run / "stdout.txt").read_text(encoding="utf-8")


def test_runner_drains_workers_after_failure_without_explicit_fixture(tmp_path):
    source = '''
from tests.test_tk_serial_ui_lane import FakeTkRoot
from tk_serial_ui_lane import TkSerialUiLane, LaneTask

def test_failure():
    lane = TkSerialUiLane(FakeTkRoot())
    lane.submit(LaneTask("checkpoint", 0, lambda: lane.call_ui_sync(lambda: True), lambda value: None, lambda exc: None))
    assert False, "intentional assertion before close"
'''
    result, observation, run = _runner_probe(tmp_path, source)
    assert result.returncode == 1
    assert observation["outside_write_attempts"] == 0
    assert "1 failed" in (run / "stdout.txt").read_text(encoding="utf-8")


@pytest.mark.parametrize("relative", [".test-runs", ".", ".."])
def test_runner_rejects_source_task_root_before_creating_output(relative):
    repository = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-B", str(repository / "tools/run_repository_tests.py"),
         "--task-root", str(repository / relative)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 2
    assert "test task root must be outside" in result.stderr

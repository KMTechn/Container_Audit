"""Ordinary logon contenders use the operator ACL and preserve launch guards."""
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

import auto_update as updates
from writer_session_fence import WriterFencedError


@pytest.mark.skipif(os.name != "nt", reason="Windows update mutex ACL")
@pytest.mark.parametrize("role", ["gui", "relay"])
def test_native_operator_bootstrap_contends_without_access_denial(tmp_path, role):
    # Both children inherit this ordinary user's real SID and execution context.
    assert not ctypes.windll.shell32.IsUserAnAdmin(), "requires a non-elevated operator"
    sid = updates.current_process_sid()
    repo = Path(updates.__file__).resolve().parent
    app = tmp_path / "current/app"
    app.mkdir(parents=True)
    for source in repo.glob("*.py"):
        shutil.copyfile(source, app / source.name)
    for name in ("vendor", "kmtech_shared"):
        shutil.copytree(repo / name, app / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    control = tmp_path / "update-control"
    control.mkdir()
    policy = control / "policy.json"
    policy.write_text(json.dumps({"operator_sid": sid}), encoding="utf-8")
    original = policy.read_bytes()
    # 9ac3d0a: a contended bootstrap now waits out the update lock (60 s) and
    # then reads the active pointer. Without a confirmed data generation for
    # this version (no operator profile slot here) it must still stop with 20.
    # The holder below therefore keeps the lock past that wait (until release).
    active = control / "active.json"
    active.write_text(json.dumps({"sha": "0" * 40}), encoding="utf-8")
    original_active = active.read_bytes()
    ready, release = tmp_path / "ready", tmp_path / "release"
    source = '''import sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import auto_update as u
assert u.ordinary_user_context(sys.argv[3])
with u.update_lock(Path(sys.argv[2]), sys.argv[3]):
    Path(sys.argv[4]).write_text("held")
    deadline = time.monotonic() + 180
    while not Path(sys.argv[5]).exists() and time.monotonic() < deadline:
        time.sleep(0.01)
'''
    holder = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", source, str(app), str(control),
         sid, str(ready), str(release)], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and holder.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists(), "native operator holder did not acquire the update mutex"
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(app / "auto_update.py"),
             "--bootstrap", "--role", role, "--"],
            capture_output=True, text=True, check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        assert result.returncode == 20, result.stderr
        assert result.stderr == ""
        report = json.loads(result.stdout)
        assert report["reason_code"] == "UPDATE_IN_PROGRESS"
        assert report["guidance"] in updates.SAFE_MESSAGES
        assert holder.poll() is None
        # Returning 20 alone could hide the old overprivileged CreateMutexW call.
        # A direct contender must open the real handle and reach its timed wait.
        with pytest.raises(RuntimeError, match="update mutex ownership is busy or abandoned"):
            with updates.update_lock(control, sid):
                pytest.fail("contender acquired a mutex still owned by the holder")
    finally:
        release.write_text("release")
        _, error = holder.communicate(timeout=20)
        assert holder.returncode == 0, error
    # The same real lock must be available after its owner releases it.
    with updates.update_lock(control, sid):
        assert policy.read_bytes() == original
        assert active.read_bytes() == original_active
    assert sorted(control.iterdir()) == sorted([active, policy])


def test_bootstrap_reports_update_mutex_open_denial(monkeypatch, capsys, tmp_path):
    def denied(*args, **kwargs):
        raise OSError(5, "update mutex cannot be opened")

    monkeypatch.setattr(updates, "_bootstrap", denied)
    assert updates.bootstrap(tmp_path, [], role="relay") == 20
    report = json.loads(capsys.readouterr().out)
    assert report["reason_code"] == "UPDATE_IN_PROGRESS"
    assert report["guidance"] in updates.SAFE_MESSAGES


@pytest.mark.parametrize("error", [
    OSError(5, "update mutex ACL conversion failed"),
    OSError(5, "policy cannot be read"),
    RuntimeError("unrelated startup failure"),
])
def test_bootstrap_preserves_other_startup_errors(monkeypatch, tmp_path, error):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(updates, "_bootstrap", fail)
    with pytest.raises(type(error)) as observed:
        updates.bootstrap(tmp_path, [], role="gui")
    assert observed.value is error


@pytest.mark.parametrize("role", ["gui", "relay"])
def test_support_writer_timeout_does_not_stop_ordinary_launch(monkeypatch, tmp_path, capsys, role):
    launches = []

    def denied(*args, **kwargs):
        raise WriterFencedError("WRITER_GATE_TIMEOUT", "test support writer timeout")

    monkeypatch.setattr(updates, "write_json_durable", denied)
    monkeypatch.setattr(updates, "launch_version", lambda *a, **k: launches.append((a, k)))
    arguments = ["--container-audit-user-relay"] if role == "relay" else []
    control = tmp_path / "update-control"
    assert updates.start_current(control, {"staging_root": str(tmp_path)}, None,
                                 {"sha": "1" * 40}, arguments,
                                 code="UPDATE_TERMINAL_RECOVERED") == 0
    assert len(launches) == 1
    assert launches[0][0] == (control, "1" * 40, arguments)
    assert launches[0][1]["deferred_at"]
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.startswith("CONTAINER_AUDIT_SUPPORT=")
    assert json.loads(captured.out.removeprefix("CONTAINER_AUDIT_SUPPORT="))["reason_code"] == "REPORT_UNAVAILABLE"


def test_support_writer_timeout_preserves_ordinary_recovery_guard(monkeypatch, tmp_path):
    def denied(*args, **kwargs):
        raise WriterFencedError("WRITER_GATE_TIMEOUT", "test support writer timeout")

    recovery_error = ValueError("ordinary recovery refused")

    def refuse(*args, **kwargs):
        raise recovery_error

    def no_launch(*args, **kwargs):
        pytest.fail("ordinary recovery guard was bypassed")

    monkeypatch.setattr(updates, "write_json_durable", denied)
    monkeypatch.setattr(updates, "assert_ordinary_recovery", refuse)
    monkeypatch.setattr(updates, "launch_version", no_launch)
    with pytest.raises(ValueError) as observed:
        updates.start_current(tmp_path, {"staging_root": str(tmp_path)}, {"phase": "FAILED"},
                              {"sha": "1" * 40}, [], code="UPDATE_TERMINAL_RECOVERED")
    assert observed.value is recovery_error

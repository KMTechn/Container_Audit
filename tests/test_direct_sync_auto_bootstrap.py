import json
from pathlib import Path

import pytest

import direct_sync_auto_bootstrap as bootstrap


def _source_app(tmp_path: Path) -> Path:
    app_root = tmp_path / "app"
    runner = app_root / "tools" / "direct_sync_relay_runner.py"
    runner.parent.mkdir(parents=True)
    runner.write_text("# runner\n", encoding="utf-8")
    return app_root


def test_session_command_hosts_relay_without_scheduled_task(tmp_path):
    app_root = _source_app(tmp_path)
    direct_root = tmp_path / "state"
    events = tmp_path / "events"

    command = bootstrap.build_session_direct_sync_command(
        app_root=app_root,
        direct_sync_root=direct_root,
        scan_source_dir=events,
    )

    assert command[0] == bootstrap.sys.executable
    assert command[1] == str(app_root / "tools" / "direct_sync_relay_runner.py")
    assert "--drain-after-scan" in command
    assert "--scan-source-dir" in command
    assert str(events.resolve()) in command
    assert "schtasks.exe" not in " ".join(command).lower()


def test_frozen_command_uses_hardened_main_in_process_mode(tmp_path):
    app_root = tmp_path / "hardened"
    app_root.mkdir()
    executable = app_root / "Container_Audit.exe"
    executable.write_bytes(b"exe")

    command = bootstrap.build_session_direct_sync_command(
        app_root=app_root,
        direct_sync_root=tmp_path / "state",
        scan_source_dir=tmp_path / "events",
    )

    assert command[:2] == [
        str(executable.resolve()),
        "--container-audit-direct-sync-relay",
    ]


def test_missing_runner_is_fail_closed(tmp_path):
    result = bootstrap.run_session_direct_sync_once(
        app_root=tmp_path / "missing",
        direct_sync_root=tmp_path / "state",
        scan_source_dir=tmp_path / "events",
    )

    assert result["status"] == "FAIL"
    assert result["reason"] == "direct-sync relay runner is missing"


@pytest.mark.parametrize("state_kind", ["direct", "events"])
def test_session_command_rejects_code_root_state_before_any_write(
    tmp_path,
    state_kind,
):
    app_root = _source_app(tmp_path)
    direct_root = (
        app_root / "runtime_data" / "direct_sync"
        if state_kind == "direct"
        else tmp_path / "state"
    )
    events = (
        app_root / "runtime_data" / "events"
        if state_kind == "events"
        else tmp_path / "events"
    )
    before = {
        path.relative_to(app_root).as_posix(): path.read_bytes()
        for path in app_root.rglob("*")
        if path.is_file()
    }

    with pytest.raises(ValueError, match="disjoint from the code root"):
        bootstrap.build_session_direct_sync_command(
            app_root=app_root,
            direct_sync_root=direct_root,
            scan_source_dir=events,
        )

    assert {
        path.relative_to(app_root).as_posix(): path.read_bytes()
        for path in app_root.rglob("*")
        if path.is_file()
    } == before
    assert not (app_root / "runtime_data").exists()


def test_session_command_rejects_relative_runtime_state_paths(tmp_path):
    app_root = _source_app(tmp_path)

    with pytest.raises(ValueError, match="must be absolute"):
        bootstrap.build_session_direct_sync_command(
            app_root=app_root,
            direct_sync_root="relative-direct-sync",
            scan_source_dir=tmp_path / "events",
        )


def test_lost_process_exit_code_is_unknown(monkeypatch):
    def raise_timeout(*_args, **_kwargs):
        raise TimeoutError("no process result")

    monkeypatch.setattr(bootstrap.subprocess, "run", raise_timeout)

    result = bootstrap._run_command(["relay"], 10)

    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "relay process did not return an exit code"
    assert result["error_type"] == "TimeoutError"


def test_app_start_wake_records_current_user_topology(tmp_path, monkeypatch):
    monkeypatch.setattr(
        bootstrap,
        "run_session_direct_sync_once",
        lambda **_kwargs: {"status": "PASS", "returncode": 0},
    )
    state = tmp_path / "state"

    report = bootstrap.run_direct_sync_auto_bootstrap(
        app_root=tmp_path / "app",
        direct_sync_root=state,
        scan_source_dir=tmp_path / "events",
    )

    persisted = json.loads(
        (
            state
            / "status"
            / "container_audit_direct_sync_auto_bootstrap.json"
        ).read_text(encoding="utf-8")
    )
    assert report == persisted
    assert report["status"] == "PASS"
    assert report["principal"] == "current_user"
    assert report["system_scheduled_task"] is False
    assert report["persistent_retry"] == "HKCU_RUN_USER_RELAY"


def test_background_wake_is_single_per_root_and_releases_key(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTAINER_AUDIT_SESSION_SYNC_TRIGGER", "1")
    observed = []

    def fake_run(**kwargs):
        observed.append(kwargs)
        return {"status": "PASS"}

    monkeypatch.setattr(bootstrap, "run_direct_sync_auto_bootstrap", fake_run)
    state = tmp_path / "state"

    thread = bootstrap.start_direct_sync_auto_bootstrap(
        app_root=tmp_path / "app",
        direct_sync_root=state,
        scan_source_dir=tmp_path / "events",
    )
    assert thread is not None
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert observed
    assert bootstrap._STARTED_ROOTS == set()


def test_module_contains_no_task_install_or_elevation_path():
    text = Path(bootstrap.__file__).read_text(encoding="utf-8")

    for forbidden in (
        "Register-ScheduledTask",
        "New-ScheduledTask",
        "Start-ScheduledTask",
        "schtasks.exe",
        "runas",
        "Verb RunAs",
    ):
        assert forbidden not in text
    assert bootstrap._install_report_relay_topology({}) == (
        "retired_scheduled_task_contract"
    )

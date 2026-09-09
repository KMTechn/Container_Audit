import json
from pathlib import Path
import threading

import pytest

import direct_sync_auto_bootstrap as bootstrap
from direct_sync_push import DEFAULT_ENDPOINT_PATH
from tests.test_real_child_http_regression import (
    ROOT, CSV_NAME, _loopback_https, _write_child_runtime, _write_csv,
)


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


def test_portable_command_reenters_isolated_main_instead_of_running_tool_script(tmp_path):
    app_root = _source_app(tmp_path)
    portable_main = app_root / "main.py"
    portable_main.write_text("# portable entry\n", encoding="utf-8")

    command = bootstrap.build_session_direct_sync_command(
        app_root=app_root,
        direct_sync_root=tmp_path / "state",
        scan_source_dir=tmp_path / "events",
    )

    assert command[:5] == [
        bootstrap.sys.executable,
        "-I",
        "-B",
        str(portable_main.resolve()),
        "--container-audit-direct-sync-relay",
    ]
    assert str(app_root / "tools" / "direct_sync_relay_runner.py") not in command


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
    with _loopback_https(tmp_path, monkeypatch) as bundle:
        state = tmp_path / "state"
        _write_child_runtime(state, bundle)
        csv_bytes = _write_csv(tmp_path / "events" / CSV_NAME)
        report = bootstrap.run_direct_sync_auto_bootstrap(
            app_root=ROOT, direct_sync_root=state, scan_source_dir=tmp_path / "events",
        )
        assert bundle['marker_path'].is_file(), 'real child isolation hook was not loaded'
        bodies = bundle['recorded'].bodies_for(DEFAULT_ENDPOINT_PATH)
        assert len(bodies) == 1 and csv_bytes in bodies[0], 'real relay did not upload the source'

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
    with _loopback_https(tmp_path, monkeypatch) as bundle:
        state = tmp_path / 'state'
        events = tmp_path / 'events'
        _write_child_runtime(state, bundle)
        _write_csv(events / CSV_NAME)
        entered, release = threading.Event(), threading.Event()
        record = bundle['recorded'].record

        def gated_record(**kwargs):
            if kwargs.get('path') == DEFAULT_ENDPOINT_PATH:
                entered.set()
                assert release.wait(15), 'test did not release the HTTP response'
            return record(**kwargs)

        monkeypatch.setattr(bundle['recorded'], 'record', gated_record)
        options = dict(app_root=ROOT, direct_sync_root=state, scan_source_dir=events)
        thread = bootstrap.start_direct_sync_auto_bootstrap(**options)
        assert thread is not None
        duplicate = None
        try:
            assert entered.wait(15), 'first real relay did not reach HTTP'
            duplicate = bootstrap.start_direct_sync_auto_bootstrap(**options)
            assert duplicate is None
        finally:
            release.set()
            thread.join(timeout=20)
            if duplicate is not None:
                duplicate.join(timeout=20)
        assert not thread.is_alive()
        assert len(bundle['recorded'].bodies_for(DEFAULT_ENDPOINT_PATH)) == 1
        bundle['marker_path'].unlink()
        second = bootstrap.start_direct_sync_auto_bootstrap(**options)
        assert second is not None, 'completed wake still prevents a later child'
        second.join(timeout=20)
        assert not second.is_alive()
        assert bundle['marker_path'].is_file(), 'later wake did not spawn a real child'
        persisted = json.loads((state/'status/container_audit_direct_sync_auto_bootstrap.json').read_text())
        assert persisted['status'] == 'PASS'


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

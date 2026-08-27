import json
from pathlib import Path

import direct_sync_auto_bootstrap as bootstrap


def test_registration_command_uses_bundled_install_host(tmp_path):
    app_root = tmp_path / "app"
    app_root.mkdir()
    install_exe = app_root / "Container_Audit_DirectSync_Install.exe"
    install_exe.write_bytes(b"exe")
    direct_sync_root = tmp_path / "data" / "direct_sync"

    command = bootstrap.build_registration_command(
        app_root=app_root,
        direct_sync_root=direct_sync_root,
        server_base_url="https://worker.example.invalid",
    )

    assert command[0] == str(install_exe.resolve())
    assert command[1] == "--register-worker-pc"
    assert "--self-enroll" in command
    assert command[command.index("--endpoint-url") + 1] == "https://worker.example.invalid/api/producer-ingest/v1/source-file"
    assert command[command.index("--manifest-path") + 1] == str((direct_sync_root / "producer_manifest.json").resolve())
    assert command[command.index("--credential-path") + 1] == str((direct_sync_root / "credential.json").resolve())


def test_registration_command_falls_back_to_install_host_script(tmp_path):
    app_root = tmp_path / "app"
    tools_dir = app_root / "tools"
    tools_dir.mkdir(parents=True)
    install_script = tools_dir / "direct_sync_relay_install_pack.py"
    install_script.write_text("raise SystemExit(0)\n", encoding="utf-8")

    command = bootstrap.build_registration_command(
        app_root=app_root,
        direct_sync_root=tmp_path / "data" / "direct_sync",
    )

    assert Path(command[1]) == install_script.resolve()
    assert command[2] == "--register-worker-pc"


def test_install_command_prefers_bundled_install_exe(tmp_path):
    app_root = tmp_path / "app"
    app_root.mkdir()
    install_exe = app_root / "Container_Audit_DirectSync_Install.exe"
    install_exe.write_bytes(b"exe")
    direct_sync_root = tmp_path / "data" / "direct_sync"
    events_dir = tmp_path / "data" / "events"

    command = bootstrap.build_install_command(
        app_root=app_root,
        direct_sync_root=direct_sync_root,
        scan_source_dir=events_dir,
    )

    assert command[0] == str(install_exe.resolve())
    assert "--apply" in command
    assert "--confirm-production-install" not in command
    assert command[command.index("--program-data-root") + 1] == str(direct_sync_root.resolve())
    assert command[command.index("--scan-source-dir") + 1] == str(events_dir.resolve())
    assert bootstrap.DEFAULT_SOURCE_GLOB in command


def test_builtin_bootstrap_requires_explicit_enable(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("CONTAINER_AUDIT_DIRECT_SYNC_BOOTSTRAP", raising=False)
    assert bootstrap._enabled() is False

    monkeypatch.setenv("CONTAINER_AUDIT_DIRECT_SYNC_BOOTSTRAP", "true")
    assert bootstrap._enabled() is True


def test_session_direct_sync_command_forces_zero_age_scan_and_drain(tmp_path):
    app_root = tmp_path / "app"
    tools_dir = app_root / "tools"
    tools_dir.mkdir(parents=True)
    runner_script = tools_dir / "direct_sync_relay_runner.py"
    runner_script.write_text("raise SystemExit(0)\n", encoding="utf-8")
    direct_sync_root = tmp_path / "data" / "direct_sync"
    events_dir = tmp_path / "data" / "events"

    command = bootstrap.build_session_direct_sync_command(
        app_root=app_root,
        direct_sync_root=direct_sync_root,
        scan_source_dir=events_dir,
    )

    assert command
    assert Path(command[1]) == runner_script.resolve()
    assert command[command.index("--scan-source-dir") + 1] == str(events_dir.resolve())
    assert command[command.index("--producer-manifest-path") + 1] == str((direct_sync_root / "producer_manifest.json").resolve())
    assert command[command.index("--credential-path") + 1] == str((direct_sync_root / "credential.json").resolve())
    assert command[command.index("--min-source-file-age-seconds") + 1] == "0"
    assert "--drain-after-scan" in command


def test_session_direct_sync_command_prefers_main_executable_relay_mode(tmp_path):
    app_root = tmp_path / "app"
    app_root.mkdir()
    application_exe = app_root / "Container_Audit.exe"
    application_exe.write_bytes(b"exe")

    command = bootstrap.build_session_direct_sync_command(
        app_root=app_root,
        direct_sync_root=tmp_path / "data" / "direct_sync",
        scan_source_dir=tmp_path / "data" / "events",
    )

    assert command[:2] == [str(application_exe.resolve()), bootstrap.DIRECT_SYNC_RELAY_MODE]
    assert "Container_Audit_DirectSync_Relay.exe" not in " ".join(command)


def test_install_command_falls_back_to_python_script(tmp_path):
    app_root = tmp_path / "app"
    tools_dir = app_root / "tools"
    tools_dir.mkdir(parents=True)
    script_path = tools_dir / "direct_sync_relay_install_pack.py"
    script_path.write_text("raise SystemExit(0)\n", encoding="utf-8")

    command = bootstrap.build_install_command(
        app_root=app_root,
        direct_sync_root=tmp_path / "data" / "direct_sync",
        scan_source_dir=tmp_path / "data" / "events",
    )

    assert Path(command[1]) == script_path.resolve()


def test_install_command_can_carry_production_task_principal(tmp_path):
    app_root = tmp_path / "app"
    app_root.mkdir()
    install_exe = app_root / "Container_Audit_DirectSync_Install.exe"
    install_exe.write_bytes(b"exe")

    command = bootstrap.build_install_command(
        app_root=app_root,
        direct_sync_root=tmp_path / "data" / "direct_sync",
        scan_source_dir=tmp_path / "data" / "events",
        confirm_production_install=True,
        task_run_user=r"TEST1\kmtech-dsync",
        task_run_password_file=str(tmp_path / "task-password.txt"),
    )

    assert "--confirm-production-install" in command
    assert command[command.index("--task-run-user") + 1] == r"TEST1\kmtech-dsync"
    assert command[command.index("--task-run-password-file") + 1] == str(tmp_path / "task-password.txt")


def test_install_command_requires_explicit_noncanonical_test_override(tmp_path):
    app_root = tmp_path / "app"
    app_root.mkdir()
    (app_root / "Container_Audit_DirectSync_Install.exe").write_bytes(b"exe")

    ordinary = bootstrap.build_install_command(
        app_root=app_root,
        direct_sync_root=tmp_path / "direct-sync",
        scan_source_dir=tmp_path / "events",
        allow_interactive_task_for_local_test=True,
    )
    explicit = bootstrap.build_install_command(
        app_root=app_root,
        direct_sync_root=tmp_path / "direct-sync",
        scan_source_dir=tmp_path / "events",
        allow_noncanonical_layout_for_test=True,
    )

    assert "--allow-interactive-task-for-local-test" in ordinary
    assert "--allow-noncanonical-layout-for-test" not in ordinary
    assert "--allow-noncanonical-layout-for-test" in explicit


def test_install_ready_requires_current_scan_source_dir(tmp_path):
    direct_sync_root = tmp_path / "data" / "direct_sync"
    events_dir = tmp_path / "data" / "events"
    status_dir = direct_sync_root / "status"
    status_dir.mkdir(parents=True)
    application_exe = tmp_path / "app" / "Container_Audit.exe"
    launcher_path = direct_sync_root / "bin" / "direct-sync-relay-container-audit.cmd"
    launcher_path.parent.mkdir(parents=True)
    launcher_path.write_text(
        f'"{application_exe}" {bootstrap.DIRECT_SYNC_RELAY_MODE}\n',
        encoding="utf-8",
    )

    report_path = status_dir / "container_audit_direct_sync_install.json"
    report_path.write_text(
        json.dumps(
            {
                "status": "PASS",
                "program_data_root": str(direct_sync_root),
                "task_name": "direct-sync-relay-container-audit",
                "field_layout_contract": {"production_layout_matches": True},
                "use_bundled_relay_executable": True,
                "relay_execution_mode": "in_process_main_executable",
                "bundled_relay_executable": {
                    "path": str(application_exe),
                    "mode": bootstrap.DIRECT_SYNC_RELAY_MODE,
                },
                "runner_command": [
                    str(application_exe),
                    bootstrap.DIRECT_SYNC_RELAY_MODE,
                ],
                "scheduled_task_launcher_path": str(launcher_path),
                "scheduled_task_wrapper_path": str(launcher_path),
                "source_scan": {
                    "scan_source_dir": str(events_dir),
                },
            }
        ),
        encoding="utf-8",
    )

    assert bootstrap._install_ready(
        direct_sync_root,
        "direct-sync-relay-container-audit",
        events_dir,
    )

    launcher_path.write_text(
        '"C:\\KMTech\\Apps\\Container_Audit\\current\\'
        'Container_Audit_DirectSync_Relay.exe" --db-path queue.sqlite3\n',
        encoding="utf-8",
    )
    assert not bootstrap._install_ready(
        direct_sync_root,
        "direct-sync-relay-container-audit",
        events_dir,
    )
    assert bootstrap._legacy_install_repair_required(direct_sync_root)
    launcher_path.write_text(
        f'"{application_exe}" {bootstrap.DIRECT_SYNC_RELAY_MODE}\n',
        encoding="utf-8",
    )

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["field_layout_contract"]["production_layout_matches"] = False
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    assert not bootstrap._install_ready(
        direct_sync_root,
        "direct-sync-relay-container-audit",
        events_dir,
    )
    payload["field_layout_contract"]["production_layout_matches"] = True
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    stale_events_dir = tmp_path / "Users" / "kmtech-remote-admin" / "AppData" / "Local" / "KMTech" / "ContainerAudit" / "events"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["source_scan"]["scan_source_dir"] = str(stale_events_dir)
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    assert not bootstrap._install_ready(
        direct_sync_root,
        "direct-sync-relay-container-audit",
        events_dir,
    )


def test_install_ready_rejects_retired_helper_topology(tmp_path):
    direct_sync_root = tmp_path / "data" / "direct_sync"
    events_dir = tmp_path / "data" / "events"
    status_dir = direct_sync_root / "status"
    status_dir.mkdir(parents=True)
    retired_helper = tmp_path / "app" / "Container_Audit_DirectSync_Relay.exe"
    (status_dir / "container_audit_direct_sync_install.json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "program_data_root": str(direct_sync_root),
                "task_name": "direct-sync-relay-container-audit",
                "field_layout_contract": {"production_layout_matches": True},
                "use_bundled_relay_executable": True,
                "bundled_relay_executable": {"path": str(retired_helper)},
                "runner_command": [str(retired_helper), "--db-path", "queue.sqlite3"],
                "source_scan": {"scan_source_dir": str(events_dir)},
            }
        ),
        encoding="utf-8",
    )

    assert not bootstrap._install_ready(
        direct_sync_root,
        "direct-sync-relay-container-audit",
        events_dir,
    )


def test_startup_forces_legacy_topology_repair_even_when_bootstrap_is_disabled(
    tmp_path, monkeypatch
):
    observed = {}

    class FakeThread:
        def __init__(self, **kwargs):
            observed.update(kwargs)

        def start(self):
            observed["started"] = True

    monkeypatch.setattr(bootstrap.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bootstrap, "_enabled", lambda: False)
    monkeypatch.setattr(bootstrap, "_legacy_install_repair_required", lambda _root: True)
    monkeypatch.setattr(bootstrap.threading, "Thread", FakeThread)
    bootstrap._STARTED_ROOTS.clear()

    thread = bootstrap.start_direct_sync_auto_bootstrap(
        app_root=tmp_path / "app",
        direct_sync_root=tmp_path / "direct-sync",
        scan_source_dir=tmp_path / "events",
    )

    assert thread is not None
    assert observed["started"] is True
    assert observed["kwargs"]["force_install_repair"] is True
    assert observed["kwargs"]["confirm_production_install"] is True
    bootstrap._STARTED_ROOTS.clear()


def test_forced_legacy_repair_requires_current_install_postcondition(tmp_path, monkeypatch):
    app_root = tmp_path / "app"
    direct_sync_root = tmp_path / "direct-sync"
    events_dir = tmp_path / "events"
    app_root.mkdir()
    (app_root / bootstrap.INSTALL_EXE_NAME).write_bytes(b"exe")
    monkeypatch.setattr(bootstrap, "CANONICAL_INSTALL_ROOT", str(app_root))
    monkeypatch.setattr(bootstrap, "CANONICAL_DIRECT_SYNC_ROOT", str(direct_sync_root))
    monkeypatch.setattr(bootstrap.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bootstrap, "_registration_ready", lambda _root: True)
    install_ready_results = iter((False, True))
    monkeypatch.setattr(bootstrap, "_install_ready", lambda *_args: next(install_ready_results))
    monkeypatch.setattr(bootstrap, "_task_exists", lambda _task: True)
    elevated_calls = []
    monkeypatch.setattr(
        bootstrap,
        "_run_elevated_task_repair",
        lambda command, **kwargs: elevated_calls.append((command, kwargs))
        or {"status": "PASS", "returncode": 0},
    )
    monkeypatch.setattr(
        bootstrap,
        "_start_task",
        lambda _task: (_ for _ in ()).throw(AssertionError("repair starts the task itself")),
    )

    report = bootstrap.run_direct_sync_auto_bootstrap(
        app_root=app_root,
        direct_sync_root=direct_sync_root,
        scan_source_dir=events_dir,
        confirm_production_install=True,
        force_install_repair=True,
    )

    assert report["status"] == "PASS"
    assert report["task_start"]["status"] == "PASS"
    assert len(elevated_calls) == 1

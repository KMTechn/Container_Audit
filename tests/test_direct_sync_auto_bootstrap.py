from pathlib import Path

import direct_sync_auto_bootstrap as bootstrap


def test_registration_command_prefers_bundled_register_exe(tmp_path):
    app_root = tmp_path / "app"
    app_root.mkdir()
    register_exe = app_root / "Container_Audit_Worker_PC_Register.exe"
    register_exe.write_bytes(b"exe")
    direct_sync_root = tmp_path / "data" / "direct_sync"

    command = bootstrap.build_registration_command(
        app_root=app_root,
        direct_sync_root=direct_sync_root,
        server_base_url="https://worker.example.invalid",
    )

    assert command[0] == str(register_exe.resolve())
    assert "--self-enroll" in command
    assert command[command.index("--endpoint-url") + 1] == "https://worker.example.invalid/api/producer-ingest/v1/source-file"
    assert command[command.index("--manifest-path") + 1] == str((direct_sync_root / "producer_manifest.json").resolve())
    assert command[command.index("--credential-path") + 1] == str((direct_sync_root / "credential.json").resolve())


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
    assert command[command.index("--program-data-root") + 1] == str(direct_sync_root.resolve())
    assert command[command.index("--scan-source-dir") + 1] == str(events_dir.resolve())
    assert bootstrap.DEFAULT_SOURCE_GLOB in command


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

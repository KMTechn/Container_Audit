import argparse
import json
import base64
import subprocess
import sys
from pathlib import Path

import pytest

import direct_sync_push
from tools import direct_sync_relay_install_pack as install_pack
from tools.direct_sync_relay_install_pack import _quote_cmd
from storage_policy import DATA_ROOT_ENV


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_PACK_SCRIPT = REPO_ROOT / "tools" / "direct_sync_relay_install_pack.py"


def decode_encoded_powershell_command(command):
    assert command[:5] == ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand"]
    return base64.b64decode(command[5]).decode("utf-16le")


def test_install_pack_report_write_uses_unique_atomic_temp_paths(tmp_path, monkeypatch):
    target = tmp_path / "install-report.json"
    observed = []
    original_replace = install_pack.os.replace

    def capture_replace(src, dst):
        observed.append((Path(src).name, Path(dst).name))
        original_replace(src, dst)

    monkeypatch.setattr(install_pack.os, "replace", capture_replace)

    install_pack._write_json(target, {"step": 1})
    install_pack._write_json(target, {"step": 2})

    assert observed[0][0].startswith("install-report.json.tmp.")
    assert observed[1][0].startswith("install-report.json.tmp.")
    assert observed[0][0] != observed[1][0]
    assert observed[0][1] == "install-report.json"
    assert json.loads(target.read_text(encoding="utf-8"))["step"] == 2
    assert list(tmp_path.glob("install-report.json.tmp.*")) == []


def test_install_pack_frozen_default_app_root_uses_executable_directory(tmp_path, monkeypatch):
    frozen_exe = tmp_path / "release" / "Container_Audit_DirectSync_Install.exe"
    frozen_exe.parent.mkdir()
    frozen_exe.write_bytes(b"exe")
    monkeypatch.setattr(install_pack.sys, "frozen", True, raising=False)
    monkeypatch.setattr(install_pack.sys, "executable", str(frozen_exe))

    assert install_pack._default_app_root() == str(frozen_exe.parent.resolve())


def make_manifest_and_credential(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "pc_identity": {
                    "pc_id": "CONTAINER-PC01",
                    "source_host_id": "install-pack-host",
                    "producer_install_id": "install-pack-producer",
                },
                "streams": [
                    {
                        "producer_role": "container_audit",
                        "stream_name": "container_audit_events",
                        "source_system": "container_audit",
                        "source_transport": "legacy_transfer_csv",
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    credential_path = tmp_path / "credential.json"
    credential_path.write_text(
        json.dumps(
            {
                "producer_id": "producer-1",
                "key_id": "key-1",
                "secret": "install-pack-secret",
                "endpoint_url": "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return manifest_path, credential_path


def test_install_pack_defaults_to_container_audit_local_storage(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    local_app_data = tmp_path / "LocalAppData"
    report_path = tmp_path / "install-pack-default-storage.json"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--report-path",
            str(report_path),
        ]
    )

    assert exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    expected_root = (local_app_data / "KMTech" / "ContainerAudit").resolve()
    assert report["status"] == "DRY_RUN"
    assert report["container_audit_storage"]["defaulted_program_data_root"] is True
    assert report["container_audit_storage"]["defaulted_scan_source_dir"] is True
    assert report["container_audit_storage"]["defaulted_source_glob"] is True
    assert report["program_data_root"] == str(expected_root / "direct_sync")
    assert report["source_scan"]["scan_source_dir"] == str(expected_root / "events")
    assert report["source_scan"]["source_globs"] == ["이적작업이벤트로그_*.csv"]
    assert report["source_scan_validation"]["status"] == "PASS"
    assert str(expected_root / "events") in report["runner_command"]
    assert str(expected_root / "direct_sync") in report["runtime_paths"]["db_path"]


def test_install_pack_blocks_syncthing_data_root_with_report(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-syncthing-block.json"
    monkeypatch.setenv(DATA_ROOT_ENV, r"C:\Sync")

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--report-path",
            str(report_path),
        ]
    )

    assert exit_code == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["container_audit_storage"]["status"] == "FAIL"
    assert "legacy Syncthing folder" in report["blocked_reason"]


def test_install_pack_blocks_explicit_syncthing_program_data_root(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-explicit-syncthing-program-data.json"
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            r"C:\Sync\container-audit-direct-sync",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert exit_code == 2
    assert report["status"] == "BLOCKED"
    assert report["runtime_path_boundary"]["status"] == "FAIL"
    assert "legacy Syncthing folder" in report["blocked_reason"]


def test_install_pack_blocks_explicit_syncthing_scan_source_dir(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-explicit-syncthing-source.json"
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--scan-source-dir",
            r"C:\Sync",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert exit_code == 2
    assert report["status"] == "BLOCKED"
    assert report["source_scan_validation"]["status"] == "FAIL"
    assert report["source_scan_validation"]["syncthing_path_rejected"] is True
    assert "legacy Syncthing folder" in report["blocked_reason"]


def test_install_pack_blocks_explicit_syncthing_manifest_and_credential_paths(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-explicit-syncthing-artifacts.json"
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            r"C:\Sync\producer_manifest.json",
            "--credential-path",
            r"C:\Sync\credential.json",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert manifest_path.is_file()
    assert credential_path.is_file()
    assert exit_code == 2
    assert report["status"] == "BLOCKED"
    assert report["explicit_path_boundary"]["status"] == "FAIL"
    assert "producer_manifest_path must not point at the legacy Syncthing folder" in report["blocked_reason"]
    assert "credential_path must not point at the legacy Syncthing folder" in report["blocked_reason"]


def test_install_pack_blocks_syncthing_report_path_without_writing_there(tmp_path, monkeypatch, capsys):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--report-path",
            r"C:\Sync\install-report.json",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 2
    assert report["status"] == "BLOCKED"
    assert report["explicit_path_boundary"]["status"] == "FAIL"
    assert "report_path must not point at the legacy Syncthing folder" in report["blocked_reason"]


def test_install_pack_dry_run_writes_redacted_scheduled_task_plan(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    (tmp_path / "sync").mkdir()
    report_path = tmp_path / "install-pack.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--scan-source-dir",
            str(tmp_path / "sync"),
            "--source-glob",
            "이적작업이벤트로그_*.csv",
            "--min-source-file-age-seconds",
            "30",
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 0
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    report_text = report_path.read_text(encoding="utf-8-sig")
    assert report["status"] == "DRY_RUN"
    assert report["task_name"] == "direct-sync-relay-container-audit"
    assert report["task_name_validation"]["status"] == "PASS"
    assert "direct_sync_relay_runner.py" in " ".join(report["runner_command"])
    assert "--scan-source-dir" in report["runner_command"]
    assert str((tmp_path / "sync").resolve()) in report["runner_command"]
    assert "이적작업이벤트로그_*.csv" in report["runner_command"]
    assert report["source_scan"]["enabled"] is True
    assert report["source_scan_validation"]["status"] == "PASS"
    assert report["source_scan"]["max_enqueue_files"] == 100
    assert report["source_scan"]["min_source_file_age_seconds"] == 30
    assert report["source_scan"]["drain_after_scan"] is True
    assert report["runtime_path_boundary"]["status"] == "PASS"
    assert report["runtime_path_boundary"]["all_runtime_paths_under_program_data_root"] is True
    assert report["app_root_dependencies"]["status"] == "PASS"
    assert report["python_runtime_imports"]["status"] == "SKIPPED"
    assert "--probe-python-runtime" in report["python_runtime_imports"]["reason"]
    assert report["producer_manifest"]["status"] == "PASS"
    assert report["credential"]["status"] == "PASS"
    assert "--operator-pause-path" in report["runner_command"]
    assert report["runtime_paths"]["operator_pause_path"] in report["runner_command"]
    assert report["backpressure"] == {
        "max_active_queue_age_seconds": 24 * 60 * 60,
        "max_active_queue_count": 1000,
    }
    assert "--max-active-queue-count" in report["runner_command"]
    assert "--max-active-queue-age-seconds" in report["runner_command"]
    assert "--min-source-file-age-seconds" in report["runner_command"]
    assert "--drain-after-scan" in report["runner_command"]
    assert "30" in report["runner_command"]
    assert "schtasks.exe" == report["scheduled_task_create_command"][0]
    tr_index = report["scheduled_task_create_command"].index("/TR")
    assert report["scheduled_task_create_command"][tr_index + 1] == report["scheduled_task_launcher_command"]
    assert len(report["scheduled_task_create_command"][tr_index + 1]) <= 261
    assert report["scheduled_task_wrapper_path"].endswith("direct-sync-relay-container-audit.cmd")
    assert report["scheduled_task_launcher_path"].endswith("direct-sync-relay-container-audit.vbs")
    assert report["scheduled_task_uses_hidden_launcher"] is True
    assert "wscript.exe" in report["scheduled_task_launcher_command"]
    assert str(credential_path.resolve()) in report["runner_command"]
    assert "install-pack-secret" not in report_text
    assert report["secret_redaction"]["raw_secret_in_report"] is False


def test_install_pack_apply_blocks_raw_secret_without_production_env(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-apply-raw-secret-blocked.json"
    commands = []
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("CONTAINER_AUDIT_PRODUCTION", raising=False)
    monkeypatch.delenv("DIRECT_SYNC_PRODUCTION", raising=False)
    monkeypatch.setattr(
        install_pack,
        "_run_command",
        lambda command: commands.append(command) or {"returncode": 0, "stdout": "", "stderr": ""},
    )

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--report-path",
            str(report_path),
            "--apply",
            "--confirm-production-install",
            "--allow-interactive-task-for-local-test",
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    report_text = report_path.read_text(encoding="utf-8-sig")
    assert exit_code == 2
    assert commands == []
    assert report["status"] == "BLOCKED"
    assert report["credential"]["status"] == "FAIL"
    assert report["credential"]["raw_secret_configured"] is True
    assert report["credential"]["raw_secret_forbidden"] is True
    assert "raw credential secret is disabled for production apply" in report["blocked_reason"]
    assert "install-pack-secret" not in report_text


def test_install_pack_prefers_bundled_relay_executable_without_python_dependency(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    app_root = tmp_path / "release-app"
    app_root.mkdir()
    bundled_relay = app_root / "Container_Audit_DirectSync_Relay.exe"
    bundled_relay.write_bytes(b"relay-exe")
    local_app_data = tmp_path / "LocalAppData"
    report_path = tmp_path / "install-pack-bundled-relay.json"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    exit_code = install_pack.main(
        [
            "--app-root",
            str(app_root),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert exit_code == 0
    assert report["status"] == "DRY_RUN"
    assert report["use_bundled_relay_executable"] is True
    assert report["bundled_relay_executable"]["status"] == "PASS"
    assert report["runner_command"][0] == str(bundled_relay.resolve())
    assert "direct_sync_relay_runner.py" not in report["runner_command"]
    assert report["app_root_dependencies"]["status"] == "SKIPPED"
    assert report["python_executable"]["status"] == "SKIPPED"
    assert report["python_runtime_imports"]["status"] == "SKIPPED"


def test_install_pack_honors_explicit_python_exe_even_when_bundled_relay_exists(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    app_root = tmp_path / "release-app"
    (app_root / "tools").mkdir(parents=True)
    (app_root / "tools" / "direct_sync_relay_runner.py").write_text("", encoding="utf-8")
    (app_root / "direct_sync_push.py").write_text("", encoding="utf-8")
    (app_root / "direct_sync_operator.py").write_text("", encoding="utf-8")
    (app_root / "direct_sync_runtime.py").write_text("", encoding="utf-8")
    (app_root / "storage_policy.py").write_text("", encoding="utf-8")
    (app_root / "Container_Audit_DirectSync_Relay.exe").write_bytes(b"relay-exe")
    report_path = tmp_path / "install-pack-explicit-python.json"

    exit_code = install_pack.main(
        [
            "--app-root",
            str(app_root),
            "--python-exe",
            sys.executable,
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData"),
            "--scan-source-dir",
            str(tmp_path),
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert exit_code == 0
    assert report["use_bundled_relay_executable"] is False
    assert report["python_exe_explicit"] is True
    assert report["runner_command"][0] == str(Path(sys.executable).resolve())
    assert report["runner_command"][1].endswith("direct_sync_relay_runner.py")


@pytest.mark.parametrize(
    "task_name",
    [
        "",
        "direct sync relay",
        "direct/sync/relay",
        r"direct\sync\relay",
        "../direct-sync-relay",
        "direct-sync-relay\ncontainer-audit",
        "x" * 129,
    ],
)
def test_install_pack_blocks_invalid_scheduled_task_name_before_apply(tmp_path, monkeypatch, task_name):
    report_path = tmp_path / "install-pack-invalid-task-name.json"
    commands = []
    monkeypatch.setattr(
        install_pack,
        "_run_command",
        lambda command: commands.append(command) or {"returncode": 0, "stdout": "", "stderr": ""},
    )

    result = install_pack.main(
        [
            "--task-name",
            task_name,
            "--report-path",
            str(report_path),
            "--apply",
            "--confirm-production-install",
            "--allow-interactive-task-for-local-test",
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert result == 2
    assert commands == []
    assert report["status"] == "BLOCKED"
    assert report["task_name_validation"]["status"] == "FAIL"
    assert "task_name" in report["blocked_reason"]


def test_install_pack_blocks_invalid_scheduled_task_name_for_uninstall_before_delete(tmp_path, monkeypatch):
    report_path = tmp_path / "install-pack-invalid-uninstall-task-name.json"
    commands = []
    monkeypatch.setattr(
        install_pack,
        "_run_command",
        lambda command: commands.append(command) or {"returncode": 0, "stdout": "", "stderr": ""},
    )

    result = install_pack.main(
        [
            "--uninstall",
            "--apply",
            "--confirm-production-install",
            "--task-name",
            "other/task",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert result == 2
    assert commands == []
    assert report["status"] == "BLOCKED"
    assert report["scheduled_task_create_command"] == []
    assert report["scheduled_task_delete_command"] == ["schtasks.exe", "/Delete", "/TN", "other/task", "/F"]
    assert report["task_name_validation"]["status"] == "FAIL"


def test_install_pack_source_scan_defaults_to_file_age_grace_period(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    (tmp_path / "sync").mkdir()
    report_path = tmp_path / "install-pack-default-age.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--scan-source-dir",
            str(tmp_path / "sync"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 0
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["source_scan"]["min_source_file_age_seconds"] == 30
    assert "--min-source-file-age-seconds" in report["runner_command"]
    assert "30" in report["runner_command"]


@pytest.mark.parametrize(
    ("option", "report_section", "field_name"),
    [
        ("--min-source-file-age-seconds", "source_scan_validation", "min_source_file_age_seconds"),
        ("--max-active-queue-count", "backpressure_validation", "max_active_queue_count"),
    ],
)
def test_install_pack_blocks_negative_safety_limits(tmp_path, option, report_section, field_name):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    (tmp_path / "sync").mkdir()
    report_path = tmp_path / f"install-pack-negative-{field_name}.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--scan-source-dir",
            str(tmp_path / "sync"),
            option,
            "-1",
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report[report_section]["status"] == "FAIL"
    assert field_name in report["blocked_reason"]


def test_install_pack_blocks_missing_scan_source_dir(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-missing-scan-dir.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--scan-source-dir",
            str(tmp_path / "missing-sync"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["source_scan_validation"]["status"] == "FAIL"
    assert report["source_scan_validation"]["scan_source_dir_exists"] is False
    assert report["blocked_reason"] == "scan_source_dir does not exist or is not a directory"


def test_install_pack_blocks_recursive_scan_source_glob(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    (tmp_path / "sync").mkdir()
    report_path = tmp_path / "install-pack-bad-source-glob.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--scan-source-dir",
            str(tmp_path / "sync"),
            "--source-glob",
            "**/*.csv",
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["source_scan_validation"]["status"] == "FAIL"
    assert report["source_scan_validation"]["source_globs_valid"] is False
    assert report["blocked_reason"] == "source glob must be a direct-child file pattern"


def test_install_pack_blocks_missing_app_root_runtime_dependencies(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-missing-app-root.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--app-root",
            str(tmp_path / "missing-app-root"),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["blocked_reason"] == "app_root missing direct-sync runtime dependencies"
    assert report["app_root_dependencies"]["status"] == "FAIL"
    assert "runner_script" in report["app_root_dependencies"]["missing"]


def test_install_pack_blocks_missing_python_executable(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-missing-python.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--python-exe",
            str(tmp_path / "missing-python.exe"),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["blocked_reason"] == "python_exe does not exist"
    assert report["python_executable"]["status"] == "FAIL"
    assert report["python_runtime_imports"]["status"] == "SKIPPED"


def test_install_pack_dry_run_skips_python_runtime_import_probe_by_default(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    app_root = tmp_path / "app-root"
    (app_root / "tools").mkdir(parents=True)
    (app_root / "tools" / "direct_sync_relay_runner.py").write_text("", encoding="utf-8")
    (app_root / "direct_sync_push.py").write_text("", encoding="utf-8")
    (app_root / "direct_sync_operator.py").write_text("", encoding="utf-8")
    (app_root / "direct_sync_runtime.py").write_text("raise RuntimeError('broken runtime import')\n", encoding="utf-8")
    (app_root / "storage_policy.py").write_text("", encoding="utf-8")
    report_path = tmp_path / "install-pack-runtime-import-skipped.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--app-root",
            str(app_root),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert completed.returncode == 0
    assert report["status"] == "DRY_RUN"
    assert report["python_runtime_imports"]["status"] == "SKIPPED"


def test_python_runtime_import_probe_includes_lazy_requests_dependency(tmp_path, monkeypatch):
    observed = {}

    def fake_run(command, *, check, capture_output, text, timeout):
        observed["command"] = command
        observed["check"] = check
        observed["capture_output"] = capture_output
        observed["text"] = text
        observed["timeout"] = timeout
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(install_pack.subprocess, "run", fake_run)

    report = install_pack._python_runtime_import_report(sys.executable, tmp_path)

    assert report["status"] == "PASS"
    assert "requests" in report["required_modules"]
    assert "import requests" in observed["command"][2]
    assert observed["timeout"] == 15


def test_install_pack_blocks_python_that_cannot_import_runtime_modules_when_probe_requested(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    app_root = tmp_path / "app-root"
    (app_root / "tools").mkdir(parents=True)
    (app_root / "tools" / "direct_sync_relay_runner.py").write_text("", encoding="utf-8")
    (app_root / "direct_sync_push.py").write_text("", encoding="utf-8")
    (app_root / "direct_sync_operator.py").write_text("", encoding="utf-8")
    (app_root / "direct_sync_runtime.py").write_text("raise RuntimeError('broken runtime import')\n", encoding="utf-8")
    (app_root / "storage_policy.py").write_text("", encoding="utf-8")
    report_path = tmp_path / "install-pack-runtime-import.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--app-root",
            str(app_root),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
            "--probe-python-runtime",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert completed.returncode == 2
    assert report["status"] == "BLOCKED"
    assert report["blocked_reason"] == "python_exe cannot import direct-sync runtime modules"
    assert report["python_runtime_imports"]["status"] == "FAIL"
    assert "direct_sync_runtime" in report["python_runtime_imports"]["stderr"]


def test_install_pack_blocks_missing_manifest_file(tmp_path):
    _manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-missing-manifest.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(tmp_path / "missing-manifest.json"),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["producer_manifest"]["status"] == "FAIL"
    assert report["blocked_reason"] == "producer_manifest file does not exist"


def test_install_pack_blocks_manifest_without_container_stream(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["streams"] = []
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    report_path = tmp_path / "install-pack-invalid-manifest.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["producer_manifest"]["container_audit_stream_present"] is False
    assert "stream does not match" in report["blocked_reason"]


def test_install_pack_blocks_manifest_with_wrong_producer_role(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["streams"][0]["producer_role"] = "other_producer"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    report_path = tmp_path / "install-pack-wrong-role.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["producer_manifest"]["container_audit_stream_present"] is True
    assert report["producer_manifest"]["container_audit_stream_valid"] is False
    assert "stream does not match" in report["blocked_reason"]


def test_install_pack_blocks_malformed_credential_without_leaking_secret(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    credential_path.write_text('{"producer_id": "producer-1", "secret": "leaky-secret"', encoding="utf-8")
    report_path = tmp_path / "install-pack-malformed-credential.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    report_text = report_path.read_text(encoding="utf-8-sig")
    report = json.loads(report_text)
    assert completed.returncode == 2
    assert report["status"] == "BLOCKED"
    assert report["credential"]["status"] == "FAIL"
    assert report["credential"]["error_type"] == "JSONDecodeError"
    assert "leaky-secret" not in report_text


def test_install_pack_blocks_duplicate_json_keys_without_shadowing_values(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    credential_path.write_text(
        '{"producer_id": "producer-1", "key_id": "key-1", '
        '"secret": "leaky-secret", "secret": "shadow-secret", '
        '"endpoint_url": "https://worker.example.invalid/api/producer-ingest/v1/source-file"}',
        encoding="utf-8",
    )
    report_path = tmp_path / "install-pack-duplicate-credential-key.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    report_text = report_path.read_text(encoding="utf-8-sig")
    report = json.loads(report_text)
    assert completed.returncode == 2
    assert report["status"] == "BLOCKED"
    assert report["credential"]["status"] == "FAIL"
    assert report["credential"]["error_type"] == "DuplicateJSONKey"
    assert "duplicate key: secret" in report["credential"]["error_message"]
    assert "leaky-secret" not in report_text
    assert "shadow-secret" not in report_text


@pytest.mark.parametrize("secret_value", [123, ["install-pack-secret"], {"value": "install-pack-secret"}, "   "])
def test_install_pack_blocks_non_string_or_blank_raw_secret_without_leaking_value(tmp_path, secret_value):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    credential = json.loads(credential_path.read_text(encoding="utf-8"))
    credential["secret"] = secret_value
    credential_path.write_text(json.dumps(credential, ensure_ascii=False), encoding="utf-8")
    report_path = tmp_path / "install-pack-invalid-secret.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    report_text = report_path.read_text(encoding="utf-8-sig")
    report = json.loads(report_text)
    assert completed.returncode == 2
    assert report["status"] == "BLOCKED"
    assert report["credential"]["status"] == "FAIL"
    assert "credential secret must be a nonempty string" in report["credential"]["blocked_reason"]
    assert "install-pack-secret" not in report_text


def test_install_pack_blocks_credential_with_invalid_endpoint(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    credential = json.loads(credential_path.read_text(encoding="utf-8"))
    credential["endpoint_url"] = "http://localhost/api/producer-ingest/v1/source-file"
    credential_path.write_text(json.dumps(credential, ensure_ascii=False), encoding="utf-8")
    report_path = tmp_path / "install-pack-invalid-credential.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert completed.returncode == 2
    assert report["status"] == "BLOCKED"
    assert report["credential"]["status"] == "FAIL"
    assert report["credential"]["endpoint_url_valid"] is False
    assert "endpoint_url" in report["blocked_reason"]


def test_install_pack_blocks_credential_with_private_endpoint_literal(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    credential = json.loads(credential_path.read_text(encoding="utf-8"))
    credential["endpoint_url"] = "https://10.1.2.3/api/producer-ingest/v1/source-file"
    credential_path.write_text(json.dumps(credential, ensure_ascii=False), encoding="utf-8")
    report_path = tmp_path / "install-pack-private-endpoint.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData" / "KMTech" / "DirectSync" / "container_audit"),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert completed.returncode == 2
    assert report["status"] == "BLOCKED"
    assert report["credential"]["status"] == "FAIL"
    assert report["credential"]["endpoint_url_valid"] is False
    assert "private" in report["credential"]["blocked_reason"]


def test_install_pack_blocks_credential_hostname_resolving_to_private_address(tmp_path, monkeypatch):
    _manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    monkeypatch.setattr(
        direct_sync_push.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(direct_sync_push.socket.AF_INET, 0, 0, "", ("10.1.2.3", 443))],
    )

    report = install_pack._credential_report(credential_path)

    assert report["status"] == "FAIL"
    assert report["endpoint_url_valid"] is False
    assert "private" in report["blocked_reason"]


def test_install_pack_blocks_raw_credential_secret_in_production_profile(tmp_path, monkeypatch):
    _manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    monkeypatch.setenv("DIRECT_SYNC_PRODUCTION", "1")

    report = install_pack._credential_report(credential_path)

    assert report["status"] == "FAIL"
    assert report["raw_secret_configured"] is True
    assert report["production_profile_enabled"] is True
    assert "raw credential secret is disabled in production" in report["blocked_reason"]
    assert "install-pack-secret" not in json.dumps(report, ensure_ascii=False)


def test_install_pack_blocks_env_secret_ref_in_production_profile(tmp_path, monkeypatch):
    _manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    credential = json.loads(credential_path.read_text(encoding="utf-8"))
    credential.pop("secret")
    credential["secret_ref"] = "env:CONTAINER_RUNTIME_SECRET"
    credential_path.write_text(json.dumps(credential, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setenv("DIRECT_SYNC_PRODUCTION", "1")
    monkeypatch.setenv("CONTAINER_RUNTIME_SECRET", "runtime-secret")

    report = install_pack._credential_report(credential_path)

    assert report["status"] == "FAIL"
    assert report["secret_ref_configured"] is True
    assert report["secret_ref_scheme"] == "env"
    assert "env secret_ref is disabled in production" in report["blocked_reason"]
    assert "runtime-secret" not in json.dumps(report, ensure_ascii=False)


def test_install_pack_blocks_invalid_secret_ref_scheme(tmp_path):
    _manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    credential = json.loads(credential_path.read_text(encoding="utf-8"))
    credential.pop("secret")
    credential["secret_ref"] = "file:producer-secret"
    credential_path.write_text(json.dumps(credential, ensure_ascii=False), encoding="utf-8")

    report = install_pack._credential_report(credential_path)

    assert report["status"] == "FAIL"
    assert report["secret_ref_scheme"] == "file"
    assert "secret_ref must start with env:, dpapi:, or wincred:" in report["blocked_reason"]


def test_install_pack_quotes_scheduled_task_command_for_windows_paths_with_spaces():
    command = _quote_cmd(
        [
            r"C:\Program Files\Python 3.11\python.exe",
            r"C:\Company Apps\Container Audit\tools\direct_sync_relay_runner.py",
            "--credential-path",
            r"C:\ProgramData\KM Tech\credential.json",
        ]
    )

    assert "'" not in command
    assert '"C:\\Program Files\\Python 3.11\\python.exe"' in command
    assert '"C:\\Company Apps\\Container Audit\\tools\\direct_sync_relay_runner.py"' in command
    assert '"C:\\ProgramData\\KM Tech\\credential.json"' in command


def test_install_pack_writes_utf8_wrapper_script_for_long_runner_command(tmp_path):
    wrapper_path = tmp_path / "direct-sync-relay-container-audit.cmd"
    runner_parts = [
        r"C:\Program Files\Python 3.12\python.exe",
        r"C:\Company Apps\Container Audit\tools\direct_sync_relay_runner.py",
        "--source-glob",
        "이적작업이벤트로그_*.csv",
    ]

    install_pack._write_scheduled_task_wrapper(wrapper_path, runner_parts)

    text = wrapper_path.read_text(encoding="utf-8")
    assert text.startswith("@echo off\nchcp 65001 >nul\n")
    assert "direct_sync_relay_runner.py" in text
    assert "이적작업이벤트로그_*.csv" in text
    assert text.rstrip().endswith("exit /b %ERRORLEVEL%")


def test_install_pack_apply_without_confirm_is_blocked(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-blocked.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--report-path",
            str(report_path),
            "--apply",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["blocked_reason"] == "apply requires --confirm-production-install"
    assert report["production_apply_guard"]["requires_confirm_production_install"] is True


def test_install_pack_apply_writes_applying_report_before_running_command(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    credential = json.loads(credential_path.read_text(encoding="utf-8"))
    credential.pop("secret")
    credential["secret_ref"] = "wincred:KMTech.DirectSync.ContainerAudit.PC-APPLY"
    credential_path.write_text(json.dumps(credential, ensure_ascii=False), encoding="utf-8")
    report_path = tmp_path / "install-pack-applying.json"
    observed_statuses = []

    def fake_run_command(command):
        observed_statuses.append(json.loads(report_path.read_text(encoding="utf-8-sig"))["status"])
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(install_pack, "_run_command", fake_run_command)

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData"),
            "--report-path",
            str(report_path),
            "--apply",
            "--confirm-production-install",
            "--allow-interactive-task-for-local-test",
        ]
    )

    assert exit_code == 0
    assert observed_statuses == ["APPLYING"]
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "PASS"
    assert report["command_result"]["returncode"] == 0
    wrapper_path = Path(report["scheduled_task_wrapper_path"])
    assert wrapper_path.is_file()
    wrapper_text = wrapper_path.read_text(encoding="utf-8")
    assert "direct_sync_relay_runner.py" in wrapper_text
    launcher_path = Path(report["scheduled_task_launcher_path"])
    assert launcher_path.is_file()
    assert not launcher_path.read_bytes().startswith(b"\xef\xbb\xbf")
    launcher_text = launcher_path.read_text(encoding="ascii")
    assert "WScript.Shell" in launcher_text
    assert str(wrapper_path.resolve()) in launcher_text
    tr_index = report["scheduled_task_create_command"].index("/TR")
    assert report["scheduled_task_create_command"][tr_index + 1] == report["scheduled_task_launcher_command"]
    assert len(report["scheduled_task_create_command"][tr_index + 1]) <= 261


def test_install_pack_apply_supports_stored_password_task_without_leaking_password(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    credential = json.loads(credential_path.read_text(encoding="utf-8"))
    credential.pop("secret")
    credential["secret_ref"] = "wincred:KMTech.DirectSync.ContainerAudit.PC-APPLY"
    credential_path.write_text(json.dumps(credential, ensure_ascii=False), encoding="utf-8")
    report_path = tmp_path / "install-pack-task-user.json"
    commands = []
    monkeypatch.setenv("TASK_PASSWORD_FOR_TEST", "stored-task-password")
    monkeypatch.setattr(
        install_pack,
        "_run_command",
        lambda command: commands.append(command) or {"returncode": 0, "stdout": "", "stderr": ""},
    )

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData"),
            "--report-path",
            str(report_path),
            "--task-run-user",
            r"TEST1\kmtech-remote-admin",
            "--task-run-password-env",
            "TASK_PASSWORD_FOR_TEST",
            "--apply",
            "--confirm-production-install",
        ]
    )

    assert exit_code == 0
    assert commands and commands[0][0] == "powershell.exe"
    assert "stored-task-password" not in " ".join(commands[0])
    command_script = decode_encoded_powershell_command(commands[0])
    assert "Register-ScheduledTask" in command_script
    assert "TASK_PASSWORD_FOR_TEST" in command_script
    assert "stored-task-password" not in command_script
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    report_text = report_path.read_text(encoding="utf-8-sig")
    assert report["task_principal"]["mode"] == "stored_password"
    assert report["task_principal"]["password_source"] == "env:TASK_PASSWORD_FOR_TEST"
    assert report["task_principal"]["password_in_report"] is False
    assert report["scheduled_task_create_command"][report["scheduled_task_create_command"].index("/RP") + 1] == "[redacted]"
    assert "stored-task-password" not in report_text


def test_install_pack_apply_supports_password_file_without_leaking_password(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    credential = json.loads(credential_path.read_text(encoding="utf-8"))
    credential.pop("secret")
    credential["secret_ref"] = "wincred:KMTech.DirectSync.ContainerAudit.PC-APPLY"
    credential_path.write_text(json.dumps(credential, ensure_ascii=False), encoding="utf-8")
    report_path = tmp_path / "install-pack-task-password-file.json"
    password_file = tmp_path / "task-password.txt"
    password_file.write_text("  file-task-password\t\n", encoding="utf-8")
    scan_source_dir = tmp_path / "events"
    scan_source_dir.mkdir()
    commands = []
    monkeypatch.setattr(
        install_pack,
        "_run_command",
        lambda command: commands.append(command) or {"returncode": 0, "stdout": "", "stderr": ""},
    )

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData"),
            "--scan-source-dir",
            str(scan_source_dir),
            "--report-path",
            str(report_path),
            "--task-run-user",
            r"TEST1\kmtech-remote-admin",
            "--task-run-password-file",
            str(password_file),
            "--apply",
            "--confirm-production-install",
        ]
    )

    assert exit_code == 0
    assert commands and commands[0][0] == "powershell.exe"
    assert "file-task-password" not in " ".join(commands[0])
    command_script = decode_encoded_powershell_command(commands[0])
    assert "Register-ScheduledTask" in command_script
    assert str(password_file.resolve()) in command_script
    assert "file-task-password" not in command_script
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    report_text = report_path.read_text(encoding="utf-8-sig")
    assert report["status"] == "PASS"
    assert report["task_principal"]["mode"] == "stored_password"
    assert report["task_principal"]["password_source"] == "file"
    assert report["scheduled_task_create_command"][report["scheduled_task_create_command"].index("/RP") + 1] == "[redacted]"
    assert "file-task-password" not in report_text
    password, source, error = install_pack._read_task_password(
        argparse.Namespace(task_run_password_env="", task_run_password_file=str(password_file))
    )
    assert (password, source, error) == ("  file-task-password\t", "file", "")


def test_install_pack_blocks_task_user_without_password_source(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-task-user-blocked.json"

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData"),
            "--report-path",
            str(report_path),
            "--task-run-user",
            r"TEST1\kmtech-remote-admin",
        ]
    )

    assert exit_code == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["task_principal"]["status"] == "FAIL"
    assert "requires --task-run-password" in report["blocked_reason"]


def test_install_pack_apply_blocks_interactive_task_without_explicit_local_test_flag(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-interactive-task-blocked.json"

    exit_code = install_pack.main(
        [
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(tmp_path / "ProgramData"),
            "--report-path",
            str(report_path),
            "--apply",
            "--confirm-production-install",
        ]
    )

    assert exit_code == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["task_principal"]["status"] == "FAIL"
    assert "production apply requires --task-run-user" in report["blocked_reason"]
    assert "--allow-interactive-task-for-local-test" in report["blocked_reason"]


def test_install_pack_blocks_invalid_task_password_sources(tmp_path, monkeypatch):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    password_file = tmp_path / "task-password.txt"
    password_file.write_text("file-task-password", encoding="utf-8")
    empty_password_file = tmp_path / "empty-task-password.txt"
    empty_password_file.write_text("", encoding="utf-8")
    monkeypatch.delenv("MISSING_TASK_PASSWORD", raising=False)
    cases = [
        (["--task-run-password-env", "MISSING_TASK_PASSWORD"], "requires --task-run-user"),
        (
            ["--task-run-user", r"TEST1\kmtech-remote-admin", "--task-run-password-env", "MISSING_TASK_PASSWORD"],
            "env var is empty",
        ),
        (
            ["--task-run-user", r"TEST1\kmtech-remote-admin", "--task-run-password-file", str(empty_password_file)],
            "file is empty",
        ),
        (
            [
                "--task-run-user",
                r"TEST1\kmtech-remote-admin",
                "--task-run-password-env",
                "MISSING_TASK_PASSWORD",
                "--task-run-password-file",
                str(password_file),
            ],
            "use only one",
        ),
    ]
    for index, (extra_args, expected_reason) in enumerate(cases):
        report_path = tmp_path / f"invalid-task-password-{index}.json"
        result = install_pack.main(
            [
                "--producer-manifest-path",
                str(manifest_path),
                "--credential-path",
                str(credential_path),
                "--program-data-root",
                str(tmp_path / "ProgramData"),
                "--report-path",
                str(report_path),
                *extra_args,
            ]
        )

        assert result == 2
        report = json.loads(report_path.read_text(encoding="utf-8-sig"))
        assert report["status"] == "BLOCKED"
        assert expected_reason in report["blocked_reason"]


def test_install_pack_uninstall_skips_create_only_preflight_without_manifest_or_credential(tmp_path, monkeypatch):
    report_path = tmp_path / "install-pack-uninstall.json"
    observed_commands = []

    def fake_run_command(command):
        observed_commands.append(command)
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(install_pack, "_run_command", fake_run_command)

    exit_code = install_pack.main(
        [
            "--report-path",
            str(report_path),
            "--task-run-user",
            r"TEST1\kmtech-remote-admin",
            "--apply",
            "--uninstall",
            "--confirm-production-install",
        ]
    )

    assert exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "PASS"
    assert report["uninstall"] is True
    assert report["task_principal"]["status"] == "SKIPPED"
    assert report["scheduled_task_create_command"] == []
    assert observed_commands == [["schtasks.exe", "/Delete", "/TN", "direct-sync-relay-container-audit", "/F"]]
    assert report["producer_manifest"]["status"] == "SKIPPED"
    assert report["credential"]["status"] == "SKIPPED"
    assert report["source_scan_validation"]["status"] == "SKIPPED"


def test_install_pack_run_command_reports_start_failure(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("missing schtasks")

    monkeypatch.setattr(install_pack.subprocess, "run", fake_run)

    result = install_pack._run_command(["missing-schtasks.exe"])

    assert result["returncode"] is None
    assert result["error_code"] == "scheduled_task_command_start_failed"
    assert "FileNotFoundError" in result["error_message"]


def test_install_pack_blocks_relative_program_data_root(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    report_path = tmp_path / "install-pack-relative-root.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            "relative-runtime-root",
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["blocked_reason"] == "program_data_root must be an absolute path"
    assert report["runtime_path_boundary"]["status"] == "FAIL"


def test_install_pack_blocks_program_data_root_that_is_existing_file(tmp_path):
    manifest_path, credential_path = make_manifest_and_credential(tmp_path)
    program_data_root = tmp_path / "runtime-root-is-file"
    program_data_root.write_text("not a directory", encoding="utf-8")
    report_path = tmp_path / "install-pack-file-root.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(INSTALL_PACK_SCRIPT),
            "--producer-manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--program-data-root",
            str(program_data_root),
            "--report-path",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert report["status"] == "BLOCKED"
    assert report["blocked_reason"] == "program_data_root exists and is not a directory"
    assert report["runtime_path_boundary"]["status"] == "FAIL"
    assert report["runtime_path_boundary"]["all_runtime_paths_under_program_data_root"] is False

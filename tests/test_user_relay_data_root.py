from types import SimpleNamespace
from pathlib import Path
import os
import subprocess

import pytest
import user_relay
import current_user_onboarding
import container_audit_product_host
import writer_session_fence
from current_user_onboarding import onboard_current_user
from tests.test_current_user_onboarding import (
    existing_possession_key_contract, _ready_state, _profile_loader,
    _credential_loader, _ledger_factory,
)
from tests.powershell_contracts import run_functions


@pytest.mark.usefixtures("existing_possession_key_contract")
def test_onboarding_preserves_custom_root_in_autostart_and_restart(tmp_path, monkeypatch):
    app_root = tmp_path / "app"
    app_root.mkdir()
    executable = app_root / "Container_Audit.exe"
    executable.write_bytes(b"fixture")
    data_root = tmp_path / "active data 한글"
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(data_root)}
    stored = {}
    launches = []
    monkeypatch.setattr(user_relay, "_registry_set", lambda value: stored.update(value=value))
    monkeypatch.setattr(user_relay, "_registry_get", lambda: stored.get("value", ""))
    monkeypatch.setattr(user_relay.subprocess, "Popen", lambda command, **kwargs:
                        launches.append(command) or SimpleNamespace(pid=123))

    def register(paths):
        _ready_state(paths)
        return 0

    report = onboard_current_user(
        app_root, environ=environment, registration_runner=register,
        profile_loader=_profile_loader, credential_loader=_credential_loader,
        ledger_factory=_ledger_factory,
    )
    assert report["status"] == "READY"
    expected = [str(executable.resolve()), user_relay.USER_RELAY_MODE,
                "--data-root", str(data_root.resolve())]
    assert stored["value"] == subprocess.list2cmdline(expected)
    assert launches == [expected]


@pytest.mark.parametrize("entrypoint", ["Container_Audit.exe", "main.py", "Container_Audit.py"])
def test_custom_root_is_explicit_and_no_credentials_enter_command(tmp_path, monkeypatch, entrypoint):
    app = tmp_path / "app"
    app.mkdir()
    (app / entrypoint).touch()
    root = tmp_path / 'data space 한글'
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(root))
    monkeypatch.setenv("CONTAINER_AUDIT_ENROLLMENT_TOKEN", "synthetic-secret-never-in-command")

    command = user_relay.build_user_relay_command(app)

    assert command[-2:] == ["--data-root", str(root.resolve())]
    assert "synthetic-secret-never-in-command" not in subprocess.list2cmdline(command)
    assert len(command[command.index(user_relay.USER_RELAY_MODE) + 1:]) == 2


@pytest.mark.parametrize("entrypoint", ["Container_Audit.exe", "main.py", "Container_Audit.py"])
def test_default_root_command_is_unchanged(tmp_path, entrypoint):
    app = tmp_path / "app"
    app.mkdir()
    entry = app / entrypoint
    entry.touch()
    prefix = ([str(entry)] if entrypoint.endswith(".exe") else
              [user_relay.sys.executable, *(["-I", "-B"] if entrypoint == "main.py" else []), str(entry)])
    assert user_relay.build_user_relay_command(app, environ={}) == [*prefix, user_relay.USER_RELAY_MODE]


def test_replacement_recovery_preserves_root_with_canonical_pythonw(tmp_path):
    app = tmp_path / "current" / "app"
    app.mkdir(parents=True)
    (app / "main.py").touch()
    runtime = app.parent / "runtime"
    runtime.mkdir()
    (runtime / "pythonw.exe").touch()
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "adopted data")}

    command = current_user_onboarding._replacement_user_relay_command(app, environ=environment)

    assert command == [str(runtime / "pythonw.exe"), "-I", "-B", str(app / "main.py"),
                       user_relay.USER_RELAY_MODE, "--data-root", environment["CONTAINER_AUDIT_DATA_ROOT"]]


def test_logon_root_argument_wins_over_environment_without_fallback(tmp_path, monkeypatch):
    active = tmp_path / "active data"
    active.mkdir()
    unused = tmp_path / "old default"
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(unused))
    cycles = []
    monkeypatch.setattr(user_relay, "_runtime_cycle", lambda **kwargs: cycles.append(kwargs) or {"status": "PASS"})

    assert user_relay.main(["--data-root", str(active), "--once"]) == 0

    assert cycles[0]["direct_sync_root"] == active / "direct_sync"
    assert cycles[0]["scan_source_dir"] == active / "events"
    assert not unused.exists()
    assert (active / "direct_sync/status/container_audit_user_relay.json").is_file()
    assert not list(active.glob(".relay-access-*"))


@pytest.mark.parametrize("failure", ["missing", "not_directory", "read_denied", "write_denied"])
def test_unavailable_root_stops_and_notifies_without_creating_default(tmp_path, monkeypatch, failure):
    active = tmp_path / "active data"
    if failure == "not_directory":
        active.touch()
    elif failure != "missing":
        active.mkdir()
    if failure == "read_denied":
        scandir = os.scandir

        def deny_read(path):
            if Path(path) == active:
                raise PermissionError("synthetic read denial")
            return scandir(path)

        monkeypatch.setattr(os, "scandir", deny_read)
    if failure == "write_denied":
        original_open = Path.open

        def deny_write(path, *args, **kwargs):
            if path.parent == active:
                raise PermissionError("synthetic write denial")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", deny_write)
    notices = []
    def notify():
        assert getattr(writer_session_fence._WRITER_LOCAL, "depth", 0) == 0
        notices.append("unavailable")

    monkeypatch.setattr(user_relay, "_notify_data_root_error", notify)
    monkeypatch.setattr(user_relay, "_runtime_cycle", lambda **kwargs: pytest.fail("unavailable root ran relay"))
    default = user_relay.build_container_audit_storage_paths().data_root

    assert container_audit_product_host.dispatch_product_mode([
        user_relay.USER_RELAY_MODE, "--data-root", str(active), "--once",
    ]) == 1

    assert notices == ["unavailable"]
    assert not default.exists()
    if failure == "missing":
        assert not active.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows logon notification")
def test_root_failure_notification_is_visible_and_contains_no_exception_payload(monkeypatch, capsys):
    from tkinter import messagebox

    calls = []
    monkeypatch.setattr(messagebox, "showerror", lambda *args: calls.append(args))
    user_relay._notify_data_root_error()
    assert len(calls) == 1
    assert "데이터 폴더" in calls[0][1]
    assert "CONTAINER_AUDIT_DATA_ROOT_UNAVAILABLE" in capsys.readouterr().err


def test_hosted_failure_diagnostics_use_explicit_root(tmp_path, monkeypatch):
    active = tmp_path / "active"
    active.mkdir()
    monkeypatch.setattr(user_relay, "main", lambda args: (_ for _ in ()).throw(RuntimeError("synthetic-secret")))
    assert container_audit_product_host.dispatch_product_mode([
        user_relay.USER_RELAY_MODE, "--data-root", str(active),
    ]) == 1
    diagnostic = active / "direct_sync/status/container_audit_user_relay.json"
    assert diagnostic.is_file()
    assert "synthetic-secret" not in diagnostic.read_text(encoding="utf-8")
    assert not user_relay.build_container_audit_storage_paths().data_root.exists()


@pytest.mark.parametrize("custom", [False, True])
def test_installer_restart_and_lifecycle_validator_agree_with_python(tmp_path, custom):
    repo = Path(__file__).resolve().parents[1]
    code = tmp_path / "code space"
    app = code / "app"
    app.mkdir(parents=True)
    (app / "main.py").touch()
    (code / "runtime").mkdir()
    (code / "runtime/pythonw.exe").touch()
    values = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "data space 한글") if custom else ""}
    if custom:
        Path(values["CONTAINER_AUDIT_DATA_ROOT"]).mkdir()
    expected = current_user_onboarding._replacement_user_relay_command_line(app, environ=values)
    values.update(CA_CODE_ROOT=str(code), CA_EXPECTED_COMMAND=expected, CA_REPO_ROOT=str(repo))
    result = run_functions(
        tmp_path, repo / "INSTALL_CANONICAL_PORTABLE.ps1", ["Full", "Arg", "Command"],
        "if ((Command $env:CA_CODE_ROOT) -cne $env:CA_EXPECTED_COMMAND) { throw 'restart root differs' }",
        values=values,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    result = run_functions(
        tmp_path, repo / "tools/container_writer_session.ps1",
        ["Test-ExactPropertySet", "Test-ContainerLifecycleMutationEvidence"],
        r'''
. (Join-Path $env:CA_REPO_ROOT 'tools/bootstrap_integrity.ps1')
$Script:UserRelayMode = '--container-audit-user-relay'
$receipt = [pscustomobject]@{
    relay_autostart = [pscustomobject]@{
        status='PASS'; principal='current_user'; registry_hive='HKEY_CURRENT_USER'
        registry_key='Software\Microsoft\Windows\CurrentVersion\Run'
        registry_value='KMTech.ContainerAudit.Relay'; command=$env:CA_EXPECTED_COMMAND
    }
    relay_start = [pscustomobject]@{status='START_REQUESTED'; process_id=123}
}
if (-not (Test-ContainerLifecycleMutationEvidence $receipt $env:CA_CODE_ROOT)) {
    throw 'correct root rejected'
}
$receipt.relay_autostart.command += ' --data-root C:\wrong-dataset'
if (Test-ContainerLifecycleMutationEvidence $receipt $env:CA_CODE_ROOT) {
    throw 'wrong root accepted'
}
''', values=values,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("invalid", ["missing", "code", "parent", "syncthing"])
def test_installer_rejects_unavailable_or_unsafe_root_before_mutation(tmp_path, invalid):
    repo = Path(__file__).resolve().parents[1]
    code = tmp_path / "code"
    code.mkdir()
    roots = {"missing": tmp_path / "missing", "code": code,
             "parent": tmp_path, "syncthing": Path("C:/Sync")}
    selected = roots[invalid]
    result = run_functions(
        tmp_path, repo / "INSTALL_CANONICAL_PORTABLE.ps1", ["Full", "Arg", "Command"],
        r'''
$rejected = $false
try { [void](Command $env:CA_CODE_ROOT) } catch { $rejected = $true }
if (-not $rejected) { throw 'unsafe or unavailable data root accepted' }
''', values={"CA_CODE_ROOT": str(code), "CONTAINER_AUDIT_DATA_ROOT": str(selected)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    if invalid == "missing":
        assert not selected.exists()

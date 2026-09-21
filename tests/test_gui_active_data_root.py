"""A normal launcher must reopen the dataset selected by user onboarding."""
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

import Container_Audit as gui
import storage_policy
import user_relay
import current_user_onboarding
import writer_session_fence
from tests.native_process_fixtures import native_argument_recorder
from tests.test_current_user_onboarding import (
    existing_possession_key_contract, _ready_state, _profile_loader,
    _credential_loader, _ledger_factory,
)
from tests.test_writer_session_fence import _active_payload, _write_active


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def registered_root(tmp_path, monkeypatch):
    if os.name != "nt":
        pytest.skip("current-user Windows relay registration")
    import winreg
    from contextlib import nullcontext

    active = tmp_path / "active data 한글"
    active.mkdir()
    command = subprocess.list2cmdline([
        str(tmp_path / "app" / "Container_Audit.exe"),
        user_relay.USER_RELAY_MODE, "--data-root", str(active),
    ])
    saved = {"command": command, "kind": winreg.REG_SZ}

    def open_key(hive, name, *args):
        assert hive == winreg.HKEY_CURRENT_USER
        assert name == user_relay.USER_RELAY_RUN_KEY
        return nullcontext("test-run-key")

    def query(key, name):
        assert key == "test-run-key" and name == user_relay.USER_RELAY_RUN_VALUE
        return saved["command"], saved["kind"]

    monkeypatch.setattr(winreg, "OpenKey", open_key)
    monkeypatch.setattr(winreg, "QueryValueEx", query)
    monkeypatch.delenv(storage_policy.DATA_ROOT_ENV, raising=False)
    return active, saved


def test_storage_without_environment_reopens_registered_dataset(tmp_path, registered_root):
    active, _ = registered_root
    paths = storage_policy.build_container_audit_storage_paths(application_path=str(tmp_path / "app"))
    assert paths.data_root == active
    assert paths.events_dir == active / "events"
    assert paths.direct_sync_root == active / "direct_sync"


def test_plain_launcher_and_gui_restart_reopen_registered_dataset(
    tmp_path, monkeypatch, registered_root, native_argument_recorder,
):
    active, _ = registered_root
    current = active / "events" / "_current_tray_state_fixture.json"
    current.parent.mkdir()
    current.write_bytes(b'{"barcode_count":1,"fixture":"preserve"}')
    original = current.read_bytes()
    hold = active / "events" / "preflight-hold-fixture.json"
    hold.write_bytes(b'{"pending":["fixture-barcode"]}')
    identity = active / "direct_sync" / "producer_identity.json"
    identity.parent.mkdir()
    identity.write_bytes(b'{"device_id":"synthetic-existing-identity"}')
    preserved = {path: path.read_bytes() for path in (current, hold, identity)}
    packet = tmp_path / "portable 한글"
    (packet / "runtime").mkdir(parents=True)
    (packet / "app").mkdir()
    shutil.copy2(native_argument_recorder, packet / "runtime/pythonw.exe")
    launcher = packet / "launch-container-audit.cmd"
    shutil.copy2(ROOT / "portable/launch-container-audit.cmd", launcher)
    receipt = tmp_path / "launcher.json"
    environment = dict(os.environ, CA_ARGUMENT_RECEIPT=str(receipt))
    assert storage_policy.DATA_ROOT_ENV not in environment
    result = subprocess.run(
        '"' + os.environ['COMSPEC'] + '" /d /s /c ""' + str(launcher) + '""',
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == 0, result.stderr
    arguments = json.loads(receipt.read_text())
    assert arguments == ['-I', '-B', str(packet / 'app/main.py')]

    observed = []
    monkeypatch.setattr(gui, "verify_factory_contract_startup", lambda: None)
    monkeypatch.setattr(gui, "_first_run_onboarding_enabled", lambda: False)
    monkeypatch.setattr(gui, "prepare_startup_item_catalog", lambda: None)
    def app():
        paths = storage_policy.build_container_audit_storage_paths(application_path=str(ROOT))
        observed.append(paths)
        assert (paths.events_dir / current.name).read_bytes() == original
        return SimpleNamespace(root=SimpleNamespace(after=lambda *args: None), run=lambda: None)
    monkeypatch.setattr(gui, "ContainerAudit", app)
    for _ in range(2):
        monkeypatch.delenv(storage_policy.DATA_ROOT_ENV, raising=False)
        monkeypatch.setattr(sys, "argv", arguments[2:])
        portable = runpy.run_path(str(ROOT / 'portable/main.py'))
        assert portable['main']() == 0
    assert [paths.data_root for paths in observed] == [active, active]
    assert current.read_bytes() == original
    assert {path: path.read_bytes() for path in preserved} == preserved


@pytest.mark.usefixtures("existing_possession_key_contract")
def test_successful_onboarding_persists_root_for_a_later_plain_gui(
    tmp_path, monkeypatch, registered_root,
):
    active, saved = registered_root
    saved["command"] = 'C:/app/Container_Audit.exe --container-audit-user-relay'
    app = tmp_path / "app"
    app.mkdir()
    (app / "Container_Audit.exe").touch()
    monkeypatch.setattr(user_relay, "_registry_set", lambda value: saved.update(command=value))
    monkeypatch.setattr(user_relay.subprocess, "Popen", lambda *args, **kw: SimpleNamespace(pid=123))
    def register(paths):
        _ready_state(paths)
        return 0
    report = current_user_onboarding.onboard_current_user(
        app, environ={storage_policy.DATA_ROOT_ENV: str(active)},
        registration_runner=register, profile_loader=_profile_loader,
        credential_loader=_credential_loader, ledger_factory=_ledger_factory,
    )
    assert report["status"] == "READY"
    assert storage_policy.DATA_ROOT_ENV not in os.environ
    paths = storage_policy.build_container_audit_storage_paths(application_path=str(app))
    assert paths.data_root == active
    assert paths.direct_sync_root == Path(report["direct_sync_root"])


def test_registered_root_is_shared_by_relay_onboarding_and_replacement(
    tmp_path, monkeypatch, registered_root,
):
    active, saved = registered_root
    app = tmp_path / "portable" / "app"
    app.mkdir(parents=True)
    (app / "main.py").touch()
    (app.parent / "runtime").mkdir()
    (app.parent / "runtime/pythonw.exe").touch()
    paths = current_user_onboarding.resolve_current_user_onboarding_paths(app)
    assert paths.data_root == active
    assert paths.logistics_profile_path == active / "logistics-profile/runtime-profile.json"
    assert paths.bootstrap_tls_ca_bundle_path == active / "bootstrap/ca-bundle.pem"
    assert user_relay.build_user_relay_command(app)[-2:] == ["--data-root", str(active)]
    assert current_user_onboarding._replacement_user_relay_command(app)[-2:] == ["--data-root", str(active)]
    cycles = []
    monkeypatch.setattr(user_relay, "_runtime_cycle", lambda **kw: cycles.append(kw) or {"status": "PASS"})
    original_command = saved["command"]
    assert user_relay.main(["--app-root", str(app), "--once"]) == 0
    assert cycles[0]["direct_sync_root"] == paths.direct_sync_root == active / "direct_sync"
    assert cycles[0]["scan_source_dir"] == paths.events_dir == active / "events"
    assert saved["command"] == original_command


def test_explicit_argument_then_environment_override_persisted_root(
    tmp_path, monkeypatch, registered_root,
):
    active, saved = registered_root
    override = tmp_path / "override"
    explicit = tmp_path / "argument"
    override.mkdir()
    explicit.mkdir()
    original = saved["command"]
    monkeypatch.setenv(storage_policy.DATA_ROOT_ENV, str(override))
    assert storage_policy.build_container_audit_storage_paths().data_root == override
    assert storage_policy.build_container_audit_storage_paths(data_root=explicit).data_root == explicit
    monkeypatch.setattr(gui, "verify_factory_contract_startup", lambda: None)
    monkeypatch.setattr(gui, "_first_run_onboarding_enabled", lambda: False)
    monkeypatch.setattr(gui, "prepare_startup_item_catalog", lambda: None)
    observed = []
    def app():
        observed.append(storage_policy.build_container_audit_storage_paths().data_root)
        return SimpleNamespace(root=SimpleNamespace(after=lambda *args: None), run=lambda: None)
    monkeypatch.setattr(gui, "ContainerAudit", app)
    assert gui.main(["--data-root", str(explicit)]) == 0
    assert observed == [explicit]
    assert saved["command"] == original
    monkeypatch.delenv(storage_policy.DATA_ROOT_ENV)
    assert storage_policy.build_container_audit_storage_paths().data_root == active


@pytest.mark.parametrize("entry", ["gui", "relay"])
@pytest.mark.parametrize("failure", ["missing", "file", "read_denied", "write_denied", "registration_denied"])
def test_saved_root_failure_stops_before_work_and_never_creates_default(
    tmp_path, monkeypatch, registered_root, entry, failure,
):
    active, _ = registered_root
    default = Path(os.environ["LOCALAPPDATA"]) / "KMTech/ContainerAudit"
    if failure in {"missing", "file"}:
        active.rmdir()
        if failure == "file":
            active.touch()
    elif failure == "read_denied":
        scandir = os.scandir
        def deny_read(path):
            if Path(path) == active:
                raise PermissionError("synthetic-read-denial")
            return scandir(path)
        monkeypatch.setattr(os, "scandir", deny_read)
    elif failure == "write_denied":
        original_open = Path.open
        def deny_write(path, *args, **kwargs):
            if path.parent == active:
                raise PermissionError("synthetic-write-denial")
            return original_open(path, *args, **kwargs)
        monkeypatch.setattr(Path, "open", deny_write)
    else:
        import winreg
        def denied(*args):
            raise PermissionError("synthetic-registration-denial")
        monkeypatch.setattr(winreg, "OpenKey", denied)
    notices = []
    def notify(*args):
        assert getattr(writer_session_fence._WRITER_LOCAL, "depth", 0) == 0
        notices.append(args)
    monkeypatch.setattr(gui.messagebox, "showerror", notify)
    monkeypatch.setattr(gui, "verify_factory_contract_startup", lambda: None)
    monkeypatch.setattr(gui, "ContainerAudit", lambda: pytest.fail("GUI reached unavailable dataset"))
    monkeypatch.setattr(user_relay, "_runtime_cycle", lambda **kw: pytest.fail("relay reached unavailable dataset"))
    assert (gui.main([]) if entry == "gui" else user_relay.main(["--once"])) == 1
    assert len(notices) == 1 and "복구" in notices[0][1]
    assert "synthetic" not in notices[0][1]
    assert not default.exists()
    if failure == "missing":
        assert not active.exists()


@pytest.mark.parametrize("suffix", ["--data-root", '--data-root ""', "--data-root relative", "--data-root C:/ --once"])
def test_malformed_saved_selection_never_falls_back(registered_root, suffix):
    _, saved = registered_root
    saved["command"] = 'C:/app/Container_Audit.exe --container-audit-user-relay ' + suffix
    with pytest.raises(ValueError):
        storage_policy.build_container_audit_storage_paths()


def test_default_registration_retains_separate_default_roots(registered_root):
    _, saved = registered_root
    saved["command"] = 'C:/app/Container_Audit.exe --container-audit-user-relay'
    paths = storage_policy.build_container_audit_storage_paths()
    home = Path(os.environ["LOCALAPPDATA"])
    assert paths.data_root == home / "KMTech/ContainerAudit"
    assert paths.direct_sync_root == home / "KMTech/DirectSync/container_audit"
    assert not paths.custom_data_root


def test_root_probe_preserves_existing_relay_delegation(tmp_path):
    """Moving the relay probe must not require a new deployment permission."""
    fence = writer_session_fence
    root = tmp_path / "data"
    root.mkdir()
    control = tmp_path / "control"
    token = "synthetic-delegation-token" * 3
    payload = _active_payload(token=token, sources=["persistent_relay_status"])
    active = _write_active(control, payload)
    original = active.read_bytes()
    ready, release = threading.Event(), threading.Event()
    def hold_authority():
        lease = fence._acquire_named_mutex(payload["session_authority_mutex_name"], 1.0)
        assert lease is not None and not lease.abandoned
        ready.set()
        release.wait(10)
        lease.release()
    thread = threading.Thread(target=hold_authority, daemon=True)
    thread.start()
    environment = {
        fence.DELEGATION_TOKEN_ENV: token,
        fence.DELEGATION_SESSION_ENV: payload["session_id"],
        fence.DELEGATION_ATTEMPT_ENV: payload["attempt_id"],
        fence.DELEGATION_TRANSACTION_ENV: payload["replacement_transaction_id"],
    }
    try:
        assert ready.wait(5)
        with pytest.raises(fence.WriterFencedError):
            with fence.writer_admission("persistent_relay_status", control_root=control, environ={}):
                storage_policy.validate_existing_data_root(root)
        with fence.writer_admission("persistent_relay_status", control_root=control, environ=environment):
            storage_policy.validate_existing_data_root(root)
        assert list(root.iterdir()) == []
        assert active.read_bytes() == original
    finally:
        release.set()
        thread.join(5)

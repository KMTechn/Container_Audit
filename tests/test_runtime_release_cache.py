"""Installed packet verification must finish before the first data admission."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import current_user_onboarding as onboarding
import data_generation_guard as guard
import writer_session_fence as fence
from tests.powershell_contracts import run_functions


def _write_packet(root, source_root, build="a" * 40):
    app = root / "app"
    app.mkdir(parents=True)
    (app / "Container_Audit.py").write_text('CURRENT_VERSION = "v2.0.99"\n', encoding="utf-8")
    (app / "data_generation_guard.py").write_text("# runtime fixture\n", encoding="utf-8")
    (root / "runtime").mkdir()
    (root / "runtime/pythonw.exe").write_bytes(b"portable runtime fixture")
    (root / "portable-manifest.json").write_text(json.dumps({
        "version": "v2.0.99", "source_commit": build}), encoding="utf-8")
    literal = str(root).replace("'", "''")
    result = run_functions(root.parent, source_root / "tools/bootstrap_integrity.ps1", [
        "Get-StrictFullPath", "Get-RelativeCodePath", "Get-FileSha256", "Get-CodeInventory",
        "Get-InventoryAggregate", "Protect-InstallationText",
        "Assert-InstallationMachineMetadataNoSecrets", "Write-Utf8Json", "Write-BootstrapIntegrityRecord",
    ], f"""
$BootstrapIntegritySchema='container-audit-bootstrap-integrity-v1'
$BootstrapIntegrityFileName='bootstrap-integrity.json'
[void](Write-BootstrapIntegrityRecord -Root '{literal}' -CodeRootIdentity '.')
""")
    assert result.returncode == 0, "official integrity record writer failed"
    return app


@pytest.fixture
def packet(tmp_path, monkeypatch):
    from tools import register_container_audit_worker_pc as registration

    # Keep identity and marker filenames synthetic even under long lane roots.
    monkeypatch.setattr(registration, "_current_user_sid", lambda: "S-1-5-21-219")
    source_root = Path(onboarding.__file__).resolve().parent
    app = _write_packet(tmp_path / "packet", source_root)
    if hasattr(guard, "_PORTABLE_RELEASE_CACHE"):
        monkeypatch.setattr(guard, "_PORTABLE_RELEASE_CACHE", {})
    monkeypatch.setattr(guard, "__file__", str(app / "data_generation_guard.py"))
    calls = []
    verify = onboarding.verify_bootstrap_integrity

    def observed(*args, **kwargs):
        calls.append(int(getattr(fence._WRITER_LOCAL, "depth", 0)))
        return verify(*args, **kwargs)

    monkeypatch.setattr(onboarding, "verify_bootstrap_integrity", observed)
    data = tmp_path / "data"
    data.mkdir()
    return SimpleNamespace(app=app, root=app.parent, source=source_root, calls=calls, data=data)


def _observations(packet, record_property):
    record_property("verification_calls", len(packet.calls))
    record_property("verification_calls_under_admission", sum(depth > 0 for depth in packet.calls))


def test_persistent_relay_cycles_verify_once_outside_admission(packet, monkeypatch, record_property):
    import auto_update
    import user_relay as relay

    direct_sync = packet.data / "direct_sync"
    direct_sync.mkdir()
    # Exercise the real credential locator/read admission without authentication IO.
    (direct_sync / "credential.json").write_bytes(b"{}")
    cycles = []
    cycle_verifications = []
    runtime_cycle = relay._runtime_cycle

    def observed_cycle(**kwargs):
        before = len(packet.calls)
        result = runtime_cycle(**kwargs)
        cycle_verifications.append(len(packet.calls) - before)
        return result

    def child(**kwargs):
        assert getattr(fence._WRITER_LOCAL, "depth", 0) == 0
        cycles.append(True)
        status = kwargs["direct_sync_root"] / "status/direct_sync_relay_status.json"
        status.parent.mkdir(parents=True, exist_ok=True)
        status.write_text(json.dumps({"status": "PASS"}), encoding="utf-8")
        return {"status": "PASS", "returncode": 0}

    monkeypatch.setattr(auto_update, "startup_gate", lambda *args, **kwargs: None)
    monkeypatch.setattr(auto_update, "trial_stop_requested", lambda *args: len(cycles) >= 3)
    monkeypatch.setattr(auto_update, "prepare_feed_packet", lambda *args: {"status": "OFF"})
    monkeypatch.setattr(auto_update, "relay_ready_metadata", lambda *args: {})
    monkeypatch.setattr(relay, "run_session_direct_sync_once", child)
    monkeypatch.setattr(relay, "_runtime_cycle", observed_cycle)
    assert relay.main(["--app-root", str(packet.app), "--data-root", str(packet.data),
                       "--interval-seconds", "0"]) == 0
    assert len(cycles) == 3
    _observations(packet, record_property)
    record_property("relay_cycle_verifications", json.dumps(cycle_verifications))
    assert packet.calls == [0]


def test_raw_relay_runner_verifies_once_outside_admission(packet, monkeypatch, record_property):
    from tools import direct_sync_relay_runner as runner

    requests = []

    def remote(config):
        assert getattr(fence._WRITER_LOCAL, "depth", 0) == 0
        requests.append(config)
        return {"status": "idle"}

    monkeypatch.setattr(runner, "run_relay_once", remote)
    (packet.data / "credential.json").write_bytes(b"{}")
    arguments = []
    for option, path in (
        ("--db-path", packet.data / "queue.sqlite3"),
        ("--spool-dir", packet.data / "spool"),
        ("--producer-manifest-path", packet.data / "producer.json"),
        ("--credential-path", packet.data / "credential.json"),
        ("--upload-status-dir", packet.data / "uploads"),
        ("--runtime-status-path", packet.data / "status.json"),
        ("--log-path", packet.data / "relay.log"),
    ):
        arguments.extend((option, str(path)))
    assert runner.main(arguments) == 0
    assert len(requests) == 1
    assert (packet.data / "data-generation.json").is_file()
    _observations(packet, record_property)
    assert packet.calls == [0]


def _headless_startup(monkeypatch, packet):
    import Container_Audit as app

    constructed = []
    monkeypatch.setattr(app, "verify_factory_contract_startup", lambda: None)
    monkeypatch.setattr(app, "_first_run_onboarding_enabled", lambda: False)
    monkeypatch.setattr(app, "prepare_startup_item_catalog", lambda: None)
    monkeypatch.setattr(app, "acquire_runtime_instance", lambda *args: SimpleNamespace(release=lambda: None))

    def constructor():
        assert (packet.data / "data-generation.json").is_file()
        constructed.append(True)
        return SimpleNamespace(root=SimpleNamespace(after=lambda *args: None), run=lambda: None)

    monkeypatch.setattr(app, "ContainerAudit", constructor)
    return app, constructed


def test_gui_startup_verifies_before_gui_admission(packet, monkeypatch, record_property):
    app, constructed = _headless_startup(monkeypatch, packet)
    prepared, lease = app._prepare_gui_startup(data_root=packet.data)
    assert prepared._runtime_data_root == packet.data
    lease.release()
    assert constructed == [True]
    _observations(packet, record_property)
    assert packet.calls == [0]


@pytest.mark.parametrize("failure", ["tampered", "missing", "absent_record"])
def test_failed_integrity_is_rechecked_with_the_same_refusal(packet, failure, record_property):
    target = packet.root / ("bootstrap-integrity.json" if failure == "absent_record" else "runtime/pythonw.exe")
    original = target.read_bytes()
    if failure == "tampered":
        target.write_bytes(b"tampered runtime")
    else:
        target.unlink()
    failures = []
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            guard._runtime_release()
        failures.append(str(error.value))
    assert failures[0] == failures[1]
    assert packet.calls == [0, 0]
    target.write_bytes(original)
    assert guard._runtime_release()["build_id"] == "a" * 40
    assert guard._runtime_release()["build_id"] == "a" * 40
    _observations(packet, record_property)
    assert packet.calls == [0, 0, 0]


def test_failed_warmup_keeps_gui_guard_closed(packet, monkeypatch, record_property):
    app, constructed = _headless_startup(monkeypatch, packet)
    (packet.root / "runtime/pythonw.exe").write_bytes(b"tampered runtime")
    with pytest.raises(guard.DataGenerationBlocked):
        app._prepare_gui_startup(data_root=packet.data)
    assert not constructed
    assert not (packet.data / "data-generation.json").exists()
    _observations(packet, record_property)
    assert len(packet.calls) == 2 and packet.calls[0] == 0 and packet.calls[1] > 0


def test_cached_release_is_a_copy_and_bound_to_the_resolved_packet(packet, monkeypatch, record_property):
    first = guard._runtime_release()
    first["build_id"] = "c" * 40
    assert guard._runtime_release()["build_id"] == "a" * 40
    second = _write_packet(packet.root.parent / "other", packet.source, build="b" * 40)
    monkeypatch.setattr(guard, "__file__", str(second / "data_generation_guard.py"))
    assert guard._runtime_release()["build_id"] == "b" * 40
    monkeypatch.setattr(guard, "__file__", str(packet.app / "data_generation_guard.py"))
    assert guard._runtime_release()["build_id"] == "a" * 40
    _observations(packet, record_property)
    assert packet.calls == [0, 0]


def test_generation_marker_is_rechecked_after_cached_release(packet, record_property):
    guard._runtime_release()
    guard.record_before_data_open(packet.data)
    marker = packet.data / "data-generation.json"
    original = marker.read_bytes()
    marker.write_bytes(b"invalid generation marker")
    with pytest.raises(guard.DataGenerationBlocked) as error:
        guard.record_before_data_open(packet.data)
    assert error.value.decision["status"] == "UNKNOWN"
    assert marker.read_bytes() == b"invalid generation marker"
    marker.write_bytes(original)
    _observations(packet, record_property)
    assert packet.calls == [0]


def test_invalid_release_identity_is_not_cached_after_integrity_pass(packet, monkeypatch, record_property):
    invalid = _write_packet(packet.root.parent / "invalid", packet.source, build="invalid")
    monkeypatch.setattr(guard, "__file__", str(invalid / "data_generation_guard.py"))
    for _ in range(2):
        with pytest.raises(ValueError, match="release build identity is not proven"):
            guard._runtime_release()
    _observations(packet, record_property)
    assert packet.calls == [0, 0]

"""G59: public removal, real mutex/fence/receipt, isolated OS boundaries."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
from types import SimpleNamespace
import pytest
import auto_update
import current_user_onboarding as onboarding
import data_generation_guard
import user_relay
import writer_session_fence as fence
from tests.test_writer_session_fence import _active_payload, _utc, _write_active
from tools.register_container_audit_worker_pc import _current_user_sid

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows named mutex required")

@pytest.fixture
def removal_case(tmp_path, monkeypatch):
    local = tmp_path / "worker" / "AppData" / "Local"
    root = local / fence.CONTROL_RELATIVE_PATH
    root.mkdir(parents=True)
    app = tmp_path / "managed" / "current" / "app"
    app.mkdir(parents=True)
    control = app.parent.parent / "update-control"
    control.mkdir()
    (control / "policy.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.delenv("CONTAINER_AUDIT_DATA_ROOT", raising=False)
    # Configure paths for the installed repository guard; proof logic stays real.
    monkeypatch.setattr(fence, "canonical_control_root", lambda environ=None: root)
    monkeypatch.setattr(data_generation_guard, "canonical_control_root", lambda environ=None: root)
    paths = onboarding.resolve_current_user_onboarding_paths(app)
    paths.data_root.mkdir(parents=True)
    ledger = paths.data_root / "preserved-ledger.csv"
    ledger.write_bytes(b"original business ledger\r\n")
    case = SimpleNamespace(root=root, local=local, app=app, paths=paths,
                           ledger=ledger, registry_deletes=0, rows=[])
    case.business_before = {p.relative_to(paths.data_root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in paths.data_root.rglob("*") if p.is_file()}
    run_process = subprocess.run
    def observe(arguments, *args, **kwargs):
        if isinstance(arguments, list) and arguments[-2:] == ["-Mode", "Observe"]:
            assert str(app.parent) in arguments
            return subprocess.CompletedProcess(arguments, 0, json.dumps(case.rows), "")
        return run_process(arguments, *args, **kwargs)
    monkeypatch.setattr(subprocess, "run", observe)
    def delete_registry():
        case.registry_deletes += 1
    monkeypatch.setattr(user_relay, "_registry_delete", delete_registry)
    monkeypatch.setattr(user_relay, "_registry_get", lambda: "")
    payload = _active_payload()
    payload.update(status="INSTALLING", owner_kind="canonical_installer")
    prepared = {name: payload[name] for name in (
        "app_id", "session_id", "attempt_id", "replacement_transaction_id",
        "session_started_at_utc", "orchestrator_sha256", "writer_contract_sha256",
        "writer_inventory_sha256",
    )}
    prepared.update(schema="container-audit-canonical-writer-prepared-v1", status="PREPARED",
                    operator_sid=_current_user_sid(), operator_local_appdata_root=str(local),
                    source_manifest_sha256=hashlib.sha256(b"G59 source").hexdigest(),
                    created_at_utc=_utc(), secret_values_recorded=False)
    case.prepared, case.payload = prepared, payload
    case.prepared_path = tmp_path / "prepared.json"
    def publish():
        case.prepared_path.write_text(json.dumps(prepared) + "\n", encoding="utf-8")
        payload["prepared_receipt_path"] = str(case.prepared_path)
        payload["prepared_receipt_sha256"] = hashlib.sha256(case.prepared_path.read_bytes()).hexdigest()
        case.path = _write_active(root, payload)
        case.original = case.path.read_bytes()
    case.publish = publish
    publish()
    return case

@contextmanager
def authority_owner(case, *, abandoned=False):
    ready, release = threading.Event(), threading.Event()
    leases = []
    def owner():
        leases.append(fence._acquire_named_mutex(case.payload["session_authority_mutex_name"], 0))
        ready.set()
        if not abandoned:
            release.wait(15)
            leases[0].release()
    thread = threading.Thread(target=owner)
    thread.start()
    assert ready.wait(10) and leases[0] is not None
    if abandoned:
        thread.join(10)
        assert not thread.is_alive()
    try:
        yield
    finally:
        release.set()
        thread.join(10)
        assert not thread.is_alive()
        for lease in leases:
            lease.release()

def assert_settled(case, report):
    assert report["status"] == "PASS_DATA_PRESERVED"
    assert not case.path.exists()
    record = report["abandoned_fence_settled"]
    assert set(record) == {"session_id_sha256", "attempt_id_sha256", "fence_copy_sha256", "fence_copy_path"}
    digest = hashlib.sha256(case.original).hexdigest()
    assert record["fence_copy_sha256"] == digest
    assert record["fence_copy_path"] == f"writer-session/settled/{digest}.json"
    assert (case.root.parent / record["fence_copy_path"]).read_bytes() == case.original
    for name in ("session_id", "attempt_id"):
        assert record[name + "_sha256"] == hashlib.sha256(case.payload[name].encode("utf-8")).hexdigest()
    assert json.loads(case.paths.removal_report_path.read_text(encoding="utf-8"))["abandoned_fence_settled"] == record
    assert case.ledger.read_bytes() == b"original business ledger\r\n"
    assert {p.relative_to(case.paths.data_root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in case.paths.data_root.rglob("*") if p.is_file()} == case.business_before

@pytest.mark.parametrize("abandoned", [False, True], ids=["dead-owner", "abandoned-owner"])
def test_dead_installer_removal_settles_exact_fence(removal_case, abandoned):
    case = removal_case
    if abandoned:
        with authority_owner(case, abandoned=True):
            report = onboarding.remove_current_user_setup(case.app)
    else:
        report = onboarding.remove_current_user_setup(case.app)
    assert_settled(case, report)
    assert case.registry_deletes == 1
    again = onboarding.remove_current_user_setup(case.app)
    assert again["status"] == "PASS_DATA_PRESERVED"
    assert "abandoned_fence_settled" not in again

def test_live_installer_authority_is_rejected_without_wait(removal_case, monkeypatch):
    case = removal_case
    acquire = fence._acquire_named_mutex
    waits = []
    def observe_wait(name, timeout_seconds):
        if name == case.payload["session_authority_mutex_name"]:
            waits.append(timeout_seconds)
        return acquire(name, timeout_seconds)
    with authority_owner(case):
        monkeypatch.setattr(fence, "_acquire_named_mutex", observe_wait)
        with pytest.raises(fence.WriterFencedError) as caught:
            onboarding.remove_current_user_setup(case.app)
    assert caught.value.code == "ACTIVE_WRITER_FENCE"
    assert waits == [0]
    assert case.path.read_bytes() == case.original
    assert case.registry_deletes == 0

def test_authority_open_failure_uses_existing_active_refusal(removal_case, monkeypatch):
    case = removal_case
    acquire = fence._acquire_named_mutex
    def unavailable(name, timeout_seconds):
        if name == case.payload["session_authority_mutex_name"]:
            assert timeout_seconds == 0
            raise fence.WriterFenceError("WRITER_MUTEX_CREATE_FAILED", "authority unavailable")
        return acquire(name, timeout_seconds)
    monkeypatch.setattr(fence, "_acquire_named_mutex", unavailable)
    with pytest.raises(fence.WriterFencedError) as caught:
        onboarding.remove_current_user_setup(case.app)
    assert caught.value.code == "ACTIVE_WRITER_FENCE"
    assert case.path.read_bytes() == case.original
    assert case.registry_deletes == 0


@pytest.mark.parametrize("error_type", [subprocess.SubprocessError, fence.WriterFenceError])
def test_proof_boundary_failure_uses_active_refusal(removal_case, monkeypatch, caplog, error_type):
    case = removal_case
    original_run = subprocess.run
    def fail_observation(arguments, *args, **kwargs):
        if isinstance(arguments, list) and arguments[-2:] == ["-Mode", "Observe"]:
            if error_type is fence.WriterFenceError:
                raise error_type("PROOF_TEST", "private proof detail")
            raise error_type("private proof detail")
        return original_run(arguments, *args, **kwargs)
    monkeypatch.setattr(subprocess, "run", fail_observation)
    with pytest.raises(fence.WriterFencedError) as caught:
        onboarding.remove_current_user_setup(case.app)
    assert caught.value.code == "ACTIVE_WRITER_FENCE"
    assert case.path.read_bytes() == case.original
    assert case.registry_deletes == 0
    assert not (case.root / "settled").exists()
    records = [r for r in caplog.records if r.name == fence.__name__]
    assert [r.getMessage() for r in records] == [error_type.__name__]
    assert all(r.exc_info is None for r in records)

def test_live_installer_delegation_keeps_its_fence(removal_case, monkeypatch):
    case = removal_case
    delegated = hashlib.sha256(os.urandom(32)).hexdigest()
    case.payload.update(
        delegated_sources=sorted(["current_user_setup_removal", "current_user_onboarding_storage",
                                  "user_relay_autostart_remove", "persistent_relay_registry",
                                  "persistent_relay_status"]),
        delegation_sha256=hashlib.sha256(delegated.encode("utf-8")).hexdigest(),
        delegation_expires_at_utc=_utc(300),
    )
    case.publish()
    for name, value in (
        (fence.DELEGATION_TOKEN_ENV, delegated),
        (fence.DELEGATION_SESSION_ENV, case.payload["session_id"]),
        (fence.DELEGATION_ATTEMPT_ENV, case.payload["attempt_id"]),
        (fence.DELEGATION_TRANSACTION_ENV, case.payload["replacement_transaction_id"]),
    ):
        monkeypatch.setenv(name, value)
    with authority_owner(case):
        report = onboarding.remove_current_user_setup(case.app)
    assert report["status"] == "PASS_DATA_PRESERVED"
    assert "abandoned_fence_settled" not in report
    assert case.path.read_bytes() == case.original
    assert not (case.root / "settled").exists()

@pytest.mark.parametrize("change", ["owner", "worker-root", "worker-sid", "receipt-app", "fence-app",
    "PREPARING", "PREPARED", "RESTORING", "RESTORE_FAILED"])
def test_unrelated_fence_is_preserved(removal_case, change):
    case = removal_case
    if change == "owner": case.payload["owner_kind"] = "session_adapter"
    elif change == "worker-root": case.prepared["operator_local_appdata_root"] = str(case.local.parent / "other")
    elif change == "worker-sid": case.prepared["operator_sid"] = "not-the-current-worker"
    elif change == "receipt-app": case.prepared["app_id"] = "another_app"
    elif change == "fence-app": case.payload["app_id"] = "another_app"
    else: case.payload["status"] = change
    case.publish()
    with pytest.raises(fence.WriterFencedError) as caught:
        onboarding.remove_current_user_setup(case.app)
    assert caught.value.code == "ACTIVE_WRITER_FENCE"
    assert case.path.read_bytes() == case.original
    assert case.registry_deletes == 0
    assert not (case.root / "settled").exists()

@pytest.mark.parametrize("role", ["gui", "relay", "unobservable"])
def test_running_or_unobservable_writer_is_rejected(removal_case, role):
    case = removal_case
    case.rows = [{"pid": os.getpid() + 100000, "role": role, "observable": role != "unobservable", "bootstrap": False}]
    with pytest.raises(fence.WriterFencedError) as caught:
        onboarding.remove_current_user_setup(case.app)
    assert caught.value.code == "ACTIVE_WRITER_FENCE"
    assert case.path.read_bytes() == case.original
    assert case.registry_deletes == 0

def test_existing_relay_instance_lease_blocks_removal(removal_case):
    from runtime_instance import acquire_runtime_instance
    case = removal_case
    lease = acquire_runtime_instance(case.paths.direct_sync_root / "user-relay-instance")
    assert lease is not None
    try:
        with pytest.raises(fence.WriterFencedError) as caught:
            onboarding.remove_current_user_setup(case.app)
        assert caught.value.code == "ACTIVE_WRITER_FENCE"
        assert case.path.read_bytes() == case.original
        assert case.registry_deletes == 0
    finally:
        lease.release()

def test_overlapping_removal_cannot_borrow_claim(removal_case):
    case = removal_case
    rejected = []
    def competitor():
        try: onboarding.remove_current_user_setup(case.app)
        except fence.WriterFencedError as error: rejected.append(error.code)
    def stop_relay(root):
        thread = threading.Thread(target=competitor)
        thread.start()
        thread.join(10)
        assert not thread.is_alive()
        return user_relay.request_user_relay_stop(root)
    report = onboarding.remove_current_user_setup(case.app, relay_stopper=stop_relay)
    assert rejected == ["ACTIVE_WRITER_FENCE"]
    assert_settled(case, report)
    assert case.registry_deletes == 1

def test_contending_removal_checks_authority_before_writer_gate(removal_case):
    case = removal_case
    rejected = []
    def competitor():
        try: onboarding.remove_current_user_setup(case.app)
        except fence.WriterFencedError as error: rejected.append(error.code)
    with fence._current_user_removal_fence_scope(case.app, case.paths.direct_sync_root):
        with fence.writer_admission("current_user_setup_removal"):
            thread = threading.Thread(target=competitor)
            thread.start()
            thread.join(10)
            assert not thread.is_alive()
            assert rejected == ["ACTIVE_WRITER_FENCE"]
    assert case.path.read_bytes() == case.original
    assert case.registry_deletes == 0

def test_copy_readback_failure_preserves_original_fence(removal_case, monkeypatch):
    case = removal_case
    read_bytes = Path.read_bytes
    def corrupt_copy(path):
        if path.parent == case.root / "settled": path.write_bytes(b"corrupted copy")
        return read_bytes(path)
    monkeypatch.setattr(Path, "read_bytes", corrupt_copy)
    with pytest.raises(onboarding.CurrentUserOnboardingError) as caught:
        onboarding.remove_current_user_setup(case.app)
    assert caught.value.status == "FAILED"
    assert case.path.read_bytes() == case.original
    report = json.loads(case.paths.removal_report_path.read_text(encoding="utf-8"))
    assert report["status"] == "FAILED"
    assert "abandoned_fence_settled" not in report
    assert case.ledger.read_bytes() == b"original business ledger\r\n"

def test_other_writer_sources_cannot_use_removal_authority(removal_case):
    case = removal_case
    denied = []
    def stop_relay(root):
        for source in ("current_user_onboarding", "auto_update_control", "event_log"):
            with pytest.raises(fence.WriterFencedError) as caught:
                with fence.writer_admission(source): pytest.fail("unrelated writer entered")
            denied.append(caught.value.code)
        return user_relay.request_user_relay_stop(root)
    report = onboarding.remove_current_user_setup(case.app, relay_stopper=stop_relay)
    assert denied == ["ACTIVE_WRITER_FENCE"] * 3
    assert_settled(case, report)

def test_settled_receipt_is_read_by_existing_g28_consumer(removal_case, tmp_path):
    from tests.test_removal_chain_admission import _run
    case = removal_case
    report = onboarding.remove_current_user_setup(case.app)
    assert_settled(case, report)
    def ps(value):
        return "'" + str(value).replace("'", "''") + "'"
    _run(tmp_path, "$binding=[pscustomobject]@{local_appdata_root=" + ps(case.local) + "};"
         "$receipt=Read-ContainerRemovalWorkerReceipt $binding;"
         "if($receipt.status -cne 'PASS_DATA_PRESERVED'){throw 'receipt status differs'};"
         "if($receipt.operator_sid -cne " + ps(_current_user_sid()) + "){throw 'receipt owner differs'};"
         "if(-not $receipt.abandoned_fence_settled.fence_copy_path){throw 'settlement reference absent'}")

def test_real_machine_worker_fence_gate_passes_after_removal(removal_case, tmp_path):
    from tests.powershell_contracts import run_powershell
    from tests.test_writer_session_fence import ROOT, WINPS
    case = removal_case
    def ps(value):
        return "'" + str(value).replace("'", "''") + "'"
    script = tmp_path / "machine-fence-gate.ps1"
    def gate(expected):
        script.write_text("""
$ErrorActionPreference='Stop'
function Load-TestFunction([string]$Path,[string[]]$Names) {
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'source parse failed'}
 foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
  if($node.Name -in $Names){. ([ScriptBlock]::Create('function global:'+$node.Name+$node.Extent.Text.Substring(('function '+$node.Name).Length)))}
 }
}
""" + "Load-TestFunction " + ps(ROOT / "tools/bootstrap_integrity.ps1") +
            " @('Get-StrictFullPath','Assert-BootstrapNoReparsePoint');\n" +
            "Load-TestFunction " + ps(ROOT / "tools/container_writer_fence.ps1") +
            " @('Get-ContainerMachineInstallStateRoot');\n" +
            "Load-TestFunction " + ps(ROOT / "INSTALL_CANONICAL_PORTABLE.ps1") +
            " @('Invoke-CanonicalMachineInstallation');\n" +
            "$env:PROGRAMDATA=" + ps(tmp_path / "programdata") + ";$testMode=$true;\n" +
            "function Assert-ContainerDataGenerationTarget {throw 'G59_AFTER_WORKER_FENCE_CHECK'}\n" +
            "$worker=[pscustomobject]@{profile_root=" + ps(case.local.parent.parent) + "};\n" +
            "try {Invoke-CanonicalMachineInstallation $worker '' '' $null $null;throw 'unexpected return'} " +
            "catch {if($_.Exception.Message -cne " + ps(expected) + "){throw 'worker fence gate result differs'}}",
            encoding="utf-8")
        result = run_powershell([str(WINPS), "-NoLogo", "-NoProfile", "-NonInteractive",
            "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", str(script)], timeout=30)
        assert result.returncode == 0, "existing machine worker-fence gate failed"
    gate("Existing worker deployment requires recovery.")
    report = onboarding.remove_current_user_setup(case.app)
    assert_settled(case, report)
    gate("G59_AFTER_WORKER_FENCE_CHECK")

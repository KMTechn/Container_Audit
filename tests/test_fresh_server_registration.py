"""Old-PC transition preserves bytes while removing every active producer input."""

import importlib
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

import current_user_onboarding as onboarding
from tests.test_current_user_onboarding import _ready_state
from tools import register_container_audit_worker_pc as registration
from tests.test_worker_pc_registration import _FakePossessionKey, TEST_MACHINE_GUID


@pytest.fixture
def transition():
    return importlib.import_module("current_user_server_transition")


@pytest.fixture
def old_pc(tmp_path, monkeypatch):
    import logistics_runtime_profile

    monkeypatch.setattr(logistics_runtime_profile, "_machine_environment_value", lambda name: "")
    app = tmp_path / "packet/app"
    app.mkdir(parents=True)
    local = tmp_path / "local"
    local.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "machine"))
    paths = onboarding.resolve_current_user_onboarding_paths(app)
    _ready_state(paths)
    paths.events_dir.mkdir(parents=True)
    (paths.events_dir / "old.csv").write_bytes(b"old event\r\n")
    parked = paths.data_root / "parked_trays"
    parked.mkdir()
    (parked / "held.json").write_text('{"barcode":"old"}', encoding="utf-8")
    paths.queue_dir.mkdir(parents=True)
    with sqlite3.connect(paths.queue_dir / "direct_sync_relay.sqlite3") as conn:
        conn.execute("CREATE TABLE direct_sync_relay_batches (status TEXT)")
        conn.execute("INSERT INTO direct_sync_relay_batches VALUES ('pending')")
    conn.close()
    (paths.queue_dir / "direct_sync_relay.sqlite3-wal").write_bytes(b"preserve sidecar")
    control = paths.direct_sync_root / "control"
    control.mkdir()
    (control / "container_audit_user_relay.stop.json").write_bytes(b'{"request_id":"original"}')
    return app, paths, tmp_path / "archive"


@pytest.mark.parametrize("state", ["READY", "legacy", "partial", "ABSENT"])
def test_prepare_archives_old_identity_and_business_without_reusing_it(transition, old_pc, monkeypatch, state):
    app, paths, archive = old_pc
    if state == "legacy":
        paths.identity_path.write_text('{"producer_id":"legacy"}', encoding="utf-8")
    elif state == "partial":
        paths.credential_path.unlink()
    elif state == "ABSENT":
        for path in (paths.identity_path, paths.producer_manifest_path, paths.credential_path,
                     paths.registration_report_path, paths.logistics_profile_path, paths.logistics_secret_path):
            path.unlink()
    plan = transition.plan_archive(app, archive_root=archive, transition_id="a" * 32)
    before = {str(p): p.read_bytes() for root in (paths.data_root, paths.direct_sync_root,
              paths.logistics_profile_path.parent) for p in root.rglob("*") if p.is_file()}
    monkeypatch.setattr(transition, "_require_quiesced_authority", lambda *a, **k: {"session_id": "test"})
    result = transition.archive_state(plan, confirm_pending=True)
    assert result["phase"] == "DETACHED"
    assert onboarding.inspect_current_user_state(paths)["status"] == "ABSENT"
    assert not (paths.events_dir / "old.csv").exists()
    assert not (paths.queue_dir / "direct_sync_relay.sqlite3").exists()
    for entry in result["entries"]:
        for item in entry["files"]:
            original = str(Path(entry["source"]) / item["relative"]) if entry["directory"] else entry["source"]
            saved = Path(entry["archive"]) / item["relative"] if entry["directory"] else Path(entry["archive"])
            assert saved.read_bytes() == before[original]
    assert (paths.direct_sync_root / "control/container_audit_user_relay.stop.json").read_bytes() == b'{"request_id":"original"}'


def test_pending_or_unknown_requires_separate_confirmation(transition, old_pc, monkeypatch):
    app, paths, archive = old_pc
    plan = transition.plan_archive(app, archive_root=archive, transition_id="a" * 32)
    monkeypatch.setattr(transition, "_require_quiesced_authority", lambda *a, **k: {})
    with pytest.raises(ValueError, match="미전송|확인"):
        transition.archive_state(plan, confirm_pending=False)
    assert paths.identity_path.is_file()
    assert (paths.events_dir / "old.csv").is_file()


def test_copy_failure_leaves_active_originals_and_retry_resumes(transition, old_pc, monkeypatch):
    app, paths, archive = old_pc
    plan = transition.plan_archive(app, archive_root=archive, transition_id="a" * 32)
    monkeypatch.setattr(transition, "_require_quiesced_authority", lambda *a, **k: {})
    copy = transition._copy_entry
    monkeypatch.setattr(transition, "_copy_entry", lambda *a: (_ for _ in ()).throw(OSError("copy failed")))
    with pytest.raises(OSError, match="copy failed"):
        transition.archive_state(plan, confirm_pending=True)
    assert paths.identity_path.is_file()
    monkeypatch.setattr(transition, "_copy_entry", copy)
    result = transition.archive_state(plan, confirm_pending=True)
    assert result["phase"] == "DETACHED"


def test_archive_cannot_be_a_runtime_input(transition, old_pc):
    app, paths, _ = old_pc
    with pytest.raises(ValueError, match="보관|겹"):
        transition.plan_archive(app, archive_root=paths.events_dir / "archive", transition_id="a" * 32)


def test_archive_requires_an_absolute_preservation_path(transition, old_pc, monkeypatch):
    app, paths, archive = old_pc
    monkeypatch.chdir(archive.parent)
    relative = os.path.relpath(archive)
    with pytest.raises(ValueError, match="로컬|절대"):
        transition.plan_archive(app, archive_root=relative, transition_id="a" * 32)
    assert paths.identity_path.is_file()
    assert not archive.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows volume policy")
@pytest.mark.parametrize("drive_type", [0, 1, 4, 5, 6])
def test_archive_rejects_nonlocal_or_nonpersistent_volumes(transition, old_pc, monkeypatch, drive_type):
    app, paths, archive = old_pc
    monkeypatch.setattr(transition.ctypes.windll.kernel32, "GetDriveTypeW", lambda path: drive_type)
    with pytest.raises(ValueError, match="로컬|보존"):
        transition.plan_archive(app, archive_root=archive, transition_id="a" * 32)
    assert paths.identity_path.is_file()
    assert not archive.exists()


@pytest.fixture
def fresh_context(transition, old_pc, monkeypatch):
    app, paths, archive = old_pc
    (app.parent / "portable-manifest.json").write_bytes(b'{"synthetic":"packet"}')
    private = app.parent / "private"
    transition._private_directory(private, transition._sid())
    record = private / "accepted.json"
    record.write_text(json.dumps({"phase": "ACCEPTED", "ready": True, "client_writes_blocked": False,
        "snapshot_rollback_allowed": False, "source_commit": "b" * 40}), encoding="utf-8")
    target = {"schema": transition.INPUT_SCHEMA, "origin": "https://new.example.invalid", "scope": "fresh-scope",
              "deployment_id": "/srv/fresh-test", "packet": hashlib.sha256((app.parent / "portable-manifest.json").read_bytes()).hexdigest(),
              "pc": os.environ["COMPUTERNAME"], "sid": transition._sid(),
              "acceptance": {"record_path": str(record), "record_sha256": hashlib.sha256(record.read_bytes()).hexdigest(),
                             "source_commit": "b" * 40, "accepted_by": "fixture-admin"}}
    input_path = private / "input.json"
    input_path.write_text(json.dumps(target), encoding="utf-8")
    class Key(_FakePossessionKey):
        def descriptor(self):
            value = super().descriptor()
            value.created = False
            value.provider_name = "Microsoft Software Key Storage Provider"
            value.key_name = "KMTech.DirectSync.Possession.v1"
            return value
        def close(self):
            pass
        def sign_reattach_proof(self, proof):
            return registration.PersistentPossessionKey.sign_reattach_proof(self, proof)
    monkeypatch.setattr(registration.PersistentPossessionKey, "open_existing", classmethod(lambda *a, **k: Key()))
    monkeypatch.setattr(registration.PersistentPossessionKey, "provision_initial", classmethod(lambda *a, **k: pytest.fail("fresh transition provisioned a shared key")))
    monkeypatch.setattr(registration, "_current_machine_guid", lambda: TEST_MACHINE_GUID)
    monkeypatch.setattr(transition, "_require_quiesced_authority", lambda *a, **k: {"session_id": "isolated"})
    verify_fresh_server = transition._verify_fresh_server
    monkeypatch.setattr(transition, "_verify_fresh_server", lambda plan: {"code": "producer_identity_not_found", "http_status": 404})
    confirm = f"이 PC의 옛 자료를 보관하고 {target['origin']} / {target['scope']} / {target['deployment_id']}에 새로 등록합니다"
    def prepare():
        return transition.prepare_registration(app, input_path=input_path, archive_root=archive, transition_id="b" * 32,
            lifecycle_receipt=app.parent / "lifecycle.json", confirm=confirm, confirm_pending=True)
    return SimpleNamespace(app=app, paths=paths, archive=archive, input=input_path, target=target, prepare=prepare,
                           verify_fresh_server=verify_fresh_server)


@pytest.mark.parametrize("field,value", [("pc", "another-pc"), ("sid", "S-1-5-21-999-999-999-1001"),
    ("packet", "a" * 64), ("origin", "http://new.example.invalid"), ("origin", "https://user@new.example.invalid"),
    ("origin", "https://new.example.invalid/other"), ("deployment_id", "relative")])
def test_target_binding_rejected_before_archiving(transition, fresh_context, field, value):
    fixture = fresh_context
    fixture.target[field] = value
    fixture.input.write_text(json.dumps(fixture.target), encoding="utf-8")
    with pytest.raises(ValueError):
        fixture.prepare()
    assert fixture.paths.identity_path.exists()
    assert not fixture.archive.exists()


def test_detached_transition_blocks_ordinary_onboarding_and_legacy_fallback(transition, fresh_context):
    from legacy_state_migration import migrate_legacy_code_root_state
    from logistics_runtime_profile import _runtime_environment, PROFILE_PATH_ENV
    plan = fresh_context.prepare()
    assert plan["identity_absent"] is True
    with pytest.raises(onboarding.CurrentUserOnboardingError, match="전환"):
        onboarding.onboard_current_user(fresh_context.app)
    assert _runtime_environment(None)[PROFILE_PATH_ENV] == plan["profile_path"]
    result = migrate_legacy_code_root_state(application_path=fresh_context.app,
        config_dir=fresh_context.paths.data_root / "config", parked_trays_dir=fresh_context.paths.data_root / "parked_trays")
    assert result["status"] == "EXCLUDED_FRESH_TRANSITION"
    assert not (fresh_context.paths.data_root / "parked_trays").exists()


def test_changed_owner_or_target_cannot_resume(transition, fresh_context):
    plan = fresh_context.prepare()
    before = transition._journal_path(plan).read_bytes()
    fresh_context.target["scope"] = "different-valid-scope"
    fresh_context.input.write_text(json.dumps(fresh_context.target), encoding="utf-8")
    with pytest.raises(ValueError):
        fresh_context.prepare()
    assert transition._journal_path(plan).read_bytes() == before


def test_rename_crash_can_resume_without_recopying_or_losing_originals(transition, fresh_context, monkeypatch):
    original = Path.rename
    count = 0
    def fail_one(path, destination):
        nonlocal count
        if ".fresh-" in Path(destination).name:
            count += 1
            if count == 2:
                raise OSError("simulated detach crash")
        return original(path, destination)
    monkeypatch.setattr(Path, "rename", fail_one)
    with pytest.raises(OSError, match="detach crash"):
        fresh_context.prepare()
    partial = transition.current_transition()
    assert partial["phase"] == "ARCHIVE_VERIFIED"
    assert partial["attempts"][-1]["status"] == "UNKNOWN"
    monkeypatch.setattr(Path, "rename", original)
    result = fresh_context.prepare()
    assert result["phase"] == "DETACHED"
    assert any(a["status"] == "UNKNOWN" for a in result["attempts"])


def test_restore_before_register_preserves_exact_bytes_and_refuses_new_local_work(transition, fresh_context):
    plan = fresh_context.prepare()
    source = Path(plan["entries"][0]["source"])
    source.mkdir(parents=True)
    (source / "new-work.csv").write_bytes(b"new local work")
    with pytest.raises(ValueError, match="새 로컬 자료"):
        transition.restore_archive(plan)
    assert (source / "new-work.csv").read_bytes() == b"new local work"


def _enrollment_response(plan, *, epoch=1):
    from tools.install_logistics_runtime_profile import MACHINE_CREDENTIAL_BUNDLE_CONTRACT_VERSION
    identity = plan["candidate"]["identity"]
    secret = "fixture-new-producer-secret"
    payload = {"contract_version": registration.SELF_ENROLLMENT_CONTRACT_VERSION, "status": "enrolled", "identity_action": "CREATED",
               "authorization_state": "OPERATION_PENDING", "credential_epoch": epoch,
               **{k: identity[k] for k in ("producer_id", "producer_install_id", "source_host_id")},
               "endpoint_url": plan["target"]["origin"] + onboarding.DEFAULT_ENDPOINT_PATH,
               "active_manifest_hashes": [plan["candidate"]["manifest_hash"]], "key_id": "fixture-new-key",
               "possession_key": {"contract_version": registration.POSSESSION_KEY_CONTRACT_VERSION, "fingerprint": plan["possession"]["fingerprint"]},
               "secret": secret, "secret_fingerprint_sha256": hashlib.sha256(secret.encode()).hexdigest()}
    payload["client_receipt"] = {k: v for k, v in payload.items() if k not in {"secret", "possession_key"}}
    payload["client_receipt"].update(receipt_schema_version="producer-self-enrollment-client-receipt-v1",
        manifest_hash=plan["candidate"]["manifest_hash"], possession_key_fingerprint=plan["possession"]["fingerprint"])
    payload["machine_credential_bundle"] = {
        "contract_version": MACHINE_CREDENTIAL_BUNDLE_CONTRACT_VERSION,
        "bindings": {"app": "ContainerAudit", "program": "Container_Audit", "source_host_id": identity["source_host_id"],
            "device_id": identity["pc_id"], "authority_scope_id": plan["target"]["scope"]},
        "credentials": {"producer_ingest": {"audience": "producer-ingest-hmac-v1", "auth_scheme": "hmac-sha256", "key_id": payload["key_id"], "secret": secret},
                        "logistics": {"audience": "worker-analysis-logistics-v1", "auth_scheme": "bearer", "token_header": "X-Logistics-API-Token", "token": "fixture-new-logistics-token"}},
        "profiles": {"logistics": {"contract_version": "km-logistics-runtime-profile-v1", "base_url": plan["target"]["origin"],
            "authority_scope": plan["target"]["scope"], "authority_epoch": 1, "authority_plane": "AUTHORITATIVE", "ledger_plane": "AUTHORITATIVE",
            "plane_epoch": 1, "device_id": identity["pc_id"], "source_host_id": identity["source_host_id"], "timeout_seconds": 10}}}
    return payload


def test_fresh_register_publishes_only_new_credentials_with_existing_key(transition, fresh_context, monkeypatch):
    plan = fresh_context.prepare()
    response = _enrollment_response(plan)
    monkeypatch.setattr(registration, "_post_enrollment_request", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: response))
    result = transition.register_transition(plan)
    assert result["phase"] == "REGISTERED"
    assert onboarding.inspect_current_user_state(fresh_context.paths)["status"] == "READY"
    assert onboarding.load_credentials_from_json(fresh_context.paths.credential_path).key_id == "fixture-new-key"
    assert not (fresh_context.paths.events_dir / "old.csv").exists()
    assert not (fresh_context.paths.queue_dir / "direct_sync_relay.sqlite3").exists()


@pytest.mark.parametrize("area,field,value", [("top", "producer_id", "valid-foreign-producer"),
    ("top", "source_host_id", "valid-foreign-source"), ("receipt", "manifest_hash", "f" * 64),
    ("receipt", "credential_epoch", 2), ("possession", "fingerprint", "x" * 43),
    ("bundle", "authority_scope_id", "valid-foreign-scope")])
def test_well_formed_foreign_response_is_rejected_before_any_secret_publication(transition, fresh_context, monkeypatch, area, field, value):
    plan = fresh_context.prepare()
    response = _enrollment_response(plan)
    target = {"top": response, "receipt": response["client_receipt"], "possession": response["possession_key"],
              "bundle": response["machine_credential_bundle"]["bindings"]}[area]
    target[field] = value
    monkeypatch.setattr(registration, "_post_enrollment_request", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: response))
    with pytest.raises(ValueError):
        transition.register_transition(plan)
    assert not fresh_context.paths.identity_path.exists()
    assert not fresh_context.paths.credential_path.exists()
    assert not fresh_context.paths.logistics_secret_path.exists()


@pytest.mark.parametrize("cut", ["lost_response", "partial_publication"])
def test_same_candidate_reattaches_after_commit_or_partial_publication(transition, fresh_context, monkeypatch, cut):
    from datetime import datetime, timedelta, timezone
    import requests

    plan = fresh_context.prepare()
    first_manifest = copy.deepcopy(plan["candidate"])
    calls = []
    attempts = 0
    def post(url, *, json, **kwargs):
        nonlocal attempts
        calls.append(url)
        if url.endswith("/enroll"):
            attempts += 1
            assert json["manifest"] == first_manifest["manifest"]
            if attempts == 1:
                if cut == "lost_response":
                    raise requests.Timeout("synthetic server commit response lost")
                return SimpleNamespace(status_code=200, json=lambda: _enrollment_response(plan))
            return SimpleNamespace(status_code=409, json=lambda: {"error": {"code": "reattach_proof_required"}})
        if url.endswith("/challenge"):
            proof = {"contract_version": "producer-reattach-proof-v1", "challenge_id": "reattach-" + "c" * 32,
                "nonce": "n" * 43, "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "audience": "worker-analysis-producer-reattach-v1",
                **{key: json[key] for key in ("producer_id", "producer_install_id", "source_host_id", "manifest_hash")}}
            return SimpleNamespace(status_code=200, json=lambda: {"contract_version": "producer-reattach-challenge-v1",
                "proof_payload": proof, "possession_key_fingerprint": plan["possession"]["fingerprint"]})
        assert url.endswith("/reattach")
        response = _enrollment_response(plan, epoch=2)
        response.update(contract_version=registration.REATTACH_COMPLETE_CONTRACT_VERSION,
                        status="reattached", identity_action="REATTACHED")
        response["client_receipt"].update(contract_version=registration.REATTACH_COMPLETE_CONTRACT_VERSION,
                                        status="reattached", identity_action="REATTACHED")
        return SimpleNamespace(status_code=200, json=lambda: response)
    monkeypatch.setattr(registration, "_post_enrollment_request", post)
    persist = registration._persist_producer_identity_file
    if cut == "partial_publication":
        monkeypatch.setattr(registration, "_persist_producer_identity_file",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("publication power loss")))
    with pytest.raises(ValueError):
        transition.register_transition(plan)
    saved = transition.current_transition()
    assert saved["phase"] == "REGISTERING"
    assert saved["candidate"] == first_manifest
    with pytest.raises(ValueError, match="되돌릴 수 없음"):
        transition.restore_archive(saved)
    monkeypatch.setattr(registration, "_persist_producer_identity_file", persist)
    result = transition.register_transition(saved)
    assert result["phase"] == "REGISTERED"
    assert result["candidate"] == first_manifest
    assert len(calls) == 4
    assert result["attempts"][-2]["status"] == "UNKNOWN"
    report = json.loads(fresh_context.paths.registration_report_path.read_text())
    assert report["credential_epoch"] == 2
    assert report["registration_action"] == "possession_reattach"


def test_run_waits_for_first_lease_and_empty_queue(transition, fresh_context, monkeypatch):
    from tests.test_current_user_onboarding import _ledger_factory

    plan = fresh_context.prepare()
    monkeypatch.setattr(registration, "_post_enrollment_request",
                        lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: _enrollment_response(plan)))
    plan = transition.register_transition(plan)
    installed = []
    result = onboarding.onboard_current_user(fresh_context.app, fresh_transition_journal=str(transition._journal_path(plan)),
        ledger_factory=_ledger_factory, relay_launcher=lambda *a, **k: {"status": "START_REQUESTED", "process_id": 123},
        autostart_installer=lambda *a, **k: pytest.fail("Run installed before first lease"))
    assert result["status"] == "ACTIVATION_PENDING"
    # These newly published non-business files must not count as queued work.
    (fresh_context.paths.data_root / "new-settings.json").write_text('{"theme":"system"}')
    assert fresh_context.paths.logistics_profile_path.is_file()
    monkeypatch.setattr(onboarding, "install_user_relay_autostart", lambda *a, **k: installed.append(True) or {"status": "PASS", "command": "synthetic"})
    with pytest.raises(ValueError, match="UNKNOWN"):
        transition.complete_activation(plan, timeout_seconds=0)
    assert installed == []
    monkeypatch.setattr(transition, "_first_lease", lambda p: True)
    conn = sqlite3.connect(fresh_context.paths.queue_dir / "direct_sync_relay.sqlite3")
    conn.execute("CREATE TABLE direct_sync_relay_batches (status TEXT)")
    conn.commit()
    conn.close()
    result = transition.complete_activation(plan)
    assert result["phase"] == "ACTIVATION_PENDING_RELEASE"
    assert installed == [True]
    assert json.loads(fresh_context.paths.onboarding_report_path.read_text())["status"] == "READY"


def test_missing_pointer_resumes_original_journal_without_new_identity(transition, fresh_context):
    plan = fresh_context.prepare()
    transition._pointer_path().unlink()
    resumed = fresh_context.prepare()
    assert resumed["candidate"] == plan["candidate"]
    assert resumed["phase"] == "DETACHED"
    assert transition.current_transition()["transition_id"] == plan["transition_id"]


def test_plan_does_not_open_key_or_mutate_old_inputs(transition, fresh_context, monkeypatch, capsys):
    before = {str(p): p.read_bytes() for p in fresh_context.paths.data_root.parent.rglob("*") if p.is_file()}
    monkeypatch.setattr(transition, "_possession", lambda: pytest.fail("Plan opened KSP"))
    assert transition.transition_main(["--app-root", str(fresh_context.app), "--action", "plan",
        "--archive-root", str(fresh_context.archive), "--transition-id", "b" * 32,
        "--input", str(fresh_context.input)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["work_observation"]["pending"] > 0
    assert summary["work_observation"]["held_files"] > 0
    assert {p: Path(p).read_bytes() for p in before} == before
    assert not transition._pointer_path().exists()


def test_original_directories_attributes_and_acl_survive_restore(transition, old_pc, monkeypatch):
    app, paths, archive = old_pc
    empty = paths.data_root / "parked_trays/empty"
    empty.mkdir()
    plan = transition.plan_archive(app, archive_root=archive, transition_id="a" * 32)
    before = {str(p): transition._acl(p) for p in paths.data_root.rglob("*")}
    monkeypatch.setattr(transition, "_require_quiesced_authority", lambda p: {})
    plan = transition.archive_state(plan, confirm_pending=True)
    assert transition.restore_archive(plan)["phase"] == "RESTORE_PENDING_RELEASE"
    assert empty.is_dir()
    assert all(transition._acl(Path(p)) == acl for p, acl in before.items())


def test_real_writer_authority_and_same_receipt_are_required(transition, old_pc, monkeypatch):
    import threading
    import writer_session_fence as fence
    from tests.test_writer_session_fence import _active_payload, _write_active

    app, paths, archive = old_pc
    plan = transition.plan_archive(app, archive_root=archive, transition_id="a" * 32)
    receipt = app.parent / "quiesced.json"
    payload = _active_payload(token="q" * 48, sources=["current_user_onboarding", "current_user_onboarding_storage"])
    payload["owner_kind"] = "canonical_installer"
    root = fence.canonical_control_root()
    _write_active(root, payload)
    plan["lifecycle_receipt"] = str(receipt)
    bound = {"schema": "container-audit-canonical-portable-install-v2", "fresh_transition": {
        "quiesced": True, "transition_id": plan["transition_id"], "sid": transition._sid()},
        "code_replacement": {"transaction_id": payload["replacement_transaction_id"]}}
    receipt.write_text(json.dumps(bound))
    with pytest.raises(fence.WriterFencedError):
        transition.archive_state(plan, confirm_pending=True)
    assert not archive.exists()
    for key, value in {fence.DELEGATION_TOKEN_ENV: "q" * 48,
        fence.DELEGATION_SESSION_ENV: payload["session_id"], fence.DELEGATION_ATTEMPT_ENV: payload["attempt_id"],
        fence.DELEGATION_TRANSACTION_ENV: payload["replacement_transaction_id"]}.items():
        monkeypatch.setenv(key, value)
    ready, release = threading.Event(), threading.Event()
    def owner():
        lease = fence._acquire_named_mutex(payload["session_authority_mutex_name"], 1.0)
        assert lease is not None and not lease.abandoned
        ready.set()
        release.wait(30)
        lease.release()
    thread = threading.Thread(target=owner, daemon=True)
    thread.start()
    assert ready.wait(5)
    try:
        bound["fresh_transition"]["sid"] = "S-1-5-21-1-2-3-999"
        receipt.write_text(json.dumps(bound))
        with pytest.raises(ValueError, match="SID"):
            transition.archive_state(plan, confirm_pending=True)
        assert not archive.exists()
        bound["fresh_transition"]["sid"] = transition._sid()
        receipt.write_text(json.dumps(bound))
        assert transition.archive_state(plan, confirm_pending=True)["phase"] == "DETACHED"
    finally:
        release.set()
        thread.join(5)
    with pytest.raises(fence.WriterFencedError):
        transition.archive_state(plan, confirm_pending=True)


@pytest.mark.parametrize("health,source,status,code", [(302, "b" * 40, 404, "producer_identity_not_found"),
    (200, "c" * 40, 404, "producer_identity_not_found"), (200, "b" * 40, 200, "producer_identity_not_found"),
    (200, "b" * 40, 404, "other_valid_error"), (200, "b" * 40, 404, "producer_identity_not_found")])
def test_initial_challenge_needs_tls_source_and_exact_404(transition, fresh_context, monkeypatch, health, source, status, code):
    import requests
    real_check = fresh_context.verify_fresh_server
    seen = []
    class Session:
        trust_env = True
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, **kwargs):
            assert self.trust_env is False and kwargs["allow_redirects"] is False and kwargs["verify"] is True
            seen.append(url)
            return SimpleNamespace(status_code=health, headers={"X-KMTech-Source-Commit": source})
    def challenge(url, **kwargs):
        assert kwargs["allow_redirects"] is False and kwargs["verify"] is True
        assert kwargs["json"]["contract_version"] == "producer-reattach-challenge-request-v1"
        seen.append(url)
        return SimpleNamespace(status_code=status, json=lambda: {"error": {"code": code}})
    monkeypatch.setattr(requests, "Session", Session)
    monkeypatch.setattr(registration, "_post_enrollment_request", challenge)
    plan = {"target": fresh_context.target, "app_root": str(fresh_context.app),
            "candidate": transition._candidate(fresh_context.paths, fresh_context.target)}
    if (health, source, status, code) == (200, "b" * 40, 404, "producer_identity_not_found"):
        assert real_check(plan)["code"] == code
        assert len(seen) == 2
    else:
        with pytest.raises(ValueError): real_check(plan)
    assert fresh_context.paths.identity_path.exists()
    assert not fresh_context.archive.exists()


@pytest.mark.parametrize("fault", ["", "sid", "hash", "foreign_root", "archive_bytes", "registering"])
def test_real_machine_profile_leaf_preserves_scope_and_restores_original(transition, old_pc, monkeypatch, tmp_path, fault):
    from tests.powershell_contracts import run_functions

    app, paths, archive = old_pc
    machine = Path(os.environ["PROGRAMDATA"]) / "KMTech/Logistics/profiles/Container_Audit"
    machine.mkdir(parents=True)
    (machine / "old-profile.json").write_text('{"old":"machine"}')
    old_relay = Path(os.environ["PROGRAMDATA"]) / "KMTech/DirectSync/container_audit"
    (old_relay / "queue").mkdir(parents=True)
    (old_relay / "queue/old.sqlite3-wal").write_bytes(b"legacy SYSTEM pending WAL")
    relay_original = transition._files(old_relay)
    original = transition._files(machine)
    monkeypatch.setattr(transition, "_require_quiesced_authority", lambda p: {})
    plan = transition.plan_archive(app, archive_root=archive, transition_id="a" * 32)
    plan["defer_machine"] = True
    plan = transition.archive_state(plan, confirm_pending=True)
    assert plan["phase"] == "QUIESCED" and plan["machine_pending"]
    entry = next(e for e in plan["entries"] if e["machine_profile"])
    if fault == "sid": plan["sid"] = "S-1-5-21-1-2-3-999"
    if fault == "foreign_root": entry["source"] = str(machine.parent / "another_app")
    if fault == "registering": plan["phase"] = "REGISTERING"
    if fault == "archive_bytes":
        Path(entry["archive"]).mkdir(parents=True)
        (Path(entry["archive"]) / "old-profile.json").write_text("different bytes")
    transition._save(plan)
    product = Path(__file__).resolve().parents[1] / "INSTALL_THIS_PC.ps1"
    script = r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/bootstrap_integrity.ps1')
$testOverride=$true
$FreshMachineTransitionJournalPath=$env:CA_FRESH_JOURNAL
$FreshMachineTransitionJournalSha256=$env:CA_FRESH_SHA
$FreshMachineTransitionId='a'*32
$OperatorSid=$env:CA_FRESH_SID
$RestoreFreshMachineProfile=($env:CA_FRESH_RESTORE -ceq '1')
Detach-FreshMachineProfile
'''
    def run(restore=False):
        return run_functions(tmp_path, product, ["Test-SamePath", "Assert-NoReparsePoint", "Detach-FreshMachineProfile"], script,
            values={"CA_FRESH_JOURNAL": str(transition._journal_path(plan)),
                    "CA_FRESH_SHA": "f" * 64 if fault == "hash" else hashlib.sha256(transition._journal_path(plan).read_bytes()).hexdigest(),
                    "CA_FRESH_SID": transition._sid(), "CA_FRESH_RESTORE": "1" if restore else "0"})
    result = run()
    if fault:
        assert result.returncode != 0
        assert machine.is_dir() and transition._files(machine) == original
        assert not Path(entry["inactive"]).exists()
        assert transition._files(old_relay) == relay_original
        return
    assert result.returncode == 0, result.stderr
    assert not machine.exists() and transition._files(Path(entry["inactive"])) == original
    plan = transition.archive_state(plan, confirm_pending=True)
    assert plan["phase"] == "DETACHED"
    plan = transition.restore_archive(plan)
    assert plan["machine_restore_pending"] and not paths.identity_path.exists()
    result = run(restore=True)
    assert result.returncode == 0, result.stderr
    assert transition.restore_archive(plan)["phase"] == "RESTORE_PENDING_RELEASE"
    assert machine.is_dir() and transition._files(machine) == original
    assert old_relay.is_dir() and transition._files(old_relay) == relay_original


@pytest.mark.parametrize("anchor", ["KM_LOGISTICS_PROFILE_PATH", "KM_LOGISTICS_REQUIRED"])
def test_hklm_anchor_stops_before_archive_without_exposing_value(transition, fresh_context, monkeypatch, anchor):
    import logistics_runtime_profile

    monkeypatch.setattr(logistics_runtime_profile, "_machine_environment_value",
                        lambda name: "synthetic-private-anchor" if name == anchor else "")
    with pytest.raises(ValueError, match="HKLM.*관리자") as exc:
        fresh_context.prepare()
    assert "synthetic-private-anchor" not in str(exc.value)
    assert not fresh_context.archive.exists()
    assert fresh_context.paths.identity_path.exists()


@pytest.mark.parametrize("state,enabled,absent,expected", [("Disabled", False, False, 0),
    ("Ready", False, False, 0), ("Ready", True, False, 1), ("Running", False, False, 1),
    ("Unknown", False, False, 1), ("Disabled", False, True, 0)])
def test_system_task_check_is_read_only_and_fails_closed(tmp_path, state, enabled, absent, expected):
    from tests.powershell_contracts import run_functions

    result = run_functions(tmp_path, Path(__file__).resolve().parents[1] / "tools/container_writer_fence.ps1",
        ["Assert-ContainerFreshSystemTasksStopped"], r'''
function Get-ScheduledTask {
    if ($env:CA_TASK_ABSENT -ceq '1') { return @() }
    return [pscustomobject]@{TaskName='direct-sync-relay-container-audit';TaskPath='\';State=$env:CA_TASK_STATE;
        Principal=[pscustomobject]@{UserId='S-1-5-18'};Settings=[pscustomobject]@{Enabled=($env:CA_TASK_ENABLED -ceq '1')}}
}
function Stop-ScheduledTask { throw 'must never stop SYSTEM task during fresh transition' }
function Disable-ScheduledTask { throw 'must never disable SYSTEM task during fresh transition' }
Assert-ContainerFreshSystemTasksStopped -SystemOnly
''', values={"CA_TASK_STATE": state, "CA_TASK_ENABLED": "1" if enabled else "0", "CA_TASK_ABSENT": "1" if absent else "0"})
    assert (result.returncode != 0) == bool(expected), result.stderr


@pytest.mark.parametrize("fault", ["", "expired", "foreign_install", "not_accepted", "unknown"])
def test_activation_requires_current_bound_first_lease(transition, fresh_context, fault):
    from datetime import datetime, timedelta, timezone

    plan = fresh_context.prepare()
    lease = {"contract_version": "producer-runtime-lease.v1", "status": "ACTIVE", "server_grant_accepted": True,
        "producer_install_id": plan["candidate"]["identity"]["producer_install_id"],
        "runtime_instance_id": "isolated-instance", "lease_id": "isolated-lease", "fence": 1,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=-1 if fault == "expired" else 5)).isoformat()}
    if fault == "foreign_install": lease["producer_install_id"] = "another-install"
    if fault == "not_accepted": lease["server_grant_accepted"] = False
    if fault == "unknown": lease["status"] = "UNKNOWN"
    report = Path(plan["direct_sync_root"]) / "status/direct_sync_relay_status.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({"runtime_lease": lease}))
    assert transition._first_lease(plan) is (not bool(fault))


@pytest.mark.parametrize("fault", ["", "request", "run"])
def test_supported_old_removal_is_read_only_and_bound_to_both_roots(tmp_path, fault):
    from tests.powershell_contracts import run_functions

    result = run_functions(tmp_path, Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1",
        ["Full", "Same", "Test-ExactPropertySet", "Test-JsonTrue", "Read-FreshRemovedPreimage"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
$activeDataRoot=Join-Path $env:CA_CONTRACT_ROOT 'data'
$activeRelayRoot=Join-Path $env:CA_CONTRACT_ROOT 'relay'
$install=Join-Path $env:CA_CONTRACT_ROOT 'code'
$stop=Join-Path $env:CA_CONTRACT_ROOT 'stop.json'
$removalPath=Join-Path $env:CA_CONTRACT_ROOT 'removal.json'
$before=@{exists=($env:CA_REMOVAL_FAULT -ceq 'run');kind='';data=''}
$old=@()
$freshRemovedPreimage=$null
$marker=@{schema_version='container-audit-user-relay-stop-v1';request_id=('a'*32);requested_at=[DateTime]::UtcNow.ToString('o')}
$receipt=@{status='PASS_DATA_PRESERVED';state_scope='current_user';data_preserved=$true;
    relay_autostart=@{status='ABSENT'};relay_process=@{status='ABSENT';request_id=$marker.request_id;stop_request_path=$stop};
    machine_code_root=(Join-Path $install 'app');preserved_paths=@($activeDataRoot,$activeRelayRoot,(Join-Path $activeDataRoot 'profile'))}
if ($env:CA_REMOVAL_FAULT -ceq 'request') {$receipt.relay_process.request_id='b'*32}
$marker|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $stop -Encoding UTF8
$receipt|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $removalPath -Encoding UTF8
$original=(Get-FileHash -LiteralPath $stop).Hash
$result=Read-FreshRemovedPreimage
if ((Get-FileHash -LiteralPath $stop).Hash -cne $original) {throw 'old stop marker changed'}
if (-not $result.stop_sha256 -or -not $result.removal_sha256) {throw 'old removal binding absent'}
''', values={"CA_REMOVAL_FAULT": fault})
    assert (result.returncode == 0) is (not bool(fault)), result.stderr

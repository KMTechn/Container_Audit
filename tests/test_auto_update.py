import pytest
from pathlib import Path

import auto_update as updates


NOW = "2026-10-01T04:00:00+00:00"
LATER = "2026-10-01T04:00:01+00:00"
OLD = "1" * 40
NEW = "2" * 40


def prepared():
    return updates.prepare_transition(
        previous_sha=OLD, candidate_sha=NEW, packet_sha256="3" * 64,
        forward_pin="4" * 64, rollback_pin="5" * 64,
        transition_id="6" * 32, nonce="7" * 32, now=NOW,
    )


def trial():
    state = updates.apply_transition(prepared(), writers_absent=True, packet_verified=True, durable_prepared=True, now=NOW)
    return updates.bind_trial(state, sha=NEW, pid=42, ordinary_user=True, now=NOW)


def ready(state):
    return {
        **{check: True for check in updates.READY_CHECKS},
        "pid": state["trial_pid"], "sha": NEW,
        "nonce": state["nonce"], "transition_id": state["transition_id"],
        "ready_at": LATER,
    }


def test_candidate_is_seen_before_system_has_created_a_marker():
    assert updates.startup_action(None, prepared_present=True) == "REQUEST_APPLY"
    assert updates.startup_action(None, prepared_present=False) == "START_CURRENT"


@pytest.mark.parametrize("missing", ["writers_absent", "packet_verified", "durable_prepared"])
@pytest.mark.parametrize("value", [False, None, 1])
def test_apply_does_not_authorize_switch_before_durable_write_or_verified_absence(missing, value):
    checks = dict(writers_absent=True, packet_verified=True, durable_prepared=True)
    checks[missing] = value
    before = prepared()
    with pytest.raises(ValueError):
        updates.apply_transition(before, now=NOW, **checks)
    assert before["phase"] == "PREPARED"


@pytest.mark.parametrize("change", [
    {"nonce": "8" * 32}, {"sha": OLD}, {"pid": 43}, {"pid": True},
    {"transition_id": "8" * 32}, {"ready_at": "2026-09-30T00:00:00+00:00"},
    {"ready_at": "2026-10-02T00:00:00+00:00"}, {"ready_at": "2026-10-01T04:00:01"},
    *[{check: False} for check in updates.READY_CHECKS],
])
def test_stale_or_partial_ready_does_not_confirm_a_new_version(change):
    state = trial()
    receipt = {**ready(state), **change}
    with pytest.raises(ValueError):
        updates.confirm_transition(state, receipt, process_matches=True, relay_matches=True, now=LATER)


def test_live_pid_and_heartbeat_are_insufficient_and_trial_only_runs_once():
    state = trial()
    assert not updates.ready_matches(state, {"pid": 42}, process_matches=True, relay_matches=True, now=LATER)
    assert not updates.ready_matches(state, ready(state), process_matches=True, relay_matches=False, now=LATER)
    with pytest.raises(ValueError):
        updates.bind_trial(state, sha=NEW, pid=43, ordinary_user=True, now=LATER)


def test_startup_failure_returns_to_previous_code_only_after_writer_absence():
    state = updates.request_rollback(trial(), reason="new application failed to initialize")
    unknown = updates.rollback_transition(state, writers_absent=None, previous_verified=True, durable_rollback=True, nonce="8" * 32, now=LATER)
    assert unknown["phase"] == "UNKNOWN"
    with pytest.raises(ValueError):
        updates.recovery_sha(unknown, pointer_sha=NEW)
    rollback = updates.rollback_transition(state, writers_absent=True, previous_verified=True, durable_rollback=True, nonce="8" * 32, now=LATER)
    assert rollback["trial_sha"] is None
    assert rollback["trial_started_at"] is None
    rollback = updates.bind_trial(rollback, sha=OLD, pid=43, ordinary_user=True, now=LATER)
    assert updates.recovery_sha(rollback, pointer_sha=NEW) == OLD
    receipt = {**ready(rollback), "sha": OLD}
    result = updates.confirm_transition(rollback, receipt, process_matches=True, relay_matches=True, now=LATER)
    assert result["phase"] == "ROLLED_BACK"
    assert result["failed_shas"] == [NEW]
    with pytest.raises(ValueError, match="failed version"):
        updates.prepare_transition(previous_sha=OLD, candidate_sha=NEW, packet_sha256="3" * 64, forward_pin="4" * 64, rollback_pin="5" * 64, transition_id="6" * 32, nonce="7" * 32, now=LATER, failed_shas=result["failed_shas"])


def test_power_loss_between_record_and_pointer_write_replays_recorded_code():
    before = prepared()
    assert updates.recovery_sha(before, pointer_sha=OLD) == OLD
    with pytest.raises(ValueError, match="before the applied record"):
        updates.recovery_sha(before, pointer_sha=NEW)
    applied = updates.apply_transition(before, writers_absent=True, packet_verified=True, durable_prepared=True, now=NOW)
    assert updates.recovery_sha(applied, pointer_sha=OLD) == NEW
    rollback = updates.request_rollback(applied, reason="startup failed")
    assert updates.recovery_sha(rollback, pointer_sha=NEW) == OLD
    assert updates.recovery_sha(rollback, pointer_sha=OLD) == OLD
    with pytest.raises(ValueError):
        updates.recovery_sha(rollback, pointer_sha="9" * 40)


def pins():
    return [
        dict(zip(updates.PIN_FIELDS, (OLD, NEW, "a" * 64, "b" * 64))),
        dict(zip(updates.PIN_FIELDS, (NEW, OLD, "b" * 64, "a" * 64))),
    ]


def test_forward_approval_does_not_grant_reverse_or_another_contract():
    forward, reverse = pins()
    assert updates.directional_pin([forward], **forward)
    with pytest.raises(ValueError, match="no exact approval"):
        updates.directional_pin([forward], **reverse)
    with pytest.raises(ValueError, match="no exact approval"):
        updates.directional_pin([forward], **{**forward, "to_contract_sha256": "c" * 64})
    with pytest.raises(ValueError, match="no exact approval"):
        updates.directional_pin([], **forward)


@pytest.mark.parametrize("change", [{"from_commit": "*"}, {"to_commit": "2" * 39}, {"extra": True}])
def test_approval_rejects_wildcards_and_malformed_entries(change):
    forward = pins()[0]
    with pytest.raises(ValueError):
        updates.directional_pin([{**forward, **change}], **forward)


def test_both_directions_and_unchanged_data_api_are_required_for_automatic_apply():
    current = dict(source_commit=OLD, writer_sink_inventory_contract_sha256="a" * 64, data_api_contract_sha256="c" * 64)
    candidate = dict(source_commit=NEW, writer_sink_inventory_contract_sha256="b" * 64, data_api_contract_sha256="c" * 64)
    assert len(updates.bidirectional_pins(pins(), current=current, candidate=candidate)) == 2
    with pytest.raises(ValueError, match="no exact approval"):
        updates.bidirectional_pins(pins()[:1], current=current, candidate=candidate)
    with pytest.raises(ValueError, match="unchanged data"):
        updates.bidirectional_pins(pins(), current=current, candidate={**candidate, "data_api_contract_sha256": "d" * 64})


def test_feed_defaults_and_work_time_switch_are_closed():
    assert updates.policy_from_settings({}) == dict(feed_url="", channel="stable", approved_transitions=[], apply_during_work=False, profile_auth=False)
    for settings in ({"apply_during_work": True}, {"feed_url": "http://example.test/update"}, {"profile_auth": "true"}):
        with pytest.raises(ValueError):
            updates.policy_from_settings(settings)


def test_logon_task_has_fixed_system_action_and_operator_trigger(monkeypatch, tmp_path):
    import xml.etree.ElementTree as xml

    monkeypatch.setattr(updates, "system_executable", lambda relative: "C:/Windows/System32/" + relative)
    root = tmp_path / "current"
    sid = "S-1-5-21-111-222-333-1001"
    task = updates.install_task_spec(root, sid)
    document = xml.fromstring(task["xml"])
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    assert document.find("t:Triggers/t:LogonTrigger/t:UserId", ns).text == sid
    assert document.find("t:Principals/t:Principal/t:UserId", ns).text == "S-1-5-18"
    # ServiceAccount is a COM/cmdlet enum, not an XML schema LogonType.
    # SYSTEM is represented by its SID with the optional LogonType omitted.
    assert document.tag == "{" + ns["t"] + "}Task"
    assert document.attrib["version"] == "1.4"
    principal = document.find("t:Principals/t:Principal", ns)
    assert [element.tag.rsplit("}", 1)[-1] for element in principal] == ["UserId", "RunLevel"]
    assert principal.find("t:RunLevel", ns).text == "HighestAvailable"
    assert document.find("t:Actions", ns).attrib["Context"] == principal.attrib["id"]
    assert document.find("t:Settings/t:Hidden", ns).text == "true"
    assert document.find("t:Settings/t:AllowHardTerminate", ns).text == "false"
    action = document.find("t:Actions/t:Exec", ns)
    assert action.find("t:Command", ns).text.startswith("C:/Windows/System32/")
    assert "apply_prepared_update.ps1" in action.find("t:Arguments", ns).text
    assert str(root) in action.find("t:Arguments", ns).text
    assert updates.task_name(root, sid) != updates.task_name(root, sid.replace("1001", "1002"))


def test_pid_reuse_cannot_confirm_a_readiness_receipt():
    state = trial()
    row = dict(pid=42, observable=True, sha=NEW, sid="operator", role="gui", ordinary_user=True, created_at=LATER)
    assert not updates.process_matches_trial(row, state=state, sha=NEW, sid="operator", role="gui")
    assert updates.process_matches_trial({**row, "created_at": NOW}, state=state, sha=NEW, sid="operator", role="gui")


@pytest.mark.parametrize("phase", ["PREPARED", "UNKNOWN", "ROLLBACK_PENDING"])
def test_old_tools_cannot_write_during_a_transition(monkeypatch, tmp_path, phase):
    control = tmp_path / "update-control"
    monkeypatch.setattr(updates, "control_root", lambda _root: control)
    monkeypatch.setattr(updates, "ordinary_user_context", lambda _sid=None: True)
    monkeypatch.setattr(updates, "runtime_matches", lambda _root: True)
    monkeypatch.setattr(updates, "optional_record", lambda _path: {**prepared(), "phase": phase})
    monkeypatch.setattr(updates, "read_json", lambda path: {"operator_sid": "operator"} if path.name == "policy.json" else {"source_commit": OLD, "sha": OLD})
    with pytest.raises(ValueError, match="startup transition"):
        updates.assert_version_writer(tmp_path / "app", source="csv", environ={})


def test_switch_record_is_flushed_before_pointer_and_failure_preserves_old_pointer(monkeypatch, tmp_path):
    calls = []
    state = trial()
    def write(path, payload):
        calls.append(path.name)
        if path.name == "active.json":
            raise OSError("injected pointer flush failure")
    monkeypatch.setattr(updates, "write_json_durable", write)
    with pytest.raises(OSError):
        updates.persist_switch(tmp_path, state, NEW)
    assert calls == ["transition.json", "active.json"]
    assert updates.recovery_sha(state, pointer_sha=OLD) == NEW


def test_failed_preparation_defers_but_failed_activation_remains_unknown(monkeypatch, tmp_path):
    from contextlib import nullcontext

    pointer = {"sha": OLD}
    state = {"schema": updates.SCHEMA, "phase": "DEFERRED"}
    writes = []
    monkeypatch.setattr(updates, "fixed_helper", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(updates, "update_lock", lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(updates, "read_json", lambda path: {"operator_sid": "operator"} if path.name == "policy.json" else dict(pointer))
    monkeypatch.setattr(updates, "optional_record", lambda _path: state)
    monkeypatch.setattr(updates, "write_json_durable", lambda path, payload: writes.append((path.name, payload)))
    def fail(_control):
        raise ValueError("injected verification failure")
    monkeypatch.setattr(updates, "_apply_prepared", fail)
    assert updates.apply_prepared(tmp_path) == 0
    assert writes[-1][1]["phase"] == "DEFERRED"
    state = {**trial(), "phase": "APPLIED_PENDING_READY"}
    assert updates.apply_prepared(tmp_path) == 20
    assert writes[-1][1]["phase"] == "UNKNOWN"


def test_engine_candidate_exit_restarts_previous_version_without_reverting_data(monkeypatch, tmp_path):
    """Exercise the apply loop/journal with synthetic process and crypto adapters."""
    import json
    import time
    from contextlib import nullcontext
    import update_service

    managed = tmp_path / "managed"
    control = managed / "update-control"
    stage = tmp_path / "operator" / "updates"
    (managed / "current/app").mkdir(parents=True)
    control.mkdir()
    stage.mkdir(parents=True)
    key = {"manifest_public_key": "key-adapter"}
    (managed / "current/app/update-manifest-key-config.json").write_text(json.dumps(key))
    policy = dict(feed_url="https://example.test/feed", channel="stable", operator_sid="operator", operator_local_app_data=str(tmp_path / "operator"), staging_root=str(stage), approved_transitions=pins())
    updates.write_json_durable(control / "policy.json", policy)
    updates.write_json_durable(control / "active.json", {"schema": updates.SCHEMA, "sha": OLD})
    updates.write_json_durable(stage / "prepared.json", {"source_commit": NEW})
    for name in ("manifest.json", "manifest.sig", "packet.zip"):
        (stage / name).write_bytes(b"synthetic adapter input")
    business = tmp_path / "ledger-and-unfinished.bin"
    business.write_bytes(b"original business state must not be restored or deleted")
    protected_key_hash = "e" * 64
    verified = []
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "operator"))
    monkeypatch.setattr(updates, "update_lock", lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(updates, "fixed_helper", lambda _control, mode, **kwargs: verified.append((mode, kwargs.get("code_root"))) or "")
    monkeypatch.setattr(updates, "now_utc", lambda: LATER)
    from tests.test_signed_pairrule import signed
    def version_manifest(bundle, **_kwargs):
        return dict(source_commit=OLD if bundle.name == OLD else NEW,
                    version="v2.0.99" if bundle.name == OLD else "v2.0.100",
                    contract_sha256="a" * 64 if bundle.name == OLD else "b" * 64,
                    writer_sink_inventory_contract_sha256="a" * 64 if bundle.name == OLD else "b" * 64,
                    data_api_contract_sha256="c" * 64)
    monkeypatch.setattr(updates, "version_manifest", version_manifest)
    monkeypatch.setattr(updates, "verify_prepared_packet", lambda *_args, **_kwargs: (
        {**signed(version_manifest(Path(OLD)), version_manifest(Path(NEW))), "source_commit": NEW},
        {"archive_policy": {}, "sha256": "3" * 64}))
    monkeypatch.setattr(updates, "copy_prepared_file", lambda source, target, **_kwargs: target.write_bytes(source.read_bytes()))
    monkeypatch.setattr(updates, "preserve_candidate_version", lambda *_args: None)
    monkeypatch.setattr(update_service, "safe_extract_update_zip", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(update_service, "file_sha256", lambda _path: protected_key_hash)
    candidate_seen = False
    nonces = []
    def snapshot(_control):
        nonlocal candidate_seen
        state = updates.optional_record(control / "transition.json")
        if not state or state["phase"] == "PREPARED":
            return []
        if state["phase"] == "APPLIED_PENDING_READY":
            if candidate_seen:
                return []  # New GUI exited normally before READY.
            candidate_seen = True
            nonces.append(state["nonce"])
            updates.write_json_durable(stage / "trial.json", {"nonce": state["nonce"], "transition_id": state["transition_id"], "pid": 42})
            return [dict(pid=42, observable=True, sha=NEW, sid="operator", role="gui", ordinary_user=True, created_at=LATER)]
        if state["phase"] == "ROLLBACK_PENDING_READY":
            nonces.append(state["nonce"])
            updates.write_json_durable(stage / "trial.json", {"nonce": state["nonce"], "transition_id": state["transition_id"], "pid": 44})
            updates.write_json_durable(stage / "ready.json", {**{check: True for check in updates.READY_CHECKS}, "nonce": state["nonce"], "transition_id": state["transition_id"], "sha": OLD, "pid": 44, "ready_at": LATER})
            return [dict(pid=pid, observable=True, sha=OLD, sid="operator", role=role, ordinary_user=True, created_at=LATER) for pid, role in ((44, "gui"), (45, "relay"))]
        return []  # Candidate writers are absent before rollback.
    monkeypatch.setattr(updates, "process_snapshot", snapshot)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    original_policy = (control / "policy.json").read_bytes()
    assert updates.apply_prepared(control) == 0
    result = updates.read_json(control / "transition.json")
    assert result["phase"] == "ROLLED_BACK"
    assert result["failed_shas"] == [NEW]
    assert updates.read_json(control / "active.json")["sha"] == OLD
    assert nonces[0] != nonces[-1]
    assert result["trial_sha"] == OLD
    assert business.read_bytes() == b"original business state must not be restored or deleted"
    assert (control / "policy.json").read_bytes() == original_policy
    assert any(mode == "Verify" and path.name == OLD for mode, path in verified)


def test_pending_gui_scan_does_not_enter_preflight_or_business_mutation():
    from Container_Audit import ContainerAudit

    app = object.__new__(ContainerAudit)
    app._startup_update_pending = True
    refusals = []
    app._refuse_entry_scan = refusals.append
    app.process_barcode()
    assert len(refusals) == 1


def test_relay_logon_launches_gui_and_ordinary_trial_relay_on_the_same_data_root(monkeypatch, tmp_path):
    from contextlib import nullcontext
    import time

    control = tmp_path / "update-control"
    stage = tmp_path / "stage"
    control.mkdir(); stage.mkdir()
    policy = dict(operator_sid="operator", staging_root=str(stage))
    state = updates.apply_transition(prepared(), writers_absent=True, packet_verified=True, durable_prepared=True, now=NOW)
    updates.write_json_durable(control / "policy.json", policy)
    updates.write_json_durable(control / "active.json", {"sha": NEW})
    updates.write_json_durable(control / "transition.json", state)
    monkeypatch.setattr(updates, "control_root", lambda _root: control)
    monkeypatch.setattr(updates, "ordinary_user_context", lambda _sid=None: True)
    monkeypatch.setattr(updates, "update_lock", lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(updates, "prepared_pending", lambda *_args: False)
    launched = []
    monkeypatch.setattr(updates, "launch_version", lambda _control, sha, args, **kwargs: launched.append((sha, args, kwargs)) or 42)
    def complete(_seconds):
        updates.write_json_durable(control / "transition.json", {**state, "phase": "CONFIRMED"})
    monkeypatch.setattr(time, "sleep", complete)
    assert updates.bootstrap(tmp_path / "app", ["--container-audit-user-relay", "--data-root", "existing-data"], role="relay") == 0
    assert [args for _, args, _ in launched] == [["--data-root", "existing-data"], ["--container-audit-user-relay", "--data-root", "existing-data"]]
    assert all(sha == NEW and settings["nonce"] == state["nonce"] for sha, _, settings in launched)


def test_portable_relay_gate_does_not_require_the_gui_pid(monkeypatch, tmp_path):
    from contextlib import nullcontext

    control = tmp_path / "control"
    state = trial()
    monkeypatch.setattr(updates, "control_root", lambda _root: control)
    monkeypatch.setattr(updates, "ordinary_user_context", lambda _sid=None: True)
    monkeypatch.setattr(updates, "update_lock", lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(updates, "optional_record", lambda path: state if path.name == "transition.json" else {"nonce": state["nonce"], "transition_id": state["transition_id"], "pid": 42})
    monkeypatch.setattr(updates, "read_json", lambda path: {"operator_sid": "operator", "staging_root": str(tmp_path)} if path.name == "policy.json" else {"sha": NEW})
    monkeypatch.setattr(updates, "version_manifest", lambda _root: {"source_commit": NEW})
    monkeypatch.setenv("KMTECH_CA_UPDATE_TRIAL_NONCE", state["nonce"])
    assert updates.startup_gate(tmp_path / "app", ["--container-audit-user-relay"]) is None


def manifests():
    current = dict(source_commit=OLD, version="v2.0.99", contract_sha256="a" * 64, writer_sink_inventory_contract_sha256="a" * 64, data_api_contract_sha256="c" * 64)
    candidate = dict(source_commit=NEW, version="v2.0.100", contract_sha256="b" * 64, writer_sink_inventory_contract_sha256="b" * 64, data_api_contract_sha256="c" * 64)
    return current, candidate


def test_signed_manifest_pairs_use_existing_es256_and_reject_other_key_and_tamper():
    import json
    import update_service
    from vendor.kmtech_zero_pe.cng_p256 import P256KeyPair

    from tests.test_signed_pairrule import signed
    current, candidate = manifests()
    manifest = dict(schema_version="kmtech-private-update-manifest-v1", manifest_version=1, signature_version="es256-v1", app_id="Container_Audit", **signed(current, candidate))
    # Existing migration fixture uses ephemeral CNG keys; none are persisted.
    with P256KeyPair.generate() as key:
        signature = key.sign_es256(update_service.canonical_manifest_bytes(manifest))
        public = json.dumps(key.public_jwk, sort_keys=True)
    update_service.verify_update_manifest_signature(manifest, signature, public)
    current, candidate = manifests()
    assert updates.manifest_transition_pins(manifest, current=current, candidate=candidate)[3] == "SIGNED_EXACT_PAIR"
    with P256KeyPair.generate() as other:
        wrong_public = json.dumps(other.public_jwk, sort_keys=True)
    with pytest.raises(ValueError):
        update_service.verify_update_manifest_signature(manifest, signature, wrong_public)
    with pytest.raises(ValueError):
        update_service.verify_update_manifest_signature({**manifest, "approved_transitions": []}, signature, public)


@pytest.mark.parametrize("approvals", [None, [], [*pins(), {**pins()[0], "from_commit": "9" * 40}], [{**pins()[0], "from_commit": "*"}, pins()[1]], [{**pins()[0], "from_commit": "9" * 40}, pins()[1]]])
def test_unsigned_or_foreign_pair_cannot_authorize_changed_contract(approvals):
    current, candidate = manifests()
    manifest = {} if approvals is None else {"approved_transitions": approvals}
    with pytest.raises(ValueError):
        updates.manifest_transition_pins(manifest, current=current, candidate=candidate)


def test_identical_writer_and_data_contract_still_requires_signed_exact_pair():
    current, candidate = manifests()
    candidate["writer_sink_inventory_contract_sha256"] = current["writer_sink_inventory_contract_sha256"]
    with pytest.raises(ValueError, match='invalid_bidirectional_update_pair'):
        updates.manifest_transition_pins({}, current=current, candidate=candidate)


def test_reverse_policy_audit_is_written_only_after_confirmation(monkeypatch, tmp_path):
    updates.write_json_durable(tmp_path / "policy.json", {"feed_url": "https://example.test/feed", "approved_transitions": []})
    original = (tmp_path / "policy.json").read_bytes()
    state = {**trial(), "rollback_pair": pins()[1], "pin_authority": "SIGNED_EXACT_PAIR"}
    updates.record_confirmed_policy(tmp_path, state)
    assert (tmp_path / "policy.json").read_bytes() == original
    confirmed = {**state, "phase": "CONFIRMED"}
    updates.write_json_durable(tmp_path / "transition.json", confirmed)
    result = updates.record_confirmed_policy(tmp_path, confirmed)
    policy = updates.read_json(tmp_path / "policy.json")
    assert policy["last_confirmed_rollback"] == pins()[1]
    assert policy["approved_transitions"] == []
    assert result["policy_audit_applied"] is True


def test_prepared_handle_rejects_hardlink_and_foreign_owner(tmp_path):
    import os

    source = tmp_path / "source"
    source.write_bytes(b"owned packet")
    with pytest.raises(ValueError, match="owned"):
        with updates.unredirected_source(source, expected_owner_sid="S-1-5-21-0-0-0-65535"):
            pass
    os.link(source, tmp_path / "alias")
    with pytest.raises(ValueError, match="hardlinks"):
        with updates.unredirected_source(source):
            pass


def test_prepared_handle_holds_ancestors_and_bytes_until_copy_finishes(tmp_path):
    directory = tmp_path / "stage"
    directory.mkdir()
    source = directory / "packet.zip"
    source.write_bytes(b"authenticated original")
    with updates.unredirected_source(source) as incoming:
        with pytest.raises(OSError):
            source.write_bytes(b"concurrent replacement")
        with pytest.raises(OSError):
            directory.rename(tmp_path / "renamed")
        assert incoming.read() == b"authenticated original"
    source.write_bytes(b"new packet after readers finish")


@pytest.mark.parametrize("queue_state", ["healthy", "missing", "corrupt"])
def test_ready_reads_existing_ledger_and_queue_without_repair(monkeypatch, tmp_path, queue_state):
    import sqlite3
    from types import SimpleNamespace
    import current_user_onboarding
    import user_relay

    paths = SimpleNamespace(data_root=tmp_path, events_dir=tmp_path / "events", queue_dir=tmp_path / "queue",
                            ledger_path=tmp_path / "ledger.db", direct_sync_root=tmp_path / "direct_sync")
    paths.events_dir.mkdir()
    paths.queue_dir.mkdir()
    with sqlite3.connect(paths.ledger_path) as connection:
        connection.execute("CREATE TABLE preserved(value TEXT)")
    queue = paths.queue_dir / "direct_sync_relay.sqlite3"
    if queue_state == "healthy":
        with sqlite3.connect(queue) as connection:
            connection.execute("CREATE TABLE preserved(value TEXT)")
    elif queue_state == "corrupt":
        queue.write_bytes(b"original corrupt evidence")
    before = queue.read_bytes() if queue.exists() else None
    state = trial()
    monkeypatch.setattr(updates, "trial_context", lambda _root: (tmp_path, {"staging_root": str(tmp_path)}, state))
    monkeypatch.setattr(updates, "ordinary_user_context", lambda *_args: True)
    monkeypatch.setattr(current_user_onboarding, "resolve_current_user_onboarding_paths", lambda _root: paths)
    monkeypatch.setattr(current_user_onboarding, "inspect_current_user_state", lambda _paths: {"status": "READY"})
    monkeypatch.setattr(user_relay, "user_relay_status_path", lambda _root: tmp_path / "relay.json")
    monkeypatch.setattr(updates, "optional_record", lambda _path: {"status": "RUNNING", "source_commit": NEW,
                                                                "update_nonce": state["nonce"], "ordinary_user": True})
    monkeypatch.setattr(updates, "version_manifest", lambda _root: {"source_commit": NEW})
    assert updates.publish_gui_ready(tmp_path / "app") is (queue_state == "healthy")
    assert (queue.read_bytes() if queue.exists() else None) == before
    assert (tmp_path / "ready.json").exists() is (queue_state == "healthy")


def test_disabled_update_preserves_the_existing_relay_cycle_shape(monkeypatch, tmp_path):
    import user_relay

    monkeypatch.setattr(user_relay, "run_session_direct_sync_once", lambda **_kwargs: {"status": "PASS", "returncode": 0})
    monkeypatch.setattr(user_relay, "_read_json", lambda _path: {"status": "paused_by_operator"})
    monkeypatch.setattr(updates, "prepare_feed_packet", lambda _root: {"status": "OFF"})
    assert user_relay._runtime_cycle(app_root=tmp_path / "app", direct_sync_root=tmp_path / "sync", scan_source_dir=tmp_path / "events") == {
        "status": "paused_by_operator", "relay_status": "paused_by_operator", "process_status": "PASS", "process_returncode": 0,
    }

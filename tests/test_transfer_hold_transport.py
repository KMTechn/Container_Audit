"""Held bundles and unbound attempts stay durable until admission is restored."""
import json
from urllib.parse import urlsplit

import pytest

from Container_Audit import TraySession
from preflight_scan_hold import PreflightScanHoldStore
from tests.test_phs2_master_preflight import _app, COMPACT_QR
from tests.test_transfer_seal import (
    FakeResponse, TransferSealCoordinator, TransferSealStore,
    _client, _prepare, _receipt, _resolved_bundle,
)
from tests.test_transfer_member_exchange import _runtime as exchange_runtime, _prepare as prepare_exchange


def seal_runtime(tmp_path):
    posts = []

    def handler(call):
        if call["method"] == "POST":
            posts.append(call["json"])
            return FakeResponse(200, {"ok": True, "data": _receipt(call["json"])})
        if urlsplit(call["url"]).path.endswith("/bundles/resolve"):
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        return FakeResponse(404, {"ok": False, "error": {"code": "RECEIPT_NOT_FOUND"}})

    client, session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator, require_completion_checkpoint=True)
    coordinator.confirm_completion_checkpoint(prepared.intent_id)
    app = _app(tmp_path, client)
    app.worker_name = "other-worker"
    app._work_session_identity_bound = True
    app._admin_pin_login_epoch = "original-login"
    app.transfer_seal_coordinator = coordinator
    app._transfer_seal_runtime()
    master = coordinator.store.load(prepared.intent_id)["master_label"]
    hold = PreflightScanHoldStore(app._preflight_hold_base_path(), capacity=68)
    return app, coordinator, prepared.intent_id, hold, master, posts, session


@pytest.mark.parametrize("gap", ["selection", "session-save-failure", "worker-change", "activation-audit-failure"])
@pytest.mark.parametrize("scheduled", ["accepted", "timer", "inflight"])
def test_unbound_attempts_preserve_hold_and_resume_once(tmp_path, monkeypatch, gap, scheduled):
    app, coordinator, intent_id, hold, master, posts, _session = seal_runtime(tmp_path)
    hold.start(worker="tester", master_raw=master, scan_epoch=1)
    original = hold.path.read_bytes()
    before = dict(coordinator.store.load(intent_id))

    def unbind():
        app.worker_name = ""
        app._work_session_identity_bound = False
        if gap == "worker-change":
            app._admin_pin_login_epoch = "selection-login"

    raw_build = coordinator._build_command
    if scheduled == "inflight":
        def build(row):
            unbind()
            return raw_build(row)
        monkeypatch.setattr(coordinator, "_build_command", build)
    else:
        unbind()
    if scheduled == "timer":
        app.root.after(30_000, lambda: coordinator.attempt(intent_id))
        app.root.run_next()
    else:
        coordinator.attempt(intent_id)
    row = coordinator.store.load(intent_id)
    assert posts == []
    assert row["status"] == "RETRY_WAIT"
    assert row["last_error_code"] == "TRANSFER_HOLD_WAIT"
    assert hold.path.read_bytes() == original
    for field in ("intent_id", "idempotency_key", "scanned_barcodes_json", "completion_checkpoint_confirmed"):
        assert row[field] == before[field]

    monkeypatch.setattr(coordinator, "_build_command", raw_build)
    assert hold.mark_draining() is None
    app.worker_name = "other-worker"
    app._work_session_identity_bound = True
    app._admin_pin_login_epoch = "new-login"
    result = coordinator.attempt(intent_id)
    assert result.status == "ACKED"
    assert len(posts) == 1
    assert posts[0]["idempotency_key"] == before["idempotency_key"]
    assert coordinator.attempt(intent_id).status == "ACKED"
    assert len(posts) == 1


@pytest.mark.parametrize("actor", ["tester", "other-worker"])
@pytest.mark.parametrize("named_slot", [False, True])
def test_held_bundle_cannot_be_posted_by_either_worker(tmp_path, actor, named_slot):
    app, coordinator, intent_id, hold, master, posts, _session = seal_runtime(tmp_path)
    if named_slot:
        hold = PreflightScanHoldStore(hold.path.with_name(hold.path.stem + "_original.json"), capacity=68)
    hold.start(worker="tester", master_raw=master, scan_epoch=1)
    original = hold.path.read_bytes()
    app.worker_name = actor
    assert coordinator.attempt(intent_id).status == "RETRY_WAIT"
    assert posts == []
    assert hold.path.read_bytes() == original


def test_other_bundle_transmits_while_foreign_hold_is_preserved(tmp_path):
    app, coordinator, intent_id, hold, master, posts, _session = seal_runtime(tmp_path)
    hold.start(worker="tester", master_raw=master.replace("PHS-SERVER-001", "PHS-OTHER"), scan_epoch=1)
    original = hold.path.read_bytes()
    assert coordinator.attempt(intent_id).status == "ACKED"
    assert len(posts) == 1
    assert hold.path.read_bytes() == original


def test_different_labels_with_same_input_anchor_remain_independent(tmp_path):
    app, _coordinator, _intent, hold, _master, _posts, _session = seal_runtime(tmp_path)
    hold.start(worker="tester", master_raw=COMPACT_QR, scan_epoch=1)
    assert app._preflight_label_is_held(COMPACT_QR + "|QT=2")
    assert not app._preflight_label_is_held(COMPACT_QR.replace("LBL-COMPACT-001", "LBL-OTHER"))


def test_client_checks_after_headers_and_preserves_original_command(tmp_path, monkeypatch):
    app, coordinator, intent_id, _hold, _master, posts, _session = seal_runtime(tmp_path)
    headers = coordinator.client._headers
    def change_actor(key=""):
        app.worker_name = ""
        return headers(key)
    # The command is already bound: change admission inside the final client
    # preparation, after the coordinator's own check has succeeded.
    row = coordinator.store.load(intent_id)
    coordinator.store.bind_command(intent_id, coordinator._build_command(row))
    original = coordinator.store.load(intent_id)["command_json"]
    monkeypatch.setattr(coordinator.client, "_headers", change_actor)
    assert coordinator.attempt(intent_id).status == "RETRY_WAIT"
    assert posts == []
    assert coordinator.store.load(intent_id)["command_json"] == original


def test_old_attempt_cannot_cross_a_new_login_binding(tmp_path, monkeypatch):
    app, coordinator, intent_id, _hold, _master, posts, _session = seal_runtime(tmp_path)
    build = coordinator._build_command
    def rebind(row):
        app._admin_pin_login_epoch = "another-login"
        return build(row)
    monkeypatch.setattr(coordinator, "_build_command", rebind)
    assert coordinator.attempt(intent_id).status == "RETRY_WAIT"
    assert posts == []


def test_identity_is_rechecked_after_reading_durable_hold_evidence(tmp_path, monkeypatch):
    app, coordinator, intent_id, hold, master, posts, _session = seal_runtime(tmp_path)
    hold.start(worker="tester", master_raw=master.replace("PHS-SERVER-001", "PHS-OTHER"), scan_epoch=1)
    load = PreflightScanHoldStore.load_path
    def changed_while_reading(path):
        snapshot = load(path)
        app.worker_name = ""
        return snapshot
    monkeypatch.setattr(PreflightScanHoldStore, "load_path", staticmethod(changed_while_reading))
    assert coordinator.attempt(intent_id).status == "RETRY_WAIT"
    assert posts == []


def test_exchange_guard_runs_after_command_preparation_and_resumes_same_key(tmp_path, monkeypatch):
    coordinator, posts, session = exchange_runtime(tmp_path)
    handler = session.handler
    session.handler = lambda call: (
        FakeResponse(404, {"ok": False, "error": {"code": "RECEIPT_NOT_FOUND"}})
        if "/receipts/" in urlsplit(call["url"]).path else handler(call)
    )
    prepared = prepare_exchange(coordinator)
    app = _app(tmp_path, coordinator.client)
    app.worker_name = "other-worker"
    app._work_session_identity_bound = True
    app._admin_pin_login_epoch = "original-login"
    coordinator.transport_guard_factory = app._transfer_transport_guard
    hold = PreflightScanHoldStore(app._preflight_hold_base_path(), capacity=68)
    master = coordinator.store.load(prepared.intent_id)["master_label"]
    build = coordinator._build_command
    def held_during_build(row):
        command = build(row)
        hold.start(worker="tester", master_raw=master, scan_epoch=1)
        return command
    monkeypatch.setattr(coordinator, "_build_command", held_during_build)
    assert coordinator.attempt(prepared.intent_id).status == "RETRY_WAIT"
    assert posts == []
    saved = coordinator.store.load(prepared.intent_id)["command_json"]
    original = hold.path.read_bytes()
    assert hold.mark_draining() is None
    assert original
    assert coordinator.attempt(prepared.intent_id).status == "ACKED"
    assert len(posts) == 1
    assert posts[0] == json.loads(saved)


@pytest.mark.parametrize("action", ["UNDO", "EXCHANGE", "complete", "finish"])
def test_mutation_gate_matches_foreign_current_bundle(tmp_path, action):
    app, _coordinator, _intent, hold, master, _posts, _session = seal_runtime(tmp_path)
    hold.start(worker="tester", master_raw=master, scan_epoch=1)
    original = hold.path.read_bytes()
    app.current_tray = TraySession(master_label_code=master)
    scans = list(app.current_tray.scanned_barcodes)
    app._render_warning_state = lambda: None
    if action == "finish":
        captured = app._capture_mutation_finish_identity()
        assert not app._mutation_finish_can_apply(captured, operation=action)
    elif action == "UNDO":
        app.undo_last_scan()
    elif action == "EXCHANGE":
        assert app.show_exchange_dialog() is False
        assert not getattr(app, "_inline_exchange_mode", "")
    elif action == "complete":
        assert app.request_complete_tray() is False
    assert app.current_tray.master_label_code == master
    assert app.current_tray.scanned_barcodes == scans
    assert hold.path.read_bytes() == original
    app.current_tray = TraySession(master_label_code=master.replace("PHS-SERVER-001", "PHS-OTHER"))
    assert not app._preflight_context_blocks_mutation()

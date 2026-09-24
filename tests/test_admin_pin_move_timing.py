"""A PIN authorizes the bytes at the final file move, including after restart."""

from __future__ import annotations

import hashlib
import sys
import uuid
from pathlib import Path

import pytest

from Container_Audit import ContainerAudit
from event_stream_policy import local_only_event_log_path
from pin_file_move import file_sha256, locked_pinned_source
from tests.test_container_admin_pin import SignedPinServer, make_headless_app


ACTIONS = (
    ("CA.PRECHECK_HOLD", "hold.json", "hold.quarantine.json"),
    ("CA.PAIR_RETRY", "current.json", "current.bad-1"),
    ("CA.PAIR_HANDOFF", "paired-current.json", "current.original"),
    ("CA.TRAY_HOLD", "tray.json", "tray.bad-1"),
)


def _approval(app, action, original, target_id):
    return app._admin_pin_approval_for(
        action, target_id, lambda: {"source_sha256": file_sha256(original)},
        ("PHS2-original",), lambda _intent: False,
    )


def _business_case(monkeypatch, tmp_path, action, transport=None):
    """Keep real PIN, durable stores and handlers; replace only UI/remote adapters."""
    import csv
    import json
    from types import SimpleNamespace
    from Container_Audit import TraySession, WarningPresenter
    from storage_utils import atomic_write_json
    from tests.test_container_admin_pin import make_client
    from tests.test_container_p0_contracts import _preflight_hold_ownership_app, _saved_tray_state
    from tests.test_paired_preflight_handoff import _app

    if action == "CA.PAIR_HANDOFF":
        app, hold, state = _app(tmp_path, monkeypatch)
    else:
        _, app, hold = _preflight_hold_ownership_app(tmp_path, monkeypatch)
        state = _saved_tray_state()
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.local_events_folder = str(tmp_path / "local_events")
    app._admin_pin_login_epoch = uuid.uuid4().hex
    server = SignedPinServer()
    app._admin_pin_client = make_client(monkeypatch, transport or server)
    app._prompt_blocked_work_admin_pin = lambda: ("manager-1", "194826")
    app._admin_pin_approval_for = ContainerAudit._admin_pin_approval_for.__get__(app)
    app._admin_pin_complete = ContainerAudit._admin_pin_complete.__get__(app)
    app.warning_presenter = WarningPresenter()
    app._stop_warning_beep = lambda: None
    app._invalidate_pending_scan_callbacks = lambda: None
    app.scanned_listbox = SimpleNamespace(delete=lambda *_args: None)
    app.root = SimpleNamespace(after=lambda _delay, callback, *args: callback(*args))
    for name in ("_reset_ui_to_waiting_state", "_update_all_summaries",
                 "_render_warning_state", "_schedule_startup_transfer_recovery"):
        setattr(app, name, lambda: None)
    app._show_left_sidebar_view = lambda *_args: None
    audits = []

    def audit(event, detail=None, **_kwargs):
        audits.append(event)
        path = Path(app.local_events_folder) / "business.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=("event", "details"))
            if stream.tell() == 0:
                writer.writeheader()
            writer.writerow({"event": event, "details": json.dumps(detail or {})})
        return True

    app._log_event = audit
    current = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    label = state["master_label_code"]
    if action == "CA.PRECHECK_HOLD":
        hold.start(worker=app.worker_name, master_raw=label, scan_epoch=1)
        hold.append("PRODUCT-A")
        hold.mark_failed(error_code="PHS2_PREFLIGHT_UNAVAILABLE")
        app._preflight_hold_snapshot = hold.load()
        app._set_preflight_scan_input_locked(True)
        original = hold.path
        invoke = lambda: app._quarantine_preflight_hold_for_supervisor(reason="test", confirm=False)
    elif action == "CA.PAIR_HANDOFF":
        original = hold.path
        invoke = app._defer_paired_preflight_from_operations
    else:
        atomic_write_json(current, state)
        original = current
        app.computer_id = "test-host"
        if action == "CA.PAIR_RETRY":
            app._paired_stale_current_blocked = True
            app._paired_stale_current_path = str(current)
            app._paired_stale_current_original_hash = file_sha256(current)
            app._paired_stale_current_original_bytes = current.read_bytes()
            invoke = app._retry_paired_stale_current_preservation
        else:
            app.current_tray = TraySession(master_label_code=label)
            app._current_tray_state_snapshot = lambda: dict(state)
            app._save_tray_state_snapshot = lambda saved: atomic_write_json(current, saved) or True
            app._active_blocking_completion_snapshot = lambda: {"blocked": True}
            app._current_transfer_member_exchange_attempt = lambda: None
            invoke = lambda: app._defer_blocked_current_tray_for_supervisor(confirm=False)
    return app, server, audits, original, label, invoke


@pytest.mark.parametrize("action,source_name,held_name", ACTIONS)
@pytest.mark.parametrize("timing", ("redemption", "after_audit", "before_move"))
def test_changed_bytes_need_new_pin_at_each_boundary(
        monkeypatch, tmp_path, action, source_name, held_name, timing):
    import json
    from tests.test_container_admin_pin import make_client

    app, server, audits, original, _label, invoke = _business_case(monkeypatch, tmp_path, action)
    # A valid document for the same label, not a malformed sentinel.
    changed = json.loads(original.read_text(encoding="utf-8"))
    changed["worker" if action in {"CA.PRECHECK_HOLD", "CA.PAIR_HANDOFF"} else "worker_name"] = "changed-worker"
    changed = json.dumps(changed, ensure_ascii=False).encode("utf-8")
    injected = []

    def mutate():
        if not injected:
            original.write_bytes(changed)
            injected.append(True)

    if timing == "redemption":
        def transport(path, body, headers):
            reply = server(path, body, headers)
            if path.endswith("/redemptions"):
                mutate()
            return reply
        app._admin_pin_client = make_client(monkeypatch, transport)
    elif timing == "after_audit":
        real_audit = app._log_event
        def audit(event, **kwargs):
            result = real_audit(event, **kwargs)
            if event == "ADMIN_PIN_CONSUMED":
                mutate()
            return result
        app._log_event = audit
    else:
        real_rename = Path.rename
        def rename(path, target):
            if path == original:
                mutate()
            return real_rename(path, target)
        monkeypatch.setattr(Path, "rename", rename)
    assert invoke() is False
    assert injected == [True]
    intent = app._admin_pin_store().list_pending()[0]
    assert intent["state"] == "TARGET_CHANGED"
    assert original.read_bytes() == changed
    assert "ADMIN_PIN_APPLIED" not in audits
    assert len([path for path, _ in server.calls if path.endswith("/redemptions")]) == 1
    app._recheck_admin_pin_intents()
    assert invoke() is True
    assert app._admin_pin_store().read(intent["operation_key"])["state"] == "SUPERSEDED"
    applied = [app._admin_pin_store().read(str(uuid.UUID(hex=path.stem[-32:])))
               for path in app._admin_pin_store().directory.glob("*.json")]
    fresh = next(row for row in applied if row["state"] == "APPLIED")
    assert fresh["operation_key"] != intent["operation_key"]
    moved = next(row for row in fresh["moving"] if row["source"] == str(original.resolve()))
    assert Path(moved["target"]).read_bytes() == changed
    assert not original.exists() and audits.count("ADMIN_PIN_APPLIED") == 1
    assert len([path for path, _ in server.calls if path.endswith("/redemptions")]) == 2


@pytest.mark.parametrize("action,source_name,held_name", ACTIONS)
@pytest.mark.parametrize("boundary", ("before_move", "after_move", "after_verification", "after_readback"))
@pytest.mark.parametrize("changed", (False, True))
def test_move_journal_recovers_each_interruption(
        monkeypatch, tmp_path, action, source_name, held_name, boundary, changed):
    import datetime
    import json
    from types import SimpleNamespace
    import pin_file_move
    import tray_state
    from tests.test_container_admin_pin import assert_other_phs2_starts

    app, server, audits, original, label, invoke = _business_case(monkeypatch, tmp_path, action)
    raw = original.read_bytes()
    fixed = datetime.datetime.now()
    class Clock(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed
    monkeypatch.setattr(tray_state, "datetime", SimpleNamespace(
        datetime=Clock, timedelta=datetime.timedelta, timezone=datetime.timezone))
    injected = []
    with monkeypatch.context() as crash:
        if boundary in {"before_move", "after_move"}:
            real_rename = Path.rename
            def rename(path, target):
                if path == original and boundary == "before_move":
                    injected.append(boundary)
                    raise KeyboardInterrupt(boundary)
                result = real_rename(path, target)
                if path == original:
                    injected.append(boundary)
                    raise KeyboardInterrupt(boundary)
                return result
            crash.setattr(Path, "rename", rename)
        elif boundary == "after_verification":
            recover = pin_file_move.recover_pinned_move
            def verified(source, target, digest):
                status = recover(source, target, digest)
                if source == original and status == "MOVED_VERIFIED":
                    injected.append(boundary)
                    raise KeyboardInterrupt(boundary)
                return status
            crash.setattr(pin_file_move, "recover_pinned_move", verified)
        else:
            complete = app._admin_pin_complete
            def after_readback(approval, readback):
                def effect(intent):
                    result = readback(intent)
                    assert result is True
                    injected.append(boundary)
                    raise KeyboardInterrupt(boundary)
                return complete(approval, effect)
            crash.setattr(app, "_admin_pin_complete", after_readback)
        with pytest.raises(KeyboardInterrupt):
            invoke()
    assert injected == [boundary]
    intent = app._admin_pin_store().list_pending()[0]
    assert intent["state"] == "CONSUMED"
    moves = intent["moving"]
    move = next(row for row in moves if row["source"] == str(original.resolve()))
    held = Path(move["target"])
    assert move["sha256"] == hashlib.sha256(raw).hexdigest()
    assert (original if boundary == "before_move" else held).read_bytes() == raw
    if changed:
        payload = json.loads(raw)
        payload["worker" if action in {"CA.PRECHECK_HOLD", "CA.PAIR_HANDOFF"} else "worker_name"] = "changed-worker"
        changed_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        (original if boundary == "before_move" else held).write_bytes(changed_bytes)
    fixed += datetime.timedelta(seconds=2)
    app._admin_pin_login_epoch = uuid.uuid4().hex
    app._recheck_admin_pin_intents()
    saved = app._admin_pin_store().read(intent["operation_key"])
    assert saved["moving"][:len(moves)] == moves
    if changed:
        assert saved["state"] == "TARGET_CHANGED"
        assert original.read_bytes() == changed_bytes
        assert not held.exists()
        assert "ADMIN_PIN_APPLIED" not in audits
    else:
        assert saved["state"] == "APPLIED"
        assert not original.exists() and held.read_bytes() == raw
        assert audits.count("ADMIN_PIN_APPLIED") == 1
        if action == "CA.PAIR_RETRY":
            # Preserve-only is followed by the existing supervisor hold command.
            assert app._continue_after_paired_stale_current() is True
        assert_other_phs2_starts(app, label)
    assert len([path for path, body in server.calls if path.endswith("/redemptions")
                and body["operation_key"] == intent["operation_key"]]) == 1


@pytest.mark.parametrize("action,source_name,held_name", ACTIONS)
@pytest.mark.parametrize("boundary", ("before_move", "after_move"))
def test_offline_detachment_resumes_journal_destination(
        monkeypatch, tmp_path, action, source_name, held_name, boundary):
    import datetime
    from types import SimpleNamespace
    import tray_state
    from tests.test_container_admin_pin import assert_other_phs2_starts

    def offline(*_args):
        raise TimeoutError("offline")
    app, _server, audits, original, label, invoke = _business_case(
        monkeypatch, tmp_path, action, transport=offline)
    raw = original.read_bytes()
    fixed = datetime.datetime.now()
    class Clock(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed
    monkeypatch.setattr(tray_state, "datetime", SimpleNamespace(
        datetime=Clock, timedelta=datetime.timedelta, timezone=datetime.timezone))
    real_rename = Path.rename
    with monkeypatch.context() as crash:
        def rename(path, target):
            if path == original and boundary == "before_move":
                raise KeyboardInterrupt(boundary)
            result = real_rename(path, target)
            if path == original:
                raise KeyboardInterrupt(boundary)
            return result
        crash.setattr(Path, "rename", rename)
        with pytest.raises(KeyboardInterrupt):
            invoke()
    intent = app._admin_pin_store().list_pending()[0]
    assert intent["state"] == "UNVERIFIED_DETACHING"
    moves = intent["moving"]
    fixed += datetime.timedelta(seconds=2)
    app._admin_pin_login_epoch = uuid.uuid4().hex
    app._admin_pin_resume_unverified_detachments(startup=True)
    saved = app._admin_pin_store().read(intent["operation_key"])
    assert saved["state"] == "UNVERIFIED_OPERATOR_HOLD"
    assert saved["moving"][:len(moves)] == moves
    assert not original.exists()
    assert Path(moves[0]["target"]).read_bytes() == raw
    assert audits.count("ADMIN_PIN_UNVERIFIED_HOLD") == 1
    assert "ADMIN_PIN_APPLIED" not in audits
    assert_other_phs2_starts(app, label)


@pytest.mark.parametrize("restart", (False, True))
@pytest.mark.parametrize("boundary", ("normal", "after_move", "after_audit", "before_record", "audit_failed"))
def test_precheck_restore_releases_only_its_original_fifo(monkeypatch, tmp_path, restart, boundary):
    from container_admin_pin import AdminPinIntentStore
    from label_qr import canonical_master_label_key
    from preflight_scan_hold import PreflightScanHoldStore
    from tests.test_container_admin_pin import assert_other_phs2_starts

    app, server, audits, original, label, invoke = _business_case(monkeypatch, tmp_path, "CA.PRECHECK_HOLD")
    before = app._preflight_hold_store().load()
    assert invoke() is True
    intent = app._admin_pin_store().pending(
        "CA.PRECHECK_HOLD", hashlib.sha256(canonical_master_label_key(label).encode()).hexdigest(), include_applied=True)[0]
    held = Path(intent["moving"][0]["target"])
    if restart:
        app._admin_pin_login_epoch = uuid.uuid4().hex
        app._preflight_hold_store_instance = None
        app._preflight_hold_snapshot = None
        assert app._restore_preflight_scan_hold() is True
    assert_other_phs2_starts(app, label)
    with monkeypatch.context() as crash:
        if boundary == "after_move":
            restore = PreflightScanHoldStore.restore_quarantined
            def stopped(store, path):
                restore(store, path)
                raise KeyboardInterrupt(boundary)
            crash.setattr(PreflightScanHoldStore, "restore_quarantined", stopped)
        elif boundary == "after_audit":
            audit = app._log_event
            def stopped(event, **kwargs):
                result = audit(event, **kwargs)
                if event == "PHS2_PREFLIGHT_HOLD_RESTORED":
                    raise KeyboardInterrupt(boundary)
                return result
            crash.setattr(app, "_log_event", stopped)
        elif boundary == "before_record":
            write = AdminPinIntentStore.write
            def stopped(store, row):
                if (row.get("restoration") or {}).get("state") == "RESTORED":
                    raise KeyboardInterrupt(boundary)
                return write(store, row)
            crash.setattr(AdminPinIntentStore, "write", stopped)
        elif boundary == "audit_failed":
            audit = app._log_event
            crash.setattr(app, "_log_event", lambda event, **kwargs:
                          False if event == "PHS2_PREFLIGHT_HOLD_RESTORED" else audit(event, **kwargs))
        if boundary == "normal":
            assert app.restore_quarantined_preflight_hold(str(held)) is True
        elif boundary == "audit_failed":
            assert app.restore_quarantined_preflight_hold(str(held)) is False
            assert held.exists() and not original.exists()
        else:
            with pytest.raises(KeyboardInterrupt):
                app.restore_quarantined_preflight_hold(str(held))
    if boundary != "normal":
        assert app._paired_preflight_blocks_label(label)
        app._admin_pin_login_epoch = uuid.uuid4().hex
        app._recheck_admin_pin_intents()
    saved = app._admin_pin_store().read(intent["operation_key"])
    assert saved["state"] == "APPLIED"
    assert saved["restoration"]["state"] == "RESTORED"
    assert saved["restoration"]["hold_sha256"] == intent["source_snapshot"]["hold_sha256"]
    assert saved["restoration"]["audit_key"]
    assert "PHS2_PREFLIGHT_HOLD_RESTORED" in audits
    assert not held.exists() and original.is_file()
    assert not app._paired_preflight_blocks_label(label)
    restored = app._preflight_hold_store().load()
    assert restored.preflight_id == before.preflight_id and restored.items == before.items
    assert restored.master_raw == before.master_raw and restored.worker == before.worker
    if restart:
        app._preflight_hold_snapshot = None
        app._preflight_hold_store_instance = None
        assert app._restore_preflight_scan_hold() is True
        assert app._preflight_hold_snapshot.items == before.items
        assert not app._paired_preflight_blocks_label(label)
    # The normal notice acknowledgment resumes the original label and FIFO.
    started = []
    app._precommand_operator_review_retry_context = lambda: None
    app._update_center_display = lambda: None
    app._begin_compact_phs2_preflight = lambda **kwargs: started.append(
        (kwargs["barcode"], app._preflight_hold_store().load().items))
    app._acknowledge_active_notice()
    assert started == [(label, before.items)]
    assert len([path for path, _ in server.calls if path.endswith("/redemptions")]) == 1


@pytest.mark.parametrize("evidence", ("intent_only", "file_only", "damaged_file", "unreadable_file", "unreadable_intent"))
def test_precheck_guard_uses_durable_evidence_after_restart(monkeypatch, tmp_path, evidence):
    from tests.test_container_admin_pin import assert_other_phs2_starts

    app, _server, _audits, _original, label, invoke = _business_case(monkeypatch, tmp_path, "CA.PRECHECK_HOLD")
    assert invoke() is True
    pin_path = next(app._admin_pin_store().directory.glob("*.json"))
    intent = app._admin_pin_store().read(str(uuid.UUID(hex=pin_path.stem[-32:])))
    held = Path(intent["moving"][0]["target"])
    if evidence == "intent_only":
        held.rename(tmp_path / "preserved-hold.json")
    elif evidence == "file_only":
        pin_path.rename(tmp_path / "preserved-intent.json")
    elif evidence == "damaged_file":
        held.write_bytes(b'{"damaged":true}')
    elif evidence == "unreadable_file":
        read = Path.read_bytes
        def unreadable(path):
            if path == held:
                raise PermissionError("owned test original is unreadable")
            return read(path)
        monkeypatch.setattr(Path, "read_bytes", unreadable)
    else:
        read_text = Path.read_text
        def unreadable_intent(path, *args, **kwargs):
            if path == pin_path:
                raise PermissionError("owned test intent is unreadable")
            return read_text(path, *args, **kwargs)
        monkeypatch.setattr(Path, "read_text", unreadable_intent)
    app._preflight_hold_snapshot = None
    app._preflight_hold_store_instance = None
    app._admin_pin_login_epoch = uuid.uuid4().hex
    assert_other_phs2_starts(app, label)


@pytest.mark.parametrize("raw", (b'{"unidentified":"original evidence"}',
                                 b'{"master_raw":""}', b'{"master_raw":"  "}'))
def test_unidentified_precheck_original_can_be_bound_from_manager_list(monkeypatch, tmp_path, raw):
    from types import SimpleNamespace
    from tests.test_container_admin_pin import assert_other_phs2_starts

    app, _server, _audits, _original, label, invoke = _business_case(monkeypatch, tmp_path, "CA.PRECHECK_HOLD")
    assert invoke() is True
    pin_path = next(app._admin_pin_store().directory.glob("*.json"))
    intent = app._admin_pin_store().read(str(uuid.UUID(hex=pin_path.stem[-32:])))
    held = Path(intent["moving"][0]["target"])
    pin_path.rename(tmp_path / "preserved-intent.json")
    held.write_bytes(raw)
    assert app._paired_preflight_blocks_label("UNRELATED")
    tasks = []
    app._ui_task_lane = lambda: SimpleNamespace(is_busy=lambda: False, submit=tasks.append)
    app._transfer_seal_runtime = lambda: SimpleNamespace(client=SimpleNamespace(
        authority_scope_id="test", resolve_phs_label=lambda **_kwargs: {"id": "verified"}))
    monkeypatch.setattr("Container_Audit.simpledialog.askstring", lambda *_a, **_k: label)
    app._show_paired_preflight_handoffs()
    assert len(tasks) == 1
    tasks[0].finish(tasks[0].work())
    assert held.read_bytes() == raw
    assert_other_phs2_starts(app, label)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows share mode is the production lock")
def test_audit_source_lock_blocks_mutation_until_effect_readback(monkeypatch, tmp_path):
    source = tmp_path / "damaged-parked.json"
    source.write_bytes(b"pinned evidence")
    app, _audits, _notices = make_headless_app(monkeypatch, tmp_path, SignedPinServer())
    approval = _approval(app, "CA.TRAY_HOLD", source, "d" * 64)
    assert approval is not None
    with app._admin_pin_locked_sources(approval, [(source, file_sha256(source))]):
        with pytest.raises(OSError):
            source.write_bytes(b"changed while audit writes")
        assert source.read_bytes() == b"pinned evidence"
    source.write_bytes(b"changed after release")
    assert source.read_bytes() == b"changed after release"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows share mode is the production lock")
@pytest.mark.parametrize("action,source_name,held_name", ACTIONS)
def test_success_audit_keeps_moved_bytes_locked(monkeypatch, tmp_path,
                                               action, source_name, held_name):
    original, held = tmp_path / source_name, tmp_path / held_name
    original.write_bytes(b"exactly pinned")
    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, SignedPinServer())
    approval = _approval(app, action, original, hashlib.sha256(action.encode()).hexdigest())
    assert approval is not None
    app._admin_pin_move(approval, original, held, hashlib.sha256(b"exactly pinned").hexdigest())
    real_log = app._log_event
    blocked = []

    def audit_with_mutation(event, **kwargs):
        if event == "ADMIN_PIN_APPLIED":
            with pytest.raises(OSError):
                held.write_bytes(b"late change")
            blocked.append(True)
        return real_log(event, **kwargs)

    app._log_event = audit_with_mutation
    assert app._admin_pin_complete(approval, lambda _intent: held.read_bytes() == b"exactly pinned")
    assert blocked == [True]
    assert held.read_bytes() == b"exactly pinned"
    assert [event for event, _ in audits].count("ADMIN_PIN_APPLIED") == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Windows share mode is the production lock")
def test_audit_evidence_success_uses_separate_local_stream(monkeypatch, tmp_path):
    app, _audits, _notices = make_headless_app(monkeypatch, tmp_path, SignedPinServer())
    app.save_folder = str(tmp_path / "events")
    app.local_events_folder = str(tmp_path / "local_events")
    source = tmp_path / "local_events" / "source.csv"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"existing audit evidence")
    destinations = []

    def write_audit(_event, **kwargs):
        override = kwargs.get("log_file_path_override")
        destination = (local_only_event_log_path(
            override, local_events_dir=app.local_events_folder) if override else source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("ab") as stream:
            stream.write(b"new audit\n")
        destinations.append(destination)
        return True

    app._log_event = write_audit
    intent = {"operation_key": str(uuid.uuid4()), "action": "CA.PAIR_HANDOFF",
              "target": {"id": "e" * 64}, "operator": {"local_id": "worker-1"},
              "source_snapshot": {"source_audit_id": "source-row"}}
    with locked_pinned_source(source, file_sha256(source)):
        assert app._admin_pin_audit("ADMIN_PIN_APPLIED", intent)
    assert destinations[0] != source
    assert source.read_bytes() == b"existing audit evidence"

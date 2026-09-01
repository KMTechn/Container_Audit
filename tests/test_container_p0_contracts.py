from __future__ import annotations

import datetime
import importlib
import json
from pathlib import Path
import queue
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest

from Container_Audit import ContainerAudit, TraySession
from direct_sync_push import init_relay_queue_schema
from parked_tray_store import ParkedTrayStore
from storage_utils import atomic_write_json
from transfer_seal import (
    LogisticsTransferClient,
    SealAttempt,
    TransferSealError,
    TransferSealStore,
)


def _saved_tray_state():
    return {
        "worker_name": "홍길동",
        "master_label_code": "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-1|CLC=AAA2270730100|LBL=LBL-1|HSH=0123456789abcdef",
        "canonical_input_tag_qr": "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-1|CLC=AAA2270730100|LBL=LBL-1|HSH=0123456789abcdef",
        "active_label_qr_payload": "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-1|CLC=AAA2270730100|LBL=LBL-1|HSH=0123456789abcdef",
        "active_label_id": "LBL-1",
        "active_label_business_date": "2026-08-30",
        "active_label_worker_code": "fixture-worker",
        "operation_lease_id": "operation-lease-1",
        "item_code": "AAA2270730100",
        "item_name": "fixture item",
        "item_spec": "fixture spec",
        "scanned_barcodes": ["AAA2270730100-SERIAL-1"],
        "scan_times": [datetime.datetime(2026, 8, 30, 8, 0, 0).isoformat()],
        "tray_size": 2,
        "mismatch_error_count": 0,
        "total_idle_seconds": 0.0,
        "stopwatch_seconds": 30.0,
        "start_time": datetime.datetime(2026, 8, 30, 7, 59, 0).isoformat(),
        "has_error_or_reset": False,
        "is_test_tray": False,
        "is_partial_submission": False,
        "pending_completion_event": {
            "schema_version": 1,
            "event_type": "TRAY_COMPLETE",
            "idempotency_key": "tray-complete:transfer-intent-1",
            "observed_at": datetime.datetime(2026, 8, 30, 8, 0, 30).isoformat(),
            "projection_log_name": "container_log_20260830.csv",
            "projection_worker_name": "홍길동",
            "transfer_intent_id": "transfer-intent-1",
            "was_restored_session": False,
            "log_may_have_been_attempted": False,
            "transfer_detail": {},
        },
    }


def test_recovery_decline_moves_full_state_to_idempotent_parked_owner(tmp_path):
    state = _saved_tray_state()
    store = ParkedTrayStore(tmp_path / "parked")

    first = store.defer_recovery_state(
        state,
        worker_name="홍길동",
        computer_id="host-01",
    )
    second = store.defer_recovery_state(
        state,
        worker_name="홍길동",
        computer_id="host-01",
    )

    assert first.path == second.path
    assert first.defer_id == second.defer_id
    assert first.state_hash == second.state_hash
    assert first.replayed is False
    assert second.replayed is True
    assert ParkedTrayStore.load(first.path) == state
    assert "operation-lease-1" in first.path.read_text(encoding="utf-8")


def test_recovery_decline_audits_park_before_releasing_current_slot(tmp_path):
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = "홍길동"
    app.computer_id = "host-01"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.current_tray = TraySession(master_label_code="STALE", item_code="OLD")
    state = _saved_tray_state()
    atomic_write_json(tmp_path / "current.json", state, ensure_ascii=False)
    calls = []

    def log_event(event, detail=None, **kwargs):
        calls.append(("audit", event, detail, kwargs, (tmp_path / "current.json").exists()))
        return True

    original_delete = ContainerAudit._delete_current_tray_state.__get__(app, ContainerAudit)

    def delete_current():
        calls.append(("delete",))
        return original_delete()

    app._log_event = log_event
    app._delete_current_tray_state = delete_current

    assert app._defer_saved_recovery_state(state) is True

    parked = list((tmp_path / "parked").glob("parked_recovery_*.json"))
    assert len(parked) == 1
    assert not (tmp_path / "current.json").exists()
    assert app.current_tray.master_label_code == ""
    assert calls[0][0:2] == ("audit", "TRAY_PARKED")
    assert calls[0][-1] is True
    assert calls[0][2]["reason"] == "restore_declined_same_worker"
    assert calls[1] == ("delete",)


def test_recovery_decline_audit_failure_keeps_current_and_parked_copies(tmp_path):
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = "홍길동"
    app.computer_id = "host-01"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.current_tray = TraySession(master_label_code="STALE", item_code="OLD")
    state = _saved_tray_state()
    atomic_write_json(tmp_path / "current.json", state, ensure_ascii=False)
    app._log_event = lambda *args, **kwargs: False
    app._delete_current_tray_state = lambda: (_ for _ in ()).throw(
        AssertionError("current slot must not be released before the audit commit")
    )

    assert app._defer_saved_recovery_state(state) is False
    assert (tmp_path / "current.json").exists()
    assert len(list((tmp_path / "parked").glob("parked_recovery_*.json"))) == 1
    assert app.current_tray.master_label_code == "STALE"


def _hold_symbols():
    module = importlib.import_module("preflight_scan_hold")
    return module, module.PreflightScanHoldStore


def test_preflight_hold_is_restart_durable_fifo_and_exactly_once(tmp_path):
    module, PreflightScanHoldStore = _hold_symbols()
    path = tmp_path / "_preflight_scan_hold_host-01.json"
    store = PreflightScanHoldStore(path, capacity=4)
    context = store.start(
        worker="tester",
        master_raw="PHS=2|ITG=ITAG-1|CLC=AAA2270730100|LBL=LBL-1|HSH=0123456789abcdef",
        scan_epoch=7,
    )
    first = store.append("PRODUCT-A")
    second = store.append("PRODUCT-B")

    restarted = PreflightScanHoldStore(path, capacity=4)
    snapshot = restarted.load()
    assert snapshot.preflight_id == context.preflight_id
    assert snapshot.state == module.HOLD_LOOKUP
    assert [item.raw_barcode for item in snapshot.items] == ["PRODUCT-A", "PRODUCT-B"]
    assert [item.scan_id for item in snapshot.items] == [first.scan_id, second.scan_id]

    restarted.mark_failed(error_code="PHS2_PREFLIGHT_UNAVAILABLE")
    failed_snapshot = PreflightScanHoldStore(path, capacity=4).load()
    assert failed_snapshot.state == module.HOLD_LOOKUP_FAILED
    assert [item.raw_barcode for item in failed_snapshot.items] == ["PRODUCT-A", "PRODUCT-B"]

    restarted.resume(master_raw=failed_snapshot.master_raw, worker="tester")
    restarted.mark_draining()
    restarted.ack_head(first.scan_id)
    assert [item.raw_barcode for item in restarted.load().items] == ["PRODUCT-B"]
    restarted.ack_head(second.scan_id)
    assert path.exists() is False


def test_preflight_hold_overflow_preserves_existing_items(tmp_path):
    module, PreflightScanHoldStore = _hold_symbols()
    path = tmp_path / "hold.json"
    store = PreflightScanHoldStore(path, capacity=1)
    store.start(worker="tester", master_raw="MASTER", scan_epoch=1)
    store.append("PRODUCT-A")

    with pytest.raises(module.PreflightHoldFull):
        store.append("PRODUCT-B")

    assert [item.raw_barcode for item in store.load().items] == ["PRODUCT-A"]


def test_preflight_hold_quarantine_and_restore_transfer_exactly_one_owner(
    tmp_path,
):
    module, PreflightScanHoldStore = _hold_symbols()
    active_path = tmp_path / "active" / "hold.json"
    quarantine_dir = tmp_path / "parked" / "preflight_hold_quarantine"
    store = PreflightScanHoldStore(active_path, capacity=4)
    store.start(worker="tester", master_raw="MASTER", scan_epoch=1)
    store.append("PRODUCT-A")
    failed = store.mark_failed(error_code="PHS2_PREFLIGHT_UNAVAILABLE")

    quarantined = store.quarantine(quarantine_dir, reason="supervisor_new_work")

    assert active_path.exists() is False
    assert quarantined.path.is_file()
    assert quarantined.snapshot_hash == store.snapshot_hash(failed)
    assert quarantined.snapshot.state == module.HOLD_LOOKUP_FAILED

    # A replay with an already verified quarantine copy still releases the
    # duplicate active owner instead of reporting success with two owners.
    atomic_write_json(active_path, failed.to_payload(), ensure_ascii=False)
    replayed = store.quarantine(quarantine_dir, reason="supervisor_new_work")
    assert replayed.path == quarantined.path
    assert active_path.exists() is False

    restored = store.restore_quarantined(quarantined.path)
    assert restored == failed
    assert active_path.is_file()
    assert quarantined.path.exists() is False


def test_supervisor_quarantine_is_audited_and_restorable_by_original_worker(
    tmp_path,
    monkeypatch,
):
    module, _PreflightScanHoldStore = _hold_symbols()
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = "tester"
    app.worker_role = "ADMIN"
    app._authenticated_protected_admin = True
    app.current_tray = TraySession()
    app.save_folder = str(tmp_path / "events")
    app.parked_trays_dir = str(tmp_path / "parked")
    app.PREFLIGHT_SCAN_HOLD_FILE = "hold.json"
    app.TRAY_SIZE = 4
    app.COLOR_PRIMARY = "primary"
    app.COLOR_DANGER = "danger"
    app.statuses = []
    app.show_status_message = lambda *args, **kwargs: app.statuses.append(args)
    app.show_fullscreen_warning = lambda *args, **kwargs: None
    app._update_parked_trays_list = lambda: None
    app._master_preflight_pending = False
    app._preflight_hold_draining = False
    app._preflight_hold_snapshot = None
    audits = []
    app._log_event = lambda event, detail=None, **kwargs: audits.append(
        (event, detail, kwargs)
    ) or True
    monkeypatch.setattr(
        "Container_Audit.messagebox.askyesno",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        "Container_Audit.messagebox.showerror",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "Container_Audit.messagebox.showwarning",
        lambda *args, **kwargs: None,
    )

    store = app._preflight_hold_store()
    store.start(worker="tester", master_raw="MASTER", scan_epoch=1)
    store.append("PRODUCT-A")
    store.mark_failed(error_code="PHS2_PREFLIGHT_UNAVAILABLE")

    assert app._quarantine_preflight_hold_for_supervisor(
        reason="supervisor_new_work_required",
        confirm=False,
    ) is True
    quarantined = app._quarantined_preflight_holds()
    assert len(quarantined) == 1
    assert store.exists() is False
    assert audits[0][0] == "PHS2_PREFLIGHT_HOLD_QUARANTINED"
    assert audits[0][1]["held_scan_count"] == 1
    assert audits[0][2]["synchronous"] is True

    app.worker_role = "WORKER"
    app._authenticated_protected_admin = False
    assert app.restore_quarantined_preflight_hold(str(quarantined[0].path)) is True
    assert store.exists() is True
    assert store.load().state == module.HOLD_LOOKUP_FAILED
    assert [item.raw_barcode for item in store.load().items] == ["PRODUCT-A"]
    assert quarantined[0].path.exists() is False
    assert audits[1][0] == "PHS2_PREFLIGHT_HOLD_RESTORED"


def test_close_hands_draining_hold_and_current_tray_to_restart_without_delete(
    tmp_path,
):
    module, _PreflightScanHoldStore = _hold_symbols()
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = "tester"
    app.worker_role = "WORKER"
    app.current_tray = TraySession(master_label_code="MASTER", item_code="ITEM")
    app.save_folder = str(tmp_path)
    app.parked_trays_dir = str(tmp_path / "parked")
    app.PREFLIGHT_SCAN_HOLD_FILE = "hold.json"
    app.TRAY_SIZE = 4
    app._ui_lane = None
    app._preflight_hold_writer_instance = None
    app._scan_callback_pending = False
    app._preflight_hold_snapshot = None
    app._preflight_hold_draining = False
    app._master_preflight_pending = False
    app.master_label_replace_state = None
    app.current_exchange_session = SimpleNamespace(
        defective_barcodes=[],
        good_barcodes=[],
    )
    calls = []
    app._save_current_tray_state = lambda: calls.append("save-current") or True
    app._delete_current_tray_state = lambda: (_ for _ in ()).throw(
        AssertionError("hold-owned current tray must not be deleted on close")
    )
    app._log_event = lambda event, **kwargs: calls.append(event) or True
    app._end_work_session = lambda **kwargs: calls.append("end-session") or True
    app._finalize_application_close = lambda: calls.append("destroy")

    store = app._preflight_hold_store()
    store.start(worker="tester", master_raw="MASTER", scan_epoch=1)
    store.append("PRODUCT-A")
    store.mark_draining()

    app.on_closing(_confirmed=True)

    assert store.exists() is True
    assert store.load().state == module.HOLD_DRAINING
    assert calls == [
        "save-current",
        "PHS2_PREFLIGHT_HOLD_CLOSE_HANDOFF",
        "end-session",
        "destroy",
    ]


def test_scan_entry_is_preserved_until_idle_lane_admits_callback():
    class Entry:
        def __init__(self, value):
            self.value = value
            self.state = "normal"

        def get(self):
            return self.value

        def delete(self, *_args):
            self.value = ""

        def configure(self, **kwargs):
            self.state = kwargs.get("state", self.state)

    class Root:
        def __init__(self):
            self.jobs = []

        def after(self, _delay, callback, *args):
            self.jobs.append((callback, args))

    class BusyLane:
        state = "BUSY"

        @staticmethod
        def is_busy():
            return True

    app = ContainerAudit.__new__(ContainerAudit)
    app.scan_entry = Entry("PRODUCT-A")
    app.root = Root()
    app._ui_lane = BusyLane()
    app._ui_close_requested = False
    app._master_preflight_pending = False
    app._preflight_scan_input_locked = False
    app._completion_lane_busy = False
    app._scan_callback_pending = False
    app._scan_callback_epoch = 1
    app.COLOR_DANGER = "danger"
    app.statuses = []
    app.show_status_message = lambda *args, **kwargs: app.statuses.append(args)

    app.process_barcode()
    assert app.scan_entry.value == "PRODUCT-A"
    assert app.root.jobs == []

    app._ui_lane = None
    app._warning_state_presenter = lambda: SimpleNamespace(
        state=SimpleNamespace(is_blocking=False)
    )
    accepted = []
    app._process_barcode_logic = accepted.append
    app.process_barcode()
    assert app.scan_entry.value == "PRODUCT-A"
    assert len(app.root.jobs) == 1

    callback, args = app.root.jobs.pop(0)
    callback(*args)
    assert accepted == ["PRODUCT-A"]
    assert app.scan_entry.value == ""


def test_preflight_entry_allows_only_one_durable_append_before_clear(tmp_path):
    module, PreflightScanHoldStore = _hold_symbols()

    class Entry:
        def __init__(self, value):
            self.value = value
            self.state = "normal"

        def get(self):
            return self.value

        def delete(self, _start, _end):
            self.value = ""

        def configure(self, *, state):
            self.state = state

    class DeferredWriter:
        def __init__(self):
            self.submissions = []

        def submit(self, work, finish, fail):
            self.submissions.append((work, finish, fail))
            return SimpleNamespace(accepted=True)

    store = PreflightScanHoldStore(tmp_path / "hold.json", capacity=4)
    store.start(worker="tester", master_raw="MASTER", scan_epoch=1)
    writer = DeferredWriter()
    app = ContainerAudit.__new__(ContainerAudit)
    app.scan_entry = Entry("PRODUCT-A")
    app._master_preflight_pending = True
    app._preflight_hold_append_pending = False
    app._preflight_scan_input_locked = False
    app._completion_lane_busy = False
    app._ui_close_requested = False
    app.COLOR_DANGER = "danger"
    app.COLOR_PRIMARY = "primary"
    app.statuses = []
    app.show_status_message = lambda *args, **kwargs: app.statuses.append(args)
    app._preflight_hold_store = lambda: store
    app._preflight_hold_writer = lambda: writer

    app.process_barcode()
    app.process_barcode()

    assert len(writer.submissions) == 1
    assert app.scan_entry.value == "PRODUCT-A"
    assert app.scan_entry.state == "disabled"
    work, finish, _fail = writer.submissions[0]
    finish(work())

    assert [item.raw_barcode for item in store.load().items] == ["PRODUCT-A"]
    assert app.scan_entry.value == ""
    assert app.scan_entry.state == "normal"
    assert app._preflight_hold_append_pending is False


def test_tray_state_round_trips_preflight_scan_receipt_ownership():
    from tray_state import tray_session_from_state, validate_tray_state

    state = _saved_tray_state()
    barcode = state["scanned_barcodes"][0]
    state["preflight_scan_receipts"] = {barcode: "held-scan-1"}

    validate_tray_state(state, default_tray_size=60)
    restored = tray_session_from_state(
        state,
        session_factory=TraySession,
        default_tray_size=60,
    )

    assert restored.preflight_scan_receipts == {barcode: "held-scan-1"}


def test_completion_local_prepare_precedes_checkpoint_and_any_http_attempt():
    calls = []
    preview = SealAttempt("intent-order", "PREVIEW")
    prepared = SealAttempt("intent-order", "PREPARED")
    acked = SealAttempt("intent-order", "ACKED")

    class Coordinator:
        def preview(self, **_kwargs):
            calls.append("preview")
            return preview

        def prepare(self, **_kwargs):
            assert _kwargs["require_completion_checkpoint"] is True
            calls.append("local-prepare")
            return prepared

        def confirm_completion_checkpoint(self, intent_id):
            assert intent_id == prepared.intent_id
            calls.append("checkpoint-dispatch-enabled")
            return prepared

        def attempt(self, intent_id):
            assert intent_id == prepared.intent_id
            calls.append("http-attempt")
            return acked

    app = ContainerAudit.__new__(ContainerAudit)
    result = app._prepare_and_attempt_transfer_seal_snapshot(
        coordinator=Coordinator(),
        source_label_payload="MASTER",
        source_label_fields={"PHS": "1"},
        item_code="ITEM",
        operator="tester",
        scanned_barcodes=("PRODUCT-A",),
        relay_log_file_path="events.csv",
        operation_lease_id="",
        on_prepared=lambda attempt: calls.append(
            f"durable-checkpoint:{attempt.status}"
        ),
    )

    assert result is acked
    assert calls == [
        "preview",
        "local-prepare",
        "durable-checkpoint:PREPARED",
        "checkpoint-dispatch-enabled",
        "http-attempt",
    ]

    calls.clear()

    def fail_checkpoint(_attempt):
        calls.append("durable-checkpoint-failed")
        raise OSError("checkpoint unavailable")

    with pytest.raises(OSError, match="checkpoint unavailable"):
        app._prepare_and_attempt_transfer_seal_snapshot(
            coordinator=Coordinator(),
            source_label_payload="MASTER",
            source_label_fields={"PHS": "1"},
            item_code="ITEM",
            operator="tester",
            scanned_barcodes=("PRODUCT-A",),
            relay_log_file_path="events.csv",
            operation_lease_id="",
            on_prepared=fail_checkpoint,
        )
    assert calls == ["preview", "local-prepare", "durable-checkpoint-failed"]


def _insert_relay_row(db_path: Path, *, relay_id: str, status: str, created_at: str, updated_at: str):
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO direct_sync_relay_batches (
                relay_id,status,source_file_path,spooled_file_path,
                producer_manifest_path,relative_path,content_sha256,byte_length,
                attempt_count,created_at,updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                relay_id,
                status,
                "source.csv",
                "spool.csv",
                "manifest.json",
                "source.csv",
                "0" * 64,
                1,
                0,
                created_at,
                updated_at,
            ),
        )
        connection.commit()


def test_direct_sync_health_pending_is_neutral_and_terminal_is_review(tmp_path):
    module = importlib.import_module("direct_sync_health")
    db_path = tmp_path / "relay.sqlite3"
    init_relay_queue_schema(db_path)
    _insert_relay_row(
        db_path,
        relay_id="acked-old",
        status="acked",
        created_at="2026-09-01T00:00:00+00:00",
        updated_at="2026-09-01T01:00:00+00:00",
    )
    _insert_relay_row(
        db_path,
        relay_id="acked-new",
        status="acked",
        created_at="2026-09-01T00:10:00+00:00",
        updated_at="2026-09-01T02:00:00+00:00",
    )
    _insert_relay_row(
        db_path,
        relay_id="pending",
        status="pending",
        created_at="2026-09-01T03:00:00+00:00",
        updated_at="2026-09-01T03:00:00+00:00",
    )

    pending = module.read_relay_health(db_path=db_path)
    assert pending.state == "pending"
    assert pending.pending_count == 1
    assert pending.last_acked_at == "2026-09-01T02:00:00+00:00"
    assert pending.operator_attention is False

    _insert_relay_row(
        db_path,
        relay_id="review",
        status="operator_review",
        created_at="2026-09-01T04:00:00+00:00",
        updated_at="2026-09-01T04:00:00+00:00",
    )
    review = module.read_relay_health(db_path=db_path)
    assert review.state == "review"
    assert review.operator_review_count == 1
    assert review.operator_attention is True
    card = module.relay_health_card_model(review)
    assert card["tone"] == "amber"
    assert "저장 상태 확인 필요" in card["detail"]
    assert "source.csv" not in json.dumps(card, ensure_ascii=False)


def test_direct_sync_runtime_terminal_status_is_blocked(tmp_path):
    module = importlib.import_module("direct_sync_health")
    db_path = tmp_path / "relay.sqlite3"
    init_relay_queue_schema(db_path)
    runtime_status = tmp_path / "runtime.json"
    atomic_write_json(
        runtime_status,
        {
            "status": "blocked_queue_backpressure",
            "updated_at": "2026-09-01T05:00:00+00:00",
            "error_message": "https://secret.example.invalid/path?token=do-not-render",
        },
    )

    health = module.read_relay_health(
        db_path=db_path,
        runtime_status_path=runtime_status,
    )
    assert health.state == "blocked"
    assert health.operator_attention is True
    assert "secret.example" not in repr(health)


def test_session_direct_sync_wake_posts_one_sanitized_result(tmp_path, monkeypatch):
    bootstrap = importlib.import_module("direct_sync_auto_bootstrap")
    results = queue.Queue()
    monkeypatch.setenv("CONTAINER_AUDIT_SESSION_SYNC_TRIGGER", "1")
    monkeypatch.setattr(
        bootstrap,
        "run_session_direct_sync_once",
        lambda **_kwargs: {
            "status": "FAIL",
            "stdout_tail": "Authorization: Bearer raw-secret",
            "stderr_tail": "https://secret.example.invalid/path",
        },
    )
    monkeypatch.setattr(bootstrap, "_write_json", lambda *_args, **_kwargs: None)

    thread = bootstrap.start_session_direct_sync(
        app_root=tmp_path,
        direct_sync_root=tmp_path / "direct-sync",
        scan_source_dir=tmp_path,
        result_queue=results,
    )
    assert thread is not None
    thread.join(timeout=2.0)

    wake = results.get_nowait()
    results.task_done()
    assert wake.status == "FAIL"
    assert wake.error_category == "relay_wake_failed"
    assert results.empty()
    assert "raw-secret" not in repr(wake)
    assert "secret.example" not in repr(wake)


class HealthPumpRoot:
    def __init__(self):
        self.jobs = []
        self.after_thread_ids = []

    def after(self, delay, callback, *args):
        self.after_thread_ids.append(threading.get_ident())
        job = f"health-job-{len(self.jobs) + 1}"
        self.jobs.append((job, delay, callback, args))
        return job

    def run_next(self):
        _job, _delay, callback, args = self.jobs.pop(0)
        callback(*args)


class HealthCardWidget:
    def __init__(self):
        self.options = {}

    def configure(self, **kwargs):
        self.options.update(kwargs)


def _health_card():
    return {
        "frame": HealthCardWidget(),
        "label": HealthCardWidget(),
        "value": HealthCardWidget(),
    }


def test_direct_sync_health_reader_is_background_and_apply_is_tk_owned(tmp_path):
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = HealthPumpRoot()
    app.direct_sync_program_data_root = str(tmp_path / "direct-sync")
    app.info_cards = {"direct_sync": _health_card()}
    app._direct_sync_health_queue = queue.Queue(maxsize=1)
    app._direct_sync_wake_results = queue.Queue()
    app._direct_sync_health_generation = 0
    app._direct_sync_health_pending = False
    app._direct_sync_health_job = None
    app._direct_sync_health_poll_job = None
    db_path = tmp_path / "direct-sync" / "queue" / "direct_sync_relay.sqlite3"
    init_relay_queue_schema(db_path)
    owner_thread_id = threading.get_ident()

    app._start_direct_sync_health_refresh()
    deadline = time.monotonic() + 2.0
    while getattr(app, "_direct_sync_health", None) is None and time.monotonic() < deadline:
        if app.root.jobs:
            app.root.run_next()
        time.sleep(0.005)

    assert app._direct_sync_health is not None
    assert app._direct_sync_health_reader_thread_id != owner_thread_id
    assert app._direct_sync_health_apply_thread_id == owner_thread_id
    assert set(app.root.after_thread_ids) == {owner_thread_id}


def test_direct_sync_health_poll_skips_busy_lane_and_stale_result():
    health_module = importlib.import_module("direct_sync_health")
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = HealthPumpRoot()
    app._ui_lane = SimpleNamespace(is_busy=lambda: True)
    app._direct_sync_health_job = "due"
    app._direct_sync_health_generation = 4
    app._direct_sync_health_pending = False

    app._start_direct_sync_health_refresh()

    assert app._direct_sync_health_generation == 4
    assert app._direct_sync_health_pending is False
    assert len(app.root.jobs) == 1
    assert app.root.jobs[0][1] == 5000

    current = health_module.RelayHealth(
        "ready", 0, 0, 0, "", "", "2026-09-01T00:00:00+00:00"
    )
    stale = health_module.RelayHealth(
        "blocked", 0, 0, 0, "", "", "2026-09-01T00:00:01+00:00", "stale"
    )
    app._direct_sync_health = current
    app._direct_sync_health_queue = queue.Queue(maxsize=1)
    app._direct_sync_health_queue.put_nowait((3, stale))
    app._direct_sync_health_pending = True
    app._direct_sync_health_job = "already-scheduled"

    app._poll_direct_sync_health_result()

    assert app._direct_sync_health is current


def test_direct_sync_card_keeps_pending_neutral_and_terminal_amber():
    health_module = importlib.import_module("direct_sync_health")
    app = ContainerAudit.__new__(ContainerAudit)
    card = _health_card()
    app.info_cards = {"direct_sync": card}
    app._direct_sync_wake_results = queue.Queue()
    app._direct_sync_wake_error_code = ""
    pending = health_module.RelayHealth(
        "pending", 3, 0, 0, "2026-09-01T01:00:00+00:00", "", ""
    )
    review = health_module.RelayHealth(
        "review", 3, 1, 1, "2026-09-01T01:00:00+00:00", "", ""
    )

    app._apply_direct_sync_health(pending)
    assert card["frame"].options["style"] == "Card.TFrame"
    assert "대기 3" in card["value"].options["text"]

    app._apply_direct_sync_health(review)
    assert card["frame"].options["style"] == "RelayAttention.TFrame"
    assert "저장 상태 확인 필요 · 2건" in card["value"].options["text"]


def test_gui_completion_is_nonblocking_and_checkpoints_on_tk(tmp_path):
    root = HealthPumpRoot()
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = root
    master = (
        "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-COMPLETE|"
        "CLC=AAA2270730100|LBL=LBL-COMPLETE|HSH=0123456789abcdef"
    )
    now = datetime.datetime(2026, 8, 30, 8, 0, 0)
    app.current_tray = TraySession(
        master_label_code=master,
        canonical_input_tag_qr=master,
        active_label_qr_payload=master,
        active_label_id="LBL-COMPLETE",
        active_label_business_date="2026-08-30",
        active_label_worker_code="fixture-worker",
        operation_lease_id="operation-lease-complete",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=["AAA2270730100-PRODUCT-1"],
        scan_times=[now],
        tray_size=1,
        start_time=now - datetime.timedelta(seconds=30),
    )
    app.worker_name = "tester"
    app.log_file_path = str(tmp_path / "events.csv")
    app._scan_callback_epoch = 9
    app._ui_lane = None
    app.COLOR_PRIMARY = "primary"
    app.COLOR_DANGER = "danger"
    app._active_blocking_completion_snapshot = lambda: None
    app._active_completion_event_contract = lambda: None
    app._operator_review_blocks_mutation = lambda: False
    app._phs_label_exchange_blocks_tray_transition = lambda _action: False
    app._transfer_member_exchange_blocks_local_action = lambda _action: False
    app._update_action_button_states = lambda: None
    app.show_status_message = lambda *_args, **_kwargs: None
    app._schedule_focus_return = lambda *_args, **_kwargs: None
    app.transfer_seal_coordinator = SimpleNamespace()
    owner_thread_id = threading.get_ident()
    checkpoint_thread_ids = []
    finish_thread_ids = []
    worker_thread_ids = []
    gate = threading.Event()
    prepared = threading.Event()
    attempt = importlib.import_module("transfer_seal").SealAttempt(
        "intent-complete",
        "ACKED",
        operation_lease_id="operation-lease-complete",
    )

    def save_state():
        checkpoint_thread_ids.append(threading.get_ident())
        return True

    def prepare_snapshot(*, on_prepared, **_kwargs):
        worker_thread_ids.append(threading.get_ident())
        prepared.set()
        on_prepared(attempt)
        assert gate.wait(timeout=2.0)
        return attempt

    def complete_tray(*, _prepared_transfer_attempt=None):
        finish_thread_ids.append(threading.get_ident())
        assert _prepared_transfer_attempt is attempt
        return True

    app._save_current_tray_state = save_state
    app._prepare_and_attempt_transfer_seal_snapshot = prepare_snapshot
    app.complete_tray = complete_tray

    started = time.perf_counter()
    assert app.request_complete_tray() is True
    assert time.perf_counter() - started < 0.1
    assert prepared.wait(timeout=1.0)

    deadline = time.monotonic() + 2.0
    while not checkpoint_thread_ids and time.monotonic() < deadline:
        if root.jobs:
            root.run_next()
        time.sleep(0.005)
    gate.set()
    app._completion_task_handle.join(timeout=2.0)
    deadline = time.monotonic() + 2.0
    while not finish_thread_ids and time.monotonic() < deadline:
        if root.jobs:
            root.run_next()
        time.sleep(0.005)

    try:
        assert checkpoint_thread_ids == [owner_thread_id]
        assert finish_thread_ids == [owner_thread_id]
        assert worker_thread_ids and worker_thread_ids[0] != owner_thread_id
        assert app._completion_lane_busy is False
    finally:
        app._ui_lane.close_idle()


class RedirectResponse:
    status_code = 302
    headers = {"Location": "https://evil.example.invalid/steal?token=raw-secret"}

    def json(self):
        raise AssertionError("redirect body must not be parsed")


class RecordingSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return RedirectResponse()


def test_logistics_auth_redirect_is_blocked_without_second_request_or_secret_leak():
    session = RecordingSession()
    client = LogisticsTransferClient(
        "https://logistics.example.invalid",
        "raw-secret-token",
        "host-01",
        session=session,
    )

    with pytest.raises(TransferSealError) as captured:
        client._request("POST", "/logistics/api/v1/test", payload={"ok": True})

    assert len(session.calls) == 1
    assert session.calls[0][2]["allow_redirects"] is False
    assert captured.value.code == "LOGISTICS_REDIRECT_BLOCKED"
    assert captured.value.retryable is False
    assert captured.value.committed is None
    assert "evil.example" not in str(captured.value)
    assert "raw-secret" not in str(captured.value)
    assert captured.value.details == {}


def test_redirect_failure_is_terminal_operator_review(tmp_path):
    store = TransferSealStore(tmp_path / "transfer-seal.sqlite3")
    prepared = store.prepare(
        master_label="MASTER-1",
        source_identity={"bundle_id": "SOURCE-1"},
        item_id="AAA2270730100",
        operator="tester",
        scanned_barcodes=["AAA2270730100-SERIAL-1"],
    )

    row = store.record_error(
        str(prepared["intent_id"]),
        TransferSealError(
            "LOGISTICS_REDIRECT_BLOCKED",
            "물류 인증 요청의 redirect를 차단했습니다.",
            status_code=302,
            retryable=False,
            committed=None,
        ),
    )

    assert row["status"] == "OPERATOR_REVIEW"
    assert row["last_error_code"] == "LOGISTICS_REDIRECT_BLOCKED"

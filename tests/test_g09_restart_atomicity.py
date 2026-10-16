"""Reopen durable cuts with new app/store objects, never reuse recovery memory."""
import csv
import json
from pathlib import Path
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from Container_Audit import ContainerAudit
from event_log_store import EventLogOutbox
from preflight_scan_hold import PreflightScanHoldStore
import test_phs2_master_preflight as helpers
from tests.operation_lease_fixtures import fixed_operation_lease_clock

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")


class PowerCut(BaseException):
    """Escape normal rollback handlers at an exact durable boundary."""


def _rows(root):
    result = []
    for directory in (root, root / "local_events"):
        for path in directory.glob("*.csv"):
            with path.open(encoding="utf-8-sig", newline="") as stream:
                result.extend(csv.DictReader(stream))
    return result


def _fresh_app(root, monkeypatch):
    gate = threading.Event()
    client = helpers.BlockingClient(helpers._resolved(count=2), gate=gate)
    app = helpers._app(root, client)
    app.local_events_folder = str(root / "local_events")
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    capture = app._log_event

    def log(event, detail=None, **kwargs):
        capture(event, detail, **kwargs)
        if kwargs.get("synchronous"):
            return ContainerAudit._log_event(app, event, detail, **kwargs)
        return True

    app._log_event = log
    # Reopened FIFO rows have their persisted details, not the first app's
    # in-memory checkpoint observation map.
    app._project_stored_audit_event = lambda event, *, stored_worker_record: (
        ContainerAudit._project_stored_audit_event(
            app, event, stored_worker_record=stored_worker_record))
    for method in ("showwarning", "showerror", "showinfo"):
        monkeypatch.setattr("Container_Audit.messagebox." + method, lambda *_a, **_k: None)
    monkeypatch.setattr("Container_Audit.messagebox.askyesno",
                        lambda *_a, **_k: pytest.fail("automatic restart requested PIN/confirmation"))
    return app, client, gate


@pytest.mark.parametrize("outbox_only", (False, True))
@pytest.mark.parametrize("boundary", ("intent_before_move", "move_before_audit", "return_before_audit"))
def test_g09_reopens_exact_durable_boundary(tmp_path, monkeypatch, boundary, outbox_only):
    app, _client = helpers._offline_queue_app(tmp_path, monkeypatch)
    store = app._preflight_hold_store()
    first, second = helpers.ITEM + "-SERIAL-001", helpers.ITEM + "-SERIAL-002"
    for barcode in (first, first, second):
        app._process_barcode_logic(barcode)
    helpers._pump_until(app.root, lambda: len(store.load().items) == 3)
    original = store.path.read_bytes()
    snapshot = store.load()
    fingerprint = store.snapshot_hash(snapshot)
    completed = []

    with monkeypatch.context() as cut:
        # Only scheduling is made synchronous to let BaseException leave the
        # real durable operation without running its rollback/finish callback.
        writer = app._preflight_hold_writer()
        def submit(operation, *_a, **_k):
            operation()
            return SimpleNamespace(accepted=True)
        cut.setattr(writer, "submit", submit)
        if outbox_only:
            cut.setattr(EventLogOutbox, "drain", lambda self, **_kwargs: {})
        native_quarantine = store.quarantine

        def quarantine(*args, **kwargs):
            if boundary == "intent_before_move":
                raise PowerCut()
            held = native_quarantine(*args, **kwargs)
            if boundary == "move_before_audit":
                raise PowerCut()
            return held

        cut.setattr(store, "quarantine", quarantine)
        if boundary != "return_before_audit":
            with pytest.raises(PowerCut):
                app._queue_offline_preflight_hold(snapshot, helpers.OTHER_LABEL)
        else:
            app._queue_offline_preflight_hold(snapshot, helpers.OTHER_LABEL)
            app._preflight_hold_switch_pending = False
            app._finish_preflight_handoff()
            held, = app._quarantined_preflight_holds()
            native_restore = PreflightScanHoldStore.restore_quarantined

            def restore(restore_store, *args, **kwargs):
                native_restore(restore_store, *args, **kwargs)
                raise PowerCut()

            cut.setattr(PreflightScanHoldStore, "restore_quarantined", restore)
            with pytest.raises(PowerCut):
                app._run_durable_ui_steps(app._restore_quarantined_preflight_hold_steps(
                    str(held.path), confirm=False, offline_return=held))

    if outbox_only:
        assert not any(r["event"] == "PHS2_PREFLIGHT_HOLD_OFFLINE_QUEUEING" for r in _rows(tmp_path))
        assert any(json.loads(p.read_text(encoding="utf-8"))["log_entry"]["event"]
                   == "PHS2_PREFLIGHT_HOLD_OFFLINE_QUEUEING"
                   for p in (tmp_path / "_event_outbox").glob("*.json"))

    reopened, client, gate = _fresh_app(tmp_path, monkeypatch)
    reopened_store = reopened._preflight_hold_store()
    assert reopened is not app and reopened_store is not store
    originals = ([reopened_store.path] if reopened_store.exists() else []) + [
        h.path for h in reopened._quarantined_preflight_holds()
        if h.snapshot.preflight_id == snapshot.preflight_id]
    assert len(originals) == 1
    assert originals[0].read_bytes() == original
    # This is the real log-writer startup flush, with a new outbox instance.
    assert reopened._flush_pending_event_logs() is True
    reopened.add_scanned_barcode = lambda barcode, when, interval: (
        reopened.current_tray.scanned_barcodes.append(barcode),
        reopened.current_tray.scan_times.append(when))
    reopened.complete_tray = lambda: completed.append((
        list(reopened.current_tray.scanned_barcodes), reopened_store.exists())) or True
    try:
        assert reopened._restore_preflight_scan_hold() is True
        if boundary == "move_before_audit":
            reopened._process_barcode_logic(helpers.COMPACT_QR)
        helpers._pump_until(reopened.root, client.started.is_set)
        loaded = reopened_store.load()
        assert loaded.items == snapshot.items
        assert loaded.worker == snapshot.worker
    finally:
        gate.set()
    helpers._pump_until(reopened.root, lambda: bool(completed))
    assert completed == [([first, second], False)]
    assert reopened.current_tray.tray_size == 2
    assert reopened.current_tray.scanned_barcodes == [first, second]
    assert not reopened._quarantined_preflight_holds()
    with sqlite3.connect(tmp_path / "transfer-seal.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM transfer_seal_intents").fetchone()[0] == 0
    assert reopened._flush_pending_event_logs() is True
    assert reopened._flush_pending_event_logs() is True
    audited = [(r["event"], json.loads(r["details"])) for r in _rows(tmp_path)]
    matching = [(event, detail) for event, detail in audited
                if detail.get("preflight_id") == snapshot.preflight_id
                and detail.get("snapshot_hash") == fingerprint]
    assert sum(event == "PHS2_PREFLIGHT_HOLD_OFFLINE_QUEUEING" for event, _d in matching) == 1
    expected_restores = 0 if boundary == "intent_before_move" else 1
    assert sum(event == "PHS2_PREFLIGHT_HOLD_RESTORED" for event, _d in matching) == expected_restores
    keys = [(event, detail.get("idempotency_key")) for event, detail in matching]
    assert len(keys) == len(set(keys))
    assert sum(r["event"] == "SCAN_OK" for r in _rows(tmp_path)) == 2
    before_again = _rows(tmp_path)
    again, _client, again_gate = _fresh_app(tmp_path, monkeypatch)
    assert again._restore_preflight_scan_hold() is True
    assert again._flush_pending_event_logs() is True
    again_gate.set()
    assert _rows(tmp_path) == before_again
    assert sum(r["event"] == "PHS2_PREFLIGHT_HOLD_RESTORED" for r in _rows(tmp_path)) == expected_restores

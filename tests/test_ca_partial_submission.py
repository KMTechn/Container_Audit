"""Draft confirmation and immediate, restart-safe shortage release."""
import csv
import json
from pathlib import Path

import pytest

import Container_Audit as ca
import ca_screen_bridge as screen
from tests.test_ca_screen_bridge import _app, _idle, _schema_errors, CONTRACT
from tests.test_w9scanonly_workflow import _active, flow, windows  # noqa: F401
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401

pytestmark = pytest.mark.usefixtures("windows", "fixed_operation_lease_clock")


def prepare(flow):
    app = _app(flow)
    app._load_session_state()
    processor = screen.CaProcessor(app)
    processor.scan(app.current_tray.known_member_barcodes[0], {})
    _idle(app, lambda: len(app.current_tray.scanned_barcodes) == 1)
    return app, processor


def ask(app, processor):
    label = app.current_tray.master_label_code
    processor.scan(label, {})
    _idle(app, lambda: processor.state()["confirm"] is not None)
    return label


def test_confirmation_and_continue_leave_durable_bytes_unchanged(flow):
    app, processor = prepare(flow)
    path = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    before = path.read_bytes()
    ask(app, processor)
    state = processor.state()
    assert state["confirm"] == {"kind": "partial_submit", "total": app.current_tray.tray_size,
                               "done": 1, "short": app.current_tray.tray_size - 1}
    assert not _schema_errors(state, CONTRACT["state"])
    assert path.read_bytes() == before
    assert not list((Path(app.save_folder) / "short_confirmations").glob("*.json"))
    assert processor.command("partial_continue")["ok"]
    assert processor.state()["confirm"] is None
    assert path.read_bytes() == before
    assert not app.current_tray.is_partial_submission


@pytest.mark.parametrize("answer", ["same_label", "enter", "button"])
def test_confirmation_releases_once_immediately_and_cannot_be_submitted_twice(flow, monkeypatch, answer):
    app, processor = prepare(flow)
    store = app.transfer_seal_coordinator.store
    original, released = store.settle_short_confirmation, []
    def release(intent_id, **kwargs):
        released.append(intent_id)
        return original(intent_id, **kwargs)
    monkeypatch.setattr(store, "settle_short_confirmation", release)
    label = ask(app, processor)
    if answer == "button":
        assert processor.command("partial_submit")["ok"]
    else:
        processor.scan(label if answer == "same_label" else "", {})
    _idle(app, lambda: not app.current_tray.master_label_code and getattr(app, '_short_confirmation_undo', None) is None)
    assert len(released) == 1
    records = list((Path(app.save_folder) / "short_confirmations").glob("*.json"))
    assert len(records) == 1
    record = json.loads(records[0].read_bytes())
    assert record["status"] == "SETTLED"
    assert record["intent_id"] == released[0]
    assert processor.state()["confirm"] is None
    assert processor.state()["work"]["result"]["text"].startswith("부분 제출 완료 — 1개(")
    assert not processor.command("partial_submit")["ok"]
    assert len(released) == 1
    assert app._undo_short_confirmation() is False


def test_product_scan_closes_confirmation_and_is_processed_normally(flow):
    app, processor = prepare(flow)
    ask(app, processor)
    raw = app.current_tray.known_member_barcodes[1]
    processor.scan(raw, {})
    _idle(app, lambda: len(app.current_tray.scanned_barcodes) == 2)
    assert processor.state()["confirm"] is None
    assert app.current_tray.scanned_barcodes[-1] == raw
    assert not list((Path(app.save_folder) / "short_confirmations").glob("*.json"))


def test_confirmation_is_absent_after_restoring_the_saved_tray(flow):
    app, processor = prepare(flow)
    ask(app, processor)
    state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_bytes())
    assert "confirm" not in state and "_partial_submit_confirmation" not in state
    app._restore_tray_from_state(state)
    assert processor.state()["confirm"] is None
    assert not app.current_tray.is_partial_submission


@pytest.mark.parametrize("lost_settled_ack", [False, True])
def test_restart_releases_a_saved_decision_once_with_the_same_completion_id(flow, monkeypatch, lost_settled_ack):
    app = _active(flow)
    app._load_session_state()
    app._process_barcode_logic(app.current_tray.known_member_barcodes[0])
    settle = app._settle_short_completion_projection
    monkeypatch.setattr(app, "_settle_short_completion_projection", lambda *_a, **_k: False)
    assert app._complete_current_tray_as_partial()
    path = next((Path(app.save_folder) / "short_confirmations").glob("*.json"))
    decision = json.loads(path.read_bytes())
    assert decision["status"] == "HELD"
    completion_id = decision["contract"]["idempotency_key"]
    store = app.transfer_seal_coordinator.store
    release, released = store.settle_short_confirmation, []
    def counted_release(intent_id, **kwargs):
        released.append(intent_id)
        return release(intent_id, **kwargs)
    monkeypatch.setattr(store, "settle_short_confirmation", counted_release)
    monkeypatch.setattr(app, "_settle_short_completion_projection", settle)
    if lost_settled_ack:
        atomic_write = ca.atomic_write_json
        def lose_settled_write(target, value, **kwargs):
            if Path(target) == path and value.get("status") == "SETTLED":
                raise OSError("simulated interruption after release")
            return atomic_write(target, value, **kwargs)
        monkeypatch.setattr(ca, "atomic_write_json", lose_settled_write)
        with pytest.raises(OSError):
            settle(completion_id)
        monkeypatch.setattr(ca, "atomic_write_json", atomic_write)
    app._short_confirmation_undo = None
    recovered = app._recover_short_completion_projections(app.transfer_seal_coordinator)
    assert "held_confirmation" not in recovered
    app._recover_short_completion_projections(app.transfer_seal_coordinator)
    after = json.loads(path.read_bytes())
    assert after["status"] == "SETTLED"
    assert after["contract"] == decision["contract"]
    assert after["detail"] == decision["detail"]
    assert after["state"] == decision["state"]
    assert released == [decision["intent_id"]]
    with Path(app.log_file_path).open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert sum(row.get("이벤트") == "TRAY_COMPLETE" or row.get("event") == "TRAY_COMPLETE" for row in rows) == 1

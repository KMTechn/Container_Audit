"""Confirmation replaces timed shortage Undo; persisted decisions release now."""
import csv
import datetime
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import Container_Audit as ca
from tests.test_ca_partial_submission import prepare, ask
from tests.test_ca_screen_bridge import _idle
from tests.test_w9scanonly_workflow import _active, flow, windows  # noqa: F401
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401

pytestmark = pytest.mark.usefixtures("windows", "fixed_operation_lease_clock")


def test_waiting_confirmation_has_no_clock_deadline_and_scans_can_still_be_undone(flow, monkeypatch):
    app, processor = prepare(flow)
    ask(app, processor)
    before = processor.state()["confirm"]
    path = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    checkpoint = path.read_bytes()
    original = ca.datetime
    base = datetime.datetime.now()
    class Later(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            value = base + datetime.timedelta(hours=25)
            return value.replace(tzinfo=tz) if tz else value
    monkeypatch.setattr(ca, "datetime", SimpleNamespace(datetime=Later, date=datetime.date,
                                                      timedelta=datetime.timedelta, timezone=datetime.timezone))
    assert app._check_short_confirmation_expiry() is None
    assert processor.state()["confirm"] == before
    assert path.read_bytes() == checkpoint
    monkeypatch.setattr(ca, "datetime", original)
    processor.command("partial_continue")
    app.undo_last_scan()
    _idle(app, lambda: not app.current_tray.scanned_barcodes)
    assert not list((Path(app.save_folder) / "short_confirmations").glob("*.json"))


def test_lost_csv_ack_retries_the_same_decision_without_duplicate_completion(flow, monkeypatch):
    app = _active(flow)
    app._load_session_state()
    app._process_barcode_logic(app.current_tray.known_member_barcodes[0])
    original = app._log_stored_event
    lost = []
    def append_with_lost_ack(event, **kwargs):
        answer = original(event, **kwargs)
        if event == "TRAY_COMPLETE" and not lost:
            lost.append(kwargs["idempotency_key"])
            return False
        return answer
    monkeypatch.setattr(app, "_log_stored_event", append_with_lost_ack)
    assert app._complete_current_tray_as_partial()
    if getattr(app, "_short_confirmation_undo", None):
        assert app._commit_short_confirmation()
    path = next((Path(app.save_folder) / "short_confirmations").glob("*.json"))
    decision = json.loads(path.read_bytes())
    assert decision["status"] == "SETTLED"
    assert lost == [decision["contract"]["idempotency_key"]]
    with Path(app.log_file_path).open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert sum(row.get("이벤트") == "TRAY_COMPLETE" or row.get("event") == "TRAY_COMPLETE" for row in rows) == 1


def test_empty_tray_cannot_open_partial_submission(flow):
    app = _active(flow)
    assert not app._request_partial_submission()
    assert app._partial_submission_state() is None
    assert not list((Path(app.save_folder) / "short_confirmations").glob("*.json"))

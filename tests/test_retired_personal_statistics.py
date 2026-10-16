import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from Container_Audit import ContainerAudit, TraySession
from ca_screen_bridge import CaProcessor, today_values
from event_payloads import build_tray_complete_detail
from session_history import load_session_history
from tests.test_ca_screen_bridge import CONTRACT, _app, _idle, _schema_errors
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401
from tests.test_w9scanonly_workflow import flow  # noqa: F401
from tray_state import tray_session_from_state, tray_session_to_state, validate_tray_state

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock")


def _idle_tray_app(flow):
    app = _app(flow)
    member = app.current_tray.known_member_barcodes[0]
    CaProcessor(app).scan(member, {"source": "scanner"})
    _idle(app, lambda: len(app.current_tray.scanned_barcodes) == 1)
    app.log_queue.join()
    app._stop_stopwatch()
    app._stop_idle_checker()
    app.info_cards = {}
    app.idle_check_job = None
    app.stopwatch_job = None
    app.current_tray.stopwatch_seconds = 321.0
    app.current_tray.total_idle_seconds = 45.0
    app.is_idle = True
    app.last_activity_time = datetime.now() - timedelta(minutes=4)
    return app


def test_actual_idle_snapshot_stays_neutral_in_current_and_parked_files(flow, tmp_path):
    app = _idle_tray_app(flow)
    tray = app.current_tray
    assert app._save_current_tray_state()
    current_bytes = (Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_bytes()
    current = json.loads(current_bytes)
    assert current["total_idle_seconds"] == current["stopwatch_seconds"] == 0.0
    business_keys = (
        "master_label_code", "item_code", "tray_size", "scanned_barcodes",
        "scan_times", "start_time", "operation_lease_id", "operation_lease_hold",
    )
    expected = tray_session_to_state(tray, worker_name=app._record_worker_name())
    assert {key: current.get(key) for key in business_keys} == {
        key: expected.get(key) for key in business_keys
    }

    legacy = dict(current, total_idle_seconds=45.0, stopwatch_seconds=321.0)
    legacy_path = tmp_path / "legacy-tray.json"
    legacy_bytes = json.dumps(legacy).encode("utf-8")
    legacy_path.write_bytes(legacy_bytes)
    loaded = json.loads(legacy_path.read_bytes())
    validate_tray_state(loaded, default_tray_size=tray.tray_size)
    restored = tray_session_from_state(
        loaded, session_factory=TraySession, default_tray_size=tray.tray_size,
    )
    assert restored.total_idle_seconds == 45.0
    assert restored.stopwatch_seconds == 321.0
    assert restored.scan_times == tray.scan_times

    assert app.park_current_tray(confirm=False)
    parked_bytes = Path(app._parked_tray_undo["path"]).read_bytes()
    parked = json.loads(parked_bytes)
    assert parked["total_idle_seconds"] == parked["stopwatch_seconds"] == 0.0
    assert {key: parked.get(key) for key in business_keys} == {
        key: current.get(key) for key in business_keys
    }
    assert not (Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).exists()
    assert legacy_path.read_bytes() == legacy_bytes


def test_actual_wakeup_outbox_and_csv_keep_event_without_personal_duration(flow, tmp_path, monkeypatch):
    app = _idle_tray_app(flow)
    app.local_events_folder = str(tmp_path / "local-events")
    store = app._event_log_outbox(app.log_file_path)
    original_stage = store.stage
    staged_bytes = []

    def stage(log_file_path, log_entry, **kwargs):
        path = original_stage(log_file_path, log_entry, **kwargs)
        if log_entry["event"] == "IDLE_END":
            assert path is not None
            staged_bytes.append(path.read_bytes())
        return path

    monkeypatch.setattr(store, "stage", stage)
    scan_times = list(app.current_tray.scan_times)
    for operation in app._wakeup_steps(activity_time=datetime.now()):
        assert operation() is not False
    app.log_queue.join()

    assert len(staged_bytes) == 1
    outbox = json.loads(staged_bytes[0])
    event = outbox["log_entry"]
    assert event["event"] == "IDLE_END"
    details = json.loads(event["details"])
    assert not {"duration_sec", "total_idle_seconds", "work_time_sec"} & details.keys()
    assert details["direct_sync_eligible"] is False
    with Path(outbox["log_file_path"]).open(encoding="utf-8-sig", newline="") as stream:
        rows = [row for row in csv.DictReader(stream) if row["event"] == "IDLE_END"]
    assert len(rows) == 1
    assert rows[0] == event
    assert app.is_idle is False
    assert app.current_tray.total_idle_seconds == 45.0
    assert app.current_tray.scan_times == scan_times
    checkpoint = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_bytes())
    assert checkpoint["total_idle_seconds"] == checkpoint["stopwatch_seconds"] == 0.0


def _timed_tray():
    fields = {"PHS": "2", "SRC": "KMTECH_INPUT_TAG", "ITG": "tag-placeholder",
              "CLC": "item-placeholder", "LBL": "label-placeholder", "HSH": "a" * 16, "QT": "2"}
    now = datetime.now().replace(microsecond=0)
    tray = TraySession(
        master_label_code="|".join(f"{key}={value}" for key, value in fields.items()),
        item_code=fields["CLC"], item_name="<item>", item_spec="<spec>", tray_size=2,
        scanned_barcodes=["<product one>", "<product two>"],
        scan_times=[now - timedelta(seconds=1), now], start_time=now - timedelta(minutes=5),
        stopwatch_seconds=300.0, total_idle_seconds=20.0,
    )
    return tray, fields, now


def test_completion_and_checkpoint_preserve_business_evidence_without_timing_metrics():
    tray, fields, now = _timed_tray()
    detail = build_tray_complete_detail(tray, master_label_fields=fields, end_time=now)
    assert "work_time_sec" not in detail
    assert "total_idle_seconds" not in detail
    assert detail["scan_count"] == 2
    assert detail["product_barcodes"] == tray.scanned_barcodes
    assert detail["end_time"] == now.isoformat()
    checkpoint = tray_session_to_state(tray, worker_name="<worker>")
    assert checkpoint["stopwatch_seconds"] == 0.0
    assert checkpoint["total_idle_seconds"] == 0.0
    assert checkpoint["start_time"] == tray.start_time.isoformat()
    assert checkpoint["scan_times"] == [value.isoformat() for value in tray.scan_times]
    assert checkpoint["scanned_barcodes"] == tray.scanned_barcodes


def test_retired_record_hooks_leave_existing_file_unchanged(tmp_path):
    path = tmp_path / "best_time_records.json"
    original = b'{"historical-date-placeholder": 300.0}\n'
    path.write_bytes(original)
    app = SimpleNamespace(storage_paths=SimpleNamespace(best_time_records_path=path))
    ContainerAudit._load_best_time_records(app)
    ContainerAudit._update_best_time_records(app, 200.0)
    ContainerAudit._save_best_time_records(app)
    assert app.best_time_records == {}
    assert not hasattr(app, "best_time_store")
    assert path.read_bytes() == original


def test_history_retains_business_counts_without_rebuilding_personal_average(tmp_path):
    tray, fields, now = _timed_tray()
    detail = build_tray_complete_detail(tray, master_label_fields=fields, end_time=now)
    detail["work_time_sec"] = 300.0  # Historical logs remain readable and untouched.
    path = tmp_path / f"이적작업이벤트로그_worker_{now:%Y%m%d}.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["timestamp", "event", "worker_name", "details"])
        writer.writeheader()
        writer.writerow({"timestamp": now.isoformat(), "event": "TRAY_COMPLETE", "worker_name": "worker",
                         "details": json.dumps(detail)})
    original = path.read_bytes()
    history = load_session_history(save_folder=tmp_path, worker_name="worker", today=now.date(), tray_size=2)
    assert history.total_tray_count == 1
    assert history.work_summary[tray.item_code]["products"] == 2
    assert history.completed_tray_times == []
    assert path.read_bytes() == original


def test_held_pane_omits_personal_statistics(flow):
    app = _app(flow)
    app.completed_tray_times = [300.0]
    app.best_time_records = {"historical-date-placeholder": 200.0}
    values = CaProcessor(app)._held_values()
    assert "stats" not in values
    assert "today" in values
    assert "park" in values


def test_screen_state_omits_all_three_personal_rows_and_preserves_business_fields(flow):
    app = _app(flow)
    app.total_tray_count = 2
    app.work_summary = {"A": {"name": "시험 품목", "count": 2, "products": 6,
                              "shipping_supplement_intents": {"pending-placeholder"}}}
    app._shipping_confirmed_intents = set()
    app.completed_tray_times = [300.0]
    app.best_time_records = {"historical-date-placeholder": 200.0}
    processor = CaProcessor(app)
    work = processor.state()["work"]
    assert processor.command("open", {"id": "held"}) == {"ok": True}
    state = processor.state()
    assert "stats" not in state
    assert state["today"] == today_values(app)
    assert state["today"] == {"total_trays": 2, "rows": [{"item": "시험 품목", "trays": 2, "products": 6}], "supply": 1}
    assert state["work"] == work
    assert state["park"] == [] and state["held_count"] == 0 and state["overflow"] is False
    assert _schema_errors(state, CONTRACT["state"]) == []

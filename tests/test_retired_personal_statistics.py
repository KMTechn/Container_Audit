import csv
import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from Container_Audit import ContainerAudit, TraySession
from ca_screen_bridge import CaProcessor
from event_payloads import build_tray_complete_detail
from session_history import load_session_history
from tests.test_ca_screen_bridge import _app
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401
from tests.test_w9scanonly_workflow import flow  # noqa: F401
from tray_state import tray_session_to_state

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock")


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

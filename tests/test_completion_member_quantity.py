"""Printed PHS2 QT survives completion at the current member target (DESIGN R4)."""
import csv
import datetime
import json

import pytest

from Container_Audit import TraySession
from event_payloads import build_tray_complete_detail
from label_qr import parse_new_format_qr
from session_history import load_session_history

ITEM = "AAA2270730100"
QR = f"PHS=2|SRC=KMTECH_INPUT_TAG|ITG=member-quantity|CLC={ITEM}|LBL=label-quantity|HSH=2222222222222222"
NOW = datetime.datetime(2026, 10, 3, 9)


def _complete(label):
    tray = TraySession(master_label_code=label, item_code=ITEM, item_name="fixture item",
                       item_spec="fixture spec", scanned_barcodes=[ITEM+"-001", ITEM+"-002"],
                       tray_size=2, start_time=NOW, stopwatch_seconds=30)
    return build_tray_complete_detail(tray, master_label_fields=parse_new_format_qr(label), end_time=NOW)


@pytest.mark.parametrize("quantity", [None, 2, 3])
def test_completion_preserves_printed_quantity_at_current_member_target(quantity):
    label = QR + (f"|QT={quantity}" if quantity is not None else "")
    detail = _complete(label)
    assert detail["master_label_code"] == label
    assert detail["master_label_fields"] == parse_new_format_qr(label)
    assert detail["tray_capacity"] == detail["scan_count"] == detail["barcode_count"] == 2
    assert detail["product_barcodes"] == [ITEM+"-001", ITEM+"-002"]


@pytest.mark.parametrize("quantity,phase,accepted", [(None, "2", True), (2, "2", True),
                                                  (3, "2", True), (1, "2", False),
                                                  (3, "1", False)])
def test_history_counts_actual_members_without_replacing_printed_quantity(tmp_path, quantity, phase, accepted):
    # Use an independently assembled durable row so the reader regression is
    # detected even if the completion builder regresses first.
    label = QR.replace("PHS=2", f"PHS={phase}") + (f"|QT={quantity}" if quantity is not None else "")
    detail = {"master_label_code": label, "master_label_fields": parse_new_format_qr(label),
              "item_code": ITEM, "tray_capacity": 2, "scan_count": 2, "barcode_count": 2,
              "product_barcodes": [ITEM+"-001", ITEM+"-002"], "work_time_sec": 30,
              "start_time": NOW.isoformat(), "end_time": NOW.isoformat()}
    path = tmp_path / "이적작업이벤트로그_worker_20261003.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["timestamp", "worker_name", "event", "details"])
        writer.writerow([NOW.isoformat(), "worker", "TRAY_COMPLETE", json.dumps(detail)])
    original = path.read_bytes()
    history = load_session_history(save_folder=tmp_path, worker_name="worker", today=NOW.date(), tray_size=60)
    if not accepted:
        assert len(history.load_errors) == 1
        assert history.total_tray_count == 0
        assert path.read_bytes() == original
        return
    assert history.load_errors == []
    assert history.total_tray_count == history.work_summary[ITEM]["count"] == 1
    assert path.read_bytes() == original


@pytest.mark.parametrize("label", [QR+"|QT=1", f"PHS=1|CLC={ITEM}|QT=3"])
def test_completion_keeps_undersized_print_and_legacy_equality_guard(label):
    with pytest.raises(ValueError, match="QT"):
        _complete(label)

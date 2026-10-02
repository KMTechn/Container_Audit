"""Roster names cannot redirect old history or reach filenames/CSV unsafely."""
import datetime
import json
from pathlib import Path

import pytest

from event_log_store import append_event_log_entry_idempotent
from session_history import _sanitize_worker_name, load_session_history
from tests.test_phs2_master_preflight import COMPACT_QR, ITEM
from tests.test_remembered_worker_start import _login
from tests.test_worker_roster import flow, windows, row, store
from worker_registry import WorkerRegistry


@pytest.mark.parametrize("bad", [
    "x" * 65, "김" * 65, *["a" + char + "b" for char in '\\/:*?"<>|'],
    "=1+1", "+1+1", "-1+1", "@SUM(1)", "", "  ",
    "a\x00b", "a\u0085b", "a\u200bb", "a\ud800b", "a\u2028b", "a\u2029b",
])
def test_unsafe_roster_row_is_excluded_without_losing_other_workers(tmp_path, bad):
    good = row(" Nguyễn Văn An ")
    roster = store(tmp_path, good, row(bad))
    expected = dict(good, display_name="Nguyễn Văn An")
    assert roster.active_workers() == [expected]
    assert roster.snapshot["source_row_count"] == 2
    assert type(roster)(roster.path, "site-1").active_workers() == [expected]


@pytest.mark.parametrize("name", ["김", "홍길", "Nguyễn Văn An", "a b", "x" * 64, "김" * 64, "😀" * 64])
def test_contract_names_have_no_minimum_length_or_alphabet_limit(tmp_path, name):
    roster = store(tmp_path, row(name))
    assert [entry["display_name"] for entry in roster.active_workers()] == [name]
    registry = WorkerRegistry(str(tmp_path / "workers.json"))
    assert registry.register(name) == name
    assert registry.list_workers() == [name]


@pytest.mark.parametrize("name", ["김" * 65, "김" * 128, "a\u200bb", "a\u2028b", "a\u2029b", "a\u0085b"])
def test_existing_local_names_keep_baseline_fallback_selection(flow, windows, tmp_path, name):
    path = tmp_path / "workers.json"
    path.write_text(json.dumps({"workers": [{"name": name, "active": True,
        "last_used_at": "2026-10-03T01:00:00"}]}, ensure_ascii=False), encoding="utf-8")
    registry = WorkerRegistry(str(path))
    assert registry.list_workers() == [name]
    assert registry.recent_worker() == name
    app = flow(transition=False)
    _login(app, registry, tmp_path)
    app.worker_roster = store(tmp_path)
    assert app._worker_selection_names() == [name]
    assert app._ensure_worker_login_name(name) == name
    registry.mark_recent(name)
    assert registry.recent_worker() == name
    assert windows == []
    with pytest.raises(ValueError):
        WorkerRegistry(str(tmp_path / "new.json")).register(name)


def _write_completion(root, name, suffix):
    details = {
        "master_label_code": COMPACT_QR.replace("LBL=LBL-", "LBL=" + suffix + "-"),
        "item_code": ITEM, "item_name": "name-safety", "spec": "LHD",
        "tray_capacity": 2, "scan_count": 2, "barcode_count": 2,
        "has_error_or_reset": False, "is_partial_submission": False,
        "is_restored_session": False, "is_test_tray": False,
        "start_time": "2026-10-03T01:00:00", "end_time": "2026-10-03T01:00:20",
        "idempotency_key": "name-safety-" + suffix,
    }
    path = root / f"이적작업이벤트로그_{_sanitize_worker_name(name)}_20261003.csv"
    assert append_event_log_entry_idempotent(str(path), {
        "timestamp": "2026-10-03T01:00:20", "worker_name": name,
        "event": "TRAY_COMPLETE", "details": json.dumps(details, ensure_ascii=False),
    }, idempotency_key=details["idempotency_key"], event_type="TRAY_COMPLETE")
    return path


@pytest.mark.parametrize("name", ["김", "홍길", "Nguyễn Văn An", "a b", "name.", "..", *["김" * length for length in range(120, 129)]])
def test_existing_completion_filename_and_daily_count_are_preserved(tmp_path, name):
    assert _sanitize_worker_name(name) == name
    path = _write_completion(tmp_path, name, "old")
    original = path.read_bytes()
    history = load_session_history(save_folder=tmp_path, worker_name=name,
        today=datetime.date(2026, 10, 3), tray_size=2)
    assert history.total_tray_count == 1
    assert path.read_bytes() == original


def test_distinct_valid_roster_names_keep_separate_history_and_counts(tmp_path):
    names = ("ab", "a b")
    roster = store(tmp_path, *(row(name) for name in names))
    assert len(roster.active_workers()) == 2
    paths = [_write_completion(tmp_path, name, str(index)) for index, name in enumerate(names)]
    assert paths[0] != paths[1]
    for path, name in zip(paths, names):
        history = load_session_history(save_folder=tmp_path, worker_name=name,
            today=datetime.date(2026, 10, 3), tray_size=2)
        assert history.total_tray_count == 1
        assert name in path.read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("name", ["=1+1", "+1+1", "-1+1", "@SUM(1)", "a/b"])
def test_unsafe_roster_name_cannot_be_selected_or_write_events(flow, windows, tmp_path, name):
    registry = WorkerRegistry(str(tmp_path / "workers.json"))
    registry.register("safe")
    app = flow(transition=False)
    _login(app, registry, tmp_path)
    app.worker_roster = store(tmp_path, row(name), row("safe"))
    assert app._worker_selection_names() == ["safe"]
    assert app._ensure_worker_login_name(name) is None
    assert app._ensure_worker_login_name("safe") == "safe"
    assert not list(Path(app.save_folder).glob("*.csv"))
    assert windows == []

"""Late central results must respect the durable tray and its exchange epoch."""
import datetime
import json
import threading
import time
from types import SimpleNamespace

import pytest

import Container_Audit as ca
from label_qr import canonical_master_label_key, parse_new_format_qr
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401
from tests.test_legacy_label_transition import flow  # noqa: F401
from tests.test_w9scanonly_workflow import _active
from tests.test_phs2_master_preflight import ITEM, _pump_until
from tests.test_legacy_label_transition import _rows
from transfer_seal import validate_compact_phs2_preflight

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")


def _pending_result(app):
    tasks = []
    app._scanonly_transport_lane = lambda: SimpleNamespace(
        is_busy=lambda: False,
        submit=lambda task: tasks.append(task) or SimpleNamespace(accepted=True),
    )
    tray = app.current_tray
    coordinator = app.transfer_seal_coordinator
    artifact = coordinator.operation_lease_manager.store.artifact(tray.operation_lease_id)
    fields = parse_new_format_qr(tray.master_label_code)
    preflight = validate_compact_phs2_preflight(fields, artifact["operation_snapshot"])
    lookup = (tray.master_label_code, fields, tray.start_time)
    assert app._schedule_scanonly_transport(lookup=lookup)
    return tasks[-1], {"preflight": (artifact, preflight), "pending": 0, "reviews": 0}, artifact


def test_late_prefetch_after_exchange_is_durably_queued_for_release(flow):
    app = _active(flow, count=3)
    task, result, artifact = _pending_result(app)
    app.current_tray.exchange_idempotency_keys = ["container-member-exchange:durable-fixture"]
    app.current_tray.operation_lease_id = ""
    app.current_tray.known_member_barcodes = []
    assert app._save_current_tray_state()

    task.finish(result)

    manager = app.transfer_seal_coordinator.operation_lease_manager
    assert artifact["lease_id"] in manager.store.pending_releases()
    assert not app.current_tray.operation_lease_id
    assert canonical_master_label_key(app.current_tray.master_label_code) not in app._scanonly_known_members


@pytest.mark.parametrize("change_round", [False, True])
def test_failed_atomic_target_save_retries_without_worker_action(flow, monkeypatch, change_round):
    app = _active(flow, count=3)
    task, result, artifact = _pending_result(app)
    tray = app.current_tray
    tray.tray_size = 5
    tray.known_member_barcodes = []
    tray.scanned_barcodes = list(result["preflight"][1].normalized_barcodes)
    assert app._save_current_tray_state()
    original = ca.atomic_write_json
    failures = []
    completion = []
    app.request_complete_tray = lambda: completion.append(app._current_tray_state_snapshot())

    def one_failure(path, state, *args, **kwargs):
        if state.get("tray_size") == 3 and not failures:
            failures.append(True)
            raise OSError("synthetic checkpoint failure")
        return original(path, state, *args, **kwargs)

    monkeypatch.setattr(ca, "atomic_write_json", one_failure)
    task.finish(result)
    assert len(failures) == 1
    assert tray.tray_size == 5 and not tray.known_member_barcodes
    assert not completion
    if change_round:
        tray.start_time += datetime.timedelta(seconds=1)
    for _ in range(12):
        if not app.root.jobs:
            break
        app.root.run_next()
        if completion:
            break
    if change_round:
        assert tray.tray_size == 5 and not completion
        manager = app.transfer_seal_coordinator.operation_lease_manager
        assert artifact["lease_id"] in manager.store.pending_releases()
    else:
        assert tray.tray_size == 3
        assert len(tray.known_member_barcodes) == 3
        assert completion and completion[0]["tray_size"] == 3


def test_central_review_keeps_worker_status_unchanged(flow):
    app = _active(flow, count=3)
    task, result, _ = _pending_result(app)
    before = list(app.statuses)
    result.update(preflight=None, reviews=1)
    task.finish(result)
    assert app._scanonly_review_count == 1
    assert app.statuses == before


def test_lookup_survives_the_central_lane_idle_barrier(flow, monkeypatch):
    app = _active(flow, count=3)
    tray = app.current_tray
    lookup = (tray.master_label_code, parse_new_format_qr(tray.master_label_code), tray.start_time)
    lane = app._scanonly_transport_lane()
    lane._idle_barrier = True
    try:
        assert not app._schedule_scanonly_transport(lookup=lookup)
    finally:
        lane._idle_barrier = False
    assert app._scanonly_lookup_jobs == [lookup]
    submitted = []
    monkeypatch.setattr(lane, "submit", lambda task: submitted.append(task)
                        or SimpleNamespace(accepted=True))
    _pump_until(app.root, lambda: bool(submitted))
    assert not app._scanonly_lookup_jobs


@pytest.mark.parametrize("projection_fails_once", [False, True])
def test_exchange_acceptance_does_not_wait_for_csv_projection(flow, monkeypatch, projection_fails_once):
    app = _active(flow, count=3)
    old, replacement = ITEM + "-SERIAL-001", ITEM + "-SERIAL-999"
    app._process_barcode_logic(old)
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    store = app._event_log_outbox(app.log_file_path)
    original_drain = store.drain
    csv_started, release_csv = threading.Event(), threading.Event()
    failures = []

    def delayed_projection(*args, **kwargs):
        if any(json.loads(path.read_text(encoding="utf-8"))["log_entry"]["event"]
               == "PRODUCT_EXCHANGE_COMPLETED" for path in store.directory.glob("*.json")):
            csv_started.set()
            assert release_csv.wait(10), "test did not release its CSV projection"
            if projection_fails_once and not failures:
                failures.append(True)
                raise OSError("synthetic CSV projection failure")
        return original_drain(*args, **kwargs)

    monkeypatch.setattr(store, "drain", delayed_projection)
    app._process_barcode_logic("KMCMD:EXCHANGE")
    app._process_barcode_logic(old)
    app._process_barcode_logic(replacement)
    try:
        _pump_until(app.root, csv_started.is_set)
        deadline = time.monotonic() + 2
        while app._ui_task_lane().is_busy() and time.monotonic() < deadline:
            if app.root.jobs:
                app.root.run_next()
            time.sleep(.005)
        assert not app._ui_task_lane().is_busy(), "durable exchange waited for CSV projection"
        assert app.current_tray.scanned_barcodes == [replacement]
        assert any(json.loads(path.read_text(encoding="utf-8"))["log_entry"]["event"]
                   == "PRODUCT_EXCHANGE_COMPLETED" for path in store.directory.glob("*.json"))
    finally:
        release_csv.set()
        _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    deadline = time.monotonic() + 4
    while not app.syncs.count("PRODUCT_EXCHANGE_COMPLETED") and time.monotonic() < deadline:
        time.sleep(.01)
    assert len(_rows(app, "PRODUCT_EXCHANGE_COMPLETED")) == 1
    assert app.syncs.count("PRODUCT_EXCHANGE_COMPLETED") == 1
    assert len(failures) == int(projection_fails_once)

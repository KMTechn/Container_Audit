"""A failed checkpoint stays UNKNOWN while independently saved work continues."""
import datetime
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import storage_utils
from tests.test_legacy_label_transition import OLD_QR
from tests.test_remembered_worker_start import _login, _registry
from tests.test_scanonly_review_regressions import public_scan
from tests.test_w9scanonly_workflow import (
    _active, fixed_operation_lease_clock, flow, windows, ITEM, COMPACT_QR,
)
from writer_session_fence import writer_admission

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")


def _fail_current(app, monkeypatch):
    original = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    prepare = ca.ContainerAudit._prepare_tray_state_snapshot

    def fail(self, path, state):
        if Path(path) == original:
            raise PermissionError("checkpoint unavailable")
        return prepare(self, path, state)

    monkeypatch.setattr(ca.ContainerAudit, "_prepare_tray_state_snapshot", fail)
    return original


def test_item_write_failure_keeps_original_and_unknown_then_allows_next_tray(flow, windows, monkeypatch):
    app = _active(flow)
    public_scan(app, ITEM + "-SERIAL-001")
    original = _fail_current(app, monkeypatch)
    before = original.read_bytes()
    before_count = list(app.current_tray.scanned_barcodes)
    public_scan(app, ITEM + "-SERIAL-002")
    assert app.current_tray.scanned_barcodes == before_count
    assert not app.seal_calls
    record, = app._storage_failures().records()
    assert record["outcome"] == "UNKNOWN"
    assert record["snapshot"]["scanned_barcodes"][-1] == ITEM + "-SERIAL-002"
    assert original.read_bytes() == before
    assert app._scan_entry_admission_block_reason()
    assert not app._transfer_transport_guard(COMPACT_QR)()

    app.reset_current_work()
    assert not app.current_tray.master_label_code
    assert not app._scan_entry_admission_block_reason()
    assert app._preflight_context_blocks_mutation(COMPACT_QR)
    assert original.read_bytes() == before
    app.legacy_label_transition = True
    public_scan(app, OLD_QR)
    assert app.current_tray.master_label_code == OLD_QR
    public_scan(app, ITEM + "-SERIAL-003")
    assert app.current_tray.scanned_barcodes == [ITEM + "-SERIAL-003"]
    assert (Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).is_file()
    assert original.read_bytes() == before
    assert app._storage_failures().records() == [record]


def test_transient_checkpoint_error_retries_without_quarantining(flow, windows, monkeypatch):
    app = _active(flow)
    prepare = ca.ContainerAudit._prepare_tray_state_snapshot
    attempts = []

    def transient(self, path, state):
        attempts.append(path)
        if len(attempts) == 1:
            raise OSError("transient checkpoint error")
        return prepare(self, path, state)

    monkeypatch.setattr(ca.ContainerAudit, "_prepare_tray_state_snapshot", transient)
    public_scan(app, ITEM + "-SERIAL-001")
    assert len(attempts) == 2
    assert app.current_tray.scanned_barcodes == [ITEM + "-SERIAL-001"]
    assert not app._storage_failures().records()
    assert not app._scan_entry_admission_block_reason()


def test_admitted_checkpoint_retries_transient_write_without_quarantining(flow, windows, monkeypatch):
    app = _active(flow)
    original = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    write = ca.atomic_write_json
    attempts = []

    def transient(path, *args, **kwargs):
        if Path(path) == original:
            attempts.append(path)
            if len(attempts) == 1:
                raise OSError("transient admitted checkpoint error")
        return write(path, *args, **kwargs)

    monkeypatch.setattr(ca, "atomic_write_json", transient)
    with writer_admission("gui_tray_state_save"):
        public_scan(app, ITEM + "-SERIAL-001")
    assert len(attempts) == 2
    assert app.current_tray.scanned_barcodes == [ITEM + "-SERIAL-001"]
    assert not app._storage_failures().records()


def test_quarantined_checkpoint_keeps_its_lease_after_detaching_tray(flow, windows, monkeypatch):
    app = _active(flow)
    app.current_tray.operation_lease_id = Path(app.save_folder).name
    lease_id = app.current_tray.operation_lease_id
    original = _fail_current(app, monkeypatch)
    public_scan(app, ITEM + "T45")
    record, = app._storage_failures().records()
    assert record["snapshot"]["operation_lease_id"] == lease_id
    monkeypatch.setattr(app, "_request_operation_lease_release", lambda *a, **kw: None)
    app.reset_current_work()
    assert not app.current_tray.master_label_code
    coordinator = SimpleNamespace(
        operation_lease_manager=SimpleNamespace(store=SimpleNamespace(
            issue_attempt_for_lease=lambda _: {"status": "PREFETCHED"},
            completion=lambda _: None,
        )),
        store=SimpleNamespace(operation_lease_referenced=lambda _: False),
    )
    assert not app._work_operation_lease_release_allowed(coordinator, lease_id, "")
    assert original.is_file()


@pytest.mark.parametrize("failure", ["data_root", "record", "probe_readback", "probe_fsync"])
def test_root_or_quarantine_failure_stops_without_releasing_tray(flow, windows, monkeypatch, failure):
    app = _active(flow)
    public_scan(app, ITEM + "-SERIAL-001")
    original = _fail_current(app, monkeypatch)
    before = original.read_bytes()
    root = Path(app.save_folder)
    write = storage_utils.atomic_write_json
    open_file = Path.open
    read = Path.read_bytes

    def fail_write(path, *args, **kwargs):
        if Path(path).parent.name == "_storage_failures":
            raise OSError("quarantine unavailable")
        return write(path, *args, **kwargs)

    def fail_open(path, mode="r", *args, **kwargs):
        if failure == "data_root" and Path(path).is_relative_to(root) and any(c in mode for c in "wax+"):
            raise OSError("data root unavailable")
        return open_file(path, mode, *args, **kwargs)

    def fail_read(path):
        if path.name.startswith(".storage-check-"):
            return b"different bytes"
        return read(path)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", fail_open)
        if failure == "record":
            patch.setattr(storage_utils, "atomic_write_json", fail_write)
        elif failure == "probe_readback":
            patch.setattr(Path, "read_bytes", fail_read)
        elif failure == "probe_fsync":
            patch.setattr(storage_utils.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("flush unavailable")))
        public_scan(app, ITEM + "-SERIAL-002")
    assert original.read_bytes() == before
    assert app.current_tray.scanned_barcodes == [ITEM + "-SERIAL-001"]
    assert "이 PC 에 저장할 수 없습니다" in app._scan_entry_admission_block_reason()
    app.reset_current_work()
    assert app.current_tray.master_label_code == COMPACT_QR
    assert not app._storage_failures().records()
    assert not app.seal_calls


def test_three_distinct_items_continue_fourth_stops_and_repeat_counts_once(tmp_path, monkeypatch):
    store = storage_utils.StorageFailureQuarantine(tmp_path)
    clock = [datetime.datetime(2026, 10, 12, 23, 55).timestamp()]
    monkeypatch.setattr(storage_utils.time, "time", lambda: clock[0])
    first = None
    for index in range(3):
        path = tmp_path / f"session-{index}.json"
        path.write_bytes(b"original")
        state = {"session_id": str(index)}
        record = store.hold(path, state, "session", "OSError")
        assert record["outcome"] == "UNKNOWN"
        assert path.read_bytes() == b"original"
        if first is None:
            first = record
        assert store.hold(path, state, "session", "OSError") == record
        clock[0] += 30
    assert len(store.records()) == 3
    fourth = tmp_path / "session-fourth.json"
    fourth.write_bytes(b"fourth original")
    with pytest.raises(OSError):
        store.hold(fourth, {"session_id": "fourth"}, "session", "OSError")
    assert fourth.read_bytes() == b"fourth original"
    assert len(store.records()) == 3
    clock[0] += 11 * 60
    assert store.hold(tmp_path / first["source_file"], {"session_id": "0"}, "session", "OSError") == first
    assert store.hold(fourth, {"session_id": "fourth"}, "session", "OSError")["outcome"] == "UNKNOWN"
    assert len(store.records()) == 4


def test_occupied_replacement_is_preserved_and_cannot_become_the_next_checkpoint(tmp_path):
    store = storage_utils.StorageFailureQuarantine(tmp_path)
    source = tmp_path / "current.json"
    source.write_bytes(b"original")
    replacement = tmp_path / "current_sf_1.json"
    replacement.write_bytes(b"unrelated")
    with pytest.raises(OSError):
        store.hold(source, {}, "tray", "PermissionError")
    assert source.read_bytes() == b"original"
    assert replacement.read_bytes() == b"unrelated"
    assert not store.records()


def test_unidentified_tray_failures_use_distinct_source_slots(tmp_path):
    store = storage_utils.StorageFailureQuarantine(tmp_path)
    first = store.hold(tmp_path / "first.json", {}, "tray", "PermissionError")
    second = store.hold(tmp_path / "second.json", {}, "tray", "PermissionError")
    assert first["item_id"] != second["item_id"]
    assert len(store.records()) == 2


def test_session_write_failure_retains_event_and_starts_new_durable_session(flow, windows, tmp_path, monkeypatch):
    root = tmp_path / "session"
    root.mkdir()
    app = flow(transition=False, root=root)
    registry = _registry(root / "registry.json")
    _login(app, registry, root)
    app.worker_name = registry.list_workers()[0]
    app.worker_role = "WORKER"
    assert app._begin_or_resume_work_session()
    original = app._work_session_state_path()
    before = original.read_bytes()
    old_session = app._work_session_id
    write = ca.atomic_write_json

    def fail(path, *args, **kwargs):
        if Path(path) == original:
            raise PermissionError("session checkpoint unavailable")
        return write(path, *args, **kwargs)

    monkeypatch.setattr(ca, "atomic_write_json", fail)
    assert not app._end_work_session(reason="app_close")
    assert original.read_bytes() == before
    record, = app._storage_failures().records()
    assert record["outcome"] == "UNKNOWN"
    assert record["snapshot"]["phase"] == ca.WORK_SESSION_PHASE_END_PENDING
    assert app._begin_or_resume_work_session()
    assert app._work_session_id != old_session
    assert app._work_session_state_path() != original
    assert json.loads(app._work_session_state_path().read_text(encoding="utf-8"))["phase"] == ca.WORK_SESSION_PHASE_ACTIVE
    assert original.read_bytes() == before
    assert app._storage_failures().records() == [record]


def test_next_day_keeps_unknown_item_and_uses_new_checkpoint_slot(flow, windows, monkeypatch):
    app = _active(flow)
    public_scan(app, ITEM + "-SERIAL-001")
    original = _fail_current(app, monkeypatch)
    before = original.read_bytes()
    public_scan(app, ITEM + "-SERIAL-002")
    record, = app._storage_failures().records()
    monkeypatch.setattr(storage_utils.time, "time", lambda: record["timestamp"] + 24 * 3600)
    restarted = flow(transition=False, root=Path(app.save_folder))
    restarted._resume_storage_failure_slots()
    assert restarted.CURRENT_TRAY_STATE_FILE == record["replacement_file"]
    assert restarted._preflight_context_blocks_mutation(COMPACT_QR)
    assert not restarted._preflight_context_blocks_mutation(OLD_QR)
    assert original.read_bytes() == before
    assert restarted._storage_failures().records() == [record]


def test_invalid_quarantine_mapping_cannot_replay_original_checkpoint(flow, windows, monkeypatch):
    app = _active(flow)
    public_scan(app, ITEM + "-SERIAL-001")
    original = _fail_current(app, monkeypatch)
    before = original.read_bytes()
    public_scan(app, ITEM + "-SERIAL-002")
    store = app._storage_failures()
    record, = store.records()
    record["replacement_file"] = record["source_file"]
    (store.directory / (record["item_id"] + ".json")).write_text(json.dumps(record), encoding="utf-8")
    restarted = flow(transition=False, root=Path(app.save_folder))
    restarted._project_audit_event_contract = lambda *a: pytest.fail("original checkpoint must not replay")
    restarted._load_current_tray_state()
    assert "이 PC 에 저장할 수 없습니다" in restarted._scan_entry_admission_block_reason()
    assert not restarted.current_tray.master_label_code
    assert original.read_bytes() == before


@pytest.mark.parametrize("phase", ["activation", "parked_restore", "restore_audit"])
def test_restore_failure_keeps_checkpoint_unknown_and_other_labels_available(flow, windows, monkeypatch, phase):
    app = _active(flow)
    public_scan(app, ITEM + "-SERIAL-001")
    original = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    before = original.read_bytes()
    app.current_tray = ca.TraySession()
    if phase == "activation":
        monkeypatch.setattr(app, "_reconcile_activation_event_from_state", lambda state: False)
    elif phase == "parked_restore":
        monkeypatch.setattr(app, "_reconcile_parked_restore_from_state", lambda state: False)
    else:
        log = app._log_event
        monkeypatch.setattr(app, "_log_event", lambda event, **kw: False if event == "TRAY_RESTORE" else log(event, **kw))
    app._load_current_tray_state(_recovery_choice=True)
    record, = app._storage_failures().records()
    assert record["outcome"] == "UNKNOWN"
    assert original.read_bytes() == before
    app._resume_storage_failure_slots()
    assert app.CURRENT_TRAY_STATE_FILE == record["replacement_file"]
    assert app._preflight_label_is_held(COMPACT_QR)
    assert not app._preflight_label_is_held(OLD_QR)
    assert not app.seal_calls

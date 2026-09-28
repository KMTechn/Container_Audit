"""Transition mode for pre-PHS2 transfer labels (13-digit item code, old QR).

An administrator-only Machine value accepts them with a local-only
TRAY_COMPLETE outside the ledger; without it they stop at tray start.
PHS2 trays behave the same in both modes.
"""
import csv
import datetime
import inspect
import json
import queue
import socket
import threading

import pytest

import Container_Audit as container_audit_module
import logistics_runtime_profile as runtime_profile
import session_history
from Container_Audit import ContainerAudit, TraySession
from direct_sync_health import RelayHealth
from label_qr import canonical_master_label_key
from parked_tray_store import ParkedTrayStore
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401 - fixture
from tests.test_container_audit_contracts import (
    CapturingListbox,
    _completion_app,
    _write_session_history_row,
)
from tests.test_phs2_master_preflight import (
    BlockingClient,
    COMPACT_QR,
    ITEM,
    _app,
    _pump_until,
    _resolved,
)
from transfer_member_exchange import (
    TransferMemberExchangeCoordinator,
    TransferMemberExchangeStore,
)
from transfer_seal import SealAttempt

pytestmark = pytest.mark.usefixtures("owned_tk_workers")

# The administrator command documents this exact Machine variable name.
SWITCH = "KMTECH_LEGACY_LABEL_TRANSITION"
MACHINE_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
USER_KEY = "Environment"
OLD_QR = f"CLC={ITEM}|QT=2"
LEGACY_REJECTION_TITLE = "새 시스템 이전 현품표"


class _FakeKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class FakeRegistry:
    """Serves only the given values and never reaches the host registry."""

    def __init__(self, winreg, *, machine=None, user=None):
        self.winreg = winreg
        self.values = {
            (winreg.HKEY_LOCAL_MACHINE, MACHINE_KEY): dict(machine or {}),
            (winreg.HKEY_CURRENT_USER, USER_KEY): dict(user or {}),
        }
        self.opened = []

    def OpenKey(self, hive, name, *_args, **_kwargs):
        self.opened.append((hive, name))
        if (hive, name) not in self.values:
            raise FileNotFoundError(name)
        return _FakeKey(self.values[(hive, name)])

    def QueryValueEx(self, key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], self.winreg.REG_SZ


@pytest.fixture
def registry(monkeypatch):
    winreg = pytest.importorskip("winreg")

    def install(**values):
        fake = FakeRegistry(winreg, **values)
        monkeypatch.setattr(winreg, "OpenKey", fake.OpenKey)
        monkeypatch.setattr(winreg, "QueryValueEx", fake.QueryValueEx)
        # The suite keeps the host switch out of tests; read through the real
        # Machine reader, which now sees only this fake registry.
        monkeypatch.setattr(
            runtime_profile,
            "_machine_environment_value",
            inspect.unwrap(runtime_profile._machine_environment_value),
        )
        return fake

    return install


def test_switch_is_on_only_for_the_machine_value_one(registry):
    fake = registry(machine={SWITCH: "1"})

    assert runtime_profile.legacy_label_transition_enabled() is True
    assert fake.opened == [(fake.winreg.HKEY_LOCAL_MACHINE, MACHINE_KEY)]


@pytest.mark.parametrize("value", ["0", "", "true", "yes", "on", "2"])
def test_switch_stays_off_for_any_other_machine_value(registry, value):
    registry(machine={SWITCH: value})

    assert runtime_profile.legacy_label_transition_enabled() is False


def test_process_or_user_scope_value_cannot_enable_the_switch(registry, monkeypatch):
    fake = registry(machine={}, user={SWITCH: "1"})
    monkeypatch.setenv(SWITCH, "1")

    assert runtime_profile.legacy_label_transition_enabled() is False
    assert {hive for hive, _name in fake.opened} == {fake.winreg.HKEY_LOCAL_MACHINE}


def test_unreadable_machine_environment_leaves_the_switch_off(registry, monkeypatch):
    fake = registry(machine={SWITCH: "1"})

    def denied(*_args, **_kwargs):
        raise PermissionError("machine environment denied")

    monkeypatch.setattr(fake.winreg, "OpenKey", denied)

    assert runtime_profile.legacy_label_transition_enabled() is False


class _StartupStopped(Exception):
    """Stop construction right after the window chrome is configured."""


class _StartupRoot:
    def __init__(self):
        self.titles = []

    def title(self, value):
        self.titles.append(value)

    def minsize(self, *_size):
        return (1, 1)

    def geometry(self, *_args):
        return None

    def update_idletasks(self):
        return None

    def state(self, _value):
        return None

    def configure(self, **_options):
        raise _StartupStopped


@pytest.mark.parametrize(("machine", "shown"), [({SWITCH: "1"}, True), ({}, False)])
def test_app_start_reads_the_switch_and_keeps_it_in_the_window_title(
    registry, monkeypatch, machine, shown
):
    registry(machine=machine)
    root = _StartupRoot()
    monkeypatch.delenv("CONTAINER_AUDIT_STARTUP_GEOMETRY", raising=False)
    monkeypatch.setattr(container_audit_module, "container_startup_logistics_client", lambda: None)
    monkeypatch.setattr(container_audit_module, "fit_restored_window_to_work_area", lambda _root: None)
    monkeypatch.setattr(container_audit_module.tk, "Tk", lambda: root)

    with pytest.raises(_StartupStopped):
        ContainerAudit()

    assert root.titles[-1].startswith(ContainerAudit.APP_TITLE)
    assert ("과도기 모드 — 옛 현품표 받음" in root.titles[-1]) is shown


@pytest.fixture
def flow(tmp_path):
    """Headless app with real tray state, event CSV and cleanup writes."""
    apps = []

    def make(*, transition, client=None, root=None):
        root = root or tmp_path
        root.mkdir(parents=True, exist_ok=True)
        app = _app(root, client or BlockingClient(_resolved(count=2)))
        for name, value in vars(_completion_app(root)).items():
            if name not in vars(app):
                setattr(app, name, value)
        for name in (
            "_save_current_tray_state",
            "_save_tray_state_snapshot",
            "_delete_current_tray_state",
            "_log_event",
        ):
            vars(app).pop(name, None)
        app.legacy_label_transition = transition
        app.save_folder = str(root)
        app.log_file_path = str(
            root / f"이적작업이벤트로그_tester_{datetime.date.today():%Y%m%d}.csv"
        )
        app.computer_id = "0xfixturepc"
        app.scanned_listbox = CapturingListbox()
        app._tray_state_persist_lock = threading.RLock()
        app._pending_activation_event_contract = None
        app._pending_completion_event_contract = None
        app._pending_operator_review_snapshot = None
        app.is_idle = False
        app.last_activity_time = None
        app.log_write_errors = []
        app.last_log_write_error = None
        app.syncs = []
        app._trigger_session_direct_sync = app.syncs.append
        app.seal_calls = []
        prepare = app._prepare_and_attempt_transfer_seal_snapshot

        def observed_prepare(**kwargs):
            app.seal_calls.append(kwargs["source_label_payload"])
            return prepare(**kwargs)

        app._prepare_and_attempt_transfer_seal_snapshot = observed_prepare
        app.log_queue = queue.Queue()
        app.log_thread = threading.Thread(
            target=app._event_log_writer, name="test-legacy-event-writer"
        )
        app.log_thread.start()
        apps.append(app)
        return app

    yield make
    for app in apps:
        lane = getattr(app, "_ui_lane", None)
        if lane is not None:
            _pump_until(app.root, lambda: not lane.is_busy())
            lane.close_idle()
        app.log_queue.put(None)
        app.log_thread.join(timeout=10)
        assert not app.log_thread.is_alive()


def _rows(app, event=None):
    app.log_queue.join()
    path = app.log_file_path
    try:
        with open(path, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except FileNotFoundError:
        return []
    return [row for row in rows if event is None or row["event"] == event]


def _details(row):
    return json.loads(row["details"])


def _scan_products(app, count, *, start=1):
    for index in range(start, start + count):
        app._process_barcode_logic(f"{ITEM}-{index:04d}")


def _has_seal_intent(app):
    return app.transfer_seal_coordinator.store.has_exact_history()


def test_off_rejects_a_13_digit_label_at_tray_start_before_any_product_scan(flow):
    app = flow(transition=False)

    app._process_barcode_logic(ITEM)
    app._process_barcode_logic(f"{ITEM}-0001")

    assert app.current_tray.master_label_code == ""
    assert app.current_tray.scanned_barcodes == []
    assert app.warnings[0][0] == LEGACY_REJECTION_TITLE
    assert "새 시스템 이전 방식입니다. 관리자에게 알려 주세요" in app.warnings[0][1]
    # The next scan is read as a label again, never as a product of that tray.
    assert app.warnings[1][0] == "작업 시작 오류"
    assert _rows(app) == []


def test_off_rejects_an_old_format_qr_label_at_tray_start(flow):
    app = flow(transition=False)

    app._process_barcode_logic(OLD_QR)

    assert app.current_tray.master_label_code == ""
    assert [warning[0] for warning in app.warnings] == [LEGACY_REJECTION_TITLE]
    assert _rows(app) == []


def test_off_keeps_resuming_a_parked_old_qr_tray_by_scanning_its_label(flow, monkeypatch):
    app = flow(transition=False)
    app.current_tray = TraySession(
        master_label_code=OLD_QR, item_code=ITEM, item_name="fixture item", tray_size=2,
        scanned_barcodes=[f"{ITEM}-0001"], scan_times=[datetime.datetime.now()],
        start_time=datetime.datetime.now(),
    )
    parked = ParkedTrayStore(app.parked_trays_dir).save_state(
        app._current_tray_state_snapshot(), worker_name="tester", master_label=OLD_QR,
    )
    app.current_tray = TraySession()
    restored = []
    app.restore_parked_tray = restored.append
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *_a, **_k: True)

    app._process_barcode_logic(OLD_QR)

    assert restored == [str(parked)]
    assert app.warnings == []


@pytest.mark.parametrize("foreground", [False, True])
def test_off_restored_13_digit_tray_is_kept_and_the_block_names_its_cause(flow, foreground):
    app = flow(transition=False)
    app.current_tray = TraySession(
        master_label_code=ITEM, item_code=ITEM, item_name="fixture item", tray_size=60,
        scanned_barcodes=[f"{ITEM}-{index:04d}" for index in range(1, 61)],
        scan_times=[datetime.datetime.now()] * 60, start_time=datetime.datetime.now(),
    )

    if foreground:
        assert app.request_complete_tray() is False
    else:
        assert app.complete_tray() is False

    assert app.current_tray.master_label_code == ITEM
    assert len(app.current_tray.scanned_barcodes) == 60
    assert "새 시스템 이전 방식이라 과도기 모드가 꺼진 이 PC에서는 완료할 수 없습니다" in app.statuses[-1][0]
    assert _rows(app, "TRAY_COMPLETE") == []


def test_on_completes_a_full_13_digit_tray_locally_without_seal_or_ledger(flow):
    app = flow(transition=True)

    app._process_barcode_logic(ITEM)
    assert app.current_tray.master_label_code == ITEM
    _scan_products(app, 60)

    completed = _rows(app, "TRAY_COMPLETE")
    assert len(completed) == 1
    row = completed[0]
    detail = _details(row)
    assert detail["transfer_seal_status"] == "LEGACY_LOCAL_ONLY"
    assert detail["transfer_seal_intent_id"].startswith("legacy-local-only-")
    assert detail["master_label_code"] == ITEM
    assert detail["item_code"] == ITEM
    assert detail["item_name"] == "fixture item"
    assert detail["scan_count"] == 60
    assert detail["product_barcodes"] == [f"{ITEM}-{index:04d}" for index in range(1, 61)]
    assert detail["is_partial_submission"] is False
    assert detail["source_computer_id"] == "0xfixturepc"
    assert detail["source_host_name"] == socket.gethostname()
    assert row["worker_name"] == "tester"
    assert datetime.datetime.fromisoformat(row["timestamp"]).date() == datetime.date.today()
    assert detail["transfer_bundle_id"] is None and detail["transfer_seal_receipt_id"] is None
    assert len(_rows(app, "MASTER_LABEL_SCANNED_OLD")) == 1
    assert any("과도기 로컬 기록" in status[0] for status in app.statuses)
    assert app.seal_calls == []
    assert _has_seal_intent(app) is False
    assert app.current_tray.master_label_code == ""
    assert app.work_summary[ITEM]["count"] == 1
    assert app.work_summary[ITEM]["legacy_count"] == 1
    assert app.syncs == ["TRAY_COMPLETE"]


def test_on_foreground_completion_request_records_the_legacy_tray(flow):
    app = flow(transition=True)
    app._process_barcode_logic(ITEM)
    app.current_tray.tray_size = 3
    _scan_products(app, 2)
    app.current_tray.scanned_barcodes.append(f"{ITEM}-0003")
    app.current_tray.scan_times.append(datetime.datetime.now())

    completed = []
    assert app.request_complete_tray(completion_callback=completed.append) is True
    _pump_until(app.root, lambda: bool(completed))

    assert completed == [True]
    assert app.seal_calls == []
    assert _has_seal_intent(app) is False
    [row] = _rows(app, "TRAY_COMPLETE")
    assert _details(row)["transfer_seal_status"] == "LEGACY_LOCAL_ONLY"
    assert app.current_tray.master_label_code == ""


def test_on_partial_submit_of_a_13_digit_tray_is_recorded_as_partial(flow, monkeypatch):
    app = flow(transition=True)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *_a, **_k: True)
    app._process_barcode_logic(ITEM)
    _scan_products(app, 10)

    app.submit_current_tray()

    [row] = _rows(app, "TRAY_COMPLETE")
    detail = _details(row)
    assert detail["transfer_seal_status"] == "LEGACY_LOCAL_ONLY"
    assert detail["is_partial_submission"] is True
    assert detail["scan_count"] == 10
    assert app.seal_calls == []
    assert app.current_tray.master_label_code == ""
    assert app.total_tray_count == 0
    assert app.work_summary[ITEM]["legacy_count"] == 1


def test_on_old_format_qr_tray_completes_locally_instead_of_a_seal_intent(flow):
    app = flow(transition=True)
    app.current_tray = TraySession(
        master_label_code=OLD_QR, item_code=ITEM, item_name="fixture item",
        tray_size=2, start_time=datetime.datetime.now(),
    )
    _scan_products(app, 2)

    [row] = _rows(app, "TRAY_COMPLETE")
    assert _details(row)["transfer_seal_status"] == "LEGACY_LOCAL_ONLY"
    assert app.seal_calls == []
    assert _has_seal_intent(app) is False


def test_on_partial_old_qr_label_is_closed_like_v209_live_and_after_restart(flow, monkeypatch):
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *_a, **_k: True)
    app = flow(transition=True)
    app._process_barcode_logic(OLD_QR)
    assert app.current_tray.master_label_code == OLD_QR
    _scan_products(app, 1)
    app.submit_current_tray()
    [row] = _rows(app, "TRAY_COMPLETE")
    assert _details(row)["is_partial_submission"] is True

    app._process_barcode_logic(OLD_QR)
    assert app.current_tray.master_label_code == ""
    assert app.warnings[-1][0] == "현품표 중복"

    restarted = flow(transition=True)
    restarted._load_session_state()
    restarted._process_barcode_logic(OLD_QR)
    assert restarted.current_tray.master_label_code == ""
    assert restarted.warnings[-1][0] == "현품표 중복"


def test_legacy_record_survives_restart_and_keeps_a_same_item_tray(flow, monkeypatch):
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *_a, **_k: True)
    first = flow(transition=True)
    first._process_barcode_logic(ITEM)
    _scan_products(first, 60)
    # A second tray of the same item is in progress when the PC restarts.
    first._process_barcode_logic(ITEM)
    _scan_products(first, 5, start=61)
    assert len(_rows(first, "TRAY_COMPLETE")) == 1

    restarted = flow(transition=True)
    restarted.worker_name = "tester"
    restarted._load_session_state()
    restarted._load_current_tray_state()

    assert restarted.work_summary[ITEM]["count"] == 1
    assert restarted.work_summary[ITEM]["legacy_count"] == 1
    assert restarted.current_tray.master_label_code == ITEM
    assert restarted.current_tray.scanned_barcodes == [
        f"{ITEM}-{index:04d}" for index in range(61, 66)
    ]
    [row] = _rows(restarted, "TRAY_COMPLETE")
    assert _details(row)["transfer_seal_status"] == "LEGACY_LOCAL_ONLY"


def test_restart_history_keeps_13_digit_item_codes_out_of_completed_labels(tmp_path):
    # Every tray of an item shares its 13-digit code; only a QR names one tray.
    log_path = tmp_path / f"이적작업이벤트로그_tester_{datetime.date.today():%Y%m%d}.csv"
    now = datetime.datetime.now().replace(microsecond=0)
    for label in (ITEM, OLD_QR):
        _write_session_history_row(
            log_path, timestamp=now, master_label=label, item_code=ITEM, worker_name="tester",
            scan_count=2, tray_capacity=2, work_time_sec=20.0,
            product_barcodes=[f"{label}-0001", f"{label}-0002"], barcode_count=2,
        )

    history = session_history.load_session_history(
        save_folder=tmp_path, worker_name="tester", today=datetime.date.today(), tray_size=60,
    )

    assert history.load_errors == []
    assert ITEM not in history.completed_master_labels
    assert canonical_master_label_key(OLD_QR) in history.completed_master_labels
    assert history.work_summary[ITEM]["count"] == 2


@pytest.mark.parametrize(
    "failure",
    [PermissionError("server rejected the event file"), OSError("relay unreachable")],
    ids=["server-rejected", "offline"],
)
def test_relay_rejection_or_outage_does_not_hold_the_next_legacy_tray(
    flow, monkeypatch, tmp_path, failure
):
    app = flow(transition=True)
    # The real trigger runs; only the HTTPS relay start fails, with a backlog.
    del app._trigger_session_direct_sync
    app.application_path = str(tmp_path / "app")
    app.direct_sync_program_data_root = str(tmp_path / "direct-sync")
    app.direct_sync_scan_source_dir = str(tmp_path)
    app._direct_sync_wake_results = queue.Queue()
    app._direct_sync_health = RelayHealth(
        state="blocked", pending_count=40, failed_permanent_count=3,
        operator_review_count=2, last_acked_at="", oldest_pending_at="2026-09-28T00:00:00+00:00",
        observed_at="2026-09-29T00:00:00+00:00", error_code="server_rejected",
    )
    starts = []

    def failing_start(**kwargs):
        starts.append(kwargs["reason"])
        raise failure

    monkeypatch.setattr(container_audit_module, "start_session_direct_sync", failing_start)
    for tray in range(2):
        app._process_barcode_logic(ITEM)
        _scan_products(app, 60, start=1 + tray * 60)

    assert len(_rows(app, "TRAY_COMPLETE")) == 2
    assert starts == ["TRAY_COMPLETE", "TRAY_COMPLETE"]
    results = [app._direct_sync_wake_results.get_nowait() for _ in range(2)]
    assert {(result.status, result.error_category) for result in results} == {
        ("UNKNOWN", "relay_wake_start_failed")
    }
    assert app.current_tray.master_label_code == ""
    assert app.work_summary[ITEM]["legacy_count"] == 2


def _phs2_completion(flow, root, *, transition):
    app = flow(transition=transition, client=BlockingClient(_resolved(count=2)), root=root)
    app._transfer_coordinator_ui_owner_thread_id = threading.get_ident()
    app.transfer_member_exchange_coordinator = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(
            root / "transfer-seal.db",
            ui_thread_id_provider=app._transfer_coordinator_ui_thread_id,
        ),
        app.transfer_seal_coordinator.client,
        owner_thread_id_provider=app._transfer_coordinator_owner_thread_id,
    )
    app._transfer_member_exchange_attempt_snapshot = {
        "known": True, "master_label": "", "attempt": None,
    }
    app._process_barcode_logic(COMPACT_QR)
    _pump_until(
        app.root,
        lambda: bool(app.current_tray.master_label_code)
        and not app._preflight_hold_store().exists()
        and not getattr(app, "_preflight_scan_input_locked", False),
    )
    app.seal_calls.clear()
    app._prepare_and_attempt_transfer_seal_snapshot = lambda **kwargs: (
        app.seal_calls.append(kwargs["source_label_payload"])
        or SealAttempt("intent-phs2", "ACKED", receipt_id="receipt-phs2")
    )
    app.current_tray.scanned_barcodes = [ITEM + "-A"]
    app.current_tray.scan_times = [datetime.datetime.now()]
    partial = app.submit_current_tray()
    blocked_partial = app.current_tray.master_label_code == COMPACT_QR
    app.current_tray.scanned_barcodes.append(ITEM + "-B")
    app.current_tray.scan_times.append(datetime.datetime.now())
    completed = []
    assert app.request_complete_tray(completion_callback=completed.append) is True
    _pump_until(app.root, lambda: bool(completed))
    [row] = _rows(app, "TRAY_COMPLETE")
    detail = _details(row)
    stable = {
        key: value for key, value in detail.items()
        if key not in {"start_time", "end_time", "work_time_sec", "total_idle_seconds",
                       "idempotency_key"}
    }
    return partial, blocked_partial, completed, list(app.seal_calls), stable


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_phs2_trays_complete_the_same_with_the_switch_on_or_off(flow, tmp_path):
    off = _phs2_completion(flow, tmp_path / "off", transition=False)
    on = _phs2_completion(flow, tmp_path / "on", transition=True)

    assert on == off
    partial, blocked_partial, completed, seal_calls, detail = on
    assert partial is None and blocked_partial is True
    assert completed == [True]
    assert seal_calls == [COMPACT_QR]
    assert detail["transfer_seal_status"] == "ACKED"
    assert "source_computer_id" not in detail


def test_summary_list_shows_the_daily_transition_count():
    class Tree:
        def __init__(self):
            self.rows = []

        def winfo_exists(self):
            return True

        def get_children(self):
            return []

        def delete(self, *_items):
            return None

    app = ContainerAudit.__new__(ContainerAudit)
    app.summary_tree = Tree()
    app.work_summary = {ITEM: {"name": "fixture item", "count": 3, "test_count": 0, "legacy_count": 2}}
    app._insert_tree_row = lambda tree, *_args, values, **_kwargs: tree.rows.append(values)
    app.root = None

    app._update_summary_list()

    assert app.summary_tree.rows == [("fixture item", ITEM, "3 (과도기 2)")]

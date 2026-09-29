"""Transition mode: accept every label and record each completion by class.

An administrator-only Machine value turns it on. Old labels (13-digit item
code, old QR) are LEGACY, new-looking labels in a broken form PHS2_MALFORMED,
PHS=2 labels the central path blocks PHS2_LOCAL - all completed on this PC
outside the ledger - and PHS=2 trays that pass it PHS2_CENTRAL, as before.
Without the switch old and broken labels stop at tray start and PHS2 is
unchanged.
"""
import base64
import csv
import datetime
import inspect
import json
import queue
import socket
import threading

from pathlib import Path

import pytest

import Container_Audit as container_audit_module
import logistics_runtime_profile as runtime_profile
import session_history
from Container_Audit import ContainerAudit, TraySession
from direct_sync_health import RelayHealth
import label_qr
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
    _offline_queue_app,
    _pump_until,
    _resolved,
)
from transfer_member_exchange import (
    TransferMemberExchangeCoordinator,
    TransferMemberExchangeStore,
)
from transfer_seal import SealAttempt, TransferSealCoordinator, TransferSealError

pytestmark = pytest.mark.usefixtures("owned_tk_workers")

# The administrator command documents this exact Machine variable name.
SWITCH = "KMTECH_LEGACY_LABEL_TRANSITION"
MACHINE_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
USER_KEY = "Environment"
OLD_QR = f"CLC={ITEM}|QT=2"
# The label CA v2.0.9 printed and read.
V209_QR = f"PHS=1|CLC={ITEM}|WID=WO-0001|SPC=A14|FPB=A146000306|OBD=2026-09-01|PJT=KMC|QT=2"
LEGACY_REJECTION_TITLE = "새 시스템 이전 현품표"
OTHER_ITEM = "BBB0000000001"


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
        # As the real constructor: the seal coordinator over the same store and
        # lease manager, and a member exchange coordinator whose UI snapshot
        # holds only what startup recovery published (no tray yet).
        app._transfer_coordinator_ui_owner_thread_id = threading.get_ident()
        fixture_seal = app.transfer_seal_coordinator
        app.transfer_seal_coordinator = TransferSealCoordinator(
            fixture_seal.store,
            fixture_seal.client,
            fixture_seal.operation_lease_manager,
        )
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


@pytest.mark.parametrize(
    ("snapshot_label", "expected"),
    [
        # Right after start or restore the member snapshot is not yet this tray's.
        ("", "이적 봉인 및 완료 작업을 할 수 없습니다"),
        # After restart recovery it is, and the central completion refuses the label.
        (ITEM, "완료할 수 없습니다"),
    ],
)
@pytest.mark.parametrize("foreground", [False, True])
def test_off_restored_13_digit_tray_is_kept_and_the_block_names_its_cause(
    flow, foreground, snapshot_label, expected
):
    # A round without a transition class (never started with the switch on) is strict.
    app = flow(transition=False)
    app._transfer_member_exchange_attempt_snapshot = {
        "known": True, "master_label": snapshot_label, "attempt": None,
    }
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
    message = app.statuses[-1][0]
    assert "새 시스템 이전 방식이라 과도기 모드가 꺼진 이 PC에서는" in message
    assert expected in message
    assert _rows(app, "TRAY_COMPLETE") == []


@pytest.mark.parametrize("foreground", [False, True])
def test_off_phs2_tray_without_a_lease_or_class_is_kept_and_the_block_names_its_cause(
    flow, foreground
):
    # A lease-less PHS=2 round without a transition class is strict with the switch off.
    app = flow(transition=False)
    app._transfer_member_exchange_attempt_snapshot = {
        "known": True, "master_label": COMPACT_QR, "attempt": None,
    }
    now = datetime.datetime.now()
    app.current_tray = TraySession(
        master_label_code=COMPACT_QR, item_code=ITEM, item_name="fixture item", tray_size=2,
        scanned_barcodes=[f"{ITEM}-0001", f"{ITEM}-0002"], scan_times=[now, now], start_time=now,
        transition_reasons=["PHS2_PREFLIGHT_UNAVAILABLE"],
    )

    if foreground:
        assert app.request_complete_tray() is False
    else:
        assert app.complete_tray() is False

    assert app.current_tray.master_label_code == COMPACT_QR
    assert len(app.current_tray.scanned_barcodes) == 2
    assert "중앙 이적 확인 정보(lease)가 없어 완료할 수 없습니다" in app.statuses[-1][0]
    assert _rows(app, "TRAY_COMPLETE") == []
    assert app.seal_calls == [] and _has_seal_intent(app) is False


NEW_SYSTEM_LABELS_WITHOUT_PHS2 = [
    COMPACT_QR.replace("PHS=2|", ""),
    COMPACT_QR.replace("PHS=2|", "PHS=|"),
    f"PHS=1|CLC={ITEM}|BND=BND-TRANSFER-0001|QT=2",
]


@pytest.mark.parametrize("label", NEW_SYSTEM_LABELS_WITHOUT_PHS2)
def test_off_refuses_a_damaged_new_system_label_at_tray_start(flow, label):
    app = flow(transition=False)

    app._process_barcode_logic(label)

    assert app.current_tray.master_label_code == ""
    assert [warning[0] for warning in app.warnings] == ["현품표 정보 확인 필요"]
    assert _rows(app) == []


def _submit(app, monkeypatch):
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *_a, **_k: True)
    app.submit_current_tray()
    _pump_until(app.root, lambda: not app.current_tray.master_label_code)


MALFORMED_LABELS = [
    (COMPACT_QR.replace("PHS=2|", ""), ["PHS_MISSING"]),
    (COMPACT_QR.replace("PHS=2|", "PHS=|"), ["PHS_EMPTY"]),
    (f"PHS=1|CLC={ITEM}|BND=BND-TRANSFER-0001|QT=2", ["PHS_NOT_2"]),
    (COMPACT_QR.replace("|HSH=aaaaaaaaaaaaaaaa", ""), ["LINEAGE_MISSING"]),
    (COMPACT_QR.replace("ITG=ITAG-COMPACT-001", "ITG="), ["LINEAGE_MISSING"]),
    (COMPACT_QR + "|LBL=LBL-COMPACT-002", ["DUPLICATE_KEY"]),
    # w9transitalign table: compact defects are the shared FORMAT_INVALID,
    # not judged beside another defect.
    (COMPACT_QR + "|QT=2", ["FORMAT_INVALID"]),
    # A later duplicate must not hide the new-system value (sub-03 P1-1).
    (f"SRC=KMTECH_INPUT_TAG|SRC=OLD|CLC={ITEM}|QT=2", ["DUPLICATE_KEY", "PHS_MISSING"]),
    (f"PHS=2|PHS=1|CLC={ITEM}|QT=2", ["DUPLICATE_KEY", "PHS_NOT_2"]),
    (f"ITG=X|ITG=|CLC={ITEM}|QT=2", ["DUPLICATE_KEY", "PHS_MISSING"]),
    # An unusable QT is recorded, never refused or used as a quantity (sub-03 P1-2).
    (COMPACT_QR + "|QT=abc", ["QT_INVALID"]),
    (COMPACT_QR + "|QT=0", ["QT_INVALID"]),
    (COMPACT_QR + "|QT=-1", ["QT_INVALID"]),
]


@pytest.mark.parametrize(("label", "reasons"), MALFORMED_LABELS)
def test_on_accepts_a_damaged_new_label_as_phs2_malformed_never_as_legacy(
    flow, monkeypatch, label, reasons
):
    client = BlockingClient(_resolved(count=2))
    app = flow(transition=True, client=client)

    app._process_barcode_logic(label)
    assert app.current_tray.master_label_code == label
    _scan_products(app, 2)
    if app.current_tray.master_label_code:
        _submit(app, monkeypatch)

    [row] = _rows(app, "TRAY_COMPLETE")
    detail = _details(row)
    assert detail["transition_class"] == "PHS2_MALFORMED"
    assert detail["transition_reasons"][: len(reasons)] == reasons
    assert detail["transfer_seal_status"] == "PHS2_MALFORMED_LOCAL_ONLY"
    assert detail["master_label_code"] == label  # the raw value
    assert client.identities == [] and app.seal_calls == []
    assert _has_seal_intent(app) is False
    assert app.work_summary[ITEM]["transition_counts"] == {"PHS2_MALFORMED": 1}


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
    assert detail["app_version"] == container_audit_module.CURRENT_VERSION
    assert row["worker_name"] == "tester"
    assert datetime.datetime.fromisoformat(row["timestamp"]).date() == datetime.date.today()
    assert detail["transfer_bundle_id"] is None and detail["transfer_seal_receipt_id"] is None
    assert detail["transition_class"] == "LEGACY"
    assert detail["transition_reasons"] == []
    assert detail["transition_duplicate"] is False
    [started] = _rows(app, "MASTER_LABEL_SCANNED_OLD")
    assert _details(started)["transition_class"] == "LEGACY"
    assert any("과도기 옛 기록(새 원장 제외)" in status[0] for status in app.statuses)
    assert app.seal_calls == []
    assert _has_seal_intent(app) is False
    assert app.current_tray.master_label_code == ""
    assert app.work_summary[ITEM]["count"] == 1
    assert app.work_summary[ITEM]["transition_counts"] == {"LEGACY": 1}
    assert app.syncs == ["TRAY_COMPLETE"]


def test_on_old_qr_with_an_unusable_quantity_is_legacy_with_its_reason(flow, monkeypatch):
    app = flow(transition=True)

    app._process_barcode_logic(f"CLC={ITEM}|QT=abc")
    assert app.current_tray.tray_size == 60
    _scan_products(app, 2)
    _submit(app, monkeypatch)

    [row] = _rows(app, "TRAY_COMPLETE")
    detail = _details(row)
    assert (detail["transition_class"], detail["transition_reasons"]) == ("LEGACY", ["QT_INVALID"])
    assert detail["master_label_code"] == f"CLC={ITEM}|QT=abc"


DAMAGED_PHS2_LABELS = [
    COMPACT_QR.replace("|HSH=aaaaaaaaaaaaaaaa", ""),
    COMPACT_QR.replace("ITG=ITAG-COMPACT-001", "ITG="),
    COMPACT_QR.replace("aaaaaaaaaaaaaaaa", "z" * 16),
    COMPACT_QR + "|QT=2",
]


@pytest.mark.parametrize("label", DAMAGED_PHS2_LABELS)
def test_on_damaged_phs2_tray_survives_restart_and_parking(flow, tmp_path, monkeypatch, label):
    # sub-03 P1-3: its state must restore like any tray, current and parked.
    first = flow(transition=True, root=tmp_path / "pc")
    first._process_barcode_logic(label)
    _scan_products(first, 1)

    restarted = flow(transition=True, root=tmp_path / "pc")
    restarted.worker_name = "tester"
    restarted._load_session_state()
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *_a, **_k: True)
    restarted._load_current_tray_state()
    assert restarted.current_tray.master_label_code == label
    assert restarted.current_tray.scanned_barcodes == [f"{ITEM}-0001"]

    assert restarted.park_current_tray(confirm=False) is True
    [parked] = [row.path for row in ParkedTrayStore(restarted.parked_trays_dir).list_for_worker("tester")]
    restarted.show_validation_screen = lambda: None  # headless: no work screen to draw
    restarted.restore_parked_tray(str(parked))
    assert restarted.current_tray.master_label_code == label
    assert restarted.current_tray.scanned_barcodes == [f"{ITEM}-0001"]


def test_on_duplicate_round_in_progress_survives_restart_and_parking(flow, tmp_path, monkeypatch):
    # sub-03 P1-5: a knowingly started second round is not the leftover of the first.
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *_a, **_k: True)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *_a, **_k: True)
    first = flow(transition=True, root=tmp_path / "pc")
    first._process_barcode_logic(OLD_QR)
    _scan_products(first, 2)
    first._process_barcode_logic(OLD_QR)
    _scan_products(first, 1, start=3)
    assert first.current_tray.transition_reasons == ["DUPLICATE_LABEL"]

    restarted = flow(transition=True, root=tmp_path / "pc")
    restarted.worker_name = "tester"
    restarted._load_session_state()
    restarted._load_current_tray_state()
    assert restarted.current_tray.master_label_code == OLD_QR
    assert restarted.current_tray.scanned_barcodes == [f"{ITEM}-0003"]

    assert restarted.park_current_tray(confirm=False) is True
    [parked] = [row.path for row in ParkedTrayStore(restarted.parked_trays_dir).list_for_worker("tester")]
    restarted.show_validation_screen = lambda: None  # headless: no work screen to draw
    restarted.restore_parked_tray(str(parked))
    assert restarted.current_tray.scanned_barcodes == [f"{ITEM}-0003"]


def test_same_label_completed_twice_with_the_same_products_counts_both_rounds(flow, tmp_path):
    # sub-03 P1-5: two rounds are two completions after a reload, a replay is one.
    app = flow(transition=True, root=tmp_path / "pc")
    for _round in range(2):
        app._process_barcode_logic(OLD_QR)
        _scan_products(app, 2)
    first, second = [_details(row) for row in _rows(app, "TRAY_COMPLETE")]
    assert first["product_barcodes"] == second["product_barcodes"]
    assert first["transfer_seal_intent_id"] != second["transfer_seal_intent_id"]

    restarted = flow(transition=True, root=tmp_path / "pc")
    restarted.worker_name = "tester"
    restarted._load_session_state()

    assert restarted.work_summary[ITEM]["transition_counts"] == {"LEGACY": 2}
    assert restarted.work_summary[ITEM]["transition_duplicates"] == 1
    # A completed round's leftover state is still discarded on restart.
    assert session_history.completed_label_round(OLD_QR, first["start_time"]) in restarted.completed_label_rounds


@pytest.mark.parametrize(
    ("action", "event", "key_prefix"),
    [("undo", "SCAN_UNDO", "scan-undo:"), ("reset", "TRAY_RESET", "tray-reset:")],
)
def test_cancellation_retried_after_a_lost_write_ack_leaves_one_row_with_its_event_id(
    flow, monkeypatch, action, event, key_prefix
):
    # sub-04 R8: the row was durable but its acknowledgement was lost; the
    # operator's retry must not write a second row (the server would quarantine
    # a second TRAY_RESET of the same label and stop this PC's upload line).
    app = flow(transition=True)
    app._process_barcode_logic(ITEM)
    _scan_products(app, 2)
    lost = []

    def losing(real):
        def append(path, entry, *args, **kwargs):
            result = real(path, entry, *args, **kwargs)
            if entry["event"] == event and not lost:
                lost.append(entry)
                raise OSError("write acknowledgement lost")
            return result
        return append

    for name in ("append_event_log_entry", "append_event_log_entry_idempotent"):
        monkeypatch.setattr(container_audit_module, name, losing(getattr(container_audit_module, name)))
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *_a, **_k: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *_a, **_k: None)
    cancel = app.undo_last_scan if action == "undo" else app.reset_current_work

    cancel()
    assert lost and app.current_tray.master_label_code == ITEM  # kept: the app saw a failure
    cancel()

    [row] = _rows(app, event)
    assert _details(row)["idempotency_key"].startswith(key_prefix)
    assert row["timestamp"] == lost[0]["timestamp"]


def _rows_in(path, event):
    with open(path, encoding="utf-8-sig", newline="") as handle:
        return [row for row in csv.DictReader(handle) if row["event"] == event]


@pytest.mark.parametrize(("action", "event"), [("undo", "SCAN_UNDO"), ("reset", "TRAY_RESET")])
def test_cancellation_retried_after_a_restart_on_a_later_day_finds_its_first_row(
    flow, tmp_path, monkeypatch, action, event
):
    # Coordinator 09-29 (LM class): the first write landed in that day's file
    # but its acknowledgement was lost; a retry after a restart the next day
    # must not write the same event ID again, with another time, to the new file.
    first = flow(transition=True, root=tmp_path / "pc")
    first._process_barcode_logic(ITEM)
    _scan_products(first, 2)
    lost = []
    real = container_audit_module.append_event_log_entry_idempotent

    def losing(path, entry, *args, **kwargs):
        result = real(path, entry, *args, **kwargs)
        if entry["event"] == event and not lost:
            lost.append(entry)
            raise OSError("write acknowledgement lost")
        return result

    monkeypatch.setattr(container_audit_module, "append_event_log_entry_idempotent", losing)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *_a, **_k: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *_a, **_k: None)
    (first.undo_last_scan if action == "undo" else first.reset_current_work)()
    assert lost and first.current_tray.master_label_code == ITEM
    day_one = first.log_file_path

    restarted = _restart(flow, tmp_path / "pc", monkeypatch, transition=True)
    assert restarted.current_tray.scanned_barcodes == [f"{ITEM}-0001", f"{ITEM}-0002"]
    restarted.log_file_path = str(tmp_path / "pc" / "이적작업이벤트로그_tester_20991231.csv")
    (restarted.undo_last_scan if action == "undo" else restarted.reset_current_work)()

    [row] = _rows_in(day_one, event)
    assert row["timestamp"] == lost[0]["timestamp"]
    later = tmp_path / "pc" / "이적작업이벤트로그_tester_20991231.csv"
    assert not later.exists() or _rows_in(later, event) == []
    if action == "undo":
        assert restarted.current_tray.scanned_barcodes == [f"{ITEM}-0001"]
    else:
        assert restarted.current_tray.master_label_code == ""


def test_replacement_and_exchange_cancellations_carry_event_ids_and_retry_as_one_row(flow, monkeypatch):
    from product_exchange import ProductExchangeSession

    app = flow(transition=False)
    app.master_label_replace_state = "awaiting_old_completed"
    app.replacement_context = {"replacement_session_id": "replace-session-1"}
    assert app._log_master_label_replacement_cancel(reason="operator_cancel") is True
    assert app._log_master_label_replacement_cancel(reason="operator_cancel") is True  # the retry

    lost = []
    real = container_audit_module.append_event_log_entry_idempotent

    def losing(path, entry, *args, **kwargs):
        result = real(path, entry, *args, **kwargs)
        if entry["event"] == "PRODUCT_EXCHANGE_CANCELLED" and not lost:
            lost.append(entry)
            raise OSError("write acknowledgement lost")
        return result

    monkeypatch.setattr(container_audit_module, "append_event_log_entry_idempotent", losing)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *_a, **_k: None)
    app._update_action_button_states = lambda: None
    app.exchange_dialog = None
    session = ProductExchangeSession(item_code=ITEM, defective_barcodes=[f"{ITEM}-0001"])
    app.current_exchange_session = session
    assert app._finish_exchange_cancel_ui("operator_cancel") is False  # kept for the retry
    first_file = app.log_file_path
    app.log_file_path = str(Path(first_file).with_name("이적작업이벤트로그_tester_20991231.csv"))  # a later day
    app.current_exchange_session = session
    assert app._finish_exchange_cancel_ui("operator_cancel") is True
    later, app.log_file_path = app.log_file_path, first_file
    assert not Path(later).exists() or _rows_in(later, "PRODUCT_EXCHANGE_CANCELLED") == []

    [replace_cancel] = _rows(app, "HISTORICAL_REPLACE_CANCEL")
    assert _details(replace_cancel)["idempotency_key"].startswith("historical-replace-cancel:")
    [exchange_cancel] = _rows(app, "PRODUCT_EXCHANGE_CANCELLED")
    assert _details(exchange_cancel)["idempotency_key"].startswith("product-exchange-cancel:")


@pytest.mark.parametrize("kind", ["replacement", "exchange"])
def test_session_cancellation_retried_for_another_reason_keeps_its_first_row(flow, monkeypatch, kind):
    # sub-05 R12: the first cancel landed but its acknowledgement was lost; the
    # window close that retries it is the same cancellation - one ID, one row.
    from product_exchange import ProductExchangeSession

    event = "HISTORICAL_REPLACE_CANCEL" if kind == "replacement" else "PRODUCT_EXCHANGE_CANCELLED"
    app = flow(transition=False)
    lost = []
    real = container_audit_module.append_event_log_entry_idempotent

    def losing(path, entry, *args, **kwargs):
        result = real(path, entry, *args, **kwargs)
        if entry["event"] == event and not lost:
            lost.append(entry)
            raise OSError("write acknowledgement lost")
        return result

    monkeypatch.setattr(container_audit_module, "append_event_log_entry_idempotent", losing)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *_a, **_k: None)
    if kind == "replacement":
        app.master_label_replace_state = "awaiting_old_completed"
        app.replacement_context = {"replacement_session_id": "replace-session-2"}
        assert app._log_master_label_replacement_cancel(reason="operator_cancel") is False
        assert app._log_master_label_replacement_cancel(reason="app_close") is True
    else:
        app._update_action_button_states = lambda: None
        app.exchange_dialog = None
        session = ProductExchangeSession(item_code=ITEM, defective_barcodes=[f"{ITEM}-0001"])
        app.current_exchange_session = session
        assert app._finish_exchange_cancel_ui("operator_cancel") is False
        app.current_exchange_session = session
        assert app._finish_exchange_cancel_ui("app_close") is True

    [row] = _rows(app, event)
    assert row["timestamp"] == lost[0]["timestamp"]
    assert _details(row)["reason"] == "operator_cancel"


def test_on_old_v209_label_is_legacy(flow):
    app = flow(transition=True)

    app._process_barcode_logic(V209_QR)
    _scan_products(app, 2)

    [row] = _rows(app, "TRAY_COMPLETE")
    assert _details(row)["transition_class"] == "LEGACY"
    assert _details(row)["transfer_seal_status"] == "LEGACY_LOCAL_ONLY"


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
    assert app.work_summary[ITEM]["transition_counts"] == {"LEGACY": 1}


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


def test_on_completed_label_is_warned_and_recorded_as_a_duplicate_live_and_after_restart(
    flow, monkeypatch
):
    app = flow(transition=True)
    app._process_barcode_logic(OLD_QR)
    _scan_products(app, 1)
    _submit(app, monkeypatch)  # a partial old QR closes its label, as in v2.0.9

    app._process_barcode_logic(OLD_QR)
    assert app.current_tray.master_label_code == OLD_QR
    assert app.warnings[-1][0] == "현품표 중복 · 과도기 기록"
    _scan_products(app, 2, start=2)

    first, second = [_details(row) for row in _rows(app, "TRAY_COMPLETE")]
    assert first["transition_duplicate"] is False
    assert second["transition_duplicate"] is True
    assert second["transition_reasons"] == ["DUPLICATE_LABEL"]
    assert second["transfer_seal_intent_id"] != first["transfer_seal_intent_id"]
    assert app.work_summary[ITEM]["transition_duplicates"] == 1

    restarted = flow(transition=True)
    restarted.worker_name = "tester"
    restarted._load_session_state()
    assert restarted.work_summary[ITEM]["transition_counts"] == {"LEGACY": 2}
    assert restarted.work_summary[ITEM]["transition_duplicates"] == 1
    restarted._process_barcode_logic(OLD_QR)
    assert restarted.current_tray.transition_reasons == ["DUPLICATE_LABEL"]
    assert restarted.warnings[-1][0] == "현품표 중복 · 과도기 기록"


def test_off_still_refuses_a_completed_label(flow):
    app = flow(transition=False)
    app._remember_completed_master_label(COMPACT_QR)

    app._process_barcode_logic(COMPACT_QR)

    assert app.current_tray.master_label_code == ""
    assert app.warnings[-1][0] == "현품표 중복"


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
    assert restarted.work_summary[ITEM]["transition_counts"] == {"LEGACY": 1}
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
    assert app.work_summary[ITEM]["transition_counts"] == {"LEGACY": 2}


def test_on_legacy_label_takes_over_from_a_phs2_label_held_offline(tmp_path, monkeypatch):
    app, _client = _offline_queue_app(tmp_path, monkeypatch)
    app.legacy_label_transition = True
    store = app._preflight_hold_store()
    app._process_barcode_logic(f"{ITEM}-SERIAL-001")
    _pump_until(app.root, lambda: len(store.load().items) == 1)
    original = store.path.read_bytes()

    app._process_barcode_logic(ITEM)
    _pump_until(app.root, lambda: app.current_tray.master_label_code == ITEM)

    # The held PHS2 label waits unchanged; the legacy tray starts during the outage.
    waiting, = app._quarantined_preflight_holds()
    assert waiting.path.read_bytes() == original
    assert [
        event[1]["reason"] for event in app.events if event[0] == "PHS2_PREFLIGHT_HOLD_QUARANTINED"
    ] == ["offline_next_label"]
    assert app.current_tray.scanned_barcodes == []


def _phs2_tray(flow, root, *, transition):
    app = flow(transition=transition, client=BlockingClient(_resolved(count=2)), root=root)
    app._process_barcode_logic(COMPACT_QR)
    _pump_until(
        app.root,
        lambda: bool(app.current_tray.master_label_code)
        and not app._preflight_hold_store().exists()
        and not getattr(app, "_preflight_scan_input_locked", False),
    )
    assert app.current_tray.operation_lease_id
    app.seal_calls.clear()

    def acked_seal(**kwargs):
        # The real pre-command checks, then a command the fixture acknowledges.
        kwargs["coordinator"].preview(
            master_label=kwargs["source_label_payload"],
            master_label_fields=kwargs["source_label_fields"],
            item_id=kwargs["item_code"],
            scanned_barcodes=kwargs["scanned_barcodes"],
            operation_lease_id=kwargs["operation_lease_id"],
        )
        app.seal_calls.append(kwargs["source_label_payload"])
        return SealAttempt("intent-phs2", "ACKED", receipt_id="receipt-phs2")

    app._prepare_and_attempt_transfer_seal_snapshot = acked_seal
    app.current_tray.scanned_barcodes = [f"{ITEM}-SERIAL-001"]  # the lease's members
    app.current_tray.scan_times = [datetime.datetime.now()]
    return app


def _phs2_completion(flow, root, *, transition, last=f"{ITEM}-SERIAL-002"):
    app = _phs2_tray(flow, root, transition=transition)
    app.current_tray.scanned_barcodes.append(last)
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
    return completed, list(app.seal_calls), stable, app


TRANSITION_KEYS = {
    "transition_class", "transition_reasons", "transition_duplicate",
    "source_computer_id", "source_host_name", "app_version",
}


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_full_phs2_tray_takes_the_same_central_path_with_the_switch_on_or_off(flow, tmp_path):
    off_completed, off_seals, off_detail, _off = _phs2_completion(flow, tmp_path / "off", transition=False)
    on_completed, on_seals, on_detail, on_app = _phs2_completion(flow, tmp_path / "on", transition=True)

    assert (on_completed, on_seals) == (off_completed, off_seals) == ([True], [COMPACT_QR])
    assert {key: value for key, value in on_detail.items() if key not in TRANSITION_KEYS} == off_detail
    assert off_detail["transfer_seal_status"] == "ACKED"
    assert not TRANSITION_KEYS & set(off_detail)
    assert on_detail["transition_class"] == "PHS2_CENTRAL"
    assert on_detail["transition_reasons"] == []
    assert on_app.work_summary[ITEM]["transition_counts"] == {"PHS2_CENTRAL": 1}


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_on_phs2_tray_the_lease_refuses_before_any_command_completes_locally(flow, tmp_path):
    # A product outside the inspected members: the real seal coordinator refuses
    # it before a command; transition mode records it instead of stopping.
    completed, seal_calls, detail, app = _phs2_completion(
        flow, tmp_path / "on", transition=True, last=f"{ITEM}-OTHER-999",
    )

    assert completed == [True] and seal_calls == []
    assert detail["transition_class"] == "PHS2_LOCAL"
    assert detail["transition_reasons"] == ["BARCODE_NOT_IN_SOURCE_BUNDLE"]
    assert detail["transfer_seal_status"] == "PHS2_LOCAL_ONLY"
    assert _has_seal_intent(app) is False


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_on_phs2_lease_expiring_between_the_checks_still_completes_locally(flow, tmp_path):
    # sub-04 P2-1: the lease passed the preview but expired before prepare wrote
    # an intent; the first press completes the tray locally.
    app = _phs2_tray(flow, tmp_path / "on", transition=True)
    del app._prepare_and_attempt_transfer_seal_snapshot  # the real seal steps
    app.current_tray.scanned_barcodes.append(f"{ITEM}-SERIAL-002")
    app.current_tray.scan_times.append(datetime.datetime.now())
    coordinator = app.transfer_seal_coordinator
    # As the real constructor: the completion lane owns the seal coordinator.
    coordinator._owner_thread_id_provider = app._transfer_coordinator_owner_thread_id
    real_verify = coordinator._verified_operation_lease
    checks = []

    def expiring(**kwargs):
        checks.append(kwargs["lease_id"])
        if len(checks) > 1:
            raise TransferSealError("OPERATION_LEASE_EXPIRED", "fixture expiry")
        return real_verify(**kwargs)

    coordinator._verified_operation_lease = expiring
    completed = []
    assert app.request_complete_tray(completion_callback=completed.append) is True
    _pump_until(app.root, lambda: bool(completed))

    assert completed == [True] and len(checks) == 2
    [row] = _rows(app, "TRAY_COMPLETE")
    detail = _details(row)
    assert (detail["transition_class"], detail["transition_reasons"]) == (
        "PHS2_LOCAL", ["OPERATION_LEASE_EXPIRED"],
    )
    assert detail["transfer_seal_status"] == "PHS2_LOCAL_ONLY"
    assert _has_seal_intent(app) is False


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_partial_phs2_tray_is_refused_off_and_recorded_locally_on(flow, tmp_path, monkeypatch):
    off = _phs2_tray(flow, tmp_path / "off", transition=False)
    assert off.submit_current_tray() is None
    assert off.current_tray.master_label_code == COMPACT_QR
    assert "일부 제출할 수 없습니다" in off.statuses[-1][0]
    assert _rows(off, "TRAY_COMPLETE") == []

    on = _phs2_tray(flow, tmp_path / "on", transition=True)
    _submit(on, monkeypatch)
    [row] = _rows(on, "TRAY_COMPLETE")
    detail = _details(row)
    assert detail["transition_class"] == "PHS2_LOCAL"
    assert detail["transition_reasons"] == ["PARTIAL_TRANSFER"]
    assert detail["transfer_seal_status"] == "PHS2_LOCAL_ONLY"
    assert detail["is_partial_submission"] is True
    assert on.seal_calls == []


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (ConnectionError("fixture outage"), "PHS2_PREFLIGHT_UNAVAILABLE"),
        (TransferSealError("PHS2_SOURCE_NOT_INSPECTED", "fixture refusal"), "PHS2_SOURCE_NOT_INSPECTED"),
        # A server code outside the shared shape is recorded in it.
        (TransferSealError("phs2-source.not inspected", "fixture refusal"), "PHS2_SOURCE_NOT_INSPECTED"),
    ],
    ids=["offline", "refused", "server-code-shape"],
)
def test_on_phs2_label_the_central_check_blocks_becomes_a_local_tray_with_its_held_scans(
    flow, monkeypatch, error, reason
):
    gate = threading.Event()
    client = BlockingClient(_resolved(count=2), gate=gate, error=error)
    app = flow(transition=True, client=client)
    store = app._preflight_hold_store()

    app._process_barcode_logic(COMPACT_QR)
    assert client.started.wait(timeout=5)
    for index in (1, 2):
        app._process_barcode_logic(f"{ITEM}-SERIAL-{index:03d}")
    _pump_until(app.root, lambda: store.exists() and len(store.load().items) == 2)
    gate.set()
    _pump_until(
        app.root,
        lambda: len(app.current_tray.scanned_barcodes) == 2 and not store.exists(),
    )

    assert app.current_tray.master_label_code == COMPACT_QR
    assert app.current_tray.operation_lease_id == ""
    assert app.current_tray.transition_reasons == [reason]
    assert any(f"중앙 확인 실패({reason})" in status[0] for status in app.statuses)
    _submit(app, monkeypatch)

    [row] = _rows(app, "TRAY_COMPLETE")
    detail = _details(row)
    assert detail["transition_class"] == "PHS2_LOCAL"
    assert detail["transition_reasons"] == [reason, "PARTIAL_TRANSFER"]
    assert detail["product_barcodes"] == [f"{ITEM}-SERIAL-001", f"{ITEM}-SERIAL-002"]
    assert app.seal_calls == [] and _has_seal_intent(app) is False


def _restart(flow, root, monkeypatch, *, transition, client=None):
    app = flow(transition=transition, client=client, root=root)
    app.worker_name = "tester"
    app._load_session_state()
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *_a, **_k: True)
    app._load_current_tray_state()
    return app


@pytest.mark.parametrize(
    ("label", "expected"),
    [(ITEM, "LEGACY"), (OLD_QR, "LEGACY"), (COMPACT_QR.replace("PHS=2|", ""), "PHS2_MALFORMED")],
)
def test_round_started_on_completes_in_its_class_after_the_switch_is_turned_off(
    flow, tmp_path, monkeypatch, label, expected
):
    # 09-29 decision: a round keeps the class it got with the switch on; only a
    # round started with the switch off is strict.
    first = flow(transition=True, root=tmp_path / "pc")
    first._process_barcode_logic(label)
    _scan_products(first, 1)
    assert first.current_tray.transition_class == expected

    restarted = _restart(flow, tmp_path / "pc", monkeypatch, transition=False)
    assert restarted.current_tray.transition_class == expected
    _submit(restarted, monkeypatch)

    [row] = _rows(restarted, "TRAY_COMPLETE")
    detail = _details(row)
    assert detail["transition_class"] == expected
    assert detail["transfer_seal_status"] == label_qr.TRANSITION_LOCAL_SEAL_STATUS[expected]
    assert restarted.seal_calls == [] and _has_seal_intent(restarted) is False


@pytest.mark.parametrize("restart_on", [True, False], ids=["restart-on", "restart-off"])
def test_phs2_round_started_locally_never_reaches_the_central_path_later(
    flow, tmp_path, monkeypatch, restart_on
):
    # Started PHS2_LOCAL during an outage; restarted with the server back (and
    # the switch on or off) it completes locally without a central call.
    first = flow(
        transition=True,
        client=BlockingClient(_resolved(count=2), error=ConnectionError("fixture outage")),
        root=tmp_path / "pc",
    )
    first._process_barcode_logic(COMPACT_QR)
    _pump_until(
        first.root,
        lambda: bool(first.current_tray.master_label_code)
        and not first._preflight_hold_store().exists()
        and not getattr(first, "_preflight_scan_input_locked", False),
    )
    first._process_barcode_logic(f"{ITEM}-SERIAL-001")
    assert first.current_tray.transition_class == "PHS2_LOCAL"

    online = BlockingClient(_resolved(count=2))
    restarted = _restart(flow, tmp_path / "pc", monkeypatch, transition=restart_on, client=online)
    assert restarted.current_tray.scanned_barcodes == [f"{ITEM}-SERIAL-001"]
    _submit(restarted, monkeypatch)

    [row] = _rows(restarted, "TRAY_COMPLETE")
    detail = _details(row)
    assert (detail["transition_class"], detail["transfer_seal_status"]) == ("PHS2_LOCAL", "PHS2_LOCAL_ONLY")
    assert detail["transition_reasons"] == ["PHS2_PREFLIGHT_UNAVAILABLE", "PARTIAL_TRANSFER"]
    assert online.identities == [] and restarted.seal_calls == []
    assert _has_seal_intent(restarted) is False


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_phs2_round_refused_before_a_command_stays_local_after_a_failed_write_and_switch_off(
    flow, tmp_path, monkeypatch
):
    app = _phs2_tray(flow, tmp_path / "pc", transition=True)
    app.current_tray.scanned_barcodes.append(f"{ITEM}-OTHER-999")
    app.current_tray.scan_times.append(datetime.datetime.now())
    failed = []

    def failing(real):
        def append(path, entry, *args, **kwargs):
            if entry["event"] == "TRAY_COMPLETE" and not failed:
                failed.append(entry)
                raise OSError("fixture write failure")
            return real(path, entry, *args, **kwargs)
        return append

    for name in ("append_event_log_entry", "append_event_log_entry_idempotent"):
        monkeypatch.setattr(container_audit_module, name, failing(getattr(container_audit_module, name)))
    completed = []
    assert app.request_complete_tray(completion_callback=completed.append) is True
    _pump_until(app.root, lambda: bool(completed))
    assert completed == [False] and failed and _rows(app, "TRAY_COMPLETE") == []

    restarted = _restart(flow, tmp_path / "pc", monkeypatch, transition=False)
    assert restarted.current_tray.transition_class == "PHS2_LOCAL"
    completed = []
    assert restarted.request_complete_tray(completion_callback=completed.append) is True
    _pump_until(restarted.root, lambda: bool(completed))

    assert completed == [True]
    [row] = _rows(restarted, "TRAY_COMPLETE")
    detail = _details(row)
    assert (detail["transition_class"], detail["transfer_seal_status"]) == ("PHS2_LOCAL", "PHS2_LOCAL_ONLY")
    assert detail["transition_reasons"] == ["BARCODE_NOT_IN_SOURCE_BUNDLE"]
    # The retry is the same event: same ID and timestamp as the failed write.
    assert detail["idempotency_key"] == json.loads(failed[0]["details"])["idempotency_key"]
    assert row["timestamp"] == failed[0]["timestamp"]
    assert restarted.seal_calls == [] and _has_seal_intent(restarted) is False


def test_on_reasons_an_older_build_saved_are_recorded_in_the_code_shape(flow):
    # sub-05 P2-2: a tray saved before the shape rule completes with shaped codes.
    app = flow(transition=True)
    now = datetime.datetime.now()
    app.current_tray = TraySession(
        master_label_code=COMPACT_QR, item_code=ITEM, item_name="fixture item", tray_size=2,
        scanned_barcodes=[f"{ITEM}-0001", f"{ITEM}-0002"], scan_times=[now, now], start_time=now,
        transition_reasons=["temporary-unavailable"],
    )

    assert app.complete_tray() is True

    [row] = _rows(app, "TRAY_COMPLETE")
    detail = _details(row)
    assert (detail["transition_class"], detail["transition_reasons"]) == (
        "PHS2_LOCAL", ["TEMPORARY_UNAVAILABLE"],
    )


def test_transition_reason_codes_keep_the_shared_shape():
    assert label_qr.transition_reason_code("PHS2_SOURCE_NOT_INSPECTED") == "PHS2_SOURCE_NOT_INSPECTED"
    assert label_qr.transition_reason_code("phs2-source.not inspected") == "PHS2_SOURCE_NOT_INSPECTED"
    assert label_qr.transition_reason_code("서버 오류") == "UNKNOWN"


def test_on_duplicate_phs2_label_goes_local_without_a_central_call(flow, monkeypatch):
    client = BlockingClient(_resolved(count=2))
    app = flow(transition=True, client=client)
    app._remember_completed_master_label(COMPACT_QR)

    app._process_barcode_logic(COMPACT_QR)
    assert app.current_tray.master_label_code == COMPACT_QR
    assert app.warnings[-1][0] == "현품표 중복 · 과도기 기록"
    _scan_products(app, 2)
    _submit(app, monkeypatch)

    [row] = _rows(app, "TRAY_COMPLETE")
    detail = _details(row)
    assert detail["transition_class"] == "PHS2_LOCAL"
    assert detail["transition_reasons"] == ["DUPLICATE_LABEL", "PARTIAL_TRANSFER"]
    assert detail["transition_duplicate"] is True
    assert client.identities == [] and app.seal_calls == []


@pytest.mark.parametrize("label", [OTHER_ITEM, f"CLC={OTHER_ITEM}|QT=2"])
def test_on_label_of_an_unknown_item_starts_and_is_recorded_item_unconfirmed(flow, label):
    app = flow(transition=True)

    app._process_barcode_logic(label)
    assert app.current_tray.item_name == "품목 미확인"
    app.current_tray.tray_size = 2
    for index in (1, 2):
        app._process_barcode_logic(f"{OTHER_ITEM}-{index:04d}")

    [row] = _rows(app, "TRAY_COMPLETE")
    detail = _details(row)
    assert detail["transition_class"] == "LEGACY"
    assert detail["transition_reasons"] == ["ITEM_UNCONFIRMED"]
    assert detail["item_code"] == OTHER_ITEM


def test_off_still_refuses_a_label_of_an_unknown_item(flow):
    app = flow(transition=False)

    app._process_barcode_logic(COMPACT_QR.replace(ITEM, OTHER_ITEM))

    assert app.current_tray.master_label_code == ""
    assert app.warnings[-1][0] == "품목 없음"


def test_on_unconfirmed_catalog_keeps_phs2_off_the_central_path(flow, monkeypatch):
    client = BlockingClient(_resolved(count=2))
    app = flow(transition=True, client=client)
    app.item_catalog_unconfirmed = True

    app._process_barcode_logic(COMPACT_QR)
    assert app.current_tray.transition_reasons == ["ITEM_UNCONFIRMED"]
    _scan_products(app, 2)
    _submit(app, monkeypatch)

    [row] = _rows(app, "TRAY_COMPLETE")
    assert _details(row)["transition_class"] == "PHS2_LOCAL"
    assert _details(row)["transition_reasons"] == ["ITEM_UNCONFIRMED", "PARTIAL_TRANSFER"]
    assert client.identities == []


class _StartupApp:
    def __init__(self):
        self.root = type("Root", (), {"after": lambda *_args: None})()
        self.ran = False

    def run(self):
        self.ran = True


@pytest.mark.parametrize("transition", [True, False])
def test_catalog_failure_without_a_cache_starts_only_in_transition_mode(
    monkeypatch, tmp_path, transition
):
    calls = []
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.delenv("CONTAINER_AUDIT_DATA_ROOT", raising=False)
    monkeypatch.setenv(container_audit_module.ACTIVE_PATH_ENV, str(tmp_path / "stale.csv"))

    class Lease:
        def release(self):
            calls.append("release")

    monkeypatch.setattr(container_audit_module, "acquire_runtime_instance", lambda _root: Lease())
    monkeypatch.setattr(
        container_audit_module,
        "prepare_startup_item_catalog",
        lambda: (_ for _ in ()).throw(
            container_audit_module.ItemCatalogSyncError(
                "offline", cause_code="REQUEST_FAILED_NO_CACHE",
            )
        ),
    )
    monkeypatch.setattr(container_audit_module, "legacy_label_transition_enabled", lambda: transition)
    started = []
    monkeypatch.setattr(
        container_audit_module, "ContainerAudit", lambda: started.append(_StartupApp()) or started[-1]
    )
    for name in ("showerror", "showwarning"):
        monkeypatch.setattr(
            container_audit_module.messagebox, name,
            lambda title, message, _name=name: calls.append((_name, title, message)),
        )

    result = container_audit_module.main()

    dialogs = [call for call in calls if isinstance(call, tuple)]
    if transition:
        assert result == 0
        [app] = started
        assert app.ran is True and app.item_catalog_unconfirmed is True
        assert container_audit_module.ACTIVE_PATH_ENV not in container_audit_module.os.environ
        assert [(name, title) for name, title, _message in dialogs] == [
            ("showwarning", container_audit_module.ITEM_CATALOG_TRANSITION_WARNING_TITLE)
        ]
        assert "REQUEST_FAILED_NO_CACHE" in dialogs[0][2]
    else:
        assert result == container_audit_module.ITEM_CATALOG_STARTUP_EXIT_CODE
        assert started == []
        assert dialogs[0][:2] == ("showerror", container_audit_module.ITEM_CATALOG_STARTUP_ERROR_TITLE)
    assert calls[-1] == "release"


def test_on_member_coordinator_leaves_every_local_action_open_after_a_phs2_tray(
    flow, tmp_path, monkeypatch, fixed_operation_lease_clock
):
    # A PHS2 tray publishes its member snapshot; the legacy trays that follow
    # must still submit, undo, reset and park under the production coordinator.
    _completed, _seals, _detail, app = _phs2_completion(flow, tmp_path / "pc", transition=True)
    assert app._transfer_member_exchange_attempt_snapshot["master_label"] == COMPACT_QR
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *_a, **_k: True)

    app._process_barcode_logic(ITEM)
    _scan_products(app, 3, start=101)
    app.undo_last_scan()
    assert len(app.current_tray.scanned_barcodes) == 2
    assert app.park_current_tray(confirm=False) is True
    assert app.current_tray.master_label_code == ""

    app._process_barcode_logic(OLD_QR)
    _scan_products(app, 1, start=201)
    app.reset_current_work()
    assert app.current_tray.master_label_code == ""

    app._process_barcode_logic(ITEM)
    _scan_products(app, 1, start=301)
    _submit(app, monkeypatch)

    assert not any("이전 중앙 작업 처리 중" in status[0] for status in app.statuses)
    classes = [_details(row)["transition_class"] for row in _rows(app, "TRAY_COMPLETE")]
    assert classes == ["PHS2_CENTRAL", "LEGACY"]
    assert [row["event"] for row in _rows(app) if row["event"] in {"SCAN_UNDO", "TRAY_PARKED", "TRAY_RESET"}] == [
        "SCAN_UNDO", "TRAY_PARKED", "TRAY_RESET",
    ]


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
    app.work_summary = {ITEM: {
        "name": "fixture item", "count": 5, "test_count": 0,
        "transition_counts": {"PHS2_LOCAL": 1, "LEGACY": 3, "PHS2_MALFORMED": 1},
        "transition_duplicates": 1,
    }}
    app._insert_tree_row = lambda tree, *_args, values, **_kwargs: tree.rows.append(values)
    app.root = None

    app._update_summary_list()

    assert app.summary_tree.rows == [
        ("fixture item", ITEM, "5 (옛 3 · 새 로컬 1 · 새 형식오류 1 · 중복 1)")
    ]


# w9transitalign: Container_Audit and Label_Match record the same class and
# reasons for the same start label; both repositories carry this vector copy.
TRANSITION_VECTORS = json.loads(
    (Path(__file__).with_name("transition_label_vectors.json")).read_text(encoding="utf-8")
)


def _transition_start_text(raw):
    """The label text the transition start classifies, as _process_barcode_logic reads it."""
    barcode = label_qr.normalize_master_label_input(raw)
    return barcode if label_qr.parse_new_format_qr(barcode) else label_qr.decode_transition_label(barcode)


@pytest.mark.parametrize(
    "vector", TRANSITION_VECTORS["vectors"], ids=[row["id"] for row in TRANSITION_VECTORS["vectors"]],
)
def test_start_label_matches_the_shared_transition_table(vector):
    # Label_Match-only lineage shapes ("lm") never reach Container_Audit; the
    # shared rules classify them here as any other marked label.
    kind, reasons, item_code = label_qr.classify_transition_label(_transition_start_text(vector["raw"]))
    assert {"kind": kind, "reasons": list(reasons), "item_code": item_code} == vector["expected"]


@pytest.mark.parametrize(
    "case", TRANSITION_VECTORS["start_cases"], ids=[row["id"] for row in TRANSITION_VECTORS["start_cases"]],
)
def test_transition_start_records_the_shared_class_and_reasons(flow, case):
    client = BlockingClient(_resolved(count=2))
    app = flow(transition=True, client=client)
    _kind, _reasons, item_code = label_qr.classify_transition_label(case["raw"])
    app.items_data = (
        [{"Item Code": item_code or case["raw"], "Item Name": "item", "Spec": ""}]
        if case["item_known"] else []
    )
    app.item_catalog = None
    app.item_catalog_unconfirmed = not case["catalog_confirmed"]
    if case["duplicate"]:
        app._remember_completed_master_label(case["raw"])

    app._process_barcode_logic(case["raw"])

    if case.get("ca", {}).get("refused"):
        assert app.current_tray.master_label_code == "" and client.identities == []
        return
    assert app.current_tray.master_label_code == case["raw"]
    assert app.current_tray.transition_class == case["class"]
    assert app.current_tray.transition_reasons == case["reasons"]
    assert ("DUPLICATE_LABEL" in app.current_tray.transition_reasons) is case["duplicate"]
    assert client.identities == [] and app.seal_calls == []


def test_on_new_label_without_an_item_code_stops_only_that_label(flow):
    # No product passes the item check without an item code (missing_item_code),
    # so the start refuses this label only; Label_Match takes it (w9transitalign 4).
    client = BlockingClient(_resolved(count=2))
    app = flow(transition=True, client=client)

    app._process_barcode_logic("PHS=2|QT=2")

    assert app.current_tray.master_label_code == ""
    assert app.warnings[-1][0] == "QR코드 오류"
    app._process_barcode_logic(ITEM)
    assert app.current_tray.master_label_code == ITEM  # the next label starts


@pytest.mark.parametrize("encoded", [
    pytest.param(base64.b64encode(f"PHS=2|CLC={ITEM}|QT=2|PHS=1".encode()).decode(),
                 id="base64-strict-refused"),
    pytest.param(base64.b64encode(f"PHS=2|CLC={ITEM}|QT=2|X=??>".encode()).decode()
                 .replace("+", "-").replace("/", "_"), id="base64-url-safe"),
])
def test_on_scanner_base64_the_strict_decoder_leaves_is_read(flow, encoded):
    app = flow(transition=True)

    app._process_barcode_logic(encoded)

    assert app.current_tray.master_label_code.startswith(f"PHS=2|CLC={ITEM}|QT=2")
    assert app.current_tray.transition_class == "PHS2_MALFORMED"


def test_off_scanner_base64_the_strict_decoder_leaves_is_still_refused(flow):
    app = flow(transition=False)
    encoded = base64.b64encode(f"PHS=2|CLC={ITEM}|QT=2|PHS=1".encode()).decode()

    app._process_barcode_logic(encoded)

    assert app.current_tray.master_label_code == ""

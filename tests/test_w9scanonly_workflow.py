"""w9scanonly preparation: desired scanner workflow, intentionally RED on 37e70ae.

설계 초안 값 — 바뀔 수 있음: compact PHS2 gains QT; command cards are
KMCMD:EXCHANGE / KMCMD:UNDO. These tests change no production implementation.
Stage-local tests seed an active tray to expose later gaps independently of
the current seven-field rejection. Windows dialogs and transports are fakes;
the imported flow fixture keeps real JSON/SQLite/CSV persistence and cleanup.
"""
from __future__ import annotations

import datetime
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

import Container_Audit as ca
from Container_Audit import TraySession
from label_qr import parse_new_format_qr
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401
from tests.test_legacy_label_transition import flow, _details, _rows  # noqa: F401
from tests.test_phs2_master_preflight import (
    BlockingClient, COMPACT_QR, ITEM, OTHER_LABEL, _pump_until, _resolved,
)
from tests.test_transfer_background_retry import (
    _LeaseServer, _reset, _scan_label, _settle,
)
from transfer_seal import TransferSealCoordinator, TransferSealStore, TransferSealError, validate_compact_phs2_fields
from transfer_member_exchange import TransferMemberExchangeCoordinator, TransferMemberExchangeStore

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")


class WindowAttempt(RuntimeError):
    pass


@pytest.fixture
def windows(monkeypatch):
    calls = []

    def dialog(name):
        def record(*args, **kwargs):
            calls.append(name)
            return True
        return record

    for name in ("showinfo", "showwarning", "showerror", "askyesno",
                 "askokcancel", "askyesnocancel", "askretrycancel", "askquestion"):
        monkeypatch.setattr(ca.messagebox, name, dialog(name))

    def window(*args, **kwargs):
        calls.append("Toplevel")
        raise WindowAttempt("test intercepted a window before native creation")

    monkeypatch.setattr(ca.tk, "Toplevel", window)
    return calls


class OfflineSealClient(BlockingClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.authority_epoch = 1
        self.seal_requests = 0

    def seal_transfer(self, context):
        self.seal_requests += 1
        raise TransferSealError("TRANSPORT_ERROR", "synthetic offline seal", retryable=True)

    def get_receipt(self, *args, **kwargs):
        raise requests.ConnectionError("synthetic offline receipt")


def _active(flow, *, count=3, client=None):
    app = flow(transition=False, client=client or OfflineSealClient(_resolved(count)))
    app._process_barcode_logic(COMPACT_QR)
    _pump_until(app.root, lambda: bool(app.current_tray.master_label_code)
                and not app._preflight_context_blocks_mutation())
    assert app.current_tray.tray_size == count
    assert app.current_tray.operation_lease_id
    return app


def _own_coordinators_on_lane(app):
    """Build real stores with the lane owner; never disable an owner guard."""
    previous = app.transfer_seal_coordinator
    provider = app._transfer_coordinator_owner_thread_id
    app._explicit_transfer_coordinator_owner_thread_id_provider = provider
    store = TransferSealStore(previous.store.db_path, owner_thread_id_provider=provider)
    app.transfer_seal_coordinator = TransferSealCoordinator(
        store, previous.client, previous.operation_lease_manager,
        owner_thread_id_provider=provider)
    app.transfer_member_exchange_coordinator = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(store.db_path, owner_thread_id_provider=provider),
        previous.client, previous.operation_lease_manager,
        owner_thread_id_provider=provider)


@pytest.fixture
def scan_clock(monkeypatch):
    """App wall and monotonic clocks move explicitly; transport pumps stay real."""
    base = datetime.datetime.now()
    seconds = [0.0]

    class ScanDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            value = base + datetime.timedelta(seconds=seconds[0])
            return value if tz is None else value.replace(tzinfo=tz)

    date_proxy = SimpleNamespace(**vars(ca.datetime))
    date_proxy.datetime = ScanDateTime
    monkeypatch.setattr(ca, "datetime", date_proxy)
    time_proxy = SimpleNamespace(**vars(ca.time))
    time_proxy.monotonic = lambda: seconds[0]
    time_proxy.time = lambda: base.timestamp() + seconds[0]
    monkeypatch.setattr(ca, "time", time_proxy)
    return lambda advance: seconds.__setitem__(0, seconds[0] + advance)


@pytest.mark.parametrize("quantity", [1, 2, 60])
def test_seven_field_phs2_accepts_qt(quantity):
    fields = parse_new_format_qr(f"{COMPACT_QR}|QT={quantity}")
    assert fields and fields["QT"] == str(quantity)
    try:
        accepted = validate_compact_phs2_fields(fields)
    except TransferSealError as exc:
        pytest.fail(f"seven-field PHS2 must be accepted; rejected with {exc.code}: {exc.details}")
    assert accepted["QT"] == str(quantity)


def test_six_field_phs2_remains_accepted():
    assert validate_compact_phs2_fields(parse_new_format_qr(COMPACT_QR))["CLC"] == ITEM


@pytest.mark.parametrize("outage", ["disconnected", "unanswered"])
def test_strict_label_starts_immediately_with_qt_during_outage(flow, windows, outage):
    gate = threading.Event()
    client = BlockingClient(_resolved(2), gate=gate if outage == "unanswered" else None,
                            error=requests.ConnectionError("synthetic preflight outage"))
    app = flow(transition=False, client=client)
    qr = f"{COMPACT_QR}|QT=2"
    try:
        app._process_barcode_logic(qr)
        # No preflight callback/result is pumped before this observation.
        assert app.current_tray.master_label_code == qr, (
            "strict QT label must start before the central answer; "
            f"warnings={app.warnings!r}, pending={app._master_preflight_pending}"
        )
        assert app.current_tray.tray_size == 2
        app._process_barcode_logic(f"{ITEM}-SERIAL-001")
        app._process_barcode_logic(f"{ITEM}-SERIAL-002")
        assert len(_rows(app, "TRAY_COMPLETE")) == 1
        app._process_barcode_logic(f"{OTHER_LABEL}|QT=1")
        assert app.current_tray.master_label_code == f"{OTHER_LABEL}|QT=1"
        assert windows == []
    finally:
        gate.set()


def test_qt_tray_without_lease_completes_locally_at_target(flow, windows):
    app = flow(transition=False, client=OfflineSealClient(_resolved(2)))
    # Stage-local setup: the requested immediate-start state, without a
    # fabricated central lease, so QR-format rejection cannot hide this gap.
    qr = f"{COMPACT_QR}|QT=2"
    app.current_tray = TraySession(master_label_code=qr, item_code=ITEM,
        item_name="fixture item", item_spec="fixture spec", tray_size=2,
        start_time=datetime.datetime.now())
    for index in (1, 2):
        app._process_barcode_logic(f"{ITEM}-SERIAL-{index:03d}")
    completed = _rows(app, "TRAY_COMPLETE")
    assert len(completed) == 1, "QT target must produce a durable local completion without a lease"
    assert _details(completed[0])["scan_count"] == 2
    assert app.current_tray.master_label_code == ""
    assert windows == []


def test_unknown_membership_product_is_durably_accepted_below_target(flow, windows):
    app = flow(transition=False, client=OfflineSealClient(_resolved(2)))
    qr = f"{COMPACT_QR}|QT=2"
    app.current_tray = TraySession(master_label_code=qr, item_code=ITEM,
        item_name="fixture item", item_spec="fixture spec", tray_size=2,
        start_time=datetime.datetime.now())
    product = f"{ITEM}-UNCONFIRMED-001"
    app._process_barcode_logic(product)
    state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
    assert app.current_tray.scanned_barcodes == [product]
    assert state["scanned_barcodes"] == [product]
    assert len(_rows(app, "SCAN_OK")) == 1
    assert windows == []


def test_known_nonmember_is_rejected_on_its_scan(flow, windows):
    app = _active(flow)
    outsider = f"{ITEM}-SERIAL-999"
    app._process_barcode_logic(outsider)
    assert app.current_tray.scanned_barcodes == [], "known nonmember must never increase scan count"
    assert _rows(app, "SCAN_OK") == []
    assert app.warnings or _rows(app, "SCAN_FAIL_FORMAT")
    assert windows == []


def test_target_scan_already_auto_completes_durably_without_dialog(flow, windows):
    app = _active(flow, count=2)
    for index in (1, 2):
        app._process_barcode_logic(f"{ITEM}-SERIAL-{index:03d}")
    rows = _rows(app, "TRAY_COMPLETE")
    assert len(rows) == 1
    assert _details(rows[0])["scan_count"] == 2
    assert app.current_tray.master_label_code == ""
    assert app.total_tray_count == 1
    _pump_until(app.root, lambda: app.transfer_seal_coordinator.client.seal_requests == 1,
                phase="background seal after local completion")
    assert windows == []


def test_completion_and_next_label_do_not_wait_for_first_seal(flow, windows):
    gate, entered = threading.Event(), threading.Event()

    class DelayedSeal(OfflineSealClient):
        def seal_transfer(self, context):
            entered.set()
            # The test owns the release; this is transport latency, not a
            # timeout assertion on SQLite or the host's scheduling speed.
            assert gate.wait(10), "test did not release synthetic seal transport"
            return super().seal_transfer(context)

    app = _active(flow, count=2, client=DelayedSeal(_resolved(2)))
    _own_coordinators_on_lane(app)
    app.current_tray.scanned_barcodes = [f"{ITEM}-SERIAL-001", f"{ITEM}-SERIAL-002"]
    app.current_tray.scan_times = [datetime.datetime.now()] * 2
    results = []
    try:
        assert app.request_complete_tray(completion_callback=results.append)
        _pump_until(app.root, entered.is_set, phase="synthetic first seal admission")
        assert len(_rows(app, "TRAY_COMPLETE")) == 1, (
            "durable completion must already exist while the first seal is unanswered"
        )
        assert app.current_tray.master_label_code == "", "next-label input must be released before seal returns"
        app._process_barcode_logic(f"{OTHER_LABEL}|QT=1")
        assert app.current_tray.master_label_code == f"{OTHER_LABEL}|QT=1"
        assert windows == []
    finally:
        gate.set()
        _pump_until(app.root, lambda: bool(results), phase="owned completion cleanup")


def test_same_label_rescan_confirms_short_tray_without_dialog(flow, windows, scan_clock):
    app = _active(flow)
    app._process_barcode_logic(f"{ITEM}-SERIAL-001")
    scan_clock(4)
    app._process_barcode_logic(COMPACT_QR)
    rows = _rows(app, "TRAY_COMPLETE")
    assert rows == [], "held short completion must not enter the shared CSV"
    assert app._partial_submission_state() is not None
    assert app.current_tray.master_label_code == COMPACT_QR
    app._process_barcode_logic("")
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1
    assert app._short_confirmation_undo is None
    assert not app.current_tray.master_label_code
    assert windows == []


def test_exchange_card_replaces_one_scan_and_keeps_quantity_offline(flow, windows):
    app = _active(flow)
    old, new = f"{ITEM}-SERIAL-001", f"{ITEM}-SERIAL-999"
    app._process_barcode_logic(old)
    app._process_barcode_logic("KMCMD:EXCHANGE")
    app._process_barcode_logic(old)
    app._process_barcode_logic(new)
    _pump_until(app.root, lambda: app.current_tray.scanned_barcodes == [new],
                phase="durable inline exchange")
    assert app.current_tray.scanned_barcodes == [new], (
        "exchange card -> damaged scan -> replacement scan must replace, not append"
    )
    assert app.current_tray.tray_size == 3
    # This is a real store read, not a fake expected-intent list.
    store = app.transfer_member_exchange_coordinator.store
    from tk_serial_ui_lane import LaneTask
    pending = []
    lane = app._ui_task_lane()
    _pump_until(app.root, lambda: not lane.is_busy())
    assert lane.submit(LaneTask(name="exchange-evidence-read", generation=app._scan_callback_epoch,
        work=store.pending_ids, finish=pending.append, fail=lambda error: pytest.fail(str(error)))).accepted
    _pump_until(app.root, lambda: bool(pending))
    assert pending[0], "offline exchange must have a durable intent"
    # Coordinator follow-up: an unknown replacement scan registers GOOD;
    # exchange provenance includes the removed defective product.
    exchange_rows = _rows(app, "PRODUCT_EXCHANGE_COMPLETED")
    assert len(exchange_rows) == 1, "replacement GOOD registration must be auditable as an exchange"
    detail = _details(exchange_rows[0])
    assert detail["defective_barcodes"] == [old]
    assert detail["good_barcodes"] == [new]
    assert exchange_rows[0]["worker_name"] == app.worker_name
    assert exchange_rows[0]["timestamp"]
    assert windows == []


def test_exchange_button_enters_scan_mode_without_window(flow, windows):
    app = _active(flow)
    app._process_barcode_logic(f"{ITEM}-SERIAL-001")
    try:
        app.show_exchange_dialog()  # Existing product exchange button handler.
        _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())
    except WindowAttempt:
        pass
    assert windows == [], "exchange button must enter inline scanner mode with zero windows"


def test_undo_card_removes_last_scan(flow, windows):
    app = _active(flow)
    app._process_barcode_logic(f"{ITEM}-SERIAL-001")
    app._process_barcode_logic("KMCMD:UNDO")
    assert app.current_tray.scanned_barcodes == [], "undo card must remove the last accepted scan"
    assert len(_rows(app, "SCAN_UNDO")) == 1
    assert windows == []


def test_abandoned_lease_release_retries_after_app_restart(tmp_path, monkeypatch, flow):
    server = _LeaseServer()
    first = flow(transition=False, client=server, root=tmp_path)
    _scan_label(first)
    _own_coordinators_on_lane(first)
    first._startup_transfer_recovery_done = True
    server.up = False
    _reset(first, monkeypatch)
    _pump_until(first.root, lambda: len(server.releases) == 1)
    _settle(first)
    assert first._operation_lease_releases_waiting == 1
    before = dict(server.releases[0])
    first._ui_lane.close_idle()

    # Reuse only the on-disk root and server; none of the old app's RAM queues.
    restarted = flow(transition=False, client=server, root=tmp_path)
    _own_coordinators_on_lane(restarted)
    server.up = True
    restarted._startup_transfer_recovery_done = False
    restarted._startup_transfer_recovery_pending = True
    assert restarted._schedule_startup_transfer_recovery()
    _pump_until(restarted.root, lambda: restarted._startup_transfer_recovery_done
                and not restarted._ui_task_lane().is_busy())
    assert len(server.releases) == 2, "unanswered lease release must survive restart and resend in background"
    assert server.releases[1] == before
    assert server.lease_status == "RELEASED"


def test_same_label_with_zero_products_does_not_complete(flow, windows, scan_clock):
    app = _active(flow)
    scan_clock(4)
    app._process_barcode_logic(COMPACT_QR)
    assert _rows(app, "TRAY_COMPLETE") == []
    assert app.current_tray.master_label_code == COMPACT_QR
    assert windows == []


def test_product_between_same_labels_confirms_within_three_seconds(flow, windows, scan_clock):
    app = _active(flow)
    scan_clock(1)
    app._process_barcode_logic(f"{ITEM}-SERIAL-001")
    scan_clock(1)
    app._process_barcode_logic(COMPACT_QR)
    assert _rows(app, "TRAY_COMPLETE") == []
    assert app._partial_submission_state() is not None
    assert app.current_tray.master_label_code == COMPACT_QR
    app._process_barcode_logic("")
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1
    assert windows == []


def test_short_completion_has_explicit_shortage_notice(flow, windows, scan_clock):
    app = _active(flow)
    app._process_barcode_logic(f"{ITEM}-SERIAL-001")
    scan_clock(4)
    app._process_barcode_logic(COMPACT_QR)
    notice = app._warning_state_presenter().state.active_notice
    text = " ".join(str(args) for args in app.statuses)
    if notice is not None:
        text += f" {notice.title} {notice.message}"
    assert "부족 2개로 확정" in text, "short completion must show the shortage, distinct from full completion"
    assert windows == []


def test_partial_completion_can_be_undone_before_next_label(flow, windows):
    # Stage-local setup through the existing real legacy partial-completion
    # writer; strict PHS2 currently refuses partial completion upstream.
    app = flow(transition=True)
    label = f"CLC={ITEM}|QT=3"
    product = f"{ITEM}-SERIAL-001"
    app._process_barcode_logic(label)
    app._process_barcode_logic(product)
    before = Path(app.save_folder, app.CURRENT_TRAY_STATE_FILE).read_bytes()
    assert app._request_partial_submission()
    assert app._partial_submission_state() is not None
    assert app._continue_partial_submission()
    assert app.current_tray.master_label_code == label
    assert app.current_tray.scanned_barcodes == [product]
    assert Path(app.save_folder, app.CURRENT_TRAY_STATE_FILE).read_bytes() == before
    assert _rows(app, 'TRAY_COMPLETE') == []
    assert app.total_tray_count == 0
    assert not list(app._short_projection_path("unused").parent.glob("*.json"))
    assert windows == []


def test_short_csv_lost_ack_retries_same_row_before_settling(flow, windows, monkeypatch):
    app = flow(transition=True)
    app._process_barcode_logic(f"CLC={ITEM}|QT=3")
    app._process_barcode_logic(f"{ITEM}-SERIAL-001")

    original = app._log_stored_event
    lost = [True]
    def append_with_lost_ack(*args, **kwargs):
        result = original(*args, **kwargs)
        if args and args[0] == "TRAY_COMPLETE" and lost[0]:
            return False
        return result
    monkeypatch.setattr(app, "_log_stored_event", append_with_lost_ack)
    assert app._complete_current_tray_as_partial()
    completion_id = app._short_confirmation_undo["completion_id"]
    path = app._short_projection_path(completion_id)
    assert app._short_confirmation_undo is not None
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "SETTLING"
    assert len(_rows(app, "TRAY_COMPLETE")) == 1
    assert not app._undo_short_confirmation()
    assert len(_rows(app, "TRAY_COMPLETE")) == 1
    lost[0] = False
    assert app._commit_short_confirmation()
    assert app._short_confirmation_undo is None
    assert len(_rows(app, "TRAY_COMPLETE")) == 1
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "SETTLED"
    assert windows == []


def test_short_legacy_restart_projects_held_csv_once(flow, windows, tmp_path, scan_clock, monkeypatch):
    root = tmp_path / "restart"
    app = flow(transition=True, root=root)
    # The flow fixture names its CSV with the host day; this module freezes
    # the PC clock for signed leases, so use that same day for history.
    app.log_file_path = str(root / f"이적작업이벤트로그_tester_{ca.datetime.date.today():%Y%m%d}.csv")
    app._process_barcode_logic(f"CLC={ITEM}|QT=3")
    app._process_barcode_logic(f"{ITEM}-SERIAL-001")
    with monkeypatch.context() as fault:
        fault.setattr(app, "_settle_short_completion_projection", lambda *_a, **_k: False)
        assert app._complete_current_tray_as_partial()
    assert _rows(app, 'TRAY_COMPLETE') == []
    assert app._has_short_projection_recovery()
    # Crash after the held outbox write, before the completed tray's cleanup.
    path = app._short_projection_path(app._short_confirmation_undo["completion_id"])
    state = json.loads(path.read_text(encoding="utf-8"))["state"]
    assert app._save_tray_state_snapshot(state)
    # DESIGN 11-13: restart projects immediately after the 60-second grace;
    # an earlier restart must retain the remaining UNDO time.
    scan_clock(61)
    restarted = flow(transition=True, root=root)
    restarted._restore_tray_from_state(state)
    restarted._load_session_state()
    assert restarted.work_summary == {}
    result = restarted._recover_short_completion_projections(restarted.transfer_seal_coordinator)
    restarted._apply_short_projection_recovery(result)
    assert restarted.current_tray.master_label_code == ""
    assert restarted.work_summary[ITEM]["count"] == 1
    assert not (root / restarted.CURRENT_TRAY_STATE_FILE).exists()
    assert len(_rows(restarted, "TRAY_COMPLETE")) == 1
    assert not restarted._has_short_projection_recovery()
    again = restarted._recover_short_completion_projections(restarted.transfer_seal_coordinator)
    assert again["history"] is None
    assert len(_rows(restarted, "TRAY_COMPLETE")) == 1
    assert windows == []


def test_partial_confirmation_sound_differs_from_full_completion(flow, windows, monkeypatch, tmp_path):
    signals = []
    monkeypatch.setattr(ca.WavSound, "play",
        lambda sound, loops=0: signals.append((Path(sound.path).name, loops)))
    monkeypatch.setattr(ca.WavSound, "stop", lambda sound: None)
    full = flow(transition=False, client=OfflineSealClient(_resolved(2)), root=tmp_path / "full")
    full.success_sound = ca.WavSound("assets/success.wav")
    full._process_barcode_logic(COMPACT_QR)
    _pump_until(full.root, lambda: bool(full.current_tray.master_label_code)
                and not full._preflight_context_blocks_mutation())
    for index in (1, 2):
        full._process_barcode_logic(f"{ITEM}-SERIAL-{index:03d}")
    assert len(_rows(full, "TRAY_COMPLETE")) == 1
    full_signal = tuple(signals[-1:])
    assert full_signal

    # The existing legacy writer provides a real partial completion so that
    # strict PHS2's missing partial route cannot hide its missing feedback.
    partial = flow(transition=True, root=tmp_path / "partial")
    partial.success_sound = ca.WavSound("assets/success.wav")
    partial.error_sound = ca.WavSound("assets/error.wav")
    partial._process_barcode_logic(f"CLC={ITEM}|QT=3")
    partial._process_barcode_logic(f"{ITEM}-SERIAL-001")
    signals.clear()  # observe confirmation feedback separately from product acceptance
    assert partial._complete_current_tray_as_partial()
    assert len(_rows(partial, 'TRAY_COMPLETE')) == 1
    assert partial._short_confirmation_undo is None
    assert signals, "a durable partial confirmation must emit a distinct sound"
    assert tuple(signals) != full_signal
    assert windows == []

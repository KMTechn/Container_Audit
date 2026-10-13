import base64
import hashlib
import json
import queue
from pathlib import Path
from types import SimpleNamespace

import pytest

import label_qr
from Container_Audit import ContainerAudit, TraySession
from preflight_scan_hold import HOLD_LOOKUP_FAILED
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401
from tests.test_container_audit_contracts import _completion_app
from tests.test_phs2_master_preflight import (
    BlockingClient, COMPACT_QR, ITEM, ScheduledRoot, _app, _pump_until, _resolved,
)
from tray_state import tray_session_to_state
from transfer_client import LogisticsTransferClient
from transfer_common import TransferSealError
from tests.test_transfer_member_exchange import _runtime as exchange_runtime, _prepare as prepare_exchange
from tests.test_transfer_seal import (
    FakeResponse, TransferSealCoordinator, TransferSealStore,
    _client, _prepare as prepare_seal, _resolved_bundle, _LogisticsServer,
    _pending_with_command,
)


pytestmark = pytest.mark.usefixtures("owned_tk_workers")
REJECTION = "잔량표는 이적에 쓸 수 없습니다 — 검사실로 돌려보내세요"
CODE = "RESIDUAL_TAG_NOT_ALLOWED"
LEASE_PATH = "/logistics/api/v1/operation-leases/issue"
RESIDUAL_QR = (
    "PHS=2|SRC=KMTECH_RESIDUAL_TAG|ITG=RT00000012|CLC=RESIDUAL|"
    "LBL=RT00000012|HSH=" + "a" * 16
)


@pytest.fixture
def flow(tmp_path):
    def make(*, transition, client=None):
        app = _app(tmp_path, client or BlockingClient(_resolved(count=2)))
        for name, value in vars(_completion_app(tmp_path)).items():
            if name not in vars(app):
                setattr(app, name, value)
        app.legacy_label_transition = transition
        app.log_queue = queue.Queue()
        app.seal_calls = []
        return app
    return make


def _residual_inputs():
    fields = dict(part.split("=", 1) for part in RESIDUAL_QR.split("|"))
    return [
        RESIDUAL_QR,
        RESIDUAL_QR.replace("CLC=RESIDUAL", "CLC=" + ITEM),
        RESIDUAL_QR + "|QT=60",
        RESIDUAL_QR + "|SRC=KMTECH_INPUT_TAG",
        RESIDUAL_QR.replace("SRC=KMTECH_RESIDUAL_TAG", "src=kmtech_residual_tag"),
        base64.b64encode(RESIDUAL_QR.encode()).decode(),
        base64.urlsafe_b64encode(RESIDUAL_QR.encode()).decode().rstrip("="),
        json.dumps(fields),
        base64.b64encode(json.dumps(fields).encode()).decode(),
    ]


def _fingerprints(root):
    return {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(root).rglob("*") if p.is_file()}


@pytest.mark.parametrize("raw", _residual_inputs(), ids=[
    "printed", "catalog-item", "quantity", "duplicate-source", "case",
    "encoded", "urlsafe", "json", "encoded-json",
])
@pytest.mark.parametrize("transition", [False, True])
def test_residual_scan_rejects_before_work_or_records(tmp_path, raw, transition):
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession()
    app.legacy_label_transition = transition
    app.COLOR_DANGER = "danger"
    app.statuses, app.events, app.seal_calls = [], [], []
    app.log_queue = queue.Queue()
    app._operator_review_blocks_mutation = lambda: False
    app.show_status_message = lambda *args, **_kwargs: app.statuses.append(args)
    app.transfer_seal_coordinator = SimpleNamespace(client=SimpleNamespace(identities=[]))
    def ordinary_reader(*_args):
        pytest.fail("residual tag reached ordinary QR processing")
    app._parse_new_format_qr = ordinary_reader
    source = tmp_path / "original.json"
    source.write_text("{}", encoding="utf-8")
    before = _fingerprints(tmp_path)
    app.beeps = []
    app._start_warning_beep = lambda: app.beeps.append(True)
    app._process_barcode_logic(raw)
    assert app.statuses and app.statuses[-1][0] == REJECTION
    assert app.beeps == [True]
    assert not app.current_tray.master_label_code
    assert not app.seal_calls
    assert not app.transfer_seal_coordinator.client.identities
    assert app.log_queue.empty()
    assert not app.events
    assert before == _fingerprints(tmp_path)


@pytest.mark.parametrize("transition", [False, True])
@pytest.mark.parametrize("active", [False, True])
def test_residual_scan_preserves_full_app_state_and_stores(flow, transition, active):
    app = flow(transition=transition)
    if active:
        app.current_tray = TraySession(master_label_code=COMPACT_QR, item_code=ITEM,
            scanned_barcodes=["held-product"], tray_size=60)
    original_tray = app.current_tray
    original_state = tray_session_to_state(original_tray, worker_name=app.worker_name)
    before = _fingerprints(app.save_folder)
    app._start_warning_beep = lambda: None
    app._process_barcode_logic(RESIDUAL_QR)
    assert app.statuses and app.statuses[-1][0] == REJECTION
    assert app.current_tray is original_tray
    assert tray_session_to_state(app.current_tray, worker_name=app.worker_name) == original_state
    assert _fingerprints(app.save_folder) == before
    assert not app.events
    assert not app.transfer_seal_coordinator.client.identities
    assert app.log_queue.empty()


@pytest.mark.parametrize("pending", ["lookup", "save", "choice"])
def test_entry_rejects_before_pending_scan_queue(flow, pending):
    app = flow(transition=True)
    app._start_warning_beep = lambda: None
    app.scan_entry = SimpleNamespace(get=lambda: RESIDUAL_QR, delete=lambda *_: None)
    app._clear_consumed_scan_entry = lambda *_: True
    app._master_preflight_pending = pending == "lookup"
    app._live_scan_save_pending = pending == "save"
    app._inline_scan_choices = [object()] if pending == "choice" else []
    calls = []
    app._hold_scan_during_preflight = lambda *_a, **_k: calls.append("hold")
    app._hold_or_refuse_entry_scan = lambda *_a, **_k: calls.append("queue")
    app._continue_after_inline_choice = lambda: calls.append("choice")
    app.process_barcode()
    assert app.statuses and app.statuses[-1][0] == REJECTION
    assert calls == []
    assert not app.current_tray.master_label_code


@pytest.mark.parametrize("entrance", ["steps", "activation", "preflight", "state", "parked", "hold", "startup", "quarantine", "hold-scan"])
def test_residual_recovery_and_direct_entrances_preserve_originals(flow, tmp_path, entrance):
    app = flow(transition=True)
    app._start_warning_beep = lambda: None
    original_tray = app.current_tray
    state = tray_session_to_state(TraySession(master_label_code=RESIDUAL_QR, item_code=ITEM, tray_size=60), worker_name=app.worker_name)
    source = tmp_path / "parked" / "residual.json"
    source.parent.mkdir(exist_ok=True)
    source.write_text(json.dumps(state), encoding="utf-8")
    original = source.read_bytes()
    if entrance == "steps":
        app._run_durable_ui_steps(app._process_barcode_steps(RESIDUAL_QR))
    elif entrance == "activation":
        app._activate_master_label_tray(barcode=RESIDUAL_QR, item_code=ITEM,
            tray_quantity=60, matched_item=app.items_data[0], event_name="MASTER_LABEL_SCANNED_NEW", event_detail={})
    elif entrance == "preflight":
        app._begin_compact_phs2_preflight(barcode=RESIDUAL_QR,
            qr_data=dict(part.split("=", 1) for part in RESIDUAL_QR.split("|")), matched_item=app.items_data[0])
    elif entrance == "state":
        app._restore_tray_from_state(state)
    elif entrance == "parked":
        app.restore_parked_tray(str(source))
    elif entrance in {"hold", "quarantine"}:
        store = app._preflight_hold_store()
        store.start(worker=app.worker_name, master_raw=RESIDUAL_QR, scan_epoch=1)
        original_hold = store.path.read_bytes()
        if entrance == "hold":
            app._restore_preflight_scan_hold()
        else:
            app._is_preflight_hold_quarantine_path = lambda _path: True
            app._admin_pin_store = lambda: pytest.fail("residual tag reached administrator storage")
            app._run_durable_ui_steps(app._restore_quarantined_preflight_hold_steps(str(store.path)))
        assert store.path.read_bytes() == original_hold
    elif entrance == "startup":
        app.CURRENT_TRAY_STATE_FILE = "current.json"
        Path(app.save_folder, app.CURRENT_TRAY_STATE_FILE).write_bytes(original)
        app._load_current_tray_state(_recovery_choice=True)
        assert Path(app.save_folder, app.CURRENT_TRAY_STATE_FILE).read_bytes() == original
    else:
        app._hold_scan_during_preflight(RESIDUAL_QR)
    assert app.current_tray is original_tray
    assert not app.current_tray.master_label_code
    assert source.read_bytes() == original
    assert app.statuses and app.statuses[-1][0] == REJECTION
    assert not app.seal_calls
    assert not app.transfer_seal_coordinator.client.identities
    assert app.log_queue.empty()


@pytest.mark.parametrize("transition", [False, True])
def test_server_residual_rejection_is_final_and_never_retried(flow, transition):
    client = BlockingClient(_resolved(), error=TransferSealError(CODE, REJECTION, status_code=409, retryable=False))
    app = flow(transition=transition, client=client)
    app._start_warning_beep = lambda: None
    app._process_barcode_logic(COMPACT_QR)
    _pump_until(app.root, lambda: not app._master_preflight_pending)
    _pump_until(app.root, lambda: app._preflight_hold_store().exists() and app._preflight_hold_store().load().state == HOLD_LOOKUP_FAILED)
    snapshot = app._preflight_hold_store().load()
    assert snapshot.error_code == CODE
    assert not app.current_tray.master_label_code
    assert app.statuses[-1][0] == REJECTION
    assert len(client.identities) == 1
    app._acknowledge_active_notice()
    app._process_barcode_logic(COMPACT_QR)
    app._restore_preflight_scan_hold()
    # The hold writer pump reschedules itself forever: drain every other job, bounded.
    for _ in range(500):
        if not [job for job in app.root.jobs if getattr(job[2], "__name__", "") != "_pump"]:
            break
        app.root.run_next()
    else:
        pytest.fail("jobs other than the hold writer pump kept rescheduling")
    assert len(client.identities) == 1
    assert not app.current_tray.master_label_code
    assert not app.seal_calls


@pytest.mark.parametrize("status,allow_not_found", [(200, False), (404, True), (409, False), (503, False)])
def test_wire_client_preserves_terminal_residual_contract(status, allow_not_found):
    calls = []
    def request(method, url, **_kwargs):
        calls.append((method, url))
        return SimpleNamespace(status_code=status, json=lambda: {
            "ok": False, "retryable": False,
            "error": {"code": CODE, "message": REJECTION},
        })
    client, _session = _client(lambda _call: None)
    client.session = SimpleNamespace(request=request)
    with pytest.raises(TransferSealError) as raised:
        client._request("POST", LEASE_PATH, payload={}, allow_not_found=allow_not_found)
    assert raised.value.code == CODE
    assert raised.value.retryable is False
    assert raised.value.committed is False
    assert client.server_unanswered() is False
    assert len(calls) == 1


def test_ordinary_labels_keep_existing_parsing():
    assert label_qr.parse_new_format_qr(COMPACT_QR)["SRC"] == "KMTECH_INPUT_TAG"
    ordinary = [COMPACT_QR, ITEM, "KMCMD:UNDO", "제품", json.dumps(
        {"PHS": "1", "CLC": ITEM, "SPC": "보통 현품표"}, ensure_ascii=False),
        RESIDUAL_QR.replace("KMTECH_RESIDUAL_TAG", "KMTECH_RESIDUAL_TAG_OTHER")]
    assert all(not label_qr.is_residual_tag(raw) for raw in ordinary)


@pytest.mark.parametrize("kind", ["seal", "exchange"])
def test_residual_error_code_is_terminal_without_http_status(tmp_path, kind):
    if kind == "seal":
        client, _session = _client(lambda _call: FakeResponse(200, {"ok": True, "data": _resolved_bundle()}))
        coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
        prepared = prepare_seal(coordinator)
    else:
        coordinator, _posted, _session = exchange_runtime(tmp_path)
        prepared = prepare_exchange(coordinator)
    row = coordinator.store.record_error(prepared.intent_id, TransferSealError(CODE, REJECTION, retryable=False))
    assert row["status"] == "OPERATOR_REVIEW"
    assert prepared.intent_id not in coordinator.store.pending_ids()


def test_server_rejection_stops_requery_before_local_failure_is_saved():
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession()
    app.root = ScheduledRoot()
    app._master_preflight_epoch = 1
    app._master_preflight_pending = True
    app.legacy_label_transition = True
    app.COLOR_DANGER = "danger"
    app.statuses = []
    app._start_warning_beep = lambda: None
    app.show_status_message = lambda *args, **_kwargs: app.statuses.append(args)
    delayed = []
    app._mark_preflight_hold_failed = delayed.append
    def unsafe_activation(*_args):
        pytest.fail("server rejection reached local activation")
    app._start_transition_tray_after_preflight_failure = unsafe_activation
    result = queue.Queue()
    result.put((False, None, "", TransferSealError(CODE, REJECTION, retryable=False)))
    app._poll_compact_phs2_preflight(1, COMPACT_QR, {}, {}, result)
    assert delayed == [CODE]
    assert app._master_preflight_pending is False
    assert app.statuses[-1][0] == REJECTION
    app._process_barcode_logic(COMPACT_QR)
    assert not app.current_tray.master_label_code
    other = COMPACT_QR.replace("ITG=", "ITG=other-")
    result.put((False, None, "", TransferSealError(CODE, REJECTION, retryable=False)))
    app._master_preflight_epoch = 3
    app._master_preflight_pending = True
    app._poll_compact_phs2_preflight(3, other, {}, {}, result)
    app._process_barcode_logic(COMPACT_QR)
    assert app.statuses[-1][0] == REJECTION


def test_rejected_durable_exchange_does_not_resend_on_direct_attempt(tmp_path):
    coordinator, posted, session = exchange_runtime(tmp_path,
        replace_error=TransferSealError(CODE, REJECTION, retryable=False))
    prepared = prepare_exchange(coordinator)
    first = coordinator.attempt(prepared.intent_id)
    assert first.status == "OPERATOR_REVIEW"
    assert len(posted) == 1
    before = len(session.calls)
    coordinator.attempt(prepared.intent_id)
    assert len(session.calls) == before
    assert len(posted) == 1


def test_rejected_durable_seal_does_not_recheck_or_retry(tmp_path):
    client, session = _client(_LogisticsServer())
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _pending_with_command(coordinator, "residual")
    coordinator.store.record_error(prepared.intent_id, TransferSealError(CODE, REJECTION, status_code=409, retryable=False))
    before = len(session.calls)
    coordinator.recheck_operator_review_receipt(prepared.intent_id)
    assert len(session.calls) == before
    with pytest.raises(TransferSealError) as raised:
        coordinator.retry_operator_review(prepared.intent_id, supervisor="reviewer",
            authorize=lambda: True, record_audit=lambda _event: pytest.fail("terminal rejection reached retry audit"))
    assert raised.value.code == "TRANSFER_REVIEW_RETRY_NOT_AVAILABLE"
    assert len(session.calls) == before

"""A refused central lease holds only its tray, with durable scanner input."""
import json
import threading
from pathlib import Path

import pytest

import Container_Audit as ca
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401
from tests.test_legacy_label_transition import flow, _rows  # noqa: F401
from tests.test_phs2_master_preflight import COMPACT_QR, OTHER_LABEL, _pump_until, _resolved, _sha256
from tests.test_w9scanonly_workflow import OfflineSealClient, windows  # noqa: F401
from transfer_seal import TransferSealError, TransferSealCoordinator

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")
REFUSAL = "OPERATION_RESOURCE_ALREADY_LEASED"
GUIDANCE = "이 현품표는 다른 이적 PC 가 작업 중입니다 — 한 현품표는 한 PC 에서"


class RefusedClient(OfflineSealClient):
    def issue_operation_lease(self, **request):
        self.calls = getattr(self, "calls", 0) + 1
        # The authentic snapshot must describe the seven-field printed label.
        # A six-field fixture would fail QT validation before lease recovery.
        def bind_qr(value):
            if isinstance(value, dict):
                return {key: bind_qr(child) for key, child in value.items()}
            if isinstance(value, list):
                return [bind_qr(child) for child in value]
            return request["scan_payload"] if value == COMPACT_QR else value
        self.response = bind_qr(self.response)
        source = self.response["work_group_source"]
        self.response["topology_hash"] = source["topology_hash"] = _sha256({
            "phs_work_group": self.response["phs_work_group"],
            "source_bundles": source["source_bundles"],
            "remainder_cover_groups": source["remainder_cover_groups"],
            "source_iin": source["source_iin"],
            "barcode_membership_hash": source["barcode_membership_hash"],
            "transfer_bundle_id": source["transfer_bundle_id"],
        })
        return super().issue_operation_lease(**request)


def _start(flow, *, code=REFUSAL, gate=None):
    client = RefusedClient(_resolved(3), gate=gate,
        error=TransferSealError(code, "synthetic refusal", retryable=True))
    app = flow(transition=False, client=client)
    app._process_barcode_logic(COMPACT_QR + "|QT=3")
    _pump_until(app.root, lambda: bool(app.current_tray.master_label_code)
                and not app._scanonly_transport_lane().is_busy())
    return app, client


def _settle(app):
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy()
                and not app._scanonly_transport_lane().is_busy())


def test_refused_lease_preserves_scan_without_count_or_completion(flow, windows):
    app, client = _start(flow)
    member = _resolved(3)["work_group_source"]["members"][0]["normalized_barcode"]
    app._process_barcode_logic(member)
    _settle(app)
    saved = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
    assert saved["scanned_barcodes"] == []
    assert saved["operation_lease_hold"]["items"][0]["raw_barcode"] == member
    assert GUIDANCE in str(app.statuses)
    assert app.current_item_label["text"] == GUIDANCE
    app.show_exchange_dialog()
    assert not app.request_complete_tray()
    assert not app.complete_tray()
    assert not _rows(app, "TRAY_COMPLETE")
    assert not app._scanonly_lookup_jobs
    assert client.calls == 1
    assert windows == []


@pytest.mark.parametrize("code", ["TRANSPORT_ERROR", "SERVER_ERROR", "OPERATION_LEASE_SNAPSHOT_CONFLICT"])
def test_other_lookup_errors_keep_background_retry(flow, windows, code):
    app, _client = _start(flow, code=code)
    assert app._scanonly_lookup_jobs
    assert not getattr(app.current_tray, "operation_lease_hold", {})
    assert getattr(app, "_scanonly_transport_retry_job", None)


def test_same_label_rechecks_and_replays_held_scan_after_release(flow, windows, monkeypatch):
    app, client = _start(flow)
    errors = set()
    original = TransferSealCoordinator.prefetch_scan_label
    def observed(coordinator, *args, **kwargs):
        try:
            return original(coordinator, *args, **kwargs)
        except Exception as exc:
            errors.add(getattr(exc, "code", type(exc).__name__))
            raise
    monkeypatch.setattr(TransferSealCoordinator, "prefetch_scan_label", observed)
    member = _resolved(3)["work_group_source"]["members"][0]["normalized_barcode"]
    app._process_barcode_logic(member)
    _settle(app)
    client.error = None
    app._process_barcode_logic(COMPACT_QR + "|QT=3")
    try:
        _pump_until(app.root, lambda: bool(app.current_tray.operation_lease_id)
                    and app.current_tray.scanned_barcodes == [member])
    except AssertionError:
        pytest.fail("Recovery errors: " + str(sorted(errors)))
    _settle(app)
    assert client.calls == 2
    assert len(_rows(app, "SCAN_OK")) == 1
    assert not _rows(app, "TRAY_COMPLETE")
    assert windows == []


def test_refused_tray_can_be_parked_while_another_label_continues(flow, windows):
    app, client = _start(flow)
    member = _resolved(3)["work_group_source"]["members"][0]["normalized_barcode"]
    app._process_barcode_logic(member)
    _settle(app)
    assert app.park_current_tray(confirm=False)
    client.error = None
    app._process_barcode_logic(OTHER_LABEL + "|QT=3")
    assert app.current_tray.master_label_code == OTHER_LABEL + "|QT=3"
    app._process_barcode_logic(member)
    assert app.current_tray.scanned_barcodes == [member]
    parked = app._parked_store().list_for_worker(app.worker_name)
    assert len(parked) == 1
    saved = app._parked_store().load(parked[0].path)
    assert saved["operation_lease_hold"]["items"][0]["raw_barcode"] == member
    assert windows == []


def test_refusal_arriving_after_a_product_save_blocks_short_completion(flow, windows):
    gate = threading.Event()
    client = RefusedClient(_resolved(3), gate=gate,
        error=TransferSealError(REFUSAL, "synthetic refusal"))
    app = flow(transition=False, client=client)
    app._process_barcode_logic(COMPACT_QR + "|QT=3")
    assert client.started.wait(2)
    member = _resolved(3)["work_group_source"]["members"][0]["normalized_barcode"]
    app._process_barcode_logic(member)
    gate.set()
    _settle(app)
    app._last_scan_input = ("", float("-inf"))
    app._process_barcode_logic(COMPACT_QR + "|QT=3")
    _settle(app)
    assert not _rows(app, "TRAY_COMPLETE")
    assert not app.current_tray.is_partial_submission
    assert app.current_tray.master_label_code == COMPACT_QR + "|QT=3"
    assert not getattr(app, "_short_confirmation_undo", None)


def test_replay_retries_the_frozen_scan_audit_after_lost_ack(flow, windows, monkeypatch):
    app, client = _start(flow)
    member = _resolved(3)["work_group_source"]["members"][0]["normalized_barcode"]
    app._process_barcode_logic(member)
    _settle(app)
    project = app._project_stored_audit_event
    attempts = []
    def lost_ack(event, **kwargs):
        result = project(event, **kwargs)
        attempts.append(event)
        return False if len(attempts) == 1 else result
    monkeypatch.setattr(app, "_project_stored_audit_event", lost_ack)
    client.error = None
    app._process_barcode_logic(COMPACT_QR + "|QT=3")
    _pump_until(app.root, lambda: bool(app.current_tray.operation_lease_id)
                and not app._operation_lease_hold_blocks_scan())
    _settle(app)
    assert len(attempts) >= 2
    assert attempts[0] == attempts[1]
    assert app.current_tray.scanned_barcodes == [member]
    assert len(_rows(app, "SCAN_OK")) == 1


def test_refused_checkpoint_restores_the_hold_and_its_input(flow, windows):
    app, client = _start(flow)
    member = _resolved(3)["work_group_source"]["members"][0]["normalized_barcode"]
    app._process_barcode_logic(member)
    _settle(app)
    saved = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
    app._restore_tray_from_state(saved)
    assert app._operation_lease_hold_blocks_scan()
    assert not app.current_tray.scanned_barcodes
    client.error = None
    app._process_barcode_logic(COMPACT_QR + "|QT=3")
    _pump_until(app.root, lambda: app.current_tray.scanned_barcodes == [member])
    _settle(app)


def test_late_refusal_updates_only_the_parked_round(flow, windows):
    gate = threading.Event()
    client = RefusedClient(_resolved(3), gate=gate,
        error=TransferSealError(REFUSAL, "synthetic refusal", status_code=409))
    app = flow(transition=False, client=client)
    app._process_barcode_logic(COMPACT_QR + "|QT=3")
    assert client.started.wait(2)
    try:
        assert app.park_current_tray(confirm=False)
    finally:
        gate.set()
    _settle(app)
    parked = app._parked_store().list_for_worker(app.worker_name)
    assert len(parked) == 1
    _pump_until(app.root, lambda: "operation_lease_hold" in app._parked_store().load(parked[0].path))
    saved = app._parked_store().load(parked[0].path)
    assert saved["operation_lease_hold"]["error_code"] == REFUSAL
    assert not app._operation_lease_hold_blocks_scan()


def _six_field_refusal(flow):
    client = RefusedClient(_resolved(3), error=TransferSealError(REFUSAL,
        "synthetic refusal", status_code=409))
    app = flow(transition=False, client=client)
    app._process_barcode_logic(COMPACT_QR)
    _pump_until(app.root, lambda: getattr(getattr(app, "_preflight_hold_snapshot", None), "error_code", "") == REFUSAL
                and app._preflight_hold_snapshot.state == ca.HOLD_LOOKUP)
    return app, client


def test_six_field_refusal_rechecks_the_same_label_and_replays(flow, windows):
    app, client = _six_field_refusal(flow)
    member = _resolved(3)["work_group_source"]["members"][0]["normalized_barcode"]
    app._process_barcode_logic(member)
    _pump_until(app.root, lambda: len(app._preflight_hold_snapshot.items) == 1)
    assert GUIDANCE in str(app.statuses)
    assert not getattr(app, "_master_preflight_retry_job", None)
    client.error = None
    app._process_barcode_logic(COMPACT_QR)
    _pump_until(app.root, lambda: app.current_tray.scanned_barcodes == [member])
    assert app.current_tray.operation_lease_id
    assert windows == []


@pytest.mark.parametrize("problem", ["changed", "manager_held", "invalid"])
def test_late_refusal_preserves_a_protected_parked_original(flow, windows, problem):
    app, _client = _start(flow)
    _settle(app)
    assert app.park_current_tray(confirm=False)
    store = app._parked_store()
    path = store.list_for_worker(app.worker_name)[0].path
    state = store.load(path)
    if problem == "manager_held":
        store.manager_hold_path(path).write_text("{}", encoding="utf-8")
    if problem == "invalid":
        state["tray_size"] = 0
        path.write_text(json.dumps(state), encoding="utf-8")
    before = path.read_bytes()
    expected = dict(state, stopwatch_seconds=state["stopwatch_seconds"] + 1) if problem == "changed" else state
    with pytest.raises(FileExistsError):
        store.save_state(state, worker_name=app.worker_name, master_label=state["master_label_code"], expected_state=expected)
    assert path.read_bytes() == before


def test_six_field_refusal_allows_a_different_label(flow, windows):
    app, _client = _six_field_refusal(flow)
    app._process_barcode_logic(OTHER_LABEL + "|QT=3")
    _pump_until(app.root, lambda: app.current_tray.master_label_code == OTHER_LABEL + "|QT=3")
    assert not app._operation_lease_hold_blocks_scan()
    assert len(app._offline_waiting_preflight_holds()) == 1
    assert windows == []

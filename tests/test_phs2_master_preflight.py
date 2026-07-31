import queue
import threading
import time
from types import SimpleNamespace

import pytest
from Container_Audit import ContainerAudit, TraySession
from item_catalog import ItemCatalog
from transfer_seal import membership_hash


ITEM = "AAA2270730100"
INPUT_TAG = "ITAG-COMPACT-001"
LABEL_ID = "LBL-COMPACT-001"
LABEL_HASH = "a" * 64
CORE_HASH = "b" * 64
HASH_PREFIX = LABEL_HASH[:16]
COMPACT_QR = (
    f"PHS=2|SRC=KMTECH_INPUT_TAG|ITG={INPUT_TAG}|CLC={ITEM}|"
    f"LBL={LABEL_ID}|HSH={HASH_PREFIX}"
)
GOAL_ITEM = "AAA2270730200"
GOAL_INPUT_TAG = "ITAG-20260727-170859-F6EAEC"
GOAL_LABEL_ID = "LBL-20260727-170859-437CA6"
GOAL_PHS2 = (
    "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-20260727-170859-F6EAEC|"
    "CLC=AAA2270730200|LBL=LBL-20260727-170859-437CA6|"
    "HSH=257f29e4f09d392e"
)


class ScheduledRoot:
    def __init__(self):
        self.jobs = []
        self.cancelled = []

    def after(self, delay, callback, *args):
        job = f"job-{len(self.jobs) + 1}"
        self.jobs.append((job, delay, callback, args))
        return job

    def after_cancel(self, job):
        self.cancelled.append(job)

    def run_next(self):
        _job, _delay, callback, args = self.jobs.pop(0)
        callback(*args)


class Toggle:
    def __init__(self):
        self.value = False

    def set(self, value):
        self.value = value


class BlockingClient:
    def __init__(self, response, *, gate=None, error=None):
        self.response = response
        self.gate = gate
        self.error = error
        self.started = threading.Event()
        self.identities = []

    def resolve_source(self, identity):
        self.identities.append(dict(identity))
        self.started.set()
        if self.gate is not None:
            assert self.gate.wait(timeout=2.0)
        if self.error is not None:
            raise self.error
        return self.response


def _resolved(count=15, *, lifecycle="INSPECTION_COMPLETED"):
    members = [
        {
            "unit_id": f"unit-{index:03d}",
            "normalized_barcode": f"{ITEM}-SERIAL-{index:03d}",
            "inbound_iin": f"ORIGIN-IIN-{index % 2}",
            "current_inbound_iin": "IIN-TARGET",
            "item_id": ITEM,
            "uom": "EA",
            "unit_state": "AVAILABLE",
            "location_code": "PHS_GOOD",
        }
        for index in range(1, count + 1)
    ]
    member_ids = [member["unit_id"] for member in members]
    barcodes = [member["normalized_barcode"] for member in members]
    return {
        "candidate_count": 1,
        "bundle": {
            "authority_scope_id": "PLANT-01",
            "ledger_plane": "AUTHORITATIVE",
            "plane_epoch": 1,
            "bundle_id": "PHS-COMPACT-001",
            "bundle_role": "TRANSFER_SOURCE",
            "bundle_type": "PHS",
            "bundle_state": "AVAILABLE",
            "external_label": COMPACT_QR,
            "source_session_id": INPUT_TAG,
            "item_id": ITEM,
            "uom": "EA",
            "source_iin": "IIN-TARGET",
            "current_location": "PHS_GOOD",
            "current_locations": ["PHS_GOOD"],
            "member_ids": member_ids,
            "member_count": count,
            "membership_hash": membership_hash(member_ids),
            "barcode_member_count": count,
            "barcode_membership_hash": membership_hash(barcodes),
            "members": members,
        },
        "input_tag": {
            "input_tag_id": INPUT_TAG,
            "label_id": LABEL_ID,
            "item_id": ITEM,
            "tag_core_hash": CORE_HASH,
            "label_instance_hash": LABEL_HASH,
            "hash_prefix": HASH_PREFIX,
            "lifecycle": lifecycle,
            "qr_payload": COMPACT_QR,
        },
    }


def _app(tmp_path, client):
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession()
    app.completed_master_labels = set()
    app.master_label_replace_state = None
    app.internal_test_commands_enabled = False
    app.worker_name = "tester"
    app.items_data = [
        {"Item Code": ITEM, "Item Name": "fixture item", "Spec": "fixture spec"}
    ]
    app.item_catalog = ItemCatalog(app.items_data)
    app.parked_trays_dir = str(tmp_path / "parked")
    app.root = ScheduledRoot()
    app.show_tray_image_var = Toggle()
    app.transfer_seal_coordinator = SimpleNamespace(client=client)
    app._master_preflight_epoch = 0
    app._master_preflight_pending = False
    app._master_preflight_poll_job = None
    app._scan_callback_epoch = 0
    app.COLOR_DANGER = "danger"
    app.COLOR_PRIMARY = "primary"
    app.COLOR_IDLE = "yellow"
    app._phs_replacement_notice_pairs = set()
    app.warnings = []
    app.statuses = []
    app.events = []
    app._operator_review_blocks_mutation = lambda: False
    app._update_last_activity_time = lambda: None
    app.show_fullscreen_warning = lambda *args, **kwargs: app.warnings.append(args)
    app.show_status_message = lambda *args, **kwargs: app.statuses.append(args)
    app._update_current_item_label = lambda *args, **kwargs: None
    app._save_current_tray_state = lambda: True
    app._delete_current_tray_state = lambda: True
    app._log_event = lambda event, detail=None, **kwargs: app.events.append(
        (event, detail, kwargs)
    ) or True
    app._clear_settled_operator_context = lambda: None
    app._update_tray_image_display = lambda: None
    app._update_center_display = lambda: None
    app._start_stopwatch = lambda: None
    app._schedule_focus_return = lambda *args, **kwargs: None
    return app


def test_compact_phs2_scan_is_nonblocking_and_uses_central_count_not_sixty(tmp_path):
    gate = threading.Event()
    client = BlockingClient(_resolved(count=15), gate=gate)
    app = _app(tmp_path, client)

    started = time.perf_counter()
    app._process_barcode_logic(COMPACT_QR)
    elapsed = time.perf_counter() - started

    assert elapsed < 0.25
    assert client.started.wait(timeout=1.0)
    assert app._master_preflight_pending is True
    assert app.current_tray.master_label_code == ""
    assert len(app.root.jobs) == 1

    app._process_barcode_logic(f"{ITEM}-SHOULD-NOT-BE-ACCEPTED-YET")
    assert app.current_tray.scanned_barcodes == []

    gate.set()
    app._master_preflight_thread.join(timeout=2.0)
    app.root.run_next()

    assert app._master_preflight_pending is False
    assert app.current_tray.master_label_code == COMPACT_QR
    assert app.current_tray.tray_size == 15
    assert app.current_tray.item_code == ITEM
    assert client.identities == [
        {
            "source_bundle_id": "",
            "input_tag_id": INPUT_TAG,
            "input_tag_label_id": LABEL_ID,
            "input_tag_hash_prefix": HASH_PREFIX,
            "compat_work_order_id": "",
            "source_kind": "KMTECH_INPUT_TAG",
            "external_label": "",
            "authority_scope_id": "",
            "item_id": ITEM,
        }
    ]
    event_name, detail, kwargs = app.events[-1]
    assert event_name == "MASTER_LABEL_SCANNED_NEW"
    assert kwargs["synchronous"] is True
    assert detail["resolved_tray_quantity"] == 15
    assert detail["central_source_preflight"]["quantity_basis"] == "CENTRAL_EXACT_MEMBERSHIP"
    assert "QT" not in detail


def test_active_tray_exact_phs2_is_never_routed_as_product(tmp_path, monkeypatch):
    client = BlockingClient(_resolved(count=2))
    app = _app(tmp_path, client)
    existing_barcode = f"{GOAL_ITEM}GOAL27C001"
    app.current_tray = TraySession(
        master_label_code=GOAL_PHS2,
        item_code=GOAL_ITEM,
        item_name="goal item",
        scanned_barcodes=[existing_barcode],
        tray_size=2,
        mismatch_error_count=0,
    )
    focus_returns = []
    app._schedule_focus_return = lambda *args, **kwargs: focus_returns.append(True)
    active_refreshes = []
    app._begin_active_phs_label_refresh = active_refreshes.append

    def fail_product_scan(*args, **kwargs):
        raise AssertionError("PHS=2 label reached the product scan path")

    monkeypatch.setattr("Container_Audit.decide_product_scan", fail_product_scan)

    app._process_barcode_logic(GOAL_PHS2)

    assert app.current_tray.scanned_barcodes == [existing_barcode]
    assert app.current_tray.mismatch_error_count == 0
    assert client.identities == []
    assert app._master_preflight_pending is False
    assert app.root.jobs == []
    event_name, detail, kwargs = app.events[-1]
    assert event_name == "ACTIVE_TRAY_PHS2_SCAN_INTERCEPTED"
    assert detail["current_input_tag_id"] == GOAL_INPUT_TAG
    assert detail["scanned_input_tag_id"] == GOAL_INPUT_TAG
    assert detail["scanned_label_id"] == GOAL_LABEL_ID
    assert kwargs == {}
    assert active_refreshes == [GOAL_PHS2]
    assert focus_returns == []


def test_compact_phs2_network_failure_never_starts_sixty_piece_fallback(tmp_path):
    client = BlockingClient(None, error=ConnectionError("offline"))
    app = _app(tmp_path, client)

    app._process_barcode_logic(COMPACT_QR)
    assert client.started.wait(timeout=1.0)
    app._master_preflight_thread.join(timeout=2.0)
    app.root.run_next()

    assert app.current_tray.master_label_code == ""
    assert app.current_tray.tray_size == app.TRAY_SIZE
    assert app.warnings
    assert "PHS2_PREFLIGHT_UNAVAILABLE" not in app.warnings[-1][1]
    assert app.events[-1][0] == "MASTER_LABEL_PREFLIGHT_FAILED"
    assert app.events[-1][1]["error_code"] == "PHS2_PREFLIGHT_UNAVAILABLE"


def test_compact_phs2_incomplete_registry_lifecycle_fails_closed(tmp_path):
    client = BlockingClient(_resolved(count=15, lifecycle="ISSUED"))
    app = _app(tmp_path, client)

    app._process_barcode_logic(COMPACT_QR)
    assert client.started.wait(timeout=1.0)
    app._master_preflight_thread.join(timeout=2.0)
    app.root.run_next()

    assert app.current_tray.master_label_code == ""
    assert app.warnings
    assert "PHS2_REGISTRY_IDENTITY_MISMATCH" not in app.warnings[-1][1]
    assert app.events[-1][1]["error_code"] == "PHS2_REGISTRY_IDENTITY_MISMATCH"


@pytest.mark.parametrize(
    ("scan_payload", "expected_code"),
    [
        (f"PHS=2|CLC={ITEM}|QT=60", "PHS2_CANONICAL_EVIDENCE_REQUIRED"),
        (f"{COMPACT_QR}|QT=60", "PHS2_COMPACT_FORMAT_REQUIRED"),
    ],
)
def test_legacy_or_noncompact_phs2_is_rejected_before_network_or_qt_fallback(
    tmp_path,
    scan_payload,
    expected_code,
):
    client = BlockingClient(_resolved(count=15))
    app = _app(tmp_path, client)

    app._process_barcode_logic(scan_payload)

    assert client.started.is_set() is False
    assert app.current_tray.master_label_code == ""
    assert app._master_preflight_pending is False
    assert app.root.jobs == []
    assert app.warnings
    assert expected_code not in app.warnings[-1][1]
    assert app.warnings[-1][1] == (
        "현품표 정보를 읽지 못했습니다. 현품표를 확인한 뒤 다시 스캔하세요."
    )


def test_compact_phs2_missing_central_client_fails_closed(tmp_path):
    app = _app(tmp_path, None)

    app._process_barcode_logic(COMPACT_QR)
    app._master_preflight_thread.join(timeout=2.0)
    app.root.run_next()

    assert app.current_tray.master_label_code == ""
    assert app.warnings
    assert "PHS2_CENTRAL_PREFLIGHT_REQUIRED" not in app.warnings[-1][1]
    assert app.events[-1][1]["error_code"] == "PHS2_CENTRAL_PREFLIGHT_REQUIRED"


def test_replaced_master_label_preflight_shows_exact_yellow_notice(tmp_path):
    app = _app(tmp_path, BlockingClient(_resolved(count=2)))
    app._update_action_button_states = lambda: None
    active_label_id = "LBL-COMPACT-NEW"
    active_qr = (
        f"PHS=2|SRC=KMTECH_INPUT_TAG|ITG={INPUT_TAG}|CLC={ITEM}|"
        f"LBL={active_label_id}|HSH={'c' * 16}"
    )
    preflight = SimpleNamespace(
        canonical_input_tag_qr=COMPACT_QR,
        item_id=ITEM,
        member_count=2,
        active_label_qr_payload=active_qr,
        active_label_id=active_label_id,
        active_label_business_date="2026-08-01",
        active_label_worker_code="8월1일-1",
        scanned_label_id=LABEL_ID,
        replaced_scan=True,
        audit_detail=lambda: {"replaced_scan": True},
    )
    result_queue = queue.Queue(maxsize=1)
    result_queue.put((True, preflight, None))

    app._poll_compact_phs2_preflight(
        0,
        COMPACT_QR,
        {
            "PHS": "2",
            "SRC": "KMTECH_INPUT_TAG",
            "ITG": INPUT_TAG,
            "CLC": ITEM,
            "LBL": LABEL_ID,
            "HSH": HASH_PREFIX,
        },
        app.items_data[0],
        result_queue,
    )

    assert app.current_tray.master_label_code == COMPACT_QR
    assert app.current_tray.active_label_id == active_label_id
    assert app.statuses[-1] == (
        "현품표 교체 필요. 작업은 계속할 수 있습니다. "
        "현재 현품표를 교체 대기로 분리해 주세요.",
        "yellow",
    )


def test_compact_phs2_partial_submit_is_blocked_before_confirmation(tmp_path, monkeypatch):
    app = _app(tmp_path, BlockingClient(_resolved(count=3)))
    app.current_tray = TraySession(
        master_label_code=COMPACT_QR,
        item_code=ITEM,
        item_name="fixture item",
        scanned_barcodes=[f"{ITEM}-SERIAL-001", f"{ITEM}-SERIAL-002"],
        tray_size=3,
    )
    app.complete_tray = lambda: (_ for _ in ()).throw(
        AssertionError("partial PHS2 must not enter completion")
    )
    monkeypatch.setattr(
        "Container_Audit.messagebox.askyesno",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("partial PHS2 must not ask for completion confirmation")
        ),
    )

    app.submit_current_tray()

    assert app.current_tray.scanned_barcodes == [
        f"{ITEM}-SERIAL-001",
        f"{ITEM}-SERIAL-002",
    ]
    assert app.statuses
    assert "일부 제출할 수 없습니다" in app.statuses[-1][0]
    assert "RSL1" in app.statuses[-1][0]

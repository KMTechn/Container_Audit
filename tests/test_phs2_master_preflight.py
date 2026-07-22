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
    assert "PHS2_PREFLIGHT_UNAVAILABLE" in app.warnings[-1][1]
    assert app.events[-1][0] == "MASTER_LABEL_PREFLIGHT_FAILED"


def test_compact_phs2_incomplete_registry_lifecycle_fails_closed(tmp_path):
    client = BlockingClient(_resolved(count=15, lifecycle="ISSUED"))
    app = _app(tmp_path, client)

    app._process_barcode_logic(COMPACT_QR)
    assert client.started.wait(timeout=1.0)
    app._master_preflight_thread.join(timeout=2.0)
    app.root.run_next()

    assert app.current_tray.master_label_code == ""
    assert app.warnings
    assert "PHS2_REGISTRY_IDENTITY_MISMATCH" in app.warnings[-1][1]


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
    assert expected_code in app.warnings[-1][1]


def test_compact_phs2_missing_central_client_fails_closed(tmp_path):
    app = _app(tmp_path, None)

    app._process_barcode_logic(COMPACT_QR)
    app._master_preflight_thread.join(timeout=2.0)
    app.root.run_next()

    assert app.current_tray.master_label_code == ""
    assert app.warnings
    assert "PHS2_CENTRAL_PREFLIGHT_REQUIRED" in app.warnings[-1][1]


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

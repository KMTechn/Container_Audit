import queue
import threading
import time
from types import SimpleNamespace

import pytest
from Container_Audit import ContainerAudit, TraySession
from item_catalog import ItemCatalog
from terminal_operation_lease import (
    OperationLeaseManager,
    OperationLeaseStore,
    PinnedOperationLeaseKeyring,
)
from transfer_seal import (
    TransferSealStore,
    _deterministic_id,
    _sha256,
    membership_hash,
)
from tests.operation_lease_fixtures import signed_transfer_artifact


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
        self.authority_scope_id = "PLANT-01"
        self.device_id = "DEVICE-01"
        self.source_host_id = "HOST-01"

    def assert_authority(self, scope_id, **_kwargs):
        assert scope_id == self.authority_scope_id

    def issue_operation_lease(
        self,
        *,
        authority_scope_id,
        operation,
        scan_payload,
        idempotency_key,
    ):
        self.identities.append(
            {
                "authority_scope_id": authority_scope_id,
                "operation": operation,
                "scan_payload": scan_payload,
                "idempotency_key": idempotency_key,
            }
        )
        self.started.set()
        if self.gate is not None:
            assert self.gate.wait(timeout=2.0)
        if self.error is not None:
            raise self.error
        artifact, _claims = signed_transfer_artifact(
            self.response,
            scan_payload=scan_payload,
            device_id=self.device_id,
            source_host_id=self.source_host_id,
            authority_scope_id=authority_scope_id,
        )
        return artifact

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
    source_bundle_id = "PHS-COMPACT-001"
    source = {
        "authority_scope_id": "PLANT-01",
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 1,
        "item_id": ITEM,
        "uom": "EA",
        "source_iin": "IIN-TARGET",
        "member_ids": member_ids,
        "member_count": count,
        "membership_hash": membership_hash(member_ids),
        "barcode_member_count": count,
        "barcode_membership_hash": membership_hash(barcodes),
        "members": members,
    }
    group = {
        "group_id": "PHSG-COMPACT-001",
        "label_id": LABEL_ID,
        "state": "ACTIVE",
        "scan_payload": COMPACT_QR,
        "scan_anchor_input_tag_id": INPUT_TAG,
        "item_id": ITEM,
        "uom": "EA",
        "member_ids": member_ids,
        "member_count": count,
        "membership_hash": source["membership_hash"],
        "membership_version": 1,
        "label_version": 1,
        "group_entity_version": 1,
        "label_entity_version": 1,
    }
    label = {
        **group,
        "qr_payload": COMPACT_QR,
        "hash_prefix": HASH_PREFIX,
        "entity_version": group["label_entity_version"],
        "business_date": "2026-08-01",
        "worker_code": "fixture-worker",
    }
    input_tag = {
        "input_tag_id": INPUT_TAG,
        "label_id": LABEL_ID,
        "item_id": ITEM,
        "uom": "EA",
        "tag_core_hash": CORE_HASH,
        "label_instance_hash": LABEL_HASH,
        "hash_prefix": HASH_PREFIX,
        "lifecycle": lifecycle,
        "qr_payload": COMPACT_QR,
        "session_id": INPUT_TAG,
        "session_state": "COMPLETED",
        "entity_version": 2,
        "member_count": count,
        "membership_hash": source["membership_hash"],
    }
    source_bundle = {
        "bundle_id": source_bundle_id,
        "bundle_type": "PHS",
        "bundle_state": "AVAILABLE",
        "entity_version": 4,
        "source_session_id": INPUT_TAG,
        "external_label": COMPACT_QR,
        "accounting_inbound_iin": "IIN-TARGET",
        "source_member_ids": member_ids,
        "source_member_count": count,
        "source_membership_hash": source["membership_hash"],
        "selected_member_ids": member_ids,
        "selected_member_count": count,
        "selected_membership_hash": source["membership_hash"],
        "remainder_member_ids": [],
        "remainder_member_count": 0,
        "remainder_membership_hash": None,
        "remainder_bundle_id": None,
        "remainder_external_label": None,
        "remainder_cover_group_ids": [],
    }
    transfer_bundle_id = _deterministic_id(
        "TRANSFER",
        {
            "group_id": group["group_id"],
            "label_id": group["label_id"],
            "member_ids": member_ids,
        },
    )
    versions = {
        f"phs_work_group:{group['group_id']}": group["group_entity_version"],
        f"phs_work_membership:{group['group_id']}": group["membership_version"],
        f"phs_work_label_version:{group['group_id']}": group["label_version"],
        f"phs_label:{group['label_id']}": group["label_entity_version"],
        f"bundle:{source_bundle_id}": source_bundle["entity_version"],
        f"bundle:{transfer_bundle_id}": 0,
    }
    source.update(
        {
            "source_bundles": [source_bundle],
            "source_bundle_count": 1,
            "source_bundle_ids": [source_bundle_id],
            "source_session_ids": [INPUT_TAG],
            "transfer_bundle_id": transfer_bundle_id,
            "transfer_external_label": transfer_bundle_id,
            "remainder_cover_groups": [],
            "entity_versions": versions,
        }
    )
    topology_hash = _sha256(
        {
            "phs_work_group": group,
            "source_bundles": [source_bundle],
            "remainder_cover_groups": [],
            "source_iin": source["source_iin"],
            "barcode_membership_hash": source["barcode_membership_hash"],
            "transfer_bundle_id": transfer_bundle_id,
        }
    )
    source["topology_hash"] = topology_hash
    return {
        "candidate_count": 1,
        "authority_scope_id": "PLANT-01",
        "authority_epoch": 1,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 1,
        "entity_versions": versions,
        "source_resolution_basis": "PHS_WORK_GROUP_EXACT_MEMBERSHIP",
        "work_group_source": source,
        "source_input_tags": [input_tag],
        "phs_work_group": group,
        "phs_label_resolution": {
            "status": "ACTIVE",
            "resolution": "OVERLAY_ACTIVE",
            "authority_scope_id": "PLANT-01",
            "ledger_plane": "AUTHORITATIVE",
            "plane_epoch": 1,
            "scanned_label": label,
            "effective_labels": [label],
        },
        "input_tag": input_tag,
        "topology_hash": topology_hash,
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
    app.log_file_path = str(tmp_path / "events.csv")
    app.root = ScheduledRoot()
    app.show_tray_image_var = Toggle()
    lease_manager = OperationLeaseManager(
        OperationLeaseStore(tmp_path / "transfer-seal.db"),
        PinnedOperationLeaseKeyring(tmp_path / "operation-lease-keyring.json"),
    )
    app.transfer_seal_coordinator = SimpleNamespace(
        client=client,
        store=TransferSealStore(tmp_path / "transfer-seal.db"),
        operation_lease_manager=lease_manager,
    )
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
    assert len(client.identities) == 1
    assert client.identities[0]["authority_scope_id"] == "PLANT-01"
    assert client.identities[0]["operation"] == "SEAL_TRANSFER_BUNDLE"
    assert client.identities[0]["scan_payload"] == COMPACT_QR
    assert client.identities[0]["idempotency_key"].startswith(
        "container-operation-lease-issue:"
    )
    assert app.current_tray.operation_lease_id == "operation-lease-fixture-01"
    event_name, detail, kwargs = app.events[-1]
    assert event_name == "MASTER_LABEL_SCANNED_NEW"
    assert kwargs["synchronous"] is True
    assert detail["resolved_tray_quantity"] == 15
    assert detail["central_source_preflight"]["quantity_basis"] == "CENTRAL_EXACT_MEMBERSHIP"
    assert "QT" not in detail


def test_admin_released_prefetch_uses_fresh_durable_key_for_same_physical_qr(
    tmp_path,
):
    class ReleasedThenActiveClient(BlockingClient):
        def issue_operation_lease(
            self,
            *,
            authority_scope_id,
            operation,
            scan_payload,
            idempotency_key,
        ):
            self.identities.append(
                {
                    "authority_scope_id": authority_scope_id,
                    "operation": operation,
                    "scan_payload": scan_payload,
                    "idempotency_key": idempotency_key,
                }
            )
            self.started.set()
            sequence = len(self.identities)
            artifact, _claims = signed_transfer_artifact(
                self.response,
                scan_payload=scan_payload,
                device_id=self.device_id,
                source_host_id=self.source_host_id,
                authority_scope_id=authority_scope_id,
                lease_id=f"operation-lease-release-sequence-{sequence}",
            )
            if sequence == 1:
                artifact["status"] = "RELEASED"
                artifact["replayed"] = True
            return artifact

    client = ReleasedThenActiveClient(_resolved(count=3))
    app = _app(tmp_path, client)

    app._process_barcode_logic(COMPACT_QR)
    assert client.started.wait(timeout=1.0)
    app._master_preflight_thread.join(timeout=2.0)
    app.root.run_next()

    assert app.current_tray.master_label_code == COMPACT_QR
    assert app.current_tray.operation_lease_id == (
        "operation-lease-release-sequence-2"
    )
    assert len(client.identities) == 2
    assert (
        client.identities[0]["idempotency_key"]
        != client.identities[1]["idempotency_key"]
    )
    manager = app.transfer_seal_coordinator.operation_lease_manager
    with manager.store._connect() as connection:
        attempts = connection.execute(
            """SELECT status FROM terminal_operation_lease_issue_attempts
                 ORDER BY rowid"""
        ).fetchall()
    assert [row["status"] for row in attempts] == ["RELEASED", "PREFETCHED"]


def test_prefetch_lost_ack_rescan_reuses_key_and_accepts_replayed_envelope(
    tmp_path,
):
    class LostAckThenReplayClient(BlockingClient):
        def __init__(self, response):
            super().__init__(response)
            self.server_artifact = None

        def issue_operation_lease(
            self,
            *,
            authority_scope_id,
            operation,
            scan_payload,
            idempotency_key,
        ):
            self.identities.append(
                {
                    "authority_scope_id": authority_scope_id,
                    "operation": operation,
                    "scan_payload": scan_payload,
                    "idempotency_key": idempotency_key,
                }
            )
            self.started.set()
            if self.server_artifact is None:
                self.server_artifact, _claims = signed_transfer_artifact(
                    self.response,
                    scan_payload=scan_payload,
                    device_id=self.device_id,
                    source_host_id=self.source_host_id,
                    authority_scope_id=authority_scope_id,
                    lease_id="operation-lease-prefetch-lost-ack",
                )
                raise ConnectionError("lost issue response")
            replay = dict(self.server_artifact)
            replay["replayed"] = True
            return replay

    client = LostAckThenReplayClient(_resolved(count=3))
    app = _app(tmp_path, client)

    app._process_barcode_logic(COMPACT_QR)
    app._master_preflight_thread.join(timeout=2.0)
    app.root.run_next()
    assert app.current_tray.master_label_code == ""

    app._process_barcode_logic(COMPACT_QR)
    app._master_preflight_thread.join(timeout=2.0)
    app.root.run_next()

    assert app.current_tray.master_label_code == COMPACT_QR
    assert app.current_tray.operation_lease_id == (
        "operation-lease-prefetch-lost-ack"
    )
    assert len(client.identities) == 2
    assert (
        client.identities[0]["idempotency_key"]
        == client.identities[1]["idempotency_key"]
    )
    manager = app.transfer_seal_coordinator.operation_lease_manager
    with manager.store._connect() as connection:
        attempts = connection.execute(
            "SELECT status FROM terminal_operation_lease_issue_attempts"
        ).fetchall()
    assert [row["status"] for row in attempts] == ["PREFETCHED"]


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
    assert (
        app.events[-1][1]["error_code"]
        == "PHS2_SOURCE_REGISTRY_IDENTITY_MISMATCH"
    )


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
    result_queue.put((True, preflight, "operation-lease-fixture-01", None))

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
    message = app.statuses[-1][0]
    assert "일부 제출할 수 없습니다" in message
    assert "이름·시간·품목·수량·수기 코드" in message
    assert "RSL1은 업그레이드 전에 시작한 예전 작업 복구에만 사용합니다" in message
    assert "RSL1 절차를 사용" not in message


def test_compact_phs2_incomplete_completion_uses_current_remainder_guidance(tmp_path):
    app = _app(tmp_path, BlockingClient(_resolved(count=3)))
    app.current_tray = TraySession(
        master_label_code=COMPACT_QR,
        item_code=ITEM,
        item_name="fixture item",
        scanned_barcodes=[f"{ITEM}-SERIAL-001", f"{ITEM}-SERIAL-002"],
        tray_size=3,
    )
    app._phs_label_exchange_blocks_tray_transition = lambda _action: False
    app._transfer_member_exchange_blocks_local_action = lambda _action: False

    assert app.complete_tray() is False

    message = app.statuses[-1][0]
    assert "등록된 제품을 모두 스캔해야 이적할 수 있습니다" in message
    assert "이름·시간·품목·수량·수기 코드" in message
    assert "RSL1은 업그레이드 전에 시작한 예전 작업 복구에만 사용합니다" in message
    assert "RSL1로 별도 발행" not in message

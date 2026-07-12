import json
from urllib.parse import parse_qs, urlsplit

import pytest

from Container_Audit import ContainerAudit
from transfer_seal import (
    LogisticsTransferClient,
    TransferSealCoordinator,
    TransferSealError,
    TransferSealStore,
    membership_hash,
    source_identity_from_label,
)


SCOPE = "PLANT-01"
ITEM = "AAA2270730100"
SOURCE = "PHS-SERVER-001"


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kwargs):
        call = {"method": method, "url": url, **kwargs}
        self.calls.append(call)
        return self.handler(call)


def _bundle(barcodes=("BC-1", "BC-2", "BC-3")):
    members = [
        {"unit_id": f"unit-{index}", "normalized_barcode": barcode}
        for index, barcode in enumerate(barcodes, start=1)
    ]
    member_ids = [member["unit_id"] for member in members]
    normalized_barcodes = sorted(member["normalized_barcode"] for member in members)
    return {
        "authority_scope_id": SCOPE,
        "authority_epoch": 7,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 3,
        "bundle_id": SOURCE,
        "bundle_role": "TRANSFER_SOURCE",
        "bundle_type": "PHS",
        "bundle_state": "AVAILABLE",
        "external_label": "WORK-001",
        "source_session_id": "ITAG-001",
        "item_id": ITEM,
        "uom": "EA",
        "source_iin": "IIN-001",
        "current_location": "PHS_GOOD",
        "member_ids": member_ids,
        "member_count": len(member_ids),
        "membership_hash": membership_hash(member_ids),
        "barcode_member_count": len(normalized_barcodes),
        "barcode_membership_hash": membership_hash(normalized_barcodes),
        "entity_version": 4,
        "entity_versions": {f"bundle:{SOURCE}": 4},
        "members": members,
    }


def _receipt(context):
    payload = context["payload"]
    normalized_barcodes = sorted(value.upper() for value in payload["scanned_barcodes"])
    remainder_ids = list(context["client_exact_evidence"]["remainder_member_ids"])
    data = {
        "source_bundle_id": payload["source_bundle_id"],
        "transfer_bundle_id": payload["transfer_bundle_id"],
        "item_id": payload["item_id"],
        "member_ids": payload["member_ids"],
        "member_count": len(payload["member_ids"]),
        "membership_hash": payload["membership_hash"],
        "scanned_barcodes": normalized_barcodes,
        "scanned_barcode_count": len(normalized_barcodes),
        "scanned_barcode_hash": membership_hash(normalized_barcodes),
        "inbound_iin": "IIN-001",
        "uom": "EA",
        "remainder_bundle_id": payload.get("remainder_bundle_id"),
        "remainder_member_ids": remainder_ids,
        "remainder_member_count": len(remainder_ids),
        "remainder_membership_hash": membership_hash(remainder_ids) if remainder_ids else None,
        "post_seal_exchange_policy": "BLOCKED_REQUIRES_TWO_BUNDLE_CAS",
        "entity_versions": {
            f"bundle:{payload['source_bundle_id']}": 5,
            f"bundle:{payload['transfer_bundle_id']}": 1,
        },
    }
    return {"receipt_id": "receipt-seal-1", "data": data}


def _client(handler):
    session = FakeSession(handler)
    return LogisticsTransferClient(
        "https://server.example",
        "secret-token",
        "PC-01",
        session=session,
    ), session


def _prepare(coordinator, barcodes=("BC-1", "BC-2", "BC-3"), *, include_bundle=True):
    fields = {
        "ITG": "ITAG-001",
        "LBL": "INPUT-LABEL-001",
        "WID": "WORK-001",
        "CLC": ITEM,
        "QT": "3",
    }
    if include_bundle:
        fields["BND"] = SOURCE
    return coordinator.prepare(
        master_label="PHS=1|BND=PHS-SERVER-001|ITG=ITAG-001|CLC=AAA2270730100|QT=3",
        master_label_fields=fields,
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=barcodes,
    )


def test_source_identity_keeps_input_label_as_evidence_not_external_identity():
    identity = source_identity_from_label(
        {"ITG": "ITAG-1", "LBL": "INPUT-LABEL", "WID": "WORK-1", "CLC": ITEM}
    )

    assert identity == {
        "source_bundle_id": "",
        "input_tag_id": "ITAG-1",
        "input_tag_label_id": "INPUT-LABEL",
        "compat_work_order_id": "WORK-1",
        "source_kind": "",
        "external_label": "",
        "item_id": ITEM,
    }

    inspection_identity = source_identity_from_label(
        {"ITG": "ITAG-2", "CLC": "INSPECTION", "ITEM": ITEM}
    )
    assert inspection_identity["item_id"] == ITEM

    regular_phs = source_identity_from_label({"WID": "WORK-REGULAR", "CLC": ITEM})
    assert regular_phs["external_label"] == "WORK-REGULAR"


def test_store_prepare_is_idempotent_and_rejects_normalized_duplicate(tmp_path):
    store = TransferSealStore(tmp_path / "seal.db")
    first = store.prepare(
        master_label="MASTER-1",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["bc-1", "bc-2"],
    )
    replay = store.prepare(
        master_label="MASTER-1",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["bc-1", "bc-2"],
    )

    assert first["intent_id"] == replay["intent_id"]
    with pytest.raises(ValueError, match="unique"):
        store.prepare(
            master_label="MASTER-2",
            source_identity={"source_bundle_id": SOURCE},
            item_id=ITEM,
            operator="tester",
            scanned_barcodes=["bc-1", "BC-1"],
        )


def test_store_methods_release_windows_db_and_wal_handles_without_gc(tmp_path):
    db_path = tmp_path / "container-seal.db"
    store = TransferSealStore(db_path)
    row = store.prepare(
        master_label="MASTER-WINDOWS-CLOSE",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
    )
    context = {
        "contract_version": "logistics-v1",
        "command_type": "SEAL_TRANSFER_BUNDLE",
        "authority_scope_id": SCOPE,
        "authority_epoch": 1,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 1,
        "idempotency_key": f"close-test:{row['intent_id']}",
        "expected_versions": {f"bundle:{SOURCE}": 1},
        "payload": {
            "source_bundle_id": SOURCE,
            "transfer_bundle_id": "TRANSFER-CLOSE-1",
            "item_id": ITEM,
            "member_ids": ["unit-1"],
            "membership_hash": membership_hash(["unit-1"]),
            "scanned_barcodes": ["BC-1"],
        },
    }
    store.bind_command(row["intent_id"], context)
    store.load(row["intent_id"])
    store.pending_ids()
    store.has_exact_history()
    store.record_error(
        row["intent_id"],
        TransferSealError("TRANSPORT_ERROR", "retry", retryable=True),
    )
    store.record_exchange_block(reason_code="TEST_BLOCK", details={"test": True})

    # Windows refuses these operations if even one sqlite connection remains
    # open. The store object intentionally stays alive so this does not depend
    # on garbage collection or a destructor.
    moved_paths = []
    for suffix in ("", "-wal", "-shm"):
        source = tmp_path / f"container-seal.db{suffix}"
        if not source.exists():
            continue
        moved = tmp_path / f"moved-container-seal.db{suffix}"
        source.rename(moved)
        moved_paths.append(moved)
    assert moved_paths
    for moved in moved_paths:
        moved.unlink()
        assert not moved.exists()


def test_full_transfer_seal_sends_exact_server_units_and_builds_memberless_qr(tmp_path):
    def handler(call):
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            query = parse_qs(urlsplit(call["url"]).query)
            assert query["bundle_id"] == [SOURCE]
            assert query["input_tag_id"] == ["ITAG-001"]
            assert "external_label" not in query
            assert query["bundle_role"] == ["TRANSFER_SOURCE"]
            assert "INPUT-LABEL-001" not in call["url"]
            return FakeResponse(200, {"ok": True, "data": _bundle()})
        if call["method"] == "POST" and call["url"].endswith("/transfers/seal"):
            context = call["json"]
            assert context["payload"]["member_ids"] == ["unit-1", "unit-2", "unit-3"]
            assert context["expected_versions"] == {f"bundle:{SOURCE}": 4}
            assert "remainder_bundle_id" not in context["payload"]
            assert call["headers"]["Idempotency-Key"] == context["idempotency_key"]
            return FakeResponse(200, {"ok": True, "status": "committed", "data": _receipt(context)})
        raise AssertionError(call)

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator)
    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED"
    assert result.member_count == 3
    assert result.membership_hash == membership_hash(["unit-1", "unit-2", "unit-3"])
    assert f"BND={result.transfer_bundle_id}" in result.seal_qr_payload
    assert f"CLC={ITEM}" in result.seal_qr_payload
    assert "unit-1" not in result.seal_qr_payload
    assert "BC-1" not in result.seal_qr_payload


def test_partial_seal_creates_exact_remainder_without_relabeling_original_phs(tmp_path):
    posted = []

    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _bundle()})
        context = call["json"]
        posted.append(context)
        return FakeResponse(200, {"ok": True, "data": _receipt(context)})

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator, ("BC-1", "BC-3"))
    result = coordinator.attempt(prepared.intent_id)
    payload = posted[0]["payload"]

    assert result.status == "ACKED"
    assert payload["member_ids"] == ["unit-1", "unit-3"]
    assert payload["external_label"] == payload["transfer_bundle_id"]
    assert payload["remainder_bundle_id"].startswith("TRANSFER-REMAINDER-")
    assert "remainder_external_label" not in payload
    assert payload["scanned_barcodes"] == ["BC-1", "BC-3"]


def test_restart_reuses_immutable_command_and_recovers_lost_ack(tmp_path):
    db_path = tmp_path / "seal.db"
    first_post = []

    def first_handler(call):
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": _bundle()})
        if call["method"] == "POST":
            first_post.append(call)
            raise ConnectionError("lost ack")
        if call["method"] == "GET" and "/receipts/" in call["url"]:
            return FakeResponse(404, {"ok": False, "error": {"code": "RECEIPT_NOT_FOUND"}})
        raise AssertionError(call)

    client1, _session1 = _client(first_handler)
    coordinator1 = TransferSealCoordinator(TransferSealStore(db_path), client1)
    prepared = _prepare(coordinator1, ("BC-1", "BC-2"))
    waiting = coordinator1.attempt(prepared.intent_id)
    durable_before = coordinator1.store.load(prepared.intent_id)

    assert waiting.status == "RETRY_WAIT"
    assert durable_before["command_json"]

    second_post = []

    def second_handler(call):
        if call["method"] == "POST":
            second_post.append(call)
            return FakeResponse(200, {"ok": True, "data": _receipt(call["json"])})
        raise AssertionError(call)

    client2, _session2 = _client(second_handler)
    coordinator2 = TransferSealCoordinator(TransferSealStore(db_path), client2)
    recovered = coordinator2.attempt(prepared.intent_id)
    durable_after = coordinator2.store.load(prepared.intent_id)

    assert recovered.status == "ACKED"
    assert second_post[0]["json"] == first_post[0]["json"]
    assert second_post[0]["headers"]["Idempotency-Key"] == first_post[0]["headers"]["Idempotency-Key"]
    assert durable_after["command_json"] == durable_before["command_json"]
    assert durable_after["command_hash"] == durable_before["command_hash"]


def test_barcode_outside_source_membership_requires_operator_review_without_post(tmp_path):
    calls = []

    def handler(call):
        calls.append(call)
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _bundle()})
        raise AssertionError("invalid membership must not be posted")

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator, ("BC-1", "OUTSIDE"))
    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "BARCODE_NOT_IN_SOURCE_BUNDLE"
    assert [call["method"] for call in calls] == ["GET"]


def test_receipt_barcode_membership_mismatch_is_not_acked(tmp_path):
    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _bundle()})
        receipt = _receipt(call["json"])
        receipt["data"]["scanned_barcodes"] = ["BC-1", "WRONG"]
        return FakeResponse(200, {"ok": True, "data": receipt})

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator, ("BC-1", "BC-2"))
    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"


def test_input_tag_resolver_excludes_compat_wid_from_identity_intersection(tmp_path):
    observed_query = {}

    def handler(call):
        if call["method"] == "GET":
            observed_query.update(parse_qs(urlsplit(call["url"]).query))
            return FakeResponse(200, {"ok": True, "data": _bundle()})
        return FakeResponse(200, {"ok": True, "data": _receipt(call["json"])})

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = coordinator.prepare(
        master_label=(
            "SRC=KMTECH_INPUT_TAG|ITG=ITAG-001|LBL=INPUT-LABEL-001|"
            "WID=COMPAT-WID-MUST-NOT-QUERY|CLC=AAA2270730100|QT=3"
        ),
        master_label_fields={
            "SRC": "KMTECH_INPUT_TAG",
            "ITG": "ITAG-001",
            "LBL": "INPUT-LABEL-001",
            "WID": "COMPAT-WID-MUST-NOT-QUERY",
            "CLC": ITEM,
        },
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1", "BC-2", "BC-3"],
    )

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED"
    assert observed_query["input_tag_id"] == ["ITAG-001"]
    assert observed_query["item_id"] == [ITEM]
    assert "external_label" not in observed_query
    assert "COMPAT-WID-MUST-NOT-QUERY" not in json.dumps(observed_query)


def test_test_environment_disables_operator_audio(monkeypatch):
    app = ContainerAudit.__new__(ContainerAudit)
    monkeypatch.setenv("KMTECH_TEST_SILENT_AUDIO", "1")

    assert app._audio_feedback_enabled() is False


def test_exact_history_blocks_unsafe_exchange_and_writes_restriction_receipt(tmp_path, monkeypatch):
    store = TransferSealStore(tmp_path / "seal.db")
    store.prepare(
        master_label="MASTER-EXACT",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
    )
    app = ContainerAudit.__new__(ContainerAudit)
    app.transfer_seal_coordinator = TransferSealCoordinator(store, None)
    app.current_tray = type("Tray", (), {"master_label_code": ""})()
    app.worker_name = ""
    app.log_file_path = ""
    warnings = []
    monkeypatch.setattr("Container_Audit.messagebox.showwarning", lambda *args: warnings.append(args))
    monkeypatch.setattr(
        "Container_Audit.tk.Toplevel",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("blocked exact exchange must not open a dialog")
        ),
    )

    app.show_exchange_dialog()

    assert warnings and "중앙 교환" in warnings[0][0]
    with store._connect() as conn:
        receipt = conn.execute(
            "SELECT reason_code,details_json FROM transfer_exchange_block_receipts"
        ).fetchone()
    assert receipt["reason_code"] == "BLOCKED_REQUIRES_TWO_BUNDLE_CAS"
    assert json.loads(receipt["details_json"])["operator"] == ""


def test_legacy_without_exact_configuration_keeps_exchange_available(tmp_path):
    app = ContainerAudit.__new__(ContainerAudit)
    app.transfer_seal_coordinator = TransferSealCoordinator(
        TransferSealStore(tmp_path / "legacy.db"), None
    )

    assert app._exact_transfer_exchange_blocked() is False


def test_configured_exact_client_blocks_exchange_before_first_history(tmp_path):
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "configured.db"), object())
    app = ContainerAudit.__new__(ContainerAudit)
    app.transfer_seal_coordinator = coordinator

    assert app._exact_transfer_exchange_blocked() is True

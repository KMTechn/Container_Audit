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
    validate_compact_phs2_fields,
    validate_compact_phs2_preflight,
)


SCOPE = "PLANT-01"
ITEM = "AAA2270730100"
SOURCE = "PHS-SERVER-001"
PHS2_LABEL_HASH = "a" * 64
PHS2_CORE_HASH = "b" * 64
PHS2_HASH_PREFIX = PHS2_LABEL_HASH[:16]


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


def _resolved_bundle(barcodes=("BC-1", "BC-2", "BC-3")):
    return {"candidate_count": 1, "bundle": _bundle(barcodes)}


def _compact_phs2_fields(**overrides):
    fields = {
        "PHS": "2",
        "SRC": "KMTECH_INPUT_TAG",
        "ITG": "ITAG-001",
        "CLC": ITEM,
        "LBL": "INPUT-LABEL-001",
        "HSH": PHS2_HASH_PREFIX,
    }
    fields.update(overrides)
    return fields


def _compact_phs2_qr(**overrides):
    fields = _compact_phs2_fields(**overrides)
    return "|".join(
        f"{key}={fields[key]}" for key in ("PHS", "SRC", "ITG", "CLC", "LBL", "HSH")
    )


def _resolved_compact_phs2(count=15):
    members = [
        {
            "unit_id": f"unit-{index:03d}",
            "normalized_barcode": f"{ITEM}-SERIAL-{index:03d}",
            "inbound_iin": f"ORIGIN-IIN-{index % 2}",
            "current_inbound_iin": "IIN-001",
            "item_id": ITEM,
            "uom": "EA",
            "unit_state": "AVAILABLE",
            "location_code": "PHS_GOOD",
        }
        for index in range(1, count + 1)
    ]
    member_ids = [member["unit_id"] for member in members]
    barcodes = [member["normalized_barcode"] for member in members]
    bundle = {
        "authority_scope_id": SCOPE,
        "authority_epoch": 7,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 3,
        "bundle_id": SOURCE,
        "bundle_role": "TRANSFER_SOURCE",
        "bundle_type": "PHS",
        "bundle_state": "AVAILABLE",
        "external_label": _compact_phs2_qr(),
        "source_session_id": "ITAG-001",
        "item_id": ITEM,
        "uom": "EA",
        "source_iin": "IIN-001",
        "source_iins": ["ORIGIN-IIN-0", "ORIGIN-IIN-1"],
        "origin_inbound_iins": ["ORIGIN-IIN-0", "ORIGIN-IIN-1"],
        "current_location": "PHS_GOOD",
        "current_locations": ["PHS_GOOD"],
        "member_ids": member_ids,
        "member_count": count,
        "membership_hash": membership_hash(member_ids),
        "barcode_member_count": count,
        "barcode_membership_hash": membership_hash(barcodes),
        "entity_version": 4,
        "entity_versions": {f"bundle:{SOURCE}": 4},
        "members": members,
    }
    return {
        "candidate_count": 1,
        "bundle": bundle,
        "input_tag": {
            "input_tag_id": "ITAG-001",
            "label_id": "INPUT-LABEL-001",
            "item_id": ITEM,
            "tag_core_hash": PHS2_CORE_HASH,
            "label_instance_hash": PHS2_LABEL_HASH,
            "hash_prefix": PHS2_HASH_PREFIX,
            "lifecycle": "INSPECTION_COMPLETED",
            "qr_payload": _compact_phs2_qr(),
        },
    }


def _receipt(context):
    payload = context["payload"]
    normalized_barcodes = sorted(value.upper() for value in payload["scanned_barcodes"])
    remainder_ids = list(context["client_exact_evidence"]["remainder_member_ids"])
    seal_id = "transfer-seal-1"
    seal_token = "transfer-seal-token-1"
    seal_qr_payload = "|".join(
        (
            "TRF=1",
            f"BND={payload['transfer_bundle_id']}",
            f"AUTH_SCOPE={context['authority_scope_id']}",
            f"CLC={payload['item_id']}",
            f"QT={len(payload['member_ids'])}",
            f"HSH={payload['membership_hash']}",
            f"EPOCH={context['authority_epoch']}",
            f"PLANE={context['ledger_plane']}",
            f"PE={context['plane_epoch']}",
            f"SID={seal_id}",
            "SREV=1",
            f"STK={seal_token}",
        )
    )
    data = {
        "source_bundle_id": payload["source_bundle_id"],
        "transfer_bundle_id": payload["transfer_bundle_id"],
        "item_id": payload["item_id"],
        "member_ids": payload["member_ids"],
        "members": [
            {"unit_id": unit_id, "normalized_barcode": barcode}
            for unit_id, barcode in zip(
                payload["member_ids"], normalized_barcodes, strict=True
            )
        ],
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
        "seal_contract_version": "transfer-seal-qr-v1",
        "seal_state": "ACTIVE",
        "seal_id": seal_id,
        "seal_revision": 1,
        "seal_token": seal_token,
        "seal_qr_payload": seal_qr_payload,
        "sealed_bundle_id": payload["transfer_bundle_id"],
        "sealed_bundle_version": 1,
        "sealed_member_ids": payload["member_ids"],
        "sealed_members": [
            {"unit_id": unit_id, "normalized_barcode": barcode}
            for unit_id, barcode in zip(
                payload["member_ids"], normalized_barcodes, strict=True
            )
        ],
        "sealed_member_count": len(payload["member_ids"]),
        "sealed_membership_hash": payload["membership_hash"],
        "sealed_normalized_barcodes": normalized_barcodes,
        "sealed_barcode_membership_hash": membership_hash(normalized_barcodes),
        "entity_versions": {
            f"bundle:{payload['source_bundle_id']}": 5,
            f"bundle:{payload['transfer_bundle_id']}": 1,
        },
    }
    if payload.get("remainder_bundle_id"):
        data["entity_versions"][f"bundle:{payload['remainder_bundle_id']}"] = 1
    return {
        "receipt_id": "receipt-seal-1",
        "contract_version": "logistics-v1",
        "command_type": "SEAL_TRANSFER_BUNDLE",
        "status": "COMMITTED",
        "authority_scope_id": context["authority_scope_id"],
        "authority_epoch": context["authority_epoch"],
        "resolved_ledger_plane": context["ledger_plane"],
        "resolved_plane_epoch": context["plane_epoch"],
        "committed_at": "2026-07-21T00:00:00Z",
        "event_ids": ["event-seal-1"],
        "outbox_ids": ["outbox-seal-1"],
        "entity_versions": dict(data["entity_versions"]),
        "data": data,
    }


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
        "input_tag_hash_prefix": "",
        "compat_work_order_id": "WORK-1",
        "source_kind": "",
        "external_label": "",
        "authority_scope_id": "",
        "item_id": ITEM,
    }

    inspection_identity = source_identity_from_label(
        {
            "ITG": "ITAG-2",
            "WID": "COMPAT-MUST-NOT-BECOME-IDENTITY",
            "AUTH_SCOPE": SCOPE,
            "CLC": "INSPECTION",
            "ITEM": ITEM,
        }
    )
    assert inspection_identity["item_id"] == ITEM
    assert inspection_identity["external_label"] == ""
    assert inspection_identity["authority_scope_id"] == SCOPE

    regular_phs = source_identity_from_label({"WID": "WORK-REGULAR", "CLC": ITEM})
    assert regular_phs["external_label"] == "WORK-REGULAR"

    phs1_membership_hash = source_identity_from_label(
        {"PHS": "1", "ITG": "ITAG-3", "HSH": "f" * 64, "CLC": ITEM}
    )
    assert phs1_membership_hash["input_tag_hash_prefix"] == ""


def test_compact_phs2_requires_canonical_registry_identity_without_qt():
    fields = validate_compact_phs2_fields(_compact_phs2_fields())

    assert fields == _compact_phs2_fields()
    assert "QT" not in fields

    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_fields({"PHS": "2", "CLC": ITEM, "QT": "60"})

    assert exc_info.value.code == "PHS2_CANONICAL_EVIDENCE_REQUIRED"


def test_compact_phs2_preflight_uses_completed_exact_member_count_without_qr_qt():
    fields = _compact_phs2_fields()
    result = validate_compact_phs2_preflight(fields, _resolved_compact_phs2(count=15))

    assert result.member_count == 15
    assert result.item_id == ITEM
    assert result.source_session_id == fields["ITG"]
    assert result.input_tag_label_id == fields["LBL"]
    assert result.input_tag_hash_prefix == fields["HSH"]
    assert result.audit_detail()["quantity_basis"] == "CENTRAL_EXACT_MEMBERSHIP"


def test_compact_phs2_rejects_qt_even_when_registry_identity_fields_are_present():
    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_fields(_compact_phs2_fields(QT="60"))

    assert exc_info.value.code == "PHS2_COMPACT_FORMAT_REQUIRED"


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda value: value["input_tag"].update({"lifecycle": "ISSUED"}),
            "PHS2_REGISTRY_IDENTITY_MISMATCH",
        ),
        (
            lambda value: value["bundle"].update({"bundle_state": "CONSUMED"}),
            "PHS2_SOURCE_IDENTITY_MISMATCH",
        ),
        (
            lambda value: value["bundle"]["members"][0].update({"item_id": "OTHER"}),
            "PHS2_MIXED_MEMBERSHIP",
        ),
        (
            lambda value: value["bundle"]["members"][0].update(
                {"current_inbound_iin": "OTHER-IIN"}
            ),
            "PHS2_MIXED_MEMBERSHIP",
        ),
        (
            lambda value: value["bundle"]["members"][0].update(
                {"unit_state": "CLAIMED"}
            ),
            "PHS2_MEMBER_NOT_AVAILABLE",
        ),
    ],
)
def test_compact_phs2_preflight_fails_closed_for_incomplete_or_mixed_source(
    mutate,
    expected_code,
):
    resolved = json.loads(json.dumps(_resolved_compact_phs2(count=3)))
    mutate(resolved)

    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_preflight(_compact_phs2_fields(), resolved)

    assert exc_info.value.code == expected_code


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["input_tag"].update(
            {"qr_payload": _compact_phs2_qr(LBL="OTHER-LABEL")}
        ),
        lambda value: value["bundle"].update(
            {"external_label": _compact_phs2_qr(ITG="OTHER-INPUT-TAG")}
        ),
    ],
)
def test_compact_phs2_preflight_rejects_registry_or_bundle_qr_identity_drift(mutate):
    resolved = json.loads(json.dumps(_resolved_compact_phs2(count=3)))
    mutate(resolved)

    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_preflight(_compact_phs2_fields(), resolved)

    assert exc_info.value.code == "PHS2_REGISTRY_IDENTITY_MISMATCH"


def test_compact_phs2_preflight_accepts_completed_consumed_member_state():
    resolved = _resolved_compact_phs2(count=2)
    for member in resolved["bundle"]["members"]:
        member["unit_state"] = "CONSUMED"

    result = validate_compact_phs2_preflight(_compact_phs2_fields(), resolved)

    assert result.member_count == 2


def test_compact_phs2_resolver_sends_itg_label_and_hash_prefix():
    observed_query = {}

    def handler(call):
        observed_query.update(parse_qs(urlsplit(call["url"]).query))
        return FakeResponse(200, {"ok": True, "data": _resolved_compact_phs2(count=2)})

    client, _session = _client(handler)
    identity = source_identity_from_label(_compact_phs2_fields())

    client.resolve_source(identity)

    assert observed_query["bundle_role"] == ["TRANSFER_SOURCE"]
    assert observed_query["input_tag_id"] == ["ITAG-001"]
    assert observed_query["input_tag_label_id"] == ["INPUT-LABEL-001"]
    assert observed_query["input_tag_hash_prefix"] == [PHS2_HASH_PREFIX]
    assert observed_query["item_id"] == [ITEM]
    assert "external_label" not in observed_query


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
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
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


def test_partial_phs_seal_is_blocked_before_post(tmp_path):
    posted = []

    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        posted.append(call["json"])
        raise AssertionError("partial PHS transfer must not be posted")

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator, ("BC-1", "BC-3"))
    result = coordinator.attempt(prepared.intent_id)
    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "PARTIAL_PHS_TRANSFER_FORBIDDEN"
    assert posted == []


def test_restart_reuses_immutable_command_and_recovers_lost_ack(tmp_path):
    db_path = tmp_path / "seal.db"
    first_post = []

    def first_handler(call):
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        if call["method"] == "POST":
            first_post.append(call)
            raise ConnectionError("lost ack")
        if call["method"] == "GET" and "/receipts/" in call["url"]:
            return FakeResponse(404, {"ok": False, "error": {"code": "RECEIPT_NOT_FOUND"}})
        raise AssertionError(call)

    client1, _session1 = _client(first_handler)
    coordinator1 = TransferSealCoordinator(TransferSealStore(db_path), client1)
    prepared = _prepare(coordinator1)
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
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        raise AssertionError("invalid membership must not be posted")

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator, ("BC-1", "OUTSIDE"))
    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "BARCODE_NOT_IN_SOURCE_BUNDLE"
    assert [call["method"] for call in calls] == ["GET"]


def test_resolver_requires_nested_canonical_bundle_before_command_is_saved(tmp_path):
    calls = []

    def handler(call):
        calls.append(call)
        if call["method"] == "GET":
            # A top-level projection omits resolver ambiguity/lineage context.
            return FakeResponse(200, {"ok": True, "data": _bundle()})
        raise AssertionError("invalid resolver response must not be posted")

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RESOLVER_CONTRACT_INVALID"
    assert [call["method"] for call in calls] == ["GET"]


def test_resolver_requires_explicit_unique_candidate_count(tmp_path):
    calls = []

    def handler(call):
        calls.append(call)
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": {"bundle": _bundle()}})
        raise AssertionError("ambiguous resolver response must not be posted")

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "count.db"), client)
    prepared = _prepare(coordinator)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "AMBIGUOUS_BUNDLE"
    assert [call["method"] for call in calls] == ["GET"]


def test_partial_or_ambiguous_source_member_mapping_is_fail_closed(tmp_path):
    for mutation in ("partial", "duplicate_barcode", "foreign_unit"):
        calls = []
        source = _bundle()
        if mutation == "partial":
            source["members"] = source["members"][:-1]
        elif mutation == "duplicate_barcode":
            source["members"][1]["normalized_barcode"] = source["members"][0][
                "normalized_barcode"
            ]
        else:
            source["members"][1]["unit_id"] = "unit-outside"

        def handler(call, response=source):
            calls.append(call)
            if call["method"] == "GET":
                return FakeResponse(
                    200,
                    {"ok": True, "data": {"candidate_count": 1, "bundle": response}},
                )
            raise AssertionError("inexact membership must not be posted")

        client, _session = _client(handler)
        coordinator = TransferSealCoordinator(
            TransferSealStore(tmp_path / f"{mutation}.db"), client
        )
        prepared = _prepare(coordinator)

        result = coordinator.attempt(prepared.intent_id)

        assert result.status == "OPERATOR_REVIEW"
        assert result.error_code == "MEMBERSHIP_CONFLICT"
        assert [call["method"] for call in calls] == ["GET"]


def test_receipt_barcode_membership_mismatch_is_not_acked(tmp_path):
    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        receipt = _receipt(call["json"])
        receipt["data"]["scanned_barcodes"] = ["BC-1", "WRONG"]
        return FakeResponse(200, {"ok": True, "data": receipt})

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator)
    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"


def test_receipt_without_server_seal_identity_is_not_acked(tmp_path):
    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        receipt = _receipt(call["json"])
        receipt["data"].pop("seal_token")
        receipt["data"].pop("seal_qr_payload")
        return FakeResponse(200, {"ok": True, "data": receipt})

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    result = coordinator.attempt(_prepare(coordinator).intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"


def test_receipt_sealed_unit_barcode_mapping_mismatch_is_not_acked(tmp_path):
    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        receipt = _receipt(call["json"])
        receipt["data"]["sealed_members"][0]["normalized_barcode"] = "WRONG"
        return FakeResponse(200, {"ok": True, "data": receipt})

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    result = coordinator.attempt(_prepare(coordinator).intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"


def test_input_tag_resolver_excludes_compat_wid_from_identity_intersection(tmp_path):
    observed_query = {}

    def handler(call):
        if call["method"] == "GET":
            observed_query.update(parse_qs(urlsplit(call["url"]).query))
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
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
            "AUTH_SCOPE": SCOPE,
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
    assert observed_query["authority_scope_id"] == [SCOPE]
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


def test_exact_history_blocks_local_master_label_replacement(tmp_path, monkeypatch):
    store = TransferSealStore(tmp_path / "replacement-block.db")
    store.prepare(
        master_label="MASTER-EXACT-REPLACEMENT",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
    )
    app = ContainerAudit.__new__(ContainerAudit)
    app.transfer_seal_coordinator = TransferSealCoordinator(store, None)
    app.current_tray = type("Tray", (), {"master_label_code": ""})()
    app.master_label_replace_state = None
    app.replacement_context = {}
    app.worker_name = ""
    app.log_file_path = ""
    app._operator_review_blocks_mutation = lambda: False
    app._update_action_button_states = lambda: None
    warnings = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.showwarning", lambda *args: warnings.append(args)
    )

    app.initiate_master_label_replacement()

    assert app.master_label_replace_state is None
    assert warnings and "중앙 교체" in warnings[0][0]
    with store._connect() as conn:
        receipt = conn.execute(
            """SELECT reason_code,details_json
                 FROM transfer_exchange_block_receipts
                WHERE reason_code='BLOCKED_REQUIRES_REPLACE_BUNDLE_MEMBERS_CAS'"""
        ).fetchone()
    assert receipt is not None
    details = json.loads(receipt["details_json"])
    assert details["operation"] == "completed_master_label_replacement"
    assert "open_reseal" in details["policy"]


@pytest.mark.parametrize("status_code", [409, 412])
def test_server_cas_conflict_is_terminal_even_when_marked_retryable(tmp_path, status_code):
    store = TransferSealStore(tmp_path / f"cas-{status_code}.db")
    prepared = store.prepare(
        master_label="MASTER-CAS",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
    )
    row = store.record_error(
        prepared["intent_id"],
        TransferSealError(
            "VERSION_CONFLICT",
            "source changed concurrently",
            status_code=status_code,
            retryable=True,
        ),
    )

    assert row["status"] == "OPERATOR_REVIEW"


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

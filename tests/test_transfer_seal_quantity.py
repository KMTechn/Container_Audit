"""Printed QT must survive signed, bound seal validation and review recovery."""
import copy
import json

import pytest

from tests.operation_lease_fixtures import fixed_operation_lease_clock
from tests import test_terminal_operation_lease as lease_helpers
from tests.test_transfer_seal import FakeResponse, _resolved_work_group_phs2
from transfer_seal import (
    TransferSealError, _physical_label_from_resolution, _sha256,
    validate_compact_phs2_preflight,
)


def _quantity_snapshot(quantity):
    resolved = copy.deepcopy(_resolved_work_group_phs2(mode="merge"))
    if quantity is None:
        return resolved
    group = resolved["phs_work_group"]
    group["scan_payload"] += f"|QT={quantity}"
    resolution = resolved["phs_label_resolution"]
    for label in [resolution["scanned_label"], *resolution["effective_labels"]]:
        label["qr_payload"] = group["scan_payload"]
        label["scan_payload"] = group["scan_payload"]
    source = resolved["work_group_source"]
    source["topology_hash"] = resolved["topology_hash"] = _sha256({
        "phs_work_group": group,
        "source_bundles": source["source_bundles"],
        "remainder_cover_groups": source["remainder_cover_groups"],
        "source_iin": source["source_iin"],
        "barcode_membership_hash": source["barcode_membership_hash"],
        "transfer_bundle_id": source["transfer_bundle_id"],
    })
    return resolved


@pytest.mark.parametrize("quantity", [None, 2])
def test_signed_bound_seal_preserves_printed_quantity(tmp_path, monkeypatch, quantity, fixed_operation_lease_clock):
    resolved = _quantity_snapshot(quantity)
    monkeypatch.setattr(lease_helpers, "_resolved_work_group_phs2", lambda **_: resolved)
    posted = []

    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(404, {"ok": False, "error": {"code": "RECEIPT_NOT_FOUND"}})
        posted.append(call["json"])
        return FakeResponse(200, {"ok": True, "status": "committed",
                                  "data": lease_helpers._consumed_receipt(call["json"])})

    coordinator, manager, _, resolved, qr, _ = lease_helpers._accepted_coordinator(tmp_path, handler)
    prepared = lease_helpers._prepare_lease_transfer(coordinator, resolved, qr, "operation-lease-test-01")
    result = coordinator.attempt(prepared.intent_id)
    assert result.status == "ACKED"
    assert len(posted) == 1
    assert posted[0]["payload"]["phs_work_group"]["scan_payload"] == qr
    assert len(posted[0]["payload"]["member_ids"]) == len(set(posted[0]["payload"]["member_ids"]))
    assert manager.store.state("operation-lease-test-01") == "ACKED"


def test_quantity_review_uses_existing_admin_retry_without_rewriting_command(tmp_path, monkeypatch, fixed_operation_lease_clock):
    resolved = _quantity_snapshot(2)
    monkeypatch.setattr(lease_helpers, "_resolved_work_group_phs2", lambda **_: resolved)
    posted = []

    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(404, {"ok": False, "error": {"code": "RECEIPT_NOT_FOUND"}})
        posted.append(call["json"])
        return FakeResponse(200, {"ok": True, "status": "committed",
                                  "data": lease_helpers._consumed_receipt(call["json"])})

    coordinator, _, _, resolved, qr, _ = lease_helpers._accepted_coordinator(tmp_path, handler)
    prepared = lease_helpers._prepare_lease_transfer(coordinator, resolved, qr, "operation-lease-test-01")
    def old_validation(*_):
        raise TransferSealError("PHS2_WORK_GROUP_MEMBERSHIP_MISMATCH", "old QT omission")

    with monkeypatch.context() as old:
        old.setattr(coordinator, "_validate_bound_command", old_validation)
        assert coordinator.attempt(prepared.intent_id).status == "OPERATOR_REVIEW"
    original = dict(coordinator.store.load(prepared.intent_id))
    assert not posted
    assert coordinator.drain_pending() == []
    audits = []
    result = coordinator.retry_operator_review(
        prepared.intent_id, supervisor="review-admin", authorize=lambda: True,
        record_audit=lambda detail: audits.append(dict(detail)) or True,
    )
    assert result.status == "ACKED"
    assert len(posted) == len(audits) == 1
    current = coordinator.store.load(prepared.intent_id)
    for field in ("command_json", "command_hash", "idempotency_key", "local_completion_id"):
        assert current[field] == original[field]
    assert posted[0] == json.loads(original["command_json"])


def test_quantity_preservation_still_rejects_different_physical_membership():
    resolved = _quantity_snapshot(2)
    qr = resolved["phs_work_group"]["scan_payload"]
    fields = dict(part.split("=", 1) for part in qr.split("|"))
    resolved["phs_label_resolution"]["effective_labels"][0]["member_ids"] = ["different-member"]
    with pytest.raises(TransferSealError) as rejected:
        validate_compact_phs2_preflight(fields, resolved)
    assert rejected.value.code == "PHS2_WORK_GROUP_MEMBERSHIP_MISMATCH"


@pytest.mark.parametrize("quantity", [None, 2])
def test_legacy_physical_resolution_preserves_scanned_field_count(quantity):
    qr = _resolved_work_group_phs2(mode="merge")["phs_work_group"]["scan_payload"]
    if quantity is not None:
        qr += f"|QT={quantity}"
    fields = dict(part.split("=", 1) for part in qr.split("|"))
    label, _, _, _ = _physical_label_from_resolution(
        scanned_fields=fields, canonical_fields=fields, response={},
    )
    assert label["qr_payload"] == qr

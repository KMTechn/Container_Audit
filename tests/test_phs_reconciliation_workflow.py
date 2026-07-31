from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

import Container_Audit as container_module
import transfer_seal as transfer_seal_module
from Container_Audit import ContainerAudit, TraySession
from phs_label_workflow import (
    PHSLabelExchangeCoordinator,
    PHSLabelExchangeJournal,
    PHSLabelWorkflowError,
    PhysicalPrintEvidence,
    RenderedPHSLabel,
)
from phs_reconciliation_workflow import PHSReconciliationExchangeCoordinator
from transfer_seal import LogisticsTransferClient, TransferSealStore


SCOPE = "scope-transfer-reconciliation"
ITEM = "AAA2270730200"
DAY = "2026-07-28"
TARGET_DAY = "2026-07-29"


def _members(*values: str) -> list[str]:
    return sorted(values)


def _member_hash(values: list[str]) -> str:
    payload = json.dumps(
        tuple(sorted(values)),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _qr(label_id: str, suffix: str) -> str:
    digest = hashlib.sha256(suffix.encode("utf-8")).hexdigest()
    return (
        "PHS=2|SRC=KMTECH_INPUT_TAG|"
        f"ITG=ITAG-{suffix}|CLC={ITEM}|LBL={label_id}|HSH={digest[:16]}"
    )


def _source(index: int, members: list[str]) -> dict:
    label_id = f"LBL-SOURCE-{index}"
    return {
        "source_label_id": label_id,
        "group_id": f"PHSG-SOURCE-{index}",
        "instruction_id": f"PHSI-SOURCE-{index}",
        "business_date": DAY,
        "item_id": ITEM,
        "display_item_code": "2270730200",
        "item_daily_ordinal": index,
        "worker_code": f"2270730200-{index}",
        "qty_pcs": len(members),
        "label_version": 1,
        "membership_version": 1,
        "membership_hash": _member_hash(members),
        "member_ids": list(members),
        "qr_payload": _qr(label_id, f"SOURCE-{index}"),
    }


def _target(index: int, qty: int) -> dict:
    return {
        "instruction_id": f"PHSI-TARGET-{index}",
        "business_date": TARGET_DAY,
        "item_id": ITEM,
        "display_item_code": "2270730200",
        "item_daily_ordinal": index,
        "worker_code": f"2270730200-{index + 10}",
        "qty_pcs": qty,
    }


def _process_membership(members: list[str]) -> list[dict]:
    return [
        {
            "unit_id": member,
            "owner_type": "PACKAGE",
            "owner_id": f"TRANSFER-{member}",
            "bundle_type": "TRANSFER",
            "bundle_state": "AVAILABLE",
            "location_code": "TRANSFER",
            "unit_state": "AVAILABLE",
        }
        for member in members
    ]


def _resolution(kind: str) -> dict:
    kind = kind.upper()
    if kind == "SINGLE":
        action_specs = [
            (
                "EXCHANGE_DATE",
                [_source(1, _members("U1", "U2"))],
                [_target(1, 2)],
                {},
            ),
        ]
        mode = "SINGLE_EXCHANGE_DATE"
    elif kind == "BATCH":
        action_specs = [
            (
                "EXCHANGE_DATE",
                [_source(1, _members("U1", "U2"))],
                [_target(1, 2)],
                {},
            ),
            (
                "EXCHANGE_DATE",
                [_source(2, _members("U3", "U4"))],
                [_target(2, 2)],
                {},
            ),
        ]
        mode = "MULTI_EXCHANGE_DATE"
    elif kind == "SPLIT":
        source = _source(1, _members("U1", "U2", "U3", "U4"))
        targets = [_target(1, 2), _target(2, 2)]
        action_specs = [
            (
                "SPLIT",
                [source],
                targets,
                {
                    targets[0]["instruction_id"]: _members("U1", "U2"),
                    targets[1]["instruction_id"]: _members("U3", "U4"),
                },
            )
        ]
        mode = "SINGLE_TOPOLOGY"
    elif kind == "MERGE":
        action_specs = [
            (
                "MERGE",
                [
                    _source(1, _members("U1", "U2")),
                    _source(2, _members("U3", "U4")),
                ],
                [_target(1, 4)],
                {},
            )
        ]
        mode = "SINGLE_TOPOLOGY"
    else:
        raise AssertionError(kind)

    actions = []
    for index, (action_type, sources, targets, split) in enumerate(
        action_specs, start=1
    ):
        union = sorted(
            member for source in sources for member in source["member_ids"]
        )
        actions.append(
            {
                "action_id": f"PHSA-{kind}-{index}",
                "action_index": index,
                "action_type": action_type,
                "action_state": "PROPOSED",
                "exchange_id": None,
                "item_id": ITEM,
                "before_qty_pcs": len(union),
                "after_qty_pcs": 0,
                "sources": sources,
                "targets": targets,
                "source_member_union_count": len(union),
                "source_member_union_hash": _member_hash(union),
                "source_member_ids": union,
                "split_member_ids_by_target": split,
                "process_membership": _process_membership(union),
                "display": {
                    "item_id": ITEM,
                    "sources": [],
                    "targets": [],
                },
            }
        )
    scanned = actions[0]["sources"][0]
    return {
        "contract_version": "phs-work-control-v1",
        "authority_scope_id": SCOPE,
        "process_context": "transfer",
        "scan": {
            "resolution": "OVERLAY_ACTIVE",
            "scanned_label_id": scanned["source_label_id"],
            "active_label_id": scanned["source_label_id"],
            "replacement_required": False,
            "active_qr_payload": scanned["qr_payload"],
        },
        "reconciliation": {
            "reconciliation_id": f"PHSR-{kind}",
            "reconciliation_no": 1,
            "business_date": DAY,
            "state": "PROPOSED",
            "entity_version": 1,
            "proposed_at": "2026-07-28T00:00:00Z",
        },
        "actions": actions,
        "selection": {
            "reconciliation_id": f"PHSR-{kind}",
            "mode": mode,
            "action_ids": [action["action_id"] for action in actions],
            "expected_reconciliation_version": 1,
        },
    }


class FakeRenderer:
    def __init__(self, root: Path):
        self.root = root
        self.calls: list[str] = []

    def render(self, tray, target):
        label_id = str(target["label_id"])
        self.calls.append(label_id)
        path = self.root / f"{label_id}.png"
        path.write_bytes(
            f"{label_id}|{tray.item_code}|{tray.tray_size}".encode("utf-8")
        )
        return RenderedPHSLabel(
            str(path), hashlib.sha256(path.read_bytes()).hexdigest()
        )


class FakePrinter:
    def __init__(self, *, fail_once_label: str = ""):
        self.fail_once_label = fail_once_label
        self.calls: list[str] = []
        self.failed = False

    def print_png(self, path, *, document_name):
        label_id = Path(path).stem
        self.calls.append(label_id)
        if label_id == self.fail_once_label and not self.failed:
            self.failed = True
            raise RuntimeError("printer offline")
        return PhysicalPrintEvidence(
            printer_name="TEST",
            spool_job_id=len(self.calls),
            document_name=document_name,
            submitted_at="2026-07-28T00:00:00Z",
        )


class FakeReconciliationServer:
    authority_scope_id = SCOPE

    def __init__(self, resolution: dict):
        self.resolution = copy.deepcopy(resolution)
        self.context = (
            PHSReconciliationExchangeCoordinator.validate_resolution(
                self.resolution,
                authority_scope_id=SCOPE,
                scan_payload=self.resolution["scan"]["active_qr_payload"],
            )
        )
        self.exchange_id = "PHSX-RECONCILIATION"
        self.prepare_calls = 0
        self.prepare_writes = 0
        self.print_request_writes: dict[str, int] = {}
        self.print_complete_writes: dict[str, int] = {}
        self.activation_writes = 0
        self.prepare_response_lost_once = False
        self.activation_response_lost_once = False
        self._prepare_seen: dict[str, dict] = {}
        self._attempt_by_key: dict[str, dict] = {}
        self._attempts: dict[str, dict] = {}
        self._target_failed: dict[str, bool] = {}
        self._target_ready: dict[str, bool] = {}
        self._committed = False
        (
            self.sources,
            self.targets,
            self.edges,
            self.union,
        ) = PHSReconciliationExchangeCoordinator._expected_topology(
            self.context
        )
        self._target_labels = {}
        for index, target in enumerate(self.targets.values(), start=1):
            label_id = f"LBL-TARGET-{index}"
            digest = hashlib.sha256(label_id.encode("utf-8")).hexdigest()
            self._target_labels[target["instruction_id"]] = {
                "label_id": label_id,
                "group_id": f"PHSG-TARGET-{index}",
                "instruction_id": target["instruction_id"],
                "business_date": target["business_date"],
                "item_id": target["item_id"],
                "worker_code": target["worker_code"],
                "qr_payload": (
                    "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-TARGET-"
                    f"{index}|CLC={ITEM}|LBL={label_id}|HSH={digest[:16]}"
                ),
                "label_instance_hash": digest,
                "hash_prefix": digest[:16],
                "member_count": len(target["member_ids"]),
                "membership_hash": target["membership_hash"],
                "label_version": 1,
                "membership_version": 1,
                "scan_anchor_input_tag_id": f"ITAG-TARGET-{index}",
            }

    def resolve_phs_reconciliation_actions(self, **kwargs):
        assert kwargs == {
            "authority_scope_id": SCOPE,
            "scan_payload": self.resolution["scan"]["active_qr_payload"],
            "process_context": "transfer",
            "limit": 20,
        }
        return copy.deepcopy(self.resolution)

    def _state(self):
        if self._committed:
            return "COMMITTED"
        ready = list(self._target_ready.values())
        failed = list(self._target_failed.values())
        if ready and len(ready) == len(self._target_labels) and all(ready):
            return "READY"
        if any(ready):
            return "PRINT_PARTIAL"
        if any(failed):
            return "PRINT_FAILED"
        return "PREPARED"

    def _projection(self, *, linked=False, replayed=False):
        state = self._state()
        source_state = {
            "SINGLE": "SUPERSEDED",
            "BATCH": "SUPERSEDED",
            "SPLIT": "RETIRED_SPLIT",
            "MERGE": "RETIRED_MERGED",
        }[self.context["expected_exchange_kind"]]
        source_labels = []
        for source in self.sources.values():
            source_labels.append(
                {
                    "label_id": source["source_label_id"],
                    "qr_payload": source["qr_payload"],
                    "item_id": source["item_id"],
                    "member_count": len(source["member_ids"]),
                    "membership_hash": source["membership_hash"],
                    "label_version": source["label_version"],
                    "membership_version": source["membership_version"],
                    "state": source_state if self._committed else "ACTIVE",
                }
            )
        target_labels = []
        for instruction_id, label in self._target_labels.items():
            label_id = label["label_id"]
            target_labels.append(
                {
                    **label,
                    "state": (
                        "ACTIVE"
                        if self._committed
                        else "PRINT_FAILED"
                        if self._target_failed.get(label_id)
                        else "PENDING_ACTIVATION"
                    ),
                }
            )
        items = []
        for index, edge in enumerate(self.edges, start=1):
            target_label = self._target_labels[
                edge["target_instruction_id"]
            ]
            label_id = target_label["label_id"]
            item_state = (
                "COMMITTED"
                if self._committed
                else "READY"
                if self._target_ready.get(label_id)
                else "PRINT_FAILED"
                if self._target_failed.get(label_id)
                else "PREPARED"
            )
            items.append(
                {
                    "item_index": index,
                    "source_label_id": edge["source_label_id"],
                    "target_label_id": label_id,
                    "before_instruction_id": edge[
                        "source_instruction_id"
                    ],
                    "after_instruction_id": edge["target_instruction_id"],
                    "edge_role": edge["edge_role"],
                    "member_count": edge["member_count"],
                    "membership_hash": edge["membership_hash"],
                    "state": item_state,
                }
            )
        response = {
            "status": state,
            "replayed": replayed,
            "exchange": {
                "authority_scope_id": SCOPE,
                "exchange_id": self.exchange_id,
                "exchange_kind": self.context["expected_exchange_kind"],
                "state": state,
                "source_label_count": len(source_labels),
                "target_label_count": len(target_labels),
                "total_qty_pcs": len(self.union),
                "member_union_hash": _member_hash(list(self.union)),
                "entity_version": 2 + sum(self._target_ready.values()),
            },
            "source_labels": source_labels,
            "target_labels": target_labels,
            "items": items,
        }
        if linked:
            response["receipt_id"] = "RECEIPT-PREPARE-1"
            response["approved_action_ids"] = list(
                self.context["selection"]["action_ids"]
            )
            response["reconciliation"] = {
                "reconciliation_id": self.context["reconciliation"][
                    "reconciliation_id"
                ],
                "state": "APPROVED",
                "entity_version": 2,
                "actions": [
                    {
                        "action_id": action_id,
                        "state": "APPROVED",
                        "exchange_id": self.exchange_id,
                    }
                    for action_id in self.context["selection"]["action_ids"]
                ],
            }
        return response

    def prepare_phs_reconciliation_label_exchange(
        self,
        reconciliation_id,
        *,
        authority_scope_id,
        action_ids,
        expected_reconciliation_version,
        idempotency_key,
    ):
        self.prepare_calls += 1
        assert reconciliation_id == self.context["reconciliation"][
            "reconciliation_id"
        ]
        assert authority_scope_id == SCOPE
        assert action_ids == self.context["selection"]["action_ids"]
        assert expected_reconciliation_version == 1
        if idempotency_key not in self._prepare_seen:
            self.prepare_writes += 1
            self._prepare_seen[idempotency_key] = self._projection(linked=True)
            if self.prepare_response_lost_once:
                self.prepare_response_lost_once = False
                raise RuntimeError("prepare response lost")
        return {
            **copy.deepcopy(self._prepare_seen[idempotency_key]),
            "replayed": self.prepare_calls > 1,
        }

    def get_phs_label_exchange(self, exchange_id, **_kwargs):
        assert exchange_id == self.exchange_id
        return self._projection()

    def request_phs_label_print(
        self,
        exchange_id,
        *,
        authority_scope_id,
        label_id,
        idempotency_key,
    ):
        assert exchange_id == self.exchange_id
        assert authority_scope_id == SCOPE
        if idempotency_key not in self._attempt_by_key:
            attempt_no = sum(
                1
                for attempt in self._attempts.values()
                if attempt["label_id"] == label_id
            ) + 1
            attempt = {
                "print_attempt_id": f"PHSP-{len(self._attempts) + 1}",
                "label_id": label_id,
                "attempt_no": attempt_no,
                "state": "REQUESTED",
            }
            self._attempt_by_key[idempotency_key] = attempt
            self._attempts[attempt["print_attempt_id"]] = attempt
            self.print_request_writes[label_id] = (
                self.print_request_writes.get(label_id, 0) + 1
            )
        attempt = self._attempt_by_key[idempotency_key]
        self._target_failed[label_id] = False
        return {
            "print_attempt": copy.deepcopy(attempt),
            "exchange": self._projection()["exchange"],
        }

    def complete_phs_label_print(
        self,
        print_attempt_id,
        *,
        authority_scope_id,
        succeeded,
        **kwargs,
    ):
        assert authority_scope_id == SCOPE
        attempt = self._attempts[print_attempt_id]
        terminal = "SUCCEEDED" if succeeded else "FAILED"
        if attempt["state"] == "REQUESTED":
            attempt["state"] = terminal
            label_id = attempt["label_id"]
            self.print_complete_writes[label_id] = (
                self.print_complete_writes.get(label_id, 0) + 1
            )
            self._target_ready[label_id] = bool(succeeded)
            self._target_failed[label_id] = not succeeded
        else:
            assert attempt["state"] == terminal
        return {
            "print_attempt": copy.deepcopy(attempt),
            "exchange": self._projection()["exchange"],
        }

    def activate_phs_label_exchange(
        self,
        exchange_id,
        *,
        authority_scope_id,
        expected_exchange_version,
    ):
        assert exchange_id == self.exchange_id
        assert authority_scope_id == SCOPE
        assert expected_exchange_version >= 2
        if not self._committed:
            assert self._state() == "READY"
            self.activation_writes += 1
            self._committed = True
            if self.activation_response_lost_once:
                self.activation_response_lost_once = False
                raise RuntimeError("activation response lost")
        return self._projection()


def _coordinator(tmp_path, client, *, printer=None):
    return PHSLabelExchangeCoordinator(
        PHSLabelExchangeJournal(tmp_path / "recovery.json"),
        client,
        renderer=FakeRenderer(tmp_path),
        printer=printer or FakePrinter(),
    )


@pytest.mark.parametrize("kind", ("SINGLE", "BATCH", "SPLIT", "MERGE"))
def test_reconciliation_topologies_print_all_targets_then_activate_once(
    tmp_path, kind
):
    server = FakeReconciliationServer(_resolution(kind))
    coordinator = _coordinator(tmp_path, server)
    context = coordinator.reconciliation.resolve(
        server.resolution["scan"]["active_qr_payload"]
    )

    result = coordinator.reconciliation.execute(context)

    assert result.success is True
    assert result.status == "COMMITTED"
    assert server.prepare_writes == 1
    assert server.activation_writes == 1
    assert sum(server.print_request_writes.values()) == len(server.targets)
    assert sum(server.print_complete_writes.values()) == len(server.targets)
    assert (
        coordinator.reconciliation.recover()
        is None
    )


def test_partial_split_accepts_plan_coverage_below_physical_source_union():
    resolution = _resolution("SPLIT")
    resolution["actions"][0]["before_qty_pcs"] = 2
    resolution["actions"][0]["targets"][1]["business_date"] = DAY

    context = PHSReconciliationExchangeCoordinator.validate_resolution(
        resolution,
        authority_scope_id=SCOPE,
        scan_payload=resolution["scan"]["active_qr_payload"],
    )

    assert context["actions"][0]["before_qty_pcs"] == 2
    assert context["actions"][0]["source_member_union_count"] == 4
    assert context["actions"][0]["after_qty_pcs"] == 0


def test_completed_phs_source_resolves_for_transfer_reconciliation():
    resolution = _resolution("SINGLE")
    for member in resolution["actions"][0]["process_membership"]:
        member.update(
            owner_type="PACKAGE",
            bundle_type="PHS",
            bundle_state="AVAILABLE",
            location_code="PHS_GOOD",
            unit_state="CONSUMED",
        )

    context = PHSReconciliationExchangeCoordinator.validate_resolution(
        resolution,
        authority_scope_id=SCOPE,
        scan_payload=resolution["scan"]["active_qr_payload"],
    )

    assert context["actions"][0]["process_membership"] == (
        resolution["actions"][0]["process_membership"]
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("before_qty_pcs", 5),
        ("after_qty_pcs", 1),
        ("after_qty_pcs", -1),
    ),
)
def test_action_plan_quantity_outside_server_contract_fails_closed(
    field,
    value,
):
    resolution = _resolution("SINGLE")
    resolution["actions"][0][field] = value

    with pytest.raises(PHSLabelWorkflowError):
        PHSReconciliationExchangeCoordinator.validate_resolution(
            resolution,
            authority_scope_id=SCOPE,
            scan_payload=resolution["scan"]["active_qr_payload"],
        )


def test_lost_prepare_and_activate_responses_replay_without_duplicate_writes(
    tmp_path,
):
    server = FakeReconciliationServer(_resolution("BATCH"))
    server.prepare_response_lost_once = True
    server.activation_response_lost_once = True
    coordinator = _coordinator(tmp_path, server)
    context = coordinator.reconciliation.resolve(
        server.resolution["scan"]["active_qr_payload"]
    )

    interrupted = coordinator.reconciliation.execute(context)
    assert interrupted.success is False
    assert server.prepare_calls == 1
    assert server.prepare_writes == 1

    restarted = _coordinator(tmp_path, server)
    recovered = restarted.reconciliation.recover()

    assert recovered is not None and recovered.success is True
    assert server.prepare_calls == 2
    assert server.prepare_writes == 1
    assert server.activation_writes == 1
    assert len(server._prepare_seen) == 1
    assert len(server._target_labels) == 2


def test_partial_print_retry_only_prints_failed_target_after_restart(tmp_path):
    server = FakeReconciliationServer(_resolution("BATCH"))
    coordinator = _coordinator(tmp_path, server)
    context = coordinator.reconciliation.resolve(
        server.resolution["scan"]["active_qr_payload"]
    )
    failed_label = list(server._target_labels.values())[1]["label_id"]
    first_printer = FakePrinter(fail_once_label=failed_label)
    coordinator.reconciliation.printer = first_printer

    partial = coordinator.reconciliation.execute(context)

    assert partial.success is False
    assert partial.error_code == "LOCAL_PRINTER_ERROR"
    first_label = list(server._target_labels.values())[0]["label_id"]
    assert first_printer.calls == [first_label, failed_label]
    assert server.activation_writes == 0

    retry_printer = FakePrinter()
    restarted = _coordinator(tmp_path, server, printer=retry_printer)
    recovered = restarted.reconciliation.recover()

    assert recovered is not None and recovered.success is True
    assert retry_printer.calls == [failed_label]
    assert server.print_request_writes[first_label] == 1
    assert server.print_request_writes[failed_label] == 2
    assert server.prepare_writes == 1
    assert server.activation_writes == 1


def test_approved_scanned_action_resumes_linked_exchange_without_prepare(
    tmp_path,
):
    resolution = _resolution("SPLIT")
    for action in resolution["actions"]:
        action["action_state"] = "APPROVED"
        action["exchange_id"] = "PHSX-RECONCILIATION"
    resolution["reconciliation"]["state"] = "APPROVED"
    resolution["reconciliation"]["entity_version"] = 2
    resolution["selection"]["expected_reconciliation_version"] = 2
    server = FakeReconciliationServer(resolution)
    coordinator = _coordinator(tmp_path, server)

    context = coordinator.reconciliation.resolve(
        resolution["scan"]["active_qr_payload"]
    )
    result = coordinator.reconciliation.execute(context)

    assert result.success is True
    assert server.prepare_calls == 0
    assert server.prepare_writes == 0
    assert server.activation_writes == 1


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: value.update(process_context="packaging"),
        lambda value: value.update(authority_scope_id="other-scope"),
        lambda value: value["actions"][0]["process_membership"][0].update(
            location_code="SHIPPED"
        ),
        lambda value: value["actions"][0].update(
            source_member_union_hash="0" * 64
        ),
        lambda value: value["actions"][0]["targets"][0].update(qty_pcs=999),
    ),
)
def test_invalid_scope_process_location_hash_or_topology_fails_closed(
    tmp_path, mutate
):
    resolution = _resolution("SPLIT")
    mutate(resolution)
    server = object.__new__(FakeReconciliationServer)
    server.authority_scope_id = SCOPE
    server.resolution = resolution
    calls = []
    server.resolve_phs_reconciliation_actions = (
        lambda **_kwargs: calls.append("resolve") or copy.deepcopy(resolution)
    )
    server.prepare_phs_reconciliation_label_exchange = (
        lambda *_args, **_kwargs: calls.append("prepare") or {}
    )
    server.get_phs_label_exchange = lambda *_args, **_kwargs: {}
    server.request_phs_label_print = lambda *_args, **_kwargs: {}
    server.complete_phs_label_print = lambda *_args, **_kwargs: {}
    server.activate_phs_label_exchange = lambda *_args, **_kwargs: {}
    coordinator = _coordinator(tmp_path, server)

    with pytest.raises(Exception):
        coordinator.reconciliation.resolve(
            resolution["scan"]["active_qr_payload"]
        )

    assert calls == ["resolve"]


def test_wrong_prepared_target_hash_blocks_before_print_or_activation(tmp_path):
    server = FakeReconciliationServer(_resolution("MERGE"))
    original = server.prepare_phs_reconciliation_label_exchange

    def corrupt(*args, **kwargs):
        response = original(*args, **kwargs)
        response["target_labels"][0]["membership_hash"] = "0" * 64
        return response

    server.prepare_phs_reconciliation_label_exchange = corrupt
    coordinator = _coordinator(tmp_path, server)
    context = coordinator.reconciliation.resolve(
        server.resolution["scan"]["active_qr_payload"]
    )

    result = coordinator.reconciliation.execute(context)

    assert result.success is False
    assert result.error_code == "PHS_RECONCILIATION_TARGET_INVALID"
    assert server.print_request_writes == {}
    assert server.activation_writes == 0


class _ImmediateRoot:
    @staticmethod
    def after(_delay, callback, *args):
        callback(*args)
        return "after-id"


class _ImmediateThread:
    def __init__(self, *, target, **_kwargs):
        self.target = target

    def start(self):
        self.target()


class _Value:
    def __init__(self, value=False):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class _GridWidget:
    def __init__(self, *, mapped=False):
        self.mapped = mapped
        self.options = {}

    def grid(self, **_kwargs):
        self.mapped = True

    def grid_remove(self):
        self.mapped = False

    def grid_forget(self):
        self.mapped = False

    def winfo_ismapped(self):
        return self.mapped

    def configure(self, **kwargs):
        self.options.update(kwargs)


class _FocusEntry(_GridWidget):
    def __init__(self):
        super().__init__(mapped=True)
        self.focused = False
        self.selection = None

    def focus_set(self):
        self.focused = True

    def selection_range(self, start, end):
        self.selection = (start, end)


def test_idle_reconciliation_keeps_visible_button_enabled():
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession()
    app._active_blocking_completion_snapshot = lambda: None
    app._exact_transfer_exchange_blocked = lambda: False
    app._phs_label_exchange_transition_pending = lambda: False
    app._phs_label_exchange_available_for_tray = lambda: False
    app._phs_reconciliation_exchange_available = lambda: True
    app._refresh_phs_active_label_info = lambda: None
    app.phs_label_exchange_button = _GridWidget()
    app.phs_label_exchange_coordinator = type(
        "Coordinator",
        (),
        {"journal": type("Journal", (), {"load": lambda _self: {}})()},
    )()

    app._update_action_button_states()

    assert app.phs_label_exchange_button.options["text"] == "현품표 교체"
    assert (
        app.phs_label_exchange_button.options["state"]
        == container_module.tk.NORMAL
    )


def test_legacy_fallback_button_is_disabled_while_exchange_is_busy():
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession()
    app._active_blocking_completion_snapshot = lambda: None
    app._exact_transfer_exchange_blocked = lambda: False
    app._phs_label_exchange_transition_pending = lambda: False
    app._phs_label_exchange_available_for_tray = lambda: True
    app._phs_reconciliation_exchange_available = lambda: True
    app._refresh_phs_active_label_info = lambda: None
    app.phs_label_legacy_fallback_button = _GridWidget()
    app.phs_label_exchange_coordinator = type(
        "Coordinator",
        (),
        {"journal": type("Journal", (), {"load": lambda _self: {}})()},
    )()
    app._phs_label_exchange_pending = False
    app._phs_label_candidate_pending = False
    app._phs_label_refresh_pending = False

    app._update_action_button_states()
    assert (
        app.phs_label_legacy_fallback_button.options["state"]
        == container_module.tk.NORMAL
    )

    app._phs_label_candidate_pending = True
    app._update_action_button_states()
    assert (
        app.phs_label_legacy_fallback_button.options["state"]
        == container_module.tk.DISABLED
    )


def test_central_reconciliation_hides_legacy_manual_single_controls():
    calls = []
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession()
    app._phs_label_exchange_pending = False
    app._phs_reconciliation_context = None
    app._phs_reconciliation_scan_armed = False
    app.phs_label_exchange_frame = _GridWidget(mapped=False)
    app.phs_reconciliation_instruction_label = _GridWidget(mapped=False)
    app.phs_label_legacy_single_controls_frame = _GridWidget(mapped=True)
    app.phs_label_candidate_combo = _GridWidget(mapped=True)
    app.phs_label_legacy_fallback_button = _GridWidget(mapped=False)
    app._phs_label_exchange_available_for_tray = lambda: True
    app.phs_label_exchange_coordinator = type(
        "Coordinator",
        (),
        {
            "journal": type("Journal", (), {"load": lambda _self: {}})(),
            "reconciliation": type(
                "Reconciliation", (), {"available": True}
            )(),
        },
    )()
    app.show_status_message = (
        lambda message, *_args, **_kwargs: calls.append(("status", message))
    )
    app._schedule_focus_return = lambda: calls.append(("focus",))

    assert app._on_phs_label_exchange_shortcut() == "break"

    assert app.phs_label_exchange_frame.mapped is True
    assert app.phs_reconciliation_instruction_label.mapped is True
    assert app.phs_label_legacy_single_controls_frame.mapped is False
    assert app.phs_label_candidate_combo.mapped is False
    assert app.phs_label_legacy_fallback_button.mapped is True
    assert app._phs_reconciliation_scan_armed is True
    status_messages = [
        call[1] for call in calls if call and call[0] == "status"
    ]
    assert all(
        "교환 작업일" not in value and "후보" not in value
        for value in status_messages
    )

    app._phs_reconciliation_context = {"selection": {}}
    app._set_phs_label_exchange_panel_mode(reconciliation_mode=True)
    assert app.phs_label_candidate_combo.mapped is False

    app._set_phs_label_exchange_panel_mode(reconciliation_mode=False)
    assert app.phs_reconciliation_instruction_label.mapped is False
    assert app.phs_label_legacy_single_controls_frame.mapped is True
    assert app.phs_label_candidate_combo.mapped is True
    assert app.phs_label_legacy_fallback_button.mapped is False


def test_explicit_legacy_single_fallback_can_return_to_central_scan_mode():
    calls = []
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession()
    app._phs_label_exchange_pending = False
    app._phs_label_candidate_pending = False
    app._phs_label_refresh_pending = False
    app._phs_reconciliation_context = {"selection": {}}
    app._phs_reconciliation_scan_armed = True
    app.root = _ImmediateRoot()
    app.phs_label_exchange_frame = _GridWidget(mapped=False)
    app.phs_reconciliation_instruction_label = _GridWidget(mapped=True)
    app.phs_label_legacy_single_controls_frame = _GridWidget(mapped=False)
    app.phs_label_candidate_combo = _GridWidget(mapped=False)
    app.phs_label_legacy_fallback_button = _GridWidget(mapped=True)
    app.phs_label_exchange_execute_button = _GridWidget(mapped=True)
    app.phs_label_target_date_entry = _FocusEntry()
    app._phs_label_exchange_available_for_tray = lambda: True
    app._phs_reconciliation_exchange_available = lambda: True
    app._active_blocking_completion_snapshot = lambda: None
    app._phs_label_exchange_transition_pending = lambda: False
    app._refresh_phs_active_label_info = lambda: calls.append(("refresh",))
    app._update_action_button_states = lambda: calls.append(("states",))
    app.show_status_message = (
        lambda message, *_args, **_kwargs: calls.append(("status", message))
    )
    app._schedule_focus_return = lambda: calls.append(("focus",))

    assert app._show_phs_label_legacy_single_fallback() == "break"

    assert app._phs_reconciliation_context is None
    assert app._phs_reconciliation_scan_armed is False
    assert app._phs_legacy_single_fallback_mode is True
    assert app.phs_label_exchange_frame.mapped is True
    assert app.phs_reconciliation_instruction_label.mapped is False
    assert app.phs_label_legacy_single_controls_frame.mapped is True
    assert app.phs_label_candidate_combo.mapped is True
    assert app.phs_label_legacy_fallback_button.mapped is False
    assert app.phs_label_exchange_execute_button.options["text"] == (
        "선택 교환 실행"
    )
    assert any(
        call[0] == "status" and "보조 기능" in call[1]
        for call in calls
    )
    assert app.phs_label_target_date_entry.focused is True
    assert app.phs_label_target_date_entry.selection == (
        0,
        container_module.tk.END,
    )

    app._toggle_phs_label_exchange_panel()

    assert app._phs_reconciliation_scan_armed is True
    assert app._phs_legacy_single_fallback_mode is False
    assert app.phs_reconciliation_instruction_label.mapped is True
    assert app.phs_label_legacy_single_controls_frame.mapped is False
    assert app.phs_label_candidate_combo.mapped is False
    assert app.phs_label_legacy_fallback_button.mapped is True


@pytest.mark.parametrize(
    "busy_field",
    (
        "_phs_label_exchange_pending",
        "_phs_label_candidate_pending",
        "_phs_label_refresh_pending",
    ),
)
def test_legacy_single_fallback_does_not_clear_central_context_while_busy(
    busy_field,
):
    calls = []
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession()
    app._phs_label_exchange_pending = False
    app._phs_label_candidate_pending = False
    app._phs_label_refresh_pending = False
    setattr(app, busy_field, True)
    context = {"selection": {"action_ids": ["action-1"]}}
    app._phs_reconciliation_context = context
    app._phs_reconciliation_scan_armed = False
    app._active_blocking_completion_snapshot = lambda: None
    app._phs_label_exchange_transition_pending = lambda: False
    app._phs_label_exchange_available_for_tray = lambda: True
    app.show_status_message = (
        lambda message, *_args, **_kwargs: calls.append(("status", message))
    )
    app._schedule_focus_return = lambda: calls.append(("focus",))

    assert app._show_phs_label_legacy_single_fallback() == "break"

    assert app._phs_reconciliation_context is context
    assert any(
        call[0] == "status" and "먼저 완료" in call[1]
        for call in calls
    )
    assert ("focus",) in calls


@pytest.mark.parametrize("completed", (False, True))
def test_current_and_completed_transfer_label_scan_resolves_without_mutating_work(
    monkeypatch,
    completed,
):
    resolution = _resolution("SPLIT")
    payload = resolution["scan"]["active_qr_payload"]
    resolved = {
        **resolution,
        "expected_exchange_kind": "SPLIT",
        "topology_hash": "a" * 64,
        "_scanned_payload": payload,
    }
    calls = []

    class Reconciliation:
        available = True

        @staticmethod
        def resolve(value):
            calls.append(("resolve", value))
            return resolved

        @staticmethod
        def target_summaries(_context):
            return [f"{TARGET_DAY} · 2270730200-11 · 2 Pcs"]

    app = ContainerAudit.__new__(ContainerAudit)
    app.root = _ImmediateRoot()
    app.current_tray = TraySession()
    if not completed:
        app.current_tray.master_label_code = "CURRENT-TRAY"
        app.current_tray.scanned_barcodes.extend(["UNIT-1"])
    app.completed_master_labels = {payload} if completed else set()
    app._phs_reconciliation_scan_armed = True
    app._phs_label_candidate_pending = False
    app._phs_label_exchange_pending = False
    app.phs_label_exchange_coordinator = type(
        "Coordinator",
        (),
        {"reconciliation": Reconciliation()},
    )()
    app._parse_new_format_qr = container_module.parse_new_format_qr
    app._set_phs_reconciliation_context = lambda context: setattr(
        app, "_phs_reconciliation_context", context
    )
    app._update_action_button_states = lambda: calls.append(("buttons",))
    app.show_status_message = lambda message, *_args, **_kwargs: calls.append(
        ("status", message)
    )
    app._schedule_focus_return = lambda: calls.append(("focus",))
    app._log_event = lambda event, **_kwargs: calls.append(("event", event))
    tray = app.current_tray
    scans = tray.scanned_barcodes
    scans_before = tuple(scans)
    monkeypatch.setattr(container_module.threading, "Thread", _ImmediateThread)

    consumed = app._intercept_phs_reconciliation_scan(payload)

    assert consumed is True
    assert ("resolve", payload) in calls
    assert app._phs_reconciliation_context is resolved
    assert app.current_tray is tray
    assert app.current_tray.scanned_barcodes is scans
    assert tuple(scans) == scans_before
    assert app._phs_reconciliation_scan_armed is False
    assert app._intercept_phs_reconciliation_scan(payload) is False
    assert calls.count(("resolve", payload)) == 1
    assert ("focus",) in calls


def test_replacement_required_notice_is_yellow_non_modal_once_per_pair():
    notice = (
        "현품표 교체 필요. 작업은 계속할 수 있습니다. "
        "현재 현품표를 교체 대기로 분리해 주세요."
    )
    messages = []
    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession(
        master_label_code="CURRENT",
        tray_size=2,
        scanned_barcodes=["UNIT-1"],
    )
    app._phs_replacement_notice_pairs = set()
    app.show_status_message = lambda message, color, **kwargs: messages.append(
        (message, color, kwargs)
    )
    before = copy.deepcopy(app.current_tray)
    context = {
        "scan": {
            "replacement_required": True,
            "scanned_label_id": "LBL-OLD-INTERNAL",
            "active_label_id": "LBL-NEW-INTERNAL",
        }
    }

    assert app._show_phs_replacement_required_notice_once(context) is True
    assert app._show_phs_replacement_required_notice_once(context) is False

    assert len(messages) == 1
    assert messages[0][0] == notice
    assert messages[0][1] == app.COLOR_IDLE
    assert app.current_tray == before
    assert not any(
        marker in messages[0][0]
        for marker in (
            "ACTIVE successor",
            "OVERLAY_REPLACED",
            "LBL-",
            "UUID",
            "hash",
        )
    )


def test_replacement_notice_marks_durable_waiting_before_yellow_display(tmp_path):
    events = []
    durable_store = TransferSealStore(tmp_path / "replacement-notice.db")

    class RecordingStore:
        def mark_phs_replacement_waiting(self, **kwargs):
            events.append(("mark", kwargs))
            return durable_store.mark_phs_replacement_waiting(**kwargs)

    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession(
        master_label_code=(
            "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-WAIT-UI|"
            f"CLC={ITEM}|LBL=LBL-NEW-UI|HSH={'a' * 16}"
        ),
        item_code=ITEM,
        tray_size=2,
        scanned_barcodes=["UNIT-1"],
    )
    app.worker_name = "tester"
    app.transfer_seal_coordinator = type(
        "Coordinator",
        (),
        {"store": RecordingStore()},
    )()
    app._phs_replacement_notice_pairs = set()
    app.show_status_message = lambda message, color, **kwargs: events.append(
        ("status", message, color, kwargs)
    )
    context = {
        "process_context": "transfer",
        "scan": {
            "replacement_required": True,
            "scanned_label_id": "LBL-OLD-UI",
            "active_label_id": "LBL-NEW-UI",
        },
        "actions": [
            {
                "process_membership": [
                    {"unit_id": "UNIT-1", "location_code": "PHS_GOOD"},
                ]
            }
        ],
    }

    assert app._show_phs_replacement_required_notice_once(context) is True
    assert app._show_phs_replacement_required_notice_once(context) is False

    assert [event[0] for event in events] == ["mark", "status"]
    marked = events[0][1]
    assert marked["session_id"] == "ITAG-WAIT-UI"
    assert marked["process_context"] == "transfer"
    assert marked["location_codes"] == ["PHS_GOOD"]
    assert durable_store.replacement_waiting_outbox()[0]["event_type"] == (
        "PHS_REPLACEMENT_WAITING_MARKED"
    )


def test_replacement_waiting_write_failure_keeps_warning_and_logs_evidence():
    events = []

    class FailingStore:
        @staticmethod
        def mark_phs_replacement_waiting(**_kwargs):
            raise OSError("disk unavailable")

    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession(
        master_label_code=(
            "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-WAIT-FAIL|"
            f"CLC={ITEM}|LBL=LBL-NEW-FAIL|HSH={'b' * 16}"
        ),
        item_code=ITEM,
        tray_size=2,
        scanned_barcodes=["UNIT-1"],
    )
    before = copy.deepcopy(app.current_tray)
    app.worker_name = "tester"
    app.transfer_seal_coordinator = type(
        "Coordinator",
        (),
        {"store": FailingStore()},
    )()
    app._phs_replacement_notice_pairs = set()
    app._log_event = lambda event, detail=None, synchronous=False: events.append(
        ("evidence", event, detail, synchronous)
    ) or True
    app.show_status_message = lambda message, color, **kwargs: events.append(
        ("status", message, color, kwargs)
    )
    context = {
        "process_context": "transfer",
        "scan": {
            "replacement_required": True,
            "scanned_label_id": "LBL-OLD-FAIL",
            "active_label_id": "LBL-NEW-FAIL",
        },
    }

    assert app._show_phs_replacement_required_notice_once(context) is True
    assert app._show_phs_replacement_required_notice_once(context) is False

    assert [event[0] for event in events] == ["evidence", "status"]
    assert events[0][1] == "PHS_REPLACEMENT_WAITING_MARK_FAILED"
    assert events[0][2]["exception_type"] == "OSError"
    assert events[0][3] is True
    assert events[1][1] == container_module.PHS_REPLACEMENT_REQUIRED_NOTICE
    assert app.current_tray == before


def test_reconciliation_execute_rechecks_lookup_snapshot_before_worker_start():
    calls = []

    class Reconciliation:
        available = True

        @staticmethod
        def execute(*_args, **_kwargs):
            calls.append(("execute",))
            raise AssertionError("stale reconciliation must not execute")

    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession(
        master_label_code="CURRENT",
        tray_size=2,
        scanned_barcodes=["UNIT-1"],
    )
    app.phs_label_exchange_coordinator = type(
        "Coordinator",
        (),
        {"reconciliation": Reconciliation()},
    )()
    app._phs_reconciliation_context = {"selection": {"action_ids": ["A-1"]}}
    app._phs_reconciliation_execution_guard = (
        app._capture_phs_reconciliation_progress()
    )
    app._phs_label_exchange_pending = False
    app._phs_label_refresh_pending = False
    app.show_status_message = lambda message, *_args, **_kwargs: calls.append(
        ("status", message)
    )
    app._schedule_focus_return = lambda: calls.append(("focus",))
    app._set_phs_reconciliation_context = lambda value: (
        setattr(app, "_phs_reconciliation_context", value),
        setattr(app, "_phs_reconciliation_execution_guard", None),
    )
    app.current_tray.scanned_barcodes.append("UNIT-2")

    app._execute_phs_reconciliation_exchange()

    assert ("execute",) not in calls
    assert app.current_tray.scanned_barcodes == ["UNIT-1", "UNIT-2"]
    assert app._phs_reconciliation_context is None
    assert any(
        call[0] == "status" and "현재 이적 작업이 바뀌어" in call[1]
        for call in calls
    )
    assert ("focus",) in calls


def test_f8_executes_resolved_reconciliation_without_mouse():
    calls = []
    app = ContainerAudit.__new__(ContainerAudit)
    app._phs_label_exchange_pending = False
    app._phs_reconciliation_context = {"selection": {}}
    app._execute_selected_phs_label_exchange = lambda: calls.append(
        "execute"
    )
    app._schedule_focus_return = lambda: calls.append("focus")

    assert app._on_phs_label_exchange_shortcut() == "break"
    assert calls == ["execute"]


def test_reconciliation_ui_execution_preserves_tray_scan_progress_and_focus(
    monkeypatch,
):
    calls = []
    result = type(
        "Result",
        (),
        {
            "success": True,
            "status": "COMMITTED",
            "message": "완료",
            "error_code": "",
            "exchange_id": "PHSX-1",
            "journal_state": {},
        },
    )()

    class Reconciliation:
        available = True

        @staticmethod
        def execute(context, **_kwargs):
            calls.append(("execute", context))
            return result

    app = ContainerAudit.__new__(ContainerAudit)
    app.root = _ImmediateRoot()
    app.current_tray = TraySession(
        master_label_code="CURRENT",
        tray_size=2,
        scanned_barcodes=["UNIT-1"],
    )
    app.phs_label_exchange_coordinator = type(
        "Coordinator",
        (),
        {"reconciliation": Reconciliation()},
    )()
    context = {"expected_exchange_kind": "SPLIT"}
    app._phs_reconciliation_context = context
    app._phs_label_exchange_pending = False
    app._phs_label_refresh_pending = False
    app.phs_label_reprint_confirm_var = _Value(False)
    app._update_action_button_states = lambda: calls.append(("buttons",))
    app.show_status_message = lambda message, *_args, **_kwargs: calls.append(
        ("status", message)
    )
    app._schedule_focus_return = lambda: calls.append(("focus",))
    app._phs_exchange_status_from_worker = lambda message: calls.append(
        ("worker_status", message)
    )
    app._set_phs_reconciliation_context = lambda value: setattr(
        app, "_phs_reconciliation_context", value
    )
    app._log_event = lambda event, **_kwargs: calls.append(("event", event))
    app._update_current_item_label = lambda: None
    app._update_center_display = lambda: None
    tray = app.current_tray
    scans = tray.scanned_barcodes
    monkeypatch.setattr(container_module.threading, "Thread", _ImmediateThread)

    app._execute_phs_reconciliation_exchange()

    assert ("execute", context) in calls
    assert app.current_tray is tray
    assert app.current_tray.scanned_barcodes is scans
    assert scans == ["UNIT-1"]
    assert app._phs_reconciliation_context is None
    assert ("focus",) in calls


@pytest.mark.parametrize("approved", (False, True))
def test_startup_local_print_starting_recovery_uses_keyboard_confirmation(
    monkeypatch,
    approved,
):
    calls = []
    recovery_context = {"expected_exchange_kind": "SINGLE"}
    recovery = {
        "workflow_kind": "RECONCILIATION",
        "status": "LOCAL_PRINT_STARTING",
        "reconciliation_context": recovery_context,
    }
    result = type(
        "Result",
        (),
        {
            "success": True,
            "status": "COMMITTED",
            "message": "완료",
            "error_code": "",
            "exchange_id": "PHSX-RECOVERY",
            "journal_state": {},
        },
    )()

    class Journal:
        @staticmethod
        def load():
            calls.append(("journal_load",))
            return recovery

    class Reconciliation:
        available = True

        @staticmethod
        def execute(context, **kwargs):
            calls.append(("execute", context, kwargs))
            return result

    def askyesno(title, message, **kwargs):
        calls.append(("prompt", title, message, kwargs))
        return approved

    app = ContainerAudit.__new__(ContainerAudit)
    app.root = _ImmediateRoot()
    app.current_tray = TraySession(
        master_label_code="CURRENT",
        tray_size=2,
        scanned_barcodes=["UNIT-1"],
    )
    app.phs_label_exchange_coordinator = type(
        "Coordinator",
        (),
        {
            "journal": Journal(),
            "reconciliation": Reconciliation(),
        },
    )()
    app._phs_reconciliation_context = None
    app._phs_label_exchange_pending = False
    app._phs_label_refresh_pending = False
    app.phs_label_reprint_confirm_var = _Value(False)
    app._update_action_button_states = lambda: calls.append(("buttons",))
    app.show_status_message = lambda message, *_args, **_kwargs: calls.append(
        ("status", message)
    )
    app._schedule_focus_return = lambda: calls.append(("focus",))
    app._phs_exchange_status_from_worker = lambda message: calls.append(
        ("worker_status", message)
    )
    app._set_phs_reconciliation_context = lambda value: setattr(
        app, "_phs_reconciliation_context", value
    )
    app._log_event = lambda event, **_kwargs: calls.append(("event", event))
    app._update_current_item_label = lambda: None
    app._update_center_display = lambda: None
    monkeypatch.setattr(container_module.messagebox, "askyesno", askyesno)
    monkeypatch.setattr(container_module.threading, "Thread", _ImmediateThread)

    app._schedule_phs_label_exchange_recovery()

    prompts = [call for call in calls if call[0] == "prompt"]
    assert len(prompts) == 1
    assert "Y 승인 / N 취소" in prompts[0][2]
    assert prompts[0][3]["parent"] is app.root
    assert prompts[0][3]["default"] == container_module.messagebox.NO
    assert ("focus",) in calls
    execute_calls = [call for call in calls if call[0] == "execute"]
    if approved:
        assert len(execute_calls) == 1
        assert execute_calls[0][1] is None
        assert execute_calls[0][2]["confirm_ambiguous_reprint"] is True
        assert app._phs_reconciliation_context is None
        assert app.phs_label_reprint_confirm_var.get() is False
        assert app._phs_label_exchange_pending is False
    else:
        assert execute_calls == []
        assert app._phs_reconciliation_context is recovery_context
        assert app.phs_label_reprint_confirm_var.get() is False
        assert app._phs_label_exchange_pending is False
        assert any(
            call[0] == "status" and "보존했습니다" in call[1]
            for call in calls
        )


def test_target_summary_never_exposes_instruction_or_label_ids():
    context = (
        PHSReconciliationExchangeCoordinator.validate_resolution(
            _resolution("BATCH"),
            authority_scope_id=SCOPE,
            scan_payload=_resolution("BATCH")["scan"]["active_qr_payload"],
        )
    )

    summaries = (
        PHSReconciliationExchangeCoordinator.target_summaries(context)
    )

    assert summaries == [
        f"{TARGET_DAY} · 2270730200-11 · 2 Pcs",
        f"{TARGET_DAY} · 2270730200-12 · 2 Pcs",
    ]
    assert all("PHSI-" not in value and "LBL-" not in value for value in summaries)


def test_logistics_client_uses_exact_machine_resolve_and_prepare_contract():
    calls = []

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"ok": True, "data": {"contract_version": "v1"}}

    class Session:
        @staticmethod
        def request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return Response()

    client = LogisticsTransferClient(
        "https://server.example",
        "token",
        "TEST1",
        device_id="test1-common-host",
        session=Session(),
        authority_scope_id=SCOPE,
    )
    client.resolve_phs_reconciliation_actions(
        authority_scope_id=SCOPE,
        scan_payload="PHS=2|TEST=1",
        process_context="transfer",
        limit=20,
    )
    client.prepare_phs_reconciliation_label_exchange(
        "PHSR-001",
        authority_scope_id=SCOPE,
        action_ids=["PHSA-1", "PHSA-2"],
        expected_reconciliation_version=7,
        idempotency_key="container-reconciliation-prepare",
    )

    first = urlsplit(calls[0][1])
    assert calls[0][0] == "GET"
    assert first.path.endswith(
        "/phs-work-reconciliations/actions/resolve"
    )
    assert parse_qs(first.query) == {
        "authority_scope_id": [SCOPE],
        "scan_payload": ["PHS=2|TEST=1"],
        "process_context": ["transfer"],
        "limit": ["20"],
    }
    assert calls[0][2]["headers"]["X-Logistics-Program"] == "Container_Audit"
    assert calls[1][0] == "POST"
    assert urlsplit(calls[1][1]).path.endswith(
        "/phs-work-reconciliations/PHSR-001/label-exchange/prepare"
    )
    assert calls[1][2]["json"] == {
        "authority_scope_id": SCOPE,
        "action_ids": ["PHSA-1", "PHSA-2"],
        "expected_reconciliation_version": 7,
    }
    assert (
        calls[1][2]["headers"]["Idempotency-Key"]
        == "container-reconciliation-prepare"
    )


def test_production_transport_has_no_test1_ack_loss_hook():
    source = Path(transfer_seal_module.__file__).read_text(encoding="utf-8")

    assert "KMTECH_TEST1_DROP_" not in source

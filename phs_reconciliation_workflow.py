"""Server-owned reconciliation label exchange for the transfer desktop.

The work-plan service owns every selected action and every source/target
membership.  This client only validates the bounded projection, persists one
durable print journal, prints the server-issued target labels, and activates
the already prepared exchange once all targets have physical evidence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Sequence

from label_qr import parse_new_format_qr
from phs_label_workflow import (
    PHSLabelExchangeJournal,
    PHSLabelExchangeResult,
    PHSLabelWorkflowError,
    PHSPhysicalPrintError,
)
from transfer_seal import TransferSealError, validate_compact_phs2_fields


_TERMINAL_STATES = frozenset({"COMMITTED", "CANCELLED"})
_EXCHANGE_STATES = frozenset(
    {"PREPARED", "PRINT_FAILED", "PRINT_PARTIAL", "READY", "COMMITTED"}
)
_TRANSFER_SIGNATURES = frozenset(
    {
        ("PACKAGE", "PHS", "PHS_GOOD", "AVAILABLE"),
        ("PACKAGE", "PHS", "PHS_GOOD", "CONSUMED"),
        ("RESIDUAL", "RESIDUAL", "INSPECTION_RESIDUAL", "AVAILABLE"),
        ("PACKAGE", "TRANSFER", "TRANSFER", "AVAILABLE"),
    }
)


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise PHSLabelWorkflowError(
            "PHS_RECONCILIATION_EVIDENCE_INVALID",
            f"{field} 값이 올바르지 않습니다.",
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise PHSLabelWorkflowError(
            "PHS_RECONCILIATION_EVIDENCE_INVALID",
            f"{field} 값이 올바르지 않습니다.",
        ) from exc
    if parsed < 1:
        raise PHSLabelWorkflowError(
            "PHS_RECONCILIATION_EVIDENCE_INVALID",
            f"{field} 값이 올바르지 않습니다.",
        )
    return parsed


def _nonnegative_integer(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise PHSLabelWorkflowError(
            "PHS_RECONCILIATION_EVIDENCE_INVALID",
            f"{field} 값이 올바르지 않습니다.",
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise PHSLabelWorkflowError(
            "PHS_RECONCILIATION_EVIDENCE_INVALID",
            f"{field} 값이 올바르지 않습니다.",
        ) from exc
    if parsed < 0:
        raise PHSLabelWorkflowError(
            "PHS_RECONCILIATION_EVIDENCE_INVALID",
            f"{field} 값이 올바르지 않습니다.",
        )
    return parsed


def _canonical_members(values: Sequence[Any]) -> tuple[str, ...]:
    members = tuple(
        sorted(
            {
                str(value or "").strip()
                for value in values
                if str(value or "").strip()
            }
        )
    )
    if len(members) != len(values):
        raise PHSLabelWorkflowError(
            "PHS_RECONCILIATION_TOPOLOGY_INVALID",
            "중앙 action membership가 비어 있거나 중복됐습니다.",
        )
    return members


def _membership_hash(values: Sequence[Any]) -> str:
    members = _canonical_members(values)
    payload = json.dumps(
        members,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _stable_key(prefix: str, *parts: Any) -> str:
    fingerprint = hashlib.sha256(
        "|".join(str(value or "") for value in parts).encode("utf-8")
    ).hexdigest()
    return f"{prefix}:{fingerprint}"


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _valid_sha256(value: Any) -> str:
    digest = str(value or "").strip().lower()
    if (
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise PHSLabelWorkflowError(
            "PHS_RECONCILIATION_EVIDENCE_INVALID",
            "중앙 membership/hash 증거가 올바르지 않습니다.",
        )
    return digest


class PHSReconciliationExchangeCoordinator:
    """Resume one BATCH/SPLIT/MERGE exchange without recreating topology."""

    def __init__(
        self,
        journal: PHSLabelExchangeJournal,
        client: Any,
        *,
        renderer: Any,
        printer: Any,
        execution_lock: Any,
    ) -> None:
        self.journal = journal
        self.client = client
        self.renderer = renderer
        self.printer = printer
        self._execution_lock = execution_lock

    @property
    def available(self) -> bool:
        required = (
            "resolve_phs_reconciliation_actions",
            "prepare_phs_reconciliation_label_exchange",
            "get_phs_label_exchange",
            "request_phs_label_print",
            "complete_phs_label_print",
            "activate_phs_label_exchange",
        )
        return self.client is not None and all(
            callable(getattr(self.client, name, None)) for name in required
        )

    def _scope(self, authority_scope_id: str = "") -> str:
        supplied = str(authority_scope_id or "").strip()
        configured = str(
            getattr(self.client, "authority_scope_id", "") or ""
        ).strip()
        scope = supplied or configured
        if not scope or (supplied and configured and supplied != configured):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_SCOPE_INVALID",
                "설치 물류 프로필과 현품표 authority scope가 다릅니다.",
            )
        return scope

    @staticmethod
    def _source(value: Any, *, action_id: str, item_id: str) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_TOPOLOGY_INVALID",
                "중앙 source topology 형식이 올바르지 않습니다.",
            )
        source = dict(value)
        members = _canonical_members(list(source.get("member_ids") or []))
        count = _positive_integer(source.get("qty_pcs"), "source.qty_pcs")
        membership = _valid_sha256(source.get("membership_hash"))
        qr_payload = str(source.get("qr_payload") or "").strip()
        try:
            qr = validate_compact_phs2_fields(
                parse_new_format_qr(qr_payload) or {}
            )
        except TransferSealError as exc:
            raise PHSLabelWorkflowError(exc.code, str(exc)) from exc
        label_id = str(source.get("source_label_id") or "").strip()
        if (
            not action_id
            or not label_id
            or label_id != qr["LBL"]
            or str(source.get("item_id") or "").strip() != item_id
            or qr["CLC"] != item_id
            or len(members) != count
            or _membership_hash(members) != membership
            or not str(source.get("group_id") or "").strip()
            or not str(source.get("instruction_id") or "").strip()
            or not str(source.get("business_date") or "").strip()
            or not str(source.get("display_item_code") or "").strip()
            or not str(source.get("worker_code") or "").strip()
            or _positive_integer(
                source.get("item_daily_ordinal"),
                "source.item_daily_ordinal",
            )
            < 1
            or _positive_integer(
                source.get("label_version"), "source.label_version"
            )
            < 1
            or _positive_integer(
                source.get("membership_version"),
                "source.membership_version",
            )
            < 1
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_TOPOLOGY_INVALID",
                "중앙 source label/QR/member 증거가 일치하지 않습니다.",
            )
        source["member_ids"] = list(members)
        source["qty_pcs"] = count
        source["membership_hash"] = membership
        return source

    @staticmethod
    def _target(value: Any, *, item_id: str) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_TOPOLOGY_INVALID",
                "중앙 target topology 형식이 올바르지 않습니다.",
            )
        target = dict(value)
        if (
            not str(target.get("instruction_id") or "").strip()
            or not str(target.get("business_date") or "").strip()
            or str(target.get("item_id") or "").strip() != item_id
            or not str(target.get("display_item_code") or "").strip()
            or not str(target.get("worker_code") or "").strip()
            or _positive_integer(
                target.get("item_daily_ordinal"),
                "target.item_daily_ordinal",
            )
            < 1
            or _positive_integer(target.get("qty_pcs"), "target.qty_pcs")
            < 1
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_TOPOLOGY_INVALID",
                "중앙 target 날짜·작업코드·수량 증거가 불완전합니다.",
            )
        target["qty_pcs"] = int(target["qty_pcs"])
        return target

    @staticmethod
    def _validate_process_membership(
        action: Mapping[str, Any],
        members: tuple[str, ...],
    ) -> None:
        rows = action.get("process_membership")
        if not isinstance(rows, list) or len(rows) != len(members):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_PROCESS_INVALID",
                "중앙 transfer membership 증거의 수량이 다릅니다.",
            )
        projected: list[str] = []
        for raw in rows:
            if not isinstance(raw, Mapping):
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_PROCESS_INVALID",
                    "중앙 transfer membership 형식이 올바르지 않습니다.",
                )
            row = dict(raw)
            signature = (
                str(row.get("owner_type") or "").strip(),
                str(row.get("bundle_type") or "").strip(),
                str(row.get("location_code") or "").strip(),
                str(row.get("unit_state") or "").strip(),
            )
            if (
                signature not in _TRANSFER_SIGNATURES
                or not str(row.get("owner_id") or "").strip()
                or str(row.get("bundle_state") or "").strip()
                != "AVAILABLE"
            ):
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_PROCESS_INVALID",
                    "현품표 member가 이적 공정의 허용 위치·상태에 있지 않습니다.",
                )
            projected.append(str(row.get("unit_id") or "").strip())
        if _canonical_members(projected) != members:
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_PROCESS_INVALID",
                "중앙 transfer membership가 action source와 다릅니다.",
            )

    @classmethod
    def validate_resolution(
        cls,
        response: Mapping[str, Any],
        *,
        authority_scope_id: str,
        scan_payload: str,
    ) -> dict[str, Any]:
        if not isinstance(response, Mapping):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_RESPONSE_INVALID",
                "중앙 reconciliation 응답이 없습니다.",
            )
        value = dict(response)
        scan = (
            dict(value.get("scan"))
            if isinstance(value.get("scan"), Mapping)
            else {}
        )
        reconciliation = (
            dict(value.get("reconciliation"))
            if isinstance(value.get("reconciliation"), Mapping)
            else {}
        )
        selection = (
            dict(value.get("selection"))
            if isinstance(value.get("selection"), Mapping)
            else {}
        )
        actions_raw = value.get("actions")
        if (
            str(value.get("authority_scope_id") or "").strip()
            != authority_scope_id
            or str(value.get("process_context") or "").strip().lower()
            != "transfer"
            or not isinstance(actions_raw, list)
            or not 1 <= len(actions_raw) <= 20
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_RESPONSE_INVALID",
                "중앙 응답의 scope/process/action 범위가 이적 요청과 다릅니다.",
            )
        active_qr_payload = str(scan.get("active_qr_payload") or "").strip()
        scanned_payload = str(scan_payload or "").strip()
        try:
            active_qr = validate_compact_phs2_fields(
                parse_new_format_qr(active_qr_payload) or {}
            )
            scanned_qr = validate_compact_phs2_fields(
                parse_new_format_qr(scanned_payload) or {}
            )
        except TransferSealError as exc:
            raise PHSLabelWorkflowError(exc.code, str(exc)) from exc
        scanned_label_id = str(scan.get("scanned_label_id") or "").strip()
        active_label_id = str(scan.get("active_label_id") or "").strip()
        replacement_required = scan.get("replacement_required")
        if (
            str(scan.get("resolution") or "").strip().upper()
            not in {"OVERLAY_ACTIVE", "OVERLAY_REPLACED"}
            or scanned_label_id != scanned_qr["LBL"]
            or active_label_id != active_qr["LBL"]
            or not isinstance(replacement_required, bool)
            or replacement_required != (scanned_label_id != active_label_id)
            or (
                not replacement_required
                and scanned_qr != active_qr
            )
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_SCAN_INVALID",
                "스캔 라벨과 중앙 ACTIVE successor 증거가 일치하지 않습니다.",
            )
        reconciliation_id = str(
            reconciliation.get("reconciliation_id") or ""
        ).strip()
        expected_version = _positive_integer(
            reconciliation.get("entity_version"),
            "reconciliation.entity_version",
        )
        if (
            not reconciliation_id
            or str(reconciliation.get("state") or "").strip().upper()
            not in {"PROPOSED", "APPROVED"}
            or str(selection.get("reconciliation_id") or "").strip()
            != reconciliation_id
            or _positive_integer(
                selection.get("expected_reconciliation_version"),
                "selection.expected_reconciliation_version",
            )
            != expected_version
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_RESPONSE_INVALID",
                "중앙 reconciliation CAS 증거가 일치하지 않습니다.",
            )

        actions: list[dict[str, Any]] = []
        action_ids: list[str] = []
        global_sources: list[str] = []
        global_targets: list[str] = []
        global_members: list[str] = []
        for raw in actions_raw:
            if not isinstance(raw, Mapping):
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_TOPOLOGY_INVALID",
                    "중앙 action 형식이 올바르지 않습니다.",
                )
            action = dict(raw)
            action_id = str(action.get("action_id") or "").strip()
            action_type = str(action.get("action_type") or "").strip().upper()
            item_id = str(action.get("item_id") or "").strip()
            sources = [
                cls._source(source, action_id=action_id, item_id=item_id)
                for source in list(action.get("sources") or [])
            ]
            targets = [
                cls._target(target, item_id=item_id)
                for target in list(action.get("targets") or [])
            ]
            source_members = _canonical_members(
                [
                    member
                    for source in sources
                    for member in source["member_ids"]
                ]
            )
            action_state = str(
                action.get("action_state") or ""
            ).strip().upper()
            linked_exchange_id = str(
                action.get("exchange_id") or ""
            ).strip()
            before_qty_pcs = _positive_integer(
                action.get("before_qty_pcs"),
                "action.before_qty_pcs",
            )
            after_qty_pcs = _nonnegative_integer(
                action.get("after_qty_pcs"),
                "action.after_qty_pcs",
            )
            if (
                not action_id
                or not item_id
                or action_state not in {"PROPOSED", "APPROVED"}
                or (
                    action_state == "PROPOSED"
                    and linked_exchange_id
                )
                or (
                    action_state == "APPROVED"
                    and not linked_exchange_id
                )
                or _positive_integer(
                    action.get("action_index"), "action.action_index"
                )
                < 1
                or _positive_integer(
                    action.get("source_member_union_count"),
                    "action.source_member_union_count",
                )
                != len(source_members)
                or _valid_sha256(
                    action.get("source_member_union_hash")
                )
                != _membership_hash(source_members)
                or _canonical_members(
                    list(action.get("source_member_ids") or [])
                )
                != source_members
                or before_qty_pcs > len(source_members)
                or after_qty_pcs != 0
            ):
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_TOPOLOGY_INVALID",
                    "중앙 action source union 증거가 일치하지 않습니다.",
                )
            if action_type == "EXCHANGE_DATE":
                topology_ok = (
                    len(sources) == 1
                    and len(targets) == 1
                    and sources[0]["qty_pcs"] == targets[0]["qty_pcs"]
                    and action.get("split_member_ids_by_target") in ({}, None)
                )
            elif action_type == "SPLIT":
                split = action.get("split_member_ids_by_target")
                topology_ok = (
                    len(sources) == 1
                    and len(targets) >= 2
                    and isinstance(split, Mapping)
                    and sum(target["qty_pcs"] for target in targets)
                    == sources[0]["qty_pcs"]
                )
                if topology_ok:
                    partition: list[str] = []
                    normalized_split: dict[str, list[str]] = {}
                    for target in targets:
                        members = _canonical_members(
                            list(split.get(target["instruction_id"]) or [])
                        )
                        if len(members) != target["qty_pcs"]:
                            topology_ok = False
                            break
                        normalized_split[target["instruction_id"]] = list(
                            members
                        )
                        partition.extend(members)
                    if topology_ok:
                        topology_ok = (
                            _canonical_members(partition) == source_members
                        )
                        action["split_member_ids_by_target"] = (
                            normalized_split
                        )
            elif action_type == "MERGE":
                topology_ok = (
                    len(sources) >= 2
                    and len(targets) == 1
                    and sum(source["qty_pcs"] for source in sources)
                    == targets[0]["qty_pcs"]
                    and action.get("split_member_ids_by_target") in ({}, None)
                )
            else:
                topology_ok = False
            if not topology_ok:
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_TOPOLOGY_INVALID",
                    "중앙 EXCHANGE_DATE/SPLIT/MERGE topology가 올바르지 않습니다.",
                )
            cls._validate_process_membership(action, source_members)
            action["action_type"] = action_type
            action["action_state"] = action_state
            action["exchange_id"] = linked_exchange_id or None
            action["sources"] = sources
            action["targets"] = targets
            action["source_member_ids"] = list(source_members)
            action["source_member_union_count"] = len(source_members)
            action["source_member_union_hash"] = _membership_hash(
                source_members
            )
            actions.append(action)
            action_ids.append(action_id)
            global_sources.extend(
                source["source_label_id"] for source in sources
            )
            global_targets.extend(
                target["instruction_id"] for target in targets
            )
            global_members.extend(source_members)

        action_indexes = [
            int(action["action_index"]) for action in actions
        ]
        reconciliation_date = str(
            reconciliation.get("business_date") or ""
        ).strip()
        if (
            len(set(action_ids)) != len(action_ids)
            or action_indexes != sorted(set(action_indexes))
            or len(set(global_sources)) != len(global_sources)
            or len(set(global_targets)) != len(global_targets)
            or len(set(global_members)) != len(global_members)
            or active_label_id not in set(global_sources)
            or not reconciliation_date
            or any(
                str(source.get("business_date") or "").strip()
                != reconciliation_date
                for action in actions
                for source in action["sources"]
            )
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_TOPOLOGY_INVALID",
                "중앙 action 간 source/target/member가 중복되거나 스캔 source가 없습니다.",
            )
        linked_exchange_ids = {
            str(action.get("exchange_id") or "").strip()
            for action in actions
            if str(action.get("exchange_id") or "").strip()
        }
        if linked_exchange_ids and (
            len(linked_exchange_ids) != 1
            or any(
                action["action_state"] != "APPROVED"
                for action in actions
            )
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_SELECTION_INVALID",
                "중앙 action의 기존 exchange 연결이 서로 다릅니다.",
            )
        if not linked_exchange_ids and any(
            action["action_state"] != "PROPOSED" for action in actions
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_SELECTION_INVALID",
                "APPROVED action에는 기존 exchange 연결이 필요합니다.",
            )
        selected_ids = [
            str(value or "").strip()
            for value in list(selection.get("action_ids") or [])
        ]
        mode = str(selection.get("mode") or "").strip().upper()
        action_types = [action["action_type"] for action in actions]
        if selected_ids != action_ids:
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_SELECTION_INVALID",
                "중앙 selection action 순서가 반환 topology와 다릅니다.",
            )
        if all(value == "EXCHANGE_DATE" for value in action_types):
            exchange_kind = "SINGLE" if len(actions) == 1 else "BATCH"
            expected_mode = (
                "SINGLE_EXCHANGE_DATE"
                if len(actions) == 1
                else "MULTI_EXCHANGE_DATE"
            )
        elif len(actions) == 1 and action_types[0] in {"SPLIT", "MERGE"}:
            exchange_kind = action_types[0]
            expected_mode = "SINGLE_TOPOLOGY"
        else:
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_SELECTION_INVALID",
                "EXCHANGE_DATE batch 또는 단일 SPLIT/MERGE만 실행할 수 있습니다.",
            )
        if mode != expected_mode:
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_SELECTION_INVALID",
                "중앙 selection mode와 action cardinality가 다릅니다.",
            )
        value["scan"] = scan
        value["reconciliation"] = reconciliation
        value["selection"] = selection
        value["actions"] = actions
        value["expected_exchange_kind"] = exchange_kind
        value["source_member_union_hash"] = _membership_hash(global_members)
        value["source_member_union_count"] = len(global_members)
        value["linked_exchange_id"] = (
            next(iter(linked_exchange_ids))
            if linked_exchange_ids
            else ""
        )
        topology_value = {
            "authority_scope_id": authority_scope_id,
            "process_context": "transfer",
            "scan": scan,
            "reconciliation": reconciliation,
            "selection": selection,
            "actions": actions,
            "expected_exchange_kind": exchange_kind,
        }
        value["topology_hash"] = _canonical_hash(topology_value)
        return value

    def resolve(
        self,
        scan_payload: str,
        *,
        authority_scope_id: str = "",
    ) -> dict[str, Any]:
        if not self.available:
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_CLIENT_UNAVAILABLE",
                "중앙 reconciliation 교체 API 설정이 없습니다.",
                retryable=True,
            )
        scope = self._scope(authority_scope_id)
        payload = str(scan_payload or "").strip()
        response = self.client.resolve_phs_reconciliation_actions(
            authority_scope_id=scope,
            scan_payload=payload,
            process_context="transfer",
            limit=20,
        )
        resolved = self.validate_resolution(
            response,
            authority_scope_id=scope,
            scan_payload=payload,
        )
        resolved["_scanned_payload"] = payload
        return resolved

    @staticmethod
    def target_summaries(context: Mapping[str, Any]) -> list[str]:
        summaries: list[str] = []
        for action in list(context.get("actions") or []):
            for target in list(action.get("targets") or []):
                summaries.append(
                    f"{target.get('business_date')} · "
                    f"{target.get('worker_code')} · "
                    f"{int(target.get('qty_pcs') or 0)} Pcs"
                )
        return summaries

    @staticmethod
    def _expected_topology(
        context: Mapping[str, Any],
    ) -> tuple[
        dict[str, dict[str, Any]],
        dict[str, dict[str, Any]],
        list[dict[str, Any]],
        tuple[str, ...],
    ]:
        sources: dict[str, dict[str, Any]] = {}
        targets: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        global_members: list[str] = []
        for action in list(context.get("actions") or []):
            action_type = str(action.get("action_type") or "")
            action_sources = list(action.get("sources") or [])
            action_targets = list(action.get("targets") or [])
            for source in action_sources:
                sources[str(source["source_label_id"])] = dict(source)
                global_members.extend(source["member_ids"])
            if action_type == "EXCHANGE_DATE":
                memberships = [tuple(action_sources[0]["member_ids"])]
                roles = ["PAIR"]
                edge_sources = [action_sources[0]]
            elif action_type == "SPLIT":
                memberships = [
                    tuple(
                        action["split_member_ids_by_target"][
                            target["instruction_id"]
                        ]
                    )
                    for target in action_targets
                ]
                roles = ["SPLIT_SUCCESSOR"] * len(action_targets)
                edge_sources = [action_sources[0]] * len(action_targets)
            else:
                merged = tuple(
                    member
                    for source in action_sources
                    for member in source["member_ids"]
                )
                memberships = [merged]
                roles = ["MERGE_SOURCE"] * len(action_sources)
                edge_sources = action_sources
            if action_type == "MERGE":
                target = action_targets[0]
                targets[str(target["instruction_id"])] = {
                    **dict(target),
                    "member_ids": list(_canonical_members(merged)),
                    "membership_hash": _membership_hash(merged),
                }
                for source, role in zip(
                    edge_sources, roles, strict=True
                ):
                    edges.append(
                        {
                            "source_label_id": source["source_label_id"],
                            "source_instruction_id": source[
                                "instruction_id"
                            ],
                            "target_instruction_id": target[
                                "instruction_id"
                            ],
                            "edge_role": role,
                            "member_count": len(source["member_ids"]),
                            "membership_hash": _membership_hash(
                                source["member_ids"]
                            ),
                        }
                    )
            else:
                for source, target, members, role in zip(
                    edge_sources,
                    action_targets,
                    memberships,
                    roles,
                    strict=True,
                ):
                    canonical = _canonical_members(members)
                    targets[str(target["instruction_id"])] = {
                        **dict(target),
                        "member_ids": list(canonical),
                        "membership_hash": _membership_hash(canonical),
                    }
                    edges.append(
                        {
                            "source_label_id": source["source_label_id"],
                            "source_instruction_id": source[
                                "instruction_id"
                            ],
                            "target_instruction_id": target[
                                "instruction_id"
                            ],
                            "edge_role": role,
                            "member_count": len(canonical),
                            "membership_hash": _membership_hash(canonical),
                        }
                    )
        return (
            sources,
            targets,
            edges,
            _canonical_members(global_members),
        )

    @classmethod
    def _validate_exchange(
        cls,
        response: Mapping[str, Any],
        *,
        context: Mapping[str, Any],
        require_reconciliation_link: bool = False,
    ) -> tuple[
        dict[str, Any],
        list[dict[str, Any]],
        dict[str, bool],
    ]:
        exchange = (
            dict(response.get("exchange"))
            if isinstance(response.get("exchange"), Mapping)
            else {}
        )
        source_labels_raw = response.get("source_labels")
        target_labels_raw = response.get("target_labels")
        items_raw = response.get("items")
        sources, targets, expected_edges, union = cls._expected_topology(
            context
        )
        state = str(exchange.get("state") or "").strip().upper()
        exchange_id = str(exchange.get("exchange_id") or "").strip()
        if (
            not exchange_id
            or state not in _EXCHANGE_STATES
            or str(exchange.get("authority_scope_id") or "").strip()
            != str(context.get("authority_scope_id") or "").strip()
            or str(exchange.get("exchange_kind") or "").strip().upper()
            != str(context.get("expected_exchange_kind") or "").upper()
            or _positive_integer(
                exchange.get("source_label_count"),
                "exchange.source_label_count",
            )
            != len(sources)
            or _positive_integer(
                exchange.get("target_label_count"),
                "exchange.target_label_count",
            )
            != len(targets)
            or _positive_integer(
                exchange.get("total_qty_pcs"),
                "exchange.total_qty_pcs",
            )
            != len(union)
            or _valid_sha256(exchange.get("member_union_hash"))
            != _membership_hash(union)
            or not isinstance(source_labels_raw, list)
            or not isinstance(target_labels_raw, list)
            or not isinstance(items_raw, list)
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_EXCHANGE_INVALID",
                "중앙 exchange scope/kind/cardinality/hash 증거가 다릅니다.",
            )
        source_labels = {
            str(value.get("label_id") or "").strip(): dict(value)
            for value in source_labels_raw
            if isinstance(value, Mapping)
        }
        target_labels = [
            dict(value)
            for value in target_labels_raw
            if isinstance(value, Mapping)
        ]
        target_by_instruction = {
            str(value.get("instruction_id") or "").strip(): value
            for value in target_labels
        }
        if (
            len(source_labels) != len(source_labels_raw)
            or set(source_labels) != set(sources)
            or len(target_by_instruction) != len(target_labels_raw)
            or set(target_by_instruction) != set(targets)
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_EXCHANGE_INVALID",
                "중앙 source/target label cardinality가 action과 다릅니다.",
            )
        for label_id, expected in sources.items():
            actual = source_labels[label_id]
            if (
                str(actual.get("qr_payload") or "").strip()
                != str(expected.get("qr_payload") or "").strip()
                or str(actual.get("item_id") or "").strip()
                != str(expected.get("item_id") or "").strip()
                or _positive_integer(
                    actual.get("member_count"), "source.member_count"
                )
                != len(expected["member_ids"])
                or _valid_sha256(actual.get("membership_hash"))
                != str(expected["membership_hash"])
                or _positive_integer(
                    actual.get("label_version"),
                    "source.label_version",
                )
                < 1
                or _positive_integer(
                    actual.get("membership_version"),
                    "source.membership_version",
                )
                < 1
                or (
                    state != "COMMITTED"
                    and (
                        int(actual.get("label_version"))
                        != int(expected["label_version"])
                        or int(actual.get("membership_version"))
                        != int(expected["membership_version"])
                    )
                )
                or (
                    state != "COMMITTED"
                    and str(actual.get("state") or "").strip().upper()
                    != "ACTIVE"
                )
                or (
                    state == "COMMITTED"
                    and str(actual.get("state") or "").strip().upper()
                    not in {
                        "SUPERSEDED",
                        "RETIRED_SPLIT",
                        "RETIRED_MERGED",
                    }
                )
            ):
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_SOURCE_INVALID",
                    "중앙 exchange source label/hash/state가 action과 다릅니다.",
                )
        label_by_instruction: dict[str, str] = {}
        for instruction_id, expected in targets.items():
            actual = target_by_instruction[instruction_id]
            label_id = str(actual.get("label_id") or "").strip()
            qr_payload = str(actual.get("qr_payload") or "").strip()
            try:
                qr = validate_compact_phs2_fields(
                    parse_new_format_qr(qr_payload) or {}
                )
            except TransferSealError as exc:
                raise PHSLabelWorkflowError(exc.code, str(exc)) from exc
            label_hash = _valid_sha256(actual.get("label_instance_hash"))
            prefix = str(actual.get("hash_prefix") or "").strip().lower()
            target_state = str(actual.get("state") or "").strip().upper()
            if (
                not label_id
                or label_id != qr["LBL"]
                or qr["CLC"] != str(expected["item_id"])
                or prefix != qr["HSH"]
                or label_hash[:16] != prefix
                or str(
                    actual.get("scan_anchor_input_tag_id") or ""
                ).strip()
                != qr["ITG"]
                or str(actual.get("business_date") or "").strip()
                != str(expected["business_date"])
                or str(actual.get("worker_code") or "").strip()
                != str(expected["worker_code"])
                or _positive_integer(
                    actual.get("member_count"), "target.member_count"
                )
                != len(expected["member_ids"])
                or _valid_sha256(actual.get("membership_hash"))
                != str(expected["membership_hash"])
                or _positive_integer(
                    actual.get("label_version"),
                    "target.label_version",
                )
                < 1
                or _positive_integer(
                    actual.get("membership_version"),
                    "target.membership_version",
                )
                < 1
                or (
                    state == "COMMITTED" and target_state != "ACTIVE"
                )
                or (
                    state != "COMMITTED"
                    and target_state
                    not in {"PENDING_ACTIVATION", "PRINT_FAILED"}
                )
            ):
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_TARGET_INVALID",
                    "중앙 target QR/date/worker/quantity/hash/state가 action과 다릅니다.",
                )
            label_by_instruction[instruction_id] = label_id

        expected_item_edges = [
            {
                **edge,
                "target_label_id": label_by_instruction[
                    edge["target_instruction_id"]
                ],
            }
            for edge in expected_edges
        ]
        actual_edges: list[dict[str, Any]] = []
        readiness: dict[str, list[bool]] = {
            label_id: [] for label_id in label_by_instruction.values()
        }
        item_indexes: list[int] = []
        for raw in items_raw:
            if not isinstance(raw, Mapping):
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_EXCHANGE_INVALID",
                    "중앙 exchange item 형식이 올바르지 않습니다.",
                )
            item = dict(raw)
            item_state = str(item.get("state") or "").strip().upper()
            label_id = str(item.get("target_label_id") or "").strip()
            if label_id not in readiness or item_state not in {
                "PREPARED",
                "PRINT_FAILED",
                "READY",
                "COMMITTED",
            }:
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_EXCHANGE_INVALID",
                    "중앙 exchange item target/state가 올바르지 않습니다.",
                )
            readiness[label_id].append(
                item_state in {"READY", "COMMITTED"}
            )
            item_indexes.append(
                _positive_integer(
                    item.get("item_index"), "item.item_index"
                )
            )
            actual_edges.append(
                {
                    "source_label_id": str(
                        item.get("source_label_id") or ""
                    ).strip(),
                    "target_instruction_id": str(
                        item.get("after_instruction_id") or ""
                    ).strip(),
                    "source_instruction_id": str(
                        item.get("before_instruction_id") or ""
                    ).strip(),
                    "target_label_id": label_id,
                    "edge_role": str(
                        item.get("edge_role") or ""
                    ).strip().upper(),
                    "member_count": _positive_integer(
                        item.get("member_count"), "item.member_count"
                    ),
                    "membership_hash": _valid_sha256(
                        item.get("membership_hash")
                    ),
                }
            )
        if sorted(item_indexes) != list(
            range(1, len(expected_item_edges) + 1)
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_EXCHANGE_INVALID",
                "중앙 exchange item index가 연속 exact cardinality가 아닙니다.",
            )
        edge_sort = lambda edge: (
            edge["source_label_id"],
            edge["source_instruction_id"],
            edge["target_instruction_id"],
            edge["target_label_id"],
            edge["edge_role"],
        )
        if sorted(actual_edges, key=edge_sort) != sorted(
            expected_item_edges, key=edge_sort
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_EXCHANGE_INVALID",
                "중앙 exchange edge topology가 reconciliation action과 다릅니다.",
            )
        target_ready = {
            label_id: bool(states) and all(states)
            for label_id, states in readiness.items()
        }
        if (
            state == "READY"
            and not all(target_ready.values())
        ) or (
            state == "COMMITTED"
            and not all(target_ready.values())
        ):
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_EXCHANGE_INVALID",
                "중앙 READY/COMMITTED 상태와 target print 상태가 다릅니다.",
            )
        if require_reconciliation_link:
            if not str(response.get("receipt_id") or "").strip():
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_LINK_INVALID",
                    "중앙 prepare receipt 증거가 없습니다.",
                )
            approved_ids = [
                str(value or "").strip()
                for value in list(response.get("approved_action_ids") or [])
            ]
            reconciliation = (
                dict(response.get("reconciliation"))
                if isinstance(response.get("reconciliation"), Mapping)
                else {}
            )
            expected_ids = list(
                context.get("selection", {}).get("action_ids") or []
            )
            linked_actions = [
                action
                for action in list(reconciliation.get("actions") or [])
                if isinstance(action, Mapping)
                and str(action.get("action_id") or "") in set(expected_ids)
            ]
            if (
                approved_ids != expected_ids
                or str(
                    reconciliation.get("reconciliation_id") or ""
                ).strip()
                != str(
                    context.get("reconciliation", {}).get(
                        "reconciliation_id"
                    )
                    or ""
                ).strip()
                or len(linked_actions) != len(expected_ids)
                or any(
                    str(action.get("exchange_id") or "").strip()
                    != exchange_id
                    or str(action.get("state") or "").strip().upper()
                    not in {"APPROVED", "APPLIED"}
                    for action in linked_actions
                )
            ):
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_LINK_INVALID",
                    "중앙 action/reconciliation과 prepared exchange 연결이 다릅니다.",
                )
        return exchange, target_labels, target_ready

    @staticmethod
    def _print_proof(value: Any) -> dict[str, Any]:
        if callable(getattr(value, "to_server_proof", None)):
            proof = dict(value.to_server_proof())
        elif isinstance(value, Mapping):
            proof = dict(value)
        else:
            proof = {}
        if (
            proof.get("attached") is not True
            or not proof.get("spool_job_id")
            or str(proof.get("proof_kind") or "").strip()
            != "WINDOWS_GDI_SPOOL"
            or proof.get("windows_gdi_end_doc") is not True
        ):
            raise PHSPhysicalPrintError(
                "실제 Windows GDI spool 성공 증거가 불완전합니다."
            )
        return proof

    def _save(self, state: Mapping[str, Any], **updates: Any) -> dict[str, Any]:
        return self.journal.save({**dict(state or {}), **updates})

    def _result(
        self,
        state: Mapping[str, Any],
        *,
        success: bool,
        message: str,
        error_code: str = "",
        retryable: bool = False,
    ) -> PHSLabelExchangeResult:
        return PHSLabelExchangeResult(
            status=str(state.get("status") or "FAILED"),
            success=success,
            message=message,
            error_code=error_code,
            retryable=retryable,
            exchange_id=str(state.get("exchange_id") or ""),
            journal_state=dict(state),
        )

    def execute(
        self,
        context: Mapping[str, Any] | None = None,
        *,
        confirm_ambiguous_reprint: bool = False,
        status_callback: Callable[[str], None] | None = None,
    ) -> PHSLabelExchangeResult:
        if not self._execution_lock.acquire(blocking=False):
            return PHSLabelExchangeResult(
                status="BUSY",
                success=False,
                message="현품표 reconciliation 교체가 이미 진행 중입니다.",
                error_code="PHS_LABEL_EXCHANGE_BUSY",
                retryable=True,
            )
        try:
            return self._execute(
                context,
                confirm_ambiguous_reprint=confirm_ambiguous_reprint,
                status_callback=status_callback,
            )
        except (PHSLabelWorkflowError, TransferSealError) as exc:
            try:
                state = self.journal.load()
            except PHSLabelWorkflowError:
                state = {}
            return self._result(
                state,
                success=False,
                message=str(exc),
                error_code=str(
                    getattr(exc, "code", "PHS_RECONCILIATION_FAILED")
                ),
                retryable=bool(getattr(exc, "retryable", False)),
            )
        except Exception as exc:
            try:
                state = self.journal.load()
            except PHSLabelWorkflowError:
                state = {}
            return self._result(
                state,
                success=False,
                message=(
                    "현품표 reconciliation 교체 응답을 확인하지 못했습니다: "
                    f"{exc.__class__.__name__}"
                ),
                error_code="PHS_RECONCILIATION_UNAVAILABLE",
                retryable=True,
            )
        finally:
            self._execution_lock.release()

    def _load_or_start(
        self,
        context: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        state = self.journal.load()
        status = str(state.get("status") or "").strip().upper()
        active_state = bool(state and status not in _TERMINAL_STATES)
        if active_state:
            if str(state.get("workflow_kind") or "") != "RECONCILIATION":
                raise PHSLabelWorkflowError(
                    "PHS_LABEL_RECOVERY_CONFLICT",
                    "미완료 SINGLE 현품표 교환을 먼저 복구해야 합니다.",
                )
            saved_context = (
                dict(state.get("reconciliation_context"))
                if isinstance(
                    state.get("reconciliation_context"), Mapping
                )
                else {}
            )
            expected_hash = str(state.get("topology_hash") or "").strip()
            if (
                not saved_context
                or expected_hash
                != str(saved_context.get("topology_hash") or "").strip()
                or expected_hash
                != _canonical_hash(
                    {
                        key: saved_context[key]
                        for key in (
                            "authority_scope_id",
                            "process_context",
                            "scan",
                            "reconciliation",
                            "selection",
                            "actions",
                            "expected_exchange_kind",
                        )
                    }
                )
            ):
                raise PHSLabelWorkflowError(
                    "PHS_LABEL_JOURNAL_CORRUPT",
                    "reconciliation recovery topology가 변경됐습니다.",
                )
            if context is not None and str(
                context.get("topology_hash") or ""
            ) != expected_hash:
                raise PHSLabelWorkflowError(
                    "PHS_LABEL_RECOVERY_CONFLICT",
                    "다른 reconciliation 교체가 복구 대기 중입니다.",
                )
            return state, saved_context
        if context is None:
            raise PHSLabelWorkflowError(
                "PHS_RECONCILIATION_CONTEXT_REQUIRED",
                "먼저 교체할 현품표를 스캔해 중앙 action을 조회하세요.",
            )
        validated = self.validate_resolution(
            context,
            authority_scope_id=str(
                context.get("authority_scope_id") or ""
            ).strip(),
            scan_payload=str(context.get("_scanned_payload") or ""),
        )
        reconciliation = validated["reconciliation"]
        selection = validated["selection"]
        action_ids = list(selection["action_ids"])
        prepare_key = _stable_key(
            "container-phs-reconciliation-prepare",
            validated["authority_scope_id"],
            reconciliation["reconciliation_id"],
            selection["expected_reconciliation_version"],
            *action_ids,
        )
        state = self._save(
            {},
            workflow_kind="RECONCILIATION",
            status="PREPARE_PENDING",
            authority_scope_id=validated["authority_scope_id"],
            reconciliation_id=reconciliation["reconciliation_id"],
            reconciliation_context=validated,
            topology_hash=validated["topology_hash"],
            prepare_idempotency_key=prepare_key,
            exchange_id=str(validated.get("linked_exchange_id") or ""),
            targets={},
        )
        return state, validated

    @staticmethod
    def _validate_artifact(progress: Mapping[str, Any]) -> None:
        path = Path(str(progress.get("rendered_path") or ""))
        expected = _valid_sha256(progress.get("rendered_artifact_hash"))
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise PHSLabelWorkflowError(
                "PHS_LOCAL_PRINT_ARTIFACT_INVALID",
                "복구할 현품표 출력 파일을 확인할 수 없습니다.",
            ) from exc
        if actual != expected:
            raise PHSLabelWorkflowError(
                "PHS_LOCAL_PRINT_ARTIFACT_INVALID",
                "복구할 현품표 출력 파일 hash가 journal과 다릅니다.",
            )

    def _save_target(
        self,
        state: Mapping[str, Any],
        label_id: str,
        progress: Mapping[str, Any],
        *,
        status: str,
        **updates: Any,
    ) -> dict[str, Any]:
        targets = {
            str(key): dict(value)
            for key, value in dict(state.get("targets") or {}).items()
            if isinstance(value, Mapping)
        }
        targets[label_id] = {
            **dict(progress),
            **updates,
            "status": status,
        }
        return self._save(state, status=status, targets=targets)

    def _record_print_failure(
        self,
        state: Mapping[str, Any],
        *,
        label_id: str,
        progress: Mapping[str, Any],
        scope: str,
        error: Exception,
    ) -> PHSLabelExchangeResult:
        message = (str(error) or error.__class__.__name__)[:1024]
        state = self._save_target(
            state,
            label_id,
            progress,
            status="PRINT_FAILURE_ACK_PENDING",
            print_error_code="LOCAL_PRINTER_ERROR",
            print_error_message=message,
        )
        failed = self.client.complete_phs_label_print(
            str(progress.get("print_attempt_id") or ""),
            authority_scope_id=scope,
            succeeded=False,
            error_code="LOCAL_PRINTER_ERROR",
            error_message=message,
        )
        failed_attempt = (
            dict(failed.get("print_attempt"))
            if isinstance(failed.get("print_attempt"), Mapping)
            else {}
        )
        if (
            str(failed_attempt.get("print_attempt_id") or "").strip()
            != str(progress.get("print_attempt_id") or "").strip()
            or str(failed_attempt.get("state") or "").strip().upper()
            != "FAILED"
        ):
            raise PHSLabelWorkflowError(
                "PHS_PRINT_FAILURE_ACK_INVALID",
                "중앙 FAILED print-attempt 증거가 일치하지 않습니다.",
            )
        state = self._save_target(
            state,
            label_id,
            progress,
            status="PRINT_FAILED",
            print_failure_ack=dict(failed),
            print_error_code="LOCAL_PRINTER_ERROR",
            print_error_message=message,
        )
        return self._result(
            state,
            success=False,
            message=(
                "출력 실패 target만 재시도 대기 중입니다. 기존 현품표는 "
                "활성화 전까지 그대로 유지됩니다."
            ),
            error_code="LOCAL_PRINTER_ERROR",
            retryable=True,
        )

    def _execute(
        self,
        context: Mapping[str, Any] | None,
        *,
        confirm_ambiguous_reprint: bool,
        status_callback: Callable[[str], None] | None,
    ) -> PHSLabelExchangeResult:
        notify = status_callback if callable(status_callback) else lambda _value: None
        if context is not None:
            context = {**dict(context), "_scanned_payload": str(
                context.get("_scanned_payload")
                or context.get("scan", {}).get("scanned_qr_payload")
                or ""
            )}
        state, context_value = self._load_or_start(context)
        scope = str(state.get("authority_scope_id") or "").strip()
        reconciliation_id = str(
            state.get("reconciliation_id") or ""
        ).strip()
        selection = context_value["selection"]
        expected_key = _stable_key(
            "container-phs-reconciliation-prepare",
            scope,
            reconciliation_id,
            selection["expected_reconciliation_version"],
            *list(selection["action_ids"]),
        )
        if (
            not scope
            or not reconciliation_id
            or str(state.get("prepare_idempotency_key") or "") != expected_key
        ):
            raise PHSLabelWorkflowError(
                "PHS_LABEL_JOURNAL_CORRUPT",
                "reconciliation prepare identity가 변경됐습니다.",
            )
        exchange_id = str(state.get("exchange_id") or "").strip()
        notify("중앙 reconciliation 교체 prepare/복구 상태를 확인합니다.")
        if not exchange_id:
            try:
                prepared = (
                    self.client.prepare_phs_reconciliation_label_exchange(
                        reconciliation_id,
                        authority_scope_id=scope,
                        action_ids=list(selection["action_ids"]),
                        expected_reconciliation_version=int(
                            selection["expected_reconciliation_version"]
                        ),
                        idempotency_key=expected_key,
                    )
                )
            except TransferSealError as exc:
                if exc.committed is False:
                    self._save(
                        state,
                        status="CANCELLED",
                        prepare_error={
                            "code": exc.code,
                            "message": str(exc),
                        },
                    )
                raise
            exchange, target_labels, target_ready = self._validate_exchange(
                prepared,
                context=context_value,
                require_reconciliation_link=True,
            )
            exchange_id = str(exchange["exchange_id"])
            targets = {
                str(label["label_id"]): {
                    "label": dict(label),
                    "status": (
                        "PRINT_COMPLETED"
                        if target_ready[str(label["label_id"])]
                        else "PREPARED"
                    ),
                    "print_attempt_no": 0,
                    "print_attempt_id": "",
                    "print_idempotency_key": "",
                }
                for label in target_labels
            }
            state = self._save(
                state,
                status="PREPARED",
                exchange_id=exchange_id,
                exchange_entity_version=_positive_integer(
                    exchange.get("entity_version"),
                    "exchange.entity_version",
                ),
                targets=targets,
                prepare_ack=dict(prepared),
            )
            central = prepared
        else:
            central = self.client.get_phs_label_exchange(
                exchange_id,
                authority_scope_id=scope,
            )
            exchange, target_labels, target_ready = self._validate_exchange(
                central,
                context=context_value,
            )
            if str(exchange.get("exchange_id") or "").strip() != exchange_id:
                raise PHSLabelWorkflowError(
                    "PHS_RECONCILIATION_EXCHANGE_INVALID",
                    "복구 exchange id가 journal과 다릅니다.",
                )
            if not dict(state.get("targets") or {}):
                targets = {
                    str(label["label_id"]): {
                        "label": dict(label),
                        "status": (
                            "PRINT_COMPLETED"
                            if target_ready[str(label["label_id"])]
                            else "PREPARED"
                        ),
                        "print_attempt_no": 0,
                        "print_attempt_id": "",
                        "print_idempotency_key": "",
                    }
                    for label in target_labels
                }
                state = self._save(
                    state,
                    status="PREPARED",
                    exchange_entity_version=_positive_integer(
                        exchange.get("entity_version"),
                        "exchange.entity_version",
                    ),
                    targets=targets,
                )
        exchange_state = str(exchange.get("state") or "").strip().upper()
        if exchange_state == "COMMITTED":
            committed = self._save(
                state,
                status="COMMITTED",
                committed_ack=dict(central),
            )
            summaries = self.target_summaries(context_value)
            return self._result(
                committed,
                success=True,
                message=(
                    f"현품표 교체 복구 완료 · {len(summaries)}장 · "
                    + " / ".join(summaries[:3])
                ),
            )

        progress_by_label = {
            str(key): dict(value)
            for key, value in dict(state.get("targets") or {}).items()
            if isinstance(value, Mapping)
        }
        target_ids = [
            str(label.get("label_id") or "").strip()
            for label in target_labels
        ]
        if set(progress_by_label) != set(target_ids):
            raise PHSLabelWorkflowError(
                "PHS_LABEL_JOURNAL_CORRUPT",
                "reconciliation target journal cardinality가 중앙과 다릅니다.",
            )

        for target_label in target_labels:
            label_id = str(target_label["label_id"])
            progress = progress_by_label[label_id]
            progress["label"] = dict(target_label)
            if target_ready.get(label_id):
                state = self._save_target(
                    state,
                    label_id,
                    progress,
                    status="PRINT_COMPLETED",
                )
                continue
            progress_status = str(
                progress.get("status") or ""
            ).strip().upper()
            if progress_status == "PRINT_FAILURE_ACK_PENDING":
                return self._record_print_failure(
                    state,
                    label_id=label_id,
                    progress=progress,
                    scope=scope,
                    error=PHSPhysicalPrintError(
                        str(
                            progress.get("print_error_message")
                            or "Local physical printer failed."
                        )
                    ),
                )

            attempt_no = int(progress.get("print_attempt_no") or 0)
            attempt_id = str(
                progress.get("print_attempt_id") or ""
            ).strip()
            if progress_status == "PRINT_FAILED":
                attempt_id = ""
            if not attempt_id:
                if progress_status == "PRINT_REQUEST_PENDING":
                    attempt_no = _positive_integer(
                        progress.get("print_attempt_no"),
                        "print_attempt_no",
                    )
                    print_key = str(
                        progress.get("print_idempotency_key") or ""
                    ).strip()
                else:
                    attempt_no += 1
                    print_key = _stable_key(
                        "container-phs-reconciliation-print",
                        exchange_id,
                        label_id,
                        attempt_no,
                    )
                    state = self._save_target(
                        state,
                        label_id,
                        progress,
                        status="PRINT_REQUEST_PENDING",
                        print_attempt_no=attempt_no,
                        print_attempt_id="",
                        print_idempotency_key=print_key,
                    )
                    progress = dict(state["targets"][label_id])
                expected_print_key = _stable_key(
                    "container-phs-reconciliation-print",
                    exchange_id,
                    label_id,
                    attempt_no,
                )
                if print_key != expected_print_key:
                    raise PHSLabelWorkflowError(
                        "PHS_LABEL_JOURNAL_CORRUPT",
                        "target print idempotency identity가 변경됐습니다.",
                    )
                notify(
                    f"현품표 {target_ids.index(label_id) + 1}/"
                    f"{len(target_ids)} 중앙 print-attempt를 요청합니다."
                )
                requested = self.client.request_phs_label_print(
                    exchange_id,
                    authority_scope_id=scope,
                    label_id=label_id,
                    idempotency_key=print_key,
                )
                attempt = (
                    dict(requested.get("print_attempt"))
                    if isinstance(
                        requested.get("print_attempt"), Mapping
                    )
                    else {}
                )
                attempt_id = str(
                    attempt.get("print_attempt_id") or ""
                ).strip()
                requested_exchange = (
                    dict(requested.get("exchange"))
                    if isinstance(requested.get("exchange"), Mapping)
                    else {}
                )
                if (
                    not attempt_id
                    or str(attempt.get("label_id") or "").strip()
                    != label_id
                    or _positive_integer(
                        attempt.get("attempt_no"), "attempt.attempt_no"
                    )
                    != attempt_no
                    or str(attempt.get("state") or "").strip().upper()
                    != "REQUESTED"
                    or str(
                        requested_exchange.get("exchange_id") or ""
                    ).strip()
                    != exchange_id
                ):
                    raise PHSLabelWorkflowError(
                        "PHS_PRINT_REQUEST_ACK_INVALID",
                        "중앙 REQUESTED print-attempt 증거가 target과 다릅니다.",
                    )
                state = self._save_target(
                    state,
                    label_id,
                    progress,
                    status="PRINT_REQUESTED",
                    print_attempt_no=attempt_no,
                    print_attempt_id=attempt_id,
                    print_idempotency_key=print_key,
                    print_request_ack=dict(requested),
                )
                progress = dict(state["targets"][label_id])
                progress_status = "PRINT_REQUESTED"
            else:
                expected_print_key = _stable_key(
                    "container-phs-reconciliation-print",
                    exchange_id,
                    label_id,
                    _positive_integer(
                        progress.get("print_attempt_no"),
                        "print_attempt_no",
                    ),
                )
                if (
                    str(progress.get("print_idempotency_key") or "")
                    != expected_print_key
                ):
                    raise PHSLabelWorkflowError(
                        "PHS_LABEL_JOURNAL_CORRUPT",
                        "target print idempotency identity가 변경됐습니다.",
                    )

            if (
                progress_status == "LOCAL_PRINT_STARTING"
                and not confirm_ambiguous_reprint
            ):
                raise PHSLabelWorkflowError(
                    "PHS_PRINT_REPRINT_CONFIRMATION_REQUIRED",
                    "이전 실행이 실물 출력 제출 중 종료됐습니다. 출력물을 확인한 "
                    "뒤 재출력을 명시적으로 승인하세요.",
                    retryable=True,
                )
            if progress_status in {
                "LOCAL_PRINT_SUCCEEDED",
                "PRINT_COMPLETE_PENDING",
            }:
                self._validate_artifact(progress)
            else:
                render_context = SimpleNamespace(
                    item_code=str(target_label.get("item_id") or ""),
                    item_name="",
                    tray_size=_positive_integer(
                        target_label.get("member_count"),
                        "target.member_count",
                    ),
                )
                notify(
                    f"현품표 {target_ids.index(label_id) + 1}/"
                    f"{len(target_ids)}를 실물 출력합니다."
                )
                try:
                    rendered = self.renderer.render(
                        render_context, target_label
                    )
                    state = self._save_target(
                        state,
                        label_id,
                        progress,
                        status="LOCAL_PRINT_STARTING",
                        rendered_path=rendered.path,
                        rendered_artifact_hash=rendered.sha256,
                    )
                    progress = dict(state["targets"][label_id])
                    evidence = self.printer.print_png(
                        rendered.path,
                        document_name=(
                            "PHS "
                            + str(
                                target_label.get("worker_code") or ""
                            )
                        ),
                    )
                    proof = self._print_proof(evidence)
                except Exception as exc:
                    return self._record_print_failure(
                        state,
                        label_id=label_id,
                        progress=progress,
                        scope=scope,
                        error=exc,
                    )
                state = self._save_target(
                    state,
                    label_id,
                    progress,
                    status="LOCAL_PRINT_SUCCEEDED",
                    local_print_proof=proof,
                )
                progress = dict(state["targets"][label_id])

            state = self._save_target(
                state,
                label_id,
                progress,
                status="PRINT_COMPLETE_PENDING",
            )
            progress = dict(state["targets"][label_id])
            notify("실물 spool 증거를 중앙 target에 완료 기록합니다.")
            completed = self.client.complete_phs_label_print(
                str(progress.get("print_attempt_id") or ""),
                authority_scope_id=scope,
                succeeded=True,
                rendered_artifact_hash=str(
                    progress.get("rendered_artifact_hash") or ""
                ),
                proof=dict(progress.get("local_print_proof") or {}),
            )
            attempt = (
                dict(completed.get("print_attempt"))
                if isinstance(completed.get("print_attempt"), Mapping)
                else {}
            )
            completed_exchange = (
                dict(completed.get("exchange"))
                if isinstance(completed.get("exchange"), Mapping)
                else {}
            )
            if (
                str(attempt.get("print_attempt_id") or "").strip()
                != str(progress.get("print_attempt_id") or "").strip()
                or str(attempt.get("label_id") or "").strip() != label_id
                or str(attempt.get("state") or "").strip().upper()
                != "SUCCEEDED"
                or str(completed_exchange.get("exchange_id") or "").strip()
                != exchange_id
            ):
                raise PHSLabelWorkflowError(
                    "PHS_PRINT_COMPLETE_ACK_INVALID",
                    "중앙 SUCCEEDED print 증거가 target과 다릅니다.",
                )
            state = self._save_target(
                state,
                label_id,
                progress,
                status="PRINT_COMPLETED",
                print_complete_ack=dict(completed),
            )

        central = self.client.get_phs_label_exchange(
            exchange_id,
            authority_scope_id=scope,
        )
        exchange, _target_labels, target_ready = self._validate_exchange(
            central,
            context=context_value,
        )
        if (
            str(exchange.get("state") or "").strip().upper() != "READY"
            or not all(target_ready.values())
        ):
            raise PHSLabelWorkflowError(
                "PHS_LABEL_EXCHANGE_NOT_READY",
                "모든 target의 실물 출력 성공 전에는 활성화할 수 없습니다.",
            )
        expected_exchange_version = _positive_integer(
            exchange.get("entity_version"), "exchange.entity_version"
        )
        state = self._save(
            state,
            status="ACTIVATE_PENDING",
            exchange_entity_version=expected_exchange_version,
        )
        notify("모든 target 출력 성공 후 중앙 ACTIVE 전환을 1회 수행합니다.")
        try:
            activated = self.client.activate_phs_label_exchange(
                exchange_id,
                authority_scope_id=scope,
                expected_exchange_version=expected_exchange_version,
            )
        except Exception:
            activated = self.client.get_phs_label_exchange(
                exchange_id,
                authority_scope_id=scope,
            )
        activated_exchange, _targets, ready = self._validate_exchange(
            activated,
            context=context_value,
        )
        if (
            str(
                activated.get("status")
                or activated_exchange.get("state")
                or ""
            ).strip().upper()
            != "COMMITTED"
            or str(activated_exchange.get("exchange_id") or "").strip()
            != exchange_id
            or not all(ready.values())
        ):
            raise PHSLabelWorkflowError(
                "PHS_ACTIVATE_ACK_INVALID",
                "중앙 COMMITTED exchange 증거가 없습니다.",
                retryable=True,
            )
        committed = self._save(
            state,
            status="COMMITTED",
            committed_ack=dict(activated),
        )
        summaries = self.target_summaries(context_value)
        return self._result(
            committed,
            success=True,
            message=(
                f"현품표 교체 완료 · {len(summaries)}장 · "
                + " / ".join(summaries[:3])
            ),
        )

    def recover(
        self,
        *,
        confirm_ambiguous_reprint: bool = False,
        status_callback: Callable[[str], None] | None = None,
    ) -> PHSLabelExchangeResult | None:
        state = self.journal.load()
        if (
            not state
            or str(state.get("workflow_kind") or "")
            != "RECONCILIATION"
            or str(state.get("status") or "").strip().upper()
            in _TERMINAL_STATES
        ):
            return None
        return self.execute(
            None,
            confirm_ambiguous_reprint=confirm_ambiguous_reprint,
            status_callback=status_callback,
        )


__all__ = ["PHSReconciliationExchangeCoordinator"]

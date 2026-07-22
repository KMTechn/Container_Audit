"""Durable pre-seal product replacement for Container Audit.

The transfer bundle does not exist while an operator is scanning a tray.  At
that point the authoritative owner is still the completed PHS bundle, so one
or two damaged members can be exchanged atomically with good members from
other PHS bundles.  The server command moves the damaged members to process
damage hold and performs CAS on every affected bundle in one transaction.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import quote, urlencode

from transfer_seal import (
    CONTRACT_VERSION,
    LogisticsTransferClient,
    TransferSealError,
    membership_hash,
    normalize_barcode,
    source_identity_from_label,
    validate_compact_phs2_preflight,
)


EXCHANGE_SCHEMA_VERSION = "container-audit-member-exchange-v1"
EXCHANGE_COMMAND_TYPE = "REPLACE_BUNDLE_MEMBERS"
EXCHANGE_CAPABILITY_ID = "bundle_member_replacement_v1"
GOOD_SOURCE_CONTRACT_VERSION = "logistics-good-replacement-source-v1"
GOOD_SOURCE_RESOLVER_PATH = "/logistics/api/v1/replacements/good-source/resolve"
MAX_EXCHANGE_PAIRS = 2
PENDING_EXCHANGE_STATUSES = (
    "PREPARED",
    "COMMAND_READY",
    "RETRY_WAIT",
    "OPERATOR_REVIEW",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized or "\x00" in normalized:
        raise ValueError(f"{field} must be non-empty safe text")
    return normalized


def _positive_version(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TransferSealError("MEMBERSHIP_CONFLICT", f"{field} version is invalid")
    return value


def _member_pairs(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    rows: list[tuple[str, str]] = []
    for raw in value:
        if not isinstance(raw, Mapping):
            return ()
        unit_id = str(raw.get("unit_id") or "").strip()
        try:
            barcode = normalize_barcode(raw.get("normalized_barcode"))
        except ValueError:
            return ()
        if not unit_id:
            return ()
        rows.append((unit_id, barcode))
    result = tuple(sorted(rows))
    if (
        len({unit_id for unit_id, _barcode in result}) != len(result)
        or len({barcode for _unit_id, barcode in result}) != len(result)
    ):
        return ()
    return result


def _canonical_barcodes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    try:
        result = tuple(sorted(normalize_barcode(item) for item in value))
    except ValueError:
        return ()
    return result if len(set(result)) == len(result) else ()


def _empty_membership_hash() -> str:
    return _sha256([])


def _exact_projection(
    projection: Mapping[str, Any],
    *,
    expected_role: str = "",
) -> dict[str, Any]:
    bundle = dict(projection or {})
    bundle_id = _identifier(bundle.get("bundle_id"), "bundle_id")
    if bundle.get("bundle_type") != "PHS" or bundle.get("bundle_state") != "AVAILABLE":
        raise TransferSealError(
            "REPLACEMENT_SOURCE_NOT_ELIGIBLE",
            "교체 대상과 새 양품 소유 bundle은 AVAILABLE PHS여야 합니다.",
        )
    if expected_role and bundle.get("bundle_role") != expected_role:
        raise TransferSealError(
            "RESOLVER_CONTRACT_INVALID",
            "bundle resolver 역할이 교체 계약과 일치하지 않습니다.",
        )
    raw_member_ids = bundle.get("member_ids")
    raw_members = bundle.get("members")
    if not isinstance(raw_member_ids, list) or not isinstance(raw_members, list):
        raise TransferSealError("MEMBERSHIP_CONFLICT", "PHS exact membership이 없습니다.")
    member_ids = [str(value or "").strip() for value in raw_member_ids]
    if (
        not member_ids
        or any(not value for value in member_ids)
        or len(member_ids) != len(set(member_ids))
        or isinstance(bundle.get("member_count"), bool)
        or bundle.get("member_count") != len(member_ids)
        or membership_hash(member_ids) != str(bundle.get("membership_hash") or "").lower()
        or len(raw_members) != len(member_ids)
    ):
        raise TransferSealError("MEMBERSHIP_CONFLICT", "PHS membership 증거가 일치하지 않습니다.")
    by_barcode: dict[str, dict[str, Any]] = {}
    row_ids: list[str] = []
    for raw_row in raw_members:
        if not isinstance(raw_row, Mapping):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "PHS member row 형식이 잘못됐습니다.")
        row = dict(raw_row)
        unit_id = str(row.get("unit_id") or "").strip()
        barcode = normalize_barcode(row.get("normalized_barcode"))
        if not unit_id or barcode in by_barcode:
            raise TransferSealError("MEMBERSHIP_CONFLICT", "PHS barcode mapping이 중복됐습니다.")
        row_ids.append(unit_id)
        by_barcode[barcode] = row
    if set(row_ids) != set(member_ids) or len(row_ids) != len(set(row_ids)):
        raise TransferSealError("MEMBERSHIP_CONFLICT", "PHS unit mapping이 일부이거나 중복됐습니다.")
    barcode_hash = membership_hash(by_barcode)
    if (
        isinstance(bundle.get("barcode_member_count"), bool)
        or bundle.get("barcode_member_count") != len(by_barcode)
        or str(bundle.get("barcode_membership_hash") or "").lower() != barcode_hash
    ):
        raise TransferSealError("MEMBERSHIP_CONFLICT", "PHS barcode membership hash가 일치하지 않습니다.")
    return {
        "bundle": bundle,
        "bundle_id": bundle_id,
        "member_ids": tuple(sorted(member_ids)),
        "membership_hash": membership_hash(member_ids),
        "by_barcode": by_barcode,
        "entity_version": _positive_version(bundle.get("entity_version"), bundle_id),
        "authority_scope_id": _identifier(
            bundle.get("authority_scope_id"), "authority_scope_id"
        ),
        "authority_epoch": _positive_version(
            bundle.get("authority_epoch"), "authority_epoch"
        ),
        "ledger_plane": _identifier(bundle.get("ledger_plane"), "ledger_plane"),
        "plane_epoch": _positive_version(bundle.get("plane_epoch"), "plane_epoch"),
        "item_id": _identifier(bundle.get("item_id"), "item_id"),
        "inbound_iin": _identifier(
            bundle.get("source_iin") or bundle.get("inbound_iin"), "inbound_iin"
        ),
        "uom": _identifier(bundle.get("uom"), "uom"),
    }


@dataclass(frozen=True)
class MemberExchangeAttempt:
    intent_id: str
    status: str
    local_apply_status: str
    old_barcodes: tuple[str, ...] = ()
    new_barcodes: tuple[str, ...] = ()
    target_bundle_id: str = ""
    damage_bundle_id: str = ""
    receipt_id: str = ""
    idempotency_key: str = ""
    entity_versions: dict[str, int] = field(default_factory=dict)
    target_label_action: str = ""
    target_label_identity_remains_valid: bool = False
    target_label_membership_bound: bool = True
    retryable: bool = False
    error_code: str = ""
    error_message: str = ""


class TransferMemberExchangeStore:
    """SQLite outbox for a central member exchange and its local application."""

    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS transfer_member_exchange_intents (
                    intent_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN (
                        'PREPARED','COMMAND_READY','RETRY_WAIT','ACKED','OPERATOR_REVIEW'
                    )),
                    local_apply_status TEXT NOT NULL DEFAULT 'PENDING'
                        CHECK(local_apply_status IN ('PENDING','APPLIED','OPERATOR_REVIEW')),
                    master_label TEXT NOT NULL,
                    source_identity_json TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    old_barcodes_json TEXT NOT NULL,
                    new_barcodes_json TEXT NOT NULL,
                    pair_count INTEGER NOT NULL CHECK(pair_count BETWEEN 1 AND 2),
                    intent_hash TEXT NOT NULL UNIQUE,
                    command_id TEXT UNIQUE,
                    command_json TEXT,
                    command_hash TEXT,
                    receipt_json TEXT,
                    local_apply_receipt_json TEXT,
                    last_error_code TEXT,
                    last_error_message TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK((command_json IS NULL) = (command_id IS NULL)),
                    CHECK((command_json IS NULL) = (command_hash IS NULL))
                );
                CREATE INDEX IF NOT EXISTS ix_transfer_member_exchange_pending
                    ON transfer_member_exchange_intents(status,local_apply_status,created_at);
                CREATE TRIGGER IF NOT EXISTS trg_transfer_member_exchange_command_immutable
                BEFORE UPDATE OF command_id,command_json,command_hash
                ON transfer_member_exchange_intents
                WHEN OLD.command_json IS NOT NULL AND (
                    NEW.command_id <> OLD.command_id OR
                    NEW.command_json <> OLD.command_json OR
                    NEW.command_hash <> OLD.command_hash
                )
                BEGIN SELECT RAISE(ABORT, 'transfer member exchange command is immutable'); END;
                """
            )

    def prepare(
        self,
        *,
        master_label: str,
        source_identity: Mapping[str, Any],
        item_id: str,
        operator: str,
        old_barcodes: Iterable[str],
        new_barcodes: Iterable[str],
    ) -> sqlite3.Row:
        old_values = tuple(normalize_barcode(value) for value in old_barcodes)
        new_values = tuple(normalize_barcode(value) for value in new_barcodes)
        if (
            not 1 <= len(old_values) <= MAX_EXCHANGE_PAIRS
            or len(old_values) != len(new_values)
            or len(set(old_values)) != len(old_values)
            or len(set(new_values)) != len(new_values)
            or set(old_values) & set(new_values)
        ):
            raise ValueError("exchange requires one or two unique, disjoint barcode pairs")
        material = {
            "master_label": _identifier(master_label, "master_label"),
            "source_identity": {
                key: str(value or "").strip() for key, value in source_identity.items()
            },
            "item_id": _identifier(item_id, "item_id"),
            "old_barcodes": list(old_values),
            "new_barcodes": list(new_values),
        }
        digest = _sha256(material)
        intent_id = f"transfer-exchange-intent-{digest[:32]}"
        now = _utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT OR IGNORE INTO transfer_member_exchange_intents (
                       intent_id,schema_version,status,local_apply_status,master_label,
                       source_identity_json,item_id,operator,old_barcodes_json,
                       new_barcodes_json,pair_count,intent_hash,created_at,updated_at
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    intent_id,
                    EXCHANGE_SCHEMA_VERSION,
                    "PREPARED",
                    "PENDING",
                    material["master_label"],
                    _canonical_json(material["source_identity"]),
                    material["item_id"],
                    str(operator or "").strip(),
                    _canonical_json(material["old_barcodes"]),
                    _canonical_json(material["new_barcodes"]),
                    len(old_values),
                    digest,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM transfer_member_exchange_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def load(self, intent_id: str) -> sqlite3.Row:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM transfer_member_exchange_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
        if row is None:
            raise KeyError(intent_id)
        return row

    def bind_command(self, intent_id: str, command: Mapping[str, Any]) -> sqlite3.Row:
        command_id = _identifier(command.get("idempotency_key"), "idempotency_key")
        command_json = _canonical_json(dict(command))
        command_hash = hashlib.sha256(command_json.encode("utf-8")).hexdigest()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM transfer_member_exchange_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            if row is None:
                raise KeyError(intent_id)
            if row["command_json"] is not None:
                if (
                    row["command_id"] != command_id
                    or row["command_json"] != command_json
                    or row["command_hash"] != command_hash
                ):
                    raise ValueError("durable exchange command differs from retry payload")
            else:
                conn.execute(
                    """UPDATE transfer_member_exchange_intents
                          SET status='COMMAND_READY',command_id=?,command_json=?,command_hash=?,
                              last_error_code=NULL,last_error_message=NULL,updated_at=?
                        WHERE intent_id=? AND command_json IS NULL""",
                    (command_id, command_json, command_hash, _utc_now(), intent_id),
                )
            row = conn.execute(
                "SELECT * FROM transfer_member_exchange_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def record_error(self, intent_id: str, error: TransferSealError) -> sqlite3.Row:
        operator_review_codes = {
            "CAPABILITY_UNAVAILABLE",
            "AUTHORITY_PROFILE_MISMATCH",
            "AMBIGUOUS_BUNDLE",
            "AMBIGUOUS_GOOD_SOURCE",
            "GOOD_SOURCE_NOT_FOUND",
            "MEMBERSHIP_CONFLICT",
            "REPLACEMENT_SOURCE_NOT_ELIGIBLE",
            "REPLACEMENT_SOURCE_NOT_SINGLETON",
            "SOURCE_IDENTITY_MISMATCH",
            "BARCODE_NOT_IN_SOURCE_BUNDLE",
            "BARCODE_MAPPING_AMBIGUOUS",
            "STALE_VERSION",
            "RECEIPT_MEMBERSHIP_MISMATCH",
            "RESOLVER_CONTRACT_INVALID",
            "POST_SEAL_REPLACEMENT_UNSUPPORTED",
            "PHS2_CANONICAL_EVIDENCE_REQUIRED",
            "PHS2_COMPACT_FORMAT_REQUIRED",
            "PHS2_CENTRAL_SOURCE_REQUIRED",
            "PHS2_IDENTITY_INVALID",
            "PHS2_HASH_PREFIX_INVALID",
            "PHS2_SOURCE_AMBIGUOUS",
            "PHS2_REGISTRY_EVIDENCE_REQUIRED",
            "PHS2_REGISTRY_IDENTITY_MISMATCH",
            "PHS2_REGISTRY_HASH_INVALID",
            "PHS2_SOURCE_IDENTITY_MISMATCH",
            "PHS2_MEMBERSHIP_INVALID",
            "PHS2_MIXED_MEMBERSHIP",
            "PHS2_MEMBER_NOT_AVAILABLE",
        }
        terminal_http = error.status_code in {400, 403, 409, 412, 422}
        status = (
            "OPERATOR_REVIEW"
            if error.code.upper() in operator_review_codes or terminal_http
            else "RETRY_WAIT"
        )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE transfer_member_exchange_intents
                      SET status=?,last_error_code=?,last_error_message=?,
                          attempt_count=attempt_count+1,updated_at=?
                    WHERE intent_id=?""",
                (status, error.code, str(error), _utc_now(), intent_id),
            )
            row = conn.execute(
                "SELECT * FROM transfer_member_exchange_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def record_receipt(self, intent_id: str, receipt: Mapping[str, Any]) -> sqlite3.Row:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE transfer_member_exchange_intents
                      SET status='ACKED',receipt_json=?,last_error_code=NULL,
                          last_error_message=NULL,attempt_count=attempt_count+1,updated_at=?
                    WHERE intent_id=?""",
                (_canonical_json(dict(receipt)), _utc_now(), intent_id),
            )
            row = conn.execute(
                "SELECT * FROM transfer_member_exchange_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def mark_local_applied(
        self, intent_id: str, evidence: Mapping[str, Any]
    ) -> sqlite3.Row:
        encoded = _canonical_json(dict(evidence or {}))
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM transfer_member_exchange_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            if row is None:
                raise KeyError(intent_id)
            if row["status"] != "ACKED":
                raise ValueError("central exchange must be ACKED before local application")
            if row["local_apply_status"] == "APPLIED":
                if row["local_apply_receipt_json"] != encoded:
                    raise ValueError("local exchange application evidence is immutable")
            else:
                conn.execute(
                    """UPDATE transfer_member_exchange_intents
                          SET local_apply_status='APPLIED',local_apply_receipt_json=?,updated_at=?
                        WHERE intent_id=? AND status='ACKED' AND local_apply_status='PENDING'""",
                    (encoded, _utc_now(), intent_id),
                )
            row = conn.execute(
                "SELECT * FROM transfer_member_exchange_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def mark_local_review(self, intent_id: str, reason: str) -> sqlite3.Row:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE transfer_member_exchange_intents
                      SET local_apply_status='OPERATOR_REVIEW',last_error_code='LOCAL_APPLY_CONFLICT',
                          last_error_message=?,updated_at=?
                    WHERE intent_id=? AND status='ACKED' AND local_apply_status='PENDING'""",
                (str(reason or "local tray changed"), _utc_now(), intent_id),
            )
            row = conn.execute(
                "SELECT * FROM transfer_member_exchange_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def pending_ids(self) -> list[str]:
        placeholders = ",".join("?" for _ in PENDING_EXCHANGE_STATUSES)
        with self._connect() as conn:
            rows = conn.execute(
                f"""SELECT intent_id FROM transfer_member_exchange_intents
                      WHERE status IN ({placeholders}) ORDER BY created_at""",
                PENDING_EXCHANGE_STATUSES,
            ).fetchall()
        return [str(row["intent_id"]) for row in rows]

    def pending_local_rows(self, *, master_label: str = "") -> list[sqlite3.Row]:
        query = (
            "SELECT * FROM transfer_member_exchange_intents "
            "WHERE status='ACKED' AND local_apply_status='PENDING'"
        )
        params: tuple[Any, ...] = ()
        if master_label:
            query += " AND master_label=?"
            params = (str(master_label),)
        query += " ORDER BY created_at"
        with self._connect() as conn:
            return list(conn.execute(query, params).fetchall())

    def blocking_rows(self, *, master_label: str = "") -> list[sqlite3.Row]:
        query = (
            "SELECT * FROM transfer_member_exchange_intents WHERE "
            "(status IN ('PREPARED','COMMAND_READY','RETRY_WAIT','OPERATOR_REVIEW') OR "
            " (status='ACKED' AND local_apply_status!='APPLIED'))"
        )
        params: tuple[Any, ...] = ()
        if master_label:
            query += " AND master_label=?"
            params = (str(master_label),)
        query += " ORDER BY created_at"
        with self._connect() as conn:
            return list(conn.execute(query, params).fetchall())


class TransferMemberExchangeCoordinator:
    def __init__(
        self,
        store: TransferMemberExchangeStore,
        client: LogisticsTransferClient | None,
    ) -> None:
        self.store = store
        self.client = client

    def prepare(
        self,
        *,
        master_label: str,
        master_label_fields: Mapping[str, Any],
        item_id: str,
        operator: str,
        old_barcodes: Iterable[str],
        new_barcodes: Iterable[str],
    ) -> MemberExchangeAttempt:
        row = self.store.prepare(
            master_label=master_label,
            source_identity=source_identity_from_label(master_label_fields),
            item_id=item_id,
            operator=operator,
            old_barcodes=old_barcodes,
            new_barcodes=new_barcodes,
        )
        return self._attempt(row)

    def _require_capability(self) -> None:
        if self.client is None:
            raise TransferSealError(
                "LOGISTICS_CLIENT_NOT_CONFIGURED",
                "물류 서버 설정이 없어 중앙 제품 교체를 진행할 수 없습니다.",
                retryable=True,
            )
        raw = self.client.get_capabilities()
        ids = raw.get("capability_ids")
        capabilities = raw.get("capabilities")
        capability = (
            capabilities.get(EXCHANGE_CAPABILITY_ID)
            if isinstance(capabilities, Mapping)
            else None
        )
        if (
            not isinstance(ids, list)
            or EXCHANGE_CAPABILITY_ID not in ids
            or not isinstance(capability, Mapping)
            or capability.get("enabled") is not True
            or capability.get("command_type") != EXCHANGE_COMMAND_TYPE
            or capability.get("resolver_contract_version")
            != GOOD_SOURCE_CONTRACT_VERSION
            or capability.get("max_pairs") != MAX_EXCHANGE_PAIRS
            or capability.get("atomic") is not True
            or capability.get("two_bundle_cas") is not True
            or capability.get("sealed_transfer_package") is not False
            or str(capability.get("resolver_path") or "") != GOOD_SOURCE_RESOLVER_PATH
            or capability.get("replacement_source_bundle_cardinality")
            != "EXACTLY_ONE_ACTIVE_MEMBER"
            or capability.get("multi_member_source_policy")
            != "REJECT_STALE_PHYSICAL_LABEL"
            or capability.get("multi_member_source_error_code")
            != "REPLACEMENT_SOURCE_NOT_SINGLETON"
            or capability.get("target_label_action") != "RETAIN_IDENTITY_LABEL"
            or capability.get("target_label_identity_remains_valid") is not True
            or capability.get("target_label_membership_bound") is not False
        ):
            raise TransferSealError(
                "CAPABILITY_UNAVAILABLE",
                "서버가 exact 중앙 제품 교체 계약을 광고하지 않습니다.",
            )

    @staticmethod
    def _target_projection(resolved: Mapping[str, Any]) -> dict[str, Any]:
        if resolved.get("candidate_count") != 1 or not isinstance(resolved.get("bundle"), Mapping):
            raise TransferSealError(
                "AMBIGUOUS_BUNDLE", "교체 대상 PHS를 정확히 하나로 확정하지 못했습니다."
            )
        target = _exact_projection(
            resolved["bundle"], expected_role="TRANSFER_SOURCE"
        )
        bundle = target["bundle"]
        if str(bundle.get("current_location") or "") != "PHS_GOOD" or any(
            str(row.get("location_code") or "") != "PHS_GOOD"
            or str(row.get("unit_state") or "") != "CONSUMED"
            for row in bundle.get("members") or []
            if isinstance(row, Mapping)
        ):
            raise TransferSealError(
                "REPLACEMENT_SOURCE_NOT_ELIGIBLE",
                "교체 대상 PHS가 검사완료 양품 위치에 있지 않습니다.",
            )
        return target

    @staticmethod
    def _good_projection(
        resolved: Mapping[str, Any], requested_barcode: str
    ) -> dict[str, Any]:
        if (
            resolved.get("contract_version") != GOOD_SOURCE_CONTRACT_VERSION
            or resolved.get("candidate_count") != 1
            or not isinstance(resolved.get("unit"), Mapping)
            or not isinstance(resolved.get("source_bundle"), Mapping)
        ):
            raise TransferSealError(
                "RESOLVER_CONTRACT_INVALID",
                "새 양품 resolver 응답이 exact source 계약과 일치하지 않습니다.",
            )
        source_bundle = dict(resolved["source_bundle"])
        source_members = source_bundle.get("members")
        source_members = source_members if isinstance(source_members, list) else []
        source_barcodes = [
            normalize_barcode(row.get("normalized_barcode"))
            for row in source_members
            if isinstance(row, Mapping)
        ]
        source_bundle.update(
            {
                "authority_scope_id": resolved.get("authority_scope_id"),
                "authority_epoch": resolved.get("authority_epoch"),
                "ledger_plane": resolved.get("ledger_plane"),
                "plane_epoch": resolved.get("plane_epoch"),
                "source_iin": resolved.get("inbound_iin"),
                "barcode_member_count": len(source_barcodes),
                "barcode_membership_hash": (
                    membership_hash(source_barcodes) if source_barcodes else ""
                ),
            }
        )
        source = _exact_projection(source_bundle)
        unit = dict(resolved["unit"])
        replacement_evidence = resolved.get("replacement_evidence")
        if not isinstance(replacement_evidence, Mapping):
            raise TransferSealError(
                "RESOLVER_CONTRACT_INVALID", "새 양품 replacement evidence가 없습니다."
            )
        barcode = normalize_barcode(requested_barcode)
        unit_id = str(unit.get("unit_id") or "").strip()
        projected = source["by_barcode"].get(barcode)
        if (
            len(source["member_ids"]) != 1
            or len(source["by_barcode"]) != 1
            or tuple(source["member_ids"]) != (unit_id,)
        ):
            raise TransferSealError(
                "REPLACEMENT_SOURCE_NOT_SINGLETON",
                "새 양품은 활성 제품이 정확히 1개인 단품 PHS에서만 가져올 수 있습니다.",
            )
        if (
            normalize_barcode(unit.get("normalized_barcode")) != barcode
            or not unit_id
            or not isinstance(projected, Mapping)
            or str(projected.get("unit_id") or "") != unit_id
            or str(resolved.get("source_bundle_id") or "") != source["bundle_id"]
            or resolved.get("source_bundle_entity_version")
            != source["entity_version"]
            or str(resolved.get("unit_id") or unit_id) != unit_id
            or normalize_barcode(resolved.get("normalized_barcode") or barcode) != barcode
            or str(replacement_evidence.get("new_unit_id") or "") != unit_id
            or str(replacement_evidence.get("new_source_bundle_id") or "")
            != source["bundle_id"]
            or replacement_evidence.get("expected_source_bundle_version")
            != source["entity_version"]
            or sorted(
                str(value) for value in replacement_evidence.get("source_member_ids") or []
            )
            != list(source["member_ids"])
            or str(replacement_evidence.get("source_membership_hash") or "").lower()
            != source["membership_hash"]
            or str(replacement_evidence.get("inbound_iin") or "")
            != source["inbound_iin"]
            or str(replacement_evidence.get("item_id") or "") != source["item_id"]
            or str(replacement_evidence.get("uom") or "") != source["uom"]
        ):
            raise TransferSealError(
                "MEMBERSHIP_CONFLICT", "새 양품 unit과 소유 PHS membership이 일치하지 않습니다."
            )
        location = str(unit.get("current_location") or "")
        state = str(unit.get("state") or "")
        if (location, state) not in {
            ("PHS_GOOD", "CONSUMED"),
            ("REWORK_GOOD_READY", "AVAILABLE"),
        }:
            raise TransferSealError(
                "REPLACEMENT_SOURCE_NOT_ELIGIBLE", "새 양품이 교체 가능한 양품 위치에 없습니다."
            )
        source["selected_unit_id"] = unit_id
        source["selected_barcode"] = barcode
        return source

    def _build_command(self, row: sqlite3.Row) -> dict[str, Any]:
        self._require_capability()
        assert self.client is not None
        identity = json.loads(row["source_identity_json"])
        resolved_target = self.client.resolve_source(
            {
                "bundle_id": identity.get("source_bundle_id"),
                "input_tag_id": identity.get("input_tag_id"),
                "input_tag_label_id": identity.get("input_tag_label_id"),
                "input_tag_hash_prefix": identity.get("input_tag_hash_prefix"),
                "external_label": identity.get("external_label"),
                "authority_scope_id": identity.get("authority_scope_id"),
                "item_id": identity.get("item_id") or row["item_id"],
            }
        )
        if str(identity.get("input_tag_hash_prefix") or "").strip():
            validate_compact_phs2_preflight(
                {
                    "PHS": "2",
                    "SRC": identity.get("source_kind"),
                    "ITG": identity.get("input_tag_id"),
                    "CLC": identity.get("item_id") or row["item_id"],
                    "LBL": identity.get("input_tag_label_id"),
                    "HSH": identity.get("input_tag_hash_prefix"),
                },
                resolved_target,
            )
        target = self._target_projection(resolved_target)
        if target["item_id"] != str(row["item_id"]):
            raise TransferSealError(
                "SOURCE_IDENTITY_MISMATCH", "교체 대상 PHS 품목이 현재 이적 품목과 다릅니다."
            )
        old_barcodes = tuple(json.loads(row["old_barcodes_json"]))
        new_barcodes = tuple(json.loads(row["new_barcodes_json"]))
        old_units: list[str] = []
        for barcode in old_barcodes:
            target_row = target["by_barcode"].get(normalize_barcode(barcode))
            if not isinstance(target_row, Mapping):
                raise TransferSealError(
                    "BARCODE_NOT_IN_SOURCE_BUNDLE", "교체 대상 제품이 현재 PHS에 없습니다."
                )
            old_units.append(_identifier(target_row.get("unit_id"), "old_unit_id"))
        good_sources: list[dict[str, Any]] = []
        for barcode in new_barcodes:
            resolved = self.client.resolve_good_source(
                authority_scope_id=target["authority_scope_id"], barcode=barcode
            )
            source = self._good_projection(resolved, barcode)
            if (
                source["authority_scope_id"] != target["authority_scope_id"]
                or source["authority_epoch"] != target["authority_epoch"]
                or source["ledger_plane"] != target["ledger_plane"]
                or source["plane_epoch"] != target["plane_epoch"]
                or source["item_id"] != target["item_id"]
                or source["inbound_iin"] != target["inbound_iin"]
                or source["uom"] != target["uom"]
                or source["bundle_id"] == target["bundle_id"]
            ):
                raise TransferSealError(
                    "REPLACEMENT_SOURCE_NOT_ELIGIBLE",
                    "새 양품은 대상과 같은 입고 lot·품목·원장 plane의 별도 PHS여야 합니다.",
                )
            good_sources.append(source)
        new_units = [source["selected_unit_id"] for source in good_sources]
        if len(set(old_units)) != len(old_units) or len(set(new_units)) != len(new_units):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "교체 unit mapping이 중복됐습니다.")
        expected_versions = {f"bundle:{target['bundle_id']}": target["entity_version"]}
        source_evidence: dict[str, Any] = {}
        for source in good_sources:
            key = f"bundle:{source['bundle_id']}"
            existing = expected_versions.get(key)
            if existing is not None and existing != source["entity_version"]:
                raise TransferSealError("STALE_VERSION", "같은 양품 PHS version 증거가 충돌합니다.")
            expected_versions[key] = source["entity_version"]
            source_evidence[source["bundle_id"]] = {
                "member_ids": list(source["member_ids"]),
                "membership_hash": source["membership_hash"],
                "members": [
                    {
                        "unit_id": unit_id,
                        "normalized_barcode": barcode,
                    }
                    for unit_id, barcode in _member_pairs(
                        list(source["by_barcode"].values())
                    )
                ],
                "member_count": len(source["member_ids"]),
                "normalized_barcodes": sorted(source["by_barcode"]),
                "barcode_membership_hash": membership_hash(source["by_barcode"]),
                "entity_version": source["entity_version"],
            }
        pairs = [
            {
                "old_unit_id": old_unit,
                "new_unit_id": source["selected_unit_id"],
                "new_source_bundle_id": source["bundle_id"],
            }
            for old_unit, source in zip(old_units, good_sources, strict=True)
        ]
        damage_bundle_id = (
            "PROCESS-DAMAGE-"
            + _sha256(
                {
                    "target_bundle_id": target["bundle_id"],
                    "old_unit_ids": sorted(old_units),
                    "intent_hash": row["intent_hash"],
                }
            )[:24].upper()
        )
        return {
            "contract_version": CONTRACT_VERSION,
            "command_type": EXCHANGE_COMMAND_TYPE,
            "authority_scope_id": target["authority_scope_id"],
            "authority_epoch": target["authority_epoch"],
            "ledger_plane": target["ledger_plane"],
            "plane_epoch": target["plane_epoch"],
            "idempotency_key": f"container-member-exchange:{row['intent_hash']}",
            "expected_versions": expected_versions,
            "payload": {
                "target_bundle_id": target["bundle_id"],
                "damage_bundle_id": damage_bundle_id,
                "damage_external_label": damage_bundle_id,
                "pairs": pairs,
            },
            "client_exact_evidence": {
                "target": {
                    "member_ids": list(target["member_ids"]),
                    "membership_hash": target["membership_hash"],
                    "members": [
                        {
                            "unit_id": unit_id,
                            "normalized_barcode": barcode,
                        }
                        for unit_id, barcode in _member_pairs(
                            list(target["by_barcode"].values())
                        )
                    ],
                    "member_count": len(target["member_ids"]),
                    "normalized_barcodes": sorted(target["by_barcode"]),
                    "barcode_membership_hash": membership_hash(target["by_barcode"]),
                    "entity_version": target["entity_version"],
                },
                "sources": source_evidence,
                "old_barcodes": list(old_barcodes),
                "new_barcodes": list(new_barcodes),
            },
            "reason": "container_audit_preseal_process_damage_exchange",
            "evidence_refs": [row["intent_id"], row["intent_hash"]],
        }

    @staticmethod
    def _validate_receipt(
        command: Mapping[str, Any], receipt: Mapping[str, Any]
    ) -> None:
        data_value = receipt.get("data")
        data = dict(data_value) if isinstance(data_value, Mapping) else dict(receipt)
        payload = command["payload"]
        evidence = command["client_exact_evidence"]
        pairs = list(payload["pairs"])
        old_ids = {pair["old_unit_id"] for pair in pairs}
        new_ids = {pair["new_unit_id"] for pair in pairs}
        target_before = set(evidence["target"]["member_ids"])
        expected_members = sorted((target_before - old_ids) | new_ids)
        target_pairs = _member_pairs(evidence["target"].get("members"))
        target_map = dict(target_pairs)
        expected_damage_pairs = tuple(
            sorted((unit_id, target_map[unit_id]) for unit_id in old_ids)
        )
        expected_target_map = {
            unit_id: barcode
            for unit_id, barcode in target_pairs
            if unit_id not in old_ids
        }
        expected_sources = evidence.get("sources")
        expected_sources = (
            dict(expected_sources) if isinstance(expected_sources, Mapping) else {}
        )
        for pair in pairs:
            source = expected_sources.get(pair["new_source_bundle_id"])
            if not isinstance(source, Mapping):
                raise TransferSealError(
                    "RECEIPT_MEMBERSHIP_MISMATCH",
                    "서버 교체 command의 source evidence가 불완전합니다.",
                )
            source_map = dict(_member_pairs(source.get("members")))
            if pair["new_unit_id"] not in source_map:
                raise TransferSealError(
                    "RECEIPT_MEMBERSHIP_MISMATCH",
                    "서버 교체 command의 unit/barcode source mapping이 불완전합니다.",
                )
            expected_target_map[pair["new_unit_id"]] = source_map[pair["new_unit_id"]]
        expected_target_pairs = tuple(sorted(expected_target_map.items()))
        expected_barcodes = sorted(expected_target_map.values())
        actual_pairs = data.get("pairs")
        normalized_actual_pairs = (
            sorted(
                (
                    str(pair.get("old_unit_id") or ""),
                    str(pair.get("new_unit_id") or ""),
                    str(pair.get("new_source_bundle_id") or ""),
                )
                for pair in actual_pairs
                if isinstance(pair, Mapping)
            )
            if isinstance(actual_pairs, list)
            else []
        )
        expected_pairs = sorted(
            (
                pair["old_unit_id"],
                pair["new_unit_id"],
                pair["new_source_bundle_id"],
            )
            for pair in pairs
        )
        versions = receipt.get("entity_versions")
        if not isinstance(versions, Mapping):
            versions = data.get("entity_versions")
        versions = dict(versions) if isinstance(versions, Mapping) else {}
        expected_versions = {
            key: int(version) + 1 for key, version in command["expected_versions"].items()
        }
        expected_versions[f"bundle:{payload['damage_bundle_id']}"] = 1
        raw_sources = data.get("sources")
        actual_sources = {
            str(source.get("source_bundle_id") or ""): source
            for source in (raw_sources if isinstance(raw_sources, list) else [])
            if isinstance(source, Mapping)
        }
        sources_valid = len(actual_sources) == len(expected_sources)
        if sources_valid:
            for source_id, source in expected_sources.items():
                actual = actual_sources.get(source_id)
                source_pairs = _member_pairs(source.get("members"))
                selected = sorted(
                    pair["new_unit_id"]
                    for pair in pairs
                    if pair["new_source_bundle_id"] == source_id
                )
                selected_pairs = tuple(
                    pair for pair in source_pairs if pair[0] in set(selected)
                )
                if not isinstance(actual, Mapping) or (
                    actual.get("source_version_before") != source.get("entity_version")
                    or actual.get("source_version_after")
                    != int(source.get("entity_version") or 0) + 1
                    or sorted(str(value) for value in actual.get("source_member_ids_before") or [])
                    != sorted(str(value) for value in source.get("member_ids") or [])
                    or _member_pairs(actual.get("source_members_before")) != source_pairs
                    or actual.get("source_member_count_before") != 1
                    or str(actual.get("source_membership_hash_before") or "").lower()
                    != str(source.get("membership_hash") or "").lower()
                    or _canonical_barcodes(
                        actual.get("source_normalized_barcodes_before")
                    )
                    != _canonical_barcodes(source.get("normalized_barcodes"))
                    or str(
                        actual.get("source_barcode_membership_hash_before") or ""
                    ).lower()
                    != str(source.get("barcode_membership_hash") or "").lower()
                    or sorted(str(value) for value in actual.get("selected_member_ids") or [])
                    != selected
                    or _member_pairs(actual.get("selected_members")) != selected_pairs
                    or list(actual.get("remainder_member_ids") or []) != []
                    or _member_pairs(actual.get("remainder_members")) != ()
                    or actual.get("remainder_member_count") != 0
                    or str(actual.get("remainder_membership_hash") or "").lower()
                    != _empty_membership_hash()
                    or list(actual.get("remainder_normalized_barcodes") or []) != []
                    or str(
                        actual.get("remainder_barcode_membership_hash") or ""
                    ).lower()
                    != _empty_membership_hash()
                    or actual.get("source_bundle_state_after") != "CONSUMED"
                ):
                    sources_valid = False
                    break
        movement_ids = data.get("movement_ids")
        if (
            not str(receipt.get("receipt_id") or "").strip()
            or receipt.get("contract_version") != CONTRACT_VERSION
            or receipt.get("command_type") != EXCHANGE_COMMAND_TYPE
            or str(receipt.get("status") or "").upper() != "COMMITTED"
            or receipt.get("authority_scope_id") != command["authority_scope_id"]
            or receipt.get("authority_epoch") != command["authority_epoch"]
            or str(receipt.get("resolved_ledger_plane") or "").upper()
            != str(command["ledger_plane"]).upper()
            or receipt.get("resolved_plane_epoch") != command["plane_epoch"]
            or data.get("idempotency_key") != command["idempotency_key"]
            or not str(receipt.get("committed_at") or "").strip()
            or not isinstance(receipt.get("event_ids"), (list, tuple))
            or not receipt.get("event_ids")
            or not isinstance(receipt.get("outbox_ids"), (list, tuple))
            or not receipt.get("outbox_ids")
            or data.get("target_bundle_id") != payload["target_bundle_id"]
            or data.get("target_bundle_type") != "PHS"
            or data.get("target_location") != "PHS_GOOD"
            or data.get("damage_bundle_id") != payload["damage_bundle_id"]
            or sorted(str(value) for value in data.get("damage_member_ids") or [])
            != sorted(old_ids)
            or _member_pairs(data.get("damage_members")) != expected_damage_pairs
            or str(data.get("damage_membership_hash") or "").lower()
            != membership_hash(old_ids)
            or data.get("damage_location") != "PROCESS_DAMAGE_HOLD"
            or not isinstance(movement_ids, (list, tuple))
            or not movement_ids
            or len({str(value).strip() for value in movement_ids}) != len(movement_ids)
            or any(not str(value).strip() for value in movement_ids)
            or data.get("atomic") is not True
            or data.get("requires_reseal") is not False
            or data.get("target_label_action") != "RETAIN_IDENTITY_LABEL"
            or data.get("target_label_identity_remains_valid") is not True
            or data.get("target_label_membership_bound") is not False
            or data.get("replacement_source_bundle_cardinality")
            != "EXACTLY_ONE_ACTIVE_MEMBER"
            or data.get("multi_member_source_policy")
            != "REJECT_STALE_PHYSICAL_LABEL"
            or data.get("pair_count") != len(pairs)
            or normalized_actual_pairs != expected_pairs
            or not sources_valid
            or sorted(str(value) for value in data.get("member_ids") or [])
            != expected_members
            or _member_pairs(data.get("members")) != expected_target_pairs
            or data.get("member_count") != len(expected_members)
            or str(data.get("membership_hash") or "").lower()
            != membership_hash(expected_members)
            or _canonical_barcodes(data.get("normalized_barcodes"))
            != tuple(expected_barcodes)
            or str(data.get("barcode_membership_hash") or "").lower()
            != membership_hash(expected_barcodes)
            or any(versions.get(key) != value for key, value in expected_versions.items())
        ):
            raise TransferSealError(
                "RECEIPT_MEMBERSHIP_MISMATCH",
                "서버 교체 receipt가 요청한 exact membership/CAS 결과와 일치하지 않습니다.",
            )

    def attempt(self, intent_id: str) -> MemberExchangeAttempt:
        row = self.store.load(intent_id)
        if row["status"] == "ACKED":
            return self._attempt(row)
        command_was_durable = row["command_json"] is not None
        operator_review = row["status"] == "OPERATOR_REVIEW"
        if operator_review and not command_was_durable:
            return self._attempt(row)
        try:
            if row["command_json"] is None:
                row = self.store.bind_command(intent_id, self._build_command(row))
            command = json.loads(row["command_json"])
            if self.client is None:
                raise TransferSealError(
                    "LOGISTICS_CLIENT_NOT_CONFIGURED",
                    "물류 서버 설정이 없어 중앙 제품 교체를 진행할 수 없습니다.",
                    retryable=True,
                )
            if command_was_durable:
                receipt_lookup = getattr(self.client, "get_receipt", None)
                if callable(receipt_lookup):
                    try:
                        receipt = receipt_lookup(
                            str(command["authority_scope_id"]),
                            str(command["idempotency_key"]),
                        )
                    except Exception:
                        if operator_review:
                            return self._attempt(row)
                        raise
                    if receipt is not None:
                        if operator_review:
                            try:
                                self._validate_receipt(command, receipt)
                                row = self.store.record_receipt(intent_id, receipt)
                            except Exception:
                                return self._attempt(row)
                        else:
                            self._validate_receipt(command, receipt)
                            row = self.store.record_receipt(intent_id, receipt)
                        return self._attempt(row)
                if operator_review:
                    # A review row may already have changed the authoritative
                    # bundles. It is receipt-only from this point and must not
                    # issue the immutable POST again.
                    return self._attempt(row)
            receipt = self.client.replace_bundle_members(command)
            self._validate_receipt(command, receipt)
            row = self.store.record_receipt(intent_id, receipt)
        except TransferSealError as exc:
            row = self.store.record_error(intent_id, exc)
        except Exception as exc:
            row = self.store.record_error(
                intent_id,
                TransferSealError(
                    "LOCAL_MEMBER_EXCHANGE_ERROR",
                    f"중앙 제품 교체 처리 중 로컬 오류가 발생했습니다: {exc.__class__.__name__}",
                    retryable=True,
                    committed=None,
                ),
            )
        return self._attempt(row)

    def drain_pending(self) -> list[MemberExchangeAttempt]:
        return [self.attempt(intent_id) for intent_id in self.store.pending_ids()]

    def pending_local_attempts(self, *, master_label: str = "") -> list[MemberExchangeAttempt]:
        return [
            self._attempt(row)
            for row in self.store.pending_local_rows(master_label=master_label)
        ]

    @staticmethod
    def _attempt(row: sqlite3.Row) -> MemberExchangeAttempt:
        command = json.loads(row["command_json"]) if row["command_json"] else {}
        payload = command.get("payload") if isinstance(command.get("payload"), Mapping) else {}
        receipt = json.loads(row["receipt_json"]) if row["receipt_json"] else {}
        receipt_data = (
            receipt.get("data")
            if isinstance(receipt, Mapping) and isinstance(receipt.get("data"), Mapping)
            else receipt
        )
        versions = receipt.get("entity_versions") if isinstance(receipt, Mapping) else {}
        return MemberExchangeAttempt(
            intent_id=str(row["intent_id"]),
            status=str(row["status"]),
            local_apply_status=str(row["local_apply_status"]),
            old_barcodes=tuple(json.loads(row["old_barcodes_json"])),
            new_barcodes=tuple(json.loads(row["new_barcodes_json"])),
            target_bundle_id=str(payload.get("target_bundle_id") or ""),
            damage_bundle_id=str(payload.get("damage_bundle_id") or ""),
            receipt_id=str(receipt.get("receipt_id") or ""),
            idempotency_key=str(row["command_id"] or ""),
            entity_versions={
                str(key): int(value)
                for key, value in (versions.items() if isinstance(versions, Mapping) else ())
                if isinstance(value, int) and not isinstance(value, bool)
            },
            target_label_action=str(receipt_data.get("target_label_action") or ""),
            target_label_identity_remains_valid=(
                receipt_data.get("target_label_identity_remains_valid") is True
            ),
            target_label_membership_bound=(
                receipt_data.get("target_label_membership_bound") is not False
            ),
            retryable=row["status"] == "RETRY_WAIT",
            error_code=str(row["last_error_code"] or ""),
            error_message=str(row["last_error_message"] or ""),
        )

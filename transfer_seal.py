"""Durable exact-membership transfer sealing for Container Audit."""

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
from urllib.parse import quote, unquote, urlencode, urlsplit

from logistics_runtime_profile import (
    LogisticsRuntimeConfigurationError,
    load_logistics_runtime_profile,
    logistics_runtime_required,
)


SCHEMA_VERSION = "container-audit-transfer-seal-v1"
CONTRACT_VERSION = "logistics-v1"
COMMAND_TYPE = "SEAL_TRANSFER_BUNDLE"
PENDING_STATUSES = ("PREPARED", "COMMAND_READY", "RETRY_WAIT")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _normalize_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized or "\x00" in normalized:
        raise ValueError(f"{field} must be non-empty safe text")
    return normalized


def normalize_barcode(value: Any) -> str:
    return _normalize_identifier(value, "barcode").upper()


def membership_hash(member_ids: Iterable[str]) -> str:
    members = sorted(_normalize_identifier(value, "member_id") for value in member_ids)
    if not members or len(set(members)) != len(members):
        raise ValueError("membership must be non-empty and unique")
    return _sha256(members)


def _deterministic_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_sha256(value)[:24].upper()}"


def source_identity_from_label(master_label_fields: Mapping[str, Any]) -> dict[str, str]:
    fields = dict(master_label_fields or {})
    clc = str(fields.get("CLC") or "").strip()
    item_alias = str(fields.get("ITEM") or fields.get("ITEM_CODE") or "").strip()
    item_id = item_alias if clc.upper() == "INSPECTION" and item_alias else (clc or item_alias)
    input_tag_id = str(fields.get("ITG") or "").strip()
    input_tag_label_id = str(fields.get("LBL") or "").strip()
    source_kind = str(fields.get("SRC") or "").strip()
    compat_work_order_id = str(fields.get("WID") or fields.get("WORK_ORDER_ID") or "").strip()
    is_input_tag = source_kind.upper() == "KMTECH_INPUT_TAG" or bool(input_tag_id)
    source_bundle_id = str(
        fields.get("BND") or fields.get("BUNDLE_ID") or fields.get("SOURCE_BUNDLE_ID") or ""
    ).strip()
    authority_scope_id = str(
        fields.get("AUTH_SCOPE") or fields.get("AUTHORITY_SCOPE_ID") or ""
    ).strip()
    return {
        "source_bundle_id": source_bundle_id,
        "input_tag_id": input_tag_id,
        "input_tag_label_id": input_tag_label_id,
        "compat_work_order_id": compat_work_order_id,
        "source_kind": source_kind,
        "external_label": "" if is_input_tag else str(
            fields.get("PHS_EXTERNAL_ID") or compat_work_order_id or ""
        ).strip(),
        "authority_scope_id": authority_scope_id,
        "item_id": item_id,
    }


class TransferSealError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 0,
        retryable: bool = False,
        committed: bool | None = False,
        details: Mapping[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = str(code or "transfer_seal_error")
        self.status_code = int(status_code or 0)
        self.retryable = bool(retryable)
        self.committed = committed
        self.details = dict(details or {})


class LogisticsTransferClient:
    """Authenticated logistics-v1 client with lost-ACK receipt recovery."""

    def __init__(
        self,
        base_url: str,
        token: str,
        source_host_id: str,
        *,
        device_id: str = "",
        timeout_seconds: float = 10.0,
        session: Any = None,
        authority_scope_id: str = "",
        authority_epoch: int = 0,
        authority_plane: str = "",
        plane_epoch: int = 0,
        authoritative_required: bool = False,
    ) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.token = str(token or "").strip()
        self.source_host_id = str(source_host_id or "").strip()
        self.device_id = str(device_id or source_host_id or "").strip()
        self.timeout_seconds = max(float(timeout_seconds), 0.1)
        self.authority_scope_id = str(authority_scope_id or "").strip()
        self.authority_epoch = int(authority_epoch or 0)
        self.authority_plane = str(authority_plane or "").strip().upper()
        self.plane_epoch = int(plane_epoch or 0)
        self.authoritative_required = bool(authoritative_required)
        if not self.base_url or not self.token or not self.source_host_id:
            raise ValueError("base_url, token, and source_host_id are required")
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("logistics base_url must be credential-free HTTPS")
        if self.authoritative_required and (
            not self.authority_scope_id
            or self.authority_epoch < 1
            or self.authority_plane != "AUTHORITATIVE"
            or self.plane_epoch < 1
        ):
            raise ValueError("authoritative logistics profile is incomplete")
        if session is None:
            import requests

            session = requests.Session()
        self.session = session

    def assert_authority(
        self,
        scope_id: str,
        *,
        authority_epoch: int | None = None,
        ledger_plane: str = "",
        plane_epoch: int | None = None,
    ) -> None:
        scope = str(scope_id or "").strip()
        if self.authority_scope_id and scope != self.authority_scope_id:
            raise TransferSealError(
                "AUTHORITY_PROFILE_MISMATCH",
                "스캔 데이터의 authority scope가 설치된 물류 프로필과 다릅니다.",
            )
        if self.authority_epoch and authority_epoch is not None and int(authority_epoch) != self.authority_epoch:
            raise TransferSealError("AUTHORITY_PROFILE_MISMATCH", "authority epoch가 설치 프로필과 다릅니다.")
        if self.authority_plane and ledger_plane and str(ledger_plane).upper() != self.authority_plane:
            raise TransferSealError("AUTHORITY_PROFILE_MISMATCH", "ledger plane이 설치 프로필과 다릅니다.")
        if self.plane_epoch and plane_epoch is not None and int(plane_epoch) != self.plane_epoch:
            raise TransferSealError("AUTHORITY_PROFILE_MISMATCH", "plane epoch가 설치 프로필과 다릅니다.")

    def _headers(self, idempotency_key: str = "") -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Logistics-Source-Host-Id": self.source_host_id,
            "X-Logistics-Device-Id": self.device_id,
            "X-Logistics-Program": "Container_Audit",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        idempotency_key: str = "",
        allow_not_found: bool = False,
    ) -> dict[str, Any] | None:
        response = self.session.request(
            method,
            f"{self.base_url}{path}",
            headers=self._headers(idempotency_key),
            json=dict(payload) if payload is not None else None,
            timeout=self.timeout_seconds,
        )
        status_code = int(getattr(response, "status_code", 0) or 0)
        try:
            body = response.json()
        except Exception as exc:
            raise TransferSealError(
                "INVALID_SERVER_RESPONSE",
                "물류 서버가 JSON 응답을 반환하지 않았습니다.",
                status_code=status_code,
                retryable=True,
                committed=None,
            ) from exc
        if allow_not_found and status_code == 404:
            return None
        if not 200 <= status_code < 300 or not isinstance(body, dict) or body.get("ok") is False:
            error = body.get("error") if isinstance(body, dict) else {}
            error = error if isinstance(error, dict) else {}
            raise TransferSealError(
                str(error.get("code") or "LOGISTICS_SERVER_REJECTED"),
                str(error.get("message") or "물류 서버 요청이 거부되었습니다."),
                status_code=status_code,
                retryable=bool(body.get("retryable")) if isinstance(body, dict) else False,
                committed=body.get("committed") if isinstance(body, dict) else None,
                details=error.get("details") if isinstance(error.get("details"), dict) else {},
            )
        data = body.get("data")
        return dict(data) if isinstance(data, dict) else {}

    def resolve_source(self, identity: Mapping[str, Any]) -> dict[str, Any]:
        params = {
            key: str(identity.get(key) or "").strip()
            for key in ("bundle_id", "input_tag_id", "external_label", "item_id", "authority_scope_id")
            if str(identity.get(key) or "").strip()
        }
        params["bundle_role"] = "TRANSFER_SOURCE"
        if self.authority_scope_id:
            supplied_scope = str(params.get("authority_scope_id") or "").strip()
            if supplied_scope and supplied_scope != self.authority_scope_id:
                self.assert_authority(supplied_scope)
            params["authority_scope_id"] = self.authority_scope_id
        if not any(params.get(key) for key in ("bundle_id", "input_tag_id", "external_label")):
            raise TransferSealError(
                "SOURCE_IDENTITY_REQUIRED",
                "현품표에 서버 PHS를 식별할 BND, ITG 또는 LBL 값이 없습니다.",
            )
        result = self._request("GET", f"/logistics/api/v1/bundles/resolve?{urlencode(params)}")
        return dict(result or {})

    def get_authority(self, scope_id: str) -> dict[str, Any]:
        self.assert_authority(scope_id)
        result = self._request(
            "GET", f"/logistics/api/v1/authority/{quote(str(scope_id), safe='')}"
        )
        return dict(result or {})

    def get_capabilities(self) -> dict[str, Any]:
        result = self._request("GET", "/logistics/api/v1/capabilities")
        return dict(result or {})

    def resolve_good_source(
        self, *, authority_scope_id: str, barcode: str
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        normalized_barcode = normalize_barcode(barcode)
        query = urlencode(
            {"authority_scope_id": scope, "barcode": normalized_barcode}
        )
        result = self._request(
            "GET",
            "/logistics/api/v1/replacements/good-source/resolve?" + query,
        )
        return dict(result or {})

    def get_receipt(self, scope_id: str, idempotency_key: str) -> dict[str, Any] | None:
        self.assert_authority(scope_id)
        return self._request(
            "GET",
            "/logistics/api/v1/receipts/"
            f"{quote(str(scope_id), safe='')}/{quote(str(idempotency_key), safe='')}",
            allow_not_found=True,
        )

    def seal_transfer(self, context: Mapping[str, Any]) -> dict[str, Any]:
        scope_id = str(context.get("authority_scope_id") or "").strip()
        idempotency_key = str(context.get("idempotency_key") or "").strip()
        if not scope_id or not idempotency_key:
            raise ValueError("command context requires scope and idempotency key")
        self.assert_authority(
            scope_id,
            authority_epoch=context.get("authority_epoch"),
            ledger_plane=str(context.get("ledger_plane") or ""),
            plane_epoch=context.get("plane_epoch"),
        )
        try:
            result = self._request(
                "POST",
                "/logistics/api/v1/transfers/seal",
                payload=context,
                idempotency_key=idempotency_key,
            )
            return dict(result or {})
        except TransferSealError as exc:
            if exc.committed is not True:
                raise
            recovered = self.get_receipt(scope_id, idempotency_key)
            if recovered is not None:
                return recovered
            raise
        except Exception as exc:
            try:
                recovered = self.get_receipt(scope_id, idempotency_key)
            except Exception:
                recovered = None
            if recovered is not None:
                return recovered
            raise TransferSealError(
                "TRANSPORT_ERROR",
                "물류 서버 응답을 확인하지 못했습니다.",
                retryable=True,
                committed=None,
                details={"exception_type": exc.__class__.__name__},
            ) from exc

    def replace_bundle_members(self, context: Mapping[str, Any]) -> dict[str, Any]:
        scope_id = str(context.get("authority_scope_id") or "").strip()
        idempotency_key = str(context.get("idempotency_key") or "").strip()
        payload = context.get("payload")
        target_bundle_id = (
            str(payload.get("target_bundle_id") or "").strip()
            if isinstance(payload, Mapping)
            else ""
        )
        if not scope_id or not idempotency_key or not target_bundle_id:
            raise ValueError("exchange command requires scope, idempotency key, and target bundle")
        self.assert_authority(
            scope_id,
            authority_epoch=context.get("authority_epoch"),
            ledger_plane=str(context.get("ledger_plane") or ""),
            plane_epoch=context.get("plane_epoch"),
        )
        path = (
            "/logistics/api/v1/bundles/"
            + quote(target_bundle_id, safe="")
            + "/members/replace"
        )
        try:
            result = self._request(
                "POST",
                path,
                payload=context,
                idempotency_key=idempotency_key,
            )
            return dict(result or {})
        except TransferSealError as exc:
            should_recover_receipt = (
                exc.committed is True
                or exc.committed is None
                or exc.status_code >= 500
            )
            if not should_recover_receipt:
                raise
            try:
                recovered = self.get_receipt(scope_id, idempotency_key)
            except Exception:
                raise exc
            if recovered is not None:
                return recovered
            raise exc
        except Exception as exc:
            try:
                recovered = self.get_receipt(scope_id, idempotency_key)
            except Exception:
                recovered = None
            if recovered is not None:
                return recovered
            raise TransferSealError(
                "TRANSPORT_ERROR",
                "중앙 제품 교체 응답을 확인하지 못했습니다.",
                retryable=True,
                committed=None,
                details={"exception_type": exc.__class__.__name__},
            ) from exc


@dataclass(frozen=True)
class SealAttempt:
    intent_id: str
    status: str
    command_id: str = ""
    transfer_bundle_id: str = ""
    seal_qr_payload: str = ""
    member_count: int = 0
    membership_hash: str = ""
    receipt_id: str = ""
    source_bundle_id: str = ""
    remainder_bundle_id: str = ""
    authority_scope_id: str = ""
    authority_epoch: int = 0
    ledger_plane: str = ""
    plane_epoch: int = 0
    item_id: str = ""
    inbound_iin: str = ""
    uom: str = ""
    entity_versions: dict[str, int] = field(default_factory=dict)
    retryable: bool = False
    error_code: str = ""
    error_message: str = ""


class TransferSealStore:
    """SQLite outbox that makes prepared scans and command payloads durable."""

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
                CREATE TABLE IF NOT EXISTS transfer_seal_intents (
                    intent_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN (
                        'PREPARED','COMMAND_READY','RETRY_WAIT','ACKED','OPERATOR_REVIEW'
                    )),
                    master_label TEXT NOT NULL,
                    source_identity_json TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    scanned_barcodes_json TEXT NOT NULL,
                    scan_count INTEGER NOT NULL CHECK(scan_count > 0),
                    intent_hash TEXT NOT NULL UNIQUE,
                    command_id TEXT UNIQUE,
                    command_json TEXT,
                    command_hash TEXT,
                    receipt_json TEXT,
                    seal_qr_payload TEXT,
                    last_error_code TEXT,
                    last_error_message TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK((command_json IS NULL) = (command_id IS NULL)),
                    CHECK((command_json IS NULL) = (command_hash IS NULL))
                );
                CREATE TRIGGER IF NOT EXISTS trg_transfer_command_immutable
                BEFORE UPDATE OF command_id, command_json, command_hash
                ON transfer_seal_intents
                WHEN OLD.command_json IS NOT NULL AND (
                    NEW.command_id <> OLD.command_id OR
                    NEW.command_json <> OLD.command_json OR
                    NEW.command_hash <> OLD.command_hash
                )
                BEGIN SELECT RAISE(ABORT, 'transfer seal command is immutable'); END;
                CREATE TABLE IF NOT EXISTS transfer_exchange_block_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    reason_code TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def prepare(
        self,
        *,
        master_label: str,
        source_identity: Mapping[str, Any],
        item_id: str,
        operator: str,
        scanned_barcodes: Iterable[str],
    ) -> sqlite3.Row:
        raw_barcodes = [_normalize_identifier(value, "scanned_barcode") for value in scanned_barcodes]
        normalized = [normalize_barcode(value) for value in raw_barcodes]
        if not raw_barcodes or len(set(normalized)) != len(normalized):
            raise ValueError("scanned barcodes must be non-empty and unique")
        intent_material = {
            "master_label": _normalize_identifier(master_label, "master_label"),
            "source_identity": {key: str(value or "").strip() for key, value in source_identity.items()},
            "item_id": _normalize_identifier(item_id, "item_id"),
            "scanned_barcodes": raw_barcodes,
        }
        digest = _sha256(intent_material)
        intent_id = f"transfer-intent-{digest[:32]}"
        now = _utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT OR IGNORE INTO transfer_seal_intents (
                       intent_id,schema_version,status,master_label,source_identity_json,
                       item_id,operator,scanned_barcodes_json,scan_count,intent_hash,created_at,updated_at
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    intent_id,
                    SCHEMA_VERSION,
                    "PREPARED",
                    intent_material["master_label"],
                    _canonical_json(intent_material["source_identity"]),
                    intent_material["item_id"],
                    str(operator or "").strip(),
                    _canonical_json(raw_barcodes),
                    len(raw_barcodes),
                    digest,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def load(self, intent_id: str) -> sqlite3.Row:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
        if row is None:
            raise KeyError(intent_id)
        return row

    def bind_command(self, intent_id: str, context: Mapping[str, Any]) -> sqlite3.Row:
        command_id = _normalize_identifier(context.get("idempotency_key"), "idempotency_key")
        command_json = _canonical_json(dict(context))
        command_hash = hashlib.sha256(command_json.encode("utf-8")).hexdigest()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(intent_id)
            if row["command_json"] is not None:
                if (
                    row["command_id"] != command_id
                    or row["command_json"] != command_json
                    or row["command_hash"] != command_hash
                ):
                    raise ValueError("durable transfer command differs from retry payload")
            else:
                conn.execute(
                    """UPDATE transfer_seal_intents
                          SET status='COMMAND_READY',command_id=?,command_json=?,command_hash=?,
                              last_error_code=NULL,last_error_message=NULL,updated_at=?
                        WHERE intent_id=?""",
                    (command_id, command_json, command_hash, _utc_now(), intent_id),
                )
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def record_error(self, intent_id: str, error: TransferSealError) -> sqlite3.Row:
        operator_review_codes = {
            "AMBIGUOUS_BUNDLE",
            "SOURCE_IDENTITY_MISMATCH",
            "BUNDLE_IDENTITY_MISMATCH",
            "MEMBERSHIP_CONFLICT",
            "BARCODE_NOT_IN_SOURCE_BUNDLE",
            "BARCODE_MAPPING_AMBIGUOUS",
            "STALE_VERSION",
            "RECEIPT_MEMBERSHIP_MISMATCH",
            "SOURCE_IDENTITY_REQUIRED",
            "AUTHORITY_INVALID",
            "AUTHORITY_PROFILE_MISMATCH",
            "RESOLVER_CONTRACT_INVALID",
        }
        terminal_cas_conflict = error.status_code in {409, 412}
        terminal_client_error = (
            400 <= error.status_code < 500
            and error.status_code != 404
            and not error.retryable
        )
        status = (
            "OPERATOR_REVIEW"
            if (
                error.code.upper() in operator_review_codes
                or terminal_cas_conflict
                or terminal_client_error
            )
            else "RETRY_WAIT"
        )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE transfer_seal_intents
                      SET status=?,last_error_code=?,last_error_message=?,attempt_count=attempt_count+1,
                          updated_at=? WHERE intent_id=?""",
                (status, error.code, str(error), _utc_now(), intent_id),
            )
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def record_receipt(self, intent_id: str, receipt: Mapping[str, Any], seal_qr_payload: str) -> sqlite3.Row:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE transfer_seal_intents
                      SET status='ACKED',receipt_json=?,seal_qr_payload=?,last_error_code=NULL,
                          last_error_message=NULL,attempt_count=attempt_count+1,updated_at=?
                    WHERE intent_id=?""",
                (_canonical_json(dict(receipt)), seal_qr_payload, _utc_now(), intent_id),
            )
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def pending_ids(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT intent_id FROM transfer_seal_intents WHERE status IN (?,?,?) ORDER BY created_at",
                PENDING_STATUSES,
            ).fetchall()
        return [str(row["intent_id"]) for row in rows]

    def has_exact_history(self) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM transfer_seal_intents LIMIT 1").fetchone()
        return row is not None

    def record_exchange_block(self, *, reason_code: str, details: Mapping[str, Any]) -> str:
        created_at = _utc_now()
        material = {
            "reason_code": _normalize_identifier(reason_code, "reason_code"),
            "details": dict(details or {}),
            "created_at": created_at,
        }
        receipt_id = _deterministic_id("EXCHANGE-BLOCK", material)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO transfer_exchange_block_receipts (
                       receipt_id,reason_code,details_json,created_at
                   ) VALUES (?,?,?,?)""",
                (receipt_id, material["reason_code"], _canonical_json(material["details"]), created_at),
            )
            conn.commit()
        return receipt_id


class TransferSealCoordinator:
    def __init__(self, store: TransferSealStore, client: LogisticsTransferClient | None) -> None:
        self.store = store
        self.client = client

    def prepare(
        self,
        *,
        master_label: str,
        master_label_fields: Mapping[str, Any],
        item_id: str,
        operator: str,
        scanned_barcodes: Iterable[str],
    ) -> SealAttempt:
        identity = source_identity_from_label(master_label_fields)
        if not identity["item_id"]:
            identity["item_id"] = str(item_id or "").strip()
        row = self.store.prepare(
            master_label=master_label,
            source_identity=identity,
            item_id=item_id,
            operator=operator,
            scanned_barcodes=scanned_barcodes,
        )
        return self._attempt_from_row(row)

    @staticmethod
    def _result_data(receipt: Mapping[str, Any]) -> dict[str, Any]:
        nested = receipt.get("data")
        return dict(nested) if isinstance(nested, Mapping) else dict(receipt)

    @staticmethod
    def _map_scans(bundle: Mapping[str, Any], scanned_barcodes: list[str]) -> list[str]:
        members = bundle.get("members")
        if not isinstance(members, list) or not members:
            raise TransferSealError("MEMBERSHIP_CONFLICT", "서버 PHS에 제품 membership 상세가 없습니다.")
        by_barcode: dict[str, list[str]] = {}
        for member in members:
            if not isinstance(member, Mapping):
                raise TransferSealError("MEMBERSHIP_CONFLICT", "서버 membership 형식이 잘못되었습니다.")
            unit_id = str(member.get("unit_id") or "").strip()
            barcode = str(member.get("normalized_barcode") or "").strip()
            if not unit_id or not barcode:
                raise TransferSealError("MEMBERSHIP_CONFLICT", "서버 membership 식별자가 누락됐습니다.")
            by_barcode.setdefault(normalize_barcode(barcode), []).append(unit_id)
        selected: list[str] = []
        for barcode in scanned_barcodes:
            candidates = by_barcode.get(normalize_barcode(barcode), [])
            if not candidates:
                raise TransferSealError(
                    "BARCODE_NOT_IN_SOURCE_BUNDLE", f"스캔 제품이 원본 PHS에 없습니다: {barcode}"
                )
            if len(candidates) != 1:
                raise TransferSealError(
                    "BARCODE_MAPPING_AMBIGUOUS", f"스캔 제품의 서버 unit 매핑이 하나가 아닙니다: {barcode}"
                )
            selected.append(candidates[0])
        if len(set(selected)) != len(selected):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "스캔 목록이 같은 서버 unit에 중복 매핑됐습니다.")
        server_member_ids = [str(value) for value in bundle.get("member_ids") or []]
        if set(selected) - set(server_member_ids):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "선택 membership이 원본 PHS 범위를 벗어났습니다.")
        return sorted(selected)

    def _build_command(self, row: sqlite3.Row) -> Mapping[str, Any]:
        if self.client is None:
            raise TransferSealError(
                "LOGISTICS_CLIENT_NOT_CONFIGURED",
                "물류 서버 설정이 없어 이적 seal을 보류했습니다.",
                retryable=True,
            )
        identity = json.loads(row["source_identity_json"])
        resolve_identity = {
            "bundle_id": identity.get("source_bundle_id"),
            "input_tag_id": identity.get("input_tag_id"),
            "external_label": identity.get("external_label"),
            "authority_scope_id": identity.get("authority_scope_id"),
            "item_id": identity.get("item_id") or row["item_id"],
        }
        try:
            resolved = self.client.resolve_source(resolve_identity)
        except TransferSealError as exc:
            if exc.status_code == 404:
                raise TransferSealError(
                    "SOURCE_NOT_YET_AVAILABLE",
                    "서버에서 원본 PHS를 아직 찾지 못해 이적 seal을 보류했습니다.",
                    retryable=True,
                    details=exc.details,
                ) from exc
            raise
        bundle_value = resolved.get("bundle") if isinstance(resolved, Mapping) else None
        if not isinstance(bundle_value, Mapping):
            raise TransferSealError(
                "RESOLVER_CONTRACT_INVALID",
                "서버 PHS resolver 응답에 정본 bundle projection이 없습니다.",
            )
        candidate_count = resolved.get("candidate_count")
        if (
            isinstance(candidate_count, bool)
            or not isinstance(candidate_count, int)
            or candidate_count != 1
        ):
            raise TransferSealError(
                "AMBIGUOUS_BUNDLE",
                "서버 PHS resolver가 이적 원본을 정확히 하나로 확정하지 못했습니다.",
            )
        bundle = dict(bundle_value)
        source_bundle_id = _normalize_identifier(bundle.get("bundle_id"), "source_bundle_id")
        if (
            bundle.get("bundle_role") != "TRANSFER_SOURCE"
            or bundle.get("bundle_type") not in {"PHS", "RESIDUAL"}
            or bundle.get("bundle_state") != "AVAILABLE"
        ):
            raise TransferSealError(
                "SOURCE_IDENTITY_MISMATCH", "서버 응답 bundle이 이적 가능한 원본 PHS/잔량이 아닙니다."
            )
        if str(bundle.get("item_id") or "") != str(row["item_id"]):
            raise TransferSealError(
                "SOURCE_IDENTITY_MISMATCH", "서버 원본 bundle의 품목이 현품표와 일치하지 않습니다."
            )
        raw_source_members = bundle.get("member_ids")
        if not isinstance(raw_source_members, list):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "원본 PHS exact membership이 없습니다.")
        source_members = [str(value or "").strip() for value in raw_source_members]
        source_member_count = bundle.get("member_count")
        if (
            not source_members
            or any(not value for value in source_members)
            or len(set(source_members)) != len(source_members)
            or isinstance(source_member_count, bool)
            or not isinstance(source_member_count, int)
            or source_member_count != len(source_members)
        ):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "원본 PHS membership이 비어 있거나 중복됐습니다.")
        if membership_hash(source_members) != str(bundle.get("membership_hash") or ""):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "원본 PHS membership hash가 일치하지 않습니다.")
        member_rows = bundle.get("members")
        if not isinstance(member_rows, list) or len(member_rows) != len(source_members):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "원본 PHS barcode mapping이 일부만 제공됐습니다.")
        row_unit_ids: list[str] = []
        source_barcodes: list[str] = []
        for member in member_rows:
            if not isinstance(member, Mapping):
                raise TransferSealError("MEMBERSHIP_CONFLICT", "서버 membership 형식이 잘못되었습니다.")
            unit_id = str(member.get("unit_id") or "").strip()
            barcode = str(member.get("normalized_barcode") or "").strip()
            if not unit_id or not barcode:
                raise TransferSealError("MEMBERSHIP_CONFLICT", "서버 membership 식별자가 누락됐습니다.")
            row_unit_ids.append(unit_id)
            source_barcodes.append(normalize_barcode(barcode))
        source_barcodes.sort()
        if (
            len(set(row_unit_ids)) != len(row_unit_ids)
            or set(row_unit_ids) != set(source_members)
            or len(set(source_barcodes)) != len(source_barcodes)
            or isinstance(bundle.get("barcode_member_count"), bool)
            or not isinstance(bundle.get("barcode_member_count"), int)
            or bundle.get("barcode_member_count") != len(source_barcodes)
            or bundle.get("barcode_membership_hash") != membership_hash(source_barcodes)
            or not str(bundle.get("source_iin") or "").strip()
            or not str(bundle.get("uom") or "").strip()
        ):
            raise TransferSealError(
                "MEMBERSHIP_CONFLICT", "원본 PHS barcode membership 증거가 일치하지 않습니다."
            )
        scans = list(json.loads(row["scanned_barcodes_json"]))
        selected = self._map_scans(bundle, scans)
        selected_hash = membership_hash(selected)
        transfer_bundle_id = _deterministic_id(
            "TRANSFER", {"source_bundle_id": source_bundle_id, "member_ids": selected}
        )
        remainder = sorted(set(source_members) - set(selected))
        payload: dict[str, Any] = {
            "source_bundle_id": source_bundle_id,
            "transfer_bundle_id": transfer_bundle_id,
            "external_label": transfer_bundle_id,
            "item_id": row["item_id"],
            "member_ids": selected,
            "membership_hash": selected_hash,
            "scanned_barcodes": scans,
        }
        if remainder:
            remainder_bundle_id = _deterministic_id(
                "TRANSFER-REMAINDER",
                {"source_bundle_id": source_bundle_id, "member_ids": remainder},
            )
            payload.update(
                {
                    "remainder_bundle_id": remainder_bundle_id,
                }
            )
        scope_id = _normalize_identifier(bundle.get("authority_scope_id"), "authority_scope_id")
        authority_epoch = bundle.get("authority_epoch")
        if not isinstance(authority_epoch, int) or isinstance(authority_epoch, bool):
            authority = self.client.get_authority(scope_id)
            authority_epoch = authority.get("authority_epoch")
        if not isinstance(authority_epoch, int) or isinstance(authority_epoch, bool):
            raise TransferSealError("AUTHORITY_INVALID", "서버 authority epoch를 확인할 수 없습니다.")
        plane_epoch = bundle.get("plane_epoch")
        entity_version = bundle.get("entity_version")
        if not isinstance(plane_epoch, int) or isinstance(plane_epoch, bool) or plane_epoch < 1:
            raise TransferSealError("AUTHORITY_INVALID", "서버 plane epoch가 잘못됐습니다.")
        if str(bundle.get("ledger_plane") or "") not in {"AUTHORITATIVE", "SHADOW_CANDIDATE"}:
            raise TransferSealError("AUTHORITY_INVALID", "서버 ledger plane이 이적 가능한 상태가 아닙니다.")
        if not isinstance(entity_version, int) or isinstance(entity_version, bool) or entity_version < 1:
            raise TransferSealError("MEMBERSHIP_CONFLICT", "원본 PHS version이 잘못됐습니다.")
        idempotency_key = f"container-seal:{row['intent_hash']}"
        return {
            "contract_version": CONTRACT_VERSION,
            "command_type": COMMAND_TYPE,
            "authority_scope_id": scope_id,
            "authority_epoch": authority_epoch,
            "ledger_plane": str(bundle.get("ledger_plane") or ""),
            "plane_epoch": plane_epoch,
            "idempotency_key": idempotency_key,
            "expected_versions": {f"bundle:{source_bundle_id}": entity_version},
            "payload": payload,
            "client_exact_evidence": {
                "source_member_ids": sorted(source_members),
                "remainder_member_ids": remainder,
            },
            "reason": "container_audit_exact_scan_seal",
            "evidence_refs": [row["intent_id"], row["intent_hash"]],
        }

    @staticmethod
    def _seal_qr(context: Mapping[str, Any], data: Mapping[str, Any]) -> str:
        # The server is the sole issuer of the opaque seal identity/token.  A
        # desktop-generated compatibility QR cannot later be invalidated
        # safely, so never synthesize one from membership data.
        qr_payload = str(data.get("seal_qr_payload") or "").strip()
        if not qr_payload:
            raise TransferSealError(
                "RECEIPT_MEMBERSHIP_MISMATCH",
                "서버 receipt에 이적 seal QR이 없습니다.",
            )
        return qr_payload

    @staticmethod
    def _validate_receipt(context: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any]:
        data = TransferSealCoordinator._result_data(receipt)
        payload = context["payload"]
        actual_ids = sorted(str(value) for value in data.get("member_ids") or [])
        expected_barcodes = sorted(normalize_barcode(value) for value in payload["scanned_barcodes"])
        actual_barcodes = sorted(str(value) for value in data.get("scanned_barcodes") or [])
        evidence = context.get("client_exact_evidence")
        evidence = evidence if isinstance(evidence, Mapping) else {}
        expected_remainder_ids = sorted(
            str(value) for value in evidence.get("remainder_member_ids") or []
        )
        actual_remainder_ids = sorted(
            str(value) for value in data.get("remainder_member_ids") or []
        )
        source_member_ids = sorted(
            str(value) for value in evidence.get("source_member_ids") or []
        )
        actual_member_pairs = sorted(
            (
                str(row.get("unit_id") or ""),
                normalize_barcode(row.get("normalized_barcode")),
            )
            for row in (data.get("members") or [])
            if isinstance(row, Mapping)
        )
        sealed_member_pairs = sorted(
            (
                str(row.get("unit_id") or ""),
                normalize_barcode(row.get("normalized_barcode")),
            )
            for row in (data.get("sealed_members") or [])
            if isinstance(row, Mapping)
        )
        seal_qr_payload = str(data.get("seal_qr_payload") or "").strip()
        seal_fields = {
            key.strip().upper(): unquote(value.strip())
            for key, value in (
                part.split("=", 1)
                for part in seal_qr_payload.split("|")
                if "=" in part
            )
        }
        raw_versions = receipt.get("entity_versions")
        if not isinstance(raw_versions, Mapping):
            raw_versions = data.get("entity_versions")
        actual_versions = dict(raw_versions) if isinstance(raw_versions, Mapping) else {}
        expected_versions = {
            str(key): int(value) + 1
            for key, value in context.get("expected_versions", {}).items()
        }
        expected_versions[f"bundle:{payload['transfer_bundle_id']}"] = 1
        if payload.get("remainder_bundle_id"):
            expected_versions[f"bundle:{payload['remainder_bundle_id']}"] = 1
        if (
            not str(receipt.get("receipt_id") or "").strip()
            or receipt.get("contract_version") != CONTRACT_VERSION
            or receipt.get("command_type") != COMMAND_TYPE
            or str(receipt.get("status") or "").upper() != "COMMITTED"
            or receipt.get("authority_scope_id") != context["authority_scope_id"]
            or receipt.get("authority_epoch") != context["authority_epoch"]
            or str(receipt.get("resolved_ledger_plane") or "").upper()
            != str(context["ledger_plane"]).upper()
            or receipt.get("resolved_plane_epoch") != context["plane_epoch"]
            or not str(receipt.get("committed_at") or "").strip()
            or not isinstance(receipt.get("event_ids"), (list, tuple))
            or not receipt.get("event_ids")
            or not isinstance(receipt.get("outbox_ids"), (list, tuple))
            or not receipt.get("outbox_ids")
            or any(
                actual_versions.get(key) != version
                for key, version in expected_versions.items()
            )
            or data.get("transfer_bundle_id") != payload["transfer_bundle_id"]
            or data.get("item_id") != payload["item_id"]
            or actual_ids != sorted(payload["member_ids"])
            or data.get("member_count") != len(payload["member_ids"])
            or data.get("membership_hash") != payload["membership_hash"]
            or actual_barcodes != expected_barcodes
            or data.get("scanned_barcode_count") != len(expected_barcodes)
            or data.get("scanned_barcode_hash") != membership_hash(expected_barcodes)
            or actual_remainder_ids != expected_remainder_ids
            or data.get("remainder_member_count") != len(expected_remainder_ids)
            or data.get("remainder_membership_hash")
            != (membership_hash(expected_remainder_ids) if expected_remainder_ids else None)
            or sorted(actual_ids + actual_remainder_ids) != source_member_ids
            or bool(set(actual_ids) & set(actual_remainder_ids))
            or not str(data.get("inbound_iin") or "").strip()
            or not str(data.get("uom") or "").strip()
            or data.get("seal_contract_version") != "transfer-seal-qr-v1"
            or data.get("seal_state") != "ACTIVE"
            or not str(data.get("seal_id") or "").strip()
            or data.get("seal_revision") != 1
            or not str(data.get("seal_token") or "").strip()
            or data.get("sealed_bundle_id") != payload["transfer_bundle_id"]
            or data.get("sealed_bundle_version") != 1
            or sorted(str(value) for value in data.get("sealed_member_ids") or [])
            != sorted(payload["member_ids"])
            or len(actual_member_pairs) != len(payload["member_ids"])
            or sealed_member_pairs != actual_member_pairs
            or len({unit_id for unit_id, _barcode in sealed_member_pairs})
            != len(sealed_member_pairs)
            or len({barcode for _unit_id, barcode in sealed_member_pairs})
            != len(sealed_member_pairs)
            or data.get("sealed_member_count") != len(payload["member_ids"])
            or data.get("sealed_membership_hash") != payload["membership_hash"]
            or sorted(
                normalize_barcode(value)
                for value in data.get("sealed_normalized_barcodes") or []
            )
            != expected_barcodes
            or data.get("sealed_barcode_membership_hash")
            != membership_hash(expected_barcodes)
            or seal_fields.get("TRF") != "1"
            or seal_fields.get("BND") != payload["transfer_bundle_id"]
            or seal_fields.get("AUTH_SCOPE") != context["authority_scope_id"]
            or seal_fields.get("CLC") != payload["item_id"]
            or seal_fields.get("QT") != str(len(payload["member_ids"]))
            or seal_fields.get("HSH") != payload["membership_hash"]
            or seal_fields.get("EPOCH") != str(context["authority_epoch"])
            or seal_fields.get("PLANE") != context["ledger_plane"]
            or seal_fields.get("PE") != str(context["plane_epoch"])
            or seal_fields.get("SID") != data.get("seal_id")
            or seal_fields.get("SREV") != str(data.get("seal_revision"))
            or seal_fields.get("STK") != data.get("seal_token")
        ):
            raise TransferSealError(
                "RECEIPT_MEMBERSHIP_MISMATCH",
                "서버 receipt의 이적 membership이 전송한 명령과 일치하지 않습니다.",
            )
        expected_remainder = str(payload.get("remainder_bundle_id") or "")
        if str(data.get("remainder_bundle_id") or "") != expected_remainder:
            raise TransferSealError(
                "RECEIPT_MEMBERSHIP_MISMATCH", "서버 receipt의 잔여 bundle이 명령과 일치하지 않습니다."
            )
        return data

    def attempt(self, intent_id: str) -> SealAttempt:
        row = self.store.load(intent_id)
        if row["status"] == "ACKED":
            return self._attempt_from_row(row)
        if row["status"] == "OPERATOR_REVIEW":
            return self._attempt_from_row(row)
        try:
            if row["command_json"] is None:
                context = self._build_command(row)
                row = self.store.bind_command(intent_id, context)
            context = json.loads(row["command_json"])
            if self.client is None:
                raise TransferSealError(
                    "LOGISTICS_CLIENT_NOT_CONFIGURED",
                    "물류 서버 설정이 없어 이적 seal을 보류했습니다.",
                    retryable=True,
                )
            receipt = self.client.seal_transfer(context)
            data = self._validate_receipt(context, receipt)
            qr_payload = self._seal_qr(context, data)
            row = self.store.record_receipt(intent_id, receipt, qr_payload)
        except TransferSealError as exc:
            row = self.store.record_error(intent_id, exc)
        except Exception as exc:
            row = self.store.record_error(
                intent_id,
                TransferSealError(
                    "LOCAL_TRANSFER_SEAL_ERROR",
                    f"이적 seal 처리 중 로컬 오류가 발생했습니다: {exc.__class__.__name__}",
                    retryable=True,
                ),
            )
        return self._attempt_from_row(row)

    def drain_pending(self) -> list[SealAttempt]:
        return [self.attempt(intent_id) for intent_id in self.store.pending_ids()]

    @staticmethod
    def _attempt_from_row(row: sqlite3.Row) -> SealAttempt:
        context = json.loads(row["command_json"]) if row["command_json"] else {}
        payload = context.get("payload") if isinstance(context.get("payload"), dict) else {}
        receipt = json.loads(row["receipt_json"]) if row["receipt_json"] else {}
        receipt_data = TransferSealCoordinator._result_data(receipt) if receipt else {}
        raw_versions = receipt.get("entity_versions") or receipt_data.get("entity_versions") or {}
        entity_versions = {
            str(key): int(value)
            for key, value in raw_versions.items()
            if isinstance(value, int) and not isinstance(value, bool)
        } if isinstance(raw_versions, Mapping) else {}
        return SealAttempt(
            intent_id=str(row["intent_id"]),
            status=str(row["status"]),
            command_id=str(row["command_id"] or ""),
            transfer_bundle_id=str(payload.get("transfer_bundle_id") or ""),
            seal_qr_payload=str(row["seal_qr_payload"] or ""),
            member_count=len(payload.get("member_ids") or []),
            membership_hash=str(payload.get("membership_hash") or ""),
            receipt_id=str(receipt.get("receipt_id") or ""),
            source_bundle_id=str(payload.get("source_bundle_id") or ""),
            remainder_bundle_id=str(payload.get("remainder_bundle_id") or ""),
            authority_scope_id=str(context.get("authority_scope_id") or ""),
            authority_epoch=int(context.get("authority_epoch") or 0),
            ledger_plane=str(context.get("ledger_plane") or ""),
            plane_epoch=int(context.get("plane_epoch") or 0),
            item_id=str(receipt_data.get("item_id") or payload.get("item_id") or ""),
            inbound_iin=str(receipt_data.get("inbound_iin") or ""),
            uom=str(receipt_data.get("uom") or ""),
            entity_versions=entity_versions,
            retryable=row["status"] == "RETRY_WAIT",
            error_code=str(row["last_error_code"] or ""),
            error_message=str(row["last_error_message"] or ""),
        )


def logistics_transfer_client_from_env(
    *,
    session: Any = None,
    probe_required: bool = True,
    environ: Mapping[str, str] | None = None,
    profile_decryptor: Any = None,
) -> LogisticsTransferClient | None:
    values = os.environ if environ is None else environ
    required = logistics_runtime_required(environ)
    profile = load_logistics_runtime_profile(
        required,
        environ=environ,
        decryptor=profile_decryptor,
    )
    if profile is not None:
        client = LogisticsTransferClient(
            profile.base_url,
            profile.bearer_token,
            profile.source_host_id,
            device_id=profile.device_id,
            timeout_seconds=profile.timeout_seconds,
            session=session,
            authority_scope_id=profile.authority_scope,
            authority_epoch=profile.authority_epoch,
            authority_plane=profile.authority_plane,
            plane_epoch=profile.plane_epoch,
            authoritative_required=required,
        )
    else:
        legacy_fields = {
            "base_url": str(
                values.get("WORKER_ANALYSIS_LOGISTICS_API_BASE_URL")
                or values.get("WORKER_ANALYSIS_SERVER_URL")
                or ""
            ).strip(),
            "token": str(values.get("WORKER_ANALYSIS_LOGISTICS_API_TOKEN") or "").strip(),
            "source_host_id": str(
                values.get("WORKER_ANALYSIS_LOGISTICS_SOURCE_HOST_ID")
                or values.get("COMPUTERNAME")
                or ""
            ).strip(),
        }
        explicitly_configured = bool(
            legacy_fields["base_url"] or legacy_fields["token"]
        )
        if not explicitly_configured:
            return None
        if not all(legacy_fields.values()):
            raise LogisticsRuntimeConfigurationError(
                "legacy Container logistics environment profile is incomplete"
            )
        try:
            timeout = float(values.get("WORKER_ANALYSIS_LOGISTICS_TIMEOUT_SECONDS", "10"))
            client = LogisticsTransferClient(
                legacy_fields["base_url"],
                legacy_fields["token"],
                legacy_fields["source_host_id"],
                device_id=values.get(
                    "WORKER_ANALYSIS_LOGISTICS_DEVICE_ID",
                    legacy_fields["source_host_id"],
                ),
                timeout_seconds=timeout,
                session=session,
            )
        except (TypeError, ValueError) as exc:
            raise LogisticsRuntimeConfigurationError(
                "legacy Container logistics environment profile is invalid"
            ) from exc
    if required and probe_required:
        try:
            capabilities = client.get_capabilities()
            capability = (capabilities.get("capabilities") or {}).get(
                "bundle_member_replacement_v1"
            )
            if (
                "bundle_member_replacement_v1"
                not in (capabilities.get("capability_ids") or [])
                or not isinstance(capability, Mapping)
                or capability.get("enabled") is not True
                or capability.get("command_type") != "REPLACE_BUNDLE_MEMBERS"
                or capability.get("resolver_contract_version")
                != "logistics-good-replacement-source-v1"
                or capability.get("resolver_path")
                != "/logistics/api/v1/replacements/good-source/resolve"
                or capability.get("max_pairs") != 2
                or capability.get("atomic") is not True
                or capability.get("two_bundle_cas") is not True
                or capability.get("sealed_transfer_package") is not False
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
                raise LogisticsRuntimeConfigurationError(
                    "authoritative logistics capability readiness is incomplete"
                )
        except LogisticsRuntimeConfigurationError:
            raise
        except TransferSealError as exc:
            raise LogisticsRuntimeConfigurationError(
                f"authoritative logistics readiness failed: {exc.code}"
            ) from exc
        except Exception as exc:
            raise LogisticsRuntimeConfigurationError(
                f"authoritative logistics readiness failed: {exc.__class__.__name__}"
            ) from exc
    return client


def transfer_seal_coordinator_from_env(
    db_path: str | os.PathLike[str],
    *,
    session: Any = None,
    probe_required: bool = True,
    profile_decryptor: Any = None,
) -> TransferSealCoordinator:
    store = TransferSealStore(db_path)
    client = logistics_transfer_client_from_env(
        session=session,
        probe_required=probe_required,
        profile_decryptor=profile_decryptor,
    )
    return TransferSealCoordinator(store, client)


__all__ = [
    "LogisticsTransferClient",
    "SealAttempt",
    "TransferSealCoordinator",
    "TransferSealError",
    "TransferSealStore",
    "membership_hash",
    "logistics_transfer_client_from_env",
    "normalize_barcode",
    "source_identity_from_label",
    "transfer_seal_coordinator_from_env",
]

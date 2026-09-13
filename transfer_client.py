"""Authenticated logistics transport and runtime-profile client construction."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import quote, urlencode, urlsplit

from logistics_runtime_profile import (
    LogisticsRuntimeConfigurationError,
    load_logistics_runtime_profile,
    logistics_runtime_required,
)
from terminal_operation_lease import TRANSFER_OPERATION
from transfer_common import TransferSealError, _normalize_identifier, normalize_barcode
from writer_session_fence import writer_sink


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
        ledger_plane: str = "",
        plane_epoch: int = 0,
        authoritative_required: bool = False,
        isolated_qualification_authority_id: str = "",
        tls_ca_bundle_path: str = "",
    ) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.token = str(token or "").strip()
        self.source_host_id = str(source_host_id or "").strip()
        self.device_id = str(device_id or source_host_id or "").strip()
        self.timeout_seconds = max(float(timeout_seconds), 0.1)
        self.authority_scope_id = str(authority_scope_id or "").strip()
        self.authority_epoch = int(authority_epoch or 0)
        self.authority_plane = str(authority_plane or "").strip().upper()
        self.ledger_plane = str(ledger_plane or authority_plane or "").strip().upper()
        self.plane_epoch = int(plane_epoch or 0)
        self.authoritative_required = bool(authoritative_required)
        self.isolated_qualification_authority_id = str(
            isolated_qualification_authority_id or ""
        ).strip()
        self.tls_ca_bundle_path = str(tls_ca_bundle_path or "").strip()
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
            or self.ledger_plane not in {"AUTHORITATIVE", "SHADOW_CANDIDATE"}
            or self.plane_epoch < 1
        ):
            raise ValueError("authoritative logistics profile is incomplete")
        if session is None:
            import requests

            session = requests.Session()
            if self.tls_ca_bundle_path:
                session.trust_env = False
                session.verify = self.tls_ca_bundle_path
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
        if self.ledger_plane and ledger_plane and str(ledger_plane).upper() != self.ledger_plane:
            raise TransferSealError("AUTHORITY_PROFILE_MISMATCH", "ledger plane이 설치 프로필과 다릅니다.")
        if self.plane_epoch and plane_epoch is not None and int(plane_epoch) != self.plane_epoch:
            raise TransferSealError("AUTHORITY_PROFILE_MISMATCH", "plane epoch가 설치 프로필과 다릅니다.")

    def _headers(self, idempotency_key: str = "") -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Logistics-API-Token": self.token,
            "X-Logistics-Source-Host-Id": self.source_host_id,
            "X-Logistics-Device-Id": self.device_id,
            "X-Logistics-Program": "Container_Audit",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    @writer_sink("transfer_api_request")
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
            allow_redirects=False,
        )
        status_code = int(getattr(response, "status_code", 0) or 0)
        if 300 <= status_code < 400:
            read_only_method = str(method or "").strip().upper() in {
                "GET",
                "HEAD",
                "OPTIONS",
            }
            raise TransferSealError(
                "LOGISTICS_REDIRECT_BLOCKED",
                "물류 인증 요청의 redirect를 차단했습니다. 관리자에게 설정을 확인하세요.",
                status_code=status_code,
                retryable=False,
                committed=False if read_only_method else None,
            )
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
        if not 200 <= status_code < 300 or not isinstance(body, dict) or body.get("ok") is not True:
            error = body.get("error") if isinstance(body, dict) else {}
            error = error if isinstance(error, dict) else {}
            raise TransferSealError(
                str(error.get("code") or "LOGISTICS_SERVER_REJECTED"),
                str(error.get("message") or "물류 서버 요청이 거부되었습니다."),
                status_code=status_code,
                retryable=body.get("retryable") is True if isinstance(body, dict) else False,
                committed=body.get("committed") if isinstance(body, dict) else None,
                details=error.get("details") if isinstance(error.get("details"), dict) else {},
            )
        data = body.get("data")
        return dict(data) if isinstance(data, dict) else {}

    @writer_sink("transfer_seal")
    def issue_operation_lease(
        self,
        *,
        authority_scope_id: str,
        operation: str,
        scan_payload: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Issue/replay one signed terminal-exclusive physical operation lease."""

        scope = str(authority_scope_id or "").strip()
        operation_name = str(operation or "").strip()
        physical_scan = str(scan_payload or "")
        key = str(idempotency_key or "").strip()
        if not scope or operation_name != TRANSFER_OPERATION or not physical_scan or not key:
            raise ValueError("operation lease issue requires exact transfer context")
        self.assert_authority(scope)
        result = self._request(
            "POST",
            "/logistics/api/v1/operation-leases/issue",
            payload={
                "authority_scope_id": scope,
                "operation": operation_name,
                "scan_payload": physical_scan,
            },
            idempotency_key=key,
        )
        return dict(result or {})

    def resolve_source(self, identity: Mapping[str, Any]) -> dict[str, Any]:
        params = {
            key: str(identity.get(key) or "").strip()
            for key in (
                "bundle_id",
                "input_tag_id",
                "external_label",
                "item_id",
                "authority_scope_id",
            )
            if str(identity.get(key) or "").strip()
        }
        input_tag_hash_prefix = str(identity.get("input_tag_hash_prefix") or "").strip()
        if input_tag_hash_prefix:
            input_tag_label_id = str(identity.get("input_tag_label_id") or "").strip()
            if not input_tag_label_id:
                raise TransferSealError(
                    "SOURCE_IDENTITY_REQUIRED",
                    "중앙 PHS=2 현품표에 LBL 식별자가 없습니다.",
                )
            params["input_tag_label_id"] = input_tag_label_id
            params["input_tag_hash_prefix"] = input_tag_hash_prefix
        params["bundle_role"] = "TRANSFER_SOURCE"
        if self.authority_scope_id:
            supplied_scope = str(params.get("authority_scope_id") or "").strip()
            if supplied_scope and supplied_scope != self.authority_scope_id:
                self.assert_authority(supplied_scope)
            params["authority_scope_id"] = self.authority_scope_id
        if not any(params.get(key) for key in ("bundle_id", "input_tag_id", "external_label")):
            raise TransferSealError(
                "SOURCE_IDENTITY_REQUIRED",
                "현품표에 서버 PHS를 식별할 BND, ITG 또는 외부 라벨 값이 없습니다.",
            )
        result = self._request("GET", f"/logistics/api/v1/bundles/resolve?{urlencode(params)}")
        return dict(result or {})

    def resolve_phs_label(
        self,
        *,
        authority_scope_id: str,
        scan_payload: str,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        query = urlencode(
            {
                "authority_scope_id": scope,
                "scan_payload": _normalize_identifier(
                    scan_payload, "scan_payload"
                ),
            }
        )
        result = self._request(
            "GET", f"/logistics/api/v1/phs-labels/resolve?{query}"
        )
        return dict(result or {})

    def resolve_phs_reconciliation_actions(
        self,
        *,
        authority_scope_id: str,
        scan_payload: str,
        process_context: str = "transfer",
        limit: int = 20,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        query = urlencode(
            {
                "authority_scope_id": scope,
                "scan_payload": _normalize_identifier(
                    scan_payload, "scan_payload"
                ),
                "process_context": str(
                    process_context or ""
                ).strip().lower(),
                "limit": int(limit),
            }
        )
        result = self._request(
            "GET",
            (
                "/logistics/api/v1/phs-work-reconciliations/"
                f"actions/resolve?{query}"
            ),
        )
        return dict(result or {})

    def list_phs_work_instruction_candidates(
        self,
        *,
        authority_scope_id: str,
        business_date: str,
        item_id: str,
        target_qty_pcs: int,
        limit: int = 20,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        query = urlencode(
            {
                "authority_scope_id": scope,
                "business_date": _normalize_identifier(
                    business_date, "business_date"
                ),
                "item_id": _normalize_identifier(item_id, "item_id"),
                "target_qty_pcs": int(target_qty_pcs),
                "limit": int(limit),
            }
        )
        result = self._request(
            "GET",
            f"/logistics/api/v1/phs-work-instructions/candidates?{query}",
        )
        return dict(result or {})

    @writer_sink("transfer_seal")
    def adopt_phs_label(
        self,
        *,
        authority_scope_id: str,
        qr_payload: str,
        business_date: str = "",
        expected_session_version: int | None = None,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        payload: dict[str, Any] = {
            "authority_scope_id": scope,
            "qr_payload": _normalize_identifier(qr_payload, "qr_payload"),
        }
        if str(business_date or "").strip():
            payload["business_date"] = str(business_date).strip()
        if expected_session_version is not None:
            payload["expected_session_version"] = int(
                expected_session_version
            )
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-labels/adopt",
            payload=payload,
        )
        return dict(result or {})

    @writer_sink("transfer_seal")
    def prepare_phs_label_exchange(
        self,
        *,
        authority_scope_id: str,
        exchange_kind: str,
        sources: list[dict[str, Any]],
        targets: list[dict[str, Any]],
        idempotency_key: str,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-label-exchanges/prepare",
            payload={
                "authority_scope_id": scope,
                "exchange_kind": str(exchange_kind or "").strip().upper(),
                "sources": list(sources),
                "targets": list(targets),
            },
            idempotency_key=_normalize_identifier(
                idempotency_key, "idempotency_key"
            ),
        )
        return dict(result or {})

    @writer_sink("transfer_seal")
    def prepare_phs_reconciliation_label_exchange(
        self,
        reconciliation_id: str,
        *,
        authority_scope_id: str,
        action_ids: list[str],
        expected_reconciliation_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        normalized_reconciliation_id = _normalize_identifier(
            reconciliation_id, "reconciliation_id"
        )
        self.assert_authority(scope)
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-work-reconciliations/"
            f"{quote(normalized_reconciliation_id, safe='')}"
            "/label-exchange/prepare",
            payload={
                "authority_scope_id": scope,
                "action_ids": [
                    _normalize_identifier(value, "action_id")
                    for value in list(action_ids or [])
                ],
                "expected_reconciliation_version": int(
                    expected_reconciliation_version
                ),
            },
            idempotency_key=_normalize_identifier(
                idempotency_key, "idempotency_key"
            ),
        )
        return dict(result or {})

    def get_phs_label_exchange(
        self,
        exchange_id: str,
        *,
        authority_scope_id: str,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        query = urlencode({"authority_scope_id": scope})
        result = self._request(
            "GET",
            "/logistics/api/v1/phs-label-exchanges/"
            f"{quote(_normalize_identifier(exchange_id, 'exchange_id'), safe='')}"
            f"?{query}",
        )
        return dict(result or {})

    @writer_sink("transfer_seal")
    def request_phs_label_print(
        self,
        exchange_id: str,
        *,
        authority_scope_id: str,
        label_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-label-exchanges/"
            f"{quote(_normalize_identifier(exchange_id, 'exchange_id'), safe='')}"
            "/prints",
            payload={
                "authority_scope_id": scope,
                "label_id": _normalize_identifier(label_id, "label_id"),
            },
            idempotency_key=_normalize_identifier(
                idempotency_key, "idempotency_key"
            ),
        )
        return dict(result or {})

    @writer_sink("transfer_seal")
    def complete_phs_label_print(
        self,
        print_attempt_id: str,
        *,
        authority_scope_id: str,
        succeeded: bool,
        rendered_artifact_hash: str = "",
        proof: Mapping[str, Any] | None = None,
        error_code: str = "",
        error_message: str = "",
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        payload: dict[str, Any] = {
            "authority_scope_id": scope,
            "succeeded": bool(succeeded),
        }
        if succeeded:
            payload["rendered_artifact_hash"] = str(
                rendered_artifact_hash or ""
            ).strip().lower()
            payload["proof"] = dict(proof or {})
        else:
            payload["error_code"] = str(error_code or "").strip()
            payload["error_message"] = str(error_message or "").strip()
            if proof is not None:
                payload["proof"] = dict(proof)
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-label-print-attempts/"
            f"{quote(_normalize_identifier(print_attempt_id, 'print_attempt_id'), safe='')}"
            "/complete",
            payload=payload,
        )
        return dict(result or {})

    @writer_sink("transfer_seal")
    def activate_phs_label_exchange(
        self,
        exchange_id: str,
        *,
        authority_scope_id: str,
        expected_exchange_version: int,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-label-exchanges/"
            f"{quote(_normalize_identifier(exchange_id, 'exchange_id'), safe='')}"
            "/activate",
            payload={
                "authority_scope_id": scope,
                "expected_exchange_version": int(
                    expected_exchange_version
                ),
            },
        )
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

    @writer_sink("transfer_seal")
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

    @writer_sink("transfer_seal")
    def replace_bundle_members(self, context: Mapping[str, Any]) -> dict[str, Any]:
        scope_id = str(context.get("authority_scope_id") or "").strip()
        idempotency_key = str(context.get("idempotency_key") or "").strip()
        payload = context.get("payload")
        rotation_command = isinstance(payload, Mapping) and isinstance(
            payload.get("operation_lease_rotation"), Mapping
        )
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
            if rotation_command:
                raise
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
            if not rotation_command:
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
    local_completion_id: str = ""
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
    operation_lease_id: str = ""
    operation_lease_state: str = ""
    retryable: bool = False
    error_code: str = ""
    error_message: str = ""


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
            base_url=profile.base_url,
            token=profile.bearer_token,
            source_host_id=profile.source_host_id,
            device_id=profile.device_id,
            timeout_seconds=profile.timeout_seconds,
            session=session,
            authority_scope_id=profile.authority_scope,
            authority_epoch=profile.authority_epoch,
            authority_plane=profile.authority_plane,
            ledger_plane=profile.ledger_plane,
            plane_epoch=profile.plane_epoch,
            authoritative_required=required,
            isolated_qualification_authority_id=(
                profile.isolated_qualification_authority_id
            ),
            tls_ca_bundle_path=profile.tls_ca_bundle_path,
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
                base_url=legacy_fields["base_url"],
                token=legacy_fields["token"],
                source_host_id=legacy_fields["source_host_id"],
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

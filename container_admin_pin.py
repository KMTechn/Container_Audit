"""Machine-authenticated admin-pin.v1 client and durable local operation intents."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import requests

from direct_sync_runtime import load_credentials_from_json
from producer_runtime_client import SIGNATURE_VERSION, _utc_now_text, canonical_json
from storage_utils import atomic_write_json
from writer_session_fence import writer_sink


CONTRACT_VERSION = "admin-pin.v1"
FAILURE_MESSAGE = (
    "관리자 확인에 실패했습니다. ID와 PIN을 확인하세요. "
    "잠긴 경우 최상위 관리자에게 해제를 요청하세요."
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$")
_ACTIONS = frozenset({"CA.PRECHECK_HOLD", "CA.PAIR_RETRY", "CA.PAIR_HANDOFF", "CA.TRAY_HOLD"})
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class AdminPinError(RuntimeError):
    def __init__(self, code: str, *, unknown: bool = False):
        self.code = code
        self.unknown = unknown
        super().__init__(code)


def operator_message(code: str) -> str:
    if code in {"PIN_INVALID", "PIN_FORMAT_INVALID", "PIN_NOT_LINKED", "PROOF_REVOKED"}:
        return FAILURE_MESSAGE
    if code == "TARGET_CHANGED":
        return "대상 또는 작업자가 바뀌었습니다. 원본을 다시 조회하세요."
    if code in {"PIN_BUSY", "PIN_RATE_LIMITED"}:
        return "관리자 확인이 바쁩니다. 잠시 뒤 다시 확인하세요. 이 건만 보류할 수 있습니다."
    if code == "CENTRAL_ACTION_UNAVAILABLE":
        return "이 관리자 동작만 서버 확인을 사용할 수 없습니다. 이 건만 보류할 수 있습니다."
    return "관리자 확인 상태가 불확실합니다. 다시 확인하거나 이 건만 보류하고 다른 작업을 계속하세요."


def fingerprint(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def operator_local_id(value: str) -> str:
    normalized = unicodedata.normalize("NFC", str(value or "").strip())
    if not normalized:
        raise AdminPinError("OPERATOR_MISSING")
    if _SAFE_ID.fullmatch(normalized):
        return normalized
    raw = normalized.encode("utf-8")
    if len(raw) <= 62:
        return "wn:" + raw.hex()
    return "wh:" + hashlib.sha256(raw).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate JSON key")
        value[name] = item
    return value


def _valid_uuid(value: Any) -> bool:
    return type(value) is str and bool(_UUID.fullmatch(value))


class AdminPinClient:
    def __init__(self, credential_path: str | Path, *, transport: Any = None):
        credentials = load_credentials_from_json(credential_path)
        endpoint = urlsplit(str(credentials.endpoint_url))
        if endpoint.scheme.lower() != "https" or not endpoint.netloc or endpoint.username or endpoint.password:
            raise AdminPinError("VERIFY_UNAVAILABLE")
        self.origin = f"https://{endpoint.netloc}"
        self.credentials = credentials
        self.transport = transport
        self.session = requests.Session() if transport is None else None
        if self.session is not None:
            ca_bundle = str(getattr(credentials, "tls_ca_bundle_path", "") or "")
            if ca_bundle:
                self.session.trust_env = False
                self.session.verify = ca_bundle

    @writer_sink("admin_pin_network")
    def post(self, route: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        path = "/api/admin-pin/v1/" + route
        body = canonical_json(payload).encode("utf-8")
        if len(body) > 8192:
            raise AdminPinError("REQUEST_TOO_LARGE")
        timestamp, nonce = _utc_now_text(), uuid.uuid4().hex
        digest = hashlib.sha256(body).hexdigest()
        identity = self.credentials
        signed = "\n".join((
            SIGNATURE_VERSION, "POST", path, "", timestamp, nonce,
            str(identity.producer_id), str(identity.key_id), digest, digest,
            str(len(body)), "application/json",
        ))
        secret = identity.secret
        key = secret.encode("utf-8") if isinstance(secret, str) else secret
        headers = {
            "Content-Type": "application/json", "Accept": "application/json",
            "X-Producer-Id": str(identity.producer_id),
            "X-Producer-Key-Id": str(identity.key_id),
            "X-Producer-Timestamp": timestamp,
            "X-Producer-Nonce": nonce,
            "X-Producer-Signature": hmac.new(key, signed.encode("utf-8"), hashlib.sha256).hexdigest(),
        }
        try:
            if self.transport is not None:
                status, raw = self.transport(path, body, headers)
            else:
                response = self.session.post(
                    self.origin + path, data=body, headers=headers, timeout=10,
                    allow_redirects=False,
                )
                status, raw = response.status_code, response.content
        except Exception:
            raise AdminPinError("VERIFY_UNAVAILABLE", unknown=True) from None
        if type(status) is not int or len(raw) > 8192:
            raise AdminPinError("VERIFY_UNAVAILABLE", unknown=True)
        try:
            answer = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError, TypeError):
            raise AdminPinError("VERIFY_UNAVAILABLE", unknown=True) from None
        if not isinstance(answer, dict):
            raise AdminPinError("VERIFY_UNAVAILABLE", unknown=True)
        error = answer.get("error")
        code = error.get("code") if isinstance(error, dict) and type(error.get("code")) is str else ""
        if status >= 500:
            raise AdminPinError("PIN_BUSY" if code == "PIN_BUSY" else "VERIFY_UNAVAILABLE", unknown=True)
        if status != (201 if route == "verifications" else 200) or answer.get("ok") is not True:
            raise AdminPinError(code or "VERIFY_UNAVAILABLE", unknown=not bool(code))
        return answer

    @writer_sink("admin_pin_network")
    def verify(self, *, request_id: str, admin_id: str, pin: str, action: str,
               target: Mapping[str, str], operator: Mapping[str, str]) -> dict[str, Any]:
        if action not in _ACTIONS or not admin_id.strip() or not re.fullmatch(r"[0-9]{6}", pin):
            raise AdminPinError("PIN_FORMAT_INVALID")
        request = {"contract_version": CONTRACT_VERSION, "request_id": request_id,
                   "admin_id": admin_id, "pin": pin, "action": action,
                   "target": dict(target), "operator": dict(operator)}
        try:
            answer = self.post("verifications", request)
        except AdminPinError as exc:
            if exc.code != "PIN_BUSY":
                raise
            answer = self.post("verifications", request)
        if (not _valid_uuid(answer.get("verification_id"))
                or type(answer.get("proof")) is not str or not answer["proof"]
                or type(answer.get("issued_at")) is not int
                or type(answer.get("expires_at")) is not int
                or answer["issued_at"] <= 0 or answer["expires_at"] <= answer["issued_at"]
                or answer.get("admin_id") != admin_id or answer.get("action") != action
                or answer.get("target_fingerprint") != target["state_fingerprint"]
                or type(answer.get("device_ref")) is not str or not answer["device_ref"]
                or answer.get("request_id") != request_id):
            raise AdminPinError("VERIFY_UNAVAILABLE", unknown=True)
        return answer

    @staticmethod
    def _consumed(answer: Mapping[str, Any], verification_id: str, operation_key: str) -> bool:
        return (answer.get("verification_id") == verification_id
                and answer.get("operation_key") == operation_key
                and _valid_uuid(answer.get("redemption_id"))
                and type(answer.get("consumed_at")) is int
                and answer["consumed_at"] > 0)

    @writer_sink("admin_pin_network")
    def status(self, verification_id: str, operation_key: str) -> str:
        answer = self.post("redemptions/status", {
            "contract_version": CONTRACT_VERSION, "verification_id": verification_id,
            "operation_key": operation_key,
        })
        state = answer.get("status")
        if (answer.get("verification_id") != verification_id
                or answer.get("operation_key") != operation_key
                or type(state) is not str or state not in {"UNUSED", "CONSUMED", "EXPIRED"}
                or (state == "CONSUMED" and not self._consumed(answer, verification_id, operation_key))
                or (state != "CONSUMED" and ("redemption_id" in answer or "consumed_at" in answer))):
            raise AdminPinError("VERIFY_UNAVAILABLE", unknown=True)
        return state

    @writer_sink("admin_pin_network")
    def redeem(self, *, verification_id: str, proof: str, operation_key: str,
               action: str, target: Mapping[str, str], operator: Mapping[str, str]) -> None:
        request = {"contract_version": CONTRACT_VERSION, "verification_id": verification_id,
                   "proof": proof, "operation_key": operation_key, "action": action,
                   "target": dict(target), "operator": dict(operator)}
        try:
            answer = self.post("redemptions", request)
        except AdminPinError as exc:
            if not exc.unknown:
                raise
        else:
            if not self._consumed(answer, verification_id, operation_key):
                raise AdminPinError("VERIFY_UNAVAILABLE", unknown=True)
            return
        if self.status(verification_id, operation_key) == "CONSUMED":
            return
        raise AdminPinError("VERIFY_UNAVAILABLE", unknown=True)


class AdminPinIntentStore:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory)

    @staticmethod
    def _target_digest(target_id: str) -> str:
        if not _SAFE_ID.fullmatch(target_id):
            raise ValueError("invalid target ID")
        return (target_id[:16] if re.fullmatch(r"[0-9a-f]{64}", target_id)
                else hashlib.sha256(target_id.encode("utf-8")).hexdigest()[:16])

    def path(self, operation_key: str, target_id: str = "") -> Path:
        if not _valid_uuid(operation_key):
            raise ValueError("invalid operation key")
        operation_hex = uuid.UUID(operation_key).hex
        matches = tuple(self.directory.glob(f"admin-pin-*-{operation_hex}.json"))
        if len(matches) == 1:
            return matches[0]
        if matches:
            raise ValueError("duplicate admin PIN intent key")
        digest = self._target_digest(target_id)
        return self.directory / f"admin-pin-{digest}-{operation_hex}.json"

    def read(self, operation_key: str) -> dict[str, Any]:
        value = json.loads(self.path(operation_key).read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(value, dict) or value.get("operation_key") != operation_key:
            raise ValueError("admin PIN intent differs")
        return value

    def pending(self, action: str, target_id: str) -> list[dict[str, Any]]:
        rows = []
        digest = self._target_digest(target_id)
        for path in sorted(self.directory.glob(f"admin-pin-{digest}-*.json")) if self.directory.exists() else ():
            row = self.read(str(uuid.UUID(hex=path.stem[-32:])))
            if row.get("target", {}).get("id") != target_id:
                raise ValueError("admin PIN target differs from bound evidence")
            if row.get("action") == action and row.get("state") not in {"APPLIED", "REJECTED", "SUPERSEDED"}:
                rows.append(row)
        return rows

    def list_pending(self) -> list[dict[str, Any]]:
        rows = []
        for path in sorted(self.directory.glob("admin-pin-*.json")) if self.directory.exists() else ():
            row = self.read(str(uuid.UUID(hex=path.stem[-32:])))
            if row.get("state") not in {"APPLIED", "REJECTED", "SUPERSEDED"}:
                rows.append(row)
        return rows

    @writer_sink("admin_pin_intent")
    def write(self, intent: Mapping[str, Any]) -> dict[str, Any]:
        if "pin" in intent or "proof" in intent:
            raise ValueError("secret cannot be stored in an intent")
        path = self.path(str(intent["operation_key"]), str(intent["target"]["id"]))
        atomic_write_json(path, dict(intent), trailing_newline=True)
        readback = self.read(str(intent["operation_key"]))
        if readback != dict(intent):
            raise OSError("admin PIN intent readback differs")
        return readback

    def transition(self, intent: Mapping[str, Any], state: str, *, reason: str = "") -> dict[str, Any]:
        updated = dict(intent, state=state, reason=reason)
        return self.write(updated)

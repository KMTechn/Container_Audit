"""Pinned verification and durable state for terminal operation leases.

The server is the only signer.  This module keeps public keys and signed
artifacts on the client, verifies every terminal/device/snapshot binding, and
records the local completion/outbox transition before a caller may report
success.  It deliberately has no GUI or network dependency.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


JWS_ALGORITHM = "ES256"
JWS_TYPE = "terminal-operation-lease+jws"
LEASE_CONTRACT_VERSION = "terminal-operation-lease-v1"
ARTIFACT_CONTRACT_VERSION = "terminal-operation-lease-artifact-v1"
KEYRING_CONTRACT_VERSION = "terminal-operation-lease-keyring-v1"
KEYRING_STORE_CONTRACT_VERSION = "terminal-operation-lease-keyring-store-v1"
CONSUME_CONTRACT_VERSION = "terminal-operation-lease-consume-v1"
STORE_SCHEMA_VERSION = "container-terminal-operation-lease-store-v1"
CONTAINER_PROGRAM = "Container_Audit"
TRANSFER_OPERATION = "SEAL_TRANSFER_BUNDLE"

ISSUE_PENDING = "PENDING"
ISSUE_PREFETCHED = "PREFETCHED"
ISSUE_LOCAL_COMPLETED = "LOCAL_COMPLETED"
ISSUE_OPERATOR_REVIEW = "OPERATOR_REVIEW"
ISSUE_EXPIRED_UNRECONCILED = "EXPIRED_UNRECONCILED"
ISSUE_RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
ISSUE_CONSUMED_UNACKED = "CONSUMED_UNACKED"
ISSUE_ACKED = "ACKED"
ISSUE_RELEASED = "RELEASED"
UNRESOLVED_ISSUE_STATUSES = frozenset(
    {
        ISSUE_PENDING,
        ISSUE_PREFETCHED,
        ISSUE_LOCAL_COMPLETED,
        ISSUE_OPERATOR_REVIEW,
        ISSUE_EXPIRED_UNRECONCILED,
        ISSUE_RECONCILIATION_REQUIRED,
        ISSUE_CONSUMED_UNACKED,
    }
)
TERMINAL_ISSUE_STATUSES = frozenset({ISSUE_ACKED, ISSUE_RELEASED})
SERVER_NONACTIVE_STATUSES = frozenset(
    {
        "EXPIRED_UNRECONCILED",
        "RECONCILIATION_REQUIRED",
        "CONSUMED",
        "RELEASED",
    }
)

MAX_TOKEN_BYTES = 131_072
MAX_PAYLOAD_BYTES = 96_000
MAX_KEYRING_BYTES = 32_768
MAX_ARTIFACT_BYTES = 512_000
MAX_PUBLIC_KEYS = 8
MIN_LEASE_SECONDS = 60
MAX_LEASE_SECONDS = 24 * 60 * 60
_P256_BYTES = 32
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+")
_HASH64_RE = re.compile(r"[0-9a-f]{64}")
_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

LEASE_CLAIM_KEYS = frozenset(
    {
        "contract_version",
        "lease_id",
        "site_id",
        "program",
        "device_id",
        "source_host_id",
        "authority_scope_id",
        "ledger_plane",
        "plane_epoch",
        "operation",
        "resource_id",
        "physical_label_id",
        "physical_qr_sha256",
        "item_id",
        "quantity",
        "member_count",
        "membership_hash",
        "expected_versions",
        "issued_at",
        "expires_at",
        "fence",
        "snapshot_hash",
    }
)
LEASE_BINDING_KEYS = frozenset(
    LEASE_CLAIM_KEYS
    - {"contract_version", "lease_id", "issued_at", "expires_at", "fence"}
)
ARTIFACT_KEYS = frozenset(
    {
        "contract_version",
        "lease_id",
        "status",
        "replayed",
        "token",
        "kid",
        "expires_at",
        "fence",
        "snapshot_hash",
        "operation_snapshot",
        "keyring",
    }
)
KEYRING_KEYS = frozenset(
    {"contract_version", "site_id", "current_kid", "keys"}
)
KEYRING_ENTRY_KEYS = frozenset(
    {"kid", "status", "public_jwk", "thumbprint"}
)
PUBLIC_JWK_KEYS = frozenset({"kty", "crv", "x", "y"})


class OperationLeaseError(ValueError):
    """Typed internal diagnostic; callers must render operator-safe copy."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = str(code)
        self.message = str(message)
        self.retryable = bool(retryable)


def _error(
    code: str,
    message: str,
    *,
    retryable: bool = False,
) -> OperationLeaseError:
    return OperationLeaseError(code, message, retryable=retryable)


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _error(
            "OPERATION_LEASE_JSON_INVALID",
            "value cannot be represented as canonical JSON",
        ) from exc


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def physical_qr_sha256(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise _error(
            "OPERATION_LEASE_BINDING_INVALID",
            "physical QR payload is required",
        )
    if len(value.encode("utf-8")) > 4_096:
        raise _error(
            "OPERATION_LEASE_BINDING_INVALID",
            "physical QR payload exceeds its bound",
        )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def utc_text(value: datetime | None = None) -> str:
    instant = value or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise _error(
            "OPERATION_LEASE_TIME_INVALID",
            "time must be timezone-aware",
        )
    return instant.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def parse_utc_text(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise _error(
            "OPERATION_LEASE_TIME_INVALID",
            f"{field} must be exact second-resolution UTC",
        )
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise _error(
            "OPERATION_LEASE_TIME_INVALID",
            f"{field} is not a valid UTC instant",
        ) from exc


def _bounded_text(value: Any, *, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise _error("OPERATION_LEASE_FIELD_INVALID", f"{field} must be text")
    if (
        not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise _error(
            "OPERATION_LEASE_FIELD_INVALID",
            f"{field} is empty, non-canonical, or exceeds its bound",
        )
    return value


def _hash64(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _HASH64_RE.fullmatch(value) is None:
        raise _error(
            "OPERATION_LEASE_FIELD_INVALID",
            f"{field} must be a lowercase SHA-256 digest",
        )
    return value


def _positive_int(value: Any, *, field: str, maximum: int = 2_147_483_647) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise _error(
            "OPERATION_LEASE_FIELD_INVALID",
            f"{field} must be a positive bounded integer",
        )
    return value


def _expected_versions(value: Any) -> dict[str, int]:
    if not isinstance(value, dict) or not value or len(value) > 256:
        raise _error(
            "OPERATION_LEASE_FIELD_INVALID",
            "expected_versions must be a non-empty bounded object",
        )
    result: dict[str, int] = {}
    for key, version in value.items():
        normalized_key = _bounded_text(
            key,
            field="expected_versions key",
            maximum=256,
        )
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or not 0 <= version <= 2_147_483_647
        ):
            raise _error(
                "OPERATION_LEASE_FIELD_INVALID",
                "expected_versions values must be bounded non-negative integers",
            )
        result[normalized_key] = version
    return result


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: Any, *, field: str, maximum: int) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or _BASE64URL_RE.fullmatch(value) is None
    ):
        raise _error(
            "OPERATION_LEASE_JWS_INVALID",
            f"{field} is not canonical bounded base64url",
        )
    try:
        decoded = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, base64.binascii.Error) as exc:
        raise _error(
            "OPERATION_LEASE_JWS_INVALID",
            f"{field} is not base64url",
        ) from exc
    if _b64url_encode(decoded) != value:
        raise _error(
            "OPERATION_LEASE_JWS_INVALID",
            f"{field} is not canonical base64url",
        )
    return decoded


def normalize_public_jwk(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != PUBLIC_JWK_KEYS:
        raise _error(
            "OPERATION_LEASE_KEY_INVALID",
            "public JWK must contain exactly kty, crv, x, and y",
        )
    if value.get("kty") != "EC" or value.get("crv") != "P-256":
        raise _error(
            "OPERATION_LEASE_KEY_INVALID",
            "public JWK must be an EC P-256 key",
        )
    x = _b64url_decode(value.get("x"), field="public_jwk.x", maximum=64)
    y = _b64url_decode(value.get("y"), field="public_jwk.y", maximum=64)
    if len(x) != _P256_BYTES or len(y) != _P256_BYTES:
        raise _error(
            "OPERATION_LEASE_KEY_INVALID",
            "public JWK coordinates must be 32 bytes",
        )
    try:
        ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"),
            int.from_bytes(y, "big"),
            ec.SECP256R1(),
        ).public_key()
    except ValueError as exc:
        raise _error(
            "OPERATION_LEASE_KEY_INVALID",
            "public JWK is not a point on P-256",
        ) from exc
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": str(value["x"]),
        "y": str(value["y"]),
    }


def jwk_thumbprint(value: Any) -> str:
    normalized = normalize_public_jwk(value)
    return _b64url_encode(
        hashlib.sha256(canonical_json_bytes(normalized)).digest()
    )


def _public_key(value: Any) -> ec.EllipticCurvePublicKey:
    normalized = normalize_public_jwk(value)
    x = _b64url_decode(normalized["x"], field="public_jwk.x", maximum=64)
    y = _b64url_decode(normalized["y"], field="public_jwk.y", maximum=64)
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"),
        int.from_bytes(y, "big"),
        ec.SECP256R1(),
    ).public_key()


def _der_low_s(raw: bytes) -> bytes:
    if len(raw) != 2 * _P256_BYTES:
        raise _error(
            "OPERATION_LEASE_SIGNATURE_INVALID",
            "ES256 signature must contain exactly 64 raw bytes",
        )
    r = int.from_bytes(raw[:_P256_BYTES], "big")
    s = int.from_bytes(raw[_P256_BYTES:], "big")
    if (
        not 1 <= r < _P256_ORDER
        or not 1 <= s < _P256_ORDER
        or s > _P256_ORDER // 2
    ):
        raise _error(
            "OPERATION_LEASE_SIGNATURE_INVALID",
            "ES256 signature must use in-range low-S components",
        )
    return encode_dss_signature(r, s)


def normalize_keyring(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != KEYRING_KEYS:
        raise _error(
            "OPERATION_LEASE_KEYRING_INVALID",
            "keyring does not contain the exact v1 fields",
        )
    if value.get("contract_version") != KEYRING_CONTRACT_VERSION:
        raise _error(
            "OPERATION_LEASE_KEYRING_INVALID",
            "keyring contract_version is invalid",
        )
    site_id = _bounded_text(value.get("site_id"), field="site_id", maximum=128)
    current_kid = _bounded_text(
        value.get("current_kid"), field="current_kid", maximum=128
    )
    raw_entries = value.get("keys")
    if not isinstance(raw_entries, list) or not 1 <= len(raw_entries) <= MAX_PUBLIC_KEYS:
        raise _error(
            "OPERATION_LEASE_KEYRING_INVALID",
            "keyring must contain a bounded non-empty keys list",
        )
    entries: list[dict[str, Any]] = []
    kids: set[str] = set()
    materials: set[str] = set()
    current: list[str] = []
    for raw in raw_entries:
        if not isinstance(raw, dict) or set(raw) != KEYRING_ENTRY_KEYS:
            raise _error(
                "OPERATION_LEASE_KEYRING_INVALID",
                "keyring entry does not contain the exact v1 fields",
            )
        kid = _bounded_text(raw.get("kid"), field="kid", maximum=128)
        status = raw.get("status")
        if status not in {"current", "retained"}:
            raise _error(
                "OPERATION_LEASE_KEYRING_INVALID",
                "key status must be current or retained",
            )
        jwk = normalize_public_jwk(raw.get("public_jwk"))
        thumbprint = jwk_thumbprint(jwk)
        if raw.get("thumbprint") != thumbprint:
            raise _error(
                "OPERATION_LEASE_KEYRING_INVALID",
                "key thumbprint does not match public key material",
            )
        if kid in kids or thumbprint in materials:
            raise _error(
                "OPERATION_LEASE_KEYRING_INVALID",
                "keyring contains duplicate identity or key material",
            )
        kids.add(kid)
        materials.add(thumbprint)
        if status == "current":
            current.append(kid)
        entries.append(
            {
                "kid": kid,
                "status": status,
                "public_jwk": jwk,
                "thumbprint": thumbprint,
            }
        )
    if current != [current_kid]:
        raise _error(
            "OPERATION_LEASE_KEYRING_INVALID",
            "keyring must identify exactly one current key",
        )
    return {
        "contract_version": KEYRING_CONTRACT_VERSION,
        "site_id": site_id,
        "current_kid": current_kid,
        "keys": entries,
    }


def validate_claims(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != LEASE_CLAIM_KEYS:
        raise _error(
            "OPERATION_LEASE_PAYLOAD_INVALID",
            "signed claims do not contain the exact v1 fields",
        )
    if value.get("contract_version") != LEASE_CONTRACT_VERSION:
        raise _error(
            "OPERATION_LEASE_PAYLOAD_INVALID",
            "signed claim contract_version is invalid",
        )
    result = {
        "contract_version": LEASE_CONTRACT_VERSION,
        "lease_id": _bounded_text(value["lease_id"], field="lease_id", maximum=128),
        "site_id": _bounded_text(value["site_id"], field="site_id", maximum=128),
        "program": _bounded_text(value["program"], field="program", maximum=64),
        "device_id": _bounded_text(value["device_id"], field="device_id", maximum=128),
        "source_host_id": _bounded_text(
            value["source_host_id"], field="source_host_id", maximum=128
        ),
        "authority_scope_id": _bounded_text(
            value["authority_scope_id"], field="authority_scope_id"
        ),
        "ledger_plane": _bounded_text(
            value["ledger_plane"], field="ledger_plane", maximum=64
        ),
        "plane_epoch": _positive_int(value["plane_epoch"], field="plane_epoch"),
        "operation": _bounded_text(value["operation"], field="operation", maximum=64),
        "resource_id": _bounded_text(value["resource_id"], field="resource_id"),
        "physical_label_id": _bounded_text(
            value["physical_label_id"], field="physical_label_id"
        ),
        "physical_qr_sha256": _hash64(
            value["physical_qr_sha256"], field="physical_qr_sha256"
        ),
        "item_id": _bounded_text(value["item_id"], field="item_id", maximum=128),
        "quantity": _positive_int(value["quantity"], field="quantity", maximum=10_000_000),
        "member_count": _positive_int(
            value["member_count"], field="member_count", maximum=10_000_000
        ),
        "membership_hash": _hash64(value["membership_hash"], field="membership_hash"),
        "expected_versions": _expected_versions(value["expected_versions"]),
        "issued_at": utc_text(parse_utc_text(value["issued_at"], field="issued_at")),
        "expires_at": utc_text(parse_utc_text(value["expires_at"], field="expires_at")),
        "fence": _positive_int(value["fence"], field="fence"),
        "snapshot_hash": _hash64(value["snapshot_hash"], field="snapshot_hash"),
    }
    if result["program"] != CONTAINER_PROGRAM or result["operation"] != TRANSFER_OPERATION:
        raise _error(
            "OPERATION_LEASE_PROGRAM_MISMATCH",
            "signed lease does not belong to Container transfer",
        )
    if result["ledger_plane"] != "AUTHORITATIVE":
        raise _error(
            "OPERATION_LEASE_AUTHORITY_MISMATCH",
            "offline terminal lease requires AUTHORITATIVE ledger plane",
        )
    if result["quantity"] != result["member_count"]:
        raise _error(
            "OPERATION_LEASE_MEMBERSHIP_MISMATCH",
            "signed quantity and member_count differ",
        )
    issued_at = parse_utc_text(result["issued_at"], field="issued_at")
    expires_at = parse_utc_text(result["expires_at"], field="expires_at")
    duration = int((expires_at - issued_at).total_seconds())
    if not MIN_LEASE_SECONDS <= duration <= MAX_LEASE_SECONDS:
        raise _error(
            "OPERATION_LEASE_DURATION_INVALID",
            "signed lease duration is outside the v1 bounds",
        )
    return result


def verify_jws(
    token: str,
    *,
    public_jwk: Mapping[str, Any],
    expected_kid: str,
) -> dict[str, Any]:
    if (
        not isinstance(token, str)
        or not token
        or len(token.encode("utf-8")) > MAX_TOKEN_BYTES
        or token.count(".") != 2
    ):
        raise _error("OPERATION_LEASE_JWS_INVALID", "lease token is invalid")
    parts = token.split(".")
    header_raw = _b64url_decode(parts[0], field="protected header", maximum=2_048)
    payload_raw = _b64url_decode(
        parts[1], field="lease payload", maximum=MAX_PAYLOAD_BYTES * 2
    )
    if len(payload_raw) > MAX_PAYLOAD_BYTES:
        raise _error("OPERATION_LEASE_JWS_INVALID", "lease payload is too large")
    try:
        header = json.loads(header_raw.decode("utf-8"))
        payload = json.loads(payload_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error("OPERATION_LEASE_JWS_INVALID", "lease JWS JSON is invalid") from exc
    expected_header = {
        "alg": JWS_ALGORITHM,
        "kid": _bounded_text(expected_kid, field="kid", maximum=128),
        "typ": JWS_TYPE,
    }
    if (
        header != expected_header
        or canonical_json_bytes(header) != header_raw
        or not isinstance(payload, dict)
        or canonical_json_bytes(payload) != payload_raw
    ):
        raise _error(
            "OPERATION_LEASE_JWS_INVALID",
            "lease protected content is not exact canonical v1 JSON",
        )
    signature = _b64url_decode(parts[2], field="signature", maximum=128)
    try:
        _public_key(public_jwk).verify(
            _der_low_s(signature),
            f"{parts[0]}.{parts[1]}".encode("ascii"),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise _error(
            "OPERATION_LEASE_SIGNATURE_INVALID",
            "lease signature is invalid",
        ) from exc
    return validate_claims(payload)


def validate_artifact(
    value: Any,
    *,
    expected: Mapping[str, Any],
    now: datetime | None = None,
    allow_expired: bool = False,
    allowed_statuses: frozenset[str] = frozenset({"ACTIVE"}),
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != ARTIFACT_KEYS:
        raise _error(
            "OPERATION_LEASE_ARTIFACT_INVALID",
            "artifact does not contain the exact v1 fields",
        )
    if value.get("contract_version") != ARTIFACT_CONTRACT_VERSION:
        raise _error(
            "OPERATION_LEASE_ARTIFACT_INVALID",
            "artifact contract_version is invalid",
        )
    if (
        not isinstance(allowed_statuses, frozenset)
        or not allowed_statuses
        or not allowed_statuses.issubset(
            frozenset({"ACTIVE", *SERVER_NONACTIVE_STATUSES})
        )
        or value.get("status") not in allowed_statuses
        or not isinstance(value.get("replayed"), bool)
    ):
        raise _error(
            "OPERATION_LEASE_NOT_ACTIVE",
            "artifact does not have an allowed authenticated status",
        )
    keyring = normalize_keyring(value.get("keyring"))
    kid = _bounded_text(value.get("kid"), field="kid", maximum=128)
    pinned = {
        entry["kid"]: entry["public_jwk"] for entry in keyring["keys"]
    }
    if kid not in pinned:
        raise _error(
            "OPERATION_LEASE_KEY_NOT_PINNED",
            "artifact signing kid is absent from its public keyring",
        )
    claims = verify_jws(
        value.get("token"),
        public_jwk=pinned[kid],
        expected_kid=kid,
    )
    snapshot = value.get("operation_snapshot")
    if not isinstance(snapshot, dict) or len(canonical_json_bytes(snapshot)) > MAX_ARTIFACT_BYTES:
        raise _error(
            "OPERATION_LEASE_SNAPSHOT_INVALID",
            "operation snapshot is not a bounded object",
        )
    snapshot_hash = canonical_hash(snapshot)
    artifact_fields_match = (
        value.get("lease_id") == claims["lease_id"]
        and value.get("expires_at") == claims["expires_at"]
        and value.get("fence") == claims["fence"]
        and value.get("snapshot_hash") == claims["snapshot_hash"]
        and snapshot_hash == claims["snapshot_hash"]
        and keyring["site_id"] == claims["site_id"]
    )
    if not artifact_fields_match:
        raise _error(
            "OPERATION_LEASE_ARTIFACT_MISMATCH",
            "artifact envelope differs from signed claims or snapshot",
        )
    if not isinstance(expected, Mapping) or set(expected) != LEASE_BINDING_KEYS:
        raise _error(
            "OPERATION_LEASE_BINDING_INVALID",
            "expected context must contain every exact lease binding",
        )
    actual_binding = {key: claims[key] for key in LEASE_BINDING_KEYS}
    try:
        binding_matches = canonical_json_bytes(actual_binding) == canonical_json_bytes(
            dict(expected)
        )
    except OperationLeaseError:
        binding_matches = False
    if not binding_matches:
        raise _error(
            "OPERATION_LEASE_BINDING_MISMATCH",
            "signed lease does not match this terminal and physical snapshot",
        )
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise _error("OPERATION_LEASE_TIME_INVALID", "verification time must be aware")
    instant = instant.astimezone(timezone.utc)
    issued_at = parse_utc_text(claims["issued_at"], field="issued_at")
    expires_at = parse_utc_text(claims["expires_at"], field="expires_at")
    if instant < issued_at:
        raise _error(
            "OPERATION_LEASE_NOT_YET_VALID",
            "operation lease is not valid before issued_at",
        )
    if not allow_expired and instant >= expires_at:
        raise _error("OPERATION_LEASE_EXPIRED", "operation lease has expired")
    normalized = {
        "contract_version": ARTIFACT_CONTRACT_VERSION,
        "lease_id": claims["lease_id"],
        "status": str(value["status"]),
        "replayed": value["replayed"],
        "token": str(value["token"]),
        "kid": kid,
        "expires_at": claims["expires_at"],
        "fence": claims["fence"],
        "snapshot_hash": claims["snapshot_hash"],
        "operation_snapshot": json.loads(
            canonical_json_bytes(snapshot).decode("utf-8")
        ),
        "keyring": keyring,
    }
    return normalized, claims


class PinnedOperationLeaseKeyring:
    """Public-only authenticated TOFU pins with rotation history."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        raw = Path(path).expanduser()
        if not raw.name or raw.is_symlink():
            raise _error(
                "OPERATION_LEASE_KEYRING_PATH_INVALID",
                "keyring store path is invalid",
            )
        self.path = Path(os.path.abspath(os.fspath(raw)))

    def _load(self, *, required: bool) -> dict[str, Any] | None:
        if self.path.is_symlink():
            raise _error(
                "OPERATION_LEASE_KEYRING_PATH_INVALID",
                "keyring store must not be a symbolic link",
            )
        try:
            metadata = self.path.stat()
        except FileNotFoundError:
            if required:
                raise _error(
                    "OPERATION_LEASE_KEYRING_NOT_BOOTSTRAPPED",
                    "no authenticated public keyring is pinned",
                )
            return None
        except OSError as exc:
            raise _error(
                "OPERATION_LEASE_KEYRING_UNAVAILABLE",
                "pinned public keyring cannot be inspected",
            ) from exc
        if not self.path.is_file() or not 1 <= metadata.st_size <= MAX_KEYRING_BYTES:
            raise _error(
                "OPERATION_LEASE_KEYRING_INVALID",
                "pinned public keyring is empty, oversized, or not a file",
            )
        try:
            raw = self.path.read_bytes()
            stored = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _error(
                "OPERATION_LEASE_KEYRING_INVALID",
                "pinned public keyring cannot be parsed",
            ) from exc
        if canonical_json_bytes(stored) != raw:
            raise _error(
                "OPERATION_LEASE_KEYRING_INVALID",
                "pinned public keyring is not canonical JSON",
            )
        if (
            not isinstance(stored, dict)
            or set(stored) != {"contract_version", "program", "keyring"}
            or stored.get("contract_version") != KEYRING_STORE_CONTRACT_VERSION
            or stored.get("program") != CONTAINER_PROGRAM
        ):
            raise _error(
                "OPERATION_LEASE_KEYRING_INVALID",
                "pinned public keyring store contract is invalid",
            )
        return normalize_keyring(stored.get("keyring"))

    def _atomic_write(self, keyring: Mapping[str, Any]) -> None:
        document = {
            "contract_version": KEYRING_STORE_CONTRACT_VERSION,
            "program": CONTAINER_PROGRAM,
            "keyring": normalize_keyring(dict(keyring)),
        }
        raw = canonical_json_bytes(document)
        if len(raw) > MAX_KEYRING_BYTES:
            raise _error(
                "OPERATION_LEASE_KEYRING_INVALID",
                "pinned keyring exceeds its byte bound",
            )
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise _error(
                "OPERATION_LEASE_KEYRING_PATH_INVALID",
                "keyring store must not be a symbolic link",
            )
        descriptor = -1
        temporary = ""
        try:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=str(self.path.parent),
            )
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            temporary = ""
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            raise _error(
                "OPERATION_LEASE_KEYRING_UNAVAILABLE",
                "public keyring could not be stored atomically",
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def bootstrap_authenticated(
        self,
        value: Mapping[str, Any],
        *,
        authenticated_online: bool,
    ) -> dict[str, Any]:
        if authenticated_online is not True:
            raise _error(
                "OPERATION_LEASE_BOOTSTRAP_UNAUTHENTICATED",
                "public keys may only be pinned from authenticated HTTPS",
            )
        incoming = normalize_keyring(dict(value))
        existing = self._load(required=False)
        if existing is not None and existing["site_id"] != incoming["site_id"]:
            raise _error(
                "OPERATION_LEASE_KEYRING_BINDING_MISMATCH",
                "authenticated site_id differs from the pinned installation",
            )
        entries = {
            entry["kid"]: entry for entry in (existing or {}).get("keys", [])
        }
        material_to_kid = {
            entry["thumbprint"]: entry["kid"] for entry in entries.values()
        }
        for entry in incoming["keys"]:
            pinned = entries.get(entry["kid"])
            if pinned is not None and pinned["public_jwk"] != entry["public_jwk"]:
                raise _error(
                    "OPERATION_LEASE_KID_REUSE_REJECTED",
                    "pinned kid cannot be rebound to different key material",
                )
            other = material_to_kid.get(entry["thumbprint"])
            if other is not None and other != entry["kid"]:
                raise _error(
                    "OPERATION_LEASE_KEY_ALIAS_REJECTED",
                    "pinned key material cannot use another kid",
                )
            entries[entry["kid"]] = entry
            material_to_kid[entry["thumbprint"]] = entry["kid"]
        if len(entries) > MAX_PUBLIC_KEYS:
            raise _error(
                "OPERATION_LEASE_KEYRING_CAPACITY_EXCEEDED",
                "pinned key history exceeds its bound",
            )
        current_kid = incoming["current_kid"]
        ordered = [current_kid, *sorted(key for key in entries if key != current_kid)]
        merged = {
            "contract_version": KEYRING_CONTRACT_VERSION,
            "site_id": incoming["site_id"],
            "current_kid": current_kid,
            "keys": [
                {
                    **entries[kid],
                    "status": "current" if kid == current_kid else "retained",
                }
                for kid in ordered
            ],
        }
        self._atomic_write(merged)
        return normalize_keyring(merged)

    def verify(
        self,
        artifact: Mapping[str, Any],
        *,
        expected: Mapping[str, Any],
        now: datetime | None = None,
        allow_expired: bool = False,
        allowed_statuses: frozenset[str] = frozenset({"ACTIVE"}),
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        normalized, claims = validate_artifact(
            dict(artifact),
            expected=expected,
            now=now,
            allow_expired=allow_expired,
            allowed_statuses=allowed_statuses,
        )
        pinned = self._load(required=True)
        assert pinned is not None
        if pinned["site_id"] != claims["site_id"]:
            raise _error(
                "OPERATION_LEASE_KEYRING_BINDING_MISMATCH",
                "lease site differs from pinned keyring",
            )
        keys = {entry["kid"]: entry for entry in pinned["keys"]}
        selected = keys.get(normalized["kid"])
        if selected is None:
            raise _error(
                "OPERATION_LEASE_KEY_NOT_PINNED",
                "lease signing key is not pinned",
            )
        claims = verify_jws(
            normalized["token"],
            public_jwk=selected["public_jwk"],
            expected_kid=selected["kid"],
        )
        return normalized, claims


class OperationLeaseStore:
    """Append-only client evidence sharing the transfer-seal SQLite file."""

    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.db_path), timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS terminal_operation_lease_meta (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    schema_version TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS terminal_operation_lease_issue_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    resource_key TEXT NOT NULL CHECK(length(resource_key)=64),
                    device_id TEXT NOT NULL,
                    source_host_id TEXT NOT NULL,
                    authority_scope_id TEXT NOT NULL,
                    physical_qr_sha256 TEXT NOT NULL
                        CHECK(length(physical_qr_sha256)=64),
                    issue_idempotency_key TEXT NOT NULL UNIQUE,
                    issue_request_json TEXT NOT NULL,
                    issue_request_hash TEXT NOT NULL
                        CHECK(length(issue_request_hash)=64),
                    status TEXT NOT NULL CHECK(status IN (
                        'PENDING','PREFETCHED','LOCAL_COMPLETED',
                        'OPERATOR_REVIEW','EXPIRED_UNRECONCILED',
                        'RECONCILIATION_REQUIRED','CONSUMED_UNACKED',
                        'ACKED','RELEASED'
                    )),
                    lease_id TEXT UNIQUE,
                    terminal_evidence_json TEXT,
                    terminal_evidence_hash TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS
                    uq_terminal_operation_lease_unresolved_resource
                ON terminal_operation_lease_issue_attempts(resource_key)
                WHERE status IN (
                    'PENDING','PREFETCHED','LOCAL_COMPLETED',
                    'OPERATOR_REVIEW','EXPIRED_UNRECONCILED',
                    'RECONCILIATION_REQUIRED','CONSUMED_UNACKED'
                );
                CREATE TABLE IF NOT EXISTS terminal_operation_lease_artifacts (
                    lease_id TEXT PRIMARY KEY,
                    issue_idempotency_key TEXT NOT NULL UNIQUE,
                    issue_request_json TEXT NOT NULL,
                    issue_request_hash TEXT NOT NULL CHECK(length(issue_request_hash)=64),
                    artifact_json TEXT NOT NULL,
                    artifact_hash TEXT NOT NULL CHECK(length(artifact_hash)=64),
                    token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64),
                    claims_json TEXT NOT NULL,
                    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
                    expires_at TEXT NOT NULL,
                    fence INTEGER NOT NULL CHECK(fence>=1),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS terminal_operation_lease_completions (
                    operation_result_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL UNIQUE
                        REFERENCES terminal_operation_lease_artifacts(lease_id),
                    transfer_intent_id TEXT NOT NULL UNIQUE,
                    transfer_idempotency_key TEXT NOT NULL UNIQUE,
                    operation_completed_at TEXT NOT NULL,
                    completion_json TEXT NOT NULL,
                    completion_hash TEXT NOT NULL CHECK(length(completion_hash)=64),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS terminal_operation_lease_outbox (
                    outbox_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL UNIQUE
                        REFERENCES terminal_operation_lease_artifacts(lease_id),
                    operation_result_id TEXT NOT NULL UNIQUE
                        REFERENCES terminal_operation_lease_completions(operation_result_id),
                    transfer_idempotency_key TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS terminal_operation_lease_receipts (
                    lease_id TEXT PRIMARY KEY
                        REFERENCES terminal_operation_lease_artifacts(lease_id),
                    operation_result_id TEXT NOT NULL UNIQUE,
                    transfer_intent_id TEXT NOT NULL UNIQUE,
                    receipt_json TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL CHECK(length(receipt_hash)=64),
                    acked_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS terminal_operation_lease_reviews (
                    lease_id TEXT PRIMARY KEY
                        REFERENCES terminal_operation_lease_artifacts(lease_id),
                    transfer_intent_id TEXT NOT NULL UNIQUE,
                    error_code TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL CHECK(length(evidence_hash)=64),
                    created_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_artifact_update
                BEFORE UPDATE ON terminal_operation_lease_artifacts
                BEGIN SELECT RAISE(ABORT, 'terminal operation lease artifact is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_artifact_delete
                BEFORE DELETE ON terminal_operation_lease_artifacts
                BEGIN SELECT RAISE(ABORT, 'terminal operation lease artifact is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_completion_update
                BEFORE UPDATE ON terminal_operation_lease_completions
                BEGIN SELECT RAISE(ABORT, 'terminal operation completion is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_completion_delete
                BEFORE DELETE ON terminal_operation_lease_completions
                BEGIN SELECT RAISE(ABORT, 'terminal operation completion is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_outbox_update
                BEFORE UPDATE ON terminal_operation_lease_outbox
                BEGIN SELECT RAISE(ABORT, 'terminal operation outbox is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_outbox_delete
                BEFORE DELETE ON terminal_operation_lease_outbox
                BEGIN SELECT RAISE(ABORT, 'terminal operation outbox is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_receipt_update
                BEFORE UPDATE ON terminal_operation_lease_receipts
                BEGIN SELECT RAISE(ABORT, 'terminal operation receipt is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_receipt_delete
                BEFORE DELETE ON terminal_operation_lease_receipts
                BEGIN SELECT RAISE(ABORT, 'terminal operation receipt is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_review_update
                BEFORE UPDATE ON terminal_operation_lease_reviews
                BEGIN SELECT RAISE(ABORT, 'terminal operation review is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_review_delete
                BEFORE DELETE ON terminal_operation_lease_reviews
                BEGIN SELECT RAISE(ABORT, 'terminal operation review is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_issue_delete
                BEFORE DELETE ON terminal_operation_lease_issue_attempts
                BEGIN SELECT RAISE(ABORT, 'terminal operation issue attempt is durable history'); END;
                CREATE TRIGGER IF NOT EXISTS trg_terminal_lease_issue_immutable
                BEFORE UPDATE ON terminal_operation_lease_issue_attempts
                WHEN NEW.attempt_id != OLD.attempt_id
                  OR NEW.resource_key != OLD.resource_key
                  OR NEW.device_id != OLD.device_id
                  OR NEW.source_host_id != OLD.source_host_id
                  OR NEW.authority_scope_id != OLD.authority_scope_id
                  OR NEW.physical_qr_sha256 != OLD.physical_qr_sha256
                  OR NEW.issue_idempotency_key != OLD.issue_idempotency_key
                  OR NEW.issue_request_json != OLD.issue_request_json
                  OR NEW.issue_request_hash != OLD.issue_request_hash
                  OR NEW.created_at != OLD.created_at
                BEGIN SELECT RAISE(ABORT, 'terminal operation issue identity is immutable'); END;
                """
            )
            row = connection.execute(
                "SELECT schema_version FROM terminal_operation_lease_meta WHERE singleton=1"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO terminal_operation_lease_meta(singleton,schema_version) VALUES(1,?)",
                    (STORE_SCHEMA_VERSION,),
                )
            elif row["schema_version"] != STORE_SCHEMA_VERSION:
                raise sqlite3.IntegrityError(
                    "terminal operation lease store schema version differs"
                )
            connection.commit()

    def begin_issue_attempt(
        self,
        *,
        device_id: str,
        source_host_id: str,
        authority_scope_id: str,
        scan_payload: str,
        explicit_new: bool,
    ) -> sqlite3.Row:
        """Persist a nonce before network I/O, or replay one unresolved attempt."""

        device = _bounded_text(device_id, field="device_id", maximum=128)
        source_host = _bounded_text(
            source_host_id, field="source_host_id", maximum=128
        )
        scope = _bounded_text(
            authority_scope_id, field="authority_scope_id"
        )
        scan_hash = physical_qr_sha256(scan_payload)
        issue_request = {
            "authority_scope_id": scope,
            "operation": TRANSFER_OPERATION,
            "scan_payload": scan_payload,
        }
        request_json = canonical_json_bytes(issue_request).decode("utf-8")
        request_hash = canonical_hash(issue_request)
        resource_key = canonical_hash(
            {
                "program": CONTAINER_PROGRAM,
                "authority_scope_id": scope,
                "operation": TRANSFER_OPERATION,
                "physical_qr_sha256": scan_hash,
            }
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            unresolved = connection.execute(
                """SELECT * FROM terminal_operation_lease_issue_attempts
                    WHERE resource_key=?
                      AND status IN (
                        'PENDING','PREFETCHED','LOCAL_COMPLETED',
                        'OPERATOR_REVIEW','EXPIRED_UNRECONCILED',
                        'RECONCILIATION_REQUIRED','CONSUMED_UNACKED'
                      )
                    ORDER BY created_at DESC,rowid DESC LIMIT 1""",
                (resource_key,),
            ).fetchone()
            if unresolved is not None:
                if (
                    unresolved["device_id"] != device
                    or unresolved["source_host_id"] != source_host
                    or unresolved["authority_scope_id"] != scope
                    or unresolved["physical_qr_sha256"] != scan_hash
                    or unresolved["issue_request_json"] != request_json
                    or unresolved["issue_request_hash"] != request_hash
                ):
                    raise sqlite3.IntegrityError(
                        "unresolved terminal issue attempt identity differs"
                    )
                connection.commit()
                return unresolved
            latest = connection.execute(
                """SELECT status FROM terminal_operation_lease_issue_attempts
                    WHERE resource_key=?
                    ORDER BY created_at DESC,rowid DESC LIMIT 1""",
                (resource_key,),
            ).fetchone()
            if latest is not None and explicit_new is not True:
                raise _error(
                    "OPERATION_LEASE_NEW_ATTEMPT_REQUIRED",
                    "a terminal lease history requires an explicit new prefetch",
                )
            nonce = secrets.token_hex(16)
            attempt_id = "TRANSFER-LEASE-ISSUE-" + canonical_hash(
                {"resource_key": resource_key, "nonce": nonce}
            )[:32]
            issue_key = "container-operation-lease-issue:" + canonical_hash(
                {"attempt_id": attempt_id, "nonce": nonce}
            )
            now = utc_text()
            connection.execute(
                """INSERT INTO terminal_operation_lease_issue_attempts(
                       attempt_id,resource_key,device_id,source_host_id,
                       authority_scope_id,physical_qr_sha256,
                       issue_idempotency_key,issue_request_json,
                       issue_request_hash,status,lease_id,
                       terminal_evidence_json,terminal_evidence_hash,
                       created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,'PENDING',NULL,NULL,NULL,?,?)""",
                (
                    attempt_id,
                    resource_key,
                    device,
                    source_host,
                    scope,
                    scan_hash,
                    issue_key,
                    request_json,
                    request_hash,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                """SELECT * FROM terminal_operation_lease_issue_attempts
                    WHERE attempt_id=?""",
                (attempt_id,),
            ).fetchone()
            connection.commit()
        assert row is not None
        return row

    def issue_attempt(self, issue_idempotency_key: str) -> sqlite3.Row:
        key = _bounded_text(
            issue_idempotency_key,
            field="issue_idempotency_key",
            maximum=256,
        )
        with self._connect() as connection:
            row = connection.execute(
                """SELECT * FROM terminal_operation_lease_issue_attempts
                    WHERE issue_idempotency_key=?""",
                (key,),
            ).fetchone()
        if row is None:
            raise _error(
                "OPERATION_LEASE_ISSUE_ATTEMPT_NOT_FOUND",
                "durable operation lease issue attempt was not found",
            )
        return row

    @staticmethod
    def _validate_issue_attempt_request(
        row: sqlite3.Row,
        *,
        issue_request: Mapping[str, Any],
    ) -> None:
        request_json = canonical_json_bytes(dict(issue_request)).decode("utf-8")
        if (
            row["issue_request_json"] != request_json
            or row["issue_request_hash"] != canonical_hash(dict(issue_request))
        ):
            raise sqlite3.IntegrityError(
                "authenticated lease differs from durable issue request"
            )

    def record_authenticated_nonactive(
        self,
        *,
        artifact: Mapping[str, Any],
        claims: Mapping[str, Any],
        issue_request: Mapping[str, Any],
        issue_idempotency_key: str,
    ) -> sqlite3.Row:
        server_status = str(artifact.get("status") or "")
        status_map = {
            "EXPIRED_UNRECONCILED": ISSUE_EXPIRED_UNRECONCILED,
            "RECONCILIATION_REQUIRED": ISSUE_RECONCILIATION_REQUIRED,
            "CONSUMED": ISSUE_CONSUMED_UNACKED,
            "RELEASED": ISSUE_RELEASED,
        }
        target_status = status_map.get(server_status)
        if target_status is None:
            raise _error(
                "OPERATION_LEASE_STATUS_INVALID",
                "server lease status is not a supported non-active state",
            )
        evidence_json = canonical_json_bytes(dict(artifact)).decode("utf-8")
        evidence_hash = hashlib.sha256(
            evidence_json.encode("utf-8")
        ).hexdigest()
        issue_key = _bounded_text(
            issue_idempotency_key,
            field="issue_idempotency_key",
            maximum=256,
        )
        lease_id = _bounded_text(
            claims.get("lease_id"), field="lease_id", maximum=128
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT * FROM terminal_operation_lease_issue_attempts
                    WHERE issue_idempotency_key=?""",
                (issue_key,),
            ).fetchone()
            if row is None:
                raise sqlite3.IntegrityError(
                    "non-active lease has no durable issue attempt"
                )
            self._validate_issue_attempt_request(
                row, issue_request=issue_request
            )
            if row["lease_id"] not in (None, lease_id):
                raise sqlite3.IntegrityError(
                    "non-active lease differs from durable attempt lease"
                )
            if (
                row["status"] in TERMINAL_ISSUE_STATUSES
                and row["status"] != target_status
            ):
                raise sqlite3.IntegrityError(
                    "terminal operation lease status differs from replay"
                )
            if row["status"] not in TERMINAL_ISSUE_STATUSES:
                connection.execute(
                    """UPDATE terminal_operation_lease_issue_attempts
                          SET status=?,lease_id=?,terminal_evidence_json=?,
                              terminal_evidence_hash=?,updated_at=?
                        WHERE attempt_id=?""",
                    (
                        target_status,
                        lease_id,
                        evidence_json,
                        evidence_hash,
                        utc_text(),
                        row["attempt_id"],
                    ),
                )
            result = connection.execute(
                """SELECT * FROM terminal_operation_lease_issue_attempts
                    WHERE attempt_id=?""",
                (row["attempt_id"],),
            ).fetchone()
            connection.commit()
        assert result is not None
        return result

    def save_prefetched(
        self,
        *,
        artifact: Mapping[str, Any],
        claims: Mapping[str, Any],
        issue_request: Mapping[str, Any],
        issue_idempotency_key: str,
    ) -> sqlite3.Row:
        normalized_artifact = dict(artifact)
        normalized_claims = dict(claims)
        request = dict(issue_request)
        artifact_json = canonical_json_bytes(normalized_artifact).decode("utf-8")
        claims_json = canonical_json_bytes(normalized_claims).decode("utf-8")
        request_json = canonical_json_bytes(request).decode("utf-8")
        lease_id = _bounded_text(
            normalized_claims.get("lease_id"), field="lease_id", maximum=128
        )
        issue_key = _bounded_text(
            issue_idempotency_key,
            field="issue_idempotency_key",
            maximum=256,
        )
        values = (
            lease_id,
            issue_key,
            request_json,
            canonical_hash(request),
            artifact_json,
            hashlib.sha256(artifact_json.encode("utf-8")).hexdigest(),
            hashlib.sha256(str(normalized_artifact["token"]).encode("ascii")).hexdigest(),
            claims_json,
            str(normalized_claims["snapshot_hash"]),
            str(normalized_claims["expires_at"]),
            int(normalized_claims["fence"]),
            utc_text(),
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                """SELECT * FROM terminal_operation_lease_issue_attempts
                    WHERE issue_idempotency_key=?""",
                (issue_key,),
            ).fetchone()
            if attempt is None:
                raise sqlite3.IntegrityError(
                    "authenticated lease has no durable issue attempt"
                )
            self._validate_issue_attempt_request(
                attempt, issue_request=request
            )
            if attempt["status"] not in {ISSUE_PENDING, ISSUE_PREFETCHED}:
                raise sqlite3.IntegrityError(
                    "authenticated ACTIVE lease belongs to a terminal attempt"
                )
            if attempt["lease_id"] not in (None, lease_id):
                raise sqlite3.IntegrityError(
                    "authenticated lease differs from durable attempt lease"
                )
            connection.execute(
                """INSERT OR IGNORE INTO terminal_operation_lease_artifacts(
                       lease_id,issue_idempotency_key,issue_request_json,
                       issue_request_hash,artifact_json,artifact_hash,token_hash,
                       claims_json,snapshot_hash,expires_at,fence,created_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                values,
            )
            row = connection.execute(
                "SELECT * FROM terminal_operation_lease_artifacts WHERE lease_id=?",
                (lease_id,),
            ).fetchone()
            expected_columns = {
                "lease_id": values[0],
                "issue_idempotency_key": values[1],
                "issue_request_json": values[2],
                "issue_request_hash": values[3],
                "token_hash": values[6],
                "claims_json": values[7],
                "snapshot_hash": values[8],
                "expires_at": values[9],
                "fence": values[10],
            }
            try:
                stored_artifact = (
                    json.loads(str(row["artifact_json"]))
                    if row is not None
                    else None
                )
            except json.JSONDecodeError:
                stored_artifact = None
            transport_fields = {"replayed", "keyring"}
            stored_core = (
                {
                    key: value
                    for key, value in stored_artifact.items()
                    if key not in transport_fields
                }
                if isinstance(stored_artifact, dict)
                else None
            )
            incoming_core = {
                key: value
                for key, value in normalized_artifact.items()
                if key not in transport_fields
            }
            if (
                row is None
                or any(row[key] != value for key, value in expected_columns.items())
                or stored_core != incoming_core
                or hashlib.sha256(
                    str(row["artifact_json"]).encode("utf-8")
                ).hexdigest()
                != row["artifact_hash"]
            ):
                raise sqlite3.IntegrityError(
                    "durable terminal operation lease differs from authenticated artifact"
                )
            connection.execute(
                """UPDATE terminal_operation_lease_issue_attempts
                      SET status='PREFETCHED',lease_id=?,updated_at=?
                    WHERE attempt_id=?""",
                (lease_id, utc_text(), attempt["attempt_id"]),
            )
            connection.commit()
        return row

    def load(self, lease_id: str) -> sqlite3.Row:
        normalized = _bounded_text(lease_id, field="lease_id", maximum=128)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM terminal_operation_lease_artifacts WHERE lease_id=?",
                (normalized,),
            ).fetchone()
        if row is None:
            raise _error(
                "OPERATION_LEASE_NOT_FOUND",
                "prefetched operation lease was not found",
            )
        return row

    def artifact(self, lease_id: str) -> dict[str, Any]:
        row = self.load(lease_id)
        try:
            artifact = json.loads(str(row["artifact_json"]))
        except json.JSONDecodeError as exc:
            raise _error(
                "OPERATION_LEASE_LOCAL_ARTIFACT_INVALID",
                "stored artifact JSON cannot be parsed",
            ) from exc
        raw = canonical_json_bytes(artifact).decode("utf-8")
        if (
            raw != row["artifact_json"]
            or hashlib.sha256(raw.encode("utf-8")).hexdigest() != row["artifact_hash"]
        ):
            raise _error(
                "OPERATION_LEASE_LOCAL_ARTIFACT_INVALID",
                "stored artifact integrity check failed",
            )
        return artifact

    @staticmethod
    def _transition_issue_for_lease(
        connection: sqlite3.Connection,
        *,
        lease_id: str,
        target_status: str,
        allowed_statuses: frozenset[str],
    ) -> None:
        attempt = connection.execute(
            """SELECT * FROM terminal_operation_lease_issue_attempts
                WHERE lease_id=?""",
            (lease_id,),
        ).fetchone()
        if attempt is None:
            raise sqlite3.IntegrityError(
                "lease lifecycle has no durable issue attempt"
            )
        if attempt["status"] == target_status:
            return
        if attempt["status"] not in allowed_statuses:
            raise sqlite3.IntegrityError(
                "lease issue attempt transition is invalid"
            )
        connection.execute(
            """UPDATE terminal_operation_lease_issue_attempts
                  SET status=?,updated_at=? WHERE attempt_id=?""",
            (target_status, utc_text(), attempt["attempt_id"]),
        )

    def record_local_completion(
        self,
        *,
        lease_id: str,
        transfer_intent_id: str,
        transfer_idempotency_key: str,
        operation_completed_at: str,
    ) -> sqlite3.Row:
        self.load(lease_id)
        completed_at = utc_text(
            parse_utc_text(operation_completed_at, field="operation_completed_at")
        )
        intent_id = _bounded_text(
            transfer_intent_id, field="transfer_intent_id", maximum=256
        )
        transfer_key = _bounded_text(
            transfer_idempotency_key,
            field="transfer_idempotency_key",
            maximum=256,
        )
        operation_result_id = "TRANSFER-LEASE-RESULT-" + canonical_hash(
            {
                "lease_id": lease_id,
                "transfer_intent_id": intent_id,
                "transfer_idempotency_key": transfer_key,
            }
        )[:32]
        completion = {
            "contract_version": "container-terminal-operation-completion-v1",
            "lease_id": lease_id,
            "operation_result_id": operation_result_id,
            "transfer_intent_id": intent_id,
            "transfer_idempotency_key": transfer_key,
            "operation_completed_at": completed_at,
        }
        completion_json = canonical_json_bytes(completion).decode("utf-8")
        completion_hash = hashlib.sha256(completion_json.encode("utf-8")).hexdigest()
        outbox = {
            **completion,
            "contract_version": "container-terminal-operation-outbox-v1",
            "event_type": "SEAL_TRANSFER_BUNDLE",
        }
        outbox_json = canonical_json_bytes(outbox).decode("utf-8")
        outbox_hash = hashlib.sha256(outbox_json.encode("utf-8")).hexdigest()
        outbox_id = "TRANSFER-LEASE-OUTBOX-" + outbox_hash[:32]
        created_at = utc_text()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT OR IGNORE INTO terminal_operation_lease_completions(
                       operation_result_id,lease_id,transfer_intent_id,
                       transfer_idempotency_key,operation_completed_at,
                       completion_json,completion_hash,created_at
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    operation_result_id,
                    lease_id,
                    intent_id,
                    transfer_key,
                    completed_at,
                    completion_json,
                    completion_hash,
                    created_at,
                ),
            )
            connection.execute(
                """INSERT OR IGNORE INTO terminal_operation_lease_outbox(
                       outbox_id,lease_id,operation_result_id,
                       transfer_idempotency_key,payload_json,payload_hash,created_at
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    outbox_id,
                    lease_id,
                    operation_result_id,
                    transfer_key,
                    outbox_json,
                    outbox_hash,
                    created_at,
                ),
            )
            row = connection.execute(
                "SELECT * FROM terminal_operation_lease_completions WHERE lease_id=?",
                (lease_id,),
            ).fetchone()
            outbox_row = connection.execute(
                "SELECT * FROM terminal_operation_lease_outbox WHERE lease_id=?",
                (lease_id,),
            ).fetchone()
            if (
                row is None
                or outbox_row is None
                or row["operation_result_id"] != operation_result_id
                or row["transfer_intent_id"] != intent_id
                or row["transfer_idempotency_key"] != transfer_key
                or row["operation_completed_at"] != completed_at
                or row["completion_json"] != completion_json
                or row["completion_hash"] != completion_hash
                or outbox_row["operation_result_id"] != operation_result_id
                or outbox_row["transfer_idempotency_key"] != transfer_key
                or outbox_row["payload_json"] != outbox_json
                or outbox_row["payload_hash"] != outbox_hash
            ):
                raise sqlite3.IntegrityError(
                    "durable terminal completion/outbox differs from retry"
                )
            self._transition_issue_for_lease(
                connection,
                lease_id=lease_id,
                target_status=ISSUE_LOCAL_COMPLETED,
                allowed_statuses=frozenset(
                    {ISSUE_PREFETCHED, ISSUE_LOCAL_COMPLETED}
                ),
            )
            connection.commit()
        return row

    def completion(self, lease_id: str) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM terminal_operation_lease_completions WHERE lease_id=?",
                (lease_id,),
            ).fetchone()

    def record_receipt(
        self,
        *,
        lease_id: str,
        transfer_intent_id: str,
        receipt: Mapping[str, Any],
    ) -> sqlite3.Row:
        completion = self.completion(lease_id)
        if completion is None or completion["transfer_intent_id"] != transfer_intent_id:
            raise _error(
                "OPERATION_LEASE_LOCAL_COMPLETION_MISSING",
                "lease receipt has no exact durable local completion",
            )
        data = receipt.get("data") if isinstance(receipt, Mapping) else None
        data = data if isinstance(data, Mapping) else receipt
        consumption = (
            data.get("operation_lease_consumption")
            if isinstance(data, Mapping)
            else None
        )
        artifact = self.load(lease_id)
        receipt_id = str(
            (receipt.get("receipt_id") if isinstance(receipt, Mapping) else "")
            or (data.get("receipt_id") if isinstance(data, Mapping) else "")
            or ""
        ).strip()
        if (
            not isinstance(consumption, Mapping)
            or set(consumption)
            != {
                "contract_version",
                "lease_id",
                "status",
                "fence",
                "operation_result_id",
                "consumed_at",
            }
            or consumption.get("contract_version") != CONSUME_CONTRACT_VERSION
            or consumption.get("lease_id") != lease_id
            or consumption.get("status") != "CONSUMED"
            or consumption.get("fence") != artifact["fence"]
            or not receipt_id
            or consumption.get("operation_result_id") != receipt_id
        ):
            raise _error(
                "OPERATION_LEASE_RECEIPT_MISMATCH",
                "server receipt does not prove atomic lease consumption",
            )
        acked_at = utc_text(
            parse_utc_text(consumption.get("consumed_at"), field="consumed_at")
        )
        receipt_value = dict(receipt)
        receipt_json = canonical_json_bytes(receipt_value).decode("utf-8")
        receipt_hash = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT OR IGNORE INTO terminal_operation_lease_receipts(
                       lease_id,operation_result_id,transfer_intent_id,
                       receipt_json,receipt_hash,acked_at
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    lease_id,
                    receipt_id,
                    transfer_intent_id,
                    receipt_json,
                    receipt_hash,
                    acked_at,
                ),
            )
            row = connection.execute(
                "SELECT * FROM terminal_operation_lease_receipts WHERE lease_id=?",
                (lease_id,),
            ).fetchone()
            if (
                row is None
                or row["operation_result_id"] != receipt_id
                or row["transfer_intent_id"] != transfer_intent_id
                or row["receipt_json"] != receipt_json
                or row["receipt_hash"] != receipt_hash
                or row["acked_at"] != acked_at
            ):
                raise sqlite3.IntegrityError(
                    "durable terminal operation receipt differs from replay"
                )
            self._transition_issue_for_lease(
                connection,
                lease_id=lease_id,
                target_status=ISSUE_ACKED,
                allowed_statuses=frozenset(
                    {ISSUE_LOCAL_COMPLETED, ISSUE_ACKED}
                ),
            )
            connection.commit()
        return row

    def record_review(
        self,
        *,
        lease_id: str,
        transfer_intent_id: str,
        error_code: str,
    ) -> sqlite3.Row:
        completion = self.completion(lease_id)
        if completion is None or completion["transfer_intent_id"] != transfer_intent_id:
            raise _error(
                "OPERATION_LEASE_LOCAL_COMPLETION_MISSING",
                "post-review requires the exact durable local completion",
            )
        code = _bounded_text(error_code, field="error_code", maximum=128)
        evidence = {
            "contract_version": "container-terminal-operation-review-v1",
            "lease_id": lease_id,
            "transfer_intent_id": transfer_intent_id,
            "operation_result_id": completion["operation_result_id"],
            "error_code": code,
        }
        evidence_json = canonical_json_bytes(evidence).decode("utf-8")
        evidence_hash = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
        created_at = utc_text()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT OR IGNORE INTO terminal_operation_lease_reviews(
                       lease_id,transfer_intent_id,error_code,evidence_json,
                       evidence_hash,created_at
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    lease_id,
                    transfer_intent_id,
                    code,
                    evidence_json,
                    evidence_hash,
                    created_at,
                ),
            )
            row = connection.execute(
                "SELECT * FROM terminal_operation_lease_reviews WHERE lease_id=?",
                (lease_id,),
            ).fetchone()
            if (
                row is None
                or row["transfer_intent_id"] != transfer_intent_id
                or row["error_code"] != code
                or row["evidence_json"] != evidence_json
                or row["evidence_hash"] != evidence_hash
            ):
                raise sqlite3.IntegrityError(
                    "durable terminal operation review differs from replay"
                )
            self._transition_issue_for_lease(
                connection,
                lease_id=lease_id,
                target_status=ISSUE_OPERATOR_REVIEW,
                allowed_statuses=frozenset(
                    {ISSUE_LOCAL_COMPLETED, ISSUE_OPERATOR_REVIEW}
                ),
            )
            connection.commit()
        return row

    def state(self, lease_id: str) -> str:
        self.load(lease_id)
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM terminal_operation_lease_reviews WHERE lease_id=?",
                (lease_id,),
            ).fetchone():
                return "OPERATOR_REVIEW"
            if connection.execute(
                "SELECT 1 FROM terminal_operation_lease_receipts WHERE lease_id=?",
                (lease_id,),
            ).fetchone():
                return "ACKED"
            if connection.execute(
                "SELECT 1 FROM terminal_operation_lease_completions WHERE lease_id=?",
                (lease_id,),
            ).fetchone():
                return "LOCAL_COMPLETED"
        return "PREFETCHED"


class OperationLeaseManager:
    """Coordinates pinned verification with append-only local evidence."""

    def __init__(
        self,
        store: OperationLeaseStore,
        keyring: PinnedOperationLeaseKeyring,
    ) -> None:
        self.store = store
        self.keyring = keyring

    def issue_idempotency_key(
        self,
        *,
        device_id: str,
        source_host_id: str,
        authority_scope_id: str,
        scan_payload: str,
        explicit_new: bool = False,
    ) -> str:
        row = self.store.begin_issue_attempt(
            device_id=device_id,
            source_host_id=source_host_id,
            authority_scope_id=authority_scope_id,
            scan_payload=scan_payload,
            explicit_new=explicit_new,
        )
        return str(row["issue_idempotency_key"])

    def accept_authenticated(
        self,
        *,
        artifact: Mapping[str, Any],
        expected: Mapping[str, Any],
        issue_request: Mapping[str, Any],
        issue_idempotency_key: str,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        normalized, claims = validate_artifact(
            dict(artifact), expected=expected, now=now
        )
        self.keyring.bootstrap_authenticated(
            normalized["keyring"], authenticated_online=True
        )
        normalized, claims = self.keyring.verify(
            normalized, expected=expected, now=now
        )
        self.store.save_prefetched(
            artifact=normalized,
            claims=claims,
            issue_request=issue_request,
            issue_idempotency_key=issue_idempotency_key,
        )
        return normalized, claims

    def accept_authenticated_nonactive(
        self,
        *,
        artifact: Mapping[str, Any],
        expected: Mapping[str, Any],
        issue_request: Mapping[str, Any],
        issue_idempotency_key: str,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        status = str(artifact.get("status") or "")
        if status not in SERVER_NONACTIVE_STATUSES:
            raise _error(
                "OPERATION_LEASE_STATUS_INVALID",
                "expected an authenticated non-active lease status",
            )
        allowed = frozenset({status})
        normalized, claims = validate_artifact(
            dict(artifact),
            expected=expected,
            now=now,
            allow_expired=True,
            allowed_statuses=allowed,
        )
        self.keyring.bootstrap_authenticated(
            normalized["keyring"], authenticated_online=True
        )
        normalized, claims = self.keyring.verify(
            normalized,
            expected=expected,
            now=now,
            allow_expired=True,
            allowed_statuses=allowed,
        )
        self.store.record_authenticated_nonactive(
            artifact=normalized,
            claims=claims,
            issue_request=issue_request,
            issue_idempotency_key=issue_idempotency_key,
        )
        return normalized, claims

    def verify_stored(
        self,
        lease_id: str,
        *,
        expected: Mapping[str, Any],
        now: datetime | None = None,
        allow_expired: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.keyring.verify(
            self.store.artifact(lease_id),
            expected=expected,
            now=now,
            allow_expired=allow_expired,
        )


__all__ = [
    "ARTIFACT_CONTRACT_VERSION",
    "CONSUME_CONTRACT_VERSION",
    "CONTAINER_PROGRAM",
    "JWS_ALGORITHM",
    "JWS_TYPE",
    "KEYRING_CONTRACT_VERSION",
    "LEASE_BINDING_KEYS",
    "LEASE_CLAIM_KEYS",
    "LEASE_CONTRACT_VERSION",
    "OperationLeaseError",
    "OperationLeaseManager",
    "OperationLeaseStore",
    "PinnedOperationLeaseKeyring",
    "TRANSFER_OPERATION",
    "canonical_hash",
    "canonical_json_bytes",
    "jwk_thumbprint",
    "normalize_keyring",
    "normalize_public_jwk",
    "parse_utc_text",
    "physical_qr_sha256",
    "utc_text",
    "validate_artifact",
    "validate_claims",
    "verify_jws",
]

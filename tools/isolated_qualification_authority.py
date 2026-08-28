#!/usr/bin/env python
"""Package-owned ephemeral HTTPS authority for Windows Sandbox qualification.

This executable is inert unless initialized through the explicit, guarded
Windows Sandbox installer route.  It binds only 127.0.0.1, creates all key
material at runtime, retains no event bodies, and exposes only the minimum
enrollment, relay-liveness, catalog, and representative workflow contracts.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
from email.parser import BytesParser
from email.policy import default as email_policy
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import threading
from typing import Any, Mapping
from urllib.parse import parse_qs, urlsplit
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import requests


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from direct_sync_push import (  # noqa: E402
    DEFAULT_ENDPOINT_PATH,
    canonical_request_string,
    manifest_hash,
)
from isolated_qualification import (  # noqa: E402
    ACTIVATION_MODE,
    CONTEXT_FILENAME,
    CONTRACT_VERSION as CLIENT_CONTRACT_VERSION,
    IsolatedQualificationError,
    assert_windows_sandbox_operator_context,
    load_isolated_qualification_context,
)
from producer_runtime_client import (  # noqa: E402
    CONTRACT_VERSION as RUNTIME_LEASE_CONTRACT_VERSION,
    _canonical_request as runtime_canonical_request,
    _jwk_thumbprint,
)
from terminal_operation_lease import (  # noqa: E402
    ARTIFACT_CONTRACT_VERSION,
    JWS_TYPE,
    KEYRING_CONTRACT_VERSION,
    LEASE_CONTRACT_VERSION,
    TRANSFER_OPERATION,
    canonical_hash,
    canonical_json_bytes,
    jwk_thumbprint,
    physical_qr_sha256,
    utc_text,
)
from transfer_seal import _deterministic_id, _sha256, membership_hash  # noqa: E402
from tools.install_logistics_runtime_profile import (  # noqa: E402
    MACHINE_CREDENTIAL_BUNDLE_CONTRACT_VERSION,
)
from vendor.kmtech_zero_pe import (  # noqa: E402
    POSSESSION_KEY_CONTRACT_VERSION,
    jwk_thumbprint as possession_jwk_thumbprint,
    normalize_public_jwk as normalize_possession_public_jwk,
)


SELF_ENROLLMENT_CONTRACT_VERSION = "producer-self-enrollment-v2"
AUTHORITY_CONTRACT_VERSION = "container-audit-isolated-qualification-authority-v1"
PRIVATE_STATE_CONTRACT_VERSION = "container-audit-isolated-qualification-private-v2"
STATUS_CONTRACT_VERSION = "container-audit-isolated-qualification-status-v1"
FIXTURE_CONTRACT_VERSION = "container-audit-isolated-qualification-fixture-v1"
DEFAULT_PORT = 18470
MAX_JSON_REQUEST_BYTES = 1024 * 1024
MAX_MULTIPART_REQUEST_BYTES = 8 * 1024 * 1024
PRIVATE_STATE_FILENAME = "private-state.json"
STATUS_FILENAME = "status.json"
FIXTURE_FILENAME = "operator-fixture.json"
CA_FILENAME = "qualification-ca.pem"
SERVER_CERT_FILENAME = "qualification-server.pem"
SERVER_KEY_FILENAME = "qualification-server-key.pem"
LEASE_KEY_FILENAME = "qualification-operation-lease-key.pem"
QUALIFICATION_ITEM_CODE = "AAA2270730100"
QUALIFICATION_INPUT_TAG = "QUAL-ITAG-001"
QUALIFICATION_INPUT_LABEL = "QUAL-INPUT-LABEL-001"
QUALIFICATION_WORK_LABEL = "QUAL-WORK-LABEL-001"
QUALIFICATION_SCOPE = "QUALIFICATION-CONTAINER-AUDIT"
QUALIFICATION_SITE = "QUALIFICATION-SITE"
QUALIFICATION_OPERATOR = "QUALIFICATION-OPERATOR"
QUALIFICATION_SOURCE_BUNDLE = "QUAL-PHS-SOURCE-001"
QUALIFICATION_GROUP = "QUAL-PHS-WORK-GROUP-001"
QUALIFICATION_INPUT_LABEL_HASH = "a" * 64
QUALIFICATION_INPUT_CORE_HASH = "b" * 64
QUALIFICATION_ACTIVE_LABEL_HASH = "e" * 64
QUALIFICATION_SOURCE_QR = (
    "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=QUAL-ITAG-001|"
    "CLC=AAA2270730100|LBL=QUAL-INPUT-LABEL-001|HSH=aaaaaaaaaaaaaaaa"
)
QUALIFICATION_MASTER_QR = (
    "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=QUAL-ITAG-001|"
    "CLC=AAA2270730100|LBL=QUAL-WORK-LABEL-001|HSH=eeeeeeeeeeeeeeee"
)
QUALIFICATION_PRODUCT_BARCODES = (
    "AAA2270730100-QUAL-SERIAL-001",
    "AAA2270730100-QUAL-SERIAL-002",
)
P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(value: datetime | None = None) -> str:
    selected = value or _utc_now()
    return selected.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    _atomic_write(
        path,
        (json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
            "utf-8"
        ),
    )


def _read_json_object(path: Path, *, maximum: int = MAX_JSON_REQUEST_BYTES) -> dict:
    try:
        size = path.stat().st_size
        if size <= 0 or size > maximum or path.is_symlink():
            raise ValueError("size or path type is invalid")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise IsolatedQualificationError(
            f"qualification authority state is invalid: {exc.__class__.__name__}"
        ) from exc
    if not isinstance(payload, dict):
        raise IsolatedQualificationError("qualification authority state must be an object")
    return payload


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _public_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }


def _sign_jws(
    key: ec.EllipticCurvePrivateKey,
    kid: str,
    claims: Mapping[str, Any],
) -> str:
    header = {"alg": "ES256", "kid": kid, "typ": JWS_TYPE}
    encoded_header = _b64(canonical_json_bytes(header))
    encoded_payload = _b64(canonical_json_bytes(dict(claims)))
    der = key.sign(
        f"{encoded_header}.{encoded_payload}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = decode_dss_signature(der)
    s = min(s, P256_ORDER - s)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{encoded_header}.{encoded_payload}.{_b64(signature)}"


def _fixture_payload() -> dict[str, Any]:
    return {
        "contract_version": FIXTURE_CONTRACT_VERSION,
        "operator_code": QUALIFICATION_OPERATOR,
        "master_label": QUALIFICATION_MASTER_QR,
        "item_code": QUALIFICATION_ITEM_CODE,
        "product_barcodes": list(QUALIFICATION_PRODUCT_BARCODES),
        "physical_scanner_proven": False,
        "purpose": "isolated non-production Windows Sandbox qualification only",
    }


def _build_snapshot() -> dict[str, Any]:
    member_ids = ["qual-unit-001", "qual-unit-002"]
    members = [
        {
            "unit_id": member_id,
            "normalized_barcode": barcode,
            "inbound_iin": "QUALIFICATION-IIN",
            "current_inbound_iin": "QUALIFICATION-IIN",
            "item_id": QUALIFICATION_ITEM_CODE,
            "uom": "EA",
            "unit_state": "AVAILABLE",
            "location_code": "PHS_GOOD",
        }
        for member_id, barcode in zip(member_ids, QUALIFICATION_PRODUCT_BARCODES)
    ]
    input_tag = {
        "input_tag_id": QUALIFICATION_INPUT_TAG,
        "label_id": QUALIFICATION_INPUT_LABEL,
        "item_id": QUALIFICATION_ITEM_CODE,
        "uom": "EA",
        "tag_core_hash": QUALIFICATION_INPUT_CORE_HASH,
        "label_instance_hash": QUALIFICATION_INPUT_LABEL_HASH,
        "hash_prefix": QUALIFICATION_INPUT_LABEL_HASH[:16],
        "lifecycle": "INSPECTION_COMPLETED",
        "qr_payload": QUALIFICATION_SOURCE_QR,
        "session_id": QUALIFICATION_INPUT_TAG,
        "session_state": "COMPLETED",
        "entity_version": 1,
        "member_count": len(member_ids),
        "membership_hash": membership_hash(member_ids),
    }
    source_bundle = {
        "bundle_id": QUALIFICATION_SOURCE_BUNDLE,
        "bundle_type": "PHS",
        "bundle_state": "AVAILABLE",
        "entity_version": 1,
        "source_session_id": QUALIFICATION_INPUT_TAG,
        "external_label": QUALIFICATION_SOURCE_QR,
        "accounting_inbound_iin": "QUALIFICATION-IIN",
        "source_member_ids": list(member_ids),
        "source_member_count": len(member_ids),
        "source_membership_hash": membership_hash(member_ids),
        "selected_member_ids": list(member_ids),
        "selected_member_count": len(member_ids),
        "selected_membership_hash": membership_hash(member_ids),
        "remainder_member_ids": [],
        "remainder_member_count": 0,
        "remainder_membership_hash": None,
        "remainder_bundle_id": None,
        "remainder_external_label": None,
        "remainder_cover_group_ids": [],
    }
    group = {
        "group_id": QUALIFICATION_GROUP,
        "label_id": QUALIFICATION_WORK_LABEL,
        "state": "ACTIVE",
        "scan_payload": QUALIFICATION_MASTER_QR,
        "scan_anchor_input_tag_id": QUALIFICATION_INPUT_TAG,
        "item_id": QUALIFICATION_ITEM_CODE,
        "uom": "EA",
        "member_ids": list(member_ids),
        "member_count": len(member_ids),
        "membership_hash": membership_hash(member_ids),
        "membership_version": 1,
        "label_version": 1,
        "group_entity_version": 1,
        "label_entity_version": 1,
    }
    active_label = {
        **group,
        "qr_payload": QUALIFICATION_MASTER_QR,
        "hash_prefix": QUALIFICATION_ACTIVE_LABEL_HASH[:16],
        "entity_version": 1,
        "business_date": "2099-01-01",
        "worker_code": QUALIFICATION_OPERATOR,
    }
    transfer_bundle_id = _deterministic_id(
        "TRANSFER",
        {
            "group_id": group["group_id"],
            "label_id": group["label_id"],
            "member_ids": list(member_ids),
        },
    )
    entity_versions = {
        f"phs_work_group:{QUALIFICATION_GROUP}": 1,
        f"phs_work_membership:{QUALIFICATION_GROUP}": 1,
        f"phs_work_label_version:{QUALIFICATION_GROUP}": 1,
        f"phs_label:{QUALIFICATION_WORK_LABEL}": 1,
        f"bundle:{QUALIFICATION_SOURCE_BUNDLE}": 1,
        f"bundle:{transfer_bundle_id}": 0,
    }
    barcode_hash = membership_hash(sorted(QUALIFICATION_PRODUCT_BARCODES))
    topology_hash = _sha256(
        {
            "phs_work_group": group,
            "source_bundles": [source_bundle],
            "remainder_cover_groups": [],
            "source_iin": "QUALIFICATION-IIN",
            "barcode_membership_hash": barcode_hash,
            "transfer_bundle_id": transfer_bundle_id,
        }
    )
    work_source = {
        "authority_scope_id": QUALIFICATION_SCOPE,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 1,
        "item_id": QUALIFICATION_ITEM_CODE,
        "uom": "EA",
        "source_iin": "QUALIFICATION-IIN",
        "member_ids": list(member_ids),
        "member_count": len(member_ids),
        "membership_hash": membership_hash(member_ids),
        "barcode_member_count": len(QUALIFICATION_PRODUCT_BARCODES),
        "barcode_membership_hash": barcode_hash,
        "members": members,
        "source_bundles": [source_bundle],
        "source_bundle_count": 1,
        "source_bundle_ids": [QUALIFICATION_SOURCE_BUNDLE],
        "source_session_ids": [QUALIFICATION_INPUT_TAG],
        "transfer_bundle_id": transfer_bundle_id,
        "transfer_external_label": transfer_bundle_id,
        "remainder_cover_groups": [],
        "entity_versions": entity_versions,
        "topology_hash": topology_hash,
    }
    return {
        "candidate_count": 1,
        "source_resolution_basis": "PHS_WORK_GROUP_EXACT_MEMBERSHIP",
        "authority_scope_id": QUALIFICATION_SCOPE,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 1,
        "input_tag": input_tag,
        "source_input_tags": [input_tag],
        "phs_label_resolution": {
            "status": "ACTIVE",
            "resolution": "OVERLAY_ACTIVE",
            "authority_scope_id": QUALIFICATION_SCOPE,
            "ledger_plane": "AUTHORITATIVE",
            "plane_epoch": 1,
            "scanned_label": active_label,
            "effective_labels": [active_label],
        },
        "phs_work_group": group,
        "work_group_source": work_source,
        "topology_hash": topology_hash,
        "entity_versions": entity_versions,
    }


def _operation_lease_artifact(
    *,
    snapshot: Mapping[str, Any],
    scan_payload: str,
    device_id: str,
    source_host_id: str,
    lease_key: ec.EllipticCurvePrivateKey,
) -> dict[str, Any]:
    now = _utc_now()
    expiry = now + timedelta(minutes=30)
    source = snapshot["work_group_source"]
    group = snapshot["phs_work_group"]
    scanned = snapshot["phs_label_resolution"]["scanned_label"]
    lease_id = f"qualification-operation-{uuid.uuid4().hex}"
    kid = "qualification-operation-key"
    claims = {
        "contract_version": LEASE_CONTRACT_VERSION,
        "lease_id": lease_id,
        "site_id": QUALIFICATION_SITE,
        "program": "Container_Audit",
        "device_id": device_id,
        "source_host_id": source_host_id,
        "authority_scope_id": QUALIFICATION_SCOPE,
        "ledger_plane": snapshot["ledger_plane"],
        "plane_epoch": snapshot["plane_epoch"],
        "operation": TRANSFER_OPERATION,
        "resource_id": f"phs-work-group:{group['group_id']}",
        "physical_label_id": scanned["label_id"],
        "physical_qr_sha256": physical_qr_sha256(scan_payload),
        "item_id": source["item_id"],
        "quantity": len(source["member_ids"]),
        "member_count": len(source["member_ids"]),
        "membership_hash": source["membership_hash"],
        "expected_versions": dict(snapshot["entity_versions"]),
        "issued_at": utc_text(now),
        "expires_at": utc_text(expiry),
        "fence": 1,
        "snapshot_hash": canonical_hash(snapshot),
    }
    jwk = _public_jwk(lease_key)
    token = _sign_jws(lease_key, kid, claims)
    keyring = {
        "contract_version": KEYRING_CONTRACT_VERSION,
        "site_id": QUALIFICATION_SITE,
        "current_kid": kid,
        "keys": [
            {
                "kid": kid,
                "status": "current",
                "public_jwk": jwk,
                "thumbprint": jwk_thumbprint(jwk),
            }
        ],
    }
    return {
        "contract_version": ARTIFACT_CONTRACT_VERSION,
        "lease_id": lease_id,
        "status": "ACTIVE",
        "replayed": False,
        "token": token,
        "kid": kid,
        "expires_at": claims["expires_at"],
        "fence": 1,
        "snapshot_hash": claims["snapshot_hash"],
        "operation_snapshot": dict(snapshot),
        "keyring": keyring,
    }


def _generate_tls_material(state_root: Path, instance_id: str) -> None:
    now = _utc_now()
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                f"Container Audit Qualification {instance_id[-12:]}",
            )
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _atomic_write(state_root / CA_FILENAME, ca_cert.public_bytes(serialization.Encoding.PEM))
    _atomic_write(
        state_root / SERVER_CERT_FILENAME,
        server_cert.public_bytes(serialization.Encoding.PEM),
    )
    _atomic_write(
        state_root / SERVER_KEY_FILENAME,
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    lease_key = ec.generate_private_key(ec.SECP256R1())
    _atomic_write(
        state_root / LEASE_KEY_FILENAME,
        lease_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _expected_private_fields() -> frozenset[str]:
    return frozenset(
        {
            "contract_version",
            "authority_instance_id",
            "producer_secret",
            "logistics_token",
            "producer_key_id",
            "enrolled_producer_id",
            "enrolled_producer_install_id",
            "enrolled_possession_key_fingerprint",
            "runtime_next_request_token",
            "runtime_next_request_sequence",
            "runtime_lease_id",
            "runtime_fence",
        }
    )


def _validate_private_state(payload: Mapping[str, Any], instance_id: str) -> dict[str, Any]:
    if set(payload) != _expected_private_fields():
        raise IsolatedQualificationError("qualification authority private fields are invalid")
    if payload.get("contract_version") != PRIVATE_STATE_CONTRACT_VERSION:
        raise IsolatedQualificationError("qualification authority private version is invalid")
    if payload.get("authority_instance_id") != instance_id:
        raise IsolatedQualificationError("qualification authority private identity is invalid")
    for name in ("producer_secret", "logistics_token", "producer_key_id"):
        value = str(payload.get(name) or "")
        if not value or len(value) > 512 or any(character.isspace() for character in value):
            raise IsolatedQualificationError(
                f"qualification authority private {name} is invalid"
            )
    for name in (
        "enrolled_producer_id",
        "enrolled_producer_install_id",
        "enrolled_possession_key_fingerprint",
    ):
        value = payload.get(name)
        if not isinstance(value, str) or len(value) > 256 or any(
            character.isspace() for character in value
        ):
            raise IsolatedQualificationError(
                f"qualification authority private {name} is invalid"
            )
    return dict(payload)


def initialize_authority(
    *,
    state_root: Path,
    operator_user_sid: str,
    operator_local_app_data_root: str,
    port: int,
    report_path: Path,
) -> dict[str, Any]:
    source_test_mode = assert_windows_sandbox_operator_context(
        operator_user_sid=operator_user_sid,
        operator_local_app_data_root=operator_local_app_data_root,
        state_root=state_root,
    )
    if not 1024 <= int(port) <= 65535:
        raise IsolatedQualificationError("qualification authority port is invalid")
    state_root.mkdir(parents=True, exist_ok=True)
    context_path = state_root / CONTEXT_FILENAME
    private_path = state_root / PRIVATE_STATE_FILENAME
    fixture_path = state_root / FIXTURE_FILENAME
    expected_files = {
        CONTEXT_FILENAME,
        PRIVATE_STATE_FILENAME,
        FIXTURE_FILENAME,
        CA_FILENAME,
        SERVER_CERT_FILENAME,
        SERVER_KEY_FILENAME,
        LEASE_KEY_FILENAME,
    }
    existing_names = {child.name for child in state_root.iterdir()}
    if existing_names:
        if not expected_files.issubset(existing_names) or not existing_names.issubset(
            expected_files | {STATUS_FILENAME}
        ):
            raise IsolatedQualificationError(
                "qualification authority state is partial or contains foreign entries"
            )
        context = load_isolated_qualification_context(context_path)
        _validate_private_state(
            _read_json_object(private_path), context.authority_instance_id
        )
        status = "REUSED"
    else:
        instance_id = f"qualification-{uuid.uuid4().hex}"
        _generate_tls_material(state_root, instance_id)
        server_base_url = f"https://127.0.0.1:{int(port)}"
        context_payload = {
            "contract_version": CLIENT_CONTRACT_VERSION,
            "activation_mode": ACTIVATION_MODE,
            "authority_instance_id": instance_id,
            "created_at": _utc_text(),
            "machine_name": str(os.environ.get("COMPUTERNAME") or "").strip(),
            "operator_user_sid": str(operator_user_sid),
            "operator_local_app_data_root": str(
                Path(operator_local_app_data_root).resolve(strict=False)
            ),
            "state_root": str(state_root.resolve(strict=False)),
            "server_base_url": server_base_url,
            "endpoint_url": f"{server_base_url}{DEFAULT_ENDPOINT_PATH}",
            "ca_bundle_path": str((state_root / CA_FILENAME).resolve(strict=False)),
        }
        private_payload = {
            "contract_version": PRIVATE_STATE_CONTRACT_VERSION,
            "authority_instance_id": instance_id,
            "producer_secret": secrets.token_urlsafe(48),
            "logistics_token": secrets.token_urlsafe(48),
            "producer_key_id": f"qualification-key-{secrets.token_hex(8)}",
            "enrolled_producer_id": "",
            "enrolled_producer_install_id": "",
            "enrolled_possession_key_fingerprint": "",
            "runtime_next_request_token": "",
            "runtime_next_request_sequence": 0,
            "runtime_lease_id": "",
            "runtime_fence": 0,
        }
        _write_json(context_path, context_payload)
        _write_json(private_path, private_payload)
        _write_json(fixture_path, _fixture_payload())
        context = load_isolated_qualification_context(context_path)
        status = "INITIALIZED"
    report = {
        "report_version": "container-audit-isolated-qualification-initialize-v1",
        "status": status,
        "activation_mode": ACTIVATION_MODE,
        "source_test_mode": source_test_mode,
        "authority_instance_id": context.authority_instance_id,
        "state_root": context.state_root,
        "context_path": str(context_path.resolve(strict=False)),
        "fixture_path": str(fixture_path.resolve(strict=False)),
        "server_base_url": context.server_base_url,
        "endpoint_url": context.endpoint_url,
        "ca_bundle_path": context.ca_bundle_path,
        "loopback_only": True,
        "production_write_enabled": False,
        "committed_secret_present": False,
        "private_values_in_report": False,
    }
    _write_json(report_path, report)
    return report


class QualificationAuthority:
    def __init__(self, state_root: Path) -> None:
        self.state_root = state_root.resolve(strict=False)
        self.context = load_isolated_qualification_context(
            self.state_root / CONTEXT_FILENAME
        )
        self.private_path = self.state_root / PRIVATE_STATE_FILENAME
        self.private = _validate_private_state(
            _read_json_object(self.private_path), self.context.authority_instance_id
        )
        self.snapshot = _build_snapshot()
        lease_key_bytes = (self.state_root / LEASE_KEY_FILENAME).read_bytes()
        lease_key = serialization.load_pem_private_key(lease_key_bytes, password=None)
        if not isinstance(lease_key, ec.EllipticCurvePrivateKey):
            raise IsolatedQualificationError("qualification operation lease key is invalid")
        self.lease_key = lease_key
        self.lock = threading.RLock()
        self.counts = {
            "enrollment": 0,
            "runtime_lease": 0,
            "producer_ingest": 0,
            "catalog": 0,
            "operation_lease": 0,
            "health": 0,
            "rejected": 0,
        }
        self.started_at = _utc_text()

    def persist_private(self) -> None:
        _validate_private_state(self.private, self.context.authority_instance_id)
        _write_json(self.private_path, self.private)

    def record(self, name: str, *, rejected: bool = False) -> None:
        with self.lock:
            if name in self.counts:
                self.counts[name] += 1
            if rejected:
                self.counts["rejected"] += 1
            self.write_status("RUNNING")

    def write_status(self, status: str) -> None:
        _write_json(
            self.state_root / STATUS_FILENAME,
            {
                "contract_version": STATUS_CONTRACT_VERSION,
                "status": status,
                "authority_instance_id": self.context.authority_instance_id,
                "activation_mode": ACTIVATION_MODE,
                "pid": os.getpid(),
                "started_at": self.started_at,
                "observed_at": _utc_text(),
                "server_base_url": self.context.server_base_url,
                "loopback_only": True,
                "production_write_enabled": False,
                "request_counts": dict(self.counts),
                "payloads_retained": False,
                "private_values_present": False,
            },
        )

    def authenticate_logistics(self, headers: Mapping[str, str]) -> bool:
        token = str(self.private["logistics_token"])
        return hmac.compare_digest(str(headers.get("X-Logistics-API-Token") or ""), token) and hmac.compare_digest(
            str(headers.get("Authorization") or ""), f"Bearer {token}"
        )

    def authenticate_producer(
        self,
        *,
        canonical: str,
        headers: Mapping[str, str],
    ) -> bool:
        if not hmac.compare_digest(
            str(headers.get("X-Producer-Key-Id") or ""),
            str(self.private["producer_key_id"]),
        ):
            return False
        expected = hmac.new(
            str(self.private["producer_secret"]).encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(
            str(headers.get("X-Producer-Signature") or ""), expected
        )


class QualificationRequestHandler(BaseHTTPRequestHandler):
    server_version = "ContainerAuditQualification/1"
    protocol_version = "HTTP/1.1"

    @property
    def authority(self) -> QualificationAuthority:
        return self.server.authority  # type: ignore[attr-defined]

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _json(self, status: int, payload: Mapping[str, Any]) -> None:
        body = (json.dumps(dict(payload), ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _bytes(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _reject(self, code: str, *, status: int = 403) -> None:
        self.authority.record("rejected", rejected=False)
        self._json(
            status,
            {
                "ok": False,
                "committed": False,
                "retryable": False,
                "error": {"code": code, "message": "isolated qualification request rejected"},
            },
        )

    def _read_body(self, maximum: int) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError as exc:
            raise ValueError("content length is invalid") from exc
        if length <= 0 or length > maximum:
            raise ValueError("request body size is invalid")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("request body is incomplete")
        return body

    def _read_json(self) -> dict:
        body = self._read_body(MAX_JSON_REQUEST_BYTES)
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request JSON must be an object")
        return value

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/health/qualification" and not parsed.query:
            self.authority.record("health")
            self._json(
                200,
                {
                    "ok": True,
                    "status": "READY",
                    "contract_version": AUTHORITY_CONTRACT_VERSION,
                    "authority_instance_id": self.authority.context.authority_instance_id,
                    "activation_mode": ACTIVATION_MODE,
                    "loopback_only": True,
                    "production_write_enabled": False,
                },
            )
            return
        if parsed.path == "/inbound/api/item-catalog.csv" and not parsed.query:
            if not self.authority.authenticate_logistics(self.headers):
                self._reject("qualification_logistics_auth_failed")
                return
            self.authority.record("catalog")
            catalog = (
                "Item Code,Item Name,Spec,Tray Image\r\n"
                f"{QUALIFICATION_ITEM_CODE},Qualification L07,KMC_LHD,assets/KMC_LHD.png\r\n"
            ).encode("utf-8")
            self._bytes(200, catalog, "text/csv; charset=utf-8")
            return
        if parsed.path == "/logistics/api/v1/bundles/resolve":
            if not self.authority.authenticate_logistics(self.headers):
                self._reject("qualification_logistics_auth_failed")
                return
            query = parse_qs(parsed.query, keep_blank_values=True)
            accepted = {
                QUALIFICATION_INPUT_TAG,
                QUALIFICATION_INPUT_LABEL,
                QUALIFICATION_WORK_LABEL,
                QUALIFICATION_MASTER_QR,
                QUALIFICATION_SOURCE_QR,
            }
            supplied = {value for values in query.values() for value in values}
            if not supplied.intersection(accepted):
                self._reject("qualification_fixture_not_selected", status=404)
                return
            self._json(200, {"ok": True, "data": self.authority.snapshot})
            return
        self._reject("qualification_route_not_found", status=404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        try:
            if parsed.query:
                raise ValueError("queries are not accepted")
            if parsed.path == "/api/producer-ingest/v2/enroll":
                self._handle_enroll()
                return
            if parsed.path == "/api/producer-ingest/v1/runtime-lease":
                self._handle_runtime_lease()
                return
            if parsed.path == DEFAULT_ENDPOINT_PATH:
                self._handle_ingest()
                return
            if parsed.path == "/logistics/api/v1/operation-leases/issue":
                self._handle_operation_lease()
                return
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            self._reject("qualification_request_invalid", status=400)
            return
        self._reject("qualification_route_not_found", status=404)

    def _handle_enroll(self) -> None:
        if self.headers.get("X-Producer-Enrollment-Token"):
            self._reject("qualification_enrollment_token_forbidden")
            return
        request = self._read_json()
        manifest = request.get("manifest")
        if (
            request.get("contract_version") != SELF_ENROLLMENT_CONTRACT_VERSION
            or not isinstance(manifest, dict)
            or request.get("endpoint_url") != self.authority.context.endpoint_url
        ):
            raise ValueError("enrollment contract is invalid")
        possession_public_jwk = normalize_possession_public_jwk(
            request.get("possession_public_jwk")
        )
        possession_fingerprint = possession_jwk_thumbprint(
            possession_public_jwk
        )
        identity = manifest.get("pc_identity")
        if not isinstance(identity, dict):
            raise ValueError("enrollment identity is invalid")
        source_host_id = str(identity.get("source_host_id") or "").strip()
        device_id = str(identity.get("pc_id") or "").strip()
        producer_id = str(request.get("producer_id") or "").strip()
        if not source_host_id or not device_id or not producer_id:
            raise ValueError("enrollment identity is incomplete")
        expected_hash = manifest_hash(manifest)
        producer_install_id = str(identity.get("producer_install_id") or "").strip()
        if not producer_install_id:
            raise ValueError("enrollment install identity is incomplete")
        producer_secret = str(self.authority.private["producer_secret"])
        logistics_token = str(self.authority.private["logistics_token"])
        key_id = str(self.authority.private["producer_key_id"])
        with self.authority.lock:
            enrolled_producer_id = str(
                self.authority.private.get("enrolled_producer_id") or ""
            )
            enrolled_install_id = str(
                self.authority.private.get("enrolled_producer_install_id") or ""
            )
            enrolled_possession_fingerprint = str(
                self.authority.private.get(
                    "enrolled_possession_key_fingerprint"
                )
                or ""
            )
            if enrolled_producer_id or enrolled_install_id:
                if (
                    enrolled_producer_id != producer_id
                    or enrolled_install_id != producer_install_id
                    or enrolled_possession_fingerprint
                    != possession_fingerprint
                ):
                    self._reject(
                        "qualification_enrollment_identity_conflict",
                        status=409,
                    )
                    return
                self._reject("reattach_proof_required", status=409)
                return
            self.authority.private.update(
                {
                    "enrolled_producer_id": producer_id,
                    "enrolled_producer_install_id": producer_install_id,
                    "enrolled_possession_key_fingerprint": possession_fingerprint,
                }
            )
            self.authority.persist_private()
        self.authority.record("enrollment")
        self._json(
            200,
            {
                "contract_version": SELF_ENROLLMENT_CONTRACT_VERSION,
                "status": "enrolled",
                "identity_action": "CREATED",
                "authorization_state": "OPERATION_PENDING",
                "credential_epoch": 1,
                "producer_id": producer_id,
                "key_id": key_id,
                "secret": producer_secret,
                "secret_fingerprint_sha256": hashlib.sha256(
                    producer_secret.encode("utf-8")
                ).hexdigest(),
                "active_manifest_hashes": [expected_hash],
                "possession_key": {
                    "contract_version": POSSESSION_KEY_CONTRACT_VERSION,
                    "fingerprint": possession_fingerprint,
                },
                "server_binding": {
                    "mode": ACTIVATION_MODE,
                    "authority_instance_id": self.authority.context.authority_instance_id,
                },
                "machine_credential_bundle": {
                    "contract_version": MACHINE_CREDENTIAL_BUNDLE_CONTRACT_VERSION,
                    "bindings": {
                        "app": "ContainerAudit",
                        "program": "Container_Audit",
                        "source_host_id": source_host_id,
                        "device_id": device_id,
                        "authority_scope_id": QUALIFICATION_SCOPE,
                    },
                    "credentials": {
                        "producer_ingest": {
                            "audience": "producer-ingest-hmac-v1",
                            "auth_scheme": "hmac-sha256",
                            "key_id": key_id,
                            "secret": producer_secret,
                        },
                        "logistics": {
                            "audience": "worker-analysis-logistics-v1",
                            "auth_scheme": "bearer",
                            "token_header": "X-Logistics-API-Token",
                            "token": logistics_token,
                        },
                    },
                    "profiles": {
                        "logistics": {
                            "contract_version": "km-logistics-runtime-profile-v1",
                            "base_url": self.authority.context.server_base_url,
                            "authority_scope": QUALIFICATION_SCOPE,
                            "authority_epoch": 1,
                            "authority_plane": "AUTHORITATIVE",
                            "ledger_plane": "AUTHORITATIVE",
                            "plane_epoch": 1,
                            "device_id": device_id,
                            "source_host_id": source_host_id,
                            "timeout_seconds": 10.0,
                        }
                    },
                },
            },
        )

    def _handle_runtime_lease(self) -> None:
        request = self._read_json()
        canonical = runtime_canonical_request(
            timestamp=str(self.headers.get("X-Producer-Timestamp") or ""),
            nonce=str(self.headers.get("X-Producer-Nonce") or ""),
            producer_id=str(self.headers.get("X-Producer-Id") or ""),
            key_id=str(self.headers.get("X-Producer-Key-Id") or ""),
            body=request,
        )
        if not self.authority.authenticate_producer(canonical=canonical, headers=self.headers):
            self._reject("qualification_producer_auth_failed")
            return
        runtime_id = str(request.get("runtime_instance_id") or "").strip()
        public_jwk = request.get("public_jwk")
        install_id = str(
            self.authority.private.get("enrolled_producer_install_id") or ""
        ).strip()
        enrolled_producer_id = str(
            self.authority.private.get("enrolled_producer_id") or ""
        ).strip()
        if (
            not runtime_id
            or not isinstance(public_jwk, dict)
            or not install_id
            or enrolled_producer_id != str(self.headers.get("X-Producer-Id") or "")
        ):
            raise ValueError("runtime lease request is incomplete")
        with self.authority.lock:
            stored_sequence = int(
                self.authority.private.get("runtime_next_request_sequence") or 0
            )
            stored_token = str(
                self.authority.private.get("runtime_next_request_token") or ""
            )
            supplied_sequence = int(request.get("runtime_request_sequence") or 0)
            supplied_token = str(request.get("runtime_request_token") or "")
            renewing = bool(stored_token)
            if renewing and (
                supplied_sequence != stored_sequence
                or not hmac.compare_digest(supplied_token, stored_token)
            ):
                self._reject("STALE_RUNTIME_REQUEST_TOKEN", status=409)
                return
            next_sequence = supplied_sequence + 1
            next_token = secrets.token_urlsafe(32)[:43]
            lease_id = str(self.authority.private.get("runtime_lease_id") or "") or (
                f"qualification-runtime-{uuid.uuid4().hex}"
            )
            fence = int(self.authority.private.get("runtime_fence") or 0) or 1
            self.authority.private.update(
                {
                    "runtime_next_request_token": next_token,
                    "runtime_next_request_sequence": next_sequence,
                    "runtime_lease_id": lease_id,
                    "runtime_fence": fence,
                }
            )
            self.authority.persist_private()
        now = _utc_now()
        self.authority.record("runtime_lease")
        self._json(
            200,
            {
                "ok": True,
                "status": "ACTIVE",
                "contract_version": RUNTIME_LEASE_CONTRACT_VERSION,
                "operation": "renewed" if renewing else "issued",
                "lease_id": lease_id,
                "producer_install_id": install_id,
                "runtime_instance_id": runtime_id,
                "public_jwk_thumbprint": _jwk_thumbprint(public_jwk),
                "issue_idempotency_key": request["issue_idempotency_key"],
                "fence": fence,
                "issued_at": _utc_text(now),
                "expires_at": _utc_text(now + timedelta(minutes=30)),
                "next_request_token": next_token,
                "next_request_sequence": next_sequence,
            },
        )

    def _multipart_parts(self, body: bytes) -> tuple[dict, bytes]:
        content_type = str(self.headers.get("Content-Type") or "")
        message = BytesParser(policy=email_policy).parsebytes(
            b"Content-Type: "
            + content_type.encode("ascii")
            + b"\r\nMIME-Version: 1.0\r\n\r\n"
            + body
        )
        metadata = None
        file_bytes = None
        for part in message.iter_parts():
            disposition = part.get("Content-Disposition", "")
            name = part.get_param("name", header="Content-Disposition")
            if "form-data" not in disposition:
                continue
            payload = part.get_payload(decode=True) or b""
            if name == "metadata":
                metadata = json.loads(payload.decode("utf-8"))
            elif name == "file":
                file_bytes = payload
        if not isinstance(metadata, dict) or file_bytes is None:
            raise ValueError("multipart request fields are missing")
        return metadata, file_bytes

    def _handle_ingest(self) -> None:
        body = self._read_body(MAX_MULTIPART_REQUEST_BYTES)
        metadata, file_bytes = self._multipart_parts(body)
        canonical = canonical_request_string(
            method="POST",
            path=DEFAULT_ENDPOINT_PATH,
            query_string="",
            timestamp=str(self.headers.get("X-Producer-Timestamp") or ""),
            nonce=str(self.headers.get("X-Producer-Nonce") or ""),
            producer_id=str(self.headers.get("X-Producer-Id") or ""),
            key_id=str(self.headers.get("X-Producer-Key-Id") or ""),
            metadata=metadata,
            content_sha256=str(metadata.get("content_sha256") or ""),
            byte_length=int(metadata.get("byte_length") or 0),
            content_type="multipart/form-data",
        )
        if not self.authority.authenticate_producer(canonical=canonical, headers=self.headers):
            self._reject("qualification_producer_auth_failed")
            return
        if len(file_bytes) != int(metadata.get("byte_length") or -1) or hashlib.sha256(
            file_bytes
        ).hexdigest() != str(metadata.get("content_sha256") or ""):
            raise ValueError("uploaded file identity differs from metadata")
        with self.authority.lock:
            current_token = str(
                self.authority.private.get("runtime_next_request_token") or ""
            )
            current_sequence = int(
                self.authority.private.get("runtime_next_request_sequence") or 0
            )
            if not current_token or not hmac.compare_digest(
                str(metadata.get("runtime_request_token") or ""), current_token
            ) or int(metadata.get("runtime_request_sequence") or -1) != current_sequence:
                self._reject("STALE_RUNTIME_REQUEST_TOKEN", status=409)
                return
            next_token = secrets.token_urlsafe(32)[:43]
            next_sequence = current_sequence + 1
            self.authority.private["runtime_next_request_token"] = next_token
            self.authority.private["runtime_next_request_sequence"] = next_sequence
            self.authority.persist_private()
        request_id = f"qualification-ingest-{uuid.uuid4().hex}"
        server_source_file_id = (
            f"{metadata['source_host_id']}/{metadata['producer_role']}/"
            f"{metadata['stream_name']}/{metadata['relative_path']}"
        )
        row_count = int(metadata.get("row_count") or 0)
        self.authority.record("producer_ingest")
        self._json(
            200,
            {
                "request_id": request_id,
                "upload_id": request_id,
                "producer_install_id": metadata["producer_install_id"],
                "client_batch_id": metadata["client_batch_id"],
                "server_source_file_id": server_source_file_id,
                "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {
                    "inserted": row_count,
                    "replayed": 0,
                    "quarantined": 0,
                    "errors": 0,
                },
                "runtime_lease": {
                    "contract_version": RUNTIME_LEASE_CONTRACT_VERSION,
                    "validation_status": "consumed",
                    "lease_id": self.authority.private["runtime_lease_id"],
                    "fence": int(metadata["runtime_fence"]),
                    "next_request_token": next_token,
                    "next_request_sequence": next_sequence,
                    "expires_at": _utc_text(_utc_now() + timedelta(minutes=30)),
                },
            },
        )

    def _handle_operation_lease(self) -> None:
        if not self.authority.authenticate_logistics(self.headers):
            self._reject("qualification_logistics_auth_failed")
            return
        request = self._read_json()
        if (
            request.get("authority_scope_id") != QUALIFICATION_SCOPE
            or request.get("operation") != TRANSFER_OPERATION
            or request.get("scan_payload") != QUALIFICATION_MASTER_QR
            or not str(self.headers.get("Idempotency-Key") or "").strip()
        ):
            self._reject("qualification_fixture_not_selected", status=404)
            return
        source_host_id = str(self.headers.get("X-Logistics-Source-Host-Id") or "").strip()
        device_id = str(self.headers.get("X-Logistics-Device-Id") or "").strip()
        if not source_host_id or not device_id:
            raise ValueError("logistics identity is incomplete")
        artifact = _operation_lease_artifact(
            snapshot=self.authority.snapshot,
            scan_payload=QUALIFICATION_MASTER_QR,
            device_id=device_id,
            source_host_id=source_host_id,
            lease_key=self.authority.lease_key,
        )
        self.authority.record("operation_lease")
        self._json(200, {"ok": True, "data": artifact})


class QualificationHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], authority: QualificationAuthority):
        super().__init__(address, QualificationRequestHandler, bind_and_activate=False)
        self.authority = authority
        self.allow_reuse_address = False
        self.server_bind()
        self.server_activate()


def serve_authority(state_root: Path) -> int:
    authority = QualificationAuthority(state_root)
    parsed = urlsplit(authority.context.server_base_url)
    assert parsed.port is not None
    server = QualificationHTTPServer(("127.0.0.1", parsed.port), authority)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(
        certfile=str(state_root / SERVER_CERT_FILENAME),
        keyfile=str(state_root / SERVER_KEY_FILENAME),
    )
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    authority.write_status("RUNNING")
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        authority.write_status("STOPPED")
    return 0


def probe_authority(state_root: Path, report_path: Path) -> dict[str, Any]:
    context = load_isolated_qualification_context(state_root / CONTEXT_FILENAME)
    with requests.Session() as session:
        session.trust_env = False
        response = session.get(
            f"{context.server_base_url}/health/qualification",
            timeout=5,
            allow_redirects=False,
            verify=context.ca_bundle_path,
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise IsolatedQualificationError(
            "qualification authority health response is not JSON"
        ) from exc
    if (
        response.status_code != 200
        or not isinstance(payload, dict)
        or payload.get("status") != "READY"
        or payload.get("authority_instance_id") != context.authority_instance_id
        or payload.get("loopback_only") is not True
        or payload.get("production_write_enabled") is not False
    ):
        raise IsolatedQualificationError("qualification authority health proof failed")
    report = {
        "report_version": "container-audit-isolated-qualification-probe-v1",
        "status": "PASS",
        "authority_instance_id": context.authority_instance_id,
        "server_base_url": context.server_base_url,
        "context_path": str((state_root / CONTEXT_FILENAME).resolve(strict=False)),
        "ca_bundle_path": context.ca_bundle_path,
        "loopback_only": True,
        "production_write_enabled": False,
        "private_values_in_report": False,
        "observed_at": _utc_text(),
    }
    _write_json(report_path, report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Container_Audit Windows Sandbox isolated qualification authority"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    initialize = subparsers.add_parser("initialize")
    initialize.add_argument("--state-root", required=True)
    initialize.add_argument("--operator-user-sid", required=True)
    initialize.add_argument("--operator-local-app-data-root", required=True)
    initialize.add_argument("--port", type=int, default=DEFAULT_PORT)
    initialize.add_argument("--report-path", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--state-root", required=True)
    probe = subparsers.add_parser("probe")
    probe.add_argument("--state-root", required=True)
    probe.add_argument("--report-path", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        state_root = Path(args.state_root).resolve(strict=False)
        if args.command == "initialize":
            report = initialize_authority(
                state_root=state_root,
                operator_user_sid=args.operator_user_sid,
                operator_local_app_data_root=args.operator_local_app_data_root,
                port=args.port,
                report_path=Path(args.report_path).resolve(strict=False),
            )
            print(f"qualification_authority_initialize={report['status']}")
            print(f"qualification_authority_report={Path(args.report_path).resolve(strict=False)}")
            return 0
        if args.command == "serve":
            return serve_authority(state_root)
        if args.command == "probe":
            probe_authority(
                state_root,
                Path(args.report_path).resolve(strict=False),
            )
            print("qualification_authority_probe=PASS")
            print(f"qualification_authority_report={Path(args.report_path).resolve(strict=False)}")
            return 0
    except Exception as exc:
        print(
            f"BLOCKED: isolated qualification authority failed: {exc.__class__.__name__}: {exc}",
            file=sys.stderr,
        )
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

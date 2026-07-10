#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Register this PC's local Container_Audit producer identity without storing raw secrets."""

from __future__ import annotations

import argparse
import ctypes
import datetime as _dt
import json
import os
import secrets
import socket
import sys
import uuid
from ctypes import wintypes
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402

from direct_sync_push import (  # noqa: E402
    DEFAULT_PRODUCER_ROLE,
    DEFAULT_SOURCE_SYSTEM,
    DEFAULT_SOURCE_TRANSPORT,
    DEFAULT_STREAM_NAME,
    DirectSyncPushError,
    validate_endpoint_url,
)
from direct_sync_runtime import _safe_secret_ref_name, _wincred_target_name  # noqa: E402
from storage_policy import (  # noqa: E402
    build_container_audit_storage_paths,
    ensure_container_audit_storage_dirs,
    is_legacy_syncthing_path,
)
from storage_utils import atomic_write_json  # noqa: E402


DEFAULT_ENDPOINT_URL = "https://worker.kmtecherp.com/api/producer-ingest/v1/source-file"
SELF_ENROLLMENT_CONTRACT_VERSION = "producer-self-enrollment-v1"
DEFAULT_ENROLLMENT_TOKEN_ENV = "CONTAINER_AUDIT_ENROLLMENT_TOKEN"
CRYPTPROTECT_LOCAL_MACHINE = 0x4
CONTAINER_AUDIT_APP = "ContainerAudit"
CONTAINER_AUDIT_RAW_EVENTS = [
    "CONTAINER_AUDIT_OBSERVED",
    "TRANSFER_WAITING_OBSERVED",
    "WORK_START",
    "MASTER_LABEL_SCANNED",
    "MASTER_LABEL_SCANNED_NEW",
    "MASTER_LABEL_SCANNED_OLD",
    "SCAN_OK",
    "SCAN_FAIL_DUPLICATE",
    "TRAY_COMPLETE",
    "TRAY_DISCARDED_BY_OPERATOR",
    "TRAY_RESET",
    "MASTER_LABEL_REPLACEMENT_APPLIED",
    "WORK_END",
]


def _default_app_root() -> str:
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve().parent)
    return str(ROOT)


def _slug(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    parts = [part for part in cleaned.split("-") if part]
    return "-".join(parts) or "unknown"


def _default_secret_ref(hostname: str) -> str:
    return f"dpapi:KMTech.DirectSync.ContainerAudit.{_slug(hostname)}"


def _validate_secret_ref(secret_ref: str) -> tuple[str, str]:
    if ":" not in secret_ref:
        raise DirectSyncPushError("secret_ref must start with env:, dpapi:, or wincred:")
    scheme, target = secret_ref.split(":", 1)
    scheme = scheme.lower()
    if scheme not in {"env", "dpapi", "wincred"}:
        raise DirectSyncPushError("secret_ref must start with env:, dpapi:, or wincred:")
    _safe_secret_ref_name(target)
    return scheme, target


def _path_text(path: Path) -> str:
    return path.expanduser().resolve(strict=False).as_posix()


def _health_url_from_endpoint(endpoint_url: str) -> str:
    parsed = urlparse(endpoint_url)
    return f"{parsed.scheme}://{parsed.netloc}/health/ingest"


def _default_enrollment_url(endpoint_url: str) -> str:
    parsed = urlparse(endpoint_url)
    return f"{parsed.scheme}://{parsed.netloc}/api/producer-ingest/v1/enroll"


def _validate_enrollment_url(enrollment_url: str, endpoint_url: str) -> str:
    validate_endpoint_url(endpoint_url)
    parsed_endpoint = urlparse(endpoint_url)
    parsed_enrollment = urlparse(str(enrollment_url or "").strip())
    if (
        parsed_enrollment.scheme != "https"
        or parsed_enrollment.netloc != parsed_endpoint.netloc
        or parsed_enrollment.username
        or parsed_enrollment.password
        or parsed_enrollment.fragment
        or parsed_enrollment.path != "/api/producer-ingest/v1/enroll"
    ):
        raise DirectSyncPushError("enrollment_url must be HTTPS, same-origin, and use /api/producer-ingest/v1/enroll")
    return parsed_enrollment.geturl()


def _legacy_path_block_report(field_name: str, path: str | os.PathLike[str]) -> dict | None:
    raw_path = str(path or "").strip()
    if raw_path and is_legacy_syncthing_path(raw_path):
        return {
            "field": field_name,
            "path": str(Path(raw_path).expanduser().resolve(strict=False)),
            "blocked_reason": f"{field_name} must not point at the legacy Syncthing folder",
        }
    return None


def _explicit_output_path_policy_report(args: argparse.Namespace) -> dict:
    checks = [
        _legacy_path_block_report("manifest_path", args.manifest_path),
        _legacy_path_block_report("credential_path", args.credential_path),
        _legacy_path_block_report("report_path", args.report_path),
    ]
    unsafe_paths = [check for check in checks if check]
    return {
        "status": "PASS" if not unsafe_paths else "FAIL",
        "unsafe_paths": unsafe_paths,
        "blocked_reason": "" if not unsafe_paths else "; ".join(item["blocked_reason"] for item in unsafe_paths),
    }


def _build_container_audit_manifest(
    *,
    hostname: str,
    source_host_id: str,
    producer_install_id: str,
    endpoint_url: str,
    secret_ref: str,
    storage_paths,
    identity_registry_status: str,
) -> dict:
    data_dir = _path_text(storage_paths.direct_sync_root)
    sync_dir = _path_text(storage_paths.events_dir)
    queue_dir = _path_text(storage_paths.direct_sync_root / "relay_queue")
    client_state_db = _path_text(storage_paths.direct_sync_root / "relay_state.sqlite3")
    source_host_example = source_host_id
    stream = {
        "stream_name": DEFAULT_STREAM_NAME,
        "source_system": DEFAULT_SOURCE_SYSTEM,
        "source_transport": DEFAULT_SOURCE_TRANSPORT,
        "raw_event_names": CONTAINER_AUDIT_RAW_EVENTS,
        "quantity_basis": "PRODUCT_BARCODE",
        "barcode_policy": "legacy_low_confidence_without_barcode",
        "hmac_required": False,
        "hash_chain_required": False,
        "producer_role": DEFAULT_PRODUCER_ROLE,
        "source_transport_or_dataset": DEFAULT_SOURCE_TRANSPORT,
        "dispatch_key_fields": ["source_system", "source_transport_or_dataset", "raw_event_name"],
        "source_lineage_fields": [
            "source_host_id",
            "source_file_id",
            "source_file_hash",
            "source_row_number",
            "source_byte_offset",
            "legacy_row_locator",
            "row_hash",
        ],
        "source_file_id_policy": {
            "format": "<source_host_id>/<producer_role>/<stream_name>/<relative_path_under_stream_root>",
            "example": f"{source_host_example}/{DEFAULT_PRODUCER_ROLE}/{DEFAULT_STREAM_NAME}/sample.csv",
            "legacy_sync_wrapper_format": "<source_host_id>:<parent_hash>:<filename>",
            "legacy_sync_wrapper_status": "not_canonical_for_batch1_onboarding",
        },
        "temp_file_exclusion_policy": {
            "excluded_suffixes": [".tmp", ".partial", ".crdownload"],
            "excluded_prefixes": ["~", "."],
        },
        "conflict_file_exclusion_policy": {
            "excluded_name_contains": ["sync-conflict"],
            "excluded_dirs": [".stfolder"],
        },
        "stability_window_policy": {
            "minimum_stable_seconds": 30,
            "requires_size_and_mtime_unchanged": True,
        },
        "replay_policy": {
            "idempotency_key": ["source_system", "event_identity"],
            "same_payload_hash": "replay",
            "same_legacy_row_locator_different_row_hash": "append_only_correction_required",
            "conflict_without_correction": "quarantine",
        },
    }
    return {
        "schema_version": "producer-onboarding-manifest-v1",
        "pc_identity": {
            "pc_id": hostname,
            "source_host_id": source_host_id,
            "producer_install_id": producer_install_id,
        },
        "apps": [CONTAINER_AUDIT_APP],
        "streams": [stream],
        "sync": {
            "sync_transport": "http_push",
            "sync_dir": sync_dir,
            "server_ingest_target": endpoint_url,
            "auth": {
                "method": "producer_hmac_v1",
                "secret_ref": secret_ref,
                "secret_material_persisted": False,
            },
            "queue": {
                "queue_dir": queue_dir,
                "client_state_db": client_state_db,
                "allowed_streams": [DEFAULT_STREAM_NAME],
                "status": "operator_supplied_uncontacted",
            },
            "fallback": {
                "sync_dir_preserved": True,
                "syncthing_folder_id_required": False,
            },
            "status": "operator_supplied_uncontacted",
        },
        "paths": {
            "data_dir": data_dir,
            "evidence_dir": _path_text(storage_paths.direct_sync_root / "evidence"),
            "rollback_dir": _path_text(storage_paths.direct_sync_root / "rollback"),
        },
        "server": {
            "health_target": _health_url_from_endpoint(endpoint_url),
            "contacted": False,
        },
        "identity_registry": {
            "required_for_pass": True,
            "status": identity_registry_status,
            "source_host_id_unique": identity_registry_status == "checked",
        },
        "hmac_gate": {
            "required": False,
            "registry_status": "not_required",
            "key_fingerprint": None,
            "fixture_verifier_status": "not_required",
            "hash_chain_status": "not_required",
            "row_verifier_status": "not_required",
            "row_verifier_id": None,
            "row_verifier_code_hash": None,
            "row_verifier_receipt_hash": None,
            "row_verifier_evidence_hash": None,
            "decision": "not_required",
        },
        "plan_b_invariants": {
            "product_barcode_priority": True,
            "source_csv_immutable": True,
            "append_only_correction_required": True,
            "quarantine_projection_business_separated": True,
            "no_erp_write": True,
            "shipping_waiting_is_no_shipping_evidence": True,
        },
        "rollback": {
            "sync_dir_preserve": True,
        },
    }


def _write_wincred_secret(target_name: str, secret: str) -> None:
    if sys.platform != "win32":
        raise DirectSyncPushError("wincred secret bootstrap requires Windows")

    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class Credential(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", FileTime),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.c_void_p),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    secret_bytes = secret.encode("utf-8")
    secret_buffer = ctypes.create_string_buffer(secret_bytes)
    credential = Credential()
    credential.Type = 1  # CRED_TYPE_GENERIC
    credential.TargetName = target_name
    credential.CredentialBlobSize = len(secret_bytes)
    credential.CredentialBlob = ctypes.cast(secret_buffer, ctypes.c_void_p)
    credential.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE
    credential.UserName = "producer"
    if not ctypes.windll.advapi32.CredWriteW(ctypes.byref(credential), 0):
        raise DirectSyncPushError("wincred secret bootstrap failed")


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.c_void_p)]


def _dpapi_protect_machine(secret: str) -> bytes:
    if sys.platform != "win32":
        raise DirectSyncPushError("dpapi secret bootstrap requires Windows")
    from ctypes import byref

    secret_bytes = secret.encode("utf-8")
    input_buffer = ctypes.create_string_buffer(secret_bytes, len(secret_bytes))
    input_blob = _DataBlob(len(secret_bytes), ctypes.cast(input_buffer, ctypes.c_void_p))
    output_blob = _DataBlob()
    if not ctypes.windll.crypt32.CryptProtectData(
        byref(input_blob),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_LOCAL_MACHINE,
        byref(output_blob),
    ):
        raise DirectSyncPushError("dpapi secret bootstrap failed")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.c_void_p(output_blob.pbData))


def _dpapi_unprotect_current_user(protected: bytes) -> str:
    if sys.platform != "win32":
        raise DirectSyncPushError("dpapi secret verify requires Windows")
    from ctypes import byref

    input_buffer = ctypes.create_string_buffer(protected, len(protected))
    input_blob = _DataBlob(len(protected), ctypes.cast(input_buffer, ctypes.c_void_p))
    output_blob = _DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(byref(input_blob), None, None, None, None, 0, byref(output_blob)):
        raise DirectSyncPushError("dpapi secret verify failed")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.c_void_p(output_blob.pbData))


def _write_dpapi_secret(data_dir: str | os.PathLike[str], target_name: str, secret: str) -> Path:
    safe_name = _safe_secret_ref_name(target_name)
    base_dir = Path(data_dir).expanduser().resolve()
    if is_legacy_syncthing_path(base_dir):
        raise DirectSyncPushError("secret_data_dir must not point at the legacy Syncthing folder")
    secret_path = base_dir / "secrets" / f"{safe_name}.dpapi"
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_bytes(_dpapi_protect_machine(secret))
    if _dpapi_unprotect_current_user(secret_path.read_bytes()) != secret:
        raise DirectSyncPushError("dpapi secret verify failed")
    return secret_path


def _bootstrap_secret_ref(
    *,
    secret_ref_scheme: str,
    secret_ref_target: str,
    credential: dict,
    secret: str,
) -> dict:
    if secret_ref_scheme == "wincred":
        _write_wincred_secret(_wincred_target_name(secret_ref_target), secret)
        return {"secret_ref_scheme": "wincred"}
    if secret_ref_scheme == "dpapi":
        secret_data_dir = str(credential.get("secret_data_dir") or "").strip()
        if not secret_data_dir:
            raise DirectSyncPushError("dpapi secret bootstrap requires secret_data_dir")
        secret_path = _write_dpapi_secret(secret_data_dir, secret_ref_target, secret)
        return {
            "secret_ref_scheme": "dpapi",
            "secret_data_dir": str(Path(secret_data_dir).expanduser().resolve()),
            "secret_artifact_path": str(secret_path),
        }
    raise DirectSyncPushError("self-enroll secret bootstrap requires dpapi: or wincred: secret_ref")


def _self_enroll(
    args: argparse.Namespace,
    manifest: dict,
    credential: dict,
    secret_ref_scheme: str,
    secret_ref_target: str,
) -> tuple[dict, dict]:
    token = args.enrollment_token or os.getenv(args.enrollment_token_env or DEFAULT_ENROLLMENT_TOKEN_ENV, "")
    enrollment_url = _validate_enrollment_url(
        args.enrollment_url or _default_enrollment_url(credential["endpoint_url"]),
        credential["endpoint_url"],
    )
    payload = {
        "contract_version": SELF_ENROLLMENT_CONTRACT_VERSION,
        "producer_id": credential["producer_id"],
        "key_id": credential["key_id"],
            "endpoint_url": credential["endpoint_url"],
            "manifest": manifest,
        }
    headers = {}
    if token:
        headers["X-Producer-Enrollment-Token"] = token
    response = requests.post(
        enrollment_url,
        json=payload,
        headers=headers,
        timeout=max(1, int(args.enrollment_timeout_seconds)),
    )
    try:
        response_payload = response.json()
    except ValueError as exc:
        raise DirectSyncPushError(f"self-enroll response is not JSON: HTTP {response.status_code}") from exc
    if response.status_code >= 400:
        code = str((response_payload.get("error") or {}).get("code") or response.status_code)
        raise DirectSyncPushError(f"self-enroll failed: {code}")
    secret = str(response_payload.get("secret") or "")
    if not secret:
        secret_hex = str(response_payload.get("secret_hex") or "").strip()
        try:
            secret = bytes.fromhex(secret_hex).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise DirectSyncPushError("self-enroll response missing valid secret") from exc
    if not secret.strip():
        raise DirectSyncPushError("self-enroll response missing valid secret")
    bootstrap_report = _bootstrap_secret_ref(
        secret_ref_scheme=secret_ref_scheme,
        secret_ref_target=secret_ref_target,
        credential=credential,
        secret=secret,
    )
    credential = dict(credential)
    credential["producer_id"] = str(response_payload.get("producer_id") or credential["producer_id"])
    credential["key_id"] = str(response_payload.get("key_id") or credential["key_id"])
    return credential, {
        "server_registration_verified": True,
        "secret_bootstrap_verified": True,
        "enrollment_url": enrollment_url,
        "enrollment_status": response_payload.get("status"),
        "enrollment_authorization_mode": "token" if token else "server_ip_allowlist",
        "secret_fingerprint_sha256": response_payload.get("secret_fingerprint_sha256"),
        "server_binding": response_payload.get("server_binding") or {},
        "secret_bootstrap": bootstrap_report,
    }


def build_registration_payloads(args: argparse.Namespace) -> tuple[dict, dict, dict]:
    hostname = args.hostname or socket.gethostname()
    host_slug = _slug(hostname)
    node_id = f"{uuid.getnode():012x}"
    source_host_id = args.source_host_id or f"container-audit-{host_slug}"
    producer_install_id = args.producer_install_id or f"container-audit-{host_slug}-{node_id}"
    producer_id = args.producer_id or source_host_id
    key_id = args.key_id or f"pending-server-key-{host_slug}"
    secret_ref = args.secret_ref or _default_secret_ref(hostname)
    endpoint_url = args.endpoint_url or DEFAULT_ENDPOINT_URL
    validate_endpoint_url(endpoint_url)
    secret_ref_scheme, secret_ref_target = _validate_secret_ref(secret_ref)

    storage_paths = build_container_audit_storage_paths(application_path=args.app_root)
    ensure_container_audit_storage_dirs(storage_paths)
    captured_at = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()

    manifest = _build_container_audit_manifest(
        hostname=hostname,
        source_host_id=source_host_id,
        producer_install_id=producer_install_id,
        endpoint_url=endpoint_url,
        secret_ref=secret_ref,
        storage_paths=storage_paths,
        identity_registry_status="checked" if bool(getattr(args, "self_enroll", False)) else "missing",
    )
    credential = {
        "credential_schema_version": "producer-ingest-credential-reference-v1",
        "created_at": captured_at,
        "producer_id": producer_id,
        "key_id": key_id,
        "secret_ref": secret_ref,
        "endpoint_url": endpoint_url,
    }
    if secret_ref_scheme == "dpapi":
        credential["secret_data_dir"] = str(storage_paths.direct_sync_root)
    report = {
        "report_version": "container-audit-worker-pc-registration-v1",
        "status": "LOCAL_REGISTRATION_WRITTEN_PENDING_SECRET",
        "captured_at": captured_at,
        "hostname": hostname,
        "source_host_id": source_host_id,
        "producer_install_id": producer_install_id,
        "producer_id": producer_id,
        "key_id": key_id,
        "endpoint_url": endpoint_url,
        "secret_ref_scheme": secret_ref_scheme,
        "secret_ref_target": secret_ref_target,
        "raw_secret_written": False,
        "server_registration_verified": False,
        "secret_bootstrap_verified": False,
        "self_enrollment_requested": bool(getattr(args, "self_enroll", False)),
        "local_storage": {
            "data_root": str(storage_paths.data_root),
            "events_dir": str(storage_paths.events_dir),
            "direct_sync_root": str(storage_paths.direct_sync_root),
            "syncthing_dependency": False,
        },
        "next_required_external_step": (
            "Run self-enrollment during install, or issue/register the producer key on the server "
            "and provision the matching secret into the referenced Windows credential target."
        ),
    }
    if getattr(args, "self_enroll", False):
        credential, enrollment_report = _self_enroll(
            args,
            manifest,
            credential,
            secret_ref_scheme,
            secret_ref_target,
        )
        report.update(enrollment_report)
        report["status"] = "SELF_ENROLLMENT_REGISTERED"
        report["next_required_external_step"] = "Run direct-sync relay and verify upload receipt."
    return manifest, credential, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register local Container_Audit producer identity for this PC")
    parser.add_argument("--app-root", default=_default_app_root())
    parser.add_argument("--endpoint-url", default=DEFAULT_ENDPOINT_URL)
    parser.add_argument("--hostname", default="")
    parser.add_argument("--source-host-id", default="")
    parser.add_argument("--producer-install-id", default="")
    parser.add_argument("--producer-id", default="")
    parser.add_argument("--key-id", default="")
    parser.add_argument("--secret-ref", default="")
    parser.add_argument("--self-enroll", action="store_true")
    parser.add_argument("--enrollment-url", default="")
    parser.add_argument("--enrollment-token", default="")
    parser.add_argument("--enrollment-token-env", default=DEFAULT_ENROLLMENT_TOKEN_ENV)
    parser.add_argument("--enrollment-timeout-seconds", type=int, default=30)
    parser.add_argument("--manifest-path", default="")
    parser.add_argument("--credential-path", default="")
    parser.add_argument("--report-path", default="")
    args = parser.parse_args(argv)

    output_path_policy = _explicit_output_path_policy_report(args)
    if output_path_policy["status"] != "PASS":
        blocked_report = {
            "report_version": "container-audit-worker-pc-registration-v1",
            "status": "BLOCKED",
            "blocked_reason": output_path_policy["blocked_reason"],
            "raw_secret_written": False,
            "output_path_policy": output_path_policy,
        }
        report_path_blocked = any(item["field"] == "report_path" for item in output_path_policy["unsafe_paths"])
        if args.report_path and not report_path_blocked:
            fallback_path = Path(args.report_path).expanduser()
            atomic_write_json(str(fallback_path), blocked_report, indent=2)
            print(f"registration_report={fallback_path.resolve()}")
        else:
            print(json.dumps(blocked_report, ensure_ascii=False, sort_keys=True))
        return 2

    try:
        manifest, credential, report = build_registration_payloads(args)
    except Exception as exc:
        fallback_path = Path(args.report_path).expanduser() if args.report_path else None
        blocked_report = {
            "report_version": "container-audit-worker-pc-registration-v1",
            "status": "BLOCKED",
            "blocked_reason": str(exc),
            "raw_secret_written": False,
        }
        if fallback_path:
            atomic_write_json(str(fallback_path), blocked_report, indent=2)
            print(f"registration_report={fallback_path.resolve()}")
        else:
            print(json.dumps(blocked_report, ensure_ascii=False, sort_keys=True))
        return 2

    storage_paths = build_container_audit_storage_paths(application_path=args.app_root)
    manifest_path = Path(args.manifest_path).expanduser() if args.manifest_path else storage_paths.producer_manifest_path
    credential_path = Path(args.credential_path).expanduser() if args.credential_path else storage_paths.credential_path
    report_path = Path(args.report_path).expanduser() if args.report_path else storage_paths.status_dir / "worker_pc_registration.json"
    report.update(
        {
            "producer_manifest_path": str(manifest_path.resolve()),
            "credential_path": str(credential_path.resolve()),
            "report_path": str(report_path.resolve()),
        }
    )

    atomic_write_json(str(manifest_path), manifest, indent=2)
    atomic_write_json(str(credential_path), credential, indent=2)
    atomic_write_json(str(report_path), report, indent=2)
    print(f"registration_report={report_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

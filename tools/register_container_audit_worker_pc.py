#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Register this PC's local Container_Audit producer identity without storing raw secrets."""

from __future__ import annotations

import argparse
import ctypes
import datetime as _dt
import hashlib
import json
import os
import re
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
    load_json_no_duplicate_keys,
    manifest_hash,
    validate_endpoint_url,
)
from direct_sync_runtime import _safe_secret_ref_name, _wincred_target_name  # noqa: E402
from storage_policy import (  # noqa: E402
    build_container_audit_storage_paths,
    ensure_container_audit_storage_dirs,
    is_legacy_syncthing_path,
)
from storage_utils import atomic_write_json  # noqa: E402
from tools.install_logistics_runtime_profile import (  # noqa: E402
    TLS_CA_BUNDLE_RELATIVE_PATH,
    default_profile_path,
    ensure_runtime_profile_from_enrollment_bundle,
)


DEFAULT_ENDPOINT_URL = "https://worker.kmtecherp.com/api/producer-ingest/v1/source-file"
SELF_ENROLLMENT_CONTRACT_VERSION = "producer-self-enrollment-v1"
DEFAULT_ENROLLMENT_TOKEN_ENV = "CONTAINER_AUDIT_ENROLLMENT_TOKEN"
CRYPTPROTECT_LOCAL_MACHINE = 0x4
CRYPTPROTECT_UI_FORBIDDEN = 0x1
CONTAINER_AUDIT_APP = "ContainerAudit"
CANONICAL_STREAM_CATALOG_RELATIVE = (
    Path("kmtech_factory_contracts") / "bundle" / "v1" / "catalogs" / "canonical-stream-catalog.json"
)
CONTAINER_AUDIT_CATALOG_APP_ID = "container_audit"
CONTAINER_AUDIT_CATALOG_STREAM_ID = "container_audit_events"
PRODUCER_IDENTITY_SCHEMA_VERSION = "container-audit-producer-identity-v1"
PRODUCER_IDENTITY_FILENAME = "producer_identity.json"
PRODUCER_IDENTITY_REQUIRED_FIELDS = ("producer_id", "source_host_id", "producer_install_id")
INSTALL_IDENTITY_DERIVATION_VERSION = "container-audit-install-identity-v1"
INSTALL_IDENTITY_APP_ID = "container_audit"
INSTALL_IDENTITY_HASH_HEX_LENGTH = 32


def _default_app_root() -> str:
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve().parent)
    return str(ROOT)


def _slug(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    parts = [part for part in cleaned.split("-") if part]
    return "-".join(parts) or "unknown"


def _normalize_machine_guid(value: str) -> str:
    try:
        return str(uuid.UUID(str(value or "").strip().strip("{}"))).lower()
    except (AttributeError, ValueError) as exc:
        raise DirectSyncPushError("Windows MachineGuid is unavailable or invalid") from exc


def _normalize_user_sid(value: str) -> str:
    normalized = str(value or "").strip().upper()
    parts = normalized.split("-")
    if (
        len(parts) < 4
        or parts[0] != "S"
        or parts[1] != "1"
        or any(not part.isdigit() for part in parts[2:])
    ):
        raise DirectSyncPushError("current Windows user SID is unavailable or invalid")
    return normalized


def _normalize_install_identity_app_id(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{1,63}", normalized):
        raise DirectSyncPushError("install identity app_id is invalid")
    return normalized


def _current_machine_guid() -> str:
    if os.name != "nt":
        raise DirectSyncPushError("Windows MachineGuid lookup is only available on Windows")
    try:
        import winreg

        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            access=access,
        ) as key:
            value, value_type = winreg.QueryValueEx(key, "MachineGuid")
    except (OSError, ImportError) as exc:
        raise DirectSyncPushError("Windows MachineGuid lookup failed") from exc
    if value_type not in {winreg.REG_SZ, winreg.REG_EXPAND_SZ}:
        raise DirectSyncPushError("Windows MachineGuid registry type is invalid")
    return _normalize_machine_guid(value)


def _current_user_sid() -> str:
    if os.name != "nt":
        raise DirectSyncPushError("Windows user SID lookup is only available on Windows")

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]

    class _TokenUser(ctypes.Structure):
        _fields_ = [("user", _SidAndAttributes)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_uint,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    )
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise DirectSyncPushError("current Windows user token lookup failed")
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        if required.value <= 0:
            raise DirectSyncPushError("current Windows user SID size lookup failed")
        token_buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            token_buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise DirectSyncPushError("current Windows user SID lookup failed")
        token_user = ctypes.cast(token_buffer, ctypes.POINTER(_TokenUser)).contents
        sid_text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(token_user.user.sid, ctypes.byref(sid_text)):
            raise DirectSyncPushError("current Windows user SID conversion failed")
        try:
            return _normalize_user_sid(sid_text.value)
        finally:
            kernel32.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(token)


def derive_path_independent_install_id(
    *,
    machine_guid: str,
    user_sid: str,
    app_id: str = INSTALL_IDENTITY_APP_ID,
) -> str:
    """Derive a lookup identity, not a possession proof, without filesystem inputs."""

    canonical = {
        "app_id": _normalize_install_identity_app_id(app_id),
        "machine_guid": _normalize_machine_guid(machine_guid),
        "user_sid": _normalize_user_sid(user_sid),
        "version": INSTALL_IDENTITY_DERIVATION_VERSION,
    }
    seed = json.dumps(
        canonical,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(seed).hexdigest()[:INSTALL_IDENTITY_HASH_HEX_LENGTH]
    return f"container-audit-install-{digest}"


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


def _validate_enrollment_url(
    enrollment_url: str,
    endpoint_url: str,
    *,
    isolated_qualification_context: object | None = None,
) -> str:
    if isolated_qualification_context is None:
        validate_endpoint_url(endpoint_url)
    parsed_endpoint = urlparse(endpoint_url)
    parsed_enrollment = urlparse(str(enrollment_url or "").strip())
    # A qualification run enrolls at the origin it will submit to, so the
    # credential it receives is issued by the server that must validate it.
    expected_scheme = (
        "https" if isolated_qualification_context is None else parsed_endpoint.scheme
    )
    if (
        parsed_enrollment.scheme != expected_scheme
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
        _legacy_path_block_report("producer_identity_path", getattr(args, "producer_identity_path", "")),
    ]
    unsafe_paths = [check for check in checks if check]
    return {
        "status": "PASS" if not unsafe_paths else "FAIL",
        "unsafe_paths": unsafe_paths,
        "blocked_reason": "" if not unsafe_paths else "; ".join(item["blocked_reason"] for item in unsafe_paths),
    }


def _canonical_stream_catalog_path() -> Path:
    return Path(_default_app_root()) / CANONICAL_STREAM_CATALOG_RELATIVE


def _container_audit_catalog_raw_event_names() -> list[str]:
    catalog_path = _canonical_stream_catalog_path()
    try:
        catalog = load_json_no_duplicate_keys(catalog_path.read_text(encoding="utf-8"))
    except DirectSyncPushError:
        raise
    except Exception as exc:
        raise DirectSyncPushError("bundled canonical-stream-catalog.json could not be read") from exc
    if not isinstance(catalog, dict):
        raise DirectSyncPushError("bundled canonical-stream-catalog.json must be a JSON object")
    streams = catalog.get("streams")
    if not isinstance(streams, list):
        raise DirectSyncPushError("canonical stream catalog streams must be a list")
    for stream in streams:
        if not isinstance(stream, dict):
            continue
        if (
            stream.get("app_id") == CONTAINER_AUDIT_CATALOG_APP_ID
            and stream.get("stream_id") == CONTAINER_AUDIT_CATALOG_STREAM_ID
        ):
            names = stream.get("raw_event_names")
            if not isinstance(names, list) or not names:
                raise DirectSyncPushError(
                    "container_audit catalog raw_event_names must be a non-empty list"
                )
            if not all(isinstance(name, str) and name.strip() for name in names):
                raise DirectSyncPushError("container_audit catalog raw_event_names must be names")
            if len(set(names)) != len(names):
                raise DirectSyncPushError("container_audit catalog raw_event_names must be unique")
            return list(names)
    raise DirectSyncPushError(
        "canonical stream catalog missing container_audit / container_audit_events"
    )


def _default_producer_identity_path(args: argparse.Namespace, storage_paths) -> Path:
    if str(getattr(args, "manifest_path", "") or "").strip():
        return Path(args.manifest_path).expanduser().parent / PRODUCER_IDENTITY_FILENAME
    return storage_paths.direct_sync_root / PRODUCER_IDENTITY_FILENAME


def _load_producer_identity_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise DirectSyncPushError("producer identity file is absent")
    size = path.stat().st_size
    if size <= 0 or size > 1024 * 1024:
        raise DirectSyncPushError("producer identity file size is invalid")
    try:
        payload = load_json_no_duplicate_keys(path.read_bytes())
    except DirectSyncPushError:
        raise
    except Exception as exc:
        raise DirectSyncPushError("producer identity file could not be read") from exc
    if not isinstance(payload, dict):
        raise DirectSyncPushError("producer identity file must be a JSON object")
    schema_version = str(payload.get("schema_version") or "").strip()
    if schema_version != PRODUCER_IDENTITY_SCHEMA_VERSION:
        raise DirectSyncPushError("producer identity file schema_version is invalid")
    identity: dict[str, str] = {}
    for field in PRODUCER_IDENTITY_REQUIRED_FIELDS:
        value = str(payload.get(field) or "").strip()
        if not value:
            raise DirectSyncPushError(f"producer identity file missing {field}")
        identity[field] = value
    return identity


def _persist_producer_identity_file(path: Path, *, producer_id: str, source_host_id: str, producer_install_id: str) -> None:
    atomic_write_json(
        str(path),
        {
            "schema_version": PRODUCER_IDENTITY_SCHEMA_VERSION,
            "producer_id": producer_id,
            "source_host_id": source_host_id,
            "producer_install_id": producer_install_id,
        },
        indent=2,
    )


def _resolve_producer_identity(
    args: argparse.Namespace,
    storage_paths,
    *,
    hostname: str,
    host_slug: str,
) -> dict[str, str]:
    generated_source_host_id = f"container-audit-{host_slug}"
    explicit_identity_path = str(getattr(args, "producer_identity_path", "") or "").strip()
    default_identity_path = _default_producer_identity_path(args, storage_paths)
    loaded: dict[str, str] | None = None
    loaded_from = ""
    if explicit_identity_path:
        identity_path = Path(explicit_identity_path).expanduser()
        loaded = _load_producer_identity_file(identity_path)
        loaded_from = str(identity_path.resolve(strict=False))
    elif default_identity_path.is_file():
        loaded = _load_producer_identity_file(default_identity_path)
        loaded_from = str(default_identity_path.expanduser().resolve(strict=False))

    cli_source_host_id = str(args.source_host_id or "").strip()
    cli_producer_install_id = str(args.producer_install_id or "").strip()
    cli_producer_id = str(args.producer_id or "").strip()
    source_host_id = cli_source_host_id or (loaded or {}).get("source_host_id") or generated_source_host_id
    producer_install_id = cli_producer_install_id or (loaded or {}).get("producer_install_id")
    if cli_producer_install_id:
        producer_install_id_derivation = "cli"
    elif loaded is not None:
        producer_install_id_derivation = "identity_file"
    else:
        producer_install_id = derive_path_independent_install_id(
            machine_guid=_current_machine_guid(),
            user_sid=_current_user_sid(),
        )
        producer_install_id_derivation = INSTALL_IDENTITY_DERIVATION_VERSION
    producer_id = cli_producer_id or (loaded or {}).get("producer_id") or source_host_id
    if cli_source_host_id or cli_producer_install_id or cli_producer_id:
        identity_source = "cli"
    elif loaded is not None:
        identity_source = "identity_file"
    else:
        identity_source = "generated"
    return {
        "hostname": hostname,
        "source_host_id": source_host_id,
        "producer_install_id": producer_install_id,
        "producer_id": producer_id,
        "identity_source": identity_source,
        "identity_loaded_from": loaded_from,
        "identity_persist_path": str(default_identity_path),
        "producer_install_id_derivation": producer_install_id_derivation,
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
        "raw_event_names": _container_audit_catalog_raw_event_names(),
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
        CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
        byref(output_blob),
    ):
        raise DirectSyncPushError("dpapi secret bootstrap failed")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.c_void_p(output_blob.pbData))


def _dpapi_protect_current_user(secret: str) -> bytes:
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
        CRYPTPROTECT_UI_FORBIDDEN,
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
    if not ctypes.windll.crypt32.CryptUnprotectData(
        byref(input_blob),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        byref(output_blob),
    ):
        raise DirectSyncPushError("dpapi secret verify failed")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.c_void_p(output_blob.pbData))


def _write_dpapi_secret(
    data_dir: str | os.PathLike[str],
    target_name: str,
    secret: str,
    *,
    credential_scope: str = "machine",
) -> Path:
    safe_name = _safe_secret_ref_name(target_name)
    base_dir = Path(data_dir).expanduser().resolve()
    if is_legacy_syncthing_path(base_dir):
        raise DirectSyncPushError("secret_data_dir must not point at the legacy Syncthing folder")
    secret_path = base_dir / "secrets" / f"{safe_name}.dpapi"
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    selected_scope = str(credential_scope or "").strip().lower()
    if selected_scope == "current_user":
        protected = _dpapi_protect_current_user(secret)
    elif selected_scope == "machine":
        protected = _dpapi_protect_machine(secret)
    else:
        raise DirectSyncPushError("credential_scope must be machine or current_user")
    secret_path.write_bytes(protected)
    if _dpapi_unprotect_current_user(secret_path.read_bytes()) != secret:
        raise DirectSyncPushError("dpapi secret verify failed")
    return secret_path


def _bootstrap_secret_ref(
    *,
    secret_ref_scheme: str,
    secret_ref_target: str,
    credential: dict,
    secret: str,
    credential_scope: str = "machine",
) -> dict:
    if secret_ref_scheme == "wincred":
        _write_wincred_secret(_wincred_target_name(secret_ref_target), secret)
        return {"secret_ref_scheme": "wincred"}
    if secret_ref_scheme == "dpapi":
        secret_data_dir = str(credential.get("secret_data_dir") or "").strip()
        if not secret_data_dir:
            raise DirectSyncPushError("dpapi secret bootstrap requires secret_data_dir")
        if credential_scope == "current_user":
            secret_path = _write_dpapi_secret(
                secret_data_dir,
                secret_ref_target,
                secret,
                credential_scope=credential_scope,
            )
        else:
            # Preserve the historical callable seam used by machine-scope
            # qualification fixtures; only the new user path needs the option.
            secret_path = _write_dpapi_secret(
                secret_data_dir,
                secret_ref_target,
                secret,
            )
        return {
            "secret_ref_scheme": "dpapi",
            "secret_data_dir": str(Path(secret_data_dir).expanduser().resolve()),
            "secret_artifact_path": str(secret_path),
            "credential_scope": credential_scope,
        }
    raise DirectSyncPushError("self-enroll secret bootstrap requires dpapi: or wincred: secret_ref")


def _self_enroll(
    args: argparse.Namespace,
    manifest: dict,
    credential: dict,
    secret_ref_scheme: str,
    secret_ref_target: str,
) -> tuple[dict, dict]:
    expected_manifest_hash = manifest_hash(manifest)
    token = args.enrollment_token or os.getenv(args.enrollment_token_env or DEFAULT_ENROLLMENT_TOKEN_ENV, "")
    enrollment_url = _validate_enrollment_url(
        args.enrollment_url or _default_enrollment_url(credential["endpoint_url"]),
        credential["endpoint_url"],
        isolated_qualification_context=getattr(
            args, "_isolated_qualification_context", None
        ),
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
    isolated_context = getattr(args, "_isolated_qualification_context", None)
    # The qualification CA signs the loopback authority alone, so enrolling at a
    # bound external origin keeps ordinary trust instead of that private root.
    authority_ca_bundle_path = (
        str(getattr(isolated_context, "ca_bundle_path", "") or "")
        if isolated_context is not None
        and credential["endpoint_url"]
        == str(getattr(isolated_context, "endpoint_url", "") or "")
        else ""
    )
    configured_ca_bundle_path = str(
        getattr(args, "tls_ca_bundle_path", "") or ""
    ).strip()
    if isolated_context is None:
        response = requests.post(
            enrollment_url,
            json=payload,
            headers=headers,
            timeout=max(1, int(args.enrollment_timeout_seconds)),
            allow_redirects=False,
            **(
                {"verify": configured_ca_bundle_path}
                if configured_ca_bundle_path
                else {}
            ),
        )
    else:
        with requests.Session() as session:
            session.trust_env = False
            response = session.post(
                enrollment_url,
                json=payload,
                headers=headers,
                timeout=max(1, int(args.enrollment_timeout_seconds)),
                allow_redirects=False,
                **({"verify": authority_ca_bundle_path} if authority_ca_bundle_path else {}),
            )
    try:
        response_payload = response.json()
    except ValueError as exc:
        raise DirectSyncPushError(f"self-enroll response is not JSON: HTTP {response.status_code}") from exc
    if response.status_code >= 400:
        code = str((response_payload.get("error") or {}).get("code") or response.status_code)
        raise DirectSyncPushError(f"self-enroll failed: {code}")
    active_manifest_hashes = response_payload.get("active_manifest_hashes")
    if (
        not isinstance(active_manifest_hashes, list)
        or expected_manifest_hash not in {
            str(value).strip().lower() for value in active_manifest_hashes
        }
    ):
        raise DirectSyncPushError(
            "self-enroll response does not authorize the requested manifest hash"
        )
    secret = str(response_payload.get("secret") or "")
    if not secret:
        secret_hex = str(response_payload.get("secret_hex") or "").strip()
        try:
            secret = bytes.fromhex(secret_hex).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise DirectSyncPushError("self-enroll response missing valid secret") from exc
    if not secret.strip():
        raise DirectSyncPushError("self-enroll response missing valid secret")
    identity = manifest["pc_identity"]
    preserve_existing_machine_profile = bool(
        getattr(args, "preserve_existing_machine_profile", False)
    )
    machine_profile = None
    if not preserve_existing_machine_profile:
        machine_profile = ensure_runtime_profile_from_enrollment_bundle(
            response_payload,
            expected_app=CONTAINER_AUDIT_APP,
            expected_program="Container_Audit",
            expected_source_host_id=str(identity["source_host_id"]),
            expected_device_id=str(identity["pc_id"]),
            profile_path=(
                str(getattr(args, "logistics_profile_path", "") or "").strip()
                or None
            ),
            tls_ca_bundle_path=(
                str(getattr(args, "tls_ca_bundle_path", "") or "").strip()
                or None
            ),
            credential_scope=str(
                getattr(args, "credential_scope", "machine") or "machine"
            ),
        )
    if machine_profile is None and bool(getattr(args, "require_machine_credential_bundle", False)):
        raise DirectSyncPushError("self-enroll response missing machine credential bundle")
    if configured_ca_bundle_path:
        if machine_profile is not None:
            selected_profile_path = (
                Path(str(getattr(args, "logistics_profile_path", "") or "")).expanduser()
                if str(getattr(args, "logistics_profile_path", "") or "").strip()
                else default_profile_path()
            )
            producer_ca_bundle_path = (
                selected_profile_path.resolve().parent / TLS_CA_BUNDLE_RELATIVE_PATH
            )
        else:
            producer_ca_bundle_path = Path(configured_ca_bundle_path).expanduser().resolve()
        credential["tls_ca_bundle_path"] = str(producer_ca_bundle_path)
    try:
        bootstrap_report = _bootstrap_secret_ref(
            secret_ref_scheme=secret_ref_scheme,
            secret_ref_target=secret_ref_target,
            credential=credential,
            secret=secret,
            credential_scope=str(
                getattr(args, "credential_scope", "machine") or "machine"
            ),
        )
    except Exception:
        for created_path in (machine_profile or {}).get("created_paths", []):
            Path(created_path).unlink(missing_ok=True)
        raise
    credential = dict(credential)
    credential["producer_id"] = str(response_payload.get("producer_id") or credential["producer_id"])
    credential["key_id"] = str(response_payload.get("key_id") or credential["key_id"])
    return credential, {
        "server_registration_verified": True,
        "manifest_hash_verified": True,
        "manifest_hash": expected_manifest_hash,
        "secret_bootstrap_verified": True,
        "enrollment_url": enrollment_url,
        "enrollment_status": response_payload.get("status"),
        "enrollment_authorization_mode": "token" if token else "server_ip_allowlist",
        "secret_fingerprint_sha256": response_payload.get("secret_fingerprint_sha256"),
        "server_binding": response_payload.get("server_binding") or {},
        "secret_bootstrap": bootstrap_report,
        "machine_profiles": {"logistics": machine_profile} if machine_profile else {},
        "machine_profile_mode": (
            "preserved_existing" if preserve_existing_machine_profile else "enrollment_bundle"
        ),
        "enrollment_tls_ca_bundle_configured": bool(
            authority_ca_bundle_path or configured_ca_bundle_path
        ),
        "producer_tls_ca_bundle_persisted": bool(
            credential.get("tls_ca_bundle_path")
        ),
    }


def build_registration_payloads(args: argparse.Namespace) -> tuple[dict, dict, dict]:
    hostname = args.hostname or socket.gethostname()
    host_slug = _slug(hostname)
    storage_paths = build_container_audit_storage_paths(application_path=args.app_root)
    ensure_container_audit_storage_dirs(storage_paths)
    identity = _resolve_producer_identity(
        args,
        storage_paths,
        hostname=hostname,
        host_slug=host_slug,
    )
    source_host_id = identity["source_host_id"]
    producer_install_id = identity["producer_install_id"]
    producer_id = identity["producer_id"]
    key_id = args.key_id or f"pending-server-key-{host_slug}"
    secret_ref = args.secret_ref or _default_secret_ref(hostname)
    endpoint_url = args.endpoint_url or DEFAULT_ENDPOINT_URL
    isolated_context = None
    isolated_context_path = str(
        getattr(args, "isolated_qualification_context", "") or ""
    ).strip()
    if isolated_context_path:
        try:
            from isolated_qualification import load_isolated_qualification_context

            isolated_context = load_isolated_qualification_context(
                isolated_context_path,
                expected_endpoint_url=endpoint_url,
            )
        except Exception as exc:
            raise DirectSyncPushError(
                f"isolated qualification context is invalid: {exc}"
            ) from exc
    else:
        validate_endpoint_url(endpoint_url)
    args._isolated_qualification_context = isolated_context
    secret_ref_scheme, secret_ref_target = _validate_secret_ref(secret_ref)
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
        credential["dpapi_scope"] = str(
            getattr(args, "credential_scope", "machine") or "machine"
        )
    if isolated_context is not None:
        credential["isolated_qualification_context_path"] = str(
            Path(isolated_context_path).expanduser().resolve()
        )
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
        "isolated_qualification_mode": isolated_context is not None,
        "isolated_qualification_authority_id": (
            str(isolated_context.authority_instance_id) if isolated_context is not None else ""
        ),
        "producer_identity_source": identity["identity_source"],
        "producer_identity_loaded_from": identity["identity_loaded_from"],
        "producer_identity_path": identity["identity_persist_path"],
        "producer_install_id_derivation": identity["producer_install_id_derivation"],
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
        report["producer_id"] = credential["producer_id"]
        report["key_id"] = credential["key_id"]
        report["status"] = "SELF_ENROLLMENT_REGISTERED"
        report["next_required_external_step"] = "Run direct-sync relay and verify upload receipt."
        persist_path = Path(identity["identity_persist_path"]).expanduser()
        _persist_producer_identity_file(
            persist_path,
            producer_id=str(report["producer_id"]),
            source_host_id=source_host_id,
            producer_install_id=producer_install_id,
        )
        report["producer_identity_path"] = str(persist_path.resolve())
        report["producer_identity_persisted"] = True
    return manifest, credential, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register local Container_Audit producer identity for this PC")
    parser.add_argument("--app-root", default=_default_app_root())
    parser.add_argument("--endpoint-url", default=DEFAULT_ENDPOINT_URL)
    parser.add_argument("--hostname", default="")
    parser.add_argument("--source-host-id", default="")
    parser.add_argument("--producer-install-id", default="")
    parser.add_argument("--producer-identity-path", default="")
    parser.add_argument("--producer-id", default="")
    parser.add_argument("--key-id", default="")
    parser.add_argument("--secret-ref", default="")
    parser.add_argument(
        "--credential-scope",
        choices=("machine", "current_user"),
        default="machine",
    )
    parser.add_argument("--logistics-profile-path", default="")
    parser.add_argument("--tls-ca-bundle-path", default="")
    parser.add_argument("--self-enroll", action="store_true")
    machine_profile_group = parser.add_mutually_exclusive_group()
    machine_profile_group.add_argument("--require-machine-credential-bundle", action="store_true")
    machine_profile_group.add_argument("--preserve-existing-machine-profile", action="store_true")
    parser.add_argument("--enrollment-url", default="")
    parser.add_argument("--enrollment-token", default="")
    parser.add_argument("--enrollment-token-env", default=DEFAULT_ENROLLMENT_TOKEN_ENV)
    parser.add_argument("--enrollment-timeout-seconds", type=int, default=30)
    parser.add_argument("--isolated-qualification-context", default="")
    parser.add_argument("--verify-manifest-hash", default="")
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

    if args.verify_manifest_hash:
        try:
            manifest_path = Path(args.manifest_path).expanduser()
            if not args.manifest_path or not manifest_path.is_file():
                raise DirectSyncPushError("producer manifest is absent")
            if manifest_path.stat().st_size <= 0 or manifest_path.stat().st_size > 1024 * 1024:
                raise DirectSyncPushError("producer manifest size is invalid")
            current_hash = manifest_hash(load_json_no_duplicate_keys(manifest_path.read_bytes()))
        except Exception:
            print("manifest_hash_verification=FAIL")
            return 2
        if current_hash != str(args.verify_manifest_hash).strip().lower():
            print("manifest_hash_verification=FAIL")
            return 2
        print("manifest_hash_verification=PASS")
        return 0

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
    persisted_manifest_hash = manifest_hash(
        load_json_no_duplicate_keys(manifest_path.read_bytes())
    )
    expected_manifest_hash = str(report.get("manifest_hash") or "")
    if bool(report.get("server_registration_verified")):
        if not expected_manifest_hash or persisted_manifest_hash != expected_manifest_hash:
            report.update(
                {
                    "status": "BLOCKED",
                    "blocked_reason": "persisted manifest hash differs from the server-authorized manifest hash",
                    "persisted_manifest_hash_verified": False,
                }
            )
            atomic_write_json(str(report_path), report, indent=2)
            print(f"registration_report={report_path.resolve()}")
            return 2
        report["persisted_manifest_hash_verified"] = True
    atomic_write_json(str(report_path), report, indent=2)
    print(f"registration_report={report_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

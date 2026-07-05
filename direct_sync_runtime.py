# -*- coding: utf-8 -*-
"""Local runtime wrapper for the Container_Audit direct-sync relay."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from direct_sync_push import (
    DEFAULT_PRODUCER_ROLE,
    DEFAULT_RETRY_SECONDS,
    DEFAULT_SOURCE_SYSTEM,
    DEFAULT_SOURCE_TRANSPORT,
    DEFAULT_STREAM_NAME,
    DEFAULT_TIMEOUT_SECONDS,
    DirectSyncPushError,
    ProducerCredentials,
    RELAY_STATUS_ACKED,
    RELAY_STATUS_FAILED_PERMANENT,
    RELAY_STATUS_LEASED,
    RELAY_STATUS_OPERATOR_REVIEW,
    RELAY_STATUS_PENDING,
    RELAY_STATUS_RETRY_WAIT,
    RelaySpoolFileError,
    SIGNATURE_VERSION,
    UploadResult,
    drain_one_relay_batch,
    enqueue_source_file_for_relay,
    load_json_no_duplicate_keys,
    manifest_hash,
    relay_queue_status,
    reset_stale_relay_leases,
    utc_now_text,
    validate_endpoint_url,
)
from direct_sync_operator import read_operator_pause
from storage_policy import is_legacy_syncthing_path


DEFAULT_WORKER_ID = "direct-sync-relay-container-audit"
PRODUCTION_PROFILE_ENV_NAMES = ("APP_ENV", "ENV", "CONTAINER_AUDIT_PRODUCTION", "DIRECT_SYNC_PRODUCTION")
SECRET_REF_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
WINCRED_TARGET_PREFIX = "KMTech.DirectSync."
RUNTIME_REDACTED_MESSAGE_MARKERS = (
    "authorization:",
    "bearer ",
    "canonical signed request",
    "hmac_key",
    "producer_signature",
    "raw_payload",
    "raw_secret",
    "receipt_json",
    "secret_hex",
    "should-not-leak",
    "source_file_bytes",
    "source_file_text",
    "x-producer-signature",
)
AUTHORIZATION_TEXT_RE = re.compile(r"(?i)authorization\s*:\s*[^\r\n\t ]+(?:[ \t]+[^\r\n\t ]+)?")
SENSITIVE_ASSIGNMENT_RE = re.compile(r"(?i)\b(secret|token|signature)\s*=\s*[^\s,;]+")
CONTROL_TEXT_RE = re.compile(r"[\x00-\x1f\x7f]+")


@dataclass(frozen=True)
class DirectSyncRuntimeConfig:
    db_path: str | os.PathLike[str]
    spool_dir: str | os.PathLike[str]
    producer_manifest_path: str | os.PathLike[str]
    credential_path: str | os.PathLike[str]
    upload_status_dir: str | os.PathLike[str]
    runtime_status_path: str | os.PathLike[str]
    log_path: str | os.PathLike[str]
    worker_id: str = DEFAULT_WORKER_ID
    min_free_bytes: int = 0
    retry_base_seconds: int = DEFAULT_RETRY_SECONDS
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    operator_pause_path: str | os.PathLike[str] = ""
    max_active_queue_count: int = 0
    max_active_queue_age_seconds: int = 0


def _write_json_atomic(path: str | os.PathLike[str], payload: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target.with_name(f"{target.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}")
    try:
        with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(dict(payload), handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def _append_jsonl(path: str | os.PathLike[str], payload: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(dict(payload), ensure_ascii=False, sort_keys=True))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _production_profile_enabled() -> bool:
    return any(
        str(os.getenv(name) or "").strip().lower() in {"1", "true", "prod", "production"}
        for name in PRODUCTION_PROFILE_ENV_NAMES
    )


def _producer_manifest_sha256(path: str | os.PathLike[str]) -> str:
    if not path:
        return ""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


def _producer_manifest_identity(config: DirectSyncRuntimeConfig) -> dict[str, Any]:
    manifest_ref = str(config.producer_manifest_path)
    identity = {
        "status": "unavailable",
        "producer_manifest_ref": manifest_ref,
        "producer_manifest_sha256": _producer_manifest_sha256(manifest_ref),
        "manifest_hash": "",
        "source_host_id": "",
        "producer_install_id": "",
        "producer_role": "",
        "stream_name": "",
        "source_system": "",
        "source_transport": "http_push",
        "manifest_source_transport": "",
        "source_scope_key": "",
        "source_scope_key_sha256": "",
        "error_code": "producer_manifest_unavailable",
        "error_message": "producer manifest is unavailable",
    }
    try:
        manifest = load_json_no_duplicate_keys(Path(manifest_ref).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        identity.update(
            {
                "error_code": "producer_manifest_invalid",
                "error_message": f"producer manifest invalid: {exc.__class__.__name__}",
            }
        )
        return identity
    if not isinstance(manifest, dict):
        identity.update(
            {
                "error_code": "producer_manifest_invalid",
                "error_message": "producer manifest must be a JSON object",
            }
        )
        return identity
    identity["manifest_hash"] = manifest_hash(manifest)
    pc_identity = manifest.get("pc_identity") if isinstance(manifest.get("pc_identity"), Mapping) else {}
    streams = manifest.get("streams") if isinstance(manifest.get("streams"), list) else []
    stream = next(
        (
            item
            for item in streams
            if isinstance(item, Mapping)
            and str(item.get("producer_role") or "") == DEFAULT_PRODUCER_ROLE
            and str(item.get("stream_name") or "") == DEFAULT_STREAM_NAME
        ),
        None,
    )
    source_host_id = str(pc_identity.get("source_host_id") or "").strip()
    producer_install_id = str(pc_identity.get("producer_install_id") or "").strip()
    if not source_host_id or not producer_install_id or stream is None:
        identity.update(
            {
                "error_code": "producer_manifest_identity_incomplete",
                "error_message": "producer manifest identity is incomplete",
            }
        )
        return identity
    producer_role = str(stream.get("producer_role") or "").strip()
    stream_name = str(stream.get("stream_name") or "").strip()
    source_system = str(stream.get("source_system") or "").strip()
    manifest_source_transport = str(stream.get("source_transport") or "").strip()
    if source_system != DEFAULT_SOURCE_SYSTEM or manifest_source_transport != DEFAULT_SOURCE_TRANSPORT:
        identity.update(
            {
                "error_code": "producer_manifest_stream_mismatch",
                "error_message": "producer manifest stream does not match Container_Audit legacy CSV",
            }
        )
        return identity
    source_scope_key = f"{source_host_id}/{producer_role}/{stream_name}"
    identity.update(
        {
            "status": "PASS",
            "source_host_id": source_host_id,
            "producer_install_id": producer_install_id,
            "producer_role": producer_role,
            "stream_name": stream_name,
            "source_system": source_system,
            "manifest_source_transport": manifest_source_transport,
            "source_scope_key": source_scope_key,
            "source_scope_key_sha256": hashlib.sha256(source_scope_key.encode("utf-8")).hexdigest(),
            "error_code": "",
            "error_message": "",
        }
    )
    return identity


def _source_identity_from_upload_metadata(
    metadata: Mapping[str, Any],
    *,
    producer_manifest_path: str | os.PathLike[str] = "",
) -> dict[str, Any]:
    source_host_id = str(metadata.get("source_host_id") or "").strip()
    producer_install_id = str(metadata.get("producer_install_id") or "").strip()
    producer_role = str(metadata.get("producer_role") or "").strip()
    stream_name = str(metadata.get("stream_name") or "").strip()
    source_system = str(metadata.get("source_system") or "").strip()
    manifest_hash_value = str(metadata.get("manifest_hash") or "").strip().lower()
    source_transport = str(metadata.get("source_transport") or "").strip()
    source_scope_key = f"{source_host_id}/{producer_role}/{stream_name}" if source_host_id and producer_role and stream_name else ""
    ok = (
        bool(source_scope_key)
        and bool(producer_install_id)
        and source_system == DEFAULT_SOURCE_SYSTEM
        and source_transport == DEFAULT_SOURCE_TRANSPORT
        and bool(manifest_hash_value)
    )
    return {
        "status": "PASS" if ok else "unavailable",
        "producer_manifest_ref": str(producer_manifest_path),
        "producer_manifest_sha256": _producer_manifest_sha256(producer_manifest_path),
        "manifest_hash": manifest_hash_value,
        "source_host_id": source_host_id,
        "producer_install_id": producer_install_id,
        "producer_role": producer_role,
        "stream_name": stream_name,
        "source_system": source_system,
        "source_transport": "http_push",
        "manifest_source_transport": source_transport,
        "source_scope_key": source_scope_key,
        "source_scope_key_sha256": hashlib.sha256(source_scope_key.encode("utf-8")).hexdigest()
        if source_scope_key
        else "",
        "error_code": "" if ok else "upload_metadata_identity_incomplete",
        "error_message": "" if ok else "upload metadata identity is incomplete",
    }


def _source_identity_from_upload_result(
    result: UploadResult | None,
    *,
    producer_manifest_path: str | os.PathLike[str],
) -> dict[str, Any] | None:
    if result is None or not result.status_path:
        return None
    try:
        status_payload = load_json_no_duplicate_keys(Path(result.status_path).read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if isinstance(status_payload, Mapping) and isinstance(status_payload.get("metadata"), Mapping):
        return _source_identity_from_upload_metadata(
            status_payload["metadata"],
            producer_manifest_path=producer_manifest_path,
        )
    return None


def _safe_secret_ref_name(value: str) -> str:
    text = str(value or "").strip()
    if not text or not SECRET_REF_NAME_RE.fullmatch(text):
        raise DirectSyncPushError("secret_ref target name is unsafe")
    return text


def _default_secret_data_dir(credential_path: Path) -> Path:
    local_app_data = os.getenv("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "CompanyProducerConnector"
    return credential_path.parent / "CompanyProducerConnector"


def _dpapi_unprotect_current_user(protected: bytes) -> bytes:
    if sys.platform != "win32":
        raise DirectSyncPushError("dpapi secret_ref requires Windows")
    import ctypes
    from ctypes import byref, c_void_p, wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", c_void_p)]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    input_buffer = ctypes.create_string_buffer(protected, len(protected))
    input_blob = DataBlob(len(protected), ctypes.cast(input_buffer, c_void_p))
    output_blob = DataBlob()
    if not crypt32.CryptUnprotectData(byref(input_blob), None, None, None, None, 0, byref(output_blob)):
        raise DirectSyncPushError("dpapi secret_ref could not be read")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(c_void_p(output_blob.pbData))


def _read_wincred_secret(target_name: str) -> str:
    if sys.platform != "win32":
        raise DirectSyncPushError("wincred secret_ref requires Windows")
    import ctypes
    from ctypes import POINTER, byref, c_void_p, wintypes

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
            ("CredentialBlob", c_void_p),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    advapi32 = ctypes.windll.advapi32
    credential_ptr = c_void_p()
    if not advapi32.CredReadW(target_name, 1, 0, byref(credential_ptr)):
        raise DirectSyncPushError("wincred secret_ref could not be read")
    try:
        credential = ctypes.cast(credential_ptr, POINTER(Credential)).contents
        secret_bytes = ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize)
        return secret_bytes.decode("utf-8")
    finally:
        advapi32.CredFree(credential_ptr)


def _wincred_target_name(name: str) -> str:
    safe_name = _safe_secret_ref_name(name)
    if safe_name.startswith(WINCRED_TARGET_PREFIX):
        return safe_name
    return f"{WINCRED_TARGET_PREFIX}{safe_name}"


def _resolve_secret_ref(secret_ref: str, *, credential_path: Path, secret_data_dir: str = "") -> str:
    text = str(secret_ref or "").strip()
    if ":" not in text:
        raise DirectSyncPushError("secret_ref must start with env:, dpapi:, or wincred:")
    scheme, target = text.split(":", 1)
    scheme = scheme.lower()
    name = _safe_secret_ref_name(target)
    if scheme == "env":
        if _production_profile_enabled():
            raise DirectSyncPushError("env secret_ref is disabled in production")
        value = os.getenv(name)
        if not value:
            raise DirectSyncPushError("env secret_ref is not available")
        return value
    if scheme == "dpapi":
        base_dir = Path(secret_data_dir).expanduser() if secret_data_dir else _default_secret_data_dir(credential_path)
        if secret_data_dir and is_legacy_syncthing_path(base_dir):
            raise DirectSyncPushError("secret_data_dir must not point at the legacy Syncthing folder")
        protected_path = base_dir / "secrets" / f"{name}.dpapi"
        if not protected_path.is_file():
            raise DirectSyncPushError("dpapi secret_ref artifact is missing")
        return _dpapi_unprotect_current_user(protected_path.read_bytes()).decode("utf-8")
    if scheme == "wincred":
        return _read_wincred_secret(_wincred_target_name(name))
    raise DirectSyncPushError("secret_ref must start with env:, dpapi:, or wincred:")


def load_credentials_from_json(path: str | os.PathLike[str]) -> ProducerCredentials:
    credential_path = Path(path)
    try:
        payload = load_json_no_duplicate_keys(credential_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DirectSyncPushError(f"credential file is missing or invalid: {exc.__class__.__name__}") from exc
    except DirectSyncPushError as exc:
        raise DirectSyncPushError(f"credential file is missing or invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise DirectSyncPushError("credential file must be a JSON object")
    producer_id = str(payload.get("producer_id") or "").strip()
    key_id = str(payload.get("key_id") or "").strip()
    raw_secret = payload.get("secret")
    if raw_secret is not None and (not isinstance(raw_secret, str) or (raw_secret != "" and not raw_secret.strip())):
        raise DirectSyncPushError("credential secret must be a nonempty string")
    secret = raw_secret if isinstance(raw_secret, str) and raw_secret.strip() else ""
    secret_ref = str(payload.get("secret_ref") or "").strip()
    endpoint_url = str(payload.get("endpoint_url") or "").strip()
    if secret and secret_ref:
        raise DirectSyncPushError("credential file must not contain both secret and secret_ref")
    if secret and _production_profile_enabled():
        raise DirectSyncPushError("raw credential secret is disabled in production")
    if secret_ref:
        secret = _resolve_secret_ref(
            secret_ref,
            credential_path=credential_path,
            secret_data_dir=str(payload.get("secret_data_dir") or ""),
        )
    if not producer_id or not key_id or not secret or not endpoint_url:
        raise DirectSyncPushError("credential file is missing producer_id, key_id, secret/secret_ref, or endpoint_url")
    validate_endpoint_url(endpoint_url)
    return ProducerCredentials(
        producer_id=producer_id,
        key_id=key_id,
        secret=secret,
        endpoint_url=endpoint_url,
    )


def _disk_pressure_report(config: DirectSyncRuntimeConfig) -> dict[str, Any]:
    spool_dir = Path(config.spool_dir)
    min_free = max(0, int(config.min_free_bytes or 0))
    try:
        spool_dir.mkdir(parents=True, exist_ok=True)
        usage = shutil.disk_usage(spool_dir)
    except OSError as exc:
        return {
            "status": "blocked",
            "path": str(spool_dir),
            "free_bytes": 0,
            "total_bytes": 0,
            "used_bytes": 0,
            "min_free_bytes": min_free,
            "error_code": "disk_pressure_check_failed",
            "error_message": f"disk pressure check failed: {exc.__class__.__name__}",
        }
    return {
        "status": "blocked" if usage.free < min_free else "pass",
        "path": str(spool_dir),
        "free_bytes": int(usage.free),
        "total_bytes": int(usage.total),
        "used_bytes": int(usage.used),
        "min_free_bytes": min_free,
    }


def _safe_relay_queue_status(db_path: str | os.PathLike[str]) -> dict[str, Any]:
    try:
        return relay_queue_status(db_path)
    except (sqlite3.DatabaseError, OSError) as exc:
        return {
            "status": "unavailable",
            "error_code": "relay_queue_db_error",
            "error_message": f"relay queue database error: {exc.__class__.__name__}",
        }


def _runtime_error_details(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, (sqlite3.DatabaseError, OSError)):
        return "relay_queue_db_error", f"relay queue database error: {exc.__class__.__name__}"
    return "direct_sync_runtime_error", _redact_runtime_error_message(str(exc))


def _redact_runtime_error_message(message: str) -> str:
    text = str(message or "")
    normalized = text.strip().lower()
    if any(marker in normalized for marker in RUNTIME_REDACTED_MESSAGE_MARKERS):
        return "[REDACTED]"
    for sensitive in (SIGNATURE_VERSION, "X-Producer-Signature"):
        text = text.replace(sensitive, "[redacted]")
    text = AUTHORIZATION_TEXT_RE.sub("[redacted]", text)
    text = SENSITIVE_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[redacted]", text)
    text = CONTROL_TEXT_RE.sub(" ", text)
    return text.strip()[:500]


def _parse_utc_text(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _queue_backpressure_report(
    config: DirectSyncRuntimeConfig,
    *,
    now: str = "",
) -> dict[str, Any]:
    max_count = max(0, int(config.max_active_queue_count or 0))
    max_age_seconds = max(0, int(config.max_active_queue_age_seconds or 0))
    if max_count <= 0 and max_age_seconds <= 0:
        return {
            "status": "pass",
            "enabled": False,
            "max_active_queue_count": max_count,
            "max_active_queue_age_seconds": max_age_seconds,
        }
    queue = relay_queue_status(config.db_path)
    counts = dict(queue.get("counts") or {})
    active_count = sum(
        int(counts.get(status, 0) or 0)
        for status in (RELAY_STATUS_PENDING, RELAY_STATUS_RETRY_WAIT, RELAY_STATUS_LEASED)
    )
    oldest_active = str(queue.get("oldest_active_created_at") or "")
    oldest_age_seconds = 0
    reasons: list[str] = []
    if max_count > 0 and active_count >= max_count:
        reasons.append("active_queue_count_threshold")
    if max_age_seconds > 0 and oldest_active:
        oldest_dt = _parse_utc_text(oldest_active)
        now_dt = _parse_utc_text(now) or datetime.now(timezone.utc)
        if oldest_dt is None:
            reasons.append("oldest_active_age_unknown")
        else:
            oldest_age_seconds = max(0, int((now_dt - oldest_dt).total_seconds()))
            if oldest_age_seconds >= max_age_seconds:
                reasons.append("oldest_active_age_threshold")
    return {
        "status": "blocked" if reasons else "pass",
        "enabled": True,
        "reasons": reasons,
        "active_queue_count": active_count,
        "oldest_active_created_at": oldest_active,
        "oldest_active_age_seconds": oldest_age_seconds,
        "max_active_queue_count": max_count,
        "max_active_queue_age_seconds": max_age_seconds,
        "queue": queue,
    }


def _result_summary(result: UploadResult | None, queue: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if result is None:
        counts = dict((queue or {}).get("counts") or {})
        dead_letter_counts = {
            status: int(counts.get(status, 0) or 0)
            for status in (RELAY_STATUS_OPERATOR_REVIEW, RELAY_STATUS_FAILED_PERMANENT)
            if int(counts.get(status, 0) or 0) > 0
        }
        if dead_letter_counts.get(RELAY_STATUS_OPERATOR_REVIEW):
            status = "operator_review"
            error_code = "dead_letter_operator_review"
        elif dead_letter_counts.get(RELAY_STATUS_FAILED_PERMANENT):
            status = "failed_permanent"
            error_code = "dead_letter_failed_permanent"
        else:
            status = "idle"
            error_code = ""
        return {
            "status": status,
            "success": False,
            "committed": False,
            "retryable": False,
            "status_code": 0,
            "error_code": error_code,
            "dead_letter_counts": dead_letter_counts,
        }
    relay_id = str(getattr(result, "relay_id", "") or "").strip()
    producer_client_batch_id = ""
    if isinstance(result.receipt, Mapping):
        producer_client_batch_id = str(result.receipt.get("client_batch_id") or "").strip()
        if not relay_id:
            relay_id = producer_client_batch_id
    if result.success:
        status = "acked"
    elif result.error_code == "operator_paused":
        status = "paused_by_operator"
    elif result.error_code == "operator_pause_marker_invalid":
        status = "blocked_operator_control"
    elif result.committed:
        status = "operator_review"
    elif result.retryable:
        status = "retry_wait"
    elif result.error_code in {"relay_metadata_invalid", "upload_unhandled_exception"}:
        status = "operator_review"
    else:
        status = "failed_permanent"
    summary = {
        "status": status,
        "success": result.success,
        "committed": result.committed,
        "retryable": result.retryable,
        "status_code": result.status_code,
        "error_code": result.error_code,
        "relay_id": relay_id,
        "upload_status_path": result.status_path,
    }
    if producer_client_batch_id and producer_client_batch_id != relay_id:
        summary["producer_client_batch_id"] = producer_client_batch_id
    return summary


def _write_runtime_status(
    config: DirectSyncRuntimeConfig,
    *,
    status: str,
    queue: Mapping[str, Any],
    disk: Mapping[str, Any],
    stale_leases_reset: int = 0,
    last_result: Mapping[str, Any] | None = None,
    operator_control: Mapping[str, Any] | None = None,
    queue_backpressure: Mapping[str, Any] | None = None,
    error_code: str = "",
    error_message: str = "",
    source_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source_identity = dict(source_identity or _producer_manifest_identity(config))
    payload = {
        "status": status,
        "app": "Container_Audit",
        "worker_id": config.worker_id,
        "producer_manifest_ref": source_identity["producer_manifest_ref"],
        "producer_manifest_sha256": source_identity["producer_manifest_sha256"],
        "manifest_hash": source_identity.get("manifest_hash", ""),
        "source_identity": source_identity,
        "queue": dict(queue),
        "disk": dict(disk),
        "stale_leases_reset": int(stale_leases_reset),
        "last_result": dict(last_result or {}),
        "operator_control": dict(operator_control or {}),
        "queue_backpressure": dict(queue_backpressure or {}),
        "error_code": error_code,
        "error_message": error_message,
        "runtime_status_write_status": "PASS",
        "updated_at": utc_now_text(),
    }
    return _write_runtime_payload(config, payload)


def _write_runtime_payload(config: DirectSyncRuntimeConfig, payload: dict[str, Any]) -> dict[str, Any]:
    payload["runtime_status_write_status"] = "PASS"
    payload.pop("runtime_status_write_error_code", None)
    payload.pop("runtime_status_write_error_message", None)
    try:
        _write_json_atomic(config.runtime_status_path, payload)
    except OSError as exc:
        payload["runtime_status_write_status"] = "FAIL"
        payload["runtime_status_write_error_code"] = "runtime_status_write_failed"
        payload["runtime_status_write_error_message"] = f"runtime status write failed: {exc.__class__.__name__}"
    return payload


def _append_runtime_event(
    config: DirectSyncRuntimeConfig,
    event: str,
    payload: Mapping[str, Any],
    *,
    source_identity: Mapping[str, Any] | None = None,
) -> tuple[bool, str]:
    source_identity = dict(source_identity or _producer_manifest_identity(config))
    entry = {
        "event": event,
        "app": "Container_Audit",
        "worker_id": config.worker_id,
        "producer_manifest_ref": source_identity["producer_manifest_ref"],
        "producer_manifest_sha256": source_identity["producer_manifest_sha256"],
        "manifest_hash": source_identity.get("manifest_hash", ""),
        "source_identity": source_identity,
        "credential_ref": str(config.credential_path),
        "generated_at": utc_now_text(),
    }
    entry.update(dict(payload))
    try:
        _append_jsonl(config.log_path, entry)
    except OSError as exc:
        return False, f"runtime log append failed: {exc.__class__.__name__}"
    return True, ""


def _append_runtime_event_with_status(
    config: DirectSyncRuntimeConfig,
    event: str,
    status: dict[str, Any],
    *,
    log_payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    status_identity = status.get("source_identity") if isinstance(status.get("source_identity"), Mapping) else None
    ok, error_message = _append_runtime_event(config, event, log_payload or status, source_identity=status_identity)
    if ok:
        return status
    status["runtime_log_write_status"] = "FAIL"
    status["runtime_log_write_error_code"] = "runtime_log_write_failed"
    status["runtime_log_write_error_message"] = error_message
    return _write_runtime_payload(config, status)


def _paused_by_operator(config: DirectSyncRuntimeConfig) -> dict[str, Any]:
    return read_operator_pause(config.operator_pause_path)


def _write_paused_status(config: DirectSyncRuntimeConfig, *, event: str) -> dict[str, Any]:
    pause = _paused_by_operator(config)
    queue = _safe_relay_queue_status(config.db_path)
    marker_invalid = bool(pause.get("enabled")) and bool(pause.get("paused")) and not bool(pause.get("marker_valid"))
    status = _write_runtime_status(
        config,
        status="blocked_operator_control" if marker_invalid else "paused_by_operator",
        queue=queue,
        disk={"status": "not_checked", "reason": "operator_pause_invalid" if marker_invalid else "operator_pause"},
        operator_control=pause,
        error_code="operator_pause_marker_invalid" if marker_invalid else "operator_paused",
        error_message=(
            "direct-sync relay operator pause marker is invalid"
            if marker_invalid
            else "direct-sync relay is paused by local operator control"
        ),
    )
    return _append_runtime_event_with_status(config, event, status)


def _write_backpressure_status(
    config: DirectSyncRuntimeConfig,
    *,
    backpressure: Mapping[str, Any],
    event: str,
    stale_leases_reset: int = 0,
) -> dict[str, Any]:
    status = _write_runtime_status(
        config,
        status="blocked_queue_backpressure",
        queue=backpressure.get("queue") if isinstance(backpressure.get("queue"), Mapping) else _safe_relay_queue_status(config.db_path),
        disk={"status": "not_checked", "reason": "queue_backpressure"},
        stale_leases_reset=stale_leases_reset,
        queue_backpressure=backpressure,
        error_code="queue_backpressure",
        error_message="direct-sync relay active queue exceeds configured enqueue threshold",
    )
    return _append_runtime_event_with_status(config, event, status)


def enqueue_completed_source_file(
    config: DirectSyncRuntimeConfig,
    *,
    source_file_path: str | os.PathLike[str],
    relative_path: str = "",
    credentials: ProducerCredentials | None = None,
) -> dict[str, Any]:
    """Spool one completed Container_Audit CSV and persist local operator evidence."""
    if _paused_by_operator(config).get("paused"):
        return _write_paused_status(config, event="enqueue_paused_by_operator")

    stale_leases_reset = 0
    try:
        stale_leases_reset = reset_stale_relay_leases(db_path=config.db_path, now=utc_now_text())
        backpressure = _queue_backpressure_report(config)
    except (sqlite3.DatabaseError, OSError) as exc:
        queue = _safe_relay_queue_status(config.db_path)
        error_code, error_message = _runtime_error_details(exc)
        status = _write_runtime_status(
            config,
            status="enqueue_error",
            queue=queue,
            disk={"status": "not_checked", "reason": "relay_queue_db_error"},
            stale_leases_reset=stale_leases_reset,
            error_code=error_code,
            error_message=error_message,
        )
        return _append_runtime_event_with_status(config, "enqueue_error", status)
    if backpressure["status"] != "pass":
        return _write_backpressure_status(
            config,
            backpressure=backpressure,
            event="enqueue_blocked_queue_backpressure",
            stale_leases_reset=stale_leases_reset,
        )

    disk = _disk_pressure_report(config)
    if disk["status"] != "pass":
        queue = _safe_relay_queue_status(config.db_path)
        status = _write_runtime_status(
            config,
            status="blocked_disk_pressure",
            queue=queue,
            disk=disk,
            stale_leases_reset=stale_leases_reset,
            error_code="disk_pressure",
            error_message="free space is below configured direct-sync relay minimum",
        )
        return _append_runtime_event_with_status(config, "enqueue_blocked_disk_pressure", status)
    try:
        creds = credentials or load_credentials_from_json(config.credential_path)
        row = enqueue_source_file_for_relay(
            db_path=config.db_path,
            spool_dir=config.spool_dir,
            source_file_path=source_file_path,
            producer_manifest_path=config.producer_manifest_path,
            credentials=creds,
            relative_path=relative_path,
            dedupe_existing=True,
        )
    except (DirectSyncPushError, sqlite3.DatabaseError, OSError) as exc:
        queue = _safe_relay_queue_status(config.db_path)
        error_code, error_message = _runtime_error_details(exc)
        if isinstance(exc, RelaySpoolFileError):
            error_code = "relay_spool_filesystem_error"
            error_message = _redact_runtime_error_message(str(exc))
        elif isinstance(exc, DirectSyncPushError):
            error_code = "direct_sync_enqueue_error"
            error_message = _redact_runtime_error_message(str(exc))
        status = _write_runtime_status(
            config,
            status="enqueue_error",
            queue=queue,
            disk=disk,
            stale_leases_reset=stale_leases_reset,
            error_code=error_code,
            error_message=error_message,
        )
        return _append_runtime_event_with_status(config, "enqueue_error", status)
    if row.deduped_existing and row.status in {RELAY_STATUS_PENDING, RELAY_STATUS_RETRY_WAIT, RELAY_STATUS_LEASED}:
        enqueue_status = "already_queued"
    elif row.deduped_existing and row.status == RELAY_STATUS_ACKED:
        enqueue_status = "already_acked"
    elif row.deduped_existing and row.status in {RELAY_STATUS_FAILED_PERMANENT, RELAY_STATUS_OPERATOR_REVIEW}:
        enqueue_status = "existing_terminal_blocked"
    else:
        enqueue_status = "enqueued"
    queue = _safe_relay_queue_status(config.db_path)
    status = _write_runtime_status(
        config,
        status=enqueue_status,
        queue=queue,
        disk=disk,
        stale_leases_reset=stale_leases_reset,
        last_result={
            "relay_id": row.relay_id,
            "relay_status": row.status,
            "spooled_file_path": row.spooled_file_path,
            "relative_path": row.relative_path,
            "content_sha256": row.content_sha256,
            "byte_length": row.byte_length,
            "deduped_existing": row.deduped_existing,
        },
    )
    return _append_runtime_event_with_status(
        config,
        "enqueue_completed_source_file" if enqueue_status == "enqueued" else "enqueue_existing_source_file",
        status,
        log_payload={
            "relay_id": row.relay_id,
            "relay_status": row.status,
            "status": enqueue_status,
            "spooled_file_path": row.spooled_file_path,
            "relative_path": row.relative_path,
            "content_sha256": row.content_sha256,
            "byte_length": row.byte_length,
            "deduped_existing": row.deduped_existing,
        },
    )


def record_scan_status(
    config: DirectSyncRuntimeConfig,
    *,
    status: str,
    scan_enqueued_count: int,
    scan_attempted_count: int,
    scan_failed_source_file: str = "",
) -> dict[str, Any]:
    queue = _safe_relay_queue_status(config.db_path)
    payload = _write_runtime_status(
        config,
        status=status,
        queue=queue,
        disk={"status": "not_checked", "reason": "source_scan"},
        last_result={
            "status": status,
            "scan_enqueued_count": int(scan_enqueued_count),
            "scan_attempted_count": int(scan_attempted_count),
            "scan_failed_source_file": scan_failed_source_file,
        },
    )
    return _append_runtime_event_with_status(config, "source_scan_status", payload)


def record_scan_result_status(
    config: DirectSyncRuntimeConfig,
    *,
    scan_result: Mapping[str, Any],
    scan_enqueued_count: int,
    scan_attempted_count: int,
    scan_failed_source_file: str = "",
) -> dict[str, Any]:
    payload = dict(scan_result)
    payload["scan_enqueued_count"] = int(scan_enqueued_count)
    payload["scan_attempted_count"] = int(scan_attempted_count)
    if scan_failed_source_file:
        payload["scan_failed_source_file"] = scan_failed_source_file
    last_result = dict(payload.get("last_result") or {})
    last_result.update(
        {
            "scan_enqueued_count": int(scan_enqueued_count),
            "scan_attempted_count": int(scan_attempted_count),
            "scan_failed_source_file": scan_failed_source_file,
        }
    )
    payload["last_result"] = last_result
    payload = _write_runtime_payload(config, payload)
    return _append_runtime_event_with_status(config, "source_scan_result_status", payload)


def record_scan_drain_status(
    config: DirectSyncRuntimeConfig,
    *,
    drain_status: Mapping[str, Any],
    scan_status: str,
    scan_enqueued_count: int,
    scan_attempted_count: int,
    scan_failed_source_file: str = "",
) -> dict[str, Any]:
    payload = dict(drain_status)
    payload["scan_status"] = scan_status
    payload["scan_enqueued_count"] = int(scan_enqueued_count)
    payload["scan_attempted_count"] = int(scan_attempted_count)
    if scan_failed_source_file:
        payload["scan_failed_source_file"] = scan_failed_source_file
    last_result = dict(payload.get("last_result") or {})
    last_result.update(
        {
            "scan_status": scan_status,
            "scan_enqueued_count": int(scan_enqueued_count),
            "scan_attempted_count": int(scan_attempted_count),
            "scan_failed_source_file": scan_failed_source_file,
        }
    )
    payload["last_result"] = last_result
    payload = _write_runtime_payload(config, payload)
    return _append_runtime_event_with_status(config, "source_scan_drain_status", payload)


def run_relay_once(
    config: DirectSyncRuntimeConfig,
    *,
    session: Any = None,
    credentials: ProducerCredentials | None = None,
    now: str = "",
) -> dict[str, Any]:
    """Run one bounded relay drain cycle and persist status/log evidence."""
    if _paused_by_operator(config).get("paused"):
        return _write_paused_status(config, event="relay_paused_by_operator")

    disk = _disk_pressure_report(config)
    if disk["status"] != "pass":
        queue = _safe_relay_queue_status(config.db_path)
        status = _write_runtime_status(
            config,
            status="blocked_disk_pressure",
            queue=queue,
            disk=disk,
            error_code="disk_pressure",
            error_message="free space is below configured direct-sync relay minimum",
        )
        return _append_runtime_event_with_status(config, "relay_blocked_disk_pressure", status)

    cycle_now = now or utc_now_text()
    reset_count = 0
    try:
        reset_count = reset_stale_relay_leases(db_path=config.db_path, now=cycle_now)
        creds = credentials or load_credentials_from_json(config.credential_path)
        result = drain_one_relay_batch(
            db_path=config.db_path,
            credentials=creds,
            worker_id=config.worker_id,
            session=session,
            status_dir=config.upload_status_dir,
            retry_base_seconds=config.retry_base_seconds,
            timeout=config.timeout_seconds,
            pre_upload_pause_check=lambda: _paused_by_operator(config),
            now=cycle_now,
        )
    except (DirectSyncPushError, sqlite3.DatabaseError, OSError) as exc:
        queue = _safe_relay_queue_status(config.db_path)
        error_code, error_message = _runtime_error_details(exc)
        status = _write_runtime_status(
            config,
            status="runtime_error",
            queue=queue,
            disk=disk,
            stale_leases_reset=reset_count,
            error_code=error_code,
            error_message=error_message,
        )
        return _append_runtime_event_with_status(config, "relay_runtime_error", status)

    queue = _safe_relay_queue_status(config.db_path)
    result_summary = _result_summary(result, queue)
    result_source_identity = _source_identity_from_upload_result(
        result,
        producer_manifest_path=config.producer_manifest_path,
    )
    operator_control = None
    error_code = ""
    error_message = ""
    if result_summary["status"] in {"paused_by_operator", "blocked_operator_control"}:
        operator_control = _paused_by_operator(config)
        error_code = result_summary["error_code"]
        error_message = (
            "direct-sync relay operator pause marker is invalid"
            if result_summary["status"] == "blocked_operator_control"
            else "direct-sync relay is paused by local operator control"
        )
    status = _write_runtime_status(
        config,
        status=result_summary["status"],
        queue=queue,
        disk=disk,
        stale_leases_reset=reset_count,
        last_result=result_summary,
        operator_control=operator_control,
        error_code=error_code,
        error_message=error_message,
        source_identity=result_source_identity,
    )
    return _append_runtime_event_with_status(config, "relay_runner_once", status)

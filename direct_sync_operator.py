"""Local operator controls for the Container_Audit direct-sync relay."""

from __future__ import annotations

import hashlib
import datetime
import json
import os
import re
import sqlite3
import uuid

from writer_session_fence import writer_sink
from pathlib import Path
from typing import Any, Mapping

from direct_sync_push import (
    DEFAULT_PRODUCER_ROLE,
    DirectSyncPushError,
    ProducerCredentials,
    RELAY_STATUS_ACKED,
    RELAY_STATUS_FAILED_PERMANENT,
    RELAY_STATUS_OPERATOR_REVIEW,
    RELAY_STATUS_PENDING,
    SOURCE_FILE_STABLE_KEY_PREFIX,
    build_raw_artifact_restore_url,
    canonical_json,
    restore_raw_artifact_to_file,
    utc_now_text,
)


PAUSE_SCHEMA_VERSION = "direct-sync-relay-operator-pause-v1"
AUDIT_SCHEMA_VERSION = "direct-sync-relay-operator-audit-v1"
OPERATOR_TOOL_VERSION = "container-audit-local-operator-v1"
RETRYABLE_DEAD_STATUSES = frozenset({RELAY_STATUS_FAILED_PERMANENT})
COMMITTED_REVIEW_RESOLUTIONS = frozenset(
    {
        "historical_local_only",
        "historical_superseded",
        "server_replayed",
    }
)
HISTORICAL_LOCAL_ONLY_EVENT_NAMES = frozenset({"RANDOM_TEST_SESSION_START"})
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
EVENT_IDENTITY_SUFFIX_RE = re.compile(r"^:[1-9][0-9]*:[0-9]+$")
REASON_REDACTED_RE = re.compile(r"^sha256:[A-Fa-f0-9]{12}$")
DEAD_LETTER_STATUSES = (RELAY_STATUS_OPERATOR_REVIEW, RELAY_STATUS_FAILED_PERMANENT)
LEGACY_SOURCE_FILE_KEY_PREFIX = "source-file:"
RETRY_RUNTIME_METADATA_FIELDS = (
    "runtime_instance_id",
    "runtime_public_jwk",
    "runtime_fence",
    "runtime_request_token",
    "runtime_request_sequence",
    "runtime_request_token_sha256",
)
RUNTIME_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(authorization|bearer|credential|hmac|raw_payload|receipt_json|secret|signature|source_file_bytes|source_file_text|token)"
)
AUTHORIZATION_TEXT_RE = re.compile(r"(?i)\b(?:authorization|x-producer-signature)\s*:\s*[^\r\n,;]+")
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<key>api[_-]?key|hmac|password|passwd|secret|signature|token)\s*=\s*[^\s,;]+"
)


@writer_sink("operator_evidence")
def _write_json_atomic(path: str | os.PathLike[str], payload: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target.with_name(f"{target.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}")
    with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(dict(payload), handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, target)


@writer_sink("operator_evidence")
def _append_jsonl(path: str | os.PathLike[str], payload: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(dict(payload), ensure_ascii=False, sort_keys=True))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _require_text(value: str, *, field_name: str, max_length: int = 512) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")
    if len(text) > max_length:
        raise ValueError(f"{field_name} exceeds {max_length} characters")
    return text


def _reason_evidence(reason: str) -> dict[str, Any]:
    digest = hashlib.sha256(reason.encode("utf-8")).hexdigest()
    return {
        "reason_redacted": f"sha256:{digest[:12]}",
        "reason_sha256": digest,
        "reason_length": len(reason),
    }


def _read_file_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _read_pause_marker(path: Path) -> tuple[dict[str, Any], bool]:
    if not path.exists():
        return {}, True
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}, False
    if not isinstance(payload, dict):
        return {}, False
    return payload, True


def _pause_marker_contract_error(marker: Mapping[str, Any]) -> str:
    if marker.get("schema_version") != PAUSE_SCHEMA_VERSION:
        return "operator_pause_marker_schema_invalid"
    if marker.get("status") != "paused":
        return "operator_pause_marker_status_invalid"
    if not isinstance(marker.get("operator_id"), str) or not str(marker.get("operator_id") or "").strip():
        return "operator_pause_marker_operator_invalid"
    reason_redacted = marker.get("reason_redacted")
    if not isinstance(reason_redacted, str) or not REASON_REDACTED_RE.fullmatch(reason_redacted):
        return "operator_pause_marker_reason_invalid"
    reason_sha256 = marker.get("reason_sha256")
    if not isinstance(reason_sha256, str) or not SHA256_RE.fullmatch(reason_sha256):
        return "operator_pause_marker_reason_invalid"
    if reason_redacted.lower() != f"sha256:{reason_sha256[:12].lower()}":
        return "operator_pause_marker_reason_invalid"
    reason_length = _safe_int(marker.get("reason_length"))
    if reason_length <= 0:
        return "operator_pause_marker_reason_invalid"
    created_at = marker.get("created_at")
    if not isinstance(created_at, str) or not created_at.strip():
        return "operator_pause_marker_created_at_invalid"
    try:
        datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return "operator_pause_marker_created_at_invalid"
    return ""


def read_operator_pause(pause_path: str | os.PathLike[str]) -> dict[str, Any]:
    path_text = str(pause_path or "").strip()
    if not path_text:
        return {"enabled": False, "paused": False, "path": "", "marker_valid": True}
    marker_path = Path(path_text)
    marker, json_valid = _read_pause_marker(marker_path)
    marker_error_code = "" if json_valid else "operator_pause_marker_json_invalid"
    if json_valid and marker_path.exists():
        marker_error_code = _pause_marker_contract_error(marker)
    valid = json_valid and not marker_error_code
    return {
        "enabled": True,
        "paused": marker_path.exists(),
        "path": str(marker_path),
        "marker_valid": valid,
        "marker_error_code": marker_error_code,
        "schema_version": str(marker.get("schema_version") or "") if json_valid else "",
        "operator_id": str(marker.get("operator_id") or "") if json_valid else "",
        "reason_redacted": str(marker.get("reason_redacted") or "") if json_valid else "",
        "reason_sha256": str(marker.get("reason_sha256") or "") if json_valid else "",
        "reason_length": _safe_int(marker.get("reason_length")) if json_valid else 0,
        "created_at": str(marker.get("created_at") or "") if json_valid else "",
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _redact_runtime_status_text(value: str) -> str:
    text = str(value or "")
    text = AUTHORIZATION_TEXT_RE.sub("[redacted]", text)
    return SENSITIVE_ASSIGNMENT_RE.sub(lambda match: f"{match.group('key')}=[redacted]", text)


def _redact_runtime_status_payload(value: Any, *, key_name: str = "") -> Any:
    if RUNTIME_SENSITIVE_KEY_RE.search(str(key_name or "")):
        return "[redacted]"
    if isinstance(value, Mapping):
        return {str(key): _redact_runtime_status_payload(item, key_name=str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_runtime_status_payload(item) for item in value]
    if isinstance(value, str):
        return _redact_runtime_status_text(value)
    return value


def _decode_receipt_json(raw_value: Any) -> tuple[dict[str, Any], bool]:
    if raw_value in (None, ""):
        return {}, True
    try:
        payload = json.loads(str(raw_value))
    except (TypeError, json.JSONDecodeError):
        return {}, False
    return (payload, True) if isinstance(payload, dict) else ({}, False)


def _manifest_denial_semantics_valid(row: Mapping[str, Any]) -> bool:
    codes = row.get("codes")
    return (
        row.get("reason") == "MANIFEST_EVENT_VALIDATION_FAILED"
        and row.get("validation_status") == "DENY"
        and isinstance(codes, list)
        and "DISPATCH_KEY_NOT_IN_MANIFEST" in codes
    )


def _committed_review_semantics_valid(
    quarantine_rows: list[Any],
    *,
    resolution: str,
    server_source_file_id: str,
) -> bool:
    """Bind an operator disposition to complete, exact quarantine semantics.

    The evidence digest is an audit preimage, not a server signature.  These
    checks make accidental or shape-only dispositions fail closed by requiring
    every quarantined identity and its resolution-specific proof to agree.
    """

    seen_ids: set[int] = set()
    seen_identities: set[str] = set()
    seen_resolution_event_ids: set[int] = set()
    for row in quarantine_rows:
        if not isinstance(row, dict):
            return False
        try:
            quarantine_id = int(row.get("id"))
        except (TypeError, ValueError):
            return False
        identity = str(row.get("event_identity") or "")
        identity_suffix = identity.removeprefix(server_source_file_id)
        event_name = str(row.get("raw_event_name") or "")
        if (
            quarantine_id <= 0
            or quarantine_id in seen_ids
            or identity in seen_identities
            or not EVENT_IDENTITY_SUFFIX_RE.fullmatch(identity_suffix)
            or not event_name
            or not str(row.get("observed_at") or "")
        ):
            return False
        seen_ids.add(quarantine_id)
        seen_identities.add(identity)

        is_local_only = row.get("local_only_under_commit_85ae9ed") is True
        if is_local_only:
            if (
                event_name not in HISTORICAL_LOCAL_ONLY_EVENT_NAMES
                or not _manifest_denial_semantics_valid(row)
                or row.get("existing_event") not in (None, {})
                or row.get("resolved_common_event") not in (None, {})
            ):
                return False
            if resolution not in {"historical_local_only", "historical_superseded"}:
                return False
            continue

        if resolution == "server_replayed":
            resolved = row.get("resolved_common_event")
            resolved_id = _safe_int(resolved.get("id")) if isinstance(resolved, dict) else 0
            if (
                not _manifest_denial_semantics_valid(row)
                or not isinstance(resolved, dict)
                or resolved_id <= 0
                or resolved_id in seen_resolution_event_ids
                or resolved.get("event_identity") != identity
                or resolved.get("raw_event_name") != event_name
                or resolved.get("projection_status") not in {"PROJECTED", "NOT_PROJECTED"}
                or not str(resolved.get("event_projection_class") or "")
            ):
                return False
            if (
                resolved.get("projection_status") == "NOT_PROJECTED"
                and not str(resolved.get("raw_only_reason_code") or "")
            ):
                return False
            seen_resolution_event_ids.add(resolved_id)
            continue

        if resolution == "historical_superseded":
            existing = row.get("existing_event")
            existing_identity = str(row.get("existing_event_identity") or "")
            existing_id = _safe_int(existing.get("id")) if isinstance(existing, dict) else 0
            if (
                row.get("reason") != "LEGACY_REPLAY_CONFLICT"
                or not SHA256_RE.fullmatch(str(row.get("legacy_business_fingerprint") or ""))
                or not isinstance(existing, dict)
                or existing_id <= 0
                or existing_id in seen_resolution_event_ids
                or existing_identity != str(existing.get("event_identity") or "")
                or existing_identity == identity
                or not EVENT_IDENTITY_SUFFIX_RE.fullmatch(
                    existing_identity.removeprefix(server_source_file_id)
                )
                or existing.get("raw_event_name") != event_name
                or not str(existing.get("actor_id") or "")
                or not str(existing.get("event_ts") or "")
                or not SHA256_RE.fullmatch(str(existing.get("payload_hash") or ""))
                or not SHA256_RE.fullmatch(str(existing.get("row_hash") or ""))
            ):
                return False
            seen_resolution_event_ids.add(existing_id)
            continue

        return False
    return bool(quarantine_rows)


def _load_committed_review_evidence(
    evidence_path: str | os.PathLike[str],
    *,
    expected_sha256: str,
    relay_id: str,
    request_id: str,
    server_source_file_id: str,
    relative_path: str,
    content_sha256: str,
    byte_length: int,
    resolution: str,
    expected_totals: Mapping[str, int],
) -> tuple[dict[str, Any], str]:
    candidate = Path(_require_text(str(evidence_path or ""), field_name="evidence_path", max_length=4096))
    if not candidate.is_absolute():
        return {}, "operator_review_evidence_path_not_absolute"
    if candidate.is_symlink() or not candidate.is_file():
        return {}, "operator_review_evidence_file_invalid"
    try:
        if candidate.stat().st_size > 1024 * 1024:
            return {}, "operator_review_evidence_file_too_large"
        evidence_bytes = candidate.read_bytes()
        if len(evidence_bytes) > 1024 * 1024:
            return {}, "operator_review_evidence_file_too_large"
        actual_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
        if actual_sha256 != expected_sha256:
            return {}, "operator_review_evidence_sha256_mismatch"
        payload = json.loads(evidence_bytes.decode("utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}, "operator_review_evidence_file_unreadable"
    if not isinstance(payload, dict) or payload.get("schema_version") != (
        "container-relay-terminal-reconciliation-evidence-v1"
    ):
        return {}, "operator_review_evidence_schema_invalid"
    cases = payload.get("cases")
    if not isinstance(cases, list):
        return {}, "operator_review_evidence_cases_invalid"
    matches = [case for case in cases if isinstance(case, dict) and case.get("relay_id") == relay_id]
    if len(matches) != 1:
        return {}, "operator_review_evidence_relay_binding_invalid"
    case = matches[0]
    bindings = {
        "request_id": request_id,
        "server_source_file_id": server_source_file_id,
        "relative_path": relative_path,
        "content_sha256": content_sha256,
        "byte_length": byte_length,
    }
    if any(case.get(field) != expected for field, expected in bindings.items()):
        return {}, "operator_review_evidence_identity_mismatch"
    totals = case.get("totals")
    if not isinstance(totals, dict) or any(
        totals.get(field) != expected for field, expected in expected_totals.items()
    ):
        return {}, "operator_review_evidence_totals_mismatch"
    quarantine_rows = case.get("quarantine_rows")
    if not isinstance(quarantine_rows, list) or len(quarantine_rows) != expected_totals["quarantined"]:
        return {}, "operator_review_evidence_quarantine_cardinality_mismatch"
    proof_ok = _committed_review_semantics_valid(
        quarantine_rows,
        resolution=resolution,
        server_source_file_id=server_source_file_id,
    )
    if not proof_ok:
        return {}, "operator_review_evidence_resolution_proof_invalid"
    return {
        "path": str(candidate.resolve()),
        "sha256": actual_sha256,
        "schema_version": str(payload["schema_version"]),
        "generated_at": str(payload.get("generated_at") or ""),
    }, ""


def _sqlite_error_message(exc: sqlite3.Error) -> str:
    return f"relay queue database error: {exc.__class__.__name__}"


def _append_operator_audit(audit_log_path: str | os.PathLike[str], *, action: str, report: Mapping[str, Any]) -> None:
    if not str(audit_log_path or "").strip():
        return
    entry = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "audit_event_id": f"operator-audit-{uuid.uuid4().hex}",
        "action": action,
        "tool_version": OPERATOR_TOOL_VERSION,
        "generated_at": utc_now_text(),
    }
    entry.update(dict(report))
    _append_jsonl(audit_log_path, entry)


def _with_operator_audit_status(
    audit_log_path: str | os.PathLike[str],
    *,
    action: str,
    report: Mapping[str, Any],
) -> dict[str, Any]:
    payload = dict(report)
    if not str(audit_log_path or "").strip():
        return payload
    try:
        _append_operator_audit(audit_log_path, action=action, report=payload)
        payload["audit_write_status"] = "PASS"
    except OSError as exc:
        payload["audit_write_status"] = "FAIL"
        payload["audit_write_error_code"] = "operator_audit_write_failed"
        payload["audit_write_error_message"] = f"operator audit write failed: {exc.__class__.__name__}"
    return payload


@writer_sink("operator_pause")
def pause_relay(
    *,
    pause_path: str | os.PathLike[str],
    operator_id: str,
    reason: str,
    audit_log_path: str | os.PathLike[str] = "",
) -> dict[str, Any]:
    operator = _require_text(operator_id, field_name="operator_id", max_length=128)
    reason_text = _require_text(reason, field_name="reason")
    target = Path(pause_path)
    previous = read_operator_pause(target)
    reason_fields = _reason_evidence(reason_text)
    marker = {
        "schema_version": PAUSE_SCHEMA_VERSION,
        "status": "paused",
        "operator_id": operator,
        **reason_fields,
        "created_at": utc_now_text(),
    }
    try:
        _write_json_atomic(target, marker)
    except OSError as exc:
        report = {
            "status": "BLOCKED",
            "operation": "pause",
            "operator_id": operator,
            "tool_version": OPERATOR_TOOL_VERSION,
            **reason_fields,
            "pause": previous,
            "previous_paused": bool(previous.get("paused")),
            "error_code": "operator_pause_write_failed",
            "error_message": f"operator pause marker could not be written: {exc.__class__.__name__}",
        }
        return _with_operator_audit_status(audit_log_path, action="pause-blocked", report=report)
    report = {
        "status": "PASS",
        "operation": "pause",
        "operator_id": operator,
        "tool_version": OPERATOR_TOOL_VERSION,
        **reason_fields,
        "pause": read_operator_pause(target),
        "previous_paused": bool(previous.get("paused")),
    }
    return _with_operator_audit_status(audit_log_path, action="pause", report=report)


@writer_sink("operator_resume")
def resume_relay(
    *,
    pause_path: str | os.PathLike[str],
    operator_id: str,
    reason: str,
    audit_log_path: str | os.PathLike[str] = "",
    force_invalid_marker: bool = False,
) -> dict[str, Any]:
    operator = _require_text(operator_id, field_name="operator_id", max_length=128)
    reason_text = _require_text(reason, field_name="reason")
    target = Path(pause_path)
    previous = read_operator_pause(target)
    reason_fields = _reason_evidence(reason_text)
    invalid_existing_marker = target.exists() and not bool(previous.get("marker_valid"))
    if invalid_existing_marker and not force_invalid_marker:
        report = {
            "status": "BLOCKED",
            "operation": "resume",
            "operator_id": operator,
            "tool_version": OPERATOR_TOOL_VERSION,
            **reason_fields,
            "pause": previous,
            "previous_paused": bool(previous.get("paused")),
            "previous_marker_valid": bool(previous.get("marker_valid")),
            "error_code": str(previous.get("marker_error_code") or "operator_pause_marker_invalid"),
            "error_message": "operator pause marker is invalid; use force_invalid_marker to remove it",
        }
        return _with_operator_audit_status(audit_log_path, action="resume-blocked", report=report)
    if target.exists():
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            report = {
                "status": "BLOCKED",
                "operation": "resume",
                "operator_id": operator,
                "tool_version": OPERATOR_TOOL_VERSION,
                **reason_fields,
                "pause": previous,
                "previous_paused": bool(previous.get("paused")),
                "previous_marker_valid": bool(previous.get("marker_valid")),
                "error_code": "operator_pause_resume_failed",
                "error_message": f"operator pause marker could not be removed: {exc.__class__.__name__}",
            }
            return _with_operator_audit_status(audit_log_path, action="resume-blocked", report=report)
    report = {
        "status": "PASS",
        "operation": "resume",
        "operator_id": operator,
        "tool_version": OPERATOR_TOOL_VERSION,
        **reason_fields,
        "pause": read_operator_pause(target),
        "previous_paused": bool(previous.get("paused")),
        "previous_marker_valid": bool(previous.get("marker_valid")),
        "forced_invalid_marker": bool(invalid_existing_marker and force_invalid_marker),
    }
    return _with_operator_audit_status(audit_log_path, action="resume", report=report)


def read_relay_queue_status_read_only(db_path: str | os.PathLike[str]) -> dict[str, Any]:
    path = Path(db_path)
    if not path.is_file():
        return {
            "status": "not_initialized",
            "counts": {},
            "oldest_active_created_at": "",
            "last_acked_at": "",
        }
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        return {
            "status": "blocked",
            "counts": {},
            "oldest_active_created_at": "",
            "last_acked_at": "",
            "error_code": "relay_db_open_failed",
            "error_message": _sqlite_error_message(exc),
        }
    try:
        counts = {
            row["status"]: int(row["count"])
            for row in conn.execute(
                "SELECT status, COUNT(*) AS count FROM direct_sync_relay_batches GROUP BY status"
            ).fetchall()
        }
        oldest = conn.execute(
            """
            SELECT created_at
            FROM direct_sync_relay_batches
            WHERE status IN ('pending', 'retry_wait', 'leased')
            ORDER BY created_at
            LIMIT 1
            """
        ).fetchone()
        last_acked = conn.execute(
            """
            SELECT MAX(updated_at) AS last_acked_at
            FROM direct_sync_relay_batches
            WHERE status='acked'
            """
        ).fetchone()
        return {
            "status": "PASS",
            "counts": counts,
            "oldest_active_created_at": oldest["created_at"] if oldest else "",
            "last_acked_at": (
                str(last_acked["last_acked_at"] or "") if last_acked else ""
            ),
        }
    except sqlite3.Error as exc:
        return {
            "status": "blocked",
            "counts": {},
            "oldest_active_created_at": "",
            "last_acked_at": "",
            "error_code": "relay_db_schema_unavailable",
            "error_message": _sqlite_error_message(exc),
        }
    finally:
        conn.close()


def read_runtime_status(path: str | os.PathLike[str]) -> dict[str, Any]:
    path_text = str(path or "").strip()
    if not path_text:
        return {"enabled": False, "available": False, "path": ""}
    runtime_path = Path(path_text)
    if not runtime_path.is_file():
        return {
            "enabled": True,
            "available": False,
            "path": str(runtime_path),
            "status": "not_found",
            "error_code": "runtime_status_not_found",
        }
    try:
        payload = json.loads(runtime_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {
            "enabled": True,
            "available": False,
            "path": str(runtime_path),
            "status": "invalid",
            "error_code": "runtime_status_unreadable",
            "error_message": f"runtime status cannot be read: {exc.__class__.__name__}",
        }
    if not isinstance(payload, dict):
        return {
            "enabled": True,
            "available": False,
            "path": str(runtime_path),
            "status": "invalid",
            "error_code": "runtime_status_invalid",
        }
    safe_payload = _redact_runtime_status_payload(payload)
    return {
        "enabled": True,
        "available": True,
        "path": str(runtime_path),
        "status": str(payload.get("status") or ""),
        "updated_at": str(payload.get("updated_at") or ""),
        "payload": safe_payload,
    }


def operator_status(
    *,
    db_path: str | os.PathLike[str],
    pause_path: str | os.PathLike[str] = "",
    runtime_status_path: str | os.PathLike[str] = "",
) -> dict[str, Any]:
    queue = read_relay_queue_status_read_only(db_path)
    pause = read_operator_pause(pause_path)
    runtime = read_runtime_status(runtime_status_path)
    pause_invalid = bool(pause.get("enabled")) and bool(pause.get("paused")) and not bool(pause.get("marker_valid"))
    runtime_invalid = bool(runtime.get("enabled")) and str(runtime.get("status") or "") == "invalid"
    counts = queue.get("counts") if isinstance(queue.get("counts"), Mapping) else {}
    dead_letter_counts = {
        status: _safe_int(counts.get(status))
        for status in DEAD_LETTER_STATUSES
        if _safe_int(counts.get(status)) > 0
    }
    requires_attention = bool(dead_letter_counts)
    status = "BLOCKED" if queue.get("status") == "blocked" or pause_invalid or runtime_invalid or requires_attention else "PASS"
    report = {
        "status": status,
        "operation": "status",
        "tool_version": OPERATOR_TOOL_VERSION,
        "queue": queue,
        "pause": pause,
        "runtime": runtime,
        "requires_attention": requires_attention,
        "dead_letter_counts": dead_letter_counts,
    }
    if requires_attention:
        report["error_code"] = (
            "dead_letter_operator_review"
            if dead_letter_counts.get(RELAY_STATUS_OPERATOR_REVIEW)
            else "dead_letter_failed_permanent"
        )
    elif runtime_invalid:
        report["error_code"] = str(runtime.get("error_code") or "runtime_status_invalid")
    return report


@writer_sink("operator_spool_restore")
def restore_relay_spool_from_server(
    *,
    db_path: str | os.PathLike[str],
    relay_id: str,
    spool_root: str | os.PathLike[str],
    credentials: ProducerCredentials,
    operator_id: str,
    reason: str,
    audit_log_path: str | os.PathLike[str] = "",
    session: Any = None,
) -> dict[str, Any]:
    relay = _require_text(relay_id, field_name="relay_id", max_length=128)
    operator = _require_text(operator_id, field_name="operator_id", max_length=128)
    reason_text = _require_text(reason, field_name="reason")
    reason_fields = _reason_evidence(reason_text)

    def blocked(error_code: str, **extra: Any) -> dict[str, Any]:
        report = {
            "status": "BLOCKED",
            "operation": "restore-spool",
            "relay_id": relay,
            "operator_id": operator,
            "tool_version": OPERATOR_TOOL_VERSION,
            **reason_fields,
            "error_code": error_code,
        }
        report.update(extra)
        return _with_operator_audit_status(audit_log_path, action="restore-spool-blocked", report=report)

    if not Path(db_path).is_file():
        return blocked("relay_db_not_initialized")
    spool_root_path = Path(spool_root).expanduser().resolve()
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT relay_id, status, spooled_file_path, content_sha256, byte_length,
                   metadata_json, producer_id, key_id, endpoint_url
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (relay,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return blocked("relay_not_found")
    previous_status = str(row["status"] or "")
    if previous_status != RELAY_STATUS_ACKED:
        return blocked("relay_status_not_restoreable", previous_status=previous_status)
    for field, expected in {
        "producer_id": credentials.producer_id,
        "key_id": credentials.key_id,
        "endpoint_url": credentials.endpoint_url,
    }.items():
        actual = str(row[field] or "")
        if not actual:
            return blocked("relay_credential_binding_missing", missing_field=field)
        if actual != str(expected):
            return blocked("relay_credential_binding_mismatch", mismatch_field=field)
    spool_path_candidate = Path(str(row["spooled_file_path"] or "")).expanduser()
    if spool_path_candidate.is_symlink():
        return blocked("spooled_file_symlink")
    spool_path = spool_path_candidate.resolve()
    if not _is_within(spool_path, spool_root_path):
        return blocked("spooled_file_outside_spool_root", spool_root=str(spool_root_path))
    expected_hash = str(row["content_sha256"] or "")
    expected_bytes = int(row["byte_length"])
    if spool_path.exists():
        if not spool_path.is_file():
            return blocked("spooled_file_not_regular")
        actual_hash, actual_bytes = _read_file_digest(spool_path)
        if actual_hash != expected_hash or actual_bytes != expected_bytes:
            return blocked(
                "spooled_file_already_exists_mismatch",
                content_sha256=expected_hash,
                byte_length=expected_bytes,
                actual_content_sha256=actual_hash,
                actual_byte_length=actual_bytes,
            )
        report = {
            "status": "PASS",
            "operation": "restore-spool",
            "relay_id": relay,
            "operator_id": operator,
            "tool_version": OPERATOR_TOOL_VERSION,
            **reason_fields,
            "previous_status": previous_status,
            "restored": False,
            "local_file_already_present": True,
            "content_sha256": expected_hash,
            "byte_length": expected_bytes,
            "spooled_file_path": str(spool_path),
            "restore_url": build_raw_artifact_restore_url(
                credentials.endpoint_url,
                content_sha256=expected_hash,
                byte_length=expected_bytes,
            ),
        }
        return _with_operator_audit_status(audit_log_path, action="restore-spool", report=report)
    try:
        metadata = json.loads(str(row["metadata_json"] or "{}"))
    except json.JSONDecodeError:
        return blocked("relay_upload_metadata_invalid")
    if not isinstance(metadata, dict):
        return blocked("relay_upload_metadata_invalid")
    try:
        result = restore_raw_artifact_to_file(
            credentials=credentials,
            metadata=metadata,
            destination_path=spool_path,
            session=session,
        )
    except DirectSyncPushError:
        return blocked("relay_restore_input_invalid")
    if not result.success:
        return blocked(
            result.error_code or "relay_restore_failed",
            restore_retryable=result.retryable,
            restore_status_code=result.status_code,
            error_message=result.error_message,
        )
    report = {
        "status": "PASS",
        "operation": "restore-spool",
        "relay_id": relay,
        "operator_id": operator,
        "tool_version": OPERATOR_TOOL_VERSION,
        **reason_fields,
        "previous_status": previous_status,
        "restored": True,
        "local_file_already_present": False,
        "content_sha256": expected_hash,
        "byte_length": expected_bytes,
        "spooled_file_path": str(spool_path),
        "restore_url": build_raw_artifact_restore_url(
            credentials.endpoint_url,
            content_sha256=expected_hash,
            byte_length=expected_bytes,
        ),
    }
    return _with_operator_audit_status(audit_log_path, action="restore-spool", report=report)


@writer_sink("operator_dead_retry")
def retry_dead_relay_batch(
    *,
    db_path: str | os.PathLike[str],
    relay_id: str,
    operator_id: str,
    reason: str,
    audit_log_path: str | os.PathLike[str] = "",
    allow_operator_review: bool = False,
    expected_error_codes: tuple[str, ...] = (),
) -> dict[str, Any]:
    relay = _require_text(relay_id, field_name="relay_id", max_length=128)
    operator = _require_text(operator_id, field_name="operator_id", max_length=128)
    reason_text = _require_text(reason, field_name="reason")
    reason_fields = _reason_evidence(reason_text)
    expected_codes = tuple(
        dict.fromkeys(
            _require_text(code, field_name="expected_error_code", max_length=128)
            for code in expected_error_codes
        )
    )
    if not Path(db_path).is_file():
        report = {
            "status": "BLOCKED",
            "operation": "retry-dead",
            "relay_id": relay,
            "operator_id": operator,
            "tool_version": OPERATOR_TOOL_VERSION,
            **reason_fields,
            "error_code": "relay_db_not_initialized",
        }
        return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
    now = utc_now_text()
    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT relay_id, status, attempt_count, spooled_file_path, content_sha256, byte_length,
                   receipt_json, metadata_json, last_error_code, relative_path
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (relay,),
        ).fetchone()
        if row is None:
            conn.rollback()
            report = {
                "status": "BLOCKED",
                "operation": "retry-dead",
                "relay_id": relay,
                "operator_id": operator,
                "tool_version": OPERATOR_TOOL_VERSION,
                **reason_fields,
                "error_code": "relay_not_found",
            }
            return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
        previous_status = str(row["status"])
        previous_attempt_count = int(row["attempt_count"])
        previous_error_code = str(row["last_error_code"] or "")
        retryable_statuses = set(RETRYABLE_DEAD_STATUSES)
        if allow_operator_review:
            retryable_statuses.add(RELAY_STATUS_OPERATOR_REVIEW)
        if previous_status not in retryable_statuses:
            conn.rollback()
            report = {
                "status": "BLOCKED",
                "operation": "retry-dead",
                "relay_id": relay,
                "operator_id": operator,
                "tool_version": OPERATOR_TOOL_VERSION,
                **reason_fields,
                "previous_status": previous_status,
                "error_code": "relay_status_not_retryable_by_operator",
            }
            return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
        if expected_codes and previous_error_code not in expected_codes:
            conn.rollback()
            report = {
                "status": "BLOCKED",
                "operation": "retry-dead",
                "relay_id": relay,
                "operator_id": operator,
                "tool_version": OPERATOR_TOOL_VERSION,
                **reason_fields,
                "previous_status": previous_status,
                "previous_error_code": previous_error_code,
                "expected_error_codes": list(expected_codes),
                "error_code": "relay_failure_cause_not_approved_for_retry",
            }
            return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
        if previous_status == RELAY_STATUS_OPERATOR_REVIEW:
            receipt, receipt_valid = _decode_receipt_json(row["receipt_json"])
            if not receipt_valid:
                conn.rollback()
                report = {
                    "status": "BLOCKED",
                    "operation": "retry-dead",
                    "relay_id": relay,
                    "operator_id": operator,
                    "tool_version": OPERATOR_TOOL_VERSION,
                    **reason_fields,
                    "previous_status": previous_status,
                    "error_code": "operator_review_receipt_invalid",
                }
                return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
            committed = receipt.get("committed")
            local_committed = receipt.get("_local_upload_result_committed")
            ambiguous_or_committed = (
                committed is True
                or local_committed is True
                or (committed is not None and committed is not False)
                or (local_committed is not None and local_committed is not False)
            )
            if ambiguous_or_committed:
                conn.rollback()
                report = {
                    "status": "BLOCKED",
                    "operation": "retry-dead",
                    "relay_id": relay,
                    "operator_id": operator,
                    "tool_version": OPERATOR_TOOL_VERSION,
                    **reason_fields,
                    "previous_status": previous_status,
                    "error_code": "operator_review_committed_receipt_not_retryable",
                }
                return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
        spool_path = Path(str(row["spooled_file_path"] or ""))
        if not spool_path.is_file():
            conn.rollback()
            report = {
                "status": "BLOCKED",
                "operation": "retry-dead",
                "relay_id": relay,
                "operator_id": operator,
                "tool_version": OPERATOR_TOOL_VERSION,
                **reason_fields,
                "previous_status": previous_status,
                "error_code": "spooled_file_missing",
            }
            return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
        try:
            actual_hash, actual_bytes = _read_file_digest(spool_path)
        except OSError as exc:
            conn.rollback()
            report = {
                "status": "BLOCKED",
                "operation": "retry-dead",
                "relay_id": relay,
                "operator_id": operator,
                "tool_version": OPERATOR_TOOL_VERSION,
                **reason_fields,
                "previous_status": previous_status,
                "error_code": "spooled_file_missing" if isinstance(exc, FileNotFoundError) else "spooled_file_unreadable",
                "error_message": f"spooled file cannot be read: {exc.__class__.__name__}",
            }
            return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
        expected_hash = str(row["content_sha256"] or "")
        expected_bytes = int(row["byte_length"])
        if actual_hash != expected_hash or actual_bytes != expected_bytes:
            conn.rollback()
            report = {
                "status": "BLOCKED",
                "operation": "retry-dead",
                "relay_id": relay,
                "operator_id": operator,
                "tool_version": OPERATOR_TOOL_VERSION,
                **reason_fields,
                "previous_status": previous_status,
                "content_sha256": expected_hash,
                "byte_length": expected_bytes,
                "actual_content_sha256": actual_hash,
                "actual_byte_length": actual_bytes,
                "error_code": "spooled_file_digest_mismatch",
            }
            return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
        legacy_key_repair = _repair_legacy_idempotency_key_for_retry(row)
        repaired_metadata_json = str(legacy_key_repair.pop("metadata_json", "") or "")
        metadata_json_value = repaired_metadata_json if legacy_key_repair.get("applied") else str(row["metadata_json"] or "")
        try:
            retry_metadata = json.loads(metadata_json_value)
        except json.JSONDecodeError:
            conn.rollback()
            report = {
                "status": "BLOCKED",
                "operation": "retry-dead",
                "relay_id": relay,
                "operator_id": operator,
                "tool_version": OPERATOR_TOOL_VERSION,
                **reason_fields,
                "previous_status": previous_status,
                "error_code": "relay_metadata_invalid",
            }
            return _with_operator_audit_status(
                audit_log_path,
                action="retry-dead-blocked",
                report=report,
            )
        if not isinstance(retry_metadata, dict):
            conn.rollback()
            report = {
                "status": "BLOCKED",
                "operation": "retry-dead",
                "relay_id": relay,
                "operator_id": operator,
                "tool_version": OPERATOR_TOOL_VERSION,
                **reason_fields,
                "previous_status": previous_status,
                "error_code": "relay_metadata_invalid",
            }
            return _with_operator_audit_status(
                audit_log_path,
                action="retry-dead-blocked",
                report=report,
            )
        reset_runtime_fields = sorted(
            field_name
            for field_name in RETRY_RUNTIME_METADATA_FIELDS
            if field_name in retry_metadata
        )
        for field_name in reset_runtime_fields:
            retry_metadata.pop(field_name, None)
        if reset_runtime_fields:
            metadata_json_value = canonical_json(retry_metadata)
        cursor = conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?,
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = NULL,
                last_error_code = NULL,
                last_error_message = NULL,
                receipt_json = NULL,
                upload_status_path = NULL,
                metadata_json = ?,
                updated_at = ?
            WHERE relay_id = ?
              AND status = ?
              AND lease_owner IS NULL
              AND lease_expires_at IS NULL
            """,
            (RELAY_STATUS_PENDING, metadata_json_value, now, relay, previous_status),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            report = {
                "status": "BLOCKED",
                "operation": "retry-dead",
                "relay_id": relay,
                "operator_id": operator,
                "tool_version": OPERATOR_TOOL_VERSION,
                **reason_fields,
                "previous_status": previous_status,
                "error_code": "relay_status_changed",
            }
            return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
        conn.commit()
    except sqlite3.Error as exc:
        if conn is not None:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
        report = {
            "status": "BLOCKED",
            "operation": "retry-dead",
            "relay_id": relay,
            "operator_id": operator,
            "tool_version": OPERATOR_TOOL_VERSION,
            **reason_fields,
            "error_code": "relay_db_unavailable",
            "error_message": f"relay queue database error: {exc.__class__.__name__}",
        }
        return _with_operator_audit_status(audit_log_path, action="retry-dead-blocked", report=report)
    finally:
        if conn is not None:
            conn.close()
    report = {
        "status": "PASS",
        "operation": "retry-dead",
        "relay_id": relay,
        "operator_id": operator,
        "tool_version": OPERATOR_TOOL_VERSION,
        **reason_fields,
        "previous_status": previous_status,
        "previous_error_code": previous_error_code,
        "expected_error_codes": list(expected_codes),
        "new_status": RELAY_STATUS_PENDING,
        "previous_attempt_count": previous_attempt_count,
        "content_sha256": expected_hash,
        "byte_length": expected_bytes,
        "spool_file_name": spool_path.name,
        "legacy_idempotency_key_repair": legacy_key_repair,
        "reset_runtime_metadata_fields": reset_runtime_fields,
        "queue": read_relay_queue_status_read_only(db_path),
    }
    return _with_operator_audit_status(audit_log_path, action="retry-dead", report=report)


@writer_sink("operator_review_resolution")
def resolve_committed_operator_review(
    *,
    db_path: str | os.PathLike[str],
    relay_id: str,
    operator_id: str,
    reason: str,
    resolution: str,
    evidence_path: str | os.PathLike[str],
    evidence_sha256: str,
    expected_request_id: str,
    expected_server_source_file_id: str,
    expected_relative_path: str,
    expected_byte_length: int,
    expected_inserted_count: int,
    expected_replayed_count: int,
    expected_error_count: int,
    expected_quarantined_count: int,
    expected_content_sha256: str,
    audit_log_path: str | os.PathLike[str] = "",
) -> dict[str, Any]:
    """Resolve a committed review without retrying or rewriting its receipt.

    The original receipt remains the immutable server result.  The local ACK is
    permitted only after an operator supplies exact receipt/file expectations
    and a digest for the separately retained reconciliation evidence.
    """

    relay = _require_text(relay_id, field_name="relay_id", max_length=128)
    operator = _require_text(operator_id, field_name="operator_id", max_length=128)
    reason_text = _require_text(reason, field_name="reason")
    resolution_text = _require_text(resolution, field_name="resolution", max_length=64)
    request_id = _require_text(expected_request_id, field_name="expected_request_id", max_length=128)
    server_source_file_id = _require_text(
        expected_server_source_file_id,
        field_name="expected_server_source_file_id",
        max_length=1024,
    )
    relative_path = _require_text(expected_relative_path, field_name="expected_relative_path", max_length=1024)
    evidence_hash = _require_text(evidence_sha256, field_name="evidence_sha256", max_length=64).lower()
    content_hash = _require_text(
        expected_content_sha256,
        field_name="expected_content_sha256",
        max_length=64,
    ).lower()
    if resolution_text not in COMMITTED_REVIEW_RESOLUTIONS:
        raise ValueError("resolution is not an approved committed-review disposition")
    if not SHA256_RE.fullmatch(evidence_hash):
        raise ValueError("evidence_sha256 must be a SHA-256 hex digest")
    if not SHA256_RE.fullmatch(content_hash):
        raise ValueError("expected_content_sha256 must be a SHA-256 hex digest")
    try:
        quarantined_count = int(expected_quarantined_count)
    except (TypeError, ValueError) as exc:
        raise ValueError("expected_quarantined_count must be an integer") from exc
    if quarantined_count <= 0:
        raise ValueError("expected_quarantined_count must be positive")
    try:
        byte_length = int(expected_byte_length)
    except (TypeError, ValueError) as exc:
        raise ValueError("expected_byte_length must be an integer") from exc
    if byte_length <= 0:
        raise ValueError("expected_byte_length must be positive")
    expected_totals: dict[str, int] = {}
    for field, value in {
        "inserted": expected_inserted_count,
        "replayed": expected_replayed_count,
        "quarantined": expected_quarantined_count,
        "errors": expected_error_count,
    }.items():
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"expected_{field}_count must be an integer") from exc
        if parsed < 0:
            raise ValueError(f"expected_{field}_count must not be negative")
        expected_totals[field] = parsed
    if expected_totals["quarantined"] <= 0:
        raise ValueError("expected_quarantined_count must be positive")
    evidence, evidence_error = _load_committed_review_evidence(
        evidence_path,
        expected_sha256=evidence_hash,
        relay_id=relay,
        request_id=request_id,
        server_source_file_id=server_source_file_id,
        relative_path=relative_path,
        content_sha256=content_hash,
        byte_length=byte_length,
        resolution=resolution_text,
        expected_totals=expected_totals,
    )
    reason_fields = _reason_evidence(reason_text)

    def blocked(error_code: str, **extra: Any) -> dict[str, Any]:
        report = {
            "status": "BLOCKED",
            "operation": "resolve-review",
            "relay_id": relay,
            "operator_id": operator,
            "tool_version": OPERATOR_TOOL_VERSION,
            **reason_fields,
            "resolution": resolution_text,
            "evidence_path": str(evidence.get("path") or Path(str(evidence_path or ""))),
            "evidence_sha256": evidence_hash,
            "error_code": error_code,
        }
        report.update(extra)
        return _with_operator_audit_status(
            audit_log_path,
            action="resolve-review-blocked",
            report=report,
        )

    if evidence_error:
        return blocked(evidence_error)

    if not Path(db_path).is_file():
        return blocked("relay_db_not_initialized")
    now = utc_now_text()
    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS direct_sync_operator_resolutions (
                resolution_id TEXT PRIMARY KEY,
                relay_id TEXT NOT NULL UNIQUE,
                previous_status TEXT NOT NULL,
                new_status TEXT NOT NULL,
                resolution TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                request_id TEXT NOT NULL,
                server_source_file_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                byte_length INTEGER NOT NULL,
                quarantined_count INTEGER NOT NULL,
                operator_id TEXT NOT NULL,
                reason_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        row = conn.execute(
            """
            SELECT relay_id, status, lease_owner, lease_expires_at, receipt_json,
                   relative_path, content_sha256, byte_length, attempt_count,
                   spooled_file_path, upload_status_path, metadata_json
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            LIMIT 1
            """,
            (relay,),
        ).fetchone()
        if row is None:
            conn.rollback()
            return blocked("relay_not_found")
        previous_status = str(row["status"] or "")
        if previous_status != RELAY_STATUS_OPERATOR_REVIEW:
            existing = conn.execute(
                """
                SELECT resolution, evidence_sha256, request_id,
                       server_source_file_id, relative_path, content_sha256,
                       byte_length, quarantined_count, new_status
                FROM direct_sync_operator_resolutions
                WHERE relay_id = ?
                LIMIT 1
                """,
                (relay,),
            ).fetchone()
            conn.rollback()
            if (
                previous_status == RELAY_STATUS_ACKED
                and existing is not None
                and str(existing["resolution"] or "") == resolution_text
                and str(existing["evidence_sha256"] or "") == evidence_hash
                and str(existing["request_id"] or "") == request_id
                and str(existing["server_source_file_id"] or "") == server_source_file_id
                and str(existing["relative_path"] or "") == relative_path
                and str(existing["content_sha256"] or "") == content_hash
                and int(existing["byte_length"] or 0) == byte_length
                and int(existing["quarantined_count"] or 0) == quarantined_count
                and str(existing["new_status"] or "") == RELAY_STATUS_ACKED
            ):
                report = {
                    "status": "PASS",
                    "operation": "resolve-review",
                    "relay_id": relay,
                    "operator_id": operator,
                    "tool_version": OPERATOR_TOOL_VERSION,
                    **reason_fields,
                    "resolution": resolution_text,
                    "evidence_path": str(evidence["path"]),
                    "evidence_sha256": evidence_hash,
                    "evidence_schema_version": evidence["schema_version"],
                    "evidence_generated_at": evidence["generated_at"],
                    "expected_totals": dict(expected_totals),
                    "previous_status": previous_status,
                    "new_status": RELAY_STATUS_ACKED,
                    "already_resolved": True,
                    "receipt_preserved": True,
                }
                return _with_operator_audit_status(
                    audit_log_path,
                    action="resolve-review-idempotent",
                    report=report,
                )
            return blocked("relay_status_not_operator_review", previous_status=previous_status)
        if row["lease_owner"] is not None or row["lease_expires_at"] is not None:
            conn.rollback()
            return blocked("relay_review_has_active_lease", previous_status=previous_status)
        if str(row["relative_path"] or "") != relative_path:
            conn.rollback()
            return blocked(
                "relay_relative_path_mismatch",
                previous_status=previous_status,
                actual_relative_path=str(row["relative_path"] or ""),
            )
        if int(row["byte_length"] or 0) != byte_length:
            conn.rollback()
            return blocked(
                "relay_byte_length_mismatch",
                previous_status=previous_status,
                actual_byte_length=int(row["byte_length"] or 0),
            )
        if str(row["content_sha256"] or "").lower() != content_hash:
            conn.rollback()
            return blocked(
                "relay_content_sha256_mismatch",
                previous_status=previous_status,
                actual_content_sha256=str(row["content_sha256"] or "").lower(),
            )
        spool_path = Path(str(row["spooled_file_path"] or ""))
        if spool_path.is_symlink() or not spool_path.is_file():
            conn.rollback()
            return blocked("operator_review_spool_file_invalid", previous_status=previous_status)
        try:
            spool_sha256, spool_byte_length = _read_file_digest(spool_path)
        except OSError:
            conn.rollback()
            return blocked("operator_review_spool_file_unreadable", previous_status=previous_status)
        if spool_sha256 != content_hash or spool_byte_length != byte_length:
            conn.rollback()
            return blocked(
                "operator_review_spool_identity_mismatch",
                previous_status=previous_status,
                actual_spool_sha256=spool_sha256,
                actual_spool_byte_length=spool_byte_length,
            )
        raw_receipt = str(row["receipt_json"] or "")
        receipt, receipt_valid = _decode_receipt_json(raw_receipt)
        if not receipt_valid or not receipt:
            conn.rollback()
            return blocked("operator_review_receipt_invalid", previous_status=previous_status)
        if receipt.get("committed") is not True or receipt.get("_local_upload_result_committed") is not True:
            conn.rollback()
            return blocked("operator_review_receipt_not_definitively_committed", previous_status=previous_status)
        if str(receipt.get("status") or "") != "accepted":
            conn.rollback()
            return blocked(
                "operator_review_receipt_not_accepted",
                previous_status=previous_status,
                receipt_status=str(receipt.get("status") or ""),
            )
        if str(receipt.get("request_id") or "") != request_id:
            conn.rollback()
            return blocked(
                "operator_review_request_id_mismatch",
                previous_status=previous_status,
                actual_request_id=str(receipt.get("request_id") or ""),
            )
        if str(receipt.get("server_source_file_id") or "") != server_source_file_id:
            conn.rollback()
            return blocked(
                "operator_review_server_source_file_id_mismatch",
                previous_status=previous_status,
                actual_server_source_file_id=str(receipt.get("server_source_file_id") or ""),
            )
        if str(receipt.get("client_batch_id") or "") != relay or receipt.get("retryable") is not False:
            conn.rollback()
            return blocked("operator_review_receipt_binding_invalid", previous_status=previous_status)
        totals = receipt.get("totals")
        if not isinstance(totals, Mapping):
            conn.rollback()
            return blocked("operator_review_totals_invalid", previous_status=previous_status)
        try:
            actual_quarantined = int(totals.get("quarantined"))
            errors = int(totals.get("errors"))
            inserted = int(totals.get("inserted"))
            replayed = int(totals.get("replayed"))
        except (TypeError, ValueError):
            conn.rollback()
            return blocked("operator_review_totals_invalid", previous_status=previous_status)
        if actual_quarantined != quarantined_count:
            conn.rollback()
            return blocked(
                "operator_review_quarantined_count_mismatch",
                previous_status=previous_status,
                actual_quarantined_count=actual_quarantined,
            )
        actual_totals = {
            "inserted": inserted,
            "replayed": replayed,
            "quarantined": actual_quarantined,
            "errors": errors,
        }
        if actual_totals != expected_totals:
            conn.rollback()
            return blocked(
                "operator_review_exact_totals_mismatch",
                previous_status=previous_status,
                actual_totals=actual_totals,
            )
        if errors != 0 or min(inserted, replayed, actual_quarantined) < 0:
            conn.rollback()
            return blocked(
                "operator_review_receipt_not_resolution_eligible",
                previous_status=previous_status,
                totals={
                    "inserted": inserted,
                    "replayed": replayed,
                    "quarantined": actual_quarantined,
                    "errors": errors,
                },
            )
        try:
            metadata = json.loads(str(row["metadata_json"] or "{}"))
        except json.JSONDecodeError:
            conn.rollback()
            return blocked("operator_review_metadata_invalid", previous_status=previous_status)
        receipt_source = receipt.get("source_file")
        if not isinstance(metadata, dict) or not isinstance(receipt_source, Mapping):
            conn.rollback()
            return blocked("operator_review_source_contract_invalid", previous_status=previous_status)
        conserved_rows = inserted + replayed + actual_quarantined + errors
        try:
            metadata_rows = int(metadata.get("row_count"))
            declared_rows = int(receipt_source.get("declared_row_count"))
        except (TypeError, ValueError):
            conn.rollback()
            return blocked("operator_review_row_count_invalid", previous_status=previous_status)
        if conserved_rows != metadata_rows or conserved_rows != declared_rows:
            conn.rollback()
            return blocked(
                "operator_review_row_conservation_failed",
                previous_status=previous_status,
                conserved_rows=conserved_rows,
                metadata_row_count=metadata_rows,
                declared_row_count=declared_rows,
            )
        upload_status_path = Path(str(row["upload_status_path"] or ""))
        if upload_status_path.is_symlink() or not upload_status_path.is_file():
            conn.rollback()
            return blocked("operator_review_upload_status_invalid", previous_status=previous_status)
        try:
            if upload_status_path.stat().st_size > 1024 * 1024:
                raise ValueError("too large")
            upload_status_bytes = upload_status_path.read_bytes()
            if len(upload_status_bytes) > 1024 * 1024:
                raise ValueError("too large")
            upload_status_sha256 = hashlib.sha256(upload_status_bytes).hexdigest()
            upload_status = json.loads(upload_status_bytes.decode("utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            conn.rollback()
            return blocked("operator_review_upload_status_unreadable", previous_status=previous_status)
        upload_receipt = upload_status.get("receipt") if isinstance(upload_status, dict) else None
        upload_metadata = upload_status.get("metadata") if isinstance(upload_status, dict) else None
        if (
            not isinstance(upload_receipt, Mapping)
            or not isinstance(upload_metadata, Mapping)
            or upload_status.get("committed") is not True
            or upload_status.get("status_code") != 200
            or upload_receipt.get("request_id") != request_id
            or upload_receipt.get("server_source_file_id") != server_source_file_id
            or upload_receipt.get("totals") != actual_totals
            or upload_metadata.get("relative_path") != relative_path
            or upload_metadata.get("content_sha256") != content_hash
            or upload_metadata.get("byte_length") != byte_length
        ):
            conn.rollback()
            return blocked("operator_review_upload_status_mismatch", previous_status=previous_status)
        receipt_sha256 = hashlib.sha256(raw_receipt.encode("utf-8")).hexdigest()
        resolution_id = f"operator-resolution-{uuid.uuid4().hex}"
        conn.execute(
            """
            INSERT INTO direct_sync_operator_resolutions (
                resolution_id, relay_id, previous_status, new_status, resolution,
                evidence_sha256, receipt_sha256, request_id, server_source_file_id,
                relative_path, content_sha256, byte_length, quarantined_count,
                operator_id, reason_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                resolution_id,
                relay,
                previous_status,
                RELAY_STATUS_ACKED,
                resolution_text,
                evidence_hash,
                receipt_sha256,
                request_id,
                server_source_file_id,
                relative_path,
                content_hash,
                byte_length,
                actual_quarantined,
                operator,
                reason_fields["reason_sha256"],
                now,
            ),
        )
        cursor = conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?, updated_at = ?
            WHERE relay_id = ?
              AND status = ?
              AND lease_owner IS NULL
              AND lease_expires_at IS NULL
              AND receipt_json = ?
              AND content_sha256 = ?
            """,
            (
                RELAY_STATUS_ACKED,
                now,
                relay,
                RELAY_STATUS_OPERATOR_REVIEW,
                raw_receipt,
                content_hash,
            ),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return blocked("relay_status_changed", previous_status=previous_status)
        conn.commit()
    except sqlite3.Error as exc:
        if conn is not None:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
        return blocked("relay_db_unavailable", error_message=_sqlite_error_message(exc))
    finally:
        if conn is not None:
            conn.close()
    report = {
        "status": "PASS",
        "operation": "resolve-review",
        "relay_id": relay,
        "operator_id": operator,
        "tool_version": OPERATOR_TOOL_VERSION,
        **reason_fields,
        "resolution_id": resolution_id,
        "resolution": resolution_text,
        "evidence_path": str(evidence["path"]),
        "evidence_sha256": evidence_hash,
        "evidence_schema_version": evidence["schema_version"],
        "evidence_generated_at": evidence["generated_at"],
        "request_id": request_id,
        "server_source_file_id": server_source_file_id,
        "relative_path": relative_path,
        "content_sha256": content_hash,
        "byte_length": byte_length,
        "quarantined_count": actual_quarantined,
        "exact_totals": dict(actual_totals),
        "receipt_sha256": receipt_sha256,
        "spool_sha256": spool_sha256,
        "spool_byte_length": spool_byte_length,
        "receipt_preserved": True,
        "upload_status_path": str(upload_status_path),
        "upload_status_sha256": upload_status_sha256,
        "upload_status_path_preserved": True,
        "previous_status": RELAY_STATUS_OPERATOR_REVIEW,
        "new_status": RELAY_STATUS_ACKED,
        "previous_attempt_count": int(row["attempt_count"]),
        "already_resolved": False,
        "queue": read_relay_queue_status_read_only(db_path),
    }
    return _with_operator_audit_status(audit_log_path, action="resolve-review", report=report)


def _repair_legacy_idempotency_key_for_retry(row: sqlite3.Row) -> dict[str, Any]:
    if str(row["last_error_code"] or "") != "metadata_field_too_large":
        return {"applied": False}
    try:
        metadata = json.loads(str(row["metadata_json"] or "{}"))
    except json.JSONDecodeError:
        return {"applied": False, "blocked_reason": "metadata_json_invalid"}
    if not isinstance(metadata, dict):
        return {"applied": False, "blocked_reason": "metadata_not_object"}
    old_key = str(metadata.get("idempotency_key") or "")
    if not old_key.startswith(LEGACY_SOURCE_FILE_KEY_PREFIX):
        return {"applied": False}
    if len(old_key.encode("utf-8")) <= 128:
        return {"applied": False, "blocked_reason": "legacy_key_not_oversized"}
    source_host_id = str(metadata.get("source_host_id") or "").strip()
    producer_role = str(metadata.get("producer_role") or DEFAULT_PRODUCER_ROLE).strip()
    stream_name = str(metadata.get("stream_name") or "").strip()
    relative_path = str(metadata.get("relative_path") or row["relative_path"] or "").strip()
    content_sha256 = str(metadata.get("content_sha256") or row["content_sha256"] or "").strip().lower()
    if not source_host_id or not producer_role or not stream_name or not relative_path or not content_sha256:
        return {"applied": False, "blocked_reason": "stable_key_source_identity_incomplete"}
    source_file_id = f"{source_host_id}/{producer_role}/{stream_name}/{relative_path}"
    digest = hashlib.sha256(f"{source_file_id}\n{content_sha256}".encode("utf-8")).hexdigest()
    new_key = f"{SOURCE_FILE_STABLE_KEY_PREFIX}{digest}"
    if len(new_key.encode("utf-8")) > 128:
        return {"applied": False, "blocked_reason": "stable_key_too_large"}
    metadata["idempotency_key"] = new_key
    return {
        "applied": True,
        "metadata_json": canonical_json(metadata),
        "old_key_prefix": LEGACY_SOURCE_FILE_KEY_PREFIX,
        "old_key_bytes": len(old_key.encode("utf-8")),
        "new_key_prefix": SOURCE_FILE_STABLE_KEY_PREFIX,
        "new_key_bytes": len(new_key.encode("utf-8")),
        "source_file_id_sha256": hashlib.sha256(source_file_id.encode("utf-8")).hexdigest(),
    }

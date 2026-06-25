"""Local operator controls for the Container_Audit direct-sync relay."""

from __future__ import annotations

import hashlib
import datetime
import json
import os
import re
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Mapping

from direct_sync_push import (
    RELAY_STATUS_FAILED_PERMANENT,
    RELAY_STATUS_OPERATOR_REVIEW,
    RELAY_STATUS_PENDING,
    utc_now_text,
)


PAUSE_SCHEMA_VERSION = "direct-sync-relay-operator-pause-v1"
AUDIT_SCHEMA_VERSION = "direct-sync-relay-operator-audit-v1"
OPERATOR_TOOL_VERSION = "container-audit-local-operator-v1"
RETRYABLE_DEAD_STATUSES = frozenset({RELAY_STATUS_FAILED_PERMANENT})
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
REASON_REDACTED_RE = re.compile(r"^sha256:[A-Fa-f0-9]{12}$")
DEAD_LETTER_STATUSES = (RELAY_STATUS_OPERATOR_REVIEW, RELAY_STATUS_FAILED_PERMANENT)
RUNTIME_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(authorization|bearer|credential|hmac|raw_payload|receipt_json|secret|signature|source_file_bytes|source_file_text|token)"
)
AUTHORIZATION_TEXT_RE = re.compile(r"(?i)\b(?:authorization|x-producer-signature)\s*:\s*[^\r\n,;]+")
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<key>api[_-]?key|hmac|password|passwd|secret|signature|token)\s*=\s*[^\s,;]+"
)


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
        return {"status": "not_initialized", "counts": {}, "oldest_active_created_at": ""}
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        return {
            "status": "blocked",
            "counts": {},
            "oldest_active_created_at": "",
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
        return {
            "status": "PASS",
            "counts": counts,
            "oldest_active_created_at": oldest["created_at"] if oldest else "",
        }
    except sqlite3.Error as exc:
        return {
            "status": "blocked",
            "counts": {},
            "oldest_active_created_at": "",
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


def retry_dead_relay_batch(
    *,
    db_path: str | os.PathLike[str],
    relay_id: str,
    operator_id: str,
    reason: str,
    audit_log_path: str | os.PathLike[str] = "",
    allow_operator_review: bool = False,
) -> dict[str, Any]:
    relay = _require_text(relay_id, field_name="relay_id", max_length=128)
    operator = _require_text(operator_id, field_name="operator_id", max_length=128)
    reason_text = _require_text(reason, field_name="reason")
    reason_fields = _reason_evidence(reason_text)
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
            SELECT relay_id, status, attempt_count, spooled_file_path, content_sha256, byte_length, receipt_json
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
                updated_at = ?
            WHERE relay_id = ?
              AND status = ?
              AND lease_owner IS NULL
              AND lease_expires_at IS NULL
            """,
            (RELAY_STATUS_PENDING, now, relay, previous_status),
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
        "new_status": RELAY_STATUS_PENDING,
        "previous_attempt_count": previous_attempt_count,
        "content_sha256": expected_hash,
        "byte_length": expected_bytes,
        "spool_file_name": spool_path.name,
        "queue": read_relay_queue_status_read_only(db_path),
    }
    return _with_operator_audit_status(audit_log_path, action="retry-dead", report=report)

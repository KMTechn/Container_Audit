from __future__ import annotations

import csv
import datetime
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Set

from event_contracts import stable_hash
from event_payloads import product_barcodes_from_completion
from label_qr import canonical_master_label_key, inspection_master_item_code, parse_new_format_qr, parse_positive_quantity


@dataclass
class SessionHistory:
    log_file_path: str
    completed_master_labels: Set[str] = field(default_factory=set)
    work_summary: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    total_tray_count: int = 0
    completed_tray_times: List[float] = field(default_factory=list)
    load_errors: List[str] = field(default_factory=list)


def _remember_completed_label(labels: Set[str], master_label: str) -> None:
    if not isinstance(master_label, str) or not master_label:
        return
    labels.add(master_label)
    labels.add(canonical_master_label_key(master_label))


def _text_field(details: Dict[str, Any], key: str, default: str = "") -> str:
    value = details.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise TypeError(f"{key} must be text")
    return value


def _history_int_field(details: Dict[str, Any], key: str, *, minimum: int) -> int | None:
    if key not in details:
        return None
    value = details.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{key} must be an integer")
    if value < minimum:
        raise ValueError(f"{key} must be >= {minimum}")
    return value


def _validate_history_complete_details(details: Dict[str, Any]) -> None:
    for key in ("master_label_code", "item_code", "item_name", "spec"):
        _text_field(details, key)
    master_label = _text_field(details, "master_label_code")
    item_code = _text_field(details, "item_code")
    if not master_label.strip():
        raise ValueError("master_label_code must be non-empty")
    if not item_code.strip():
        raise ValueError("item_code must be non-empty")
    master_label_fields = parse_new_format_qr(master_label) or {}
    label_item_code = inspection_master_item_code(master_label_fields)
    if label_item_code and label_item_code != item_code:
        raise ValueError("master_label_code CLC must match item_code")
    tray_capacity = _history_int_field(details, "tray_capacity", minimum=1)
    if any(str(master_label_fields.get(key) or "").strip() for key in ("QT", "QTY", "QUANTITY")) and "tray_capacity" in details:
        parsed_label_quantity = parse_positive_quantity(master_label_fields)
        if parsed_label_quantity is None or parsed_label_quantity <= 0 or tray_capacity is None or parsed_label_quantity != tray_capacity:
            raise ValueError("master_label_code QT must match tray_capacity")
    scan_count = _history_int_field(details, "scan_count", minimum=0)
    barcode_count = _history_int_field(details, "barcode_count", minimum=0)
    if scan_count is not None and tray_capacity is not None and scan_count > tray_capacity:
        raise ValueError("scan_count must not exceed tray_capacity")
    product_barcodes = product_barcodes_from_completion(details)
    if product_barcodes:
        if scan_count is not None and scan_count != len(product_barcodes):
            raise ValueError("scan_count must match product_barcodes")
        if barcode_count is not None and barcode_count != len(product_barcodes):
            raise ValueError("barcode_count must match product_barcodes")
    if scan_count is not None and barcode_count is not None and scan_count != barcode_count:
        raise ValueError("scan_count must match barcode_count")
    for key in ("has_error_or_reset", "is_partial_submission", "is_restored_session", "is_test_tray"):
        if key in details and not isinstance(details[key], bool):
            raise TypeError(f"{key} must be a boolean")


def _replacement_source_identity(details: Dict[str, Any]) -> Dict[str, Any]:
    identity = details.get("original_event_identity")
    if isinstance(identity, dict):
        return identity
    identity = details.get("supersedes_identity")
    if isinstance(identity, dict):
        return identity
    return {}


def _validate_history_replacement_details(
    details: Dict[str, Any],
    *,
    stable_hash_func: Callable[[Dict[str, Any]], str] | None = None,
    require_projection: bool = False,
) -> None:
    old_label = _text_field(details, "old_master_label")
    new_label = _text_field(details, "new_master_label")
    if not old_label.strip() or not new_label.strip():
        raise ValueError("replacement labels must be non-empty")
    if not parse_new_format_qr(old_label) or not parse_new_format_qr(new_label):
        raise ValueError("replacement labels must be parseable master labels")
    if canonical_master_label_key(old_label) == canonical_master_label_key(new_label):
        raise ValueError("replacement labels must not be equivalent")

    projection = details.get("corrected_completion_projection")
    if projection is None:
        if require_projection:
            raise ValueError("replacement projection is required")
        return
    if not isinstance(projection, dict):
        raise TypeError("replacement projection must be a mapping")
    _validate_history_complete_details(projection)
    projection_label = _text_field(projection, "master_label_code")
    if canonical_master_label_key(projection_label) != canonical_master_label_key(new_label):
        raise ValueError("replacement projection master_label_code must match new_master_label")

    if stable_hash_func is None:
        return
    expected_payload_hash = stable_hash_func(projection)
    if _text_field(details, "new_payload_hash") != expected_payload_hash:
        raise ValueError("replacement new_payload_hash does not match projection")

    identity = _replacement_source_identity(details)
    source_system = identity.get("source_system")
    source_transport = identity.get("source_transport_or_dataset")
    source_file_id = identity.get("source_file_id")
    source_row_number = identity.get("source_row_number")
    source_byte_offset = identity.get("source_byte_offset")
    if not isinstance(source_system, str) or not source_system.strip():
        raise ValueError("replacement source_system is missing")
    if not isinstance(source_transport, str) or not source_transport.strip():
        raise ValueError("replacement source_transport_or_dataset is missing")
    if not isinstance(source_file_id, str) or not source_file_id.strip():
        raise ValueError("replacement source_file_id is missing")
    if isinstance(source_row_number, bool) or not isinstance(source_row_number, int) or source_row_number <= 0:
        raise ValueError("replacement source_row_number is invalid")
    if source_byte_offset is not None and (
        isinstance(source_byte_offset, bool) or not isinstance(source_byte_offset, int) or source_byte_offset < 0
    ):
        raise ValueError("replacement source_byte_offset is invalid")
    expected_row_hash = stable_hash_func(
        {
            "source_system": source_system,
            "source_transport_or_dataset": source_transport,
            "source_file_id": source_file_id,
            "source_row_number": source_row_number,
            "source_byte_offset": source_byte_offset,
            "payload_hash": expected_payload_hash,
        }
    )
    if _text_field(details, "new_row_hash") != expected_row_hash:
        raise ValueError("replacement new_row_hash does not match projection identity")


def _validated_history_summary_key(details: Dict[str, Any]) -> str:
    value = _text_field(details, "item_code", "UNKNOWN")
    return value or "UNKNOWN"


def _history_spec(details: Dict[str, Any]) -> str:
    if "spec" in details:
        return _text_field(details, "spec", "")
    return _text_field(details, "item_spec", "")


def _completion_replay_identity(details: Dict[str, Any]) -> str | None:
    master_label = _text_field(details, "master_label_code")
    if not parse_new_format_qr(master_label):
        return None
    label_identity = canonical_master_label_key(master_label)
    if details.get("is_partial_submission") is True:
        intent_id = str(details.get("transfer_seal_intent_id") or "").strip()
        if not intent_id:
            intent_id = stable_hash(
                {
                    "master_label": label_identity,
                    "product_barcodes": product_barcodes_from_completion(details),
                }
            )
        return f"{label_identity}|partial:{intent_id}"
    return label_identity


def _sanitize_worker_name(worker_name: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', "", str(worker_name or ""))


def _session_capacity(session: Dict[str, Any], fallback_tray_size: int) -> int:
    value = session.get("tray_capacity", fallback_tray_size)
    if isinstance(value, bool):
        return fallback_tray_size
    try:
        capacity = int(value)
    except (TypeError, ValueError):
        return fallback_tray_size
    return capacity if capacity > 0 else fallback_tray_size


def _session_scan_count(session: Dict[str, Any]) -> int | None:
    value = session.get("scan_count")
    if isinstance(value, bool):
        return None
    try:
        scan_count = int(value)
    except (TypeError, ValueError):
        return None
    return scan_count if scan_count >= 0 else None


def load_session_history(
    *,
    save_folder: str | os.PathLike[str],
    worker_name: str,
    today: datetime.date,
    tray_size: int,
    lookback_days: int = 7,
    minimum_realistic_time_per_pc: float = 5.0,
) -> SessionHistory:
    sanitized_name = _sanitize_worker_name(worker_name)
    log_file_path = str(Path(save_folder) / f"이적작업이벤트로그_{sanitized_name}_{today.strftime('%Y%m%d')}.csv")
    history = SessionHistory(log_file_path=log_file_path)
    lookback_start_date = today - datetime.timedelta(days=lookback_days)
    log_file_pattern = re.compile(r"(이적작업이벤트로그|검사작업이벤트로그)_(.+)_(\d{8})\.csv")
    all_log_files: List[tuple[Path, bool]] = []

    try:
        for path in Path(save_folder).iterdir():
            if not path.is_file():
                continue
            match = log_file_pattern.fullmatch(path.name)
            if not match:
                continue
            prefix, matched_worker, date_text = match.groups()
            try:
                file_date = datetime.datetime.strptime(date_text, "%Y%m%d").date()
            except ValueError:
                continue
            if file_date <= today:
                include_for_summary = (
                    prefix == "이적작업이벤트로그"
                    and lookback_start_date <= file_date <= today
                    and matched_worker == sanitized_name
                )
                all_log_files.append((path, include_for_summary))
    except FileNotFoundError:
        return history

    completed_sessions: List[Dict[str, Any]] = []
    seen_current_worker_completion_identities: Set[str] = set()
    for log_path, is_current_worker_file in sorted(all_log_files):
        if not log_path.exists():
            continue
        try:
            with log_path.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                for row_number, row in enumerate(reader, start=2):
                    event_name = row.get("event")
                    if event_name not in {"MASTER_LABEL_REPLACEMENT_APPLIED", "TRAY_COMPLETE"}:
                        continue
                    try:
                        details = json.loads(row["details"])
                    except (json.JSONDecodeError, KeyError, ValueError):
                        history.load_errors.append(f"로그 파일 '{log_path}' {row_number}행 {row.get('event', '') or 'UNKNOWN'} 처리 중 오류")
                        continue
                    if not isinstance(details, dict):
                        history.load_errors.append(f"로그 파일 '{log_path}' {row_number}행 {row.get('event', '') or 'UNKNOWN'} 처리 중 오류")
                        continue

                    try:
                        timestamp = datetime.datetime.fromisoformat(row["timestamp"])
                    except (KeyError, TypeError, ValueError):
                        history.load_errors.append(f"로그 파일 '{log_path}' {row_number}행 {event_name} 처리 중 오류")
                        continue
                    if timestamp.date() > today:
                        continue

                    if event_name == "MASTER_LABEL_REPLACEMENT_APPLIED":
                        try:
                            _validate_history_replacement_details(details, stable_hash_func=stable_hash)
                            _remember_completed_label(history.completed_master_labels, _text_field(details, "old_master_label"))
                            _remember_completed_label(history.completed_master_labels, _text_field(details, "new_master_label"))
                        except (TypeError, ValueError):
                            history.load_errors.append(f"로그 파일 '{log_path}' {row_number}행 MASTER_LABEL_REPLACEMENT_APPLIED 처리 중 오류")
                        continue
                    try:
                        _validate_history_complete_details(details)
                        details["timestamp"] = timestamp
                        details["_history_source"] = f"{log_path}:{row_number}"
                        if (
                            details.get("is_test_tray") is not True
                            and details.get("is_partial_submission") is not True
                        ):
                            _remember_completed_label(history.completed_master_labels, _text_field(details, "master_label_code"))
                        row_worker_name = _sanitize_worker_name(row.get("worker_name", ""))
                        if is_current_worker_file and row_worker_name == sanitized_name:
                            completion_identity = _completion_replay_identity(details)
                            if completion_identity:
                                if completion_identity in seen_current_worker_completion_identities:
                                    continue
                                seen_current_worker_completion_identities.add(completion_identity)
                            completed_sessions.append(details)
                    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                        history.load_errors.append(f"로그 파일 '{log_path}' {row_number}행 TRAY_COMPLETE 처리 중 오류")
                        continue
        except Exception as exc:
            history.load_errors.append(f"로그 파일 '{log_path}' 처리 중 오류: {exc}")

    if not completed_sessions:
        return history

    today_sessions = [session for session in completed_sessions if session["timestamp"].date() == today]
    start_of_week = today - datetime.timedelta(days=today.weekday())
    current_week_sessions = [session for session in completed_sessions if session["timestamp"].date() >= start_of_week]

    for session in today_sessions:
        item_code = _validated_history_summary_key(session)
        if item_code not in history.work_summary:
            history.work_summary[item_code] = {
                "name": _text_field(session, "item_name", "알 수 없음") or "알 수 없음",
                "spec": _history_spec(session),
                "count": 0,
                "test_count": 0,
            }
        if session.get("is_test_tray", False):
            history.work_summary[item_code]["test_count"] += 1
        else:
            history.work_summary[item_code]["count"] += 1
        if not session.get("is_test_tray", False) and not session.get("is_partial_submission", False):
            history.total_tray_count += 1

    valid_times: List[float] = []
    for session in current_week_sessions:
        capacity = _session_capacity(session, tray_size)
        scan_count = _session_scan_count(session)
        if not (
            scan_count == capacity
            and session.get("has_error_or_reset") is False
            and session.get("is_partial_submission") is False
            and session.get("is_restored_session") is False
            and session.get("is_test_tray") is False
        ):
            continue
        try:
            work_time = float(session.get("work_time_sec", 0.0))
        except (TypeError, ValueError):
            history.load_errors.append(f"{session.get('_history_source', 'TRAY_COMPLETE')} work_time_sec 처리 중 오류")
            continue
        if work_time / capacity >= minimum_realistic_time_per_pc:
            valid_times.append(work_time)
    history.completed_tray_times = valid_times
    return history

import datetime
import json
from pathlib import Path
from typing import Any, Callable, Dict, Mapping

from label_qr import inspection_master_item_code, parse_new_format_qr, parse_positive_quantity
from protected_admin import persistent_operator_name
from writer_session_fence import writer_sink


class TrayStateValidationError(ValueError):
    pass


FUTURE_TIMESTAMP_SKEW_SECONDS = 300.0
OPERATOR_REVIEW_STATE_KEY = "pending_operator_review"
OPERATOR_REVIEW_STATE_SCHEMA_VERSION = 1
COMPLETION_EVENT_STATE_KEY = "pending_completion_event"
COMPLETION_EVENT_STATE_SCHEMA_VERSION = 1
ACTIVATION_EVENT_STATE_KEY = "pending_activation_event"
ACTIVATION_EVENT_STATE_SCHEMA_VERSION = 1
ACTIVATION_EVENT_TYPES = frozenset(
    {
        "MASTER_LABEL_SCANNED_NEW",
        "MASTER_LABEL_SCANNED_OLD",
    }
)
PARKED_RESTORE_STATE_KEY = "pending_parked_restore"
PARKED_RESTORE_STATE_SCHEMA_VERSION = 1
PARKED_RESTORE_EVENT_TYPES = frozenset(
    {
        "TRAY_DISCARDED_BY_OPERATOR",
        "TRAY_RESTORED_FROM_PARK",
    }
)


def tray_session_to_state(tray: Any, *, worker_name: str) -> Dict[str, Any]:
    master_label = str(tray.master_label_code or "")
    canonical_input_tag_qr = str(
        getattr(tray, "canonical_input_tag_qr", "") or master_label
    )
    active_label_qr_payload = str(
        getattr(tray, "active_label_qr_payload", "") or master_label
    )
    return {
        "worker_name": persistent_operator_name(worker_name),
        "master_label_code": master_label,
        "canonical_input_tag_qr": canonical_input_tag_qr,
        "active_label_qr_payload": active_label_qr_payload,
        "active_label_id": str(getattr(tray, "active_label_id", "") or ""),
        "active_label_business_date": str(
            getattr(tray, "active_label_business_date", "") or ""
        ),
        "active_label_worker_code": str(
            getattr(tray, "active_label_worker_code", "") or ""
        ),
        "operation_lease_id": str(
            getattr(tray, "operation_lease_id", "") or ""
        ),
        "item_code": tray.item_code,
        "item_name": tray.item_name,
        "item_spec": tray.item_spec,
        "scanned_barcodes": list(tray.scanned_barcodes),
        "scan_times": [dt.isoformat() for dt in tray.scan_times],
        "tray_size": tray.tray_size,
        "mismatch_error_count": tray.mismatch_error_count,
        "total_idle_seconds": tray.total_idle_seconds,
        "stopwatch_seconds": tray.stopwatch_seconds,
        "start_time": tray.start_time.isoformat() if tray.start_time else None,
        "has_error_or_reset": tray.has_error_or_reset,
        "is_test_tray": tray.is_test_tray,
        "is_partial_submission": tray.is_partial_submission,
    }


def _require_mapping(state: Any) -> Mapping[str, Any]:
    if not isinstance(state, Mapping):
        raise TrayStateValidationError("tray state must be a JSON object")
    return state


def _require_string(state: Mapping[str, Any], key: str, *, allow_empty: bool = True) -> None:
    value = state.get(key)
    if not isinstance(value, str):
        raise TrayStateValidationError(f"{key} must be a string")
    if not allow_empty and not value.strip():
        raise TrayStateValidationError(f"{key} must not be empty")


def _require_non_negative_number(state: Mapping[str, Any], key: str) -> None:
    value = state.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TrayStateValidationError(f"{key} must be a number")
    if value < 0:
        raise TrayStateValidationError(f"{key} must be non-negative")


def _require_non_negative_int(state: Mapping[str, Any], key: str) -> None:
    value = state.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TrayStateValidationError(f"{key} must be a non-negative integer")


def _validate_master_label_consistency(state: Mapping[str, Any], *, tray_size: int) -> None:
    master_label_fields = parse_new_format_qr(state["master_label_code"])
    if not master_label_fields:
        return

    parsed_item_code = inspection_master_item_code(master_label_fields)
    state_item_code = str(state.get("item_code") or "").strip()
    if parsed_item_code and state_item_code and parsed_item_code != state_item_code:
        raise TrayStateValidationError("master_label_code CLC must match item_code")

    parsed_tray_size = parse_positive_quantity(master_label_fields)
    if parsed_tray_size is not None and parsed_tray_size != tray_size:
        raise TrayStateValidationError("master_label_code QT must match tray_size")


def _validate_phs_label_state(state: Mapping[str, Any]) -> None:
    master_label = str(state.get("master_label_code") or "")
    canonical = state.get("canonical_input_tag_qr", master_label)
    active = state.get("active_label_qr_payload", master_label)
    active_label_id = state.get("active_label_id", "")
    active_business_date = state.get("active_label_business_date", "")
    active_worker_code = state.get("active_label_worker_code", "")
    operation_lease_id = state.get("operation_lease_id", "")
    for key, value in (
        ("canonical_input_tag_qr", canonical),
        ("active_label_qr_payload", active),
        ("active_label_id", active_label_id),
        ("active_label_business_date", active_business_date),
        ("active_label_worker_code", active_worker_code),
        ("operation_lease_id", operation_lease_id),
    ):
        if not isinstance(value, str):
            raise TrayStateValidationError(f"{key} must be a string")

    master_fields = parse_new_format_qr(master_label)
    if str((master_fields or {}).get("PHS") or "").strip() != "2":
        if operation_lease_id:
            raise TrayStateValidationError(
                "operation_lease_id is only valid for a PHS2 tray"
            )
        return
    canonical_fields = parse_new_format_qr(canonical)
    active_fields = parse_new_format_qr(active)
    required = ("PHS", "SRC", "ITG", "CLC", "LBL", "HSH")
    if (
        canonical != master_label
        or set(canonical_fields or {}) != set(required)
        or set(active_fields or {}) != set(required)
        or any(not str((canonical_fields or {}).get(key) or "").strip() for key in required)
        or any(not str((active_fields or {}).get(key) or "").strip() for key in required)
        or str(canonical_fields.get("PHS") or "").strip() != "2"
        or str(active_fields.get("PHS") or "").strip() != "2"
        or str(canonical_fields.get("SRC") or "").strip().upper()
        != "KMTECH_INPUT_TAG"
        or str(active_fields.get("SRC") or "").strip().upper()
        != "KMTECH_INPUT_TAG"
        or len(str(canonical_fields.get("HSH") or "").strip()) != 16
        or any(
            value not in "0123456789abcdef"
            for value in str(
                canonical_fields.get("HSH") or ""
            ).strip().lower()
        )
        or len(str(active_fields.get("HSH") or "").strip()) != 16
        or any(
            value not in "0123456789abcdef"
            for value in str(
                active_fields.get("HSH") or ""
            ).strip().lower()
        )
        or str(canonical_fields.get("ITG") or "").strip()
        != str(master_fields.get("ITG") or "").strip()
        or str(canonical_fields.get("CLC") or "").strip()
        != str(master_fields.get("CLC") or "").strip()
        or str(active_fields.get("ITG") or "").strip()
        != str(canonical_fields.get("ITG") or "").strip()
        or str(active_fields.get("CLC") or "").strip()
        != str(canonical_fields.get("CLC") or "").strip()
    ):
        raise TrayStateValidationError(
            "canonical and active PHS2 labels must retain the master ITG/item anchor"
        )
    parsed_active_label_id = str(active_fields.get("LBL") or "").strip()
    if active_label_id and active_label_id != parsed_active_label_id:
        raise TrayStateValidationError(
            "active_label_id must match active_label_qr_payload LBL"
        )
    if active_business_date:
        try:
            parsed_date = datetime.datetime.strptime(
                active_business_date, "%Y-%m-%d"
            )
        except ValueError as exc:
            raise TrayStateValidationError(
                "active_label_business_date must be YYYY-MM-DD"
            ) from exc
        if parsed_date.strftime("%Y-%m-%d") != active_business_date:
            raise TrayStateValidationError(
                "active_label_business_date must be YYYY-MM-DD"
            )


def _validate_pending_operator_review(
    state: Mapping[str, Any],
    *,
    scanned_barcodes: list[str],
    tray_size: int,
) -> None:
    payload = state.get(OPERATOR_REVIEW_STATE_KEY)
    if payload is None:
        return
    if not isinstance(payload, Mapping):
        raise TrayStateValidationError(f"{OPERATOR_REVIEW_STATE_KEY} must be a JSON object")
    if payload.get("schema_version") != OPERATOR_REVIEW_STATE_SCHEMA_VERSION:
        raise TrayStateValidationError(f"{OPERATOR_REVIEW_STATE_KEY} has an unsupported schema version")
    if payload.get("outcome") not in {
        "OPERATOR_REVIEW",
        "RETRY_WAIT",
        "LOCAL_EVENT_RETRY",
    }:
        raise TrayStateValidationError(
            f"{OPERATOR_REVIEW_STATE_KEY} outcome is unsupported"
        )
    for key in ("item_name", "master_label", "message", "receipt_id", "error_code"):
        if not isinstance(payload.get(key), str):
            raise TrayStateValidationError(f"{OPERATOR_REVIEW_STATE_KEY}.{key} must be a string")
    for key in ("scan_count", "target_count"):
        value = payload.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise TrayStateValidationError(
                f"{OPERATOR_REVIEW_STATE_KEY}.{key} must be a non-negative integer"
            )
    scan_count = payload["scan_count"]
    target_count = payload["target_count"]
    if scan_count > target_count:
        raise TrayStateValidationError(f"{OPERATOR_REVIEW_STATE_KEY} scan_count exceeds target_count")
    if scan_count != len(scanned_barcodes):
        raise TrayStateValidationError(f"{OPERATOR_REVIEW_STATE_KEY} scan_count does not match tray state")
    if target_count != tray_size:
        raise TrayStateValidationError(f"{OPERATOR_REVIEW_STATE_KEY} target_count does not match tray_size")
    if payload["master_label"] != state.get("master_label_code"):
        raise TrayStateValidationError(f"{OPERATOR_REVIEW_STATE_KEY} master_label does not match tray state")
    if payload["item_name"] != state.get("item_name"):
        raise TrayStateValidationError(f"{OPERATOR_REVIEW_STATE_KEY} item_name does not match tray state")
    if not payload["message"].strip():
        raise TrayStateValidationError(f"{OPERATOR_REVIEW_STATE_KEY}.message must not be empty")


def _validate_pending_completion_event(
    state: Mapping[str, Any],
    *,
    now: datetime.datetime,
    future_clock_skew_seconds: float,
) -> None:
    payload = state.get(COMPLETION_EVENT_STATE_KEY)
    if payload is None:
        return
    if not isinstance(payload, Mapping):
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY} must be a JSON object"
        )
    if payload.get("schema_version") != COMPLETION_EVENT_STATE_SCHEMA_VERSION:
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY} has an unsupported schema version"
        )
    for key in (
        "event_type",
        "idempotency_key",
        "observed_at",
        "projection_log_name",
        "projection_worker_name",
        "transfer_intent_id",
    ):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise TrayStateValidationError(
                f"{COMPLETION_EVENT_STATE_KEY}.{key} must be non-empty text"
            )
    if payload["event_type"] != "TRAY_COMPLETE":
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY}.event_type must be TRAY_COMPLETE"
        )
    intent_id = payload["transfer_intent_id"].strip()
    if payload["idempotency_key"].strip() != f"tray-complete:{intent_id}":
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY}.idempotency_key does not match transfer intent"
        )
    log_name = payload["projection_log_name"].strip()
    if (
        log_name != Path(log_name).name
        or "/" in log_name
        or "\\" in log_name
        or not log_name.lower().endswith(".csv")
    ):
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY}.projection_log_name is invalid"
        )
    projection_worker_name = payload["projection_worker_name"].strip()
    if (
        len(projection_worker_name) > 128
        or any(ord(character) < 32 for character in projection_worker_name)
    ):
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY}.projection_worker_name is invalid"
        )
    observed_at = _parse_iso_datetime(
        payload["observed_at"], key=f"{COMPLETION_EVENT_STATE_KEY}.observed_at"
    )
    _reject_future_datetime(
        observed_at,
        key=f"{COMPLETION_EVENT_STATE_KEY}.observed_at",
        now=now,
        future_clock_skew_seconds=future_clock_skew_seconds,
    )
    for key in ("was_restored_session", "log_may_have_been_attempted"):
        if not isinstance(payload.get(key), bool):
            raise TrayStateValidationError(
                f"{COMPLETION_EVENT_STATE_KEY}.{key} must be a boolean"
            )
    transfer_detail = payload.get("transfer_detail")
    if not isinstance(transfer_detail, Mapping):
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY}.transfer_detail must be a JSON object"
        )
    if len(transfer_detail) > 64:
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY}.transfer_detail is too large"
        )
    detail_intent = str(transfer_detail.get("transfer_seal_intent_id") or "").strip()
    if transfer_detail and detail_intent != intent_id:
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY}.transfer_detail intent mismatch"
        )
    if payload["log_may_have_been_attempted"] and not transfer_detail:
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY}.transfer_detail is required after log admission"
        )
    review = state.get(OPERATOR_REVIEW_STATE_KEY)
    if isinstance(review, Mapping) and review.get("outcome") not in {
        "OPERATOR_REVIEW",
        "RETRY_WAIT",
        "LOCAL_EVENT_RETRY",
    }:
        raise TrayStateValidationError(
            f"{COMPLETION_EVENT_STATE_KEY} conflicts with non-retryable completion state"
        )


def _validate_pending_activation_event(
    state: Mapping[str, Any],
    *,
    now: datetime.datetime,
    future_clock_skew_seconds: float,
) -> None:
    """Validate the durable outbox row paired with a new active tray.

    The event payload lives in the same atomically replaced JSON document as
    the tray state.  CSV is only an idempotent projection of this row, so a
    process crash cannot leave an active tray without the information needed
    to reproduce its exact audit event.
    """

    payload = state.get(ACTIVATION_EVENT_STATE_KEY)
    if payload is None:
        return
    if not isinstance(payload, Mapping):
        raise TrayStateValidationError(
            f"{ACTIVATION_EVENT_STATE_KEY} must be a JSON object"
        )
    if payload.get("schema_version") != ACTIVATION_EVENT_STATE_SCHEMA_VERSION:
        raise TrayStateValidationError(
            f"{ACTIVATION_EVENT_STATE_KEY} has an unsupported schema version"
        )
    for key in (
        "event_type",
        "idempotency_key",
        "observed_at",
        "projection_log_name",
        "projection_worker_name",
        "master_label_code",
    ):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise TrayStateValidationError(
                f"{ACTIVATION_EVENT_STATE_KEY}.{key} must be non-empty text"
            )
    event_type = payload["event_type"].strip()
    if event_type not in ACTIVATION_EVENT_TYPES:
        raise TrayStateValidationError(
            f"{ACTIVATION_EVENT_STATE_KEY}.event_type is unsupported"
        )
    idempotency_key = payload["idempotency_key"].strip()
    key_prefix = "tray-activation:"
    key_suffix = idempotency_key[len(key_prefix) :] if idempotency_key.startswith(key_prefix) else ""
    if len(key_suffix) != 32 or any(character not in "0123456789abcdef" for character in key_suffix):
        raise TrayStateValidationError(
            f"{ACTIVATION_EVENT_STATE_KEY}.idempotency_key is invalid"
        )
    if payload["master_label_code"] != state.get("master_label_code"):
        raise TrayStateValidationError(
            f"{ACTIVATION_EVENT_STATE_KEY}.master_label_code does not match tray state"
        )
    log_name = payload["projection_log_name"].strip()
    if (
        log_name != Path(log_name).name
        or "/" in log_name
        or "\\" in log_name
        or not log_name.lower().endswith(".csv")
    ):
        raise TrayStateValidationError(
            f"{ACTIVATION_EVENT_STATE_KEY}.projection_log_name is invalid"
        )
    projection_worker_name = payload["projection_worker_name"].strip()
    if (
        len(projection_worker_name) > 128
        or any(ord(character) < 32 for character in projection_worker_name)
    ):
        raise TrayStateValidationError(
            f"{ACTIVATION_EVENT_STATE_KEY}.projection_worker_name is invalid"
        )
    observed_at = _parse_iso_datetime(
        payload["observed_at"],
        key=f"{ACTIVATION_EVENT_STATE_KEY}.observed_at",
    )
    _reject_future_datetime(
        observed_at,
        key=f"{ACTIVATION_EVENT_STATE_KEY}.observed_at",
        now=now,
        future_clock_skew_seconds=future_clock_skew_seconds,
    )
    event_detail = payload.get("event_detail")
    if not isinstance(event_detail, Mapping):
        raise TrayStateValidationError(
            f"{ACTIVATION_EVENT_STATE_KEY}.event_detail must be a JSON object"
        )
    if len(event_detail) > 128:
        raise TrayStateValidationError(
            f"{ACTIVATION_EVENT_STATE_KEY}.event_detail is too large"
        )
    try:
        json.dumps(event_detail, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise TrayStateValidationError(
            f"{ACTIVATION_EVENT_STATE_KEY}.event_detail is not canonical JSON"
        ) from exc


def _validate_parked_restore_projection_event(
    payload: Any,
    *,
    operation_id: str,
    restored_master_label_code: str,
    now: datetime.datetime,
    future_clock_skew_seconds: float,
) -> str:
    key_root = f"{PARKED_RESTORE_STATE_KEY}.projection_events"
    if not isinstance(payload, Mapping):
        raise TrayStateValidationError(f"{key_root} entries must be JSON objects")
    for key in (
        "event_type",
        "canonical_event_name",
        "idempotency_key",
        "observed_at",
        "projection_log_name",
        "projection_worker_name",
    ):
        value = payload.get(key)
        if not isinstance(value, str):
            raise TrayStateValidationError(f"{key_root}.{key} must be text")
    event_type = payload["event_type"].strip()
    if event_type not in PARKED_RESTORE_EVENT_TYPES:
        raise TrayStateValidationError(f"{key_root}.event_type is unsupported")
    expected_suffix = (
        "discard"
        if event_type == "TRAY_DISCARDED_BY_OPERATOR"
        else "restore"
    )
    if payload["idempotency_key"] != f"{operation_id}:{expected_suffix}":
        raise TrayStateValidationError(f"{key_root}.idempotency_key is invalid")
    canonical_event_name = payload["canonical_event_name"].strip()
    if event_type == "TRAY_RESTORED_FROM_PARK":
        if canonical_event_name != "TRAY_RESTORED":
            raise TrayStateValidationError(
                f"{key_root}.canonical_event_name is invalid"
            )
    elif canonical_event_name:
        raise TrayStateValidationError(
            f"{key_root}.canonical_event_name must be empty"
        )
    log_name = payload["projection_log_name"].strip()
    if (
        not log_name
        or log_name != Path(log_name).name
        or "/" in log_name
        or "\\" in log_name
        or not log_name.lower().endswith(".csv")
    ):
        raise TrayStateValidationError(
            f"{key_root}.projection_log_name is invalid"
        )
    projection_worker_name = payload["projection_worker_name"].strip()
    if (
        not projection_worker_name
        or len(projection_worker_name) > 128
        or any(ord(character) < 32 for character in projection_worker_name)
    ):
        raise TrayStateValidationError(
            f"{key_root}.projection_worker_name is invalid"
        )
    observed_at = _parse_iso_datetime(
        payload["observed_at"],
        key=f"{key_root}.observed_at",
    )
    _reject_future_datetime(
        observed_at,
        key=f"{key_root}.observed_at",
        now=now,
        future_clock_skew_seconds=future_clock_skew_seconds,
    )
    event_detail = payload.get("event_detail")
    if not isinstance(event_detail, Mapping):
        raise TrayStateValidationError(f"{key_root}.event_detail must be a JSON object")
    if len(event_detail) > 128:
        raise TrayStateValidationError(f"{key_root}.event_detail is too large")
    try:
        json.dumps(event_detail, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise TrayStateValidationError(
            f"{key_root}.event_detail is not canonical JSON"
        ) from exc
    if (
        event_type == "TRAY_RESTORED_FROM_PARK"
        and str(event_detail.get("master_label_code") or "")
        != restored_master_label_code
    ):
        raise TrayStateValidationError(
            f"{key_root}.event_detail does not match restored tray"
        )
    return event_type


def _validate_pending_parked_restore(
    state: Mapping[str, Any],
    *,
    now: datetime.datetime,
    future_clock_skew_seconds: float,
) -> None:
    payload = state.get(PARKED_RESTORE_STATE_KEY)
    if payload is None:
        return
    if not isinstance(payload, Mapping):
        raise TrayStateValidationError(
            f"{PARKED_RESTORE_STATE_KEY} must be a JSON object"
        )
    if payload.get("schema_version") != PARKED_RESTORE_STATE_SCHEMA_VERSION:
        raise TrayStateValidationError(
            f"{PARKED_RESTORE_STATE_KEY} has an unsupported schema version"
        )
    operation_id = payload.get("operation_id")
    operation_prefix = "parked-restore:"
    if not isinstance(operation_id, str) or not operation_id.startswith(
        operation_prefix
    ):
        raise TrayStateValidationError(
            f"{PARKED_RESTORE_STATE_KEY}.operation_id is invalid"
        )
    operation_suffix = operation_id[len(operation_prefix) :]
    if len(operation_suffix) != 32 or any(
        character not in "0123456789abcdef" for character in operation_suffix
    ):
        raise TrayStateValidationError(
            f"{PARKED_RESTORE_STATE_KEY}.operation_id is invalid"
        )
    source_name = payload.get("parked_source_name")
    if (
        not isinstance(source_name, str)
        or not source_name
        or source_name != Path(source_name).name
        or not source_name.startswith("parked_")
        or not source_name.lower().endswith(".json")
    ):
        raise TrayStateValidationError(
            f"{PARKED_RESTORE_STATE_KEY}.parked_source_name is invalid"
        )
    source_sha256 = payload.get("parked_source_sha256")
    if (
        not isinstance(source_sha256, str)
        or len(source_sha256) != 64
        or any(character not in "0123456789abcdef" for character in source_sha256)
    ):
        raise TrayStateValidationError(
            f"{PARKED_RESTORE_STATE_KEY}.parked_source_sha256 is invalid"
        )
    restored_master_label_code = str(
        payload.get("restored_master_label_code") or ""
    )
    if (
        not restored_master_label_code
        or restored_master_label_code != str(state.get("master_label_code") or "")
    ):
        raise TrayStateValidationError(
            f"{PARKED_RESTORE_STATE_KEY}.restored_master_label_code does not match tray state"
        )
    projection_events = payload.get("projection_events")
    if not isinstance(projection_events, list) or len(projection_events) not in {1, 2}:
        raise TrayStateValidationError(
            f"{PARKED_RESTORE_STATE_KEY}.projection_events is invalid"
        )
    event_types = [
        _validate_parked_restore_projection_event(
            event,
            operation_id=operation_id,
            restored_master_label_code=restored_master_label_code,
            now=now,
            future_clock_skew_seconds=future_clock_skew_seconds,
        )
        for event in projection_events
    ]
    expected = (
        ["TRAY_RESTORED_FROM_PARK"]
        if len(event_types) == 1
        else ["TRAY_DISCARDED_BY_OPERATOR", "TRAY_RESTORED_FROM_PARK"]
    )
    if event_types != expected:
        raise TrayStateValidationError(
            f"{PARKED_RESTORE_STATE_KEY}.projection_events order is invalid"
        )


def _parse_iso_datetime(value: str, *, key: str) -> datetime.datetime:
    try:
        return datetime.datetime.fromisoformat(value)
    except ValueError as exc:
        raise TrayStateValidationError(f"{key} contains an invalid ISO timestamp: {value}") from exc


def _has_timezone(value: datetime.datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _require_comparable_datetimes(left: datetime.datetime, right: datetime.datetime) -> None:
    if _has_timezone(left) != _has_timezone(right):
        raise TrayStateValidationError("tray timestamps must use consistent timezone awareness")


def _future_limit_for(
    reference: datetime.datetime,
    *,
    now: datetime.datetime,
    future_clock_skew_seconds: float,
) -> datetime.datetime:
    if _has_timezone(reference) and not _has_timezone(now):
        comparison_now = datetime.datetime.now(reference.tzinfo)
    elif not _has_timezone(reference) and _has_timezone(now):
        comparison_now = now.replace(tzinfo=None)
    else:
        comparison_now = now.astimezone(reference.tzinfo) if _has_timezone(reference) else now
    return comparison_now + datetime.timedelta(seconds=future_clock_skew_seconds)


def _reject_future_datetime(
    value: datetime.datetime,
    *,
    key: str,
    now: datetime.datetime,
    future_clock_skew_seconds: float,
) -> None:
    if value > _future_limit_for(value, now=now, future_clock_skew_seconds=future_clock_skew_seconds):
        raise TrayStateValidationError(f"{key} must not be in the future")


def validate_tray_state(
    state: Any,
    *,
    default_tray_size: int,
    now: datetime.datetime | None = None,
    future_clock_skew_seconds: float = FUTURE_TIMESTAMP_SKEW_SECONDS,
) -> Mapping[str, Any]:
    state = _require_mapping(state)
    validation_now = now or datetime.datetime.now()
    _require_string(state, "worker_name", allow_empty=False)
    _require_string(state, "master_label_code", allow_empty=False)
    _require_string(state, "item_code", allow_empty=False)
    _require_string(state, "item_name")
    _require_string(state, "item_spec")
    _require_non_negative_int(state, "mismatch_error_count")
    _require_non_negative_number(state, "total_idle_seconds")
    _require_non_negative_number(state, "stopwatch_seconds")

    tray_size = state.get("tray_size", default_tray_size)
    if not isinstance(tray_size, int) or isinstance(tray_size, bool) or tray_size <= 0:
        raise TrayStateValidationError("tray_size must be a positive integer")

    scanned_barcodes = state.get("scanned_barcodes")
    if not isinstance(scanned_barcodes, list) or not all(isinstance(value, str) for value in scanned_barcodes):
        raise TrayStateValidationError("scanned_barcodes must be a list of strings")
    if len(scanned_barcodes) != len(set(scanned_barcodes)):
        raise TrayStateValidationError("scanned_barcodes must not contain duplicates")

    scan_times = state.get("scan_times")
    if not isinstance(scan_times, list) or not all(isinstance(value, str) for value in scan_times):
        raise TrayStateValidationError("scan_times must be a list of ISO timestamp strings")
    if len(scan_times) != len(scanned_barcodes):
        raise TrayStateValidationError("scan_times length must match scanned_barcodes length")
    if len(scanned_barcodes) > tray_size:
        raise TrayStateValidationError("scanned_barcodes length must not exceed tray_size")
    parsed_scan_times: list[datetime.datetime] = []
    for scan_time in scan_times:
        parsed_scan_times.append(_parse_iso_datetime(scan_time, key="scan_times"))

    previous_scan_time: datetime.datetime | None = None
    for scan_time in parsed_scan_times:
        _reject_future_datetime(
            scan_time,
            key="scan_times",
            now=validation_now,
            future_clock_skew_seconds=future_clock_skew_seconds,
        )
        if previous_scan_time is not None:
            _require_comparable_datetimes(previous_scan_time, scan_time)
            if scan_time < previous_scan_time:
                raise TrayStateValidationError("scan_times must be in chronological order")
        previous_scan_time = scan_time

    start_time = state.get("start_time")
    parsed_start_time: datetime.datetime | None = None
    if start_time is not None:
        if not isinstance(start_time, str):
            raise TrayStateValidationError("start_time must be an ISO timestamp string or null")
        parsed_start_time = _parse_iso_datetime(start_time, key="start_time")
        _reject_future_datetime(
            parsed_start_time,
            key="start_time",
            now=validation_now,
            future_clock_skew_seconds=future_clock_skew_seconds,
        )
        for scan_time in parsed_scan_times:
            _require_comparable_datetimes(parsed_start_time, scan_time)
            if scan_time < parsed_start_time:
                raise TrayStateValidationError("scan_times must not be before start_time")

    for key in ("has_error_or_reset", "is_test_tray", "is_partial_submission"):
        value = state.get(key, False)
        if not isinstance(value, bool):
            raise TrayStateValidationError(f"{key} must be a boolean")

    _validate_master_label_consistency(state, tray_size=tray_size)
    _validate_phs_label_state(state)
    _validate_pending_operator_review(
        state,
        scanned_barcodes=scanned_barcodes,
        tray_size=tray_size,
    )
    _validate_pending_completion_event(
        state,
        now=validation_now,
        future_clock_skew_seconds=future_clock_skew_seconds,
    )
    _validate_pending_activation_event(
        state,
        now=validation_now,
        future_clock_skew_seconds=future_clock_skew_seconds,
    )
    _validate_pending_parked_restore(
        state,
        now=validation_now,
        future_clock_skew_seconds=future_clock_skew_seconds,
    )

    return state


@writer_sink("tray_state_quarantine")
def quarantine_tray_state_file(path: str | Path, *, now: datetime.datetime | None = None) -> Path:
    source = Path(path)
    timestamp = (now or datetime.datetime.now()).strftime("%Y%m%d%H%M%S")
    target = source.with_name(f"{source.name}.bad-{timestamp}")
    suffix = 1
    while target.exists():
        target = source.with_name(f"{source.name}.bad-{timestamp}-{suffix}")
        suffix += 1
    source.replace(target)
    return target


def tray_session_from_state(
    state: Dict[str, Any],
    *,
    session_factory: Callable[..., Any],
    default_tray_size: int,
) -> Any:
    active_label_qr_payload = state.get(
        "active_label_qr_payload", state["master_label_code"]
    )
    active_fields = parse_new_format_qr(active_label_qr_payload) or {}
    active_label_id = state.get("active_label_id") or str(
        active_fields.get("LBL") or ""
    ).strip()
    return session_factory(
        master_label_code=state["master_label_code"],
        canonical_input_tag_qr=state.get(
            "canonical_input_tag_qr", state["master_label_code"]
        ),
        active_label_qr_payload=active_label_qr_payload,
        active_label_id=active_label_id,
        active_label_business_date=state.get(
            "active_label_business_date", ""
        ),
        active_label_worker_code=state.get("active_label_worker_code", ""),
        operation_lease_id=state.get("operation_lease_id", ""),
        item_code=state["item_code"],
        item_name=state["item_name"],
        item_spec=state["item_spec"],
        scanned_barcodes=list(state["scanned_barcodes"]),
        scan_times=[datetime.datetime.fromisoformat(dt) for dt in state["scan_times"]],
        tray_size=state.get("tray_size", default_tray_size),
        mismatch_error_count=state["mismatch_error_count"],
        total_idle_seconds=state["total_idle_seconds"],
        stopwatch_seconds=state["stopwatch_seconds"],
        start_time=datetime.datetime.fromisoformat(state["start_time"]) if state.get("start_time") else None,
        has_error_or_reset=state.get("has_error_or_reset", False),
        is_test_tray=state.get("is_test_tray", False),
        is_partial_submission=state.get("is_partial_submission", False),
        is_restored_session=True,
    )

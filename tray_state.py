import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Mapping

from label_qr import inspection_master_item_code, parse_new_format_qr, parse_positive_quantity


class TrayStateValidationError(ValueError):
    pass


FUTURE_TIMESTAMP_SKEW_SECONDS = 300.0


def tray_session_to_state(tray: Any, *, worker_name: str) -> Dict[str, Any]:
    return {
        "worker_name": worker_name,
        "master_label_code": tray.master_label_code,
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

    return state


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
    return session_factory(
        master_label_code=state["master_label_code"],
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

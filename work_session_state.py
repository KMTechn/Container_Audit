import datetime
import json
from pathlib import Path
from typing import Any, Dict, Mapping


WORK_SESSION_STATE_SCHEMA_VERSION = 1
WORK_SESSION_PHASE_START_PENDING = "START_PENDING"
WORK_SESSION_PHASE_ACTIVE = "ACTIVE"
WORK_SESSION_PHASE_END_PENDING = "END_PENDING"
WORK_SESSION_PHASE_CLOSED = "CLOSED"
WORK_SESSION_PHASES = frozenset(
    {
        WORK_SESSION_PHASE_START_PENDING,
        WORK_SESSION_PHASE_ACTIVE,
        WORK_SESSION_PHASE_END_PENDING,
        WORK_SESSION_PHASE_CLOSED,
    }
)
WORK_SESSION_EVENT_TYPES = frozenset({"WORK_START", "WORK_END"})
FUTURE_TIMESTAMP_SKEW_SECONDS = 300.0


class WorkSessionStateError(ValueError):
    pass


def _parse_timestamp(value: Any, *, key: str) -> datetime.datetime:
    if not isinstance(value, str) or not value.strip():
        raise WorkSessionStateError(f"{key} must be non-empty ISO text")
    try:
        return datetime.datetime.fromisoformat(value)
    except ValueError as exc:
        raise WorkSessionStateError(f"{key} is invalid") from exc


def _validate_identifier(value: Any, *, prefix: str, key: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix):
        raise WorkSessionStateError(f"{key} is invalid")
    suffix = value[len(prefix) :]
    if len(suffix) != 32 or any(
        character not in "0123456789abcdef" for character in suffix
    ):
        raise WorkSessionStateError(f"{key} is invalid")
    return value


def _coerce_for_comparison(
    value: datetime.datetime,
    reference: datetime.datetime,
) -> datetime.datetime:
    if value.tzinfo is not None and reference.tzinfo is None:
        return value.replace(tzinfo=None)
    if value.tzinfo is None and reference.tzinfo is not None:
        return value.replace(tzinfo=reference.tzinfo)
    return value


def _validate_event(
    payload: Any,
    *,
    session_id: str,
    worker_name: str,
    expected_event_type: str,
    now: datetime.datetime,
    future_clock_skew_seconds: float,
) -> Dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise WorkSessionStateError("pending_event must be a JSON object")
    event_type = str(payload.get("event_type") or "").strip()
    if event_type != expected_event_type or event_type not in WORK_SESSION_EVENT_TYPES:
        raise WorkSessionStateError("pending_event.event_type is invalid")
    session_suffix = session_id.removeprefix("work-session:")
    expected_key = (
        f"work-session-start:{session_suffix}"
        if event_type == "WORK_START"
        else f"work-session-end:{session_suffix}"
    )
    if payload.get("idempotency_key") != expected_key:
        raise WorkSessionStateError("pending_event.idempotency_key is invalid")
    if payload.get("projection_worker_name") != worker_name:
        raise WorkSessionStateError("pending_event worker does not match session")
    log_name = str(payload.get("projection_log_name") or "").strip()
    if (
        not log_name
        or log_name != Path(log_name).name
        or "/" in log_name
        or "\\" in log_name
        or not log_name.lower().endswith(".csv")
    ):
        raise WorkSessionStateError("pending_event.projection_log_name is invalid")
    observed_at = _parse_timestamp(
        payload.get("observed_at"),
        key="pending_event.observed_at",
    )
    observed_for_compare = _coerce_for_comparison(observed_at, now)
    if observed_for_compare > now + datetime.timedelta(
        seconds=future_clock_skew_seconds
    ):
        raise WorkSessionStateError("pending_event.observed_at is too far in the future")
    detail = payload.get("event_detail")
    if not isinstance(detail, Mapping) or len(detail) > 64:
        raise WorkSessionStateError("pending_event.event_detail is invalid")
    try:
        json.dumps(detail, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise WorkSessionStateError("pending_event.event_detail is not JSON-safe") from exc
    return {
        "schema_version": int(payload.get("schema_version") or 0),
        "event_type": event_type,
        "canonical_event_name": str(payload.get("canonical_event_name") or ""),
        "idempotency_key": expected_key,
        "observed_at": str(payload["observed_at"]),
        "projection_log_name": log_name,
        "projection_worker_name": worker_name,
        "event_detail": dict(detail),
    }


def validate_work_session_state(
    state: Any,
    *,
    now: datetime.datetime | None = None,
    future_clock_skew_seconds: float = FUTURE_TIMESTAMP_SKEW_SECONDS,
) -> Dict[str, Any]:
    if not isinstance(state, Mapping):
        raise WorkSessionStateError("work session state must be a JSON object")
    if state.get("schema_version") != WORK_SESSION_STATE_SCHEMA_VERSION:
        raise WorkSessionStateError("unsupported work session schema version")
    session_id = _validate_identifier(
        state.get("session_id"),
        prefix="work-session:",
        key="session_id",
    )
    worker_name = str(state.get("worker_name") or "").strip()
    if (
        not worker_name
        or len(worker_name) > 128
        or any(ord(character) < 32 for character in worker_name)
    ):
        raise WorkSessionStateError("worker_name is invalid")
    worker_role = str(state.get("worker_role") or "").strip()
    if worker_role not in {"WORKER", "ADMIN"}:
        raise WorkSessionStateError("worker_role is invalid")
    phase = str(state.get("phase") or "").strip()
    if phase not in WORK_SESSION_PHASES:
        raise WorkSessionStateError("phase is invalid")
    validation_now = now or datetime.datetime.now()
    started_at = _parse_timestamp(state.get("started_at"), key="started_at")
    started_for_compare = _coerce_for_comparison(started_at, validation_now)
    if started_for_compare > validation_now + datetime.timedelta(
        seconds=future_clock_skew_seconds
    ):
        raise WorkSessionStateError("started_at is too far in the future")
    ended_at_raw = state.get("ended_at")
    ended_at = None
    if ended_at_raw not in {None, ""}:
        ended_at = _parse_timestamp(ended_at_raw, key="ended_at")
        ended_for_compare = _coerce_for_comparison(ended_at, started_at)
        if ended_for_compare < started_at:
            raise WorkSessionStateError("ended_at precedes started_at")
    previous_session_id = str(state.get("previous_session_id") or "").strip()
    if previous_session_id:
        _validate_identifier(
            previous_session_id,
            prefix="work-session:",
            key="previous_session_id",
        )
        if previous_session_id == session_id:
            raise WorkSessionStateError("previous_session_id cannot equal session_id")
    pending_event = state.get("pending_event")
    expected_event_type = ""
    if phase == WORK_SESSION_PHASE_START_PENDING:
        expected_event_type = "WORK_START"
        if ended_at is not None:
            raise WorkSessionStateError("START_PENDING cannot have ended_at")
    elif phase == WORK_SESSION_PHASE_END_PENDING:
        expected_event_type = "WORK_END"
        if ended_at is None:
            raise WorkSessionStateError("END_PENDING requires ended_at")
    elif pending_event is not None:
        raise WorkSessionStateError("settled work session cannot have pending_event")
    if phase == WORK_SESSION_PHASE_ACTIVE and ended_at is not None:
        raise WorkSessionStateError("ACTIVE cannot have ended_at")
    if phase == WORK_SESSION_PHASE_CLOSED and ended_at is None:
        raise WorkSessionStateError("CLOSED requires ended_at")
    normalized_event = None
    if expected_event_type:
        normalized_event = _validate_event(
            pending_event,
            session_id=session_id,
            worker_name=worker_name,
            expected_event_type=expected_event_type,
            now=validation_now,
            future_clock_skew_seconds=future_clock_skew_seconds,
        )
        if normalized_event["schema_version"] != 1:
            raise WorkSessionStateError("pending_event schema version is invalid")
    return {
        "schema_version": WORK_SESSION_STATE_SCHEMA_VERSION,
        "session_id": session_id,
        "previous_session_id": previous_session_id,
        "worker_name": worker_name,
        "worker_role": worker_role,
        "phase": phase,
        "started_at": str(state["started_at"]),
        "ended_at": str(ended_at_raw or ""),
        "pending_event": normalized_event,
    }

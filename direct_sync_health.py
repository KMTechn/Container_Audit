"""Sanitized read-only DirectSync health model for the operator UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from typing import Any, Mapping

from direct_sync_operator import read_relay_queue_status_read_only, read_runtime_status


RELAY_HEALTH_SPEC = "container-audit-relay-health-v1"
ACTIVE_STATUSES = ("pending", "retry_wait", "leased")
RUNTIME_BLOCKED_STATUSES = {
    "blocked_disk_pressure",
    "blocked_queue_backpressure",
    "enqueue_error",
    "failed_permanent",
    "operator_review",
}


def _safe_count(counts: Mapping[str, Any], key: str) -> int:
    value = counts.get(key, 0)
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


@dataclass(frozen=True)
class RelayHealth:
    state: str
    pending_count: int
    failed_permanent_count: int
    operator_review_count: int
    last_acked_at: str
    oldest_pending_at: str
    observed_at: str
    error_code: str = ""
    clock_warning: Mapping[str, Any] = field(default_factory=dict)
    scan_terminal_blocked_count: int = 0
    scan_terminal_blocked_record_count: int | None = None

    @property
    def operator_attention(self) -> bool:
        return self.state in {"review", "blocked", "isolated"}

    @property
    def read_failed(self) -> bool:
        return self.error_code in {
            "relay_health_read_failed", "relay_status_unreadable",
            "relay_db_open_failed", "relay_db_schema_unavailable",
            "relay_health_not_loaded",
        }


def read_relay_health(
    *,
    db_path: str | os.PathLike[str],
    runtime_status_path: str | os.PathLike[str] = "",
) -> RelayHealth:
    queue_status = read_relay_queue_status_read_only(db_path)
    counts = (
        queue_status.get("counts")
        if isinstance(queue_status.get("counts"), Mapping)
        else {}
    )
    pending_count = sum(_safe_count(counts, status) for status in ACTIVE_STATUSES)
    failed_permanent = _safe_count(counts, "failed_permanent")
    operator_review = _safe_count(counts, "operator_review")
    runtime = read_runtime_status(runtime_status_path)
    runtime_enabled = bool(runtime.get("enabled"))
    runtime_available = bool(runtime.get("available"))
    runtime_state = str(runtime.get("status") or "").strip().lower()
    runtime_payload = runtime.get("payload") if isinstance(runtime.get("payload"), Mapping) else {}
    runtime_lease = runtime_payload.get("runtime_lease")

    state = "ready"
    error_code = ""
    if queue_status.get("status") == "blocked":
        state = "blocked"
        error_code = str(queue_status.get("error_code") or "relay_status_unreadable")
    elif runtime_enabled and not runtime_available:
        state = "blocked"
        error_code = str(runtime.get("error_code") or "runtime_status_unreadable")
    elif runtime_state in RUNTIME_BLOCKED_STATUSES:
        state = "blocked"
        error_code = "direct_sync_runtime_blocked"
    elif isinstance(runtime_lease, Mapping) and runtime_lease.get("status") == "operator_review":
        # Scanning continues; the relay stays stopped until an administrator acts.
        state = "isolated"
        error_code = "runtime_lease_operator_review"
    elif failed_permanent or operator_review:
        state = "review"
        error_code = (
            "direct_sync_operator_review"
            if operator_review
            else "direct_sync_failed_permanent"
        )
    elif pending_count:
        state = "pending"

    clock_warning = runtime_payload.get("clock_warning")
    if not (isinstance(clock_warning, Mapping)
            and clock_warning.get("status_code") == 401
            and clock_warning.get("error_code") == "stale_timestamp"):
        clock_warning = {}
    if clock_warning and not error_code:
        error_code = "stale_timestamp"

    return RelayHealth(
        state=state,
        pending_count=pending_count,
        failed_permanent_count=failed_permanent,
        operator_review_count=operator_review,
        last_acked_at=str(queue_status.get("last_acked_at") or ""),
        oldest_pending_at=str(queue_status.get("oldest_active_created_at") or ""),
        observed_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        error_code=error_code,
        clock_warning=clock_warning,
        scan_terminal_blocked_count=_safe_count(runtime_payload, "scan_terminal_blocked_count"),
        scan_terminal_blocked_record_count=(
            runtime_payload["scan_terminal_blocked_record_count"]
            if isinstance(runtime_payload.get("scan_terminal_blocked_record_count"), int)
            and not isinstance(runtime_payload["scan_terminal_blocked_record_count"], bool)
            and runtime_payload["scan_terminal_blocked_record_count"] >= 0 else None
        ),
    )


def relay_clock_warning_model(health: RelayHealth | None) -> dict[str, str]:
    if not isinstance(health, RelayHealth) or not health.clock_warning:
        return {}
    tail = "찍은 기록은 이 PC에 그대로 있고, 시계를 맞추면 저절로 보내집니다"
    observation = health.clock_warning.get("clock_skew")
    if isinstance(observation, Mapping):
        try:
            pc = datetime.fromisoformat(str(observation["pc_time_utc"]).replace("Z", "+00:00"))
            server = datetime.fromisoformat(str(observation["server_time_utc"]).replace("Z", "+00:00"))
            if pc.tzinfo is not None and server.tzinfo is not None:
                tail += f" · 이 PC {pc.astimezone():%H:%M} · 회사 서버 {server.astimezone():%H:%M}"
        except (KeyError, ValueError, TypeError, OverflowError):
            pass
    return {
        "kind": "warn",
        "text": "이 PC 시계가 회사 서버와 5분 넘게 달라 기록을 보내지 못하고 있습니다 — 현장 관리자에게 알리세요",
        "tail": tail,
    }


def relay_blocked_files_warning_model(health: RelayHealth | None) -> dict[str, str]:
    if not isinstance(health, RelayHealth) or not health.scan_terminal_blocked_count:
        return {}
    records = health.scan_terminal_blocked_record_count
    quantity = f" {records}건" if records is not None else ""
    return {
        "kind": "warn",
        "text": f"회사 서버가 받지 않은 기록이 있어 그 뒤 기록{quantity}을 보내지 못하고 있습니다 — 현장 관리자에게 알리세요",
        "tail": f"찍은 기록은 이 PC에 그대로 있습니다 · 막힌 기록 파일 {health.scan_terminal_blocked_count}개",
    }


def relay_send_warning_model(health: RelayHealth | None) -> dict[str, str]:
    """One nonblocking send band, ahead of the four existing alert slots."""
    if not isinstance(health, RelayHealth):
        return {}
    clock = relay_clock_warning_model(health)
    if clock:
        if health.scan_terminal_blocked_count and health.scan_terminal_blocked_record_count is not None:
            clock["tail"] += (
                f" · 막혀서 못 보낸 기록 {health.scan_terminal_blocked_record_count}건"
                f" · 막힌 기록 파일 {health.scan_terminal_blocked_count}개"
            )
        return clock
    blocked = relay_blocked_files_warning_model(health)
    if blocked:
        return blocked
    if health.pending_count and health.oldest_pending_at:
        try:
            oldest = datetime.fromisoformat(health.oldest_pending_at.replace("Z", "+00:00")).astimezone()
            delayed = (datetime.now().astimezone() - oldest).total_seconds() > 600
        except (ValueError, TypeError, OverflowError):
            delayed = False
        if delayed:
            return {
                "kind": "warn",
                "text": "회사 서버로 기록을 보내지 못하고 있습니다 — 현장 관리자에게 알리세요",
                "tail": "찍은 기록은 이 PC에 그대로 있고, 연결이 돌아오면 저절로 보내집니다",
            }
    return {}


def _compact_timestamp(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "없음"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return "확인 필요"
    return parsed.astimezone().strftime("%m-%d %H:%M")


def relay_health_card_model(
    health: RelayHealth,
    transfer_pending_count: int = 0,
) -> dict[str, str]:
    """``transfer_pending_count``: completions stored on this PC and not yet
    accepted by the server, which the app itself sends again."""
    tone = "amber" if health.operator_attention else "neutral"
    review_count = health.failed_permanent_count + health.operator_review_count
    if health.state == "blocked":
        summary = "전송 확인 필요"
        detail = f"대기 {health.pending_count}건 · 전송 상세 확인"
        if review_count:
            detail += f" · 담당자 확인 {review_count}건"
    elif health.state == "isolated":
        summary = "서버 반영 멈춤"
        detail = "작업 계속 가능 · 관리자에게 알려 주세요"
    elif health.operator_attention:
        summary = f"담당자 확인 {review_count}건"
        detail = f"전송 대기 {health.pending_count}건"
    elif health.pending_count:
        summary = f"전송 대기 {health.pending_count}건"
        detail = "자동 전송 예정"
    else:
        summary = "전송 대기 없음"
        detail = ""
    if transfer_pending_count > 0:
        transfer = f"완료 전송 대기 {transfer_pending_count}건"
        if health.state == "ready":
            summary, detail = transfer, "자동으로 다시 보냄"
        else:
            detail = " · ".join(value for value in (detail, transfer) if value)
    return {
        "summary": summary,
        "detail": detail,
        "tone": tone,
    }


def relay_health_detail_model(
    health: RelayHealth,
    *,
    last_read_health: RelayHealth | None = None,
) -> dict[str, str]:
    has_previous_read = isinstance(last_read_health, RelayHealth)
    values = last_read_health if health.read_failed and has_previous_read else health
    detail = {
        "대기": str(values.pending_count),
        "영구 실패": str(values.failed_permanent_count),
        "담당자 확인": str(values.operator_review_count),
        "가장 오래된 대기": _compact_timestamp(values.oldest_pending_at),
        "마지막 ACK": _compact_timestamp(values.last_acked_at),
        "상태": health.state,
        "진단 코드": health.error_code or "없음",
    }
    if health.read_failed:
        if has_previous_read:
            detail["확인 상태"] = "읽기 실패 · 마지막 확인값"
            detail["마지막 확인 시각"] = _compact_timestamp(last_read_health.observed_at)
        else:
            for label in ("대기", "영구 실패", "담당자 확인", "가장 오래된 대기", "마지막 ACK"):
                detail[label] = "미확인"
            detail["확인 상태"] = (
                "미확인 · 아직 읽지 못함"
                if health.error_code == "relay_health_not_loaded"
                else "미확인 · 읽기 실패"
            )
    return detail


__all__ = [
    "RELAY_HEALTH_SPEC",
    "RelayHealth",
    "read_relay_health",
    "relay_health_card_model",
    "relay_health_detail_model",
    "relay_clock_warning_model",
    "relay_blocked_files_warning_model",
    "relay_send_warning_model",
]

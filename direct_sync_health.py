"""Sanitized read-only DirectSync health model for the operator UI."""

from __future__ import annotations

from dataclasses import dataclass
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

    @property
    def operator_attention(self) -> bool:
        return self.state in {"review", "blocked"}


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
    elif failed_permanent or operator_review:
        state = "review"
        error_code = (
            "direct_sync_operator_review"
            if operator_review
            else "direct_sync_failed_permanent"
        )
    elif pending_count:
        state = "pending"

    return RelayHealth(
        state=state,
        pending_count=pending_count,
        failed_permanent_count=failed_permanent,
        operator_review_count=operator_review,
        last_acked_at=str(queue_status.get("last_acked_at") or ""),
        oldest_pending_at=str(queue_status.get("oldest_active_created_at") or ""),
        observed_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        error_code=error_code,
    )


def _compact_timestamp(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "없음"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return "확인 필요"
    return parsed.astimezone().strftime("%m-%d %H:%M")


def relay_health_card_model(health: RelayHealth) -> dict[str, str]:
    tone = "amber" if health.operator_attention else "neutral"
    detail = (
        f"저장 상태 확인 필요 · "
        f"{health.failed_permanent_count + health.operator_review_count}건"
        if health.operator_attention
        else "정상 대기" if health.pending_count else "전송 정상"
    )
    return {
        "summary": (
            f"대기 {health.pending_count} · 최근 성공 "
            f"{_compact_timestamp(health.last_acked_at)}"
        ),
        "detail": detail,
        "tone": tone,
    }


def relay_health_detail_model(health: RelayHealth) -> dict[str, str]:
    return {
        "대기": str(health.pending_count),
        "영구 실패": str(health.failed_permanent_count),
        "담당자 확인": str(health.operator_review_count),
        "가장 오래된 대기": _compact_timestamp(health.oldest_pending_at),
        "마지막 ACK": _compact_timestamp(health.last_acked_at),
        "상태": health.state,
    }


__all__ = [
    "RELAY_HEALTH_SPEC",
    "RelayHealth",
    "read_relay_health",
    "relay_health_card_model",
    "relay_health_detail_model",
]

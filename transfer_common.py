"""Shared transfer values, errors and owner guards; no transport or storage imports."""

from __future__ import annotations

import hashlib
import json
import threading
import unicodedata
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping


SCHEMA_VERSION = "container-audit-transfer-seal-v1"


LOCAL_COMPLETION_SCHEMA_VERSION = "container-audit-transfer-completion-v1"


REPLACEMENT_WAITING_SCHEMA_VERSION = (
    "container-audit-phs-replacement-waiting-v1"
)


REPLACEMENT_WAITING_EVENT = "PHS_REPLACEMENT_WAITING_MARKED"


POST_REVIEW_SCHEMA_VERSION = "container-audit-post-review-required-v1"


POST_REVIEW_REQUIRED_EVENT = "POST_REVIEW_REQUIRED"


CONTRACT_VERSION = "logistics-v1"


COMMAND_TYPE = "SEAL_TRANSFER_BUNDLE"


PENDING_STATUSES = ("PREPARED", "COMMAND_READY", "RETRY_WAIT")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _normalize_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized or "\x00" in normalized:
        raise ValueError(f"{field} must be non-empty safe text")
    return normalized


def normalize_barcode(value: Any) -> str:
    return _normalize_identifier(value, "barcode").upper()


def membership_hash(member_ids: Iterable[str]) -> str:
    members = sorted(_normalize_identifier(value, "member_id") for value in member_ids)
    if not members or len(set(members)) != len(members):
        raise ValueError("membership must be non-empty and unique")
    return _sha256(members)


def _deterministic_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_sha256(value)[:24].upper()}"


class TransferSealError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 0,
        retryable: bool = False,
        committed: bool | None = False,
        details: Mapping[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = str(code or "transfer_seal_error")
        self.status_code = int(status_code or 0)
        self.retryable = bool(retryable)
        self.committed = committed
        self.details = dict(details or {})


class TransferCoordinatorOwnerError(TransferSealError):
    """Fail closed when a mutable transfer coordinator has no declared owner."""

    def __init__(self) -> None:
        super().__init__(
            "TRANSFER_COORDINATOR_OWNER_VIOLATION",
            "transfer coordinator mutation requires its declared owner thread",
            retryable=False,
        )


class TransferCoordinatorOwnerBindingError(TransferSealError):
    """Reject attempts to replace an already-declared coordinator owner."""

    def __init__(self) -> None:
        super().__init__(
            "TRANSFER_COORDINATOR_OWNER_REBIND",
            "transfer coordinator owner provider is already bound",
            retryable=False,
        )


class TransferCoordinatorUiThreadReadError(TransferSealError):
    """Reject transfer-store reads from the registered Tk owner thread."""

    def __init__(self) -> None:
        super().__init__(
            "TRANSFER_COORDINATOR_UI_THREAD_READ",
            "transfer coordinator reads require a non-UI owner context",
            retryable=False,
        )


class TransferCoordinatorUiThreadBindingError(TransferSealError):
    """Reject attempts to replace an already-declared Tk owner provider."""

    def __init__(self) -> None:
        super().__init__(
            "TRANSFER_COORDINATOR_UI_THREAD_REBIND",
            "transfer coordinator UI thread provider is already bound",
            retryable=False,
        )


def _assert_transfer_coordinator_owner(
    owner_thread_id_provider: Callable[[], int | None] | None,
) -> None:
    try:
        owner_thread_id = (
            owner_thread_id_provider()
            if callable(owner_thread_id_provider)
            else None
        )
    except Exception as exc:
        raise TransferCoordinatorOwnerError() from exc
    if owner_thread_id is None or threading.get_ident() != owner_thread_id:
        raise TransferCoordinatorOwnerError()


def _assert_not_transfer_coordinator_ui_thread(
    ui_thread_id_provider: Callable[[], int | None] | None,
) -> None:
    """Fail closed when a registered UI-context probe identifies this thread."""

    if not callable(ui_thread_id_provider):
        return
    try:
        ui_thread_id = ui_thread_id_provider()
    except Exception as exc:
        raise TransferCoordinatorUiThreadReadError() from exc
    if ui_thread_id is not None and threading.get_ident() == ui_thread_id:
        raise TransferCoordinatorUiThreadReadError()

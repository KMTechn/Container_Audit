from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any, Mapping

from storage_utils import atomic_write_json


JOURNAL_SCHEMA_VERSION = "kmtech-recovery-2pc-client-journal-v1"
PROTOCOL_VERSION = "producer-admin-recovery-2pc-v1"
TERMINAL_REASON_SIGNED_STATUS_EXPIRED = (
    "SIGNED_STATUS_CONFIRMED_PREPARE_EXPIRED"
)

STATE_PREPARE_INTENT_DURABLE = "PREPARE_INTENT_DURABLE"
STATE_PREPARED = "PREPARED"
STATE_LOCAL_PACKAGE_DURABLE = "LOCAL_PACKAGE_DURABLE"
STATE_COMMIT_INTENT_DURABLE = "COMMIT_INTENT_DURABLE"
STATE_SERVER_COMMITTED = "SERVER_COMMITTED"
STATE_LOCAL_PERSISTED = "LOCAL_PERSISTED"
STATE_CLEANUP_INTENT_DURABLE = "CLEANUP_INTENT_DURABLE"
STATE_COMPLETE = "COMPLETE"
STATE_ABORTED = "ABORTED"
STATE_EXPIRED = "EXPIRED"

TERMINAL_STATES = frozenset({STATE_COMPLETE, STATE_ABORTED, STATE_EXPIRED})

_ALLOWED_TRANSITIONS = {
    STATE_PREPARE_INTENT_DURABLE: frozenset({STATE_PREPARED, STATE_ABORTED}),
    STATE_PREPARED: frozenset(
        {STATE_LOCAL_PACKAGE_DURABLE, STATE_ABORTED, STATE_EXPIRED}
    ),
    STATE_LOCAL_PACKAGE_DURABLE: frozenset(
        {STATE_COMMIT_INTENT_DURABLE, STATE_ABORTED, STATE_EXPIRED}
    ),
    STATE_COMMIT_INTENT_DURABLE: frozenset(
        {STATE_SERVER_COMMITTED, STATE_ABORTED, STATE_EXPIRED}
    ),
    STATE_SERVER_COMMITTED: frozenset({STATE_LOCAL_PERSISTED}),
    STATE_LOCAL_PERSISTED: frozenset({STATE_CLEANUP_INTENT_DURABLE}),
    STATE_CLEANUP_INTENT_DURABLE: frozenset({STATE_COMPLETE}),
    STATE_COMPLETE: frozenset(),
    STATE_ABORTED: frozenset(),
    STATE_EXPIRED: frozenset(),
}

_REQUIRED_BINDING_FIELDS = frozenset(
    {
        "authorization_id",
        "authorization_audit_event_id",
        "client_request_id",
        "commit_id",
        "producer_id",
        "producer_install_id",
        "source_host_id",
        "manifest_hash",
        "possession_key_fingerprint",
    }
)

_FORBIDDEN_JOURNAL_KEYS = frozenset(
    {
        "secret",
        "secret_hex",
        "recovery_token",
        "nonce",
        "bearer_token",
        "token",
        "private_jwk",
        "private_key",
    }
)


class RecoveryTwoPhaseStateError(RuntimeError):
    pass


def _utc_now() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _path_text(path: str | os.PathLike[str]) -> str:
    return str(Path(path).expanduser().resolve(strict=False))


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).strip().lower() in _FORBIDDEN_JOURNAL_KEYS:
                return True
            if _contains_forbidden_key(child):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_forbidden_key(child) for child in value)
    return False


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


class RecoveryTwoPhaseJournal:
    """Secret-free durable state for one possession-bound recovery attempt."""

    def __init__(
        self,
        journal_path: str | os.PathLike[str],
        *,
        sealed_package_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.path = Path(journal_path).expanduser().resolve(strict=False)
        self.sealed_package_path = (
            Path(sealed_package_path).expanduser().resolve(strict=False)
            if sealed_package_path is not None
            else self.path.with_name(f"{self.path.stem}.prepared-package.dpapi")
        )

    def load(self) -> dict[str, Any] | None:
        if not self.path.is_file():
            return None
        size = self.path.stat().st_size
        if size <= 0 or size > 262_144:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal size is invalid"
            )
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal is unreadable"
            ) from exc
        if not isinstance(payload, dict) or _contains_forbidden_key(payload):
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal contains invalid or secret fields"
            )
        if (
            payload.get("schema_version") != JOURNAL_SCHEMA_VERSION
            or payload.get("protocol_version") != PROTOCOL_VERSION
            or payload.get("state") not in _ALLOWED_TRANSITIONS
            or not isinstance(payload.get("bindings"), dict)
            or set(payload["bindings"]) != _REQUIRED_BINDING_FIELDS
            or not isinstance(payload.get("transitions"), list)
            or not payload["transitions"]
        ):
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal contract is invalid"
            )
        if payload.get("sealed_package_path") != _path_text(
            self.sealed_package_path
        ):
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase sealed package path changed"
            )
        return payload

    def initialize(self, bindings: Mapping[str, str]) -> dict[str, Any]:
        normalized = {str(key): str(value or "").strip() for key, value in bindings.items()}
        if set(normalized) != _REQUIRED_BINDING_FIELDS or not all(
            normalized.values()
        ):
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal bindings are invalid"
            )
        existing = self.load()
        if existing is not None:
            if existing["bindings"] != normalized:
                if (
                    existing["state"] in TERMINAL_STATES
                    and not self.sealed_package_path.exists()
                ):
                    archive_prefix = (
                        "completed"
                        if existing["state"] == STATE_COMPLETE
                        else "terminal"
                    )
                    archive = self.path.with_name(
                        f"{archive_prefix}-"
                        f"{existing['bindings']['client_request_id']}.json"
                    )
                    if archive.exists():
                        raise RecoveryTwoPhaseStateError(
                            "terminal recovery journal archive already exists"
                        )
                    os.replace(self.path, archive)
                    existing = None
                else:
                    raise RecoveryTwoPhaseStateError(
                        "recovery two-phase journal binding mismatch"
                    )
        if existing is not None:
            return existing
        now = _utc_now()
        payload: dict[str, Any] = {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "state": STATE_PREPARE_INTENT_DURABLE,
            "bindings": normalized,
            "prepare_id": "",
            "prepare_expires_at": "",
            "proposed_credential_epoch": None,
            "prepared_key_id": "",
            "prepared_secret_fingerprint_sha256": "",
            "sealed_package_path": _path_text(self.sealed_package_path),
            "sealed_package_sha256": "",
            "server_committed_at": "",
            "committed_credential_epoch": None,
            "terminal_reason_code": "",
            "terminal_server_state": "",
            "terminal_observed_at": "",
            "created_at": now,
            "updated_at": now,
            "transitions": [
                {
                    "sequence": 1,
                    "from": "NONE",
                    "to": STATE_PREPARE_INTENT_DURABLE,
                    "at": now,
                }
            ],
        }
        self._write(payload)
        return payload

    def assert_bindings(self, expected: Mapping[str, str]) -> dict[str, Any]:
        payload = self.load()
        if payload is None:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal is absent"
            )
        normalized = {str(key): str(value or "").strip() for key, value in expected.items()}
        if payload["bindings"] != normalized:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal binding mismatch"
            )
        return payload

    def transition(
        self,
        expected_states: set[str] | frozenset[str],
        next_state: str,
        **updates: Any,
    ) -> dict[str, Any]:
        payload = self.load()
        if payload is None:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal is absent"
            )
        current = str(payload["state"])
        if current == next_state:
            for key, value in updates.items():
                if payload.get(key) != value:
                    raise RecoveryTwoPhaseStateError(
                        "recovery two-phase idempotent transition mismatch"
                    )
            return payload
        if current not in expected_states or next_state not in _ALLOWED_TRANSITIONS[current]:
            raise RecoveryTwoPhaseStateError(
                f"forbidden recovery two-phase transition: {current}->{next_state}"
            )
        if _contains_forbidden_key(updates):
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase transition contains secret fields"
            )
        now = _utc_now()
        payload.update(updates)
        payload["state"] = next_state
        payload["updated_at"] = now
        payload["transitions"] = list(payload["transitions"]) + [
            {
                "sequence": len(payload["transitions"]) + 1,
                "from": current,
                "to": next_state,
                "at": now,
            }
        ]
        self._write(payload)
        return payload

    def record_prepared(
        self,
        *,
        prepare_id: str,
        prepare_expires_at: str,
        proposed_credential_epoch: int,
        prepared_key_id: str,
        prepared_secret_fingerprint_sha256: str,
    ) -> dict[str, Any]:
        return self.transition(
            {STATE_PREPARE_INTENT_DURABLE},
            STATE_PREPARED,
            prepare_id=str(prepare_id),
            prepare_expires_at=str(prepare_expires_at),
            proposed_credential_epoch=int(proposed_credential_epoch),
            prepared_key_id=str(prepared_key_id),
            prepared_secret_fingerprint_sha256=str(
                prepared_secret_fingerprint_sha256
            ),
        )

    def stage_sealed_package(self, sealed_payload: bytes) -> dict[str, Any]:
        if not isinstance(sealed_payload, bytes) or not sealed_payload:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase sealed package is invalid"
            )
        _atomic_write_bytes(self.sealed_package_path, sealed_payload)
        readback = self.sealed_package_path.read_bytes()
        if readback != sealed_payload:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase sealed package readback mismatch"
            )
        return self.transition(
            {STATE_PREPARED},
            STATE_LOCAL_PACKAGE_DURABLE,
            sealed_package_sha256=_sha256_bytes(readback),
        )

    def read_sealed_package(self) -> bytes:
        payload = self.load()
        if payload is None or payload["state"] in {
            STATE_PREPARE_INTENT_DURABLE,
            STATE_PREPARED,
            STATE_ABORTED,
            STATE_EXPIRED,
        }:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase package is not durable"
            )
        try:
            sealed = self.sealed_package_path.read_bytes()
        except OSError as exc:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase sealed package is unavailable"
            ) from exc
        if not sealed or _sha256_bytes(sealed) != payload["sealed_package_sha256"]:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase sealed package hash mismatch"
            )
        return sealed

    def mark_commit_intent(self) -> dict[str, Any]:
        return self.transition(
            {STATE_LOCAL_PACKAGE_DURABLE},
            STATE_COMMIT_INTENT_DURABLE,
        )

    def mark_server_committed(
        self,
        *,
        committed_at: str,
        credential_epoch: int,
    ) -> dict[str, Any]:
        return self.transition(
            {STATE_COMMIT_INTENT_DURABLE},
            STATE_SERVER_COMMITTED,
            server_committed_at=str(committed_at),
            committed_credential_epoch=int(credential_epoch),
        )

    def mark_local_persisted(self) -> dict[str, Any]:
        return self.transition(
            {STATE_SERVER_COMMITTED},
            STATE_LOCAL_PERSISTED,
        )

    def mark_cleanup_intent(self) -> dict[str, Any]:
        return self.transition(
            {STATE_LOCAL_PERSISTED},
            STATE_CLEANUP_INTENT_DURABLE,
        )

    def mark_complete(self) -> dict[str, Any]:
        return self.transition(
            {STATE_CLEANUP_INTENT_DURABLE},
            STATE_COMPLETE,
        )

    def mark_aborted(self) -> dict[str, Any]:
        payload = self.load()
        if payload is None:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal is absent"
            )
        state = str(payload["state"])
        if state not in {
            STATE_PREPARE_INTENT_DURABLE,
            STATE_PREPARED,
            STATE_LOCAL_PACKAGE_DURABLE,
            STATE_COMMIT_INTENT_DURABLE,
        }:
            raise RecoveryTwoPhaseStateError(
                "committed recovery cannot transition to ABORTED"
            )
        return self.transition({state}, STATE_ABORTED)

    def mark_expired(self) -> dict[str, Any]:
        payload = self.load()
        if payload is None:
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal is absent"
            )
        state = str(payload["state"])
        if state == STATE_EXPIRED:
            return payload
        if state not in {
            STATE_PREPARED,
            STATE_LOCAL_PACKAGE_DURABLE,
            STATE_COMMIT_INTENT_DURABLE,
        }:
            raise RecoveryTwoPhaseStateError(
                "only an uncommitted prepared recovery can expire"
            )
        return self.transition(
            {state},
            STATE_EXPIRED,
            terminal_reason_code=TERMINAL_REASON_SIGNED_STATUS_EXPIRED,
            terminal_server_state=STATE_EXPIRED,
            terminal_observed_at=_utc_now(),
        )

    def remove_sealed_package_after_expiry(self) -> None:
        payload = self.load()
        if payload is None or payload["state"] != STATE_EXPIRED:
            raise RecoveryTwoPhaseStateError(
                "expired sealed package cleanup requires EXPIRED journal"
            )
        self.sealed_package_path.unlink(missing_ok=True)
        if self.sealed_package_path.exists():
            raise RecoveryTwoPhaseStateError(
                "expired sealed package cleanup failed"
            )

    def remove_sealed_package_after_terminal(self) -> None:
        payload = self.load()
        if payload is None or payload["state"] not in TERMINAL_STATES:
            raise RecoveryTwoPhaseStateError(
                "sealed package cleanup requires a terminal journal"
            )
        self.sealed_package_path.unlink(missing_ok=True)
        if self.sealed_package_path.exists():
            raise RecoveryTwoPhaseStateError(
                "terminal sealed package cleanup failed"
            )

    def remove_sealed_package_after_complete(self) -> None:
        payload = self.load()
        if payload is None or payload["state"] != STATE_COMPLETE:
            raise RecoveryTwoPhaseStateError(
                "sealed package cleanup requires COMPLETE journal"
            )
        self.sealed_package_path.unlink(missing_ok=True)
        if self.sealed_package_path.exists():
            raise RecoveryTwoPhaseStateError(
                "sealed package cleanup failed"
            )

    def _write(self, payload: Mapping[str, Any]) -> None:
        if _contains_forbidden_key(payload):
            raise RecoveryTwoPhaseStateError(
                "recovery two-phase journal contains secret fields"
            )
        atomic_write_json(
            str(self.path),
            dict(payload),
            indent=2,
            ensure_ascii=False,
            trailing_newline=True,
        )

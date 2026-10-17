"""Fail-closed admission for every Container_Audit runtime writer.

The deployment coordinator owns the session-authority mutex.  This module
owns the stable, per-user admission mutex and the durable active-fence
contract consumed by Python writer processes.  Normal writer admission is
read-only: it never creates the control directory or writes denial evidence.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
import ctypes
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import sys
import threading
import time
from typing import Any, Callable, Iterator, Mapping, ParamSpec, TypeVar
import unicodedata
import weakref


APP_ID = "container_audit"
ACTIVE_SCHEMA = "container-audit-all-writer-fence-active-v1"
RELEASE_SCHEMA = "container-audit-all-writer-fence-release-v1"
SESSION_TUPLE_VERSION = "container-audit-deployment-session-authority-v1"
SESSION_MUTEX_PREFIX = r"Local\KMTech.ContainerAudit.DeploymentSession."
WRITER_MUTEX_NAME = r"Local\KMTech.ContainerAudit.WriterAdmission.v1"
CONTROL_RELATIVE_PATH = Path("KMTech") / "DirectSync" / "container_audit" / "control" / "writer-session"
ACTIVE_FILENAME = "active.json"
MAX_CONTROL_BYTES = 256 * 1024
MAX_SESSION_AGE = timedelta(hours=24)
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_ISO_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$"
)
_WRITER_LOCAL = threading.local()
_WRITER_EXIT_CONDITION = threading.Condition()
_WRITER_EXIT_CLOSED = False
_WRITER_EXIT_COUNT = 0
_LANE_WORKERS = weakref.WeakSet()
EXIT_WRITE_WAIT_S = 120
EXIT_POLL_S = 5


def start_lane_worker(worker: threading.Thread) -> None:
    """Track every lane worker, including one whose lane later becomes BROKEN."""
    with _WRITER_EXIT_CONDITION:
        if _WRITER_EXIT_CLOSED:
            raise WriterFencedError("WRITER_EXIT_CLOSED", "lane worker admission is closed for exit")
        _LANE_WORKERS.add(worker)
        worker.start()


def close_and_wait_writers(timeout_seconds: float) -> bool:
    """Close admissions; wait for writes and every lane worker's actual exit."""
    global _WRITER_EXIT_CLOSED
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    with _WRITER_EXIT_CONDITION:
        _WRITER_EXIT_CLOSED = True
    # A receipt-bound delegation/maintenance session has no normal admission
    # token to drain. Reuse the existing capability validation, not env presence.
    delegated = False
    try:
        active = active_fence(canonical_control_root())
        delegated = active is not None and any(
            _delegation_matches(active, source=source, environ=os.environ)
            for source in active["delegated_sources"]
        )
    except WriterFenceError:
        pass  # Unproven delegation retains the normal exit criterion.
    with _WRITER_EXIT_CONDITION:
        while (not delegated and _WRITER_EXIT_COUNT) or any(worker.is_alive() for worker in tuple(_LANE_WORKERS)):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            _WRITER_EXIT_CONDITION.wait(min(EXIT_POLL_S, remaining))
    if delegated:
        return True
    try:
        lease = _acquire_named_mutex(
            writer_admission_mutex_name(canonical_control_root()),
            max(0.0, deadline - time.monotonic()),
        )
    except WriterFenceError:
        return False
    if lease is None:
        return False
    try:
        return not lease.abandoned
    finally:
        lease.release()

# This pin is generated and checked by tools/derive_container_writer_sinks.py.
# It is updated together with the inventory after all sink markers are placed.
WRITER_INVENTORY_SHA256 = "96350fd36df916853f11aa479880ea058f32ab83d15b06e30e6a970b8e03d157"

DELEGATION_TOKEN_ENV = "CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN"
DELEGATION_SESSION_ENV = "CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID"
DELEGATION_ATTEMPT_ENV = "CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID"
DELEGATION_TRANSACTION_ENV = "CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID"

ACTIVE_FIELDS = frozenset(
    {
        "schema",
        "status",
        "app_id",
        "session_id",
        "attempt_id",
        "replacement_transaction_id",
        "session_started_at_utc",
        "orchestrator_sha256",
        "writer_contract_sha256",
        "session_authority_mutex_name",
        "writer_inventory_sha256",
        "owner_kind",
        "prepared_receipt_path",
        "prepared_receipt_sha256",
        "delegation_sha256",
        "delegated_sources",
        "delegation_expires_at_utc",
        "activated_at_utc",
        "secret_values_recorded",
    }
)


class WriterFenceError(RuntimeError):
    """The writer fence could not be observed or changed exactly."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = str(code or "WRITER_FENCE_FAILED")


class WriterFencedError(WriterFenceError):
    """A writer was denied without mutating application or fence state."""


def _canonical_tuple(*values: str) -> str:
    return "\n".join(unicodedata.normalize("NFC", str(value)) for value in values)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ascii_lower(value: str) -> str:
    return "".join(chr(ord(character) + 32) if "A" <= character <= "Z" else character for character in value)


def _sha256_file_bounded(path: Path, maximum_bytes: int = 4 * 1024 * 1024) -> str:
    _assert_no_reparse_components(path)
    try:
        stat = path.stat()
    except OSError as exc:
        raise WriterFenceError(
            "FENCE_PREPARED_RECEIPT_UNOBSERVABLE",
            "writer fence prepared receipt cannot be observed",
        ) from exc
    if not path.is_file() or stat.st_size <= 0 or stat.st_size > maximum_bytes:
        raise WriterFenceError(
            "FENCE_PREPARED_RECEIPT_INVALID",
            "writer fence prepared receipt size or kind differs",
        )
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise WriterFenceError(
            "FENCE_PREPARED_RECEIPT_UNOBSERVABLE",
            "writer fence prepared receipt cannot be read",
        ) from exc
    return digest.hexdigest()


def session_authority_mutex_name(
    session_id: str,
    attempt_id: str,
    orchestrator_sha256: str,
    replacement_transaction_id: str,
    writer_contract_sha256: str,
) -> str:
    """Derive the exact mutex name published by the writer-session contract."""

    canonical = _canonical_tuple(
        SESSION_TUPLE_VERSION,
        session_id,
        attempt_id,
        orchestrator_sha256,
        replacement_transaction_id,
        writer_contract_sha256,
    )
    return SESSION_MUTEX_PREFIX + _sha256_text(canonical)


def _normalized_control_root(value: str | os.PathLike[str]) -> str:
    selected = os.path.abspath(os.fspath(Path(value).expanduser()))
    selected = selected.replace("/", "\\").rstrip("\\")
    return _ascii_lower(unicodedata.normalize("NFC", selected))


def canonical_control_root(environ: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environ is None else environ
    local_app_data = str(values.get("LOCALAPPDATA") or "").strip()
    if not local_app_data:
        raise WriterFenceError(
            "LOCALAPPDATA_UNAVAILABLE",
            "writer fence control root cannot be observed",
        )
    return Path(os.path.abspath(os.fspath(Path(local_app_data).expanduser()))) / CONTROL_RELATIVE_PATH


def writer_admission_mutex_name(
    control_root: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Use the stable production name and isolate explicit test roots."""

    selected = _normalized_control_root(control_root)
    try:
        production = _normalized_control_root(canonical_control_root(environ))
    except WriterFenceError:
        production = ""
    if production and selected == production:
        return WRITER_MUTEX_NAME
    return f"{WRITER_MUTEX_NAME}.{_sha256_text(selected)[:16]}"


def _assert_no_reparse_components(path: Path) -> None:
    selected = Path(os.path.abspath(os.fspath(path.expanduser())))
    current = Path(selected.anchor)
    for part in selected.parts[1:]:
        current /= part
        try:
            stat = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise WriterFenceError(
                "FENCE_PATH_UNOBSERVABLE",
                "writer fence path cannot be observed",
            ) from exc
        attributes = int(getattr(stat, "st_file_attributes", 0))
        if current.is_symlink() or bool(attributes & 0x400):
            raise WriterFenceError(
                "FENCE_REPARSE_REJECTED",
                "writer fence path contains a reparse point",
            )


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not _ISO_UTC.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _bounded_json(path: Path) -> dict[str, Any]:
    try:
        before = path.stat()
        if before.st_size <= 0 or before.st_size > MAX_CONTROL_BYTES:
            raise WriterFenceError(
                "FENCE_SIZE_INVALID",
                "writer fence size is invalid",
            )
        raw = path.read_bytes()
        after = path.stat()
    except WriterFenceError:
        raise
    except OSError as exc:
        raise WriterFenceError(
            "FENCE_STATE_UNREADABLE",
            "writer fence state is unreadable",
        ) from exc
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(raw) != before.st_size
    ):
        raise WriterFenceError(
            "FENCE_STATE_CHANGED",
            "writer fence changed while it was read",
        )
    try:
        value = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WriterFenceError(
            "FENCE_JSON_INVALID",
            "writer fence JSON is invalid",
        ) from exc
    if not isinstance(value, dict):
        raise WriterFenceError(
            "FENCE_SHAPE_INVALID",
            "writer fence must be one JSON object",
        )
    return value


def _validate_active_fence(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(payload)
    if set(value) != ACTIVE_FIELDS:
        raise WriterFenceError("FENCE_SHAPE_INVALID", "writer fence fields differ")
    status = value.get("status")
    owner_kind = value.get("owner_kind")
    delegated_sources = value.get("delegated_sources")
    if (
        value.get("schema") != ACTIVE_SCHEMA
        or value.get("app_id") != APP_ID
        or status
        not in {"PREPARING", "PREPARED", "RESTORING", "RESTORE_FAILED", "INSTALLING"}
        or owner_kind not in {"session_adapter", "canonical_installer"}
        or not _HEX_32.fullmatch(str(value.get("session_id") or ""))
        or not _HEX_32.fullmatch(str(value.get("attempt_id") or ""))
        or not _HEX_32.fullmatch(str(value.get("replacement_transaction_id") or ""))
        or not _HEX_64.fullmatch(str(value.get("orchestrator_sha256") or ""))
        or not _HEX_64.fullmatch(str(value.get("writer_contract_sha256") or ""))
        or value.get("writer_inventory_sha256") != WRITER_INVENTORY_SHA256
        or _parse_utc(value.get("session_started_at_utc")) is None
        or _parse_utc(value.get("activated_at_utc")) is None
        or value.get("secret_values_recorded") is not False
        or not isinstance(value.get("prepared_receipt_path"), str)
        or not isinstance(value.get("prepared_receipt_sha256"), str)
        or not isinstance(delegated_sources, list)
        or any(not isinstance(item, str) or not item for item in delegated_sources)
        or delegated_sources != sorted(set(delegated_sources))
    ):
        raise WriterFenceError("FENCE_BINDING_INVALID", "writer fence binding differs")
    expected_mutex = session_authority_mutex_name(
        value["session_id"],
        value["attempt_id"],
        value["orchestrator_sha256"],
        value["replacement_transaction_id"],
        value["writer_contract_sha256"],
    )
    if value.get("session_authority_mutex_name") != expected_mutex:
        raise WriterFenceError(
            "FENCE_AUTHORITY_NAME_INVALID",
            "writer fence authority mutex name differs",
        )
    prepared_sha = value["prepared_receipt_sha256"]
    receipt_bound_statuses = {
        "PREPARING",
        "PREPARED",
        "RESTORING",
        "RESTORE_FAILED",
        "INSTALLING",
    }
    delegation_statuses = {"PREPARED", "RESTORING", "RESTORE_FAILED", "INSTALLING"}
    if delegated_sources and status not in delegation_statuses:
        raise WriterFenceError(
            "FENCE_DELEGATION_INVALID",
            "writer fence delegation requires a receipt-bound phase",
        )
    if status in receipt_bound_statuses or delegated_sources:
        if not value["prepared_receipt_path"] or not _HEX_64.fullmatch(prepared_sha):
            raise WriterFenceError(
                "FENCE_PREPARED_BINDING_INVALID",
                "writer fence prepared receipt binding differs",
            )
        prepared_path = Path(value["prepared_receipt_path"])
        if not prepared_path.is_absolute() or _sha256_file_bounded(prepared_path) != prepared_sha:
            raise WriterFenceError(
                "FENCE_PREPARED_RECEIPT_MISMATCH",
                "writer fence prepared receipt bytes differ",
            )
    elif prepared_sha and not _HEX_64.fullmatch(prepared_sha):
        raise WriterFenceError(
            "FENCE_PREPARED_BINDING_INVALID",
            "writer fence prepared receipt pin is malformed",
        )
    delegation_sha = value.get("delegation_sha256")
    delegation_expiry = value.get("delegation_expires_at_utc")
    if delegated_sources:
        if (
            not _HEX_64.fullmatch(str(delegation_sha or ""))
            or _parse_utc(delegation_expiry) is None
        ):
            raise WriterFenceError(
                "FENCE_DELEGATION_INVALID",
                "writer fence delegation binding differs",
            )
    elif delegation_sha != "" or delegation_expiry != "":
        raise WriterFenceError(
            "FENCE_DELEGATION_INVALID",
            "writer fence empty delegation binding differs",
        )
    return value


def active_fence(
    control_root: str | os.PathLike[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any] | None:
    root = (
        Path(os.path.abspath(os.fspath(Path(control_root).expanduser())))
        if control_root is not None
        else canonical_control_root(environ)
    )
    _assert_no_reparse_components(root)
    path = root / ACTIVE_FILENAME
    _assert_no_reparse_components(path)
    try:
        present = path.exists()
    except OSError as exc:
        raise WriterFenceError(
            "FENCE_STATE_UNOBSERVABLE",
            "writer fence presence cannot be observed",
        ) from exc
    if not present:
        return None
    return _validate_active_fence(_bounded_json(path))


def _emit_machine_recovery_guidance(active: Mapping[str, Any], root) -> None:
    if root is not None and Path(root).parent.parent.name.casefold() == "machine-install" and active["owner_kind"] == "canonical_installer":
        audit = rf"install-audit\canonical-portable-{active['replacement_transaction_id']}.json"
        print("CONTAINER_AUDIT_MACHINE_RECOVERY=" + json.dumps({"guidance": f"Recovery: -RecoverMachineInstallation; audit: {audit}"}, separators=(",", ":")), file=sys.stderr)


class _NamedMutexLease:
    def __init__(self, handle: int, *, abandoned: bool = False) -> None:
        self.handle = handle
        self.abandoned = abandoned

    def release(self) -> None:
        handle, self.handle = self.handle, 0
        if not handle:
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        try:
            kernel32.ReleaseMutex(ctypes.c_void_p(handle))
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle))


def _acquire_named_mutex(name: str, timeout_seconds: float) -> _NamedMutexLease | None:
    if os.name != "nt":
        return _NamedMutexLease(0)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexExW.argtypes = [
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
    ]
    kernel32.CreateMutexExW.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    # SYNCHRONIZE permits waiting; ReleaseMutex checks thread ownership. Keep
    # default security while avoiding full-access denial when the same user's
    # elevated relay created the admission mutex.
    handle = kernel32.CreateMutexExW(None, name, 0, 0x00100000)
    if not handle:
        raise WriterFenceError(
            "WRITER_MUTEX_CREATE_FAILED",
            "writer admission mutex could not be opened",
        )
    milliseconds = max(0, min(0xFFFFFFFE, int(float(timeout_seconds) * 1000)))
    result = int(kernel32.WaitForSingleObject(handle, milliseconds))
    if result == 0:
        return _NamedMutexLease(int(handle))
    if result == 0x80:
        return _NamedMutexLease(int(handle), abandoned=True)
    kernel32.CloseHandle(handle)
    if result == 0x102:
        return None
    raise WriterFenceError(
        "WRITER_MUTEX_WAIT_FAILED",
        "writer admission mutex wait failed",
    )


def _named_mutex_held_by_other(name: str) -> bool:
    if os.name != "nt":
        return True
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenMutexW.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_wchar_p]
    kernel32.OpenMutexW.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    handle = kernel32.OpenMutexW(0x00100001, False, name)
    if not handle:
        return False
    try:
        result = int(kernel32.WaitForSingleObject(handle, 0))
        if result == 0x102:
            return True
        if result in {0, 0x80}:
            try:
                kernel32.ReleaseMutex(handle)
            except Exception:
                pass
            return False
        return False
    finally:
        kernel32.CloseHandle(handle)


def _delegation_matches(
    active: Mapping[str, Any],
    *,
    source: str,
    environ: Mapping[str, str],
) -> bool:
    if (
        active.get("status")
        not in {"PREPARED", "RESTORING", "RESTORE_FAILED", "INSTALLING"}
        or source not in active["delegated_sources"]
    ):
        return False
    expires = _parse_utc(active["delegation_expires_at_utc"])
    token = str(environ.get(DELEGATION_TOKEN_ENV) or "")
    return bool(
        len(token) >= 32
        and expires is not None
        and datetime.now(timezone.utc) <= expires
        and environ.get(DELEGATION_SESSION_ENV) == active["session_id"]
        and environ.get(DELEGATION_ATTEMPT_ENV) == active["attempt_id"]
        and environ.get(DELEGATION_TRANSACTION_ENV)
        == active["replacement_transaction_id"]
        and _named_mutex_held_by_other(active["session_authority_mutex_name"])
        and secrets.compare_digest(
            _sha256_text(token),
            active["delegation_sha256"],
        )
    )


@contextmanager
def writer_admission(
    source: str,
    *,
    control_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = 5.0,
    environ: Mapping[str, str] | None = None,
) -> Iterator[None]:
    global _WRITER_EXIT_COUNT
    nested = bool(getattr(_WRITER_LOCAL, "depth", 0))
    with _WRITER_EXIT_CONDITION:
        if _WRITER_EXIT_CLOSED and not nested:
            raise WriterFencedError("WRITER_EXIT_CLOSED", "writer admission is closed for exit")
        _WRITER_EXIT_COUNT += 1
    try:
        with _writer_admission(source, control_root=control_root,
                               timeout_seconds=timeout_seconds, environ=environ):
            yield
    finally:
        with _WRITER_EXIT_CONDITION:
            _WRITER_EXIT_COUNT -= 1
            _WRITER_EXIT_CONDITION.notify_all()


@contextmanager
def _writer_admission(
    source: str,
    *,
    control_root: str | os.PathLike[str] | None = None,
    timeout_seconds: float = 5.0,
    environ: Mapping[str, str] | None = None,
) -> Iterator[None]:
    """Admit one writer or fail closed without changing any persistent state."""

    selected_source = str(source or "").strip()
    if not selected_source:
        raise WriterFencedError("WRITER_SOURCE_MISSING", "writer source is required")
    depth = int(getattr(_WRITER_LOCAL, "depth", 0))
    if depth < 0:
        # A negative depth is truthy, so it would route this writer down the
        # nested branch with no admission mutex and no active-fence check.
        # Deny instead, and leave the corrupted count exactly as it is: a
        # silent reset here would hide the accounting defect that produced it.
        raise WriterFenceError(
            "WRITER_ADMISSION_DEPTH_UNDERFLOW",
            "writer admission depth accounting underflowed",
        )
    if depth:
        nested_active = getattr(_WRITER_LOCAL, "active", None)
        nested_environ = getattr(_WRITER_LOCAL, "environ", None)
        if nested_active is not None and not _removal_admits(
            selected_source, getattr(_WRITER_LOCAL, "root", None), nested_active,
        ) and not _delegation_matches(
            nested_active,
            source=selected_source,
            environ=nested_environ if nested_environ is not None else os.environ,
        ):
            _emit_machine_recovery_guidance(nested_active, getattr(_WRITER_LOCAL, "root", None))
            raise WriterFencedError(
                "ACTIVE_WRITER_FENCE",
                "nested writer source denied by the active deployment fence",
            )
        _WRITER_LOCAL.depth = depth + 1
        try:
            yield
        finally:
            _WRITER_LOCAL.depth -= 1
        return
    values = os.environ if environ is None else environ
    try:
        root = (
            Path(os.path.abspath(os.fspath(Path(control_root).expanduser())))
            if control_root is not None
            else canonical_control_root(values)
        )
        lease = _acquire_named_mutex(
            writer_admission_mutex_name(root, environ=values),
            timeout_seconds,
        )
        if lease is None:
            raise WriterFencedError(
                "WRITER_GATE_TIMEOUT",
                "writer admission mutex is held by a deployment operation",
            )
        if lease.abandoned:
            raise WriterFencedError(
                "WRITER_GATE_ABANDONED",
                "writer admission mutex ownership was abandoned",
            )
        try:
            active = active_fence(root, environ=values)
        except WriterFenceError as exc:
            if selected_source == "current_user_setup_removal" and getattr(_WRITER_LOCAL, "removal_scope", None):
                raise WriterFencedError("ACTIVE_WRITER_FENCE", "writer denied by the active deployment fence") from exc
            raise
        if active is not None and not _delegation_matches(
            active,
            source=selected_source,
            environ=values,
        ) and not _removal_admits(selected_source, root, active):
            _emit_machine_recovery_guidance(active, root)
            raise WriterFencedError(
                "ACTIVE_WRITER_FENCE",
                "writer denied by the active deployment fence",
            )
    except WriterFenceError:
        if "lease" in locals() and lease is not None:
            lease.release()
        raise
    _WRITER_LOCAL.depth = 1
    _WRITER_LOCAL.active = active
    _WRITER_LOCAL.root = root
    _WRITER_LOCAL.environ = values
    try:
        yield
    finally:
        _WRITER_LOCAL.depth = 0
        _WRITER_LOCAL.active = None
        _WRITER_LOCAL.root = None
        _WRITER_LOCAL.environ = None
        lease.release()


P = ParamSpec("P")
R = TypeVar("R")

# Remote orchestration probes the fence before dispatch, releases admission
# while waiting, and admits each local mutation again when applying a result.
# These exact functions have no unguarded local writes. Nested admission would
# retain the caller's mutex, so refuse it before a remote request can escape.
NETWORK_PROBE_ONLY_WRITER_SINKS = frozenset(
    {
        ("transfer_api_request", "transfer_client.LogisticsTransferClient._request"),
        *(('transfer_seal', 'transfer_client.LogisticsTransferClient.' + name)
          for name in ('issue_operation_lease', 'adopt_phs_label',
                       'prepare_phs_label_exchange', 'prepare_phs_reconciliation_label_exchange',
                       'request_phs_label_print', 'complete_phs_label_print',
                       'activate_phs_label_exchange', 'seal_transfer', 'replace_bundle_members')),
        *(('admin_pin_network', 'container_admin_pin.AdminPinClient.' + name)
          for name in ('post', 'verify', 'status', 'redeem', 'query_roster',
                       'query_roster_v2', 'register_roster', '_post_signed')),
        ("relay_network_upload", "direct_sync_push.upload_source_file"),
        ("relay_batch_drain", "direct_sync_push.drain_one_relay_batch"),
        ("direct_sync_relay_cycle", "direct_sync_runtime.run_relay_once"),
        ("raw_relay_runner", "tools.direct_sync_relay_runner.main"),
        ("relay_spool_storage", "direct_sync_push.restore_raw_artifact_to_file"),
        ("runtime_lease_network", "producer_runtime_client._post_lease_request"),
        ("producer_runtime_storage", "producer_runtime_client.ensure_runtime_authority"),
        ("producer_runtime_storage", "producer_runtime_client.prepare_runtime_metadata"),
        ("item_catalog_refresh", "item_catalog_sync.refresh_item_catalog"),
        ("gui_startup", "Container_Audit._prepare_gui_startup"),
        ("operator_spool_restore", "direct_sync_operator.restore_relay_spool_from_server"),
        ("worker_enrollment_network", "tools.register_container_audit_worker_pc._post_enrollment_request"),
        ("worker_pc_registration", "tools.register_container_audit_worker_pc.main"),
        ("current_user_onboarding", "current_user_onboarding.onboard_current_user"),
    }
)

# Feed writes/copies/cleanup affect only owned staging temporaries. Fence actors
# do not consume staging, and SYSTEM defers fixed-packet consumption while the
# relay is live. Reject inherited admissions so slow HDD writes/fsync remain
# outside the gate; the ordinary publish sink alone replaces fixed names.
STAGING_PROBE_ONLY_WRITER_SINKS = frozenset(
    ("auto_update_control", "auto_update." + name)
    for name in ("write_download_bytes", "write_download_chunk", "stage_prepared_copies", "_run_download_attempt")
) | frozenset({
    ("gui_tray_state_save", "Container_Audit.ContainerAudit._prepare_tray_state_snapshot"),
    ("relay_upload_status", "direct_sync_push._prepare_status_temp"),
})

# The process wrappers also release before a child can acquire admission.
PROBE_ONLY_WRITER_SINKS = frozenset(
    {
        (
            "session_direct_sync_process",
            "direct_sync_auto_bootstrap.run_session_direct_sync_once",
        ),
        (
            "session_direct_sync_process",
            "direct_sync_auto_bootstrap._run_command",
        ),
        ("persistent_relay_status", "user_relay.main"),
        ("persistent_relay_status", "user_relay.native_app_process_snapshot"),
    }
) | NETWORK_PROBE_ONLY_WRITER_SINKS | STAGING_PROBE_ONLY_WRITER_SINKS


def writer_sink(
    source: str,
    *,
    probe_only: bool = False,
    report_only: bool = False,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Mark and guard a concrete writer sink for code-derived inventory."""

    selected_source = str(source or "").strip()
    if not selected_source:
        raise ValueError("writer sink source is required")

    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        if (
            inspect.iscoroutinefunction(function)
            or inspect.isasyncgenfunction(function)
            or inspect.isgeneratorfunction(function)
        ):
            raise TypeError("writer sinks must execute synchronously inside admission")

        module_name = function.__module__
        if module_name == "__main__":
            definition_path = Path(
                function.__globals__.get("__file__", function.__code__.co_filename)
            ).resolve()
            try:
                app_path = definition_path.relative_to(Path(__file__).resolve().parent)
            except ValueError:
                pass
            else:
                module_name = ".".join(app_path.with_suffix("").parts)
        sink_id = f"{module_name}.{function.__qualname__}"
        if report_only and (
            probe_only or (selected_source, sink_id) not in {
                ("startup_check_report", "startup_check_report._write_result"),
                ("startup_gui_ready", "startup_check_report._write_gui_ready"),
                ("runtime_instance_marker", "runtime_instance._write_entry_marker"),
                ("runtime_instance_marker", "runtime_instance._clear_entry_marker"),
            }
        ):
            raise WriterFencedError(
                "REPORT_ONLY_SINK_NOT_ALLOWED",
                "only fixed non-authoritative startup reports bypass admission",
            )
        if probe_only and (selected_source, sink_id) not in PROBE_ONLY_WRITER_SINKS:
            raise WriterFencedError(
                "WRITER_PROBE_ONLY_SINK_NOT_ALLOWED",
                "probe-only admission is not approved for this writer sink",
            )

        @wraps(function)
        def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
            if report_only:
                if int(getattr(_WRITER_LOCAL, "depth", 0)) > 0:
                    raise WriterFencedError(
                        "STARTUP_REPORT_ADMISSION_HELD", "startup reports run outside admission",
                    )
                return function(*args, **kwargs)
            if probe_only:
                if (selected_source, sink_id) in STAGING_PROBE_ONLY_WRITER_SINKS and int(
                    getattr(_WRITER_LOCAL, "depth", 0)
                ) > 0:
                    raise WriterFencedError(
                        "STAGING_WRITER_ADMISSION_HELD",
                        "feed staging cannot run inside a local writer admission",
                    )
                if (selected_source, sink_id) in NETWORK_PROBE_ONLY_WRITER_SINKS and int(
                    getattr(_WRITER_LOCAL, "depth", 0)
                ) > 0:
                    raise WriterFencedError(
                        "NETWORK_WRITER_ADMISSION_HELD",
                        "remote operation cannot run inside a local writer admission",
                    )
                with writer_admission(selected_source):
                    pass
                return function(*args, **kwargs)
            with writer_admission(selected_source):
                return function(*args, **kwargs)

        setattr(guarded, "__container_writer_sink__", selected_source)
        return guarded

    return decorate


class _FailedInstallerRemoval:
    """A thread-local claim held across every admission of one public removal."""

    def __init__(self, app_root: Path, direct_sync_root: Path) -> None:
        self.app_root = app_root
        self.direct_sync_root = direct_sync_root
        self.claim = None
        self.root = None
        self.active = None
        self.original = b""
        self.ready = False
        self.checking_processes = False

    def release(self) -> None:
        claim, self.claim = self.claim, None
        self.ready = False
        if claim is not None:
            claim.release()

    def admits(self, source: str, root: Path, active: Mapping[str, Any]) -> bool:
        if self.claim is not None:
            if root != self.root or active != self.active:
                return False
            if self.checking_processes:
                # process_snapshot dispatches only the existing read-only
                # Observe mode through the guarded fixed helper.
                return source == "auto_update_control"
            return self.ready and source in {
                "current_user_setup_removal", "current_user_onboarding_storage",
                "user_relay_autostart_remove", "persistent_relay_registry",
                "persistent_relay_status",
            }
        if (os.name != "nt" or source != "current_user_setup_removal" or active["status"] != "INSTALLING"
                or active["owner_kind"] != "canonical_installer"):
            return False
        try:
            claim = _acquire_named_mutex(active["session_authority_mutex_name"], 0)
        except (OSError, WriterFenceError):
            return False
        if claim is None:
            return False
        self.claim, self.root, self.active = claim, root, dict(active)
        try:
            from tools.register_container_audit_worker_pc import _current_user_sid
            from auto_update import control_root, process_snapshot, writer_processes
            from runtime_instance import acquire_runtime_instance

            prepared = _bounded_json(Path(active["prepared_receipt_path"]))
            identity_fields = (
                "app_id", "session_id", "attempt_id", "replacement_transaction_id",
                "session_started_at_utc", "orchestrator_sha256", "writer_contract_sha256",
                "writer_inventory_sha256",
            )
            local = prepared.get("operator_local_appdata_root")
            if (prepared.get("schema") != "container-audit-canonical-writer-prepared-v1"
                    or prepared.get("status") != "PREPARED"
                    or prepared.get("operator_sid") != _current_user_sid()
                    or prepared.get("secret_values_recorded") is not False
                    or any(prepared.get(name) != active[name] for name in identity_fields)
                    or not isinstance(local, str) or not Path(local).is_absolute()
                    or _normalized_control_root(Path(local) / CONTROL_RELATIVE_PATH) != _normalized_control_root(root)):
                self.release()
                return False
            self.original = (root / ACTIVE_FILENAME).read_bytes()
            control = control_root(self.app_root)
            if control is None:
                self.release()
                return False
            self.checking_processes = True
            if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                self.release()
                return False
            self.checking_processes = False
            relay = acquire_runtime_instance(self.direct_sync_root / "user-relay-instance")
            if relay is None:
                self.release()
                return False
            relay.release()
            if (active_fence(root) != active
                    or (root / ACTIVE_FILENAME).read_bytes() != self.original):
                self.release()
                return False
            self.ready = True
            return True
        except (OSError, ValueError, TypeError, KeyError, RuntimeError):
            self.release()
            return False
        finally:
            self.checking_processes = False


def _removal_admits(source: str, root: Path, active: Mapping[str, Any]) -> bool:
    scope = getattr(_WRITER_LOCAL, "removal_scope", None)
    return scope is not None and scope.admits(source, root, active)


@contextmanager
def _current_user_removal_fence_scope(app_root: Path, direct_sync_root: Path):
    if getattr(_WRITER_LOCAL, "removal_scope", None) is not None:
        raise WriterFencedError("ACTIVE_WRITER_FENCE", "another current-user removal owns this thread")
    scope = _FailedInstallerRemoval(app_root, direct_sync_root)
    _WRITER_LOCAL.removal_scope = scope
    try:
        yield
    finally:
        _WRITER_LOCAL.removal_scope = None
        scope.release()


@writer_sink("current_user_setup_removal")
def _settle_failed_installer_removal() -> dict[str, str] | None:
    scope = getattr(_WRITER_LOCAL, "removal_scope", None)
    if scope is None or scope.claim is None:
        return None
    root, active, original = scope.root, scope.active, scope.original
    path = root / ACTIVE_FILENAME
    if not scope.ready or active_fence(root) != active or path.read_bytes() != original:
        raise ValueError("writer fence changed before removal settlement")
    digest = hashlib.sha256(original).hexdigest()
    copy = root / "settled" / (digest + ".json")
    _assert_no_reparse_components(copy)
    copy.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_reparse_components(copy)
    if not copy.exists():
        with copy.open("xb") as handle:
            handle.write(original)
            handle.flush()
            os.fsync(handle.fileno())
    _assert_no_reparse_components(copy)
    if copy.read_bytes() != original or path.read_bytes() != original or active_fence(root) != active:
        raise ValueError("writer fence copy readback differs")
    path.unlink()
    if path.exists():
        raise ValueError("writer fence absence was not proven")
    return {
        "session_id_sha256": _sha256_text(active["session_id"]),
        "attempt_id_sha256": _sha256_text(active["attempt_id"]),
        "fence_copy_sha256": digest,
        "fence_copy_path": "writer-session/settled/" + digest + ".json",
    }


__all__ = [
    "ACTIVE_FILENAME",
    "ACTIVE_SCHEMA",
    "CONTROL_RELATIVE_PATH",
    "DELEGATION_ATTEMPT_ENV",
    "DELEGATION_SESSION_ENV",
    "DELEGATION_TOKEN_ENV",
    "DELEGATION_TRANSACTION_ENV",
    "PROBE_ONLY_WRITER_SINKS",
    "SESSION_MUTEX_PREFIX",
    "SESSION_TUPLE_VERSION",
    "WRITER_INVENTORY_SHA256",
    "WRITER_MUTEX_NAME",
    "WriterFenceError",
    "WriterFencedError",
    "active_fence",
    "canonical_control_root",
    "session_authority_mutex_name",
    "writer_admission",
    "writer_admission_mutex_name",
    "writer_sink",
]

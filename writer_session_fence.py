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
import threading
from typing import Any, Callable, Iterator, Mapping, ParamSpec, TypeVar
import unicodedata


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

# This pin is generated and checked by tools/derive_container_writer_sinks.py.
# It is updated together with the inventory after all sink markers are placed.
WRITER_INVENTORY_SHA256 = "24108d791a40b7f038157f948c5969aa893a6b28ff439eb89af48a9a92f83a8a"

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
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    handle = kernel32.CreateMutexW(None, False, name)
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
    """Admit one writer or fail closed without changing any persistent state."""

    selected_source = str(source or "").strip()
    if not selected_source:
        raise WriterFencedError("WRITER_SOURCE_MISSING", "writer source is required")
    depth = int(getattr(_WRITER_LOCAL, "depth", 0))
    if depth:
        nested_active = getattr(_WRITER_LOCAL, "active", None)
        nested_environ = getattr(_WRITER_LOCAL, "environ", None)
        if nested_active is not None and not _delegation_matches(
            nested_active,
            source=selected_source,
            environ=nested_environ if nested_environ is not None else os.environ,
        ):
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
        active = active_fence(root, environ=values)
        if active is not None and not _delegation_matches(
            active,
            source=selected_source,
            environ=values,
        ):
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
    _WRITER_LOCAL.environ = values
    try:
        yield
    finally:
        _WRITER_LOCAL.depth = 0
        _WRITER_LOCAL.active = None
        _WRITER_LOCAL.environ = None
        lease.release()


P = ParamSpec("P")
R = TypeVar("R")

# The only sinks allowed to probe admission and release it before the body
# runs: the session direct-sync wrapper, its process launcher, and the resident
# relay entry point that drives them. The relay child takes the same single
# admission for its own spanning writes, so a parent that held it across
# subprocess.run would starve the child out. Every one of these releases only
# after the probe has already denied an active fence, and each keeps its own
# writes under an explicit admission of its own.
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
    }
)


def writer_sink(
    source: str,
    *,
    probe_only: bool = False,
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

        sink_id = f"{function.__module__}.{function.__qualname__}"
        if probe_only and (selected_source, sink_id) not in PROBE_ONLY_WRITER_SINKS:
            raise WriterFencedError(
                "WRITER_PROBE_ONLY_SINK_NOT_ALLOWED",
                "probe-only admission is not approved for this writer sink",
            )

        @wraps(function)
        def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
            if probe_only:
                # Deny under an active fence before the child exists, then
                # release so the child can take the same admission itself.
                with writer_admission(selected_source):
                    pass
                return function(*args, **kwargs)
            with writer_admission(selected_source):
                return function(*args, **kwargs)

        setattr(guarded, "__container_writer_sink__", selected_source)
        return guarded

    return decorate


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

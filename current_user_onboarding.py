"""First-run current-user state onboarding for Container_Audit."""

from __future__ import annotations
from storage_utils import RemoteAttempt

import argparse
import ctypes
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, MutableMapping
from urllib.parse import urlsplit
import uuid
from contextlib import nullcontext

from direct_sync_push import load_json_no_duplicate_keys, manifest_hash
from direct_sync_runtime import load_credentials_from_json, prepare_credential_config, PreparedCredentialConfig
from logistics_runtime_profile import (
    PROFILE_PATH_ENV,
    REQUIRED_ENV,
    LogisticsRuntimeConfigurationError,
    default_logistics_profile_path,
    load_logistics_runtime_profile,
    unprotect_current_user_secret,
)
from storage_policy import (
    DATA_ROOT_ENV,
    build_container_audit_storage_paths,
    current_user_data_home,
    is_legacy_syncthing_path,
    path_is_within,
)
from user_relay import (
    USER_RELAY_RUN_KEY,
    USER_RELAY_RUN_VALUE,
    USER_RELAY_MODE,
    install_user_relay_autostart,
    installation_relay_start_deferred,
    relay_data_root_arguments,
    remove_user_relay_autostart,
    request_user_relay_stop,
    start_user_relay_process,
    user_relay_stop_path,
)
from writer_session_fence import WriterFenceError, writer_admission, writer_sink
from kmtech_shared import data_generation as generation
from vendor.kmtech_zero_pe import (
    ADMIN_RECOVERY_ACTION,
    AdminRecoveryRequired as PossessionKeyAdminRecoveryRequired,
    POSSESSION_KEY_CONTRACT_VERSION,
    PersistentPossessionKey,
    SCOPE_CURRENT_USER,
)
from storage_policy import ensure_user_runtime_directory

DEFAULT_SERVER_BASE_URL = "https://worker.kmtecherp.com"
DEFAULT_ENDPOINT_PATH = "/api/producer-ingest/v1/source-file"
ONBOARDING_REPORT_VERSION = "container-audit-current-user-onboarding-v1"
REMOVAL_REPORT_VERSION = "container-audit-current-user-removal-v1"
REPLACEMENT_LIFECYCLE_RESTORE_REPORT_VERSION = (
    "container-audit-replacement-lifecycle-restore-v1"
)
BOOTSTRAP_INTEGRITY_VERSION = "container-audit-bootstrap-integrity-v1"
LOGISTICS_PROFILE_PATH_ENV = PROFILE_PATH_ENV
ENROLLMENT_TLS_CA_BUNDLE_PATH_ENV = "CONTAINER_AUDIT_ENROLLMENT_TLS_CA_BUNDLE_PATH"
ONBOARDING_EXIT_CODE = 4
INSTALL_SERVER_ORIGIN_CHANGED = "INSTALL_SERVER_ORIGIN_CHANGED"
INSTALL_SERVER_ORIGIN_MESSAGE = "설치 주소가 바뀌었습니다. 관리자에게 알려 주세요."
WRITER_FENCE_EXIT_CODE = 23
INSTALLER_FAILURE_PREFIX = "CONTAINER_AUDIT_INSTALLER_FAILURE="
INSTALLER_WRITER_FENCE_CODES = frozenset({
    "ACTIVE_WRITER_FENCE", "FENCE_AUTHORITY_NAME_INVALID", "FENCE_BINDING_INVALID",
    "FENCE_DELEGATION_INVALID", "FENCE_JSON_INVALID", "FENCE_PATH_UNOBSERVABLE",
    "FENCE_PREPARED_BINDING_INVALID", "FENCE_PREPARED_RECEIPT_INVALID",
    "FENCE_PREPARED_RECEIPT_MISMATCH", "FENCE_PREPARED_RECEIPT_UNOBSERVABLE",
    "FENCE_REPARSE_REJECTED", "FENCE_SHAPE_INVALID", "FENCE_SIZE_INVALID",
    "FENCE_STATE_CHANGED", "FENCE_STATE_UNOBSERVABLE", "FENCE_STATE_UNREADABLE",
    "LOCALAPPDATA_UNAVAILABLE", "NETWORK_WRITER_ADMISSION_HELD",
    "WRITER_ADMISSION_DEPTH_UNDERFLOW", "WRITER_FENCE_FAILED", "WRITER_GATE_ABANDONED",
    "WRITER_GATE_TIMEOUT", "WRITER_MUTEX_CREATE_FAILED", "WRITER_MUTEX_WAIT_FAILED",
    "WRITER_PROBE_ONLY_SINK_NOT_ALLOWED", "WRITER_SOURCE_MISSING",
})
INSTALLER_PUBLIC_CODES = frozenset({
    "FAILED", "INSTALLER_CHILD_FAILURE", "REPORT_UNAVAILABLE",
    "DATA_GENERATION_REFUSED", "DATA_GENERATION_UNKNOWN",
    "onboarding", "onboarding_preflight", "current_user_removal",
    "replacement_lifecycle_restore", "installer_entrypoint",
}) | INSTALLER_WRITER_FENCE_CODES
INSTALLER_SAFE_MESSAGES = ("자료를 보존하고 관리자 지원 복구를 요청하세요.",
                           generation.REFUSAL_MESSAGE, generation.UNKNOWN_MESSAGE)
# A fresh CLI context owns references; exception attributes and old report paths
# are observations, never publication authority for a later attempt.
_FAILURE_ATTEMPT: ContextVar[dict | None] = ContextVar("installer_failure_attempt", default=None)
SELF_ENROLLMENT_CONTRACT_VERSION = "producer-self-enrollment-v2"
REPLACEMENT_RECEIPT_VERSION = "container-audit-verified-replacement-v1"
PORTABLE_MANIFEST_VERSION = "container-audit-portable-tree-v1"
_TARGET_PREFLIGHT_CODE_IDENTITY_ONLY = object()

_REPLACEMENT_IDENTITY_FIELDS = frozenset(
    {
        "file_count",
        "aggregate_sha256",
        "integrity_sha256",
        "manifest_sha256",
        "source_commit",
        "source_tree",
        "owner_sid",
        "access_rules_protected",
        "acl_sddl_sha256",
        "reparse_count",
    }
)
_REPLACEMENT_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "app_id",
        "transaction_id",
        "created_at",
        "helper_sha256",
        "integrity_helper_sha256",
        "receipt_path",
        "install_root",
        "install_parent",
        "rollback_root",
        "failed_root",
        "parent_acl",
        "old",
        "new",
        "identity_or_credential_copied",
    }
)


class CurrentUserOnboardingError(RuntimeError):
    def __init__(
        self, message: str, *, report_path: Path, status: str = "FAILED",
        reason_code: str = "",
    ) -> None:
        from auto_update import _failure_text, failure_user_line
        self.original_failure_text = _failure_text(message, limit=65536)
        super().__init__(failure_user_line(message))
        self.report_path = Path(report_path)
        self.status = status
        self.reason_code = reason_code


class CurrentUserPossessionRecoveryRequired(ValueError):
    recovery_action = ADMIN_RECOVERY_ACTION


@dataclass(frozen=True)
class CurrentUserOnboardingPaths:
    app_root: Path
    data_root: Path
    events_dir: Path
    direct_sync_root: Path
    queue_dir: Path
    spool_dir: Path
    status_dir: Path
    logs_dir: Path
    identity_path: Path
    producer_manifest_path: Path
    credential_path: Path
    registration_report_path: Path
    onboarding_report_path: Path
    removal_report_path: Path
    logistics_profile_path: Path
    logistics_secret_path: Path
    bootstrap_tls_ca_bundle_path: Path
    ledger_path: Path
    bootstrap_integrity_path: Path


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _resolved(path: str | os.PathLike[str]) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def resolve_current_user_onboarding_paths(
    app_root: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> CurrentUserOnboardingPaths:
    values = os.environ if environ is None else environ
    selected_app_root = _resolved(app_root)
    try:
        storage_paths = build_container_audit_storage_paths(
            application_path=str(selected_app_root),
            environ=values,
        )
        explicit_data_root = storage_paths.custom_data_root
        user_root = (
            storage_paths.data_root
            if explicit_data_root
            else current_user_data_home(values)
        )
    except ValueError as exc:
        safe_report_root = str(values.get("TEMP") or values.get("TMP") or "").strip()
        report_root = (
            _resolved(safe_report_root)
            if safe_report_root
            else _resolved(Path.home() / ".kmtech")
        )
        raise CurrentUserOnboardingError(
            str(exc),
            report_path=report_root
            / "container-audit-current-user-onboarding-rejected.json",
            status="FAILED",
        ) from exc
    data_root = storage_paths.data_root
    direct_sync_root = storage_paths.direct_sync_root
    try:
        logistics_profile = _resolved(default_logistics_profile_path(values))
    except LogisticsRuntimeConfigurationError as exc:
        raise CurrentUserOnboardingError(
            str(exc),
            report_path=user_root
            / "KMTech"
            / "ContainerAudit"
            / "current-user-onboarding-rejected.json",
            status="FAILED",
        ) from exc
    bootstrap_tls_ca_bundle = (
        data_root / "bootstrap" / "ca-bundle.pem"
        if explicit_data_root
        else user_root / "KMTech" / "Bootstrap" / "Container_Audit" / "ca-bundle.pem"
    )
    code_root_state_paths = (
        data_root,
        direct_sync_root,
        logistics_profile,
        bootstrap_tls_ca_bundle,
    )
    from storage_policy import require_prepared_machine_directory
    for directory in (logistics_profile.parent, bootstrap_tls_ca_bundle.parent):
        require_prepared_machine_directory(directory, environ=values)
    if any(
        path_is_within(candidate, selected_app_root)
        or path_is_within(selected_app_root, candidate)
        for candidate in code_root_state_paths
    ):
        safe_report_root = str(values.get("TEMP") or values.get("TMP") or "").strip()
        report_path = (
            _resolved(safe_report_root)
            if safe_report_root
            else _resolved(Path.home() / ".kmtech")
        ) / "container-audit-current-user-onboarding-rejected.json"
        raise CurrentUserOnboardingError(
            "current-user onboarding state must be outside the read-only application code root",
            report_path=report_path,
            status="FAILED",
        )
    for candidate in (data_root, direct_sync_root, logistics_profile):
        if is_legacy_syncthing_path(candidate):
            raise CurrentUserOnboardingError(
                "current-user onboarding state must not use the legacy Syncthing root",
                report_path=direct_sync_root
                / "status"
                / "current_user_onboarding.json",
            )
    status_dir = direct_sync_root / "status"
    return CurrentUserOnboardingPaths(
        app_root=selected_app_root,
        data_root=data_root,
        events_dir=data_root / "events",
        direct_sync_root=direct_sync_root,
        queue_dir=direct_sync_root / "queue",
        spool_dir=direct_sync_root / "spool",
        status_dir=status_dir,
        logs_dir=direct_sync_root / "logs",
        identity_path=direct_sync_root / "producer_identity.json",
        producer_manifest_path=direct_sync_root / "producer_manifest.json",
        credential_path=direct_sync_root / "credential.json",
        registration_report_path=status_dir / "worker_pc_registration.json",
        onboarding_report_path=status_dir / "current_user_onboarding.json",
        removal_report_path=status_dir / "current_user_removal.json",
        logistics_profile_path=logistics_profile,
        logistics_secret_path=(
            logistics_profile.parent / "secrets" / "bearer-token.dpapi"
        ),
        bootstrap_tls_ca_bundle_path=bootstrap_tls_ca_bundle,
        ledger_path=data_root / "transfer_seal" / "transfer_seal.db",
        bootstrap_integrity_path=selected_app_root / "bootstrap-integrity.json",
    )



def _report_metadata_for_sink(payload: Mapping[str, Any]) -> dict[str, Any]:
    # Give existing path/digest metadata its contract field names. This is
    # serialization only: owner comparisons and the returned report stay exact.
    result = dict(payload)
    for field, suffix in (("owner_artifact_paths", "_path"),
                          ("owner_artifact_fingerprints_before", "_sha256"),
                          ("owner_artifact_fingerprints_after", "_sha256")):
        entries = result.get(field)
        if isinstance(entries, Mapping):
            result[field] = {name + suffix: value for name, value in entries.items()}
    return result


def _exception_chain(error: BaseException):
    seen = set()
    while error is not None and id(error) not in seen and len(seen) < 16:
        seen.add(id(error))
        yield error
        error = error.__cause__ or error.__context__


def _failure_location(error: BaseException) -> dict[str, Any]:
    chain = list(_exception_chain(error))
    fields = {"exception_type": type(chain[-1]).__module__ + "." + type(chain[-1]).__name__}
    app_root = Path(__file__).resolve().parent
    for cause in reversed(chain):
        selected = None
        frame = cause.__traceback__
        while frame is not None:
            module = frame.tb_frame.f_globals.get("__name__")
            function = frame.tb_frame.f_code.co_name
            if (isinstance(module, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", module)
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", function)):
                try:
                    relative = Path(frame.tb_frame.f_code.co_filename).resolve().relative_to(app_root)
                except (OSError, ValueError):
                    pass
                else:
                    if relative.parts and relative.parts[0].casefold() != 'site-packages':
                        selected = {"location_module": module, "location_function": function,
                                    "location_line": frame.tb_lineno}
            frame = frame.tb_next
        if selected is not None:
            fields.update(selected)
            break
    return fields


def emit_installer_failure(error: BaseException, stage: str) -> int:
    """Emit one allowlisted record; never serialize an exception message."""
    from auto_update import public_record
    attempt = _FAILURE_ATTEMPT.get()
    chain = list(_exception_chain(error))
    from data_generation_guard import DataGenerationBlocked
    reason = "INSTALLER_CHILD_FAILURE"
    exit_code = ONBOARDING_EXIT_CODE
    guidance = INSTALLER_SAFE_MESSAGES[0]
    blocked = next((entry for entry in chain if isinstance(entry, DataGenerationBlocked)), None)
    writer_error = next((entry for entry in chain if isinstance(entry, WriterFenceError)), None)
    if writer_error is not None:
        exit_code = WRITER_FENCE_EXIT_CODE
        reason = (writer_error.code if type(writer_error.code) is str
                  and writer_error.code in INSTALLER_WRITER_FENCE_CODES else "WRITER_FENCE_FAILED")
    elif blocked is not None:
        refused = blocked.decision.get("status") == "REFUSE"
        reason = "DATA_GENERATION_REFUSED" if refused else "DATA_GENERATION_UNKNOWN"
        guidance = generation.REFUSAL_MESSAGE if refused else generation.UNKNOWN_MESSAGE
    else:
        # Identity-readback failures already use these two fixed G messages.
        # Accept only the project exception and exact registered constants;
        # arbitrary exception sentences remain private.
        for entry in chain:
            if isinstance(entry, CurrentUserOnboardingError) and entry.args and type(entry.args[0]) is str:
                if entry.args[0] in (generation.REFUSAL_MESSAGE, generation.UNKNOWN_MESSAGE):
                    guidance = entry.args[0]
                    reason = ("DATA_GENERATION_REFUSED" if guidance == generation.REFUSAL_MESSAGE
                              else "DATA_GENERATION_UNKNOWN")
                    break
    fields = {
        "status": "FAILED", "stage": stage, "reason_code": reason,
        "exit_code": exit_code, "guidance": guidance,
        "attempt_id": attempt["id"] if attempt else uuid.uuid4().hex,
    }
    fields.update(_failure_location(error))
    # These caller-selected/current-user report roots have no proven reader ACL.
    # An atomic JSON write alone does not authorize publishing original text.
    fields["report_status"] = "REPORT_UNAVAILABLE"
    print(INSTALLER_FAILURE_PREFIX + json.dumps(
        public_record(fields, INSTALLER_PUBLIC_CODES, INSTALLER_SAFE_MESSAGES),
        ensure_ascii=True, separators=(",", ":")), file=sys.stderr)
    return exit_code


def _new_failure_attempt():
    return _FAILURE_ATTEMPT.set({"id": uuid.uuid4().hex, "publications": {}})


def _persist_failure_report(path: Path, report: dict[str, Any], error: BaseException,
                            *, create_new: bool = False) -> None:
    from auto_update import _failure_details, mixed_status_record, public_record
    attempt = _FAILURE_ATTEMPT.get()
    if attempt:
        attempt["publications"].pop(id(error), None)
    report["failure_attempt_id"] = attempt["id"] if attempt else uuid.uuid4().hex
    report["failure"] = "SUPPORT_FAILURE"
    report["failure_details"] = mixed_status_record({"failure_details": _failure_details(error)})["failure_details"]
    report["failure_evidence_refs"] = []
    report["failure_evidence_status"] = "REPORT_UNAVAILABLE"
    report.update(public_record(_failure_location(error), INSTALLER_PUBLIC_CODES, INSTALLER_SAFE_MESSAGES))
    try:
        # Only diagnostic fields are transformed; generic metadata writers keep
        # their original-byte/fail-closed contract for READY and owner records.
        safe_report = mixed_status_record(report)
        writer = _write_json_atomic_create_new if create_new else _write_json_atomic
        writer(path, safe_report)
    except Exception:
        # Publication refusal must not replace the primary failure or advertise
        # an old pathname. The public boundary emits REPORT_UNAVAILABLE.
        report["failure_report_status"] = "REPORT_UNAVAILABLE"


def _atomic_report_reference(path: Path, expected: bytes) -> dict[str, str]:
    raw = path.read_bytes()
    if raw != expected:
        raise ValueError("FAILURE_REPORT_PUBLICATION_READBACK_DIFFERS")
    raw.decode("utf-8", errors="strict")
    return {"path": str(path.absolute()), "sha256": hashlib.sha256(raw).hexdigest()}


@writer_sink("current_user_onboarding_storage")
def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> dict[str, str]:
    from atomic_replace import atomic_replace
    from auto_update import serialize_machine_metadata
    safe_text = serialize_machine_metadata(payload)
    ensure_user_runtime_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(safe_text)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        atomic_replace(temporary, path)
        return _atomic_report_reference(path, (safe_text + "\n").encode("utf-8"))
    finally:
        temporary.unlink(missing_ok=True)


@writer_sink("current_user_onboarding_storage")
def _write_json_atomic_create_new(path: Path, payload: Mapping[str, Any]) -> dict[str, str]:
    """Publish JSON atomically without ever replacing an existing pathname."""

    from auto_update import serialize_machine_metadata
    safe_text = serialize_machine_metadata(payload)
    ensure_user_runtime_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(safe_text)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        return _atomic_report_reference(path, (safe_text + "\n").encode("utf-8"))
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path, purpose: str) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"{purpose} is absent") from exc
    if size <= 0 or size > 1024 * 1024:
        raise ValueError(f"{purpose} size is invalid")
    try:
        value = load_json_no_duplicate_keys(path.read_bytes())
    except Exception as exc:
        raise ValueError(f"{purpose} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{purpose} must be a JSON object")
    return value


def _read_pinned_json(
    path: Path,
    purpose: str,
    *,
    expected_sha256: str,
    maximum_bytes: int,
) -> dict[str, Any]:
    _require_regular_unredirected_file(path, purpose)
    try:
        with path.open("rb") as handle:
            data = handle.read(maximum_bytes + 1)
    except OSError as exc:
        raise ValueError(f"{purpose} is absent or unreadable") from exc
    if not data or len(data) > maximum_bytes:
        raise ValueError(f"{purpose} size is invalid")
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError(f"{purpose} SHA-256 differs")
    try:
        value = load_json_no_duplicate_keys(data)
    except Exception as exc:
        raise ValueError(f"{purpose} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{purpose} must be a JSON object")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class BootstrapIntegrityMismatch(ValueError):
    """The installed inventory comparison completed and proved a mismatch."""


def verify_bootstrap_integrity(
    paths: CurrentUserOnboardingPaths,
    *,
    required: bool,
    expected_entrypoint: str = "Container_Audit.exe",
    rehash_paths: frozenset[str] | None = None,
    deadline: float | None = None,
) -> dict[str, Any]:
    if not required:
        return {"status": "NOT_TESTED", "reason": "source-mode onboarding"}
    try:
        record_stat = paths.bootstrap_integrity_path.lstat()
    except FileNotFoundError:
        return {
            "status": "ABSENT",
            "reason": "bootstrap integrity record is absent; continuing with a warning",
            "record_path": str(paths.bootstrap_integrity_path),
        }
    except OSError as exc:
        raise ValueError("bootstrap integrity record is unreadable") from exc
    if stat.S_ISLNK(record_stat.st_mode) or not stat.S_ISREG(record_stat.st_mode):
        raise ValueError(
            "bootstrap integrity record is redirected or not a regular file"
        )
    record = _read_json(paths.bootstrap_integrity_path, "bootstrap integrity record")
    if record.get("schema_version") != BOOTSTRAP_INTEGRITY_VERSION:
        raise ValueError("bootstrap integrity record schema is invalid")
    if record.get("status") != "PASS":
        raise ValueError("bootstrap integrity record is not PASS")
    declared_code_root = str(record.get("code_root") or "")
    resolved_code_root = (
        paths.bootstrap_integrity_path.parent.resolve()
        if declared_code_root == "."
        else _resolved(declared_code_root)
    )
    if resolved_code_root != paths.app_root:
        raise ValueError("bootstrap integrity record code root is invalid")
    files = record.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("bootstrap integrity record file inventory is invalid")
    if record.get("file_count") != len(files):
        raise ValueError("bootstrap integrity record file count is invalid")
    normalized: list[tuple[str, int, str]] = []
    declared_paths: set[str] = set()
    for item in files:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("bootstrap inventory budget exhausted")
        if not isinstance(item, Mapping):
            raise ValueError("bootstrap integrity inventory entry is invalid")
        relative_text = str(item.get("path") or "").replace("\\", "/")
        parts = relative_text.split("/")
        if (
            not relative_text
            or relative_text.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
            or ":" in parts[0]
        ):
            raise ValueError("bootstrap integrity inventory path is unsafe")
        folded = relative_text.casefold()
        if folded in declared_paths:
            raise ValueError("bootstrap integrity inventory path is duplicated")
        declared_paths.add(folded)
        try:
            expected_size = int(item.get("size"))
        except (TypeError, ValueError) as exc:
            raise ValueError("bootstrap integrity inventory size is invalid") from exc
        expected_hash = str(item.get("sha256") or "").strip().lower()
        if expected_size < 0 or len(expected_hash) != 64:
            raise ValueError("bootstrap integrity inventory metadata is invalid")
        target = paths.app_root.joinpath(*parts)
        if target.is_symlink() or not target.is_file():
            raise BootstrapIntegrityMismatch(
                f"bootstrap code file is absent or redirected: {relative_text}"
            )
        if (
            target.stat().st_size != expected_size
            or ((rehash_paths is None or relative_text in rehash_paths)
                and _file_sha256(target) != expected_hash)
        ):
            raise BootstrapIntegrityMismatch(f"bootstrap code file integrity failed: {relative_text}")
        normalized.append((expected_hash, expected_size, relative_text))
    actual_paths = set()
    for candidate in paths.app_root.rglob("*"):
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("bootstrap inventory budget exhausted")
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(paths.app_root).as_posix().casefold()
        if relative == paths.bootstrap_integrity_path.name.casefold():
            continue
        actual_paths.add(relative)
    if actual_paths != declared_paths:
        raise BootstrapIntegrityMismatch("bootstrap code inventory exact readback failed")
    aggregate_payload = "".join(
        f"{sha256} {size} {relative_path}\n"
        for sha256, size, relative_path in normalized
    ).encode("utf-8")
    aggregate = hashlib.sha256(aggregate_payload).hexdigest()
    if aggregate != str(record.get("aggregate_sha256") or "").strip().lower():
        raise BootstrapIntegrityMismatch("bootstrap integrity aggregate is invalid")
    if expected_entrypoint not in {"Container_Audit.exe", "app/Container_Audit.py", "Container_Audit.py"}:
        raise ValueError("bootstrap code entrypoint is not approved")
    main_entries = [
        item
        for item in files
        if isinstance(item, Mapping)
        and str(item.get("path") or "").replace("\\", "/").casefold()
        == expected_entrypoint.casefold()
    ]
    if len(main_entries) != 1:
        raise ValueError(
            f"bootstrap integrity record does not identify {expected_entrypoint}"
        )
    executable = paths.app_root / expected_entrypoint
    if not executable.is_file():
        raise ValueError("verified Container_Audit code entrypoint is absent")
    return {
        "status": "PASS",
        "record_path": str(paths.bootstrap_integrity_path),
        "code_root": str(paths.app_root),
        "file_count": len(files),
        "aggregate_sha256": aggregate,
    }


def _is_reparse_or_link(path_stat: os.stat_result) -> bool:
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    attributes = int(getattr(path_stat, "st_file_attributes", 0))
    return stat.S_ISLNK(path_stat.st_mode) or bool(attributes & reparse_flag)


def _require_regular_unredirected_file(path: Path, purpose: str) -> os.stat_result:
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise ValueError(f"{purpose} is absent or unreadable") from exc
    if _is_reparse_or_link(path_stat) or not stat.S_ISREG(path_stat.st_mode):
        raise ValueError(f"{purpose} is redirected or not a regular file")
    return path_stat


def _assert_tree_has_no_reparse_points(root: Path, purpose: str) -> None:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise ValueError(f"{purpose} is absent or unreadable") from exc
    if _is_reparse_or_link(root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError(f"{purpose} is redirected or not a directory")
    for candidate in root.rglob("*"):
        try:
            candidate_stat = candidate.lstat()
        except OSError as exc:
            raise ValueError(f"{purpose} contains an unreadable path") from exc
        if _is_reparse_or_link(candidate_stat):
            raise ValueError(f"{purpose} contains a reparse point")


@writer_sink("current_user_onboarding")
def _windows_acl_identity(path: Path) -> dict[str, Any]:
    """Read the same owner/protection/SDDL identity as bootstrap_integrity.ps1."""

    if os.name != "nt":
        raise OSError("replacement lifecycle ACL readback is Windows-only")
    import ctypes

    system_directory_buffer = ctypes.create_unicode_buffer(32768)
    system_directory_length = ctypes.windll.kernel32.GetSystemDirectoryW(
        system_directory_buffer,
        len(system_directory_buffer),
    )
    if system_directory_length <= 0 or system_directory_length >= len(
        system_directory_buffer
    ):
        raise OSError("Windows system directory readback failed")
    powershell = (
        Path(system_directory_buffer.value)
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    _require_regular_unredirected_file(
        powershell,
        "Windows PowerShell ACL reader",
    )
    escaped_path = str(path).replace("'", "''")
    command = (
        r"""Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
"""
        "$ErrorActionPreference='Stop';"
        f"$item=Get-Item -LiteralPath '{escaped_path}' -Force;"
        "$sections=([Security.AccessControl.AccessControlSections]::Access -bor "
        "[Security.AccessControl.AccessControlSections]::Owner -bor "
        "[Security.AccessControl.AccessControlSections]::Group);"
        "$acl=if($item.PSIsContainer){"
        "[IO.Directory]::GetAccessControl($item.FullName,$sections)"
        "}else{[IO.File]::GetAccessControl($item.FullName,$sections)};"
        "$sddl=$acl.GetSecurityDescriptorSddlForm($sections);"
        "$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($sddl);"
        "$sha=[Security.Cryptography.SHA256]::Create();"
        "try{$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-',"
        "'').ToLowerInvariant()}finally{$sha.Dispose()};"
        "[ordered]@{owner_sid=[string]$acl.GetOwner("
        "[Security.Principal.SecurityIdentifier]).Value;"
        "access_rules_protected=[bool]$acl.AreAccessRulesProtected;"
        "acl_sddl_sha256=$hash;acl_sddl=$sddl}|ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=15,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if (
        completed.returncode != 0
        or len(completed.stdout.encode("utf-8")) > 131072
        or len(completed.stderr.encode("utf-8")) > 4096
    ):
        error = OSError("replacement lifecycle ACL readback failed")
        error.stderr, error.exit_code = completed.stderr, completed.returncode
        # ACL stdout is restoration material, never diagnostic text.
        error.stdout_sha256 = hashlib.sha256(completed.stdout.encode('utf-8')).hexdigest()
        raise error
    try:
        result = json.loads(completed.stdout)
    except (TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("replacement lifecycle ACL identity is invalid") from exc
    if not isinstance(result, dict):
        raise ValueError("replacement lifecycle ACL identity is invalid")
    return result


def _validate_acl_raw_binding(value: Mapping[str, Any], raw_field: str, hash_field: str) -> None:
    if raw_field in value:
        raw = value[raw_field]
        if (not isinstance(raw, str) or not raw.strip() or len(raw) > 65536
                or hashlib.sha256(raw.encode("utf-8")).hexdigest() != value[hash_field]):
            raise ValueError("replacement ACL raw descriptor binding is invalid")


@writer_sink("current_user_lifecycle_restore")
def _replacement_identities_match(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
    fields = _REPLACEMENT_IDENTITY_FIELDS - {"acl_sddl_sha256"}
    if any(expected[field] != actual[field] for field in fields):
        return False
    if "acl_sddl" not in expected and "acl_sddl" not in actual:
        return expected["acl_sddl_sha256"] == actual["acl_sddl_sha256"]
    # Use the same library shipped with this executing module, never a helper
    # from either receipt-selected tree. Parsing only extracts trusted functions.
    module_root = Path(__file__).resolve().parent
    helper = module_root / "tools" / "bootstrap_integrity.ps1"
    if not helper.exists():
        helper = module_root.parent / "tools" / "bootstrap_integrity.ps1"
    info = _require_regular_unredirected_file(helper, "executing ACL comparison library")
    if info.st_size > 1048576:
        raise ValueError("executing ACL comparison library is oversized")
    import ctypes

    directory = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(directory, len(directory))
    if length <= 0 or length >= len(directory):
        raise OSError("Windows system directory readback failed")
    powershell = Path(directory.value) / "WindowsPowerShell/v1.0/powershell.exe"
    _require_regular_unredirected_file(powershell, "Windows PowerShell ACL reader")
    escaped = str(helper).replace("'", "''")
    command = (
        r"""Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
"""
        "$ErrorActionPreference='Stop';$tokens=$null;$errors=$null;"
        f"$ast=[Management.Automation.Language.Parser]::ParseFile('{escaped}',[ref]$tokens,[ref]$errors);"
        "if($errors.Count){throw 'Invalid ACL library'};"
        "$names=@('Get-BootstrapStringSha256','Get-BootstrapAclComparisonKey',"
        "'Test-BootstrapAclRawBinding','Test-BootstrapAclIdentity');"
        "foreach($name in $names){$nodes=@($ast.FindAll({param($n) "
        "$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false));"
        "if($nodes.Count -ne 1){throw 'Invalid ACL function'};"
        "Invoke-Expression $nodes[0].Extent.Text};"
        "$pair=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
        "Test-BootstrapAclIdentity $pair.expected $pair.actual 'acl_sddl_sha256' 'acl_sddl'"
    )
    completed = subprocess.run(
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
        input=json.dumps({"expected": dict(expected), "actual": dict(actual)}),
        capture_output=True, text=True, encoding="utf-8", errors="strict",
        timeout=15, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0 or completed.stdout.strip() not in ("True", "False"):
        error = OSError("replacement ACL comparison failed")
        error.stderr, error.exit_code = completed.stderr, completed.returncode
        raise error
    return completed.stdout.strip() == "True"


def _normalized_replacement_identity(
    value: Any,
    purpose: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) not in (
        _REPLACEMENT_IDENTITY_FIELDS, _REPLACEMENT_IDENTITY_FIELDS | {"acl_sddl"}
    ):
        raise ValueError(f"{purpose} shape is invalid")
    file_count = value.get("file_count")
    reparse_count = value.get("reparse_count")
    protected = value.get("access_rules_protected")
    if type(file_count) is not int or file_count <= 0:
        raise ValueError(f"{purpose} file count is invalid")
    if type(reparse_count) is not int or reparse_count != 0:
        raise ValueError(f"{purpose} reparse count is invalid")
    if type(protected) is not bool:
        raise ValueError(f"{purpose} ACL protection is invalid")
    for field in (
        "aggregate_sha256",
        "integrity_sha256",
        "manifest_sha256",
        "acl_sddl_sha256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(value.get(field) or "")):
            raise ValueError(f"{purpose} {field} is invalid")
    for field in ("source_commit", "source_tree"):
        if not re.fullmatch(r"[0-9a-f]{40}", str(value.get(field) or "")):
            raise ValueError(f"{purpose} {field} is invalid")
    owner_sid = str(value.get("owner_sid") or "")
    if not owner_sid or len(owner_sid) > 184:
        raise ValueError(f"{purpose} owner identity is invalid")
    _validate_acl_raw_binding(value, "acl_sddl", "acl_sddl_sha256")
    return dict(value)


def _read_replacement_tree_identity(
    tree_root: Path,
    declared_code_root: Path,
    *,
    acl_identity_reader: Callable[[Path], Mapping[str, Any]] | None = _windows_acl_identity,
    _preflight_code_identity: object | None = None,
) -> dict[str, Any]:
    """Read an exact portable tree identity without executing code from that tree."""

    if acl_identity_reader is None and _preflight_code_identity is not _TARGET_PREFLIGHT_CODE_IDENTITY_ONLY:
        raise ValueError("code-only identity is restricted to target-generation preflight")

    selected_root = _resolved(tree_root)
    expected_code_root = _resolved(declared_code_root)
    _assert_tree_has_no_reparse_points(selected_root, "replacement code tree")
    record_path = selected_root / "bootstrap-integrity.json"
    record_stat = _require_regular_unredirected_file(
        record_path,
        "replacement bootstrap integrity record",
    )
    if record_stat.st_size <= 0 or record_stat.st_size > 1024 * 1024:
        raise ValueError("replacement bootstrap integrity record size is invalid")
    record = _read_json(record_path, "replacement bootstrap integrity record")
    declared_root_text = str(record.get("code_root") or "")
    if declared_root_text == ".":
        resolved_declared_root = selected_root
    elif Path(declared_root_text).is_absolute():
        resolved_declared_root = _resolved(declared_root_text)
    else:
        raise ValueError("replacement bootstrap code root is invalid")
    files = record.get("files")
    if (
        record.get("schema_version") != BOOTSTRAP_INTEGRITY_VERSION
        or record.get("status") != "PASS"
        or resolved_declared_root != expected_code_root
        or not isinstance(files, list)
        or not files
        or type(record.get("file_count")) is not int
        or record.get("file_count") != len(files)
    ):
        raise ValueError("replacement bootstrap integrity identity is invalid")

    normalized: list[tuple[str, int, str]] = []
    declared_paths: set[str] = set()
    for item in files:
        if not isinstance(item, Mapping):
            raise ValueError("replacement bootstrap inventory entry is invalid")
        relative_text = str(item.get("path") or "").replace("\\", "/")
        parts = relative_text.split("/")
        folded = relative_text.casefold()
        expected_size = item.get("size")
        expected_hash = str(item.get("sha256") or "")
        if (
            not relative_text
            or relative_text.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
            or ":" in parts[0]
            or folded in declared_paths
            or type(expected_size) is not int
            or expected_size < 0
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
        ):
            raise ValueError("replacement bootstrap inventory metadata is invalid")
        target = selected_root.joinpath(*parts)
        target_stat = _require_regular_unredirected_file(
            target,
            "replacement bootstrap code file",
        )
        if (
            target_stat.st_size != expected_size
            or _file_sha256(target) != expected_hash
        ):
            raise ValueError("replacement bootstrap code file integrity failed")
        declared_paths.add(folded)
        normalized.append((expected_hash, expected_size, relative_text))

    actual_paths: set[str] = set()
    for candidate in selected_root.rglob("*"):
        candidate_stat = candidate.lstat()
        if not stat.S_ISREG(candidate_stat.st_mode):
            continue
        relative = candidate.relative_to(selected_root).as_posix().casefold()
        if relative == "bootstrap-integrity.json":
            continue
        if relative in actual_paths:
            raise ValueError("replacement bootstrap inventory has a case collision")
        actual_paths.add(relative)
    if actual_paths != declared_paths:
        raise ValueError("replacement bootstrap inventory exact readback failed")
    aggregate_payload = "".join(
        f"{sha256} {size} {relative_path}\n"
        for sha256, size, relative_path in normalized
    ).encode("utf-8")
    aggregate = hashlib.sha256(aggregate_payload).hexdigest()
    if aggregate != str(record.get("aggregate_sha256") or ""):
        raise ValueError("replacement bootstrap aggregate is invalid")
    if (
        "runtime/pythonw.exe" not in declared_paths
        or "app/main.py" not in declared_paths
        or "container_audit.exe" in declared_paths
    ):
        raise ValueError("replacement code tree is not the portable runtime layout")

    manifest_path = selected_root / "portable-manifest.json"
    manifest_stat = _require_regular_unredirected_file(
        manifest_path,
        "replacement portable manifest",
    )
    if manifest_stat.st_size <= 0 or manifest_stat.st_size > 65536:
        raise ValueError("replacement portable manifest size is invalid")
    manifest = _read_json(manifest_path, "replacement portable manifest")
    source_commit = str(manifest.get("source_commit") or "")
    source_tree = str(manifest.get("source_tree") or "")
    if (
        manifest.get("schema") != PORTABLE_MANIFEST_VERSION
        or manifest.get("entrypoint") != "runtime/pythonw.exe app/main.py"
        or not re.fullmatch(r"[0-9a-f]{40}", source_commit)
        or not re.fullmatch(r"[0-9a-f]{40}", source_tree)
    ):
        raise ValueError("replacement portable manifest identity is invalid")
    if acl_identity_reader is None:
        return {
            "file_count": len(files), "aggregate_sha256": aggregate,
            "integrity_sha256": _file_sha256(record_path),
            "manifest_sha256": _file_sha256(manifest_path),
            "source_commit": source_commit, "source_tree": source_tree,
            "reparse_count": 0,
        }
    acl = dict(acl_identity_reader(selected_root))
    if set(acl) not in ({
        "owner_sid",
        "access_rules_protected",
        "acl_sddl_sha256",
    }, {"owner_sid", "access_rules_protected", "acl_sddl_sha256", "acl_sddl"}):
        raise ValueError("replacement code ACL identity is invalid")
    return _normalized_replacement_identity(
        {
            "file_count": len(files),
            "aggregate_sha256": aggregate,
            "integrity_sha256": _file_sha256(record_path),
            "manifest_sha256": _file_sha256(manifest_path),
            "source_commit": source_commit,
            "source_tree": source_tree,
            "owner_sid": acl["owner_sid"],
            "access_rules_protected": acl["access_rules_protected"],
            "acl_sddl_sha256": acl["acl_sddl_sha256"],
            **({"acl_sddl": acl["acl_sddl"]} if "acl_sddl" in acl else {}),
            "reparse_count": 0,
        },
        "replacement code identity",
    )


def _owner_artifact_paths(
    paths: CurrentUserOnboardingPaths,
) -> dict[str, Path]:
    return {
        "identity": paths.identity_path,
        "producer_manifest": paths.producer_manifest_path,
        "credential": paths.credential_path,
        "registration_report": paths.registration_report_path,
        "logistics_profile": paths.logistics_profile_path,
        "logistics_secret": paths.logistics_secret_path,
        "ledger": paths.ledger_path,
    }


def _owner_artifact_fingerprints(
    owner_paths: Mapping[str, Path],
) -> dict[str, str]:
    fingerprints: dict[str, str] = {}
    for name, path in owner_paths.items():
        before = _require_regular_unredirected_file(
            path,
            f"current-user owner artifact {name}",
        )
        fingerprint = _file_sha256(path)
        after = _require_regular_unredirected_file(
            path,
            f"current-user owner artifact {name}",
        )
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or getattr(before, "st_ino", 0) != getattr(after, "st_ino", 0)
        ):
            raise ValueError("current-user owner state changed during readback")
        fingerprints[name] = fingerprint
    return fingerprints


def _replacement_user_relay_command(
    app_root: Path, *, environ: Mapping[str, str] | None = None,
) -> list[str]:
    selected = _resolved(app_root)
    pythonw = selected.parent / "runtime" / "pythonw.exe"
    entrypoint = selected / "main.py"
    _require_regular_unredirected_file(
        pythonw,
        "replacement lifecycle canonical relay runtime",
    )
    _require_regular_unredirected_file(
        entrypoint,
        "replacement lifecycle canonical relay entrypoint",
    )
    from auto_update import control_root

    control = control_root(selected)
    if control is not None:
        fixed = control.parent / "current"
        return [str(fixed / "runtime/pythonw.exe"), "-I", "-B", str(fixed / "app/auto_update.py"), "--bootstrap", "--role", "relay", "--", USER_RELAY_MODE,
                *relay_data_root_arguments(selected, environ=environ)]
    return [str(pythonw), "-I", "-B", str(entrypoint), USER_RELAY_MODE,
            *relay_data_root_arguments(selected, environ=environ)]


def _replacement_user_relay_command_line(
    app_root: Path, *, environ: Mapping[str, str] | None = None,
) -> str:
    return subprocess.list2cmdline(_replacement_user_relay_command(app_root, environ=environ))


@writer_sink("current_user_lifecycle_restore")
def _start_replacement_user_relay_process(
    app_root: Path, *, environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    selected = _resolved(app_root)
    command = _replacement_user_relay_command(selected, environ=environ)
    creation_flags = (
        getattr(subprocess, "CREATE_NO_WINDOW", 0)
        | getattr(subprocess, "DETACHED_PROCESS", 0)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    )
    process = subprocess.Popen(
        command,
        cwd=str(selected),
        close_fds=True,
        creationflags=creation_flags,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if type(process.pid) is not int or process.pid <= 0:
        raise ValueError("replacement lifecycle relay launch did not return a process id")
    return {"status": "START_REQUESTED", "process_id": process.pid}


def _inspect_current_process_execution_context() -> dict[str, Any]:
    if os.name != "nt":
        raise ValueError("replacement lifecycle token inspection requires Windows")
    from ctypes import wintypes

    token_query = 0x0008
    token_elevation = 20
    token_integrity_level = 25
    error_insufficient_buffer = 122
    process_token = wintypes.HANDLE()
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetSidSubAuthorityCount.argtypes = [wintypes.LPVOID]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi32.GetSidSubAuthority.argtypes = [wintypes.LPVOID, wintypes.DWORD]
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), token_query, ctypes.byref(process_token)
    ):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        elevated = wintypes.DWORD()
        returned = wintypes.DWORD()
        if not advapi32.GetTokenInformation(
            process_token,
            token_elevation,
            ctypes.byref(elevated),
            ctypes.sizeof(elevated),
            ctypes.byref(returned),
        ):
            raise OSError(ctypes.get_last_error(), "TokenElevation readback failed")

        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            process_token,
            token_integrity_level,
            None,
            0,
            ctypes.byref(required),
        )
        if ctypes.get_last_error() != error_insufficient_buffer or required.value <= 0:
            raise OSError(
                ctypes.get_last_error(), "TokenIntegrityLevel sizing failed"
            )
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            process_token,
            token_integrity_level,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError(
                ctypes.get_last_error(), "TokenIntegrityLevel readback failed"
            )

        class SidAndAttributes(ctypes.Structure):
            _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]

        sid = ctypes.cast(buffer, ctypes.POINTER(SidAndAttributes)).contents.sid
        count_pointer = advapi32.GetSidSubAuthorityCount(sid)
        if not count_pointer:
            raise OSError(ctypes.get_last_error(), "integrity SID count failed")
        count = count_pointer.contents.value
        if count <= 0:
            raise ValueError("integrity SID contains no subauthority")
        rid_pointer = advapi32.GetSidSubAuthority(sid, count - 1)
        if not rid_pointer:
            raise OSError(ctypes.get_last_error(), "integrity SID RID failed")
        rid = rid_pointer.contents.value
    finally:
        kernel32.CloseHandle(process_token)

    if 0x2000 <= rid < 0x3000:
        integrity = "MEDIUM"
    elif rid < 0x2000:
        integrity = "LOW"
    else:
        integrity = "HIGH"
    return {
        "status": "PASS",
        "token_elevated": bool(elevated.value),
        "integrity_level": integrity,
    }


@writer_sink("current_user_onboarding_storage")
def _install_replacement_user_relay_autostart(
    app_root: Path, *, environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if os.name != "nt":
        raise ValueError("replacement lifecycle HKCU relay requires Windows")
    import winreg

    command = _replacement_user_relay_command_line(app_root, environ=environ)
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER,
        USER_RELAY_RUN_KEY,
        0,
        winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
    ) as key:
        winreg.SetValueEx(key, USER_RELAY_RUN_VALUE, 0, winreg.REG_SZ, command)
        readback, value_type = winreg.QueryValueEx(key, USER_RELAY_RUN_VALUE)
    if value_type != winreg.REG_SZ or str(readback) != command:
        raise ValueError("replacement lifecycle HKCU relay exact readback failed")
    return {
        "status": "PASS",
        "principal": "current_user",
        "registry_hive": "HKEY_CURRENT_USER",
        "registry_key": USER_RELAY_RUN_KEY,
        "registry_value": USER_RELAY_RUN_VALUE,
        "command": command,
    }


def _default_profile_loader(path: Path) -> Any:
    return load_logistics_runtime_profile(
        required=True,
        profile_path=path,
        decryptor=unprotect_current_user_secret,
    )


def _possession_key_readback(identity: Mapping[str, Any]) -> dict[str, Any]:
    enrollment_contract = str(identity.get("enrollment_contract_version") or "")
    key_contract = str(identity.get("possession_key_contract_version") or "")
    expected_fingerprint = str(identity.get("possession_key_fingerprint") or "")
    if (
        enrollment_contract != SELF_ENROLLMENT_CONTRACT_VERSION
        or key_contract != POSSESSION_KEY_CONTRACT_VERSION
        or not expected_fingerprint
    ):
        raise CurrentUserPossessionRecoveryRequired(
            "legacy producer identity has no v2 possession-key binding; audited administrator recovery is required"
        )
    try:
        with PersistentPossessionKey.open_existing(
            scope=SCOPE_CURRENT_USER
        ) as possession_key:
            descriptor = possession_key.descriptor()
            non_exportability = possession_key.assert_non_exportable()
    except PossessionKeyAdminRecoveryRequired as exc:
        raise CurrentUserPossessionRecoveryRequired(
            f"persisted possession key requires audited administrator recovery: {exc.reason}"
        ) from exc
    if descriptor.fingerprint != expected_fingerprint:
        raise CurrentUserPossessionRecoveryRequired(
            "persisted producer identity and current possession key fingerprint differ"
        )
    return {
        "status": "READY",
        "contract_version": descriptor.contract_version,
        "scope": descriptor.scope,
        "fingerprint": descriptor.fingerprint,
        "export_policy": descriptor.export_policy,
        "private_export_status": non_exportability.private_export_status_hex,
    }


def first_run_onboarding_enabled() -> bool:
    if getattr(sys, "frozen", False) and os.name == "nt":
        return True
    value = os.getenv("CONTAINER_AUDIT_ENABLE_FIRST_RUN_ONBOARDING", "").strip().lower()
    return value in {"1", "true", "yes", "on", "enabled"}


def startup_onboarding_reason(state, *, machine=False, can_onboard=False):
    """Classify an existing inspection result, without reading or changing state."""
    if state is None and machine:
        return None
    if not isinstance(state, Mapping):
        return "UNKNOWN_ACCOUNT"
    if state.get("error_type") not in (None, "ValueError", "CurrentUserPossessionRecoveryRequired"):
        return "UNKNOWN_ACCOUNT"
    status = state.get("status")
    if status == "READY":
        return None
    if machine:
        if status == "PENDING":
            return "FIRST_RUN_PENDING"
        if status in {"FAILED", "MACHINE_ONBOARDING_FAILED"}:
            return "MACHINE_ONBOARDING_PENDING"
    else:
        if status in {"ABSENT", "ABSENT_RETRYABLE"}:
            return "FIRST_RUN_PENDING" if can_onboard else "FIRST_RUN_SETUP_REQUIRED"
        if status in {"RECOVERY_REQUIRED", "FAILED"}:
            return "FIRST_RUN_SETUP_REQUIRED"
    return "UNKNOWN_ACCOUNT"


def _observe_startup_onboarding(state, **kwargs):
    try:
        from startup_check_report import observe
        reason = startup_onboarding_reason(state, **kwargs)
        if reason:
            observe("note", reason)
    except Exception:
        pass


def _server_origin(value: Any) -> tuple[str, str, int] | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if any(character.isspace() for character in value) or "\\" in value:
        return None
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
        if (scheme not in {"http", "https"} or not host
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment
                or (port is not None and not 1 <= port <= 65535)):
            return None
        return scheme, host, port if port is not None else (443 if scheme == "https" else 80)
    except ValueError:
        return None


def _install_server_origin_changed(
    paths: CurrentUserOnboardingPaths,
    credential: Mapping[str, Any] | None = None,
    *, environ: Mapping[str, str] | None = None,
) -> bool:
    # The administrator-owned intent survives completion and records the
    # installation origin. A response-supplied logistics host is not this binding.
    values = os.environ if environ is None else environ
    program_data = str(values.get("PROGRAMDATA") or "").strip()
    if not program_data:
        return False
    marker_path = Path(program_data) / "KMTech/ContainerAudit/machine-install/pending-onboarding.json"
    try:
        from logistics_runtime_profile import assert_path_has_no_reparse_components
        assert_path_has_no_reparse_components(marker_path, label="machine onboarding intent")
        if marker_path.stat().st_size > 65536:
            return False
        marker = _read_json(marker_path, "machine onboarding intent")
        if marker.get("schema") != "container-audit-machine-pending-v1" or marker.get("status") != "PENDING":
            return False
        install_root = marker.get("install_root")
        if not isinstance(install_root, str) or not Path(install_root).is_absolute():
            return False
        installed_root = _resolved(install_root)
        code_root = paths.app_root.parent
        if code_root != installed_root and not (
            code_root.parent == installed_root.parent / "versions"
        ):
            return False
        installed_origin = _server_origin(marker.get("server_base_url"))
        if installed_origin is None:
            return False
        if credential is None:
            credential = _read_json(paths.credential_path, "producer credential")
        registered_origin = _server_origin(credential.get("endpoint_url"))
        return registered_origin is not None and installed_origin != registered_origin
    except Exception:
        # Missing or unreadable historical records retain the existing decision.
        return False


def inspect_current_user_state(
    paths: CurrentUserOnboardingPaths,
    *,
    profile_loader: Callable[[Path], Any] = _default_profile_loader,
    credential_loader: Callable[[Path], Any] = load_credentials_from_json,
    prepared_credential: PreparedCredentialConfig | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    state_paths = {
        "identity": paths.identity_path,
        "producer_manifest": paths.producer_manifest_path,
        "credential": paths.credential_path,
        "registration_report": paths.registration_report_path,
        "logistics_profile": paths.logistics_profile_path,
        "logistics_secret": paths.logistics_secret_path,
    }
    present = {name: path.is_file() for name, path in state_paths.items()}
    if not any(present.values()):
        return {"status": "ABSENT", "present": present}
    if present["registration_report"] and sum(present.values()) == 1:
        report = _read_json(paths.registration_report_path, "registration report")
        if (
            str(report.get("status") or "") == ADMIN_RECOVERY_ACTION
            or str(report.get("recovery_action") or "") == ADMIN_RECOVERY_ACTION
        ):
            return {
                "status": "RECOVERY_REQUIRED",
                "present": present,
                "reason": str(report.get("blocked_reason") or "").strip()
                or "audited administrator recovery is required",
                "recovery_action": ADMIN_RECOVERY_ACTION,
                "enrollment_error_code": str(report.get("enrollment_error_code") or ""),
            }
        if str(report.get("status") or "") in {"BLOCKED", "FAILED", "UNKNOWN"}:
            return {"status": "ABSENT_RETRYABLE", "present": present}
    if not all(present.values()):
        return {
            "status": "RECOVERY_REQUIRED",
            "present": present,
            "reason": "current-user onboarding state is partial",
        }
    try:
        identity = _read_json(paths.identity_path, "producer identity")
        manifest = _read_json(paths.producer_manifest_path, "producer manifest")
        if prepared_credential is not None and prepared_credential.credential_error is not None:
            raise prepared_credential.credential_error
        credential = (dict(prepared_credential.payload) if prepared_credential is not None
                      else _read_json(paths.credential_path, "producer credential"))
        registration = _read_json(paths.registration_report_path, "registration report")
        profile_payload = _read_json(paths.logistics_profile_path, "logistics profile")
        required_identity = {
            field: str(identity.get(field) or "").strip()
            for field in ("producer_id", "source_host_id", "producer_install_id")
        }
        if not all(required_identity.values()):
            raise ValueError("producer identity is incomplete")
        from tools.register_container_audit_worker_pc import (
            _default_secret_ref,
            derive_install_bound_identity_id,
        )

        expected_source_host_id = derive_install_bound_identity_id(
            required_identity["producer_install_id"],
            purpose="source_host_id",
            prefix="container-audit-source",
        )
        expected_pc_id = derive_install_bound_identity_id(
            required_identity["producer_install_id"],
            purpose="pc_id",
            prefix="container-audit-pc",
        )
        expected_secret_ref = _default_secret_ref(
            required_identity["producer_install_id"]
        )
        if (
            required_identity["source_host_id"] != expected_source_host_id
            or required_identity["producer_id"] != expected_source_host_id
        ):
            raise CurrentUserPossessionRecoveryRequired(
                "hostname-era producer identity requires audited install-identity migration"
            )
        pc_identity = manifest.get("pc_identity")
        if not isinstance(pc_identity, Mapping):
            raise ValueError("producer manifest identity is absent")
        if (
            str(pc_identity.get("source_host_id") or "")
            != required_identity["source_host_id"]
            or str(pc_identity.get("producer_install_id") or "")
            != required_identity["producer_install_id"]
            or str(pc_identity.get("pc_id") or "") != expected_pc_id
        ):
            raise ValueError("producer identity and manifest binding differ")
        if (
            str(credential.get("producer_id") or "")
            != required_identity["producer_id"]
            or str(credential.get("secret_ref") or "") != expected_secret_ref
        ):
            raise CurrentUserPossessionRecoveryRequired(
                "producer credential requires audited install-identity migration"
            )
        expected_manifest_hash = str(registration.get("manifest_hash") or "").lower()
        if (
            registration.get("server_registration_verified") is not True
            or registration.get("manifest_hash_verified") is not True
            or registration.get("persisted_manifest_hash_verified") is not True
            or registration.get("possession_key_verified") is not True
            or registration.get("enrollment_contract_version")
            != SELF_ENROLLMENT_CONTRACT_VERSION
            or len(expected_manifest_hash) != 64
            or manifest_hash(manifest) != expected_manifest_hash
        ):
            raise ValueError("server-authorized manifest readback is incomplete")
        if str(credential.get("dpapi_scope") or "") != "current_user":
            raise ValueError("producer credential is not current-user scoped")
        if str(profile_payload.get("credential_scope") or "") != "current_user":
            raise ValueError("logistics profile is not current-user scoped")
        if _install_server_origin_changed(paths, credential, environ=environ):
            return {
                "status": "RECOVERY_REQUIRED", "present": present,
                "reason_code": INSTALL_SERVER_ORIGIN_CHANGED,
                "reason": INSTALL_SERVER_ORIGIN_MESSAGE,
            }
        resolved_credential = (credential_loader(paths.credential_path, prepared_config=prepared_credential)
                               if prepared_credential is not None else credential_loader(paths.credential_path))
        resolved_profile = profile_loader(paths.logistics_profile_path)
        possession_key = _possession_key_readback(identity)
        if resolved_credential is None or resolved_profile is None:
            raise ValueError("credential/profile readback returned no value")
        if (
            str(getattr(resolved_profile, "source_host_id", ""))
            != required_identity["source_host_id"]
        ):
            raise ValueError("logistics profile identity binding differs")
    except Exception as exc:
        result = {
            "status": "RECOVERY_REQUIRED",
            "present": present,
            "reason": str(exc),
            "error_type": exc.__class__.__name__,
        }
        if isinstance(exc, CurrentUserPossessionRecoveryRequired):
            result["recovery_action"] = ADMIN_RECOVERY_ACTION
        return result
    return {
        "status": "READY",
        "present": present,
        "source_host_id": required_identity["source_host_id"],
        "producer_install_id": required_identity["producer_install_id"],
        "manifest_hash": expected_manifest_hash,
        "possession_key": possession_key,
        "base_url": str(getattr(resolved_profile, "base_url", "") or ""),
        "tls_private_ca_configured": bool(
            getattr(resolved_profile, "tls_ca_bundle_path", "")
        ),
    }


def _configured_tls_ca_bundle_source(
    paths: CurrentUserOnboardingPaths,
    environ: Mapping[str, str] | None = None,
) -> str:
    values = os.environ if environ is None else environ
    explicit = str(values.get(ENROLLMENT_TLS_CA_BUNDLE_PATH_ENV) or "").strip()
    if explicit:
        return explicit
    if paths.bootstrap_tls_ca_bundle_path.is_file():
        return str(paths.bootstrap_tls_ca_bundle_path)
    return ""


def _registration_runner(
    paths: CurrentUserOnboardingPaths,
    *,
    server_base_url: str,
    environ: Mapping[str, str] | None = None,
    tls_ca_bundle_source: str | None = None,
) -> int:
    from tools import register_container_audit_worker_pc

    endpoint_url = f"{server_base_url.rstrip('/')}{DEFAULT_ENDPOINT_PATH}"
    tls_ca_source = (
        _configured_tls_ca_bundle_source(paths, environ)
        if tls_ca_bundle_source is None else tls_ca_bundle_source
    )
    arguments = [
        "--app-root",
        str(paths.app_root),
        "--endpoint-url",
        endpoint_url,
        "--self-enroll",
        "--require-machine-credential-bundle",
        "--credential-scope",
        "current_user",
        "--logistics-profile-path",
        str(paths.logistics_profile_path),
        "--manifest-path",
        str(paths.producer_manifest_path),
        "--credential-path",
        str(paths.credential_path),
        "--report-path",
        str(paths.registration_report_path),
    ]
    if tls_ca_source:
        arguments.extend(["--tls-ca-bundle-path", tls_ca_source])
    return int(register_container_audit_worker_pc.main(arguments))


def _create_ledger(path: Path) -> None:
    from transfer_seal import TransferSealStore

    TransferSealStore(path)


def apply_current_user_runtime_environment(
    paths: CurrentUserOnboardingPaths,
    *,
    environ: MutableMapping[str, str] | None = None,
) -> None:
    values = os.environ if environ is None else environ
    values[PROFILE_PATH_ENV] = str(paths.logistics_profile_path)
    values[REQUIRED_ENV] = "1"


def _prepare_onboarding_inputs(paths, tls_ca_source, environ, credential_loader):
    """Read-only admission shared by canonical preflight and onboarding."""
    from data_generation_guard import DataGenerationBlocked, probe_before_owner_paths, resolve_owner_path
    from protected_admin import default_protected_admin_profile_path
    from logistics_runtime_profile import assert_path_has_no_reparse_components

    try:
        if tls_ca_source:
            tls_ca_source = str(assert_path_has_no_reparse_components(
                tls_ca_source, label="TLS CA bundle source",
            ))
        admin_profile = resolve_owner_path(default_protected_admin_profile_path(environ=environ))
    except (OSError, ValueError) as exc:
        raise DataGenerationBlocked({"status": "UNKNOWN", "allowed": False}) from exc
    owner_paths = _owner_artifact_paths(paths)
    probe_before_owner_paths(paths.data_root, file_paths=(
        *owner_paths.values(), tls_ca_source, admin_profile,
    ))
    prepared_credential = None
    if credential_loader is load_credentials_from_json and paths.credential_path.is_file():
        prepared_credential = prepare_credential_config(paths.credential_path, data_root=paths.data_root)
    # Only the digest crosses the process boundary; credentials are never emitted.
    binding = hashlib.sha256(json.dumps({
        "owner_paths": {name: str(path) for name, path in owner_paths.items()},
        "tls_ca_source": tls_ca_source,
        "tls_ca_sha256": (_file_sha256(Path(tls_ca_source))
                          if tls_ca_source and Path(tls_ca_source).is_file() else None),
        "admin_profile": str(admin_profile),
        "credential": dict(prepared_credential.payload) if prepared_credential is not None else None,
        "protected_secret_path": str(prepared_credential.protected_secret_path) if prepared_credential is not None else None,
    }, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()
    return tls_ca_source, prepared_credential, binding


def _verified_onboarding_target_release(target_root):
    """Use the existing exact portable reader for the archived/restored target."""
    from tools.check_release_version import read_current_version

    root = _resolved(target_root)
    record = _read_json(root / "bootstrap-integrity.json", "target bootstrap integrity record")
    declared_root = root if record.get("code_root") == "." else _resolved(record.get("code_root") or "")
    identity = _read_replacement_tree_identity(
        root, declared_root, acl_identity_reader=None,
        _preflight_code_identity=_TARGET_PREFLIGHT_CODE_IDENTITY_ONLY,
    )
    manifest = _read_json(root / "portable-manifest.json", "target portable manifest")
    version = read_current_version(root / "app" / "Container_Audit.py")
    if manifest.get("version") != version:
        raise ValueError("target release version binding differs")
    return {"version": version, "build_id": identity["source_commit"],
            "aggregate_sha256": identity["aggregate_sha256"],
            "manifest_sha256": identity["manifest_sha256"]}


def _probe_onboarding_target_owners(release, paths, *, file_paths=(), directory_paths=()):
    from data_generation_guard import DataGenerationBlocked, marker_paths, owner_roots
    from kmtech_shared import data_generation as generation
    from tools.register_container_audit_worker_pc import _current_user_sid

    sid = _current_user_sid()
    for root in owner_roots(paths.data_root, file_paths=file_paths, directory_paths=directory_paths):
        decision = generation.probe_downgrade(
            marker_paths(root, sid), release["version"], app_id="container_audit",
            subject_sid=sid, target_build_id=release["build_id"],
        )
        if not decision["allowed"]:
            raise DataGenerationBlocked(decision)


def _rollback_preflight_owner_alive(pid):
    from ctypes import wintypes
    from writer_session_fence import WriterFencedError
    if type(pid) is not int or not 0 < pid <= 2147483647 or os.name != 'nt':
        raise WriterFencedError('ACTIVE_WRITER_FENCE', 'rollback owner identity is not proven')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return False
        raise WriterFencedError('ACTIVE_WRITER_FENCE', 'rollback owner cannot be observed')
    try:
        code = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise WriterFencedError('ACTIVE_WRITER_FENCE', 'rollback owner cannot be observed')
        return code.value == 259
    finally:
        kernel.CloseHandle(handle)


def _verified_rollback_preflight(app_root, target_root, release, journal_path, journal_sha256,
                                 fence_sha256, *, environ=None):
    """Recheck the parent's exact, protected continuation without publishing state."""
    import writer_session_fence as fence
    from tools.register_container_audit_worker_pc import _current_user_sid
    pins = []
    def deny():
        raise fence.WriterFencedError('ACTIVE_WRITER_FENCE', '끝나지 않은 되돌리기의 실행 경계가 인증 기록과 달라 변경하지 않았습니다. 자료와 복구 기록을 보존하고 관리자에게 지원 복구를 요청하세요.')
    def read_pinned(path, expected, maximum_bytes=131072):
        path = Path(path)
        if not path.is_absolute() or not re.fullmatch('[0-9a-f]{64}', str(expected)):
            deny()
        fence._assert_no_reparse_components(path)
        if fence._sha256_file_bounded(path, maximum_bytes) != expected:
            deny()
        value = _read_json(path, 'rollback preflight metadata')
        if fence._sha256_file_bounded(path, maximum_bytes) != expected:
            deny()
        pins.append((path, expected))
        return value
    try:
        journal_path = Path(journal_path)
        record = read_pinned(journal_path, journal_sha256)
        fields = {'schema','event','install_root','operator_sid','operator_local_appdata_root',
            'owner_process_id','owner_started_at_utc','session_id','attempt_id','orchestrator_sha256',
            'writer_contract_sha256','source_manifest_sha256','receipt_path','receipt_binding_path',
            'receipt_sha256','old_manifest_sha256','new_manifest_sha256','transaction_id',
            'original_audit_sha256','preimage','original_relays','relay_count','runtime_preimage_binding',
            'secret_values_recorded'}
        if (journal_path.name != 'continuation-journal.json' or
                set(record) != fields or
                journal_path.parent.name != record.get('transaction_id') or
                journal_path.parent.parent.name != 'rollback-continuations' or
                record.get('schema') != 'container-audit-rollback-continuation-v1' or
                record.get('event') != 'ROLLBACK_CONTINUATION' or
                record.get('secret_values_recorded') is not False or
                record.get('operator_sid') != _current_user_sid() or
                _resolved(record.get('operator_local_appdata_root') or '') !=
                _resolved((os.environ if environ is None else environ).get('LOCALAPPDATA') or '') or
                record.get('old_manifest_sha256') != release['manifest_sha256']):
            deny()
        if (type(record['relay_count']) is not int or record['relay_count'] not in (0,1) or
                not isinstance(record['original_relays'],list) or len(record['original_relays']) != record['relay_count'] or
                set(record['preimage']) != {'exists','kind','data'} or type(record['preimage']['exists']) is not bool or
                not all(isinstance(record['preimage'][name],str) for name in ('kind','data')) or
                record['runtime_preimage_binding'].get('status') != 'PASS' or
                record['runtime_preimage_binding'].get('relay_count') != record['relay_count'] or
                fence._parse_utc(record['owner_started_at_utc']) is None or
                any(not re.fullmatch('[0-9a-f]{64}',str(record[name])) for name in (
                    'orchestrator_sha256','writer_contract_sha256','source_manifest_sha256','receipt_sha256',
                    'old_manifest_sha256','new_manifest_sha256','original_audit_sha256'))):
            deny()
        source = _resolved(app_root).parent
        source_manifest = _read_json(source / 'portable-manifest.json', 'rollback source manifest')
        if (_file_sha256(source / 'portable-manifest.json') != record.get('source_manifest_sha256') or
                source_manifest.get('writer_session_contract_sha256') != record['writer_contract_sha256'] or
                record.get('new_manifest_sha256') != record.get('source_manifest_sha256') or
                _file_sha256(source / 'INSTALL_CANONICAL_PORTABLE.ps1') != record.get('orchestrator_sha256')):
            deny()
        receipt_path = journal_path.parent / 'replacement-receipt.json'
        if _resolved(record.get('receipt_path') or '') != receipt_path:
            deny()
        receipt = read_pinned(receipt_path, record.get('receipt_sha256'))
        binding = Path(record.get('receipt_binding_path') or '')
        if (receipt.get('transaction_id') != record.get('transaction_id') or
                receipt.get('old', {}).get('manifest_sha256') != record.get('old_manifest_sha256') or
                receipt.get('old', {}).get('source_commit') != release['build_id'] or
                receipt.get('new', {}).get('manifest_sha256') != record.get('new_manifest_sha256') or
                _resolved(receipt.get('install_root') or '') != _resolved(record.get('install_root') or '') or
                _resolved(receipt.get('receipt_path') or '') != _resolved(binding) or
                binding.name != 'replacement-receipt.json' or
                not re.fullmatch('run-[0-9a-f]{32}', binding.parent.parent.name) or
                binding.parent.parent.parent != journal_path.parent.parent.parent / 'installation-evidence'):
            deny()
        fence._assert_no_reparse_components(Path(target_root))
        if _resolved(target_root) not in {_resolved(receipt['install_root']), _resolved(receipt['rollback_root'])}:
            deny()
        read_pinned(binding, record.get('receipt_sha256'))
        active_path = fence.canonical_control_root(environ) / fence.ACTIVE_FILENAME
        read_pinned(active_path, fence_sha256)
        active = fence.active_fence(environ=environ)
        # The authenticated resume controller can hold its old continuation
        # claim during this child read. No writer authority is acquired here;
        # the original owner must still be exited and every exact pin survives.
        if (active is None or active.get('owner_kind') != 'canonical_installer' or
                active.get('status') not in ('INSTALLING', 'RESTORING', 'RESTORE_FAILED')):
            deny()
        names = ('session_id', 'attempt_id', 'orchestrator_sha256',
                 'writer_contract_sha256', 'replacement_transaction_id')
        original = {name: record.get('transaction_id' if name == 'replacement_transaction_id' else name)
                    for name in names}
        for name, value in original.items():
            if not isinstance(value, str) or not re.fullmatch(
                    '[0-9a-f]{64}' if name.endswith('sha256') else '[0-9a-f]{32}', value):
                deny()
        wanted = {name: active[name] for name in names}
        links = []
        for depth in range(129):
            if wanted == original:
                predecessor_sha = ''
                if _rollback_preflight_owner_alive(record.get('owner_process_id')):
                    deny()
                break
            if depth == 128 or not re.fullmatch('[0-9a-f]{32}', str(wanted.get('attempt_id'))):
                deny()
            path = journal_path.parent / ('authority-' + wanted['attempt_id'] + '.json')
            link_sha = fence._sha256_file_bounded(path, 131072)
            link = read_pinned(path, link_sha)
            if (set(link) != {'schema','transaction_id','journal_sha256','receipt_sha256','prepared_receipt_path',
                    'owner_process_id','owner_started_at_utc','previous','previous_link_sha256',
                    'authority','prepared_receipt_sha256','secret_values_recorded'} or
                    link.get('schema') != 'container-audit-rollback-authority-link-v1' or
                    link.get('transaction_id') != record['transaction_id'] or
                    link.get('journal_sha256') != journal_sha256 or
                    link.get('receipt_sha256') != record['receipt_sha256'] or
                    link.get('secret_values_recorded') is not False or
                    link.get('authority') != wanted or
                    set(link.get('previous', {})) != set(names) or
                    wanted['orchestrator_sha256'] != original['orchestrator_sha256'] or
                    wanted['writer_contract_sha256'] != original['writer_contract_sha256'] or
                    not re.fullmatch('[0-9a-f]{64}',str(link.get('prepared_receipt_sha256'))) or
                    fence._parse_utc(link.get('owner_started_at_utc')) is None or
                    _rollback_preflight_owner_alive(link.get('owner_process_id'))):
                deny()
            links.append((link, link_sha))
            wanted = link['previous']
        for link, link_sha in reversed(links):
            if link.get('previous_link_sha256') != predecessor_sha:
                deny()
            predecessor_sha = link_sha
        if links:
            link_path = journal_path.parent / ('authority-' + active['attempt_id'] + '.json')
            if _resolved(active['prepared_receipt_path']) == link_path:
                if active['prepared_receipt_sha256'] != links[0][1]: deny()
            else:
                authorization = read_pinned(active['prepared_receipt_path'],active['prepared_receipt_sha256'])
                if (authorization.get('schema') != 'container-audit-writer-release-authorization-v1' or
                        any(authorization.get(name) != active[name] for name in (
                            'session_id','attempt_id','replacement_transaction_id'))): deny()
                audit = read_pinned(authorization.get('install_audit_path') or '',
                    authorization.get('install_audit_sha256'),1048576)
                published = audit.get('code_replacement',{}).get('continuation_authority_link',{})
                if (_resolved(published.get('path') or '') != link_path or
                        published.get('sha256') != links[0][1]): deny()
        pins.extend([(source / 'portable-manifest.json', record['source_manifest_sha256']),
                     (source / 'INSTALL_CANONICAL_PORTABLE.ps1', record['orchestrator_sha256']),
                     (Path(target_root) / 'portable-manifest.json', release['manifest_sha256']),
                     (Path(target_root) / 'bootstrap-integrity.json',_file_sha256(Path(target_root) / 'bootstrap-integrity.json'))])
        def verify_pending():
            for path, expected in pins:
                if fence._sha256_file_bounded(path) != expected:
                    deny()
            if fence.active_fence(environ=environ) != active:
                deny()
        verify_pending()
        return verify_pending
    except fence.WriterFenceError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise fence.WriterFencedError('ACTIVE_WRITER_FENCE', 'rollback preflight binding is not proven') from exc


def preflight_current_user_onboarding(app_root, *, environ=None, target_release_root="",
        rollback_journal_path="", rollback_journal_sha256="", rollback_fence_sha256="",
        installer_source_inventory_sha256=""):
    """Admit locator and nested owners without changing installation or user state."""
    from data_generation_guard import DataGenerationBlocked
    from writer_session_fence import WriterFenceError

    paths = resolve_current_user_onboarding_paths(app_root, environ=environ)
    try:
        tls_ca_source = _configured_tls_ca_bundle_source(paths, environ)
        release = None
        if target_release_root:
            release = _verified_onboarding_target_release(target_release_root)
            from protected_admin import default_protected_admin_profile_path
            _probe_onboarding_target_owners(release, paths, file_paths=(
                *_owner_artifact_paths(paths).values(), tls_ca_source,
                default_protected_admin_profile_path(environ=environ),
            ))
        read_scope = nullcontext()
        if installer_source_inventory_sha256:
            if target_release_root or any((rollback_journal_path, rollback_journal_sha256, rollback_fence_sha256)):
                raise ValueError('installer source pin cannot authorize a restored target')
            from data_generation_guard import _readonly_installer_source
            read_scope = _readonly_installer_source(app_root, installer_source_inventory_sha256)
        if any((rollback_journal_path, rollback_journal_sha256, rollback_fence_sha256)):
            if release is None or not all((rollback_journal_path, rollback_journal_sha256, rollback_fence_sha256)):
                raise WriterFenceError('ACTIVE_WRITER_FENCE', 'rollback preflight scope is incomplete')
            from data_generation_guard import _authenticated_readonly_rollback_target
            verify_pending = _verified_rollback_preflight(app_root, target_release_root, release, rollback_journal_path,
                rollback_journal_sha256, rollback_fence_sha256, environ=environ)
            read_scope = _authenticated_readonly_rollback_target(release, verify_pending)
        with read_scope:
            inputs = _prepare_onboarding_inputs(
                paths, tls_ca_source, environ,
                load_credentials_from_json,
            )
        if release is not None and inputs[1] is not None:
            prepared = inputs[1]
            _probe_onboarding_target_owners(release, paths, file_paths=(
                prepared.protected_secret_path, prepared.payload.get("tls_ca_bundle_path"),
                prepared.payload.get("isolated_qualification_context_path"),
            ), directory_paths=((prepared.payload.get("secret_data_dir"),)
                if prepared.protected_secret_path is not None else ()))
    except WriterFenceError as exc:
        failure = CurrentUserOnboardingError(str(exc), report_path=paths.onboarding_report_path, status='FAILED')
        failure.original_error_type = type(exc).__name__
        failure.reason_code = exc.code
        raise failure from exc
    except DataGenerationBlocked as exc:
        raise CurrentUserOnboardingError(
            exc.user_message, report_path=paths.onboarding_report_path, status="FAILED",
        ) from exc
    except Exception as exc:
        from kmtech_shared import data_generation as generation
        raise CurrentUserOnboardingError(
            generation.UNKNOWN_MESSAGE, report_path=paths.onboarding_report_path, status="FAILED",
        ) from exc
    if inputs[1] is not None and inputs[1].credential_error is not None:
        raise CurrentUserOnboardingError(
            str(inputs[1].credential_error), report_path=paths.onboarding_report_path, status="BLOCKED",
        ) from inputs[1].credential_error
    if release is None:
        return inputs[2]
    input_binding = hashlib.sha256((inputs[2] + json.dumps(release, sort_keys=True)).encode("utf-8")).hexdigest()
    code_binding = hashlib.sha256((release["build_id"] + "|" + release["aggregate_sha256"]
        + "|" + release["manifest_sha256"]).encode("utf-8")).hexdigest()
    return input_binding + ":" + code_binding


_MACHINE_ONBOARDING_KEY = r"Software\KMTech\ContainerAudit\MachineOnboarding"


def _completed_machine_install_id() -> str:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _MACHINE_ONBOARDING_KEY) as key:
            value, kind = winreg.QueryValueEx(key, "CompletedInstallId")
    except FileNotFoundError:
        return ""
    if kind != winreg.REG_SZ:
        raise ValueError("machine onboarding completion type is invalid")
    return str(value)


@writer_sink("current_user_onboarding_storage")
def _record_completed_machine_install_id(install_id: str) -> None:
    import winreg

    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, _MACHINE_ONBOARDING_KEY, 0,
        winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
    ) as key:
        winreg.SetValueEx(key, "CompletedInstallId", 0, winreg.REG_SZ, install_id)
        value, kind = winreg.QueryValueEx(key, "CompletedInstallId")
    if kind != winreg.REG_SZ or value != install_id:
        raise ValueError("machine onboarding completion readback failed")


class MachineDeploymentFenced(ValueError):
    """The existing machine-placement fence already refuses onboarding."""


def machine_deployment_fence_present(marker_path):
    return (Path(marker_path).parent / "control/writer-session/active.json").exists()


def consume_pending_machine_onboarding(
    app_root: str | os.PathLike[str], *,
    environ: MutableMapping[str, str] | None = None,
    onboarder=None, sid_reader=None, completion_reader=None, completion_writer=None,
    check_target_only: bool = False,
    read_only: bool = False,
) -> dict[str, Any] | None:
    """Read machine intent; finish only this SID, once per installed identity."""
    values = os.environ if environ is None else environ
    program_data = str(values.get("PROGRAMDATA", "")).strip()
    if not program_data:
        return None
    marker_path = Path(program_data) / "KMTech/ContainerAudit/machine-install/pending-onboarding.json"
    if not marker_path.exists():
        return None
    try:
        from logistics_runtime_profile import assert_path_has_no_reparse_components
        assert_path_has_no_reparse_components(marker_path, label="machine onboarding intent")
        if machine_deployment_fence_present(marker_path):
            raise MachineDeploymentFenced("machine placement still requires recovery")
        if marker_path.stat().st_size > 65536:
            raise ValueError("machine onboarding intent is oversized")
        marker = _read_json(marker_path, "machine onboarding intent")
        if marker.get("schema") != "container-audit-machine-pending-v1" or marker.get("status") != "PENDING":
            raise ValueError("machine onboarding intent is invalid")
        if sid_reader is None:
            from tools.register_container_audit_worker_pc import _current_user_sid
            sid_reader = _current_user_sid
        if marker.get("target_sid") != sid_reader():
            raise CurrentUserOnboardingError(
                "자료를 보존하고 관리자 지원 복구를 요청하세요.",
                report_path=marker_path, status="PENDING_WORKER_SID_MISMATCH",
            )
        install_id = marker.get("install_id")
        if not isinstance(install_id, str) or re.fullmatch(r"[0-9a-f]{32}", install_id) is None:
            raise ValueError("machine onboarding installation id is invalid")
        if check_target_only:
            return {"status": "PENDING"}
        reader = completion_reader or _completed_machine_install_id
        if reader() == install_id:
            try:
                paths = resolve_current_user_onboarding_paths(app_root, environ=environ)
            except Exception:
                paths = None
            if paths is not None and _install_server_origin_changed(paths, environ=environ):
                raise CurrentUserOnboardingError(
                    INSTALL_SERVER_ORIGIN_MESSAGE, report_path=paths.onboarding_report_path,
                    status="RECOVERY_REQUIRED", reason_code=INSTALL_SERVER_ORIGIN_CHANGED,
                )
            return {"status": "READY", "action": "MACHINE_INSTALL_ALREADY_COMPLETED"}
        root = _resolved(app_root).parent
        installed_root = _resolved(marker.get("install_root", ""))
        commit = marker.get("source_commit")
        if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise ValueError("machine onboarding release identity is invalid")
        version_root = installed_root.parent / "versions" / commit
        if root not in (installed_root, version_root):
            raise ValueError("machine onboarding code root differs")
        for code_root in {installed_root, root}:
            manifest = _read_json(code_root / "portable-manifest.json", "machine onboarding manifest")
            if (commit != manifest.get("source_commit") or marker.get("version") != manifest.get("version")):
                raise ValueError("machine onboarding intent belongs to another release")
        if read_only:
            return {"status": "PENDING"}
        _observe_startup_onboarding({"status": "PENDING"}, machine=True)
        runner = onboarder or onboard_current_user
        options = {"environ": environ, "require_bootstrap_integrity": True}
        if onboarder is None:
            options["startup"] = True
        if marker.get("server_base_url"):
            options["server_base_url"] = marker["server_base_url"]
        result = runner(app_root, **options)
        if result.get("status") != "READY":
            raise ValueError("machine onboarding did not reach READY")
        # Intent is administrator-owned and remains byte-for-byte unchanged.
        (completion_writer or _record_completed_machine_install_id)(install_id)
        return result
    except CurrentUserOnboardingError:
        raise
    except Exception as exc:
        raise CurrentUserOnboardingError(
            "자료를 보존하고 관리자 지원 복구를 요청하세요.",
            report_path=marker_path, status="MACHINE_ONBOARDING_FAILED",
        ) from exc


@writer_sink("current_user_onboarding", probe_only=True)
def onboard_current_user(
    app_root: str | os.PathLike[str],
    *,
    environ: MutableMapping[str, str] | None = None,
    server_base_url: str = DEFAULT_SERVER_BASE_URL,
    require_bootstrap_integrity: bool | None = None,
    registration_runner: Callable[[CurrentUserOnboardingPaths], Any] | None = None,
    profile_loader: Callable[[Path], Any] = _default_profile_loader,
    credential_loader: Callable[[Path], Any] = load_credentials_from_json,
    ledger_factory: Callable[[Path], None] = _create_ledger,
    autostart_installer: Callable[..., Mapping[str, Any]] = install_user_relay_autostart,
    relay_launcher: Callable[..., Mapping[str, Any]] = start_user_relay_process,
    expected_input_binding: str = "",
    startup: bool = False,
) -> dict[str, Any]:
    from data_generation_guard import warm_runtime_release
    warm_runtime_release()
    from auto_update import installation_root, resolve_lifecycle_context
    managed = installation_root(Path(app_root))
    if managed is not None and any((managed / 'update-control' / name).exists() for name in ('policy.json', 'active.json', 'transition.json')):
        owner = _read_json(managed / 'current/portable-manifest.json', 'fixed owner manifest')
        pointer = _read_json(managed / 'update-control/active.json', 'active pointer')
        if pointer.get('sha') != owner.get('source_commit'):
            context = resolve_lifecycle_context(managed, operation='register', startup=startup)
            if context['status'] == 'PASS':
                app_root = context['active_app_root']
    paths = resolve_current_user_onboarding_paths(app_root, environ=environ)
    if managed is not None:
        namespaces = tuple(managed / name for name in ('current', 'versions', 'update-control', 'removal-evidence', 'removed.json'))
        if any(path_is_within(candidate, namespace) or path_is_within(namespace, candidate)
               for candidate in (paths.data_root, paths.direct_sync_root, paths.logistics_profile_path, paths.bootstrap_tls_ca_bundle_path)
               for namespace in namespaces):
            raise CurrentUserOnboardingError('자료 경로가 코드·제어·제거 증거 경로와 겹칩니다. 자료를 보존하고 별도 경로를 선택하세요.',
                                             report_path=paths.registration_report_path, status='FAILED')
    tls_ca_source = _configured_tls_ca_bundle_source(paths, environ)
    prepared_inputs = None
    if expected_input_binding:
        from data_generation_guard import DataGenerationBlocked
        try:
            prepared_inputs = _prepare_onboarding_inputs(paths, tls_ca_source, environ, credential_loader)
        except DataGenerationBlocked as exc:
            raise CurrentUserOnboardingError(
                exc.user_message, report_path=paths.onboarding_report_path, status="FAILED",
            ) from exc
        if prepared_inputs[2] != expected_input_binding:
            raise CurrentUserOnboardingError(
                "설치 전 확인한 자격 설정 경로가 바뀌었습니다. 자료를 보존하고 설치를 다시 확인하세요.",
                report_path=paths.onboarding_report_path, status="BLOCKED",
            )
    attempt = None
    require_integrity = (
        bool(getattr(sys, "frozen", False))
        if require_bootstrap_integrity is None
        else bool(require_bootstrap_integrity)
    )
    report: dict[str, Any] = {
        "report_version": ONBOARDING_REPORT_VERSION,
        "status": "UNKNOWN",
        "action": "UNKNOWN",
        "captured_at": _now(),
        "state_scope": "current_user",
        "elevation_required": False,
        "data_root": str(paths.data_root),
        "direct_sync_root": str(paths.direct_sync_root),
        "logistics_profile_path": str(paths.logistics_profile_path),
        "ledger_path": str(paths.ledger_path),
        "tls_ca_bundle_source_configured": bool(tls_ca_source),
        "server_registration_verified": False,
        "failure": "",
    }
    from data_generation_guard import DataGenerationBlocked
    try:
        with writer_admission("current_user_onboarding"):
            bootstrap_integrity_detail = verify_bootstrap_integrity(
                paths,
                required=require_integrity,
            )
            report["bootstrap_integrity"] = str(
                bootstrap_integrity_detail.get("status") or "UNKNOWN"
            ).lower()
            report["bootstrap_integrity_detail"] = bootstrap_integrity_detail
            from data_generation_guard import probe_before_owner_paths, record_before_owner_paths
            tls_ca_source, prepared_credential, _ = (prepared_inputs if prepared_inputs is not None
                else _prepare_onboarding_inputs(paths, tls_ca_source, environ, credential_loader))
            probe_before_owner_paths(paths.data_root, file_paths=_owner_artifact_paths(paths).values())
            # Preserve the canonical installer's explicit legacy-transition
            # locator when refreshing this existing installation result. The
            # retirement controller alone validates and consumes its proof.
            if paths.onboarding_report_path.is_file():
                prior = _read_json(paths.onboarding_report_path, "prior onboarding result")
                if "official_legacy_relay_transition" in prior:
                    report["official_legacy_relay_transition"] = prior["official_legacy_relay_transition"]
            attempt = RemoteAttempt.begin(paths.onboarding_report_path, "current_user_onboarding")
            for directory in (
                paths.data_root, paths.events_dir, paths.direct_sync_root,
                paths.queue_dir, paths.spool_dir, paths.status_dir, paths.logs_dir,
                paths.logistics_profile_path.parent,
            ):
                ensure_user_runtime_directory(directory)
            state = inspect_current_user_state(
                paths,
                profile_loader=profile_loader,
                credential_loader=credential_loader,
                prepared_credential=prepared_credential,
                environ=environ,
            )
            _observe_startup_onboarding(state, can_onboard=True)
            report["initial_state"] = state
            if state["status"] == "READY" and tls_ca_source:
                from tools.install_logistics_runtime_profile import (
                    install_tls_ca_bundle_for_existing_profile,
                )

                report["tls_ca_bundle_upgrade"] = (
                    install_tls_ca_bundle_for_existing_profile(
                        profile_path=paths.logistics_profile_path,
                        tls_ca_bundle_path=tls_ca_source,
                        credential_scope="current_user",
                    )
                )
                state = inspect_current_user_state(
                    paths,
                    profile_loader=profile_loader,
                    credential_loader=credential_loader,
                    prepared_credential=prepared_credential,
                    environ=environ,
                )
            if state["status"] == "RECOVERY_REQUIRED":
                if state.get("reason_code") == INSTALL_SERVER_ORIGIN_CHANGED:
                    raise CurrentUserOnboardingError(
                        INSTALL_SERVER_ORIGIN_MESSAGE, report_path=paths.onboarding_report_path,
                        status="RECOVERY_REQUIRED", reason_code=INSTALL_SERVER_ORIGIN_CHANGED,
                    )
                if state.get("recovery_action") == ADMIN_RECOVERY_ACTION:
                    raise CurrentUserOnboardingError(
                        str(
                            state.get("reason")
                            or "audited administrator recovery is required"
                        ),
                        report_path=paths.onboarding_report_path,
                        status=ADMIN_RECOVERY_ACTION,
                    )
                raise ValueError(str(state.get("reason") or "partial current-user state"))
        if state["status"] in {"ABSENT", "ABSENT_RETRYABLE"}:
            if registration_runner is None:
                return_code = _registration_runner(
                    paths,
                    server_base_url=server_base_url,
                    environ=environ,
                    tls_ca_bundle_source=tls_ca_source,
                )
            else:
                return_code = registration_runner(paths)
            if type(return_code) is not int:
                raise CurrentUserOnboardingError(
                    "registration result is UNKNOWN because no exit code was returned",
                    report_path=paths.onboarding_report_path,
                    status="UNKNOWN",
                )
            if return_code != 0:
                raise ValueError(
                    f"current-user registration failed with exit code {return_code}"
                )
            state = inspect_current_user_state(
                paths,
                profile_loader=profile_loader,
                credential_loader=credential_loader,
                prepared_credential=prepared_credential,
                environ=environ,
            )
            if state["status"] != "READY":
                raise ValueError(
                    "registration returned success without complete current-user readback"
                )
            report["action"] = "CREATED"
        else:
            report["action"] = "REUSED"
        with writer_admission("current_user_onboarding"):
            current_state = inspect_current_user_state(
                paths, profile_loader=profile_loader, credential_loader=credential_loader,
                prepared_credential=prepared_credential,
                environ=environ,
            )
            if not attempt.is_current():
                raise ValueError("a newer onboarding attempt superseded this response")
            if current_state != state:
                raise ValueError("current-user owner state changed before local onboarding apply")
            if tls_ca_source and not state.get("tls_private_ca_configured"):
                raise ValueError(
                    "configured TLS CA bundle was not persisted in the logistics profile"
                )
            # Registration preparation is read-only with respect to generation.
            # READY owner/TLS readback precedes the marker; the marker precedes
            # the first business ledger open and the public READY result.
            record_before_owner_paths(paths.data_root, file_paths=_owner_artifact_paths(paths).values())
            ledger_factory(paths.ledger_path)
            if not paths.ledger_path.is_file():
                raise ValueError("current-user business ledger readback failed")
            stop_path = user_relay_stop_path(paths.direct_sync_root)
            stop_path.unlink(missing_ok=True)
            report["relay_autostart"] = dict(autostart_installer(paths.app_root, environ=environ))
            autostart_status = str(report["relay_autostart"].get("status") or "")
            if autostart_status in {"", "UNKNOWN"}:
                raise CurrentUserOnboardingError(
                    "current-user relay autostart result is UNKNOWN",
                    report_path=paths.onboarding_report_path,
                    status="UNKNOWN",
                )
            if autostart_status != "PASS":
                raise ValueError("current-user relay autostart was not proven")
        report["relay_start"] = dict(relay_launcher(paths.app_root, environ=environ))
        relay_start_status = str(report["relay_start"].get("status") or "")
        if relay_start_status in {"", "UNKNOWN"}:
            raise CurrentUserOnboardingError(
                "current-user relay launch result is UNKNOWN",
                report_path=paths.onboarding_report_path,
                status="UNKNOWN",
            )
        deferred = (
            report["relay_start"] == {"status": "DEFERRED_CANONICAL_RELEASE", "process_id": 0}
            and installation_relay_start_deferred()
        )
        if relay_start_status != "START_REQUESTED" and not deferred:
            raise ValueError("current-user relay launch was not requested")
        with writer_admission("current_user_onboarding"):
            if not attempt.is_current():
                raise ValueError("a newer onboarding attempt superseded this response")
            if inspect_current_user_state(
                paths, profile_loader=profile_loader, credential_loader=credential_loader,
                prepared_credential=prepared_credential,
                environ=environ,
            ) != state:
                raise ValueError("current-user owner state changed before local onboarding apply")
            apply_current_user_runtime_environment(
                paths,
                environ=environ,
            )
            report.update(
                {
                    "status": "READY",
                    "state_readback": state,
                    "server_registration_verified": True,
                    "ledger_status": "READY",
                    "persistent_relay_principal": "current_user",
                    "system_scheduled_task_required": False,
                    "completed_at": _now(),
                }
            )
            _write_json_atomic(paths.onboarding_report_path, report)
            return report
    except DataGenerationBlocked as exc:
        raise CurrentUserOnboardingError(
            exc.user_message, report_path=paths.onboarding_report_path, status="FAILED",
        ) from exc
    except CurrentUserOnboardingError as exc:
        report["status"] = exc.status
        if exc.reason_code:
            report["reason_code"] = exc.reason_code
        report["error_type"] = exc.__class__.__name__
        if attempt is None:
            _persist_failure_report(paths.onboarding_report_path, report, exc)
        else:
            with attempt.apply() as current:
                if current:
                    _persist_failure_report(paths.onboarding_report_path, report, exc)
        raise
    except Exception as exc:
        report["status"] = "FAILED"
        report["error_type"] = exc.__class__.__name__
        from data_generation_guard import DataGenerationBlocked
        if isinstance(exc, DataGenerationBlocked):
            report["error_code"] = exc.decision["message_key"]
        if attempt is None:
            _persist_failure_report(paths.onboarding_report_path, report, exc)
        else:
            with attempt.apply() as current:
                if current:
                    _persist_failure_report(paths.onboarding_report_path, report, exc)
        raise CurrentUserOnboardingError(
            f"Container_Audit first-run onboarding failed: {exc}",
            report_path=paths.onboarding_report_path,
            status="FAILED",
        ) from exc


def remove_current_user_setup(
    app_root: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
    autostart_remover: Callable[[], Mapping[str, Any]] = remove_user_relay_autostart,
    relay_stopper: Callable[
        [str | os.PathLike[str]], Mapping[str, Any]
    ] = request_user_relay_stop,
) -> dict[str, Any]:
    paths = resolve_current_user_onboarding_paths(app_root, environ=environ)
    status_dir: Path = paths.status_dir
    from data_generation_guard import (
        DataGenerationBlocked, _authenticated_support_removal_source, probe_before_owner_paths,
    )
    try:
        with _authenticated_support_removal_source(app_root):
            with writer_admission("current_user_setup_removal"):
                probe_before_owner_paths(paths.data_root, file_paths=_owner_artifact_paths(paths).values(), admission_source="current_user_setup_removal")
    except DataGenerationBlocked as exc:
        raise CurrentUserOnboardingError(
            exc.user_message, report_path=paths.removal_report_path, status="FAILED",
        ) from exc
    with writer_admission("current_user_setup_removal"):
        ensure_user_runtime_directory(status_dir)
    report: dict[str, Any] = {
        "report_version": REMOVAL_REPORT_VERSION,
        "status": "UNKNOWN",
        "captured_at": _now(),
        "state_scope": "current_user",
        "data_preserved": True,
        "preserved_paths": [
            str(paths.data_root),
            str(paths.direct_sync_root),
            str(paths.logistics_profile_path.parent),
        ],
        "machine_code_root": str(paths.app_root),
        "machine_code_removal_requires_elevation": True,
        "failure": "",
    }
    try:
        with writer_admission("current_user_setup_removal"):
            report["relay_autostart"] = dict(autostart_remover())
        # The relay needs admission for its final STOPPED write before it can
        # release the runtime lease. Keep this wait outside our mutation scope.
        report["relay_process"] = dict(relay_stopper(paths.direct_sync_root))
        autostart_status = str(report["relay_autostart"].get("status") or "")
        relay_status = str(report["relay_process"].get("status") or "")
        if autostart_status in {"", "UNKNOWN"} or relay_status in {"", "UNKNOWN"}:
            raise CurrentUserOnboardingError(
                "current-user removal result is UNKNOWN",
                report_path=paths.removal_report_path,
                status="UNKNOWN",
            )
        if autostart_status != "ABSENT":
            raise ValueError("HKCU relay persistence absence was not proven")
        if relay_status != "ABSENT":
            raise ValueError("current-user relay process absence is UNKNOWN")
        report.update({"status": "PASS_DATA_PRESERVED", "completed_at": _now()})
        _write_json_atomic(paths.removal_report_path, report)
        return report
    except CurrentUserOnboardingError as exc:
        report.update(
            {
                "status": exc.status,
                "error_type": exc.__class__.__name__,
            }
        )
        _persist_failure_report(paths.removal_report_path, report, exc)
        raise
    except Exception as exc:
        report.update(
            {
                "status": "FAILED",
                "error_type": exc.__class__.__name__,
            }
        )
        _persist_failure_report(paths.removal_report_path, report, exc)
        raise CurrentUserOnboardingError(
            f"Container_Audit current-user removal failed: {exc}",
            report_path=paths.removal_report_path,
        ) from exc


@writer_sink("current_user_lifecycle_restore")
def restore_current_user_lifecycle_after_replacement(
    app_root: str | os.PathLike[str],
    *,
    code_root: str | os.PathLike[str],
    report_path: str | os.PathLike[str] | None = None,
    producer_code_root: str | os.PathLike[str] | None = None,
    session_id: str,
    attempt_id: str,
    session_started_at_utc: str,
    orchestrator_sha256: str,
    replacement_transaction_id: str,
    replacement_receipt_path: str | os.PathLike[str],
    replacement_receipt_sha256: str,
    writer_contract_sha256: str,
    environ: MutableMapping[str, str] | None = None,
    state_inspector: Callable[..., Mapping[str, Any]] = inspect_current_user_state,
    profile_loader: Callable[[Path], Any] = _default_profile_loader,
    credential_loader: Callable[[Path], Any] = load_credentials_from_json,
    code_identity_reader: Callable[[Path, Path], Mapping[str, Any]] | None = None,
    autostart_installer: Callable[..., Mapping[str, Any]] = _install_replacement_user_relay_autostart,
    autostart_remover: Callable[[], Mapping[str, Any]] = remove_user_relay_autostart,
    relay_launcher: Callable[..., Mapping[str, Any]] = _start_replacement_user_relay_process,
    relay_stopper: Callable[
        [str | os.PathLike[str]], Mapping[str, Any]
    ] = request_user_relay_stop,
    execution_context_inspector: Callable[[], Mapping[str, Any]] = (
        _inspect_current_process_execution_context
    ),
) -> dict[str, Any]:
    """Restore only lifecycle bindings for an exact, previously READY owner state.

    This path has no registration or network call and never constructs or opens the
    ledger database.  The ledger and all identity/credential artifacts are only
    hashed before and after the lifecycle actions to prove exact preservation.
    """

    paths = resolve_current_user_onboarding_paths(app_root, environ=environ)
    selected_code_root = _resolved(code_root)
    report_path = _resolved(
        report_path
        if report_path is not None
        else paths.status_dir / "replacement_lifecycle_restore.json"
    )
    if path_is_within(report_path, selected_code_root):
        raise CurrentUserOnboardingError(
            "replacement lifecycle report must be outside the mutable code root",
            report_path=report_path,
            status="FAILED",
        )
    from data_generation_guard import DataGenerationBlocked, probe_before_owner_paths, record_before_owner_paths
    try:
        from logistics_runtime_profile import assert_path_has_no_reparse_components
        try:
            receipt_path = assert_path_has_no_reparse_components(
                replacement_receipt_path, label="replacement lifecycle receipt",
            )
        except (OSError, ValueError) as exc:
            raise DataGenerationBlocked({"status": "UNKNOWN", "allowed": False}) from exc
        probe_before_owner_paths(paths.data_root, file_paths=(
            *_owner_artifact_paths(paths).values(), receipt_path, report_path,
        ))
        prepared_credential = None
        if credential_loader is load_credentials_from_json and paths.credential_path.is_file():
            prepared_credential = prepare_credential_config(paths.credential_path, data_root=paths.data_root)
        record_before_owner_paths(paths.data_root, file_paths=_owner_artifact_paths(paths).values())
    except DataGenerationBlocked as exc:
        raise CurrentUserOnboardingError(
            exc.user_message, report_path=report_path, status="FAILED",
        ) from exc
    owner_paths = _owner_artifact_paths(paths)
    if report_path == receipt_path or report_path in {
        _resolved(path) for path in owner_paths.values()
    }:
        raise CurrentUserOnboardingError(
            "replacement lifecycle report collides with protected input or owner state",
            report_path=report_path,
            status="FAILED",
        )
    if report_path.exists():
        raise CurrentUserOnboardingError(
            "replacement lifecycle report must be absent for this attempt",
            report_path=report_path,
            status="FAILED",
        )
    report: dict[str, Any] = {
        "schema": REPLACEMENT_LIFECYCLE_RESTORE_REPORT_VERSION,
        "report_version": REPLACEMENT_LIFECYCLE_RESTORE_REPORT_VERSION,
        "status": "FAILED",
        "action": "NOT_RESTORED",
        "app_id": "container_audit",
        "captured_at": _now(),
        "state_scope": "current_user",
        "registration_attempted": False,
        "network_attempted": False,
        "ledger_opened": False,
        "identity_or_credential_copied": False,
        "secret_values_recorded": False,
        "session_id": session_id,
        "attempt_id": attempt_id,
        "session_started_at_utc": session_started_at_utc,
        "orchestrator_sha256": orchestrator_sha256,
        "producer_code_root": str(
            _resolved(producer_code_root)
            if producer_code_root is not None
            else Path(__file__).resolve().parent.parent
        ),
        "replacement_transaction_id": replacement_transaction_id,
        "replacement_receipt_path": str(replacement_receipt_path),
        "replacement_receipt_sha256": replacement_receipt_sha256,
        "writer_contract_sha256": writer_contract_sha256,
        "owner_artifact_count": len(owner_paths),
        "owner_artifact_paths": {
            name: str(_resolved(path)) for name, path in owner_paths.items()
        },
        "owner_state_preserved_exact": False,
        "containment_status": "NOT_REQUIRED",
        "failure_code": "AUTHORIZATION_FAILED",
        "failure": "",
    }
    owner_before: dict[str, str] | None = None
    lifecycle_mutated = False
    failure_stage = "OWNER_ARTIFACT_READBACK"
    try:
        if not paths.status_dir.is_dir():
            raise ValueError(
                "replacement lifecycle requires existing owner status state"
            )
        owner_before = _owner_artifact_fingerprints(owner_paths)
        report["owner_artifact_fingerprints_before"] = owner_before

        failure_stage = "EXECUTION_CONTEXT"
        execution_context = dict(execution_context_inspector())
        if execution_context != {
            "status": "PASS",
            "token_elevated": False,
            "integrity_level": "MEDIUM",
        }:
            raise ValueError(
                "replacement lifecycle requires a non-elevated medium-integrity token"
            )
        report["execution_context"] = execution_context

        failure_stage = "RECEIPT_BINDING"
        if not re.fullmatch(r"[0-9a-f]{32}", session_id):
            raise ValueError("replacement lifecycle session id is invalid")
        if not re.fullmatch(r"[0-9a-f]{32}", attempt_id):
            raise ValueError("replacement lifecycle attempt id is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", orchestrator_sha256):
            raise ValueError("replacement lifecycle orchestrator SHA-256 is invalid")
        try:
            session_started = datetime.fromisoformat(
                session_started_at_utc.replace("Z", "+00:00")
            )
            if session_started.tzinfo is None:
                raise ValueError("session start has no time zone")
            session_started = session_started.astimezone(timezone.utc)
        except (TypeError, ValueError) as exc:
            raise ValueError("replacement lifecycle session start is invalid") from exc
        current_time = datetime.now(timezone.utc)
        if session_started > current_time + timedelta(
            seconds=5
        ) or session_started < current_time - timedelta(hours=24):
            raise ValueError("replacement lifecycle session is not current")
        if paths.app_root != selected_code_root / "app":
            raise ValueError("replacement lifecycle code/app root binding is invalid")
        if not re.fullmatch(r"[0-9a-f]{32}", replacement_transaction_id):
            raise ValueError("replacement lifecycle transaction id is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", replacement_receipt_sha256):
            raise ValueError("replacement lifecycle receipt SHA-256 is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", writer_contract_sha256):
            raise ValueError("replacement lifecycle writer contract SHA-256 is invalid")
        if path_is_within(receipt_path, selected_code_root.parent):
            raise ValueError("replacement lifecycle receipt readback is invalid")
        receipt = _read_pinned_json(
            receipt_path,
            "replacement lifecycle receipt",
            expected_sha256=replacement_receipt_sha256,
            maximum_bytes=131072,
        )
        report["replacement_receipt_path"] = str(receipt_path)
        if set(receipt) != _REPLACEMENT_RECEIPT_FIELDS:
            raise ValueError("replacement lifecycle receipt shape is invalid")
        parent_acl = receipt.get("parent_acl")
        if (
            not isinstance(parent_acl, Mapping)
            or set(parent_acl) not in (
                {"owner_sid", "access_rules_protected", "sddl_sha256"},
                {"owner_sid", "access_rules_protected", "sddl_sha256", "sddl"},
            )
            or not str(parent_acl.get("owner_sid") or "")
            or type(parent_acl.get("access_rules_protected")) is not bool
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                str(parent_acl.get("sddl_sha256") or ""),
            )
        ):
            raise ValueError("replacement lifecycle parent ACL receipt is invalid")
        _validate_acl_raw_binding(parent_acl, "sddl", "sddl_sha256")
        for field in ("helper_sha256", "integrity_helper_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get(field) or "")):
                raise ValueError(
                    "replacement lifecycle receipt helper identity is invalid"
                )
        old_identity = _normalized_replacement_identity(
            receipt.get("old"),
            "replacement receipt old identity",
        )
        new_identity = _normalized_replacement_identity(
            receipt.get("new"),
            "replacement receipt new identity",
        )
        install_parent = _resolved(str(receipt.get("install_parent") or ""))
        rollback_root = _resolved(str(receipt.get("rollback_root") or ""))
        failed_root = _resolved(str(receipt.get("failed_root") or ""))
        selected_producer_root = _resolved(
            producer_code_root
            if producer_code_root is not None
            else Path(__file__).resolve().parent.parent
        )
        if (
            receipt.get("schema_version") != REPLACEMENT_RECEIPT_VERSION
            or receipt.get("status") != "OLD_PRESERVED_NEW_VERIFIED"
            or receipt.get("app_id") != "container_audit"
            or receipt.get("transaction_id") != replacement_transaction_id
            or receipt.get("identity_or_credential_copied") is not False
            or _resolved(str(receipt.get("receipt_path") or "")) != receipt_path
            or _resolved(str(receipt.get("install_root") or "")) != selected_code_root
            or install_parent != selected_code_root.parent
            or rollback_root.parent != install_parent
            or rollback_root.name != f".current.rollback.{replacement_transaction_id}"
            or rollback_root.exists()
            or failed_root.parent != install_parent
            or failed_root.name != f".current.failed.{replacement_transaction_id}"
            or selected_producer_root != failed_root
        ):
            raise ValueError("replacement lifecycle receipt identity is invalid")
        _assert_tree_has_no_reparse_points(failed_root, "replacement failed-new tree")
        ambiguous_siblings = [
            candidate
            for candidate in install_parent.iterdir()
            if candidate.is_dir()
            and re.fullmatch(
                r"\.current\.(?:rollback|failed)\.[0-9a-f]{32}", candidate.name
            )
            and candidate != failed_root
        ]
        if ambiguous_siblings:
            raise ValueError("replacement lifecycle transaction siblings are ambiguous")

        failure_stage = "RESTORED_CODE_READBACK"
        identity_reader = code_identity_reader or _read_replacement_tree_identity
        restored_identity = _normalized_replacement_identity(
            identity_reader(selected_code_root, selected_code_root),
            "restored replacement code identity",
        )
        failed_new_identity = _normalized_replacement_identity(
            identity_reader(failed_root, selected_code_root),
            "failed-new replacement code identity",
        )
        if (not _replacement_identities_match(old_identity, restored_identity)
                or not _replacement_identities_match(new_identity, failed_new_identity)):
            raise ValueError(
                "replacement lifecycle trees differ from the exact receipt"
            )
        manifest_path = selected_code_root / "portable-manifest.json"
        writer_contract_path = (
            selected_code_root / "tools" / "container_writer_session_contract.json"
        )
        _require_regular_unredirected_file(
            writer_contract_path,
            "replacement writer session contract",
        )
        manifest = _read_json(manifest_path, "replacement portable manifest")
        if (
            str(manifest.get("writer_session_contract_sha256") or "")
            != writer_contract_sha256
            or _file_sha256(writer_contract_path) != writer_contract_sha256
        ):
            raise ValueError("replacement writer session contract binding differs")
        report.update(
            {
                "code_root": str(selected_code_root),
                "restored_code_identity": restored_identity,
                "failed_new_code_identity": failed_new_identity,
                "bootstrap_integrity": "PASS",
                "release_layout": "portable_runtime",
                "writer_contract_verified": True,
            }
        )

        failure_stage = "OWNER_STATE_READBACK"
        state = dict(
            state_inspector(
                paths,
                profile_loader=profile_loader,
                credential_loader=credential_loader,
                prepared_credential=prepared_credential,
            )
        )
        if state.get("status") != "READY":
            raise ValueError("replacement lifecycle restore requires exact READY state")
        possession_key = state.get("possession_key")
        report["owner_state_readback"] = {
            "status": "READY",
            "source_host_id": str(state.get("source_host_id") or ""),
            "producer_install_id": str(state.get("producer_install_id") or ""),
            "manifest_hash": str(state.get("manifest_hash") or ""),
            "possession_key_fingerprint": str(
                possession_key.get("fingerprint")
                if isinstance(possession_key, Mapping)
                else ""
            ),
        }

        failure_stage = "QUIESCENCE_RELEASE"
        stop_path = user_relay_stop_path(paths.direct_sync_root)
        _require_regular_unredirected_file(
            stop_path,
            "replacement lifecycle stop marker",
        )
        stop_path.unlink()
        lifecycle_mutated = True

        failure_stage = "RUN_RESTORE"
        autostart = dict(autostart_installer(paths.app_root, environ=environ))
        expected_autostart = {
            "status": "PASS",
            "principal": "current_user",
            "registry_hive": "HKEY_CURRENT_USER",
            "registry_key": USER_RELAY_RUN_KEY,
            "registry_value": USER_RELAY_RUN_VALUE,
            "command": _replacement_user_relay_command_line(paths.app_root, environ=environ),
        }
        if autostart != expected_autostart:
            raise ValueError(
                "replacement lifecycle HKCU relay autostart was not proven"
            )

        failure_stage = "RELAY_START"
        relay_start = dict(relay_launcher(paths.app_root, environ=environ))
        if (
            set(relay_start) != {"status", "process_id"}
            or str(relay_start.get("status") or "") != "START_REQUESTED"
            or type(relay_start.get("process_id")) is not int
            or int(relay_start["process_id"]) <= 0
        ):
            raise ValueError("replacement lifecycle relay launch was not requested")

        failure_stage = "OWNER_ARTIFACT_FINAL_READBACK"
        owner_after = _owner_artifact_fingerprints(owner_paths)
        report["owner_artifact_fingerprints_after"] = owner_after
        if owner_after != owner_before:
            raise ValueError("replacement lifecycle changed current-user owner state")
        report.update(
            {
                "status": "READY",
                "action": "REUSED",
                "completed_at": _now(),
                "failure_code": "",
                "failure": "",
                "owner_state_preserved_exact": True,
                "relay_autostart": autostart,
                "relay_start": relay_start,
                "persistent_relay_principal": "current_user",
                "system_scheduled_task_required": False,
            }
        )
        failure_stage = "REPORT_PERSISTENCE"
        _write_json_atomic_create_new(report_path, report)
        return report
    except Exception as exc:
        containment_status = "NOT_REQUIRED"
        if lifecycle_mutated:
            try:
                autostart_absent = dict(autostart_remover())
                relay_absent = dict(relay_stopper(paths.direct_sync_root))
                stop_path = user_relay_stop_path(paths.direct_sync_root)
                _require_regular_unredirected_file(
                    stop_path,
                    "replacement lifecycle containment stop marker",
                )
                if (
                    str(autostart_absent.get("status") or "") != "ABSENT"
                    or str(relay_absent.get("status") or "") != "ABSENT"
                ):
                    raise ValueError("replacement lifecycle containment is UNKNOWN")
                containment_status = "PASS_SAFE_QUIESCENT"
            except Exception:
                containment_status = "FAILED"
        owner_after: dict[str, str] | None = None
        if owner_before is not None:
            try:
                owner_after = _owner_artifact_fingerprints(owner_paths)
            except Exception:
                owner_after = None
        if owner_after is not None:
            report["owner_artifact_fingerprints_after"] = owner_after
        report.update(
            {
                "status": "FAILED",
                "action": "NOT_RESTORED",
                "failed_at": _now(),
                "failure_code": f"{failure_stage}_FAILED",
                "failure": "replacement lifecycle restore failed",
                "error_type": exc.__class__.__name__,
                "owner_state_preserved_exact": (
                    owner_before is not None and owner_after == owner_before
                ),
                "containment_status": containment_status,
            }
        )
        try:
            _persist_failure_report(report_path, report, exc, create_new=True)
        except Exception as persistence_exc:
            raise CurrentUserOnboardingError(
                "Container_Audit replacement lifecycle failure evidence could not be persisted",
                report_path=report_path,
                status="FAILED",
            ) from persistence_exc
        raise CurrentUserOnboardingError(
            "Container_Audit replacement lifecycle restore failed",
            report_path=report_path,
            status="FAILED",
        ) from exc


def _default_app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def replacement_lifecycle_restore_main(argv: list[str] | None = None) -> int:
    from auto_update import SupportArgumentParser, emit_support_record
    parser = SupportArgumentParser(
        description=(
            "Restore an exact READY Container_Audit current-user lifecycle after "
            "verified replacement rollback."
        )
    )
    parser.add_argument("--app-root", required=True)
    parser.add_argument("--code-root", required=True)
    parser.add_argument("--replacement-transaction-id", required=True)
    parser.add_argument("--replacement-receipt-path", required=True)
    parser.add_argument("--replacement-receipt-sha256", required=True)
    parser.add_argument("--writer-contract-sha256", required=True)
    parser.add_argument("--report-path")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--session-started-at-utc", required=True)
    parser.add_argument("--orchestrator-sha256", required=True)
    args = parser.parse_args(argv)
    failure_attempt = _new_failure_attempt()
    try:
        report = restore_current_user_lifecycle_after_replacement(
            args.app_root,
            code_root=args.code_root,
            report_path=args.report_path,
            session_id=args.session_id,
            attempt_id=args.attempt_id,
            session_started_at_utc=args.session_started_at_utc,
            orchestrator_sha256=args.orchestrator_sha256,
            replacement_transaction_id=args.replacement_transaction_id,
            replacement_receipt_path=args.replacement_receipt_path,
            replacement_receipt_sha256=args.replacement_receipt_sha256,
            writer_contract_sha256=args.writer_contract_sha256,
        )
    except Exception as exc:
        return emit_installer_failure(exc, "replacement_lifecycle_restore")
    finally:
        _FAILURE_ATTEMPT.reset(failure_attempt)
    print(f"replacement_lifecycle_restore_status={report['status']}")
    print(f"replacement_lifecycle_restore_action={report['action']}")
    emit_support_record({'status': report['status']}, stage='replacement_lifecycle_restore')
    return 0


def onboarding_main(argv: list[str] | None = None) -> int:
    from auto_update import SupportArgumentParser, emit_support_record
    parser = SupportArgumentParser(
        description="Onboard Container_Audit for the current user"
    )
    parser.add_argument("--app-root", default=str(_default_app_root()))
    parser.add_argument("--server-base-url", default=DEFAULT_SERVER_BASE_URL)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--installer-source-inventory-sha256", default="")
    parser.add_argument("--expected-input-binding", default="")
    parser.add_argument("--target-release-root", default="")
    parser.add_argument("--rollback-preflight-journal-path", default="")
    parser.add_argument("--rollback-preflight-journal-sha256", default="")
    parser.add_argument("--rollback-preflight-fence-sha256", default="")
    args = parser.parse_args(argv)
    failure_attempt = _new_failure_attempt()
    if args.installer_source_inventory_sha256 and not args.preflight_only:
        parser.error('installer source inventory pin is read-only preflight only')
    try:
        if args.preflight_only:
            preflight_options = {'target_release_root': args.target_release_root}
            if args.installer_source_inventory_sha256:
                preflight_options['installer_source_inventory_sha256'] = args.installer_source_inventory_sha256
            if any((args.rollback_preflight_journal_path, args.rollback_preflight_journal_sha256,
                    args.rollback_preflight_fence_sha256)):
                preflight_options.update(rollback_journal_path=args.rollback_preflight_journal_path,
                    rollback_journal_sha256=args.rollback_preflight_journal_sha256,
                    rollback_fence_sha256=args.rollback_preflight_fence_sha256)
            binding = preflight_current_user_onboarding(args.app_root, **preflight_options)
            print(f"onboarding_input_binding={binding}")
            return 0
        report = onboard_current_user(
            args.app_root,
            server_base_url=args.server_base_url,
            require_bootstrap_integrity=bool(getattr(sys, "frozen", False)),
            expected_input_binding=args.expected_input_binding,
        )
    except Exception as exc:
        return emit_installer_failure(exc, "onboarding_preflight" if args.preflight_only else "onboarding")
    finally:
        _FAILURE_ATTEMPT.reset(failure_attempt)
    print(f"onboarding_status={report['status']}")
    print(f"onboarding_action={report['action']}")
    print(f"bootstrap_integrity={report['bootstrap_integrity']}")
    emit_support_record({'status': report['status']}, stage='onboarding')
    return 0


def removal_main(argv: list[str] | None = None) -> int:
    from auto_update import SupportArgumentParser, emit_support_record
    parser = SupportArgumentParser(
        description="Remove Container_Audit current-user setup"
    )
    parser.add_argument("--app-root", default=str(_default_app_root()))
    args = parser.parse_args(argv)
    failure_attempt = _new_failure_attempt()
    try:
        report = remove_current_user_setup(args.app_root)
    except Exception as exc:
        return emit_installer_failure(exc, "current_user_removal")
    finally:
        _FAILURE_ATTEMPT.reset(failure_attempt)
    paths = resolve_current_user_onboarding_paths(args.app_root)
    print(f"current_user_removal_status={report['status']}")
    print("data_preserved=true")
    emit_support_record({'status': report['status']}, stage='current_user_removal')
    print("machine_code_removal_command=INSTALL_CANONICAL_PORTABLE.ps1 -Uninstall")
    return 0

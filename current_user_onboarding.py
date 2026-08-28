"""First-run current-user state onboarding for Container_Audit."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable, Mapping, MutableMapping
import uuid

from direct_sync_push import load_json_no_duplicate_keys, manifest_hash
from direct_sync_runtime import load_credentials_from_json
from logistics_runtime_profile import (
    PROFILE_PATH_ENV,
    REQUIRED_ENV,
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
    install_user_relay_autostart,
    remove_user_relay_autostart,
    request_user_relay_stop,
    start_user_relay_process,
    user_relay_stop_path,
)
from vendor.kmtech_zero_pe import (
    ADMIN_RECOVERY_ACTION,
    AdminRecoveryRequired as PossessionKeyAdminRecoveryRequired,
    POSSESSION_KEY_CONTRACT_VERSION,
    PersistentPossessionKey,
    SCOPE_CURRENT_USER,
)


DEFAULT_SERVER_BASE_URL = "https://worker.kmtecherp.com"
DEFAULT_ENDPOINT_PATH = "/api/producer-ingest/v1/source-file"
ONBOARDING_REPORT_VERSION = "container-audit-current-user-onboarding-v1"
REMOVAL_REPORT_VERSION = "container-audit-current-user-removal-v1"
BOOTSTRAP_INTEGRITY_VERSION = "container-audit-bootstrap-integrity-v1"
LOGISTICS_PROFILE_PATH_ENV = "CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH"
ENROLLMENT_TLS_CA_BUNDLE_PATH_ENV = (
    "CONTAINER_AUDIT_ENROLLMENT_TLS_CA_BUNDLE_PATH"
)
ONBOARDING_EXIT_CODE = 4
SELF_ENROLLMENT_CONTRACT_VERSION = "producer-self-enrollment-v2"


class CurrentUserOnboardingError(RuntimeError):
    def __init__(self, message: str, *, report_path: Path, status: str = "FAILED") -> None:
        super().__init__(message)
        self.report_path = Path(report_path)
        self.status = status


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
    explicit_data_root = str(values.get(DATA_ROOT_ENV) or "").strip()
    try:
        storage_paths = build_container_audit_storage_paths(
            application_path=str(selected_app_root),
            environ=values,
        )
        user_root = (
            storage_paths.data_root
            if explicit_data_root
            else current_user_data_home(values)
        )
    except ValueError as exc:
        safe_report_root = str(values.get("TEMP") or values.get("TMP") or "").strip()
        report_root = _resolved(safe_report_root) if safe_report_root else _resolved(Path.home() / ".kmtech")
        raise CurrentUserOnboardingError(
            str(exc),
            report_path=report_root / "container-audit-current-user-onboarding-rejected.json",
            status="FAILED",
        ) from exc
    data_root = storage_paths.data_root
    direct_sync_root = storage_paths.direct_sync_root
    if explicit_data_root:
        default_logistics_profile = (
            data_root / "logistics-profile" / "runtime-profile.json"
        )
    else:
        default_logistics_profile = (
            user_root
            / "KMTech"
            / "Logistics"
            / "profiles"
            / "Container_Audit"
            / "runtime-profile.json"
        )
    explicit_profile = str(values.get(LOGISTICS_PROFILE_PATH_ENV) or "").strip()
    if explicit_profile:
        profile_candidate = Path(explicit_profile).expanduser()
        if not profile_candidate.is_absolute():
            raise CurrentUserOnboardingError(
                f"{LOGISTICS_PROFILE_PATH_ENV} must be an absolute current-user path",
                report_path=user_root / "KMTech" / "ContainerAudit" / "current-user-onboarding-rejected.json",
                status="FAILED",
            )
        logistics_profile = _resolved(profile_candidate)
    else:
        logistics_profile = default_logistics_profile
    bootstrap_tls_ca_bundle = (
        data_root / "bootstrap" / "ca-bundle.pem"
        if explicit_data_root
        else user_root
        / "KMTech"
        / "Bootstrap"
        / "Container_Audit"
        / "ca-bundle.pem"
    )
    code_root_state_paths = (
        data_root,
        direct_sync_root,
        logistics_profile,
        bootstrap_tls_ca_bundle,
    )
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
                report_path=direct_sync_root / "status" / "current_user_onboarding.json",
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


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(dict(payload), handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
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


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_bootstrap_integrity(
    paths: CurrentUserOnboardingPaths,
    *,
    required: bool,
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
        raise ValueError("bootstrap integrity record is redirected or not a regular file")
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
            raise ValueError(f"bootstrap code file is absent or redirected: {relative_text}")
        if target.stat().st_size != expected_size or _file_sha256(target) != expected_hash:
            raise ValueError(f"bootstrap code file integrity failed: {relative_text}")
        normalized.append((expected_hash, expected_size, relative_text))
    actual_paths = set()
    for candidate in paths.app_root.rglob("*"):
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(paths.app_root).as_posix().casefold()
        if relative == paths.bootstrap_integrity_path.name.casefold():
            continue
        actual_paths.add(relative)
    if actual_paths != declared_paths:
        raise ValueError("bootstrap code inventory exact readback failed")
    aggregate_payload = "".join(
        f"{sha256} {size} {relative_path}\n"
        for sha256, size, relative_path in normalized
    ).encode("utf-8")
    aggregate = hashlib.sha256(aggregate_payload).hexdigest()
    if aggregate != str(record.get("aggregate_sha256") or "").strip().lower():
        raise ValueError("bootstrap integrity aggregate is invalid")
    main_entries = [
        item
        for item in files
        if isinstance(item, Mapping)
        and str(item.get("path") or "").replace("\\", "/").casefold()
        == "container_audit.exe".casefold()
    ]
    if len(main_entries) != 1:
        raise ValueError("bootstrap integrity record does not identify Container_Audit.exe")
    executable = paths.app_root / "Container_Audit.exe"
    if not executable.is_file():
        raise ValueError("hardened Container_Audit executable is absent")
    return {
        "status": "PASS",
        "record_path": str(paths.bootstrap_integrity_path),
        "code_root": str(paths.app_root),
        "file_count": len(files),
        "aggregate_sha256": aggregate,
    }


def _default_profile_loader(path: Path) -> Any:
    return load_logistics_runtime_profile(
        required=True,
        profile_path=path,
        decryptor=unprotect_current_user_secret,
    )


def _possession_key_readback(identity: Mapping[str, Any]) -> dict[str, Any]:
    enrollment_contract = str(
        identity.get("enrollment_contract_version") or ""
    )
    key_contract = str(
        identity.get("possession_key_contract_version") or ""
    )
    expected_fingerprint = str(
        identity.get("possession_key_fingerprint") or ""
    )
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


def inspect_current_user_state(
    paths: CurrentUserOnboardingPaths,
    *,
    profile_loader: Callable[[Path], Any] = _default_profile_loader,
    credential_loader: Callable[[Path], Any] = load_credentials_from_json,
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
            or str(report.get("recovery_action") or "")
            == ADMIN_RECOVERY_ACTION
        ):
            return {
                "status": "RECOVERY_REQUIRED",
                "present": present,
                "reason": str(report.get("blocked_reason") or "").strip()
                or "audited administrator recovery is required",
                "recovery_action": ADMIN_RECOVERY_ACTION,
                "enrollment_error_code": str(
                    report.get("enrollment_error_code") or ""
                ),
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
        credential = _read_json(paths.credential_path, "producer credential")
        registration = _read_json(paths.registration_report_path, "registration report")
        profile_payload = _read_json(paths.logistics_profile_path, "logistics profile")
        required_identity = {
            field: str(identity.get(field) or "").strip()
            for field in ("producer_id", "source_host_id", "producer_install_id")
        }
        if not all(required_identity.values()):
            raise ValueError("producer identity is incomplete")
        pc_identity = manifest.get("pc_identity")
        if not isinstance(pc_identity, Mapping):
            raise ValueError("producer manifest identity is absent")
        if (
            str(pc_identity.get("source_host_id") or "")
            != required_identity["source_host_id"]
            or str(pc_identity.get("producer_install_id") or "")
            != required_identity["producer_install_id"]
        ):
            raise ValueError("producer identity and manifest binding differ")
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
        resolved_credential = credential_loader(paths.credential_path)
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
        "tls_private_ca_configured": bool(
            getattr(resolved_profile, "tls_ca_bundle_path", "")
        ),
    }


def _configured_tls_ca_bundle_source(
    paths: CurrentUserOnboardingPaths,
    environ: Mapping[str, str] | None = None,
) -> str:
    values = os.environ if environ is None else environ
    explicit = str(
        values.get(ENROLLMENT_TLS_CA_BUNDLE_PATH_ENV) or ""
    ).strip()
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
) -> int:
    from tools import register_container_audit_worker_pc

    endpoint_url = f"{server_base_url.rstrip('/')}{DEFAULT_ENDPOINT_PATH}"
    tls_ca_source = _configured_tls_ca_bundle_source(paths, environ)
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
    values[LOGISTICS_PROFILE_PATH_ENV] = str(paths.logistics_profile_path)


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
    autostart_installer: Callable[[str | os.PathLike[str]], Mapping[str, Any]] = install_user_relay_autostart,
    relay_launcher: Callable[[str | os.PathLike[str]], Mapping[str, Any]] = start_user_relay_process,
) -> dict[str, Any]:
    paths = resolve_current_user_onboarding_paths(app_root, environ=environ)
    tls_ca_source = _configured_tls_ca_bundle_source(paths, environ)
    for directory in (
        paths.data_root,
        paths.events_dir,
        paths.direct_sync_root,
        paths.queue_dir,
        paths.spool_dir,
        paths.status_dir,
        paths.logs_dir,
        paths.logistics_profile_path.parent,
    ):
        directory.mkdir(parents=True, exist_ok=True)
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
    try:
        bootstrap_integrity_detail = verify_bootstrap_integrity(
            paths,
            required=require_integrity,
        )
        report["bootstrap_integrity"] = str(
            bootstrap_integrity_detail.get("status") or "UNKNOWN"
        ).lower()
        report["bootstrap_integrity_detail"] = bootstrap_integrity_detail
        state = inspect_current_user_state(
            paths,
            profile_loader=profile_loader,
            credential_loader=credential_loader,
        )
        report["initial_state"] = state
        if (
            state["status"] == "READY"
            and tls_ca_source
        ):
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
            )
        if state["status"] == "RECOVERY_REQUIRED":
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
                raise ValueError(f"current-user registration failed with exit code {return_code}")
            state = inspect_current_user_state(
                paths,
                profile_loader=profile_loader,
                credential_loader=credential_loader,
            )
            if state["status"] != "READY":
                raise ValueError(
                    "registration returned success without complete current-user readback"
                )
            report["action"] = "CREATED"
        else:
            report["action"] = "REUSED"
        if tls_ca_source and not state.get("tls_private_ca_configured"):
            raise ValueError(
                "configured TLS CA bundle was not persisted in the logistics profile"
            )
        ledger_factory(paths.ledger_path)
        if not paths.ledger_path.is_file():
            raise ValueError("current-user business ledger readback failed")
        stop_path = user_relay_stop_path(paths.direct_sync_root)
        stop_path.unlink(missing_ok=True)
        report["relay_autostart"] = dict(autostart_installer(paths.app_root))
        autostart_status = str(report["relay_autostart"].get("status") or "")
        if autostart_status in {"", "UNKNOWN"}:
            raise CurrentUserOnboardingError(
                "current-user relay autostart result is UNKNOWN",
                report_path=paths.onboarding_report_path,
                status="UNKNOWN",
            )
        if autostart_status != "PASS":
            raise ValueError("current-user relay autostart was not proven")
        report["relay_start"] = dict(relay_launcher(paths.app_root))
        relay_start_status = str(report["relay_start"].get("status") or "")
        if relay_start_status in {"", "UNKNOWN"}:
            raise CurrentUserOnboardingError(
                "current-user relay launch result is UNKNOWN",
                report_path=paths.onboarding_report_path,
                status="UNKNOWN",
            )
        if relay_start_status != "START_REQUESTED":
            raise ValueError("current-user relay launch was not requested")
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
    except CurrentUserOnboardingError as exc:
        report["status"] = exc.status
        report["failure"] = str(exc)
        report["error_type"] = exc.__class__.__name__
        _write_json_atomic(paths.onboarding_report_path, report)
        raise
    except Exception as exc:
        report["status"] = "FAILED"
        report["failure"] = str(exc)[:500]
        report["error_type"] = exc.__class__.__name__
        _write_json_atomic(paths.onboarding_report_path, report)
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
    relay_stopper: Callable[[str | os.PathLike[str]], Mapping[str, Any]] = request_user_relay_stop,
) -> dict[str, Any]:
    paths = resolve_current_user_onboarding_paths(app_root, environ=environ)
    paths.status_dir.mkdir(parents=True, exist_ok=True)
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
        report["relay_autostart"] = dict(autostart_remover())
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
                "failure": str(exc)[:500],
                "error_type": exc.__class__.__name__,
            }
        )
        _write_json_atomic(paths.removal_report_path, report)
        raise
    except Exception as exc:
        report.update(
            {
                "status": "FAILED",
                "failure": str(exc)[:500],
                "error_type": exc.__class__.__name__,
            }
        )
        _write_json_atomic(paths.removal_report_path, report)
        raise CurrentUserOnboardingError(
            f"Container_Audit current-user removal failed: {exc}",
            report_path=paths.removal_report_path,
        ) from exc


def _default_app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def onboarding_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Onboard Container_Audit for the current user")
    parser.add_argument("--app-root", default=str(_default_app_root()))
    parser.add_argument("--server-base-url", default=DEFAULT_SERVER_BASE_URL)
    args = parser.parse_args(argv)
    try:
        report = onboard_current_user(
            args.app_root,
            server_base_url=args.server_base_url,
            require_bootstrap_integrity=bool(getattr(sys, "frozen", False)),
        )
    except CurrentUserOnboardingError as exc:
        print(f"onboarding_status={exc.status}")
        print(f"onboarding_report={exc.report_path}")
        return ONBOARDING_EXIT_CODE
    print(f"onboarding_status={report['status']}")
    print(f"onboarding_action={report['action']}")
    print(f"bootstrap_integrity={report['bootstrap_integrity']}")
    print(f"onboarding_report={resolve_current_user_onboarding_paths(args.app_root).onboarding_report_path}")
    return 0


def removal_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Remove Container_Audit current-user setup")
    parser.add_argument("--app-root", default=str(_default_app_root()))
    args = parser.parse_args(argv)
    try:
        report = remove_current_user_setup(args.app_root)
    except CurrentUserOnboardingError as exc:
        print("current_user_removal_status=FAILED")
        print(f"current_user_removal_report={exc.report_path}")
        return ONBOARDING_EXIT_CODE
    paths = resolve_current_user_onboarding_paths(args.app_root)
    print(f"current_user_removal_status={report['status']}")
    print("data_preserved=true")
    print(f"current_user_removal_report={paths.removal_report_path}")
    print("machine_code_removal_command=INSTALL_THIS_PC.ps1 -Uninstall")
    return 0

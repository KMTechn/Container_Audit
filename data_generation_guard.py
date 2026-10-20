"""CA admission before the first user-data read; no launch-time generation claim."""
from __future__ import annotations

import json
import logging
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from contextlib import contextmanager
from contextvars import ContextVar

from kmtech_shared import data_generation as generation
from writer_session_fence import canonical_control_root, writer_sink

_READONLY_ROLLBACK_TARGET = ContextVar('container_readonly_rollback_target', default=None)
_READONLY_INSTALLER_SOURCE = ContextVar('container_readonly_installer_source', default=None)
_READONLY_STARTUP_TARGET = ContextVar('container_readonly_startup_target', default=None)
_SUPPORT_REMOVAL_RELEASE = ContextVar('container_support_removal_release', default=None)
_PORTABLE_RELEASE_CACHE = {}
logger = logging.getLogger(__name__)


@contextmanager
def _authenticated_readonly_rollback_target(release, verify_pending):
    """Only the exact continuation preflight supplies this read-only target."""
    verify_pending()
    scope = _READONLY_ROLLBACK_TARGET.set((dict(release), verify_pending))
    try:
        yield
    finally:
        _READONLY_ROLLBACK_TARGET.reset(scope)


@contextmanager
def _readonly_installer_source(app_root, expected_inventory_sha256):
    """Use the canonical caller's already admitted stock inventory, only for probes."""
    from auto_update import source_version_literal
    from current_user_onboarding import _file_sha256
    from logistics_runtime_profile import assert_path_has_no_reparse_components

    if not re.fullmatch(r'[0-9a-f]{64}', expected_inventory_sha256):
        raise ValueError('installer source inventory pin is invalid')
    app = assert_path_has_no_reparse_components(Path(app_root).absolute(), label='installer source app').resolve()
    root = app.parent
    if app.name != 'app' or not (root / 'portable-manifest.json').is_file():
        raise ValueError('installer source is not a stock packet')

    def verify_source():
        # This is the existing bootstrap Get-CodeInventory/Get-InventoryAggregate
        # protocol: ordinal UTF-16 paths; only the root installation record excluded.
        rows = []
        for path in root.rglob('*'):
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, 'st_file_attributes', 0) & 0x400:
                raise ValueError('installer source inventory is redirected')
            if stat.S_ISREG(metadata.st_mode):
                relative = path.relative_to(root).as_posix()
                if relative.casefold() != 'bootstrap-integrity.json':
                    rows.append((relative, metadata.st_size, _file_sha256(path)))
        rows.sort(key=lambda row: row[0].encode('utf-16-be'))
        aggregate = hashlib.sha256(''.join(f'{sha} {size} {path}\n' for path, size, sha in rows).encode('utf-8')).hexdigest()
        if aggregate != expected_inventory_sha256:
            raise ValueError('installer source inventory binding differs')
        return {path: (size, sha) for path, size, sha in rows}

    inventory = verify_source()
    if (root / 'portable-manifest.json').stat().st_size > 65536 or (app / 'Container_Audit.py').stat().st_size > 2097152:
        raise ValueError('installer source identity is oversized')
    manifest_bytes = (root / 'portable-manifest.json').read_bytes()
    version_bytes = (app / 'Container_Audit.py').read_bytes()
    for name, data in (('portable-manifest.json', manifest_bytes), ('app/Container_Audit.py', version_bytes)):
        if inventory.get(name) != (len(data), hashlib.sha256(data).hexdigest()):
            raise ValueError('installer source identity snapshot differs')
    manifest = json.loads(manifest_bytes)
    version = source_version_literal(version_bytes)
    if (manifest.get('schema') != 'container-audit-portable-tree-v1'
            or manifest.get('version') != version
            or not re.fullmatch(r'[0-9a-f]{40}', str(manifest.get('source_commit', '')))
            or not re.fullmatch(r'[0-9a-f]{40}', str(manifest.get('source_tree', '')))):
        raise ValueError('installer source release binding differs')
    generation.version_key(version)
    release = {'version': version, 'build_id': manifest['source_commit'],
               'data_compatible_min_version': version, 'compatibility_verified': False}
    verify_source()
    scope = _READONLY_INSTALLER_SOURCE.set((release, verify_source))
    try:
        yield
        verify_source()
    finally:
        _READONLY_INSTALLER_SOURCE.reset(scope)


@contextmanager
def _authenticated_support_removal_source(installed_app_root):
    """Bind a record-free removal packet to the verified active installed release."""
    source_app = Path(__file__).resolve().parent
    source_root = source_app.parent
    if (getattr(sys, "frozen", False) or source_app.name != "app"
            or Path(installed_app_root).resolve() == source_app
            or not (source_root / "portable-manifest.json").is_file()
            or (source_root / "bootstrap-integrity.json").exists()):
        # Installed hosts also hash their cold inventory before writer admission.
        warm_runtime_release()
        yield
        return

    from current_user_onboarding import (
        _assert_tree_has_no_reparse_points, _read_json, verify_bootstrap_integrity,
    )
    from logistics_runtime_profile import assert_path_has_no_reparse_components
    from types import SimpleNamespace

    probe_failed = False
    try:
        installed_app = assert_path_has_no_reparse_components(
            Path(installed_app_root).absolute(), label="installed removal app",
        ).resolve()
        if installed_app.name != "app":
            raise ValueError("support removal target is not a stock packet")
        installed_root = installed_app.parent
        _assert_tree_has_no_reparse_points(installed_root, "installed removal packet")
        detail = verify_bootstrap_integrity(SimpleNamespace(
            app_root=installed_root, bootstrap_integrity_path=installed_root / "bootstrap-integrity.json",
        ), required=True, expected_entrypoint="app/Container_Audit.py")
        if detail.get("status") != "PASS":
            raise ValueError("installed removal code integrity is not proven")
        records, snapshot, failed_support = [], None, False
        if installed_root.name == "current":
            from auto_update import SCHEMA, assert_failed_support_quiescent, read_json, version_bundle

            control = installed_root.parent / "update-control"
            assert_path_has_no_reparse_components(control, label="removal update control")
            records = [control / name for name in ("policy.json", "active.json", "transition.json")]
            present = [path.exists() for path in records]
            if any(present):
                if not all(present):
                    raise ValueError("removal update control is incomplete")
                snapshot = [read_json(path) for path in records]
                policy, pointer, state = snapshot
                phase, active_sha = state.get("phase"), pointer.get("sha")
                failed_support = phase == "FAILED"
                # Installation/placement DEFERRED records carry no transition ID.
                # Match lifecycle resolution's phase-specific SHA relationships.
                if (policy.get("schema") != "container-audit-startup-update-policy-v1"
                        or pointer.get("schema") != SCHEMA or state.get("schema") != SCHEMA
                        or (phase not in {"CONFIRMED", "DEFERRED", "ROLLED_BACK"} and not failed_support)
                        or (phase == "CONFIRMED" and state.get("candidate_sha") != active_sha)
                        or (phase == "ROLLED_BACK" and state.get("previous_sha") != active_sha)):
                    raise ValueError("removal active release selection differs")
                active_root = version_bundle(control, active_sha)
                _assert_tree_has_no_reparse_points(active_root, "active removal packet")
                detail = verify_bootstrap_integrity(SimpleNamespace(
                    app_root=active_root, bootstrap_integrity_path=active_root / "bootstrap-integrity.json",
                ), required=True, expected_entrypoint="app/Container_Audit.py")
                if (detail.get("status") != "PASS"
                        or read_json(active_root / "portable-manifest.json").get("source_commit") != active_sha):
                    raise ValueError("removal active code integrity is not proven")
                keys = [root / "app/update-manifest-key-config.json" for root in (installed_root, active_root)]
                if any(path.stat().st_size > 16 * 1024 for path in keys) or keys[0].read_bytes() != keys[1].read_bytes():
                    raise ValueError("removal active trust key differs")
            else:
                records = []
        # The existing source verifier binds all executing files, the manifest,
        # and its version/build to the selected bootstrap's exact inventory.
        with _readonly_installer_source(source_app, detail["aggregate_sha256"]):
            release, _ = _READONLY_INSTALLER_SOURCE.get()
            manifest = _read_json(source_root / "portable-manifest.json", "support removal manifest")
            proof = manifest.get("data_generation_signed_manifest")
            signature_hex = manifest.get("data_generation_signature_hex")
            if proof is not None or signature_hex is not None:
                if (not isinstance(proof, dict) or not isinstance(signature_hex, str)
                        or not re.fullmatch(r"[0-9a-f]{128}", signature_hex)):
                    raise ValueError("support removal signature is invalid")
                key_path = source_app / "update-manifest-key-config.json"
                if key_path.stat().st_size > 16 * 1024:
                    raise ValueError("support removal key config is oversized")
                key_config = _read_json(key_path, "support removal key config")
                if (set(key_config) != {"schema", "manifest_public_key"}
                        or key_config.get("schema") != "container-audit-update-key-config-v1"):
                    raise ValueError("support removal key config is invalid")
                verified_private_compatibility(
                    proof, bytes.fromhex(signature_hex), key_config["manifest_public_key"],
                    version=release["version"], build_id=release["build_id"],
                )
            if records and [read_json(path) for path in records] != snapshot:
                raise ValueError("removal active selection changed during verification")
            if failed_support:
                assert_failed_support_quiescent(control, policy, state)
            # Proof work and the source scope's final inventory readback stay
            # outside writer admission. Nothing is cached beyond this probe.
            scope = _SUPPORT_REMOVAL_RELEASE.set({**release, "require_existing_generation": failed_support})
            try:
                try:
                    yield
                except BaseException:
                    probe_failed = True
                    raise
            finally:
                _SUPPORT_REMOVAL_RELEASE.reset(scope)
            if failed_support:
                assert_failed_support_quiescent(control, policy, state)
        if records and [read_json(path) for path in records] != snapshot:
            raise ValueError("removal active selection changed during probe")
    except DataGenerationBlocked:
        raise
    except Exception as exc:
        if probe_failed:
            raise
        raise DataGenerationBlocked({"status": "UNKNOWN", "allowed": False,
            "message_key": "data_generation_unknown", "message": generation.UNKNOWN_MESSAGE}) from exc


class DataGenerationBlocked(RuntimeError):
    def __init__(self, decision):
        self.decision = decision
        self.private_cause = getattr(decision, "private_cause", None)
        self.user_message = (generation.REFUSAL_MESSAGE if decision.get("status") == "REFUSE"
                             else generation.UNKNOWN_MESSAGE)
        super().__init__(self.user_message)


def verified_private_compatibility(manifest, signature, public_key_config, *, version, build_id):
    """Bind the existing ES256 update proof to this running release."""
    from update_service import verified_data_compatibility_from_manifest

    if not isinstance(manifest, dict) or manifest.get("signature_version") != "es256-v1":
        raise ValueError("data compatibility requires an ES256 update manifest")
    metadata = verified_data_compatibility_from_manifest(manifest, signature, public_key_config)
    if (generation.version_key(metadata["version"]) != generation.version_key(version)
            or manifest.get("source_commit") != build_id):
        raise ValueError("data compatibility release binding differs")
    return {"version": version, "build_id": build_id,
            "data_compatible_min_version": metadata["data_compatible_min_version"],
            "compatibility_verified": "data_compatible_min_version" in manifest}


class InstalledReleaseMismatch(ValueError):
    """A completed installed-release comparison proved a mismatch."""


def _portable_runtime_release(*, app_root=None, rehash_paths=None, deadline=None):
    """Read and remember only a verified installed packet; never probe source Git."""
    from tools.check_release_version import read_current_version

    app_root = Path(__file__).resolve().parent if app_root is None else Path(app_root).absolute()
    packet_root = app_root.parent if (app_root.parent / "portable-manifest.json").is_file() else app_root
    manifest_path = packet_root / "portable-manifest.json"
    if not manifest_path.exists():
        return None
    expected_entrypoint = (app_root / "Container_Audit.py").relative_to(packet_root).as_posix()
    portable_identity = (packet_root.resolve(), app_root, expected_entrypoint)
    cached = _PORTABLE_RELEASE_CACHE.get(portable_identity) if rehash_paths is None else None
    if cached is not None:
        return dict(cached)
    version = read_current_version(app_root / "Container_Audit.py")
    from current_user_onboarding import verify_bootstrap_integrity
    from types import SimpleNamespace

    verification = ({'reuse_in_process': True} if rehash_paths is None
                    else {'rehash_paths': rehash_paths, 'deadline': deadline})
    detail = verify_bootstrap_integrity(SimpleNamespace(
        app_root=packet_root, bootstrap_integrity_path=packet_root / "bootstrap-integrity.json"), required=True,
        expected_entrypoint=expected_entrypoint, **verification)
    if detail.get("status") != "PASS":
        failure = InstalledReleaseMismatch if rehash_paths is not None else ValueError
        raise failure("release code integrity is not proven")
    if manifest_path.stat().st_size > 65536:
        raise ValueError("release manifest is oversized")
    manifest = json.loads(manifest_path.read_bytes())
    if manifest.get("version") != version:
        raise InstalledReleaseMismatch("release version binding differs")
    build = manifest.get("source_commit")
    if not isinstance(build, str) or not re.fullmatch(r"[0-9a-f]{40}", build):
        raise InstalledReleaseMismatch("release build identity is not proven")
    release = {"version": version, "build_id": build,
               "data_compatible_min_version": version, "compatibility_verified": False}
    proof = manifest.get("data_generation_signed_manifest")
    signature_hex = manifest.get("data_generation_signature_hex")
    if proof is not None or signature_hex is not None:
        try:
            if (not isinstance(proof, dict) or not isinstance(signature_hex, str)
                    or not re.fullmatch(r"[0-9a-f]{128}", signature_hex)):
                raise ValueError("data compatibility proof is invalid")
            key_path = app_root / "update-manifest-key-config.json"
            if key_path.stat().st_size > 16 * 1024:
                raise ValueError("packaged update key config is oversized")
            key_config = json.loads(key_path.read_bytes())
            if (not isinstance(key_config, dict)
                    or set(key_config) != {"schema", "manifest_public_key"}
                    or key_config.get("schema") != "container-audit-update-key-config-v1"):
                raise ValueError("packaged update key config is invalid")
            release = verified_private_compatibility(
                proof, bytes.fromhex(signature_hex), key_config["manifest_public_key"],
                version=version, build_id=build,
            )
        except Exception:
            # A bad or unavailable proof grants no compatibility permission.
            # The already verified code identity still uses its own version.
            logger.warning("Installed data compatibility proof unavailable; using release version")
    if rehash_paths is None:
        _PORTABLE_RELEASE_CACHE[portable_identity] = dict(release)
    return dict(release)


def warm_runtime_release():
    """Warm the installed packet check outside admission without source processes."""
    if getattr(sys, "frozen", False):
        return
    try:
        _portable_runtime_release()
    except Exception:
        pass


def _runtime_release():
    """Bind to the running clean source commit or the verified installed packet."""
    removal_release = _SUPPORT_REMOVAL_RELEASE.get()
    if removal_release is not None:
        return dict(removal_release)
    from tools.check_release_version import read_current_version

    if getattr(sys, "frozen", False):
        from kmtech_factory_contracts.package import verify_staged_package
        detail = verify_staged_package(Path(sys.executable).resolve().parent, release_mode=True)
        if detail.get("app_id") != "container_audit":
            raise ValueError("release application identity differs")
        version, build = detail["app_version"], detail["source_commit"]
        generation.version_key(version)
        return {"version": version, "build_id": build,
                "data_compatible_min_version": version, "compatibility_verified": False}
    app_root = Path(__file__).resolve().parent
    release = _portable_runtime_release()
    if release is not None:
        return release
    else:
        version = read_current_version(app_root / "Container_Audit.py")
        build = subprocess.check_output(
            ["git", "--no-optional-locks", "-C", str(app_root), "rev-parse", "HEAD^{commit}"], stderr=subprocess.DEVNULL, text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).strip()
        changed = subprocess.check_output(["git", "--no-optional-locks", "-C", str(app_root), "status", "--porcelain"],
                                          stderr=subprocess.DEVNULL, text=True,
                                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if changed.strip():
            raise ValueError("running source is not the release commit")
    if not isinstance(build, str) or not re.fullmatch(r"[0-9a-f]{40}", build):
        raise ValueError("release build identity is not proven")
    # This support-portable path has no verified private release declaration.
    release = {"version": version, "build_id": build,
               "data_compatible_min_version": version, "compatibility_verified": False}
    return release


def marker_paths(data_root, subject_sid, *, environ=None):
    # The shared slot is the commit point, including for external owner roots.
    # A crash before it changes must imply that no owner generation was raised.
    return (canonical_control_root(environ) / "data-generation" / (subject_sid + ".json"),
            resolve_owner_path(data_root) / "data-generation.json")


def resolve_owner_path(value):
    """Use one expansion and filesystem resolution for the guard and reader."""
    path = Path(value).expanduser().absolute()
    # Preserve uncertainty when resolving an alias would hide a reparse
    # ancestor of a structurally impossible input path.
    _owner_root_cannot_exist(path.parent)
    return path.resolve(strict=False)


def _owner_root_cannot_exist(root):
    """Only a plain file ancestor proves there can be no data or marker."""
    saw_reparse = False
    for path in (*reversed(root.parents), root):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise DataGenerationBlocked({"status": "UNKNOWN", "allowed": False}) from exc
        reparse = bool(getattr(metadata, "st_file_attributes", 0) &
                       getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)) or stat.S_ISLNK(metadata.st_mode)
        if reparse and not path.is_dir():
            raise DataGenerationBlocked({"status": "UNKNOWN", "allowed": False})
        saw_reparse |= reparse
        if stat.S_ISREG(metadata.st_mode):
            if saw_reparse:
                raise DataGenerationBlocked({"status": "UNKNOWN", "allowed": False})
            return True
    return False


def owner_roots(data_root, *, file_paths=(), directory_paths=()):
    root = resolve_owner_path(data_root)
    roots = {root}
    for value in file_paths:
        if value:
            path = resolve_owner_path(value)
            if not path.is_relative_to(root) and not _owner_root_cannot_exist(path.parent):
                roots.add(path.parent)
    for value in directory_paths:
        if value:
            original = Path(value).expanduser().absolute()
            _owner_root_cannot_exist(original)
            path = resolve_owner_path(value)
            if not path.is_relative_to(root) and not _owner_root_cannot_exist(path):
                roots.add(path)
    return sorted(roots, key=lambda path: os.path.normcase(str(path)))


def probe_before_owner_paths(data_root, *, file_paths=(), directory_paths=(), admission_source=None):
    for root in owner_roots(data_root, file_paths=file_paths, directory_paths=directory_paths):
        probe_before_data_open(root, admission_source=admission_source)


def record_before_owner_paths(data_root, *, file_paths=(), directory_paths=()):
    roots = owner_roots(data_root, file_paths=file_paths, directory_paths=directory_paths)
    # Refusal in any external owner root must precede all marker mutations.
    for root in roots:
        probe_before_data_open(root)
    for root in roots:
        record_before_data_open(root)


@writer_sink("data_generation_marker")
def record_before_data_open(data_root, *, probe_only=False):
    """Probe/record/readback under existing admission, before any DB or sidecar."""
    try:
        from tools.register_container_audit_worker_pc import _current_user_sid

        sid = _current_user_sid()
        release = _runtime_release()
        try:
            from startup_check_report import observe
            observe("release_identity", release)
        except Exception:
            pass
        # Bind to the same ambient current-user control root as writer_sink's
        # admission. An onboarding data-root override does not relocate admission.
        paths = marker_paths(data_root, sid)
        decision = generation.probe_downgrade(paths, release["version"], app_id="container_audit",
                                              subject_sid=sid, target_build_id=release["build_id"])
        if release.get("require_existing_generation") and (not decision["allowed"] or decision.get("version") is None):
            raise ValueError("failed support removal generation is not proven")
        if not decision["allowed"]:
            raise DataGenerationBlocked(decision)
        if probe_only:
            return decision
        from storage_policy import ensure_user_runtime_directory
        for path in paths:
            ensure_user_runtime_directory(path.parent)
            generation.record_generation(path, app_id="container_audit", subject_sid=sid, **release)
        return decision
    except DataGenerationBlocked:
        raise
    except Exception as exc:
        raise DataGenerationBlocked({"status": "UNKNOWN", "allowed": False,
            "message_key": "data_generation_unknown", "message": generation.UNKNOWN_MESSAGE}) from exc


@contextmanager
def _readonly_startup_probe(release, verify_snapshot):
    """Observe existing guards without admitting a writer or publishing markers."""
    verify_snapshot()
    scope = _READONLY_STARTUP_TARGET.set((dict(release), verify_snapshot))
    try:
        yield
    finally:
        _READONLY_STARTUP_TARGET.reset(scope)


def probe_before_data_open(data_root, *, admission_source=None):
    """Existing admission must cover this check and the following control read."""
    if admission_source is None:
        target = _READONLY_ROLLBACK_TARGET.get() or _READONLY_INSTALLER_SOURCE.get() or _READONLY_STARTUP_TARGET.get()
        if target is not None:
            release, verify_pending = target
            verify_pending()
            from tools.register_container_audit_worker_pc import _current_user_sid
            sid = _current_user_sid()
            decision = generation.probe_downgrade(
                marker_paths(data_root, sid), release['version'],
                app_id='container_audit', subject_sid=sid,
                target_build_id=release['build_id'],
            )
            if not decision['allowed']:
                raise DataGenerationBlocked(decision)
            return decision
        return record_before_data_open(data_root, probe_only=True)
    if admission_source != "current_user_setup_removal":
        raise ValueError("unsupported generation probe admission source")
    # Only remove_current_user_setup supplies this argument, inside its existing
    # removal admission. A static regression fixes that single call site. This
    # exact read-only body returns before mkdir or marker publication; marker
    # writes and all other probes retain their existing writer decorator.
    return record_before_data_open.__wrapped__(data_root, probe_only=True)

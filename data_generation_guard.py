"""CA admission before the first user-data read; no launch-time generation claim."""
from __future__ import annotations

import json
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


class DataGenerationBlocked(RuntimeError):
    def __init__(self, decision):
        self.decision = decision
        self.user_message = (generation.REFUSAL_MESSAGE if decision.get("status") == "REFUSE"
                             else generation.UNKNOWN_MESSAGE)
        super().__init__(self.user_message)


def _runtime_release():
    """Bind to the running clean source commit or the verified installed packet."""
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
    version = read_current_version(app_root / "Container_Audit.py")
    packet_root = app_root.parent if (app_root.parent / "portable-manifest.json").is_file() else app_root
    manifest_path = packet_root / "portable-manifest.json"
    if manifest_path.exists():
        from current_user_onboarding import verify_bootstrap_integrity
        from types import SimpleNamespace

        detail = verify_bootstrap_integrity(SimpleNamespace(
            app_root=packet_root, bootstrap_integrity_path=packet_root / "bootstrap-integrity.json"), required=True,
            expected_entrypoint=(app_root / "Container_Audit.py").relative_to(packet_root).as_posix())
        if detail.get("status") != "PASS":
            raise ValueError("release code integrity is not proven")
        if manifest_path.stat().st_size > 65536:
            raise ValueError("release manifest is oversized")
        manifest = json.loads(manifest_path.read_bytes())
        if manifest.get("version") != version:
            raise ValueError("release version binding differs")
        build = manifest.get("source_commit")
    else:
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
    return {"version": version, "build_id": build,
            "data_compatible_min_version": version, "compatibility_verified": False}


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
        # Bind to the same ambient current-user control root as writer_sink's
        # admission. An onboarding data-root override does not relocate admission.
        paths = marker_paths(data_root, sid)
        decision = generation.probe_downgrade(paths, release["version"], app_id="container_audit",
                                              subject_sid=sid, target_build_id=release["build_id"])
        if not decision["allowed"]:
            raise DataGenerationBlocked(decision)
        if probe_only:
            return decision
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            generation.record_generation(path, app_id="container_audit", subject_sid=sid, **release)
        return decision
    except DataGenerationBlocked:
        raise
    except Exception as exc:
        raise DataGenerationBlocked({"status": "UNKNOWN", "allowed": False,
            "message_key": "data_generation_unknown", "message": generation.UNKNOWN_MESSAGE}) from exc


def probe_before_data_open(data_root, *, admission_source=None):
    """Existing admission must cover this check and the following control read."""
    if admission_source is None:
        target = _READONLY_ROLLBACK_TARGET.get() or _READONLY_INSTALLER_SOURCE.get()
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

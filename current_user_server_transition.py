"""Receipt-bound fresh-server transition of the current user's CA lifecycle.

The canonical installer owns quiescence and its existing writer authority.
This module preserves state before detaching it; it never deletes old business
data, resets a queue row, or changes the shared possession key.
"""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import tempfile
import time
import uuid
from urllib.parse import urlsplit

import current_user_onboarding as onboarding
from direct_sync_push import load_json_no_duplicate_keys, manifest_hash
from logistics_runtime_profile import DEFAULT_PROFILE_RELATIVE_PATH
from storage_policy import current_user_data_home, path_is_within
from writer_session_fence import (
    _assert_no_reparse_components, active_fence, canonical_control_root,
    writer_admission, writer_sink,
)

SCHEMA = "container-audit-fresh-server-transition-v1"
INPUT_SCHEMA = "kmtech.fresh-transition.v1"
POINTER_NAME = "fresh-server-transition.json"
PHASES = ("PLANNED", "QUIESCED", "ARCHIVE_VERIFIED", "DETACHED", "REGISTERING", "REGISTERED",
          "ACTIVATION_PENDING_RELEASE", "ACTIVATED", "RESTORE_PENDING_RELEASE", "RESTORED")


def _json(path, maximum=64 * 1024):
    path = Path(path)
    _assert_no_reparse_components(path)
    if not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError("전환 기록 크기 또는 경로를 확인하세요")
    value = load_json_no_duplicate_keys(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("전환 기록은 JSON 객체여야 합니다")
    return value


def _sid():
    from tools.register_container_audit_worker_pc import _current_user_sid
    return _current_user_sid()


def _acl(path):
    """Owner/group/DACL readback, without spawning one shell per archived file."""
    if os.name != "nt":
        return oct(Path(path).stat().st_mode & 0o777)
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD)]
    descriptor = ctypes.c_void_p()
    # Match .NET Get-Acl's named-file API, including inherited ACE flags.
    error = advapi.GetNamedSecurityInfoW(str(path), 1, 7, None, None, None, None, ctypes.byref(descriptor))
    if error:
        raise ctypes.WinError(error)
    text = wintypes.LPWSTR()
    try:
        if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 7, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return text.value
    finally:
        if text:
            ctypes.windll.kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        ctypes.windll.kernel32.LocalFree(descriptor)


@writer_sink("current_user_onboarding_storage")
def _private_directory(path, sid):
    _assert_no_reparse_components(Path(path))
    Path(path).mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        Path(path).chmod(0o700)
        return
    if not re.fullmatch(r"S-1-[0-9-]+", sid):
        raise ValueError("전환 소유 SID가 올바르지 않습니다")
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        ctypes.windll.kernel32.LocalFree(descriptor)
    if "D:P" not in _acl(path):
        raise ValueError("전환 보관 폴더의 보호 ACL을 확인하지 못했습니다")


def _files(path):
    _assert_no_reparse_components(path)
    if not path.exists():
        return []
    onboarding._assert_tree_has_no_reparse_points(path, "fresh transition") if path.is_dir() else None
    files = sorted(path.rglob("*")) if path.is_dir() else [path]
    result = []
    for item in files:
        if item.is_dir():
            continue
        metadata = onboarding._require_regular_unredirected_file(item, "fresh transition")
        result.append({"relative": item.relative_to(path).as_posix() if path.is_dir() else "",
                       "bytes": metadata.st_size, "sha256": onboarding._file_sha256(item),
                       "attributes": int(getattr(metadata, "st_file_attributes", 0)), "acl": _acl(item)})
    return result


def _same_files(path, entry, *, original):
    if not path.exists() or path.is_dir() != entry["directory"]:
        return False
    if original and (_acl(path) != entry["root_acl"] or _directories(path) != entry.get("directories", [])):
        return False
    if not original:
        fields = ("relative", "attributes")
        if [{k: d[k] for k in fields} for d in _directories(path)] != [{k: d[k] for k in fields} for d in entry.get("directories", [])]:
            return False
    actual = _files(path)
    fields = ("relative", "bytes", "sha256", "attributes", "acl") if original else ("relative", "bytes", "sha256", "attributes")
    return [{k: item[k] for k in fields} for item in actual] == [{k: item[k] for k in fields} for item in entry["files"]]


def _directories(path):
    if not path.is_dir():
        return []
    onboarding._assert_tree_has_no_reparse_points(path, "fresh transition")
    return [{"relative": p.relative_to(path).as_posix(), "acl": _acl(p),
             "attributes": int(getattr(p.stat(), "st_file_attributes", 0))}
            for p in sorted(path.rglob("*")) if p.is_dir()]


@writer_sink("current_user_onboarding_storage")
def _copy_attributes(source, target):
    shutil.copystat(source, target)
    if os.name == "nt":
        from ctypes import wintypes
        set_attributes = ctypes.windll.kernel32.SetFileAttributesW
        set_attributes.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
        set_attributes.restype = wintypes.BOOL
        if not set_attributes(str(target), source.stat().st_file_attributes):
            raise ctypes.WinError()


def _require_quiesced_authority(plan):
    fence = active_fence()
    if not fence or fence["owner_kind"] != "canonical_installer" or fence["status"] != "INSTALLING":
        raise ValueError("공개 설치기의 앱·relay 정지 확인과 전환 소유권이 필요합니다")
    receipt = _json(plan["lifecycle_receipt"], maximum=1024 * 1024)
    if (receipt.get("schema") != "container-audit-canonical-portable-install-v2"
            or receipt.get("fresh_transition", {}).get("quiesced") is not True
            or receipt["fresh_transition"].get("transition_id") != plan["transition_id"]
            or receipt["fresh_transition"].get("sid") != _sid()
            or receipt["code_replacement"]["transaction_id"] != fence["replacement_transaction_id"]):
        raise ValueError("이번 전환의 정지 증명·SID·transaction이 다릅니다")
    return {"session_id": fence["session_id"], "attempt_id": fence["attempt_id"],
            "transaction_id": fence["replacement_transaction_id"]}


def _roots(paths, environ):
    home = current_user_data_home(environ)
    default_data = home / "KMTech/ContainerAudit"
    default_relay = home / "KMTech/DirectSync/container_audit"
    own_profiles = [paths.data_root / "logistics-profile", home / "KMTech/Logistics/profiles/Container_Audit"]
    profile_inputs = [paths.logistics_profile_path.parent] if paths.logistics_profile_path.parent in own_profiles else []
    roots = [paths.data_root, paths.direct_sync_root, default_data, default_relay,
             *profile_inputs, home / "KMTech/Logistics/profiles/Container_Audit",
             paths.bootstrap_tls_ca_bundle_path.parent,
             Path(environ.get("PROGRAMDATA", r"C:\ProgramData")) / DEFAULT_PROFILE_RELATIVE_PATH.parent,
             Path(environ.get("PROGRAMDATA", r"C:\ProgramData")) / "KMTech/DirectSync/container_audit"]
    # Manifest paths are consumers too, including pre-canonical split roots.
    for manifest_path in (paths.producer_manifest_path, default_relay / "producer_manifest.json"):
        if not manifest_path.is_file():
            continue
        try:
            manifest = _json(manifest_path)
        except ValueError:
            continue  # Preserved as UNKNOWN below; never used to invent paths.
        sync = manifest.get("sync") or {}
        queue = sync.get("queue") or {}
        for candidate in (sync.get("sync_dir"), queue.get("queue_dir"), queue.get("client_state_db"),
                          *(manifest.get("paths") or {}).values()):
            if isinstance(candidate, str) and candidate:
                path = Path(candidate)
                if not path.is_absolute() or path == Path(path.anchor):
                    raise ValueError("옛 manifest의 소비 경로를 확인하세요")
                roots.append(path)
                if path.suffix.lower() in {".db", ".sqlite3"}:
                    roots.extend(Path(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal"))
    for credential_path in (paths.credential_path, default_relay / "credential.json"):
        if credential_path.is_file():
            try:
                credential = _json(credential_path)
                reference = str(credential.get("secret_ref") or "")
                if reference.startswith("dpapi:") and credential.get("secret_data_dir"):
                    from direct_sync_runtime import _safe_secret_ref_name

                    base = Path(credential["secret_data_dir"])
                    if not base.is_absolute():
                        raise ValueError("옛 credential의 외부 저장 경로가 올바르지 않습니다")
                    roots.append(base / "secrets" / (_safe_secret_ref_name(reference.split(":", 1)[1]) + ".dpapi"))
            except (ValueError, KeyError):
                pass  # Its unparseable bytes remain in the archived app root.
    unique = sorted(set(p.resolve() for p in roots), key=lambda p: (len(p.parts), str(p).casefold()))
    return [p for i, p in enumerate(unique) if not any(path_is_within(p, other) for other in unique[:i])]


@writer_sink("current_user_onboarding_storage")
def _work_observation(entries):
    result = {"pending": 0, "unknown": 0, "held_files": 0, "incomplete": 0,
              "unresolved_files": 0, "details": []}
    for entry in entries:
        for item in entry["files"]:
            path = Path(entry["source"]) / item["relative"] if entry["directory"] else Path(entry["source"])
            lower = str(path).lower()
            if path.suffix.lower() in {".db", ".sqlite3"}:
                row = {"path": str(path), "pending": 0, "unknown": 0, "incomplete": 0}
                # Never open a source DB: even a read-only WAL reader can create
                # or change its SHM. Inspect only these disposable exact copies.
                with tempfile.TemporaryDirectory(prefix="ca-fresh-count-") as scratch:
                    copy = Path(scratch) / path.name
                    for suffix in ("", "-wal", "-shm", "-journal"):
                        source = Path(str(path) + suffix)
                        if source.is_file():
                            _assert_no_reparse_components(source)
                            shutil.copy2(source, Path(str(copy) + suffix))
                    conn = None
                    try:
                        conn = sqlite3.connect(copy.as_uri() + "?mode=ro", uri=True)
                        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                        for table in ("direct_sync_relay_batches", "transfer_seal_intents", "transfer_member_exchange_intents"):
                            if table not in tables:
                                continue
                            for status, count in conn.execute(f'SELECT status, COUNT(*) FROM "{table}" GROUP BY status'):
                                if str(status).upper() in {"ACKED", "COMPLETE", "COMPLETED"}:
                                    continue
                                field = "pending" if table == "direct_sync_relay_batches" else "incomplete"
                                row[field] += count
                                if str(status).upper() in {"UNKNOWN", "OPERATOR_REVIEW", "LEASED", "UPLOADING"}:
                                    row["unknown"] += count
                        if not tables.intersection({"direct_sync_relay_batches", "transfer_seal_intents", "transfer_member_exchange_intents"}):
                            row["unknown"] += 1
                    except sqlite3.DatabaseError:
                        row["unknown"] += 1
                    finally:
                        if conn is not None:
                            conn.close()
                result["details"].append(row)
                for field in ("pending", "unknown", "incomplete"):
                    result[field] += row[field]
                if any(row[k] for k in ("pending", "unknown", "incomplete")):
                    result["unresolved_files"] += 1
            elif path.suffix.lower() == ".csv" or "current_tray" in lower or "parked" in lower or "quarantine" in lower:
                # A CSV/session alone does not prove central acknowledgment.
                result["unknown"] += 1
                result["unresolved_files"] += 1
                result["held_files"] += int("parked" in lower or "quarantine" in lower)
                result["details"].append({"path": str(path), "status": "ACK_UNKNOWN_FILE_PRESERVED"})
    return result


def plan_archive(app_root, *, archive_root, transition_id, environ=None, preserve_active_removal=False):
    _require_no_machine_environment()
    values = os.environ if environ is None else environ
    if not re.fullmatch(r"[0-9a-f]{32}", transition_id):
        raise ValueError("전환 ID가 올바르지 않습니다")
    paths = onboarding.resolve_current_user_onboarding_paths(app_root, environ=values)
    archive_root = Path(archive_root)
    if not archive_root.is_absolute() or str(archive_root).startswith(("\\\\", "//")):
        raise ValueError("보관 위치는 별도 로컬 보존 폴더여야 합니다")
    _assert_no_reparse_components(archive_root)
    archive_root = archive_root.resolve()
    if archive_root == Path(archive_root.anchor):
        raise ValueError("보관 위치는 별도 로컬 보존 폴더여야 합니다")
    if os.name == "nt":
        from ctypes import wintypes
        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        get_drive_type.argtypes = [wintypes.LPCWSTR]
        get_drive_type.restype = wintypes.UINT
        # A mapped network drive also has a drive letter; only persistent local
        # fixed/removable volumes satisfy the preservation contract.
        if get_drive_type(archive_root.anchor) not in (2, 3):
            raise ValueError("보관 위치는 별도 로컬 보존 볼륨이어야 합니다")
    roots = _roots(paths, values)
    code_roots = [paths.app_root]
    if (paths.app_root.parent / "portable-manifest.json").is_file():
        code_roots.append(paths.app_root.parent)
    for root in [*roots, *code_roots]:
        if path_is_within(archive_root, root) or path_is_within(root, archive_root):
            raise ValueError("보관 위치가 코드·소비 경로와 겹칩니다")
    for root in roots:
        if path_is_within(paths.app_root, root) or path_is_within(root, paths.app_root):
            raise ValueError("옛 소비 경로가 코드 루트와 겹칩니다")
        _assert_no_reparse_components(root)
    _assert_no_reparse_components(archive_root)
    home = current_user_data_home(values)
    # Keep current control, the two-root retirement evidence, and the installer's
    # own audit/prepared/release receipts outside the moving set.
    preserve = [paths.direct_sync_root / "control", home / "KMTech/DirectSync/container_audit/control",
                paths.data_root / "install-audit", home / "KMTech/ContainerAudit/install-audit",
                paths.removal_report_path, home / "KMTech/DirectSync/container_audit/status/current_user_removal.json"]
    selected = []

    def select(path):
        if not path.exists() or any(path_is_within(path, p) for p in preserve):
            return
        if any(path_is_within(p, path) for p in preserve):
            for child in sorted(path.iterdir()):
                select(child)
        else:
            selected.append(path)

    for root in roots:
        select(root)
    entries = []
    machine_profile_root = (Path(values.get("PROGRAMDATA", r"C:\ProgramData")) / DEFAULT_PROFILE_RELATIVE_PATH.parent).resolve()
    machine_relay_root = (Path(values.get("PROGRAMDATA", r"C:\ProgramData")) / "KMTech/DirectSync/container_audit").resolve()
    for index, path in enumerate(selected):
        inactive = path.with_name(f".{path.name}.fresh-{transition_id}")
        # Whole roots are detached beside their original parent, never under a
        # directory traversed by an events/queue/parked consumer.
        entries.append({"source": str(path), "archive": str(archive_root / "original" / str(index)),
                        "inactive": str(inactive), "directory": path.is_dir(), "files": _files(path),
                        "directories": _directories(path),
                        "root_acl": _acl(path), "detached": False,
                        "machine_state": path in {machine_profile_root, machine_relay_root},
                        "machine_profile": path == machine_profile_root})
    from logistics_runtime_profile import PROFILE_PATH_ENV, _machine_environment_value, _resolve_secret_path, _resolve_tls_ca_bundle_path

    shared_profiles = [paths.logistics_profile_path]
    machine_binding = _machine_environment_value(PROFILE_PATH_ENV)
    if machine_binding:
        shared_profiles.append(Path(machine_binding))
    process_binding = values.get(PROFILE_PATH_ENV)
    if process_binding:
        shared_profiles.append(Path(process_binding))
    shared_inputs = []
    for profile in shared_profiles:
        profile = profile.resolve()
        if any(path_is_within(profile, root) for root in roots) or not profile.is_file():
            continue
        shared_inputs.append(profile)
        payload = _json(profile)
        if payload.get("bearer_token_ref"):
            shared_inputs.append(_resolve_secret_path(profile, payload["bearer_token_ref"]))
        if payload.get("tls_ca_bundle_path"):
            shared_inputs.append(Path(_resolve_tls_ca_bundle_path(profile, payload["tls_ca_bundle_path"])))
    for path in sorted(set(shared_inputs)):
        if path_is_within(archive_root, path.parent) or path_is_within(path, archive_root):
            raise ValueError("공유 profile과 보관 위치가 겹칩니다")
        entries.append({"source": str(path), "archive": str(archive_root / "original" / str(len(entries))),
                        "inactive": "", "directory": False, "files": _files(path), "root_acl": _acl(path),
                        "directories": [],
                        "detached": False, "shared_read_only": True, "machine_profile": False})
    # A supported old removal is also a valid starting state. Keep its marker
    # in place until new activation; preserve its exact bytes independently of
    # the immutable two-root retirement evidence and the live writer control.
    historical_controls = ([paths.removal_report_path,
        paths.direct_sync_root / "control/container_audit_user_relay.stop.json"] if preserve_active_removal else [])
    if paths.direct_sync_root != home / "KMTech/DirectSync/container_audit":
        historical_controls.extend([home / "KMTech/DirectSync/container_audit/status/current_user_removal.json",
            home / "KMTech/DirectSync/container_audit/control/container_audit_user_relay.stop.json"])
    for path in sorted(set(historical_controls)):
        if path.is_file():
            entries.append({"source": str(path), "archive": str(archive_root / "original" / str(len(entries))),
                "inactive": "", "directory": False, "files": _files(path), "directories": [], "root_acl": _acl(path),
                "detached": False, "shared_read_only": True, "historical_control": True, "machine_profile": False})
    explicit_data = paths.direct_sync_root == paths.data_root / "direct_sync"
    new_profile = (paths.data_root / "logistics-profile/runtime-profile.json" if explicit_data else
                   home / "KMTech/Logistics/profiles/Container_Audit/runtime-profile.json")
    return {"schema": SCHEMA, "transition_id": transition_id, "phase": "PLANNED", "sid": _sid(),
            "pc": os.environ.get("COMPUTERNAME") or socket.gethostname(), "app_root": str(paths.app_root),
            "data_root": str(paths.data_root), "direct_sync_root": str(paths.direct_sync_root),
            "profile_path": str(new_profile), "old_profile_path": str(paths.logistics_profile_path), "archive_root": str(archive_root),
            "roots": [str(p) for p in roots], "preserved": [str(p) for p in preserve], "entries": entries,
            "bytes": sum(item["bytes"] for entry in entries for item in entry["files"]),
            "work_observation": _work_observation(entries),
            "attempts": [], "created_at": onboarding._now()}


@writer_sink("current_user_onboarding_storage")
def _copy_entry(entry):
    source, target = Path(entry["source"]), Path(entry["archive"])
    if not _same_files(source, entry, original=True):
        raise ValueError("보관 전 원본이 변경됐습니다")
    if entry["directory"]:
        target.mkdir(parents=True, exist_ok=True)
        for directory in entry.get("directories", []):
            (target / directory["relative"]).mkdir(parents=True, exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
    for item in entry["files"]:
        old = source / item["relative"] if entry["directory"] else source
        new = target / item["relative"] if entry["directory"] else target
        new.parent.mkdir(parents=True, exist_ok=True)
        if new.exists():
            if new.stat().st_size == item["bytes"] and onboarding._file_sha256(new) == item["sha256"]:
                continue
            raise ValueError("보관 사본이 원본과 다릅니다; 기존 시도는 보존합니다")
        staging = target.parent / "copy-attempts"
        staging.mkdir(parents=True, exist_ok=True)
        temporary = staging / uuid.uuid4().hex
        with old.open("rb") as reader, temporary.open("xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
        _copy_attributes(old, temporary)
        temporary.rename(new)
    for directory in reversed(entry.get("directories", [])):
        _copy_attributes(source / directory["relative"], target / directory["relative"])
    if not _same_files(target, entry, original=False):
        raise ValueError("보관 사본 바이트·속성 대조 실패")


def _journal_path(plan):
    return Path(plan["archive_root"]) / "transition-journal.json"


@writer_sink("current_user_onboarding_storage")
def _save(plan):
    onboarding._write_json_atomic(_journal_path(plan), plan)
    public = {key: plan[key] for key in ("schema", "transition_id", "phase", "archive_root", "pc", "sid", "work_observation")}
    public.update(updated_at=onboarding._now(), restore_available=plan["phase"] in PHASES[:4],
                  next_action="다시 확인 / 이어서 등록 / 가능한 경우 복원",
                  original_credentials_uploaded=False)
    if plan["phase"] in {"REGISTERING", "REGISTERED", "ACTIVATION_PENDING_RELEASE", "ACTIVATED"}:
        public["administrator_message"] = "새 서버 등록이 시작됐을 수 있어 되돌릴 수 없음 — 관리자 지원 필요"
    public["attempts"] = [{k: attempt[k] for k in ("stage", "status", "started_at", "error_type") if k in attempt}
                          for attempt in plan["attempts"]]
    onboarding._write_json_atomic(Path(plan["archive_root"]) / "transition-result.json", public)


@writer_sink("current_user_onboarding")
def archive_state(plan, *, confirm_pending=False):
    owner = _require_quiesced_authority(plan)
    if plan["sid"] != _sid():
        raise ValueError("전환 소유 SID가 다릅니다")
    if plan["work_observation"]["unresolved_files"] and not confirm_pending:
        raise ValueError("미전송·UNKNOWN·보류 원본을 보관만 하고 새 서버에 보내지 않는다는 별도 확인이 필요합니다")
    root = Path(plan["archive_root"])
    _private_directory(root, plan["sid"])
    if _journal_path(plan).exists():
        saved = _json(_journal_path(plan), maximum=32 * 1024 * 1024)
        for key in ("transition_id", "sid", "app_root", "data_root", "direct_sync_root", "profile_path", "archive_root", "target"):
            if saved.get(key) != plan.get(key):
                raise ValueError("기존 전환의 소유·대상·경로가 다릅니다")
        plan = saved
    plan["attempts"].append({"owner": owner, "started_at": onboarding._now(), "status": "UNKNOWN"})
    try:
        if plan["phase"] == "PLANNED":
            plan["phase"] = "QUIESCED"
        _save(plan)
        if plan["phase"] == "QUIESCED":
            plan["machine_pending"] = False
            for entry in plan["entries"]:
                if entry.get("machine_state") and plan.get("defer_machine"):
                    if not Path(entry["inactive"]).exists():
                        plan["machine_pending"] = True
                        continue
                    if not _same_files(Path(entry["inactive"]), entry, original=True) or not _same_files(Path(entry["archive"]), entry, original=False):
                        raise ValueError("승격 helper의 machine 원본·보관 사본 대조 실패")
                    continue
                _copy_entry(entry)
            if plan["machine_pending"]:
                _save(plan)
                return plan  # Elevation owns machine copies and the rename.
            plan["phase"] = "ARCHIVE_VERIFIED"
            _save(plan)
        if plan["phase"] == "ARCHIVE_VERIFIED":
            plan["machine_pending"] = False
            for entry in plan["entries"]:
                if entry.get("shared_read_only"):
                    if not _same_files(Path(entry["source"]), entry, original=True):
                        raise ValueError("다른 앱과 공유하는 profile이 변경됐습니다")
                    continue
                source, inactive, archive = (Path(entry[k]) for k in ("source", "inactive", "archive"))
                if not _same_files(archive, entry, original=False):
                    raise ValueError("분리 전 보관 사본이 변경됐습니다")
                if inactive.exists():
                    if source.exists() or not _same_files(inactive, entry, original=True):
                        raise ValueError("중단된 분리의 원본 위치·바이트가 다릅니다")
                else:
                    if entry["detached"] or not _same_files(source, entry, original=True):
                        raise ValueError("분리 원본이 없거나 변경됐습니다")
                    if entry.get("machine_state") and plan.get("defer_machine"):
                        plan["machine_pending"] = True
                        continue
                    source.rename(inactive)
                if source.exists() or not _same_files(inactive, entry, original=True) or _acl(inactive) != entry["root_acl"]:
                    raise ValueError("원본 비활성 분리 readback 실패")
                entry["detached"] = True
                _save(plan)
            if not plan["machine_pending"]:
                plan["phase"] = "DETACHED"
        plan["attempts"][-1]["status"] = "PASS"
        _save(plan)
        return plan
    except Exception as exc:
        plan["attempts"][-1].update(status="UNKNOWN", error_type=type(exc).__name__)
        _save(plan)
        raise


def read_target(path, *, packet_root):
    _private_input(Path(path))
    target = _json(path)
    if set(target) != {"schema", "origin", "scope", "deployment_id", "packet", "pc", "sid", "acceptance"} or target["schema"] != INPUT_SCHEMA:
        raise ValueError("공통 전환 입력 v1 필드가 다릅니다")
    for key in ("origin", "scope", "deployment_id", "packet", "pc", "sid"):
        if not isinstance(target[key], str) or not target[key] or any(ord(c) < 32 for c in target[key]):
            raise ValueError("공통 전환 입력 값이 올바르지 않습니다")
    parsed = urlsplit(target["origin"])
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or any(c.isspace() for c in target["origin"])
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or "\\" in target["origin"]):
        raise ValueError("새 서버는 HTTPS origin이어야 합니다")
    target["origin"] = target["origin"].rstrip("/")
    if not target["deployment_id"].startswith("/"):
        raise ValueError("새 서버 deployment_id는 절대 설치 root여야 합니다")
    if not re.fullmatch(r"[0-9a-f]{64}", target["packet"]) or onboarding._file_sha256(Path(packet_root) / "portable-manifest.json") != target["packet"]:
        raise ValueError("전환 입력과 배포 packet이 다릅니다")
    if target["sid"] != _sid() or target["pc"].casefold() != (os.environ.get("COMPUTERNAME") or socket.gethostname()).casefold():
        raise ValueError("전환 입력과 현재 PC·SID가 다릅니다")
    acceptance = target["acceptance"]
    if not isinstance(acceptance, dict) or set(acceptance) != {"record_path", "record_sha256", "source_commit", "accepted_by"}:
        raise ValueError("새 서버 수용 기록 필드가 다릅니다")
    if (not isinstance(acceptance["accepted_by"], str) or not acceptance["accepted_by"].strip()
            or not re.fullmatch(r"[0-9a-f]{40}", str(acceptance["source_commit"]))
            or not re.fullmatch(r"[0-9a-f]{64}", str(acceptance["record_sha256"]))
            or not Path(acceptance["record_path"]).is_absolute()):
        raise ValueError("새 서버 수용 기록 결속이 올바르지 않습니다")
    _private_input(Path(acceptance["record_path"]))
    record = onboarding._read_pinned_json(Path(acceptance["record_path"]), "fresh server acceptance",
                                         expected_sha256=acceptance["record_sha256"], maximum_bytes=64 * 1024)
    if (record.get("phase") != "ACCEPTED" or record.get("ready") is not True
            or record.get("client_writes_blocked") is not False or record.get("snapshot_rollback_allowed") is not False
            or record.get("source_commit") != acceptance["source_commit"]):
        raise ValueError("새 서버 수용 완료를 확인하지 못했습니다")
    return target


def _private_input(path):
    _assert_no_reparse_components(path)
    if os.name != "nt":
        if path.stat().st_mode & 0o077:
            raise ValueError("전환 입력은 원 사용자·SYSTEM·관리자만 읽을 수 있어야 합니다")
        return
    allowed = {_sid(), "SY", "BA", "S-1-5-18", "S-1-5-32-544"}
    descriptor = _acl(path)
    if "D:" not in descriptor or "NO_ACCESS_CONTROL" in descriptor:
        raise ValueError("전환 입력에 보호 DACL이 필요합니다")
    for ace in re.findall(r"\(([^)]+)\)", descriptor):
        fields = ace.split(";")
        if fields[0] not in {"D", "OD"} and fields[-1] not in allowed:
            raise ValueError("전환 입력은 원 사용자·SYSTEM·관리자만 읽을 수 있어야 합니다")


def _require_no_machine_environment():
    from logistics_runtime_profile import _machine_environment_value, PROFILE_PATH_ENV, REQUIRED_ENV

    if any(_machine_environment_value(name) for name in (PROFILE_PATH_ENV, REQUIRED_ENV)):
        raise ValueError("HKLM 물류 환경 앵커가 있어 보관 전에 중단했습니다 — 관리자 지원 필요 (값 비출력)")


def _possession():
    with onboarding.PersistentPossessionKey.open_existing(scope=onboarding.SCOPE_CURRENT_USER) as key:
        descriptor = key.descriptor()
        policy = key.assert_non_exportable()
        return {"fingerprint": descriptor.fingerprint, "scope": descriptor.scope,
                "provider_name": descriptor.provider_name, "key_name": descriptor.key_name,
                "contract_version": descriptor.contract_version, "export_policy": descriptor.export_policy,
                "private_export_status": policy.private_export_status_hex}


def _candidate(paths, target):
    from tools import register_container_audit_worker_pc as registration
    from storage_policy import build_container_audit_storage_paths

    install_id = registration.derive_path_independent_install_id(
        machine_guid=registration._current_machine_guid(), user_sid=_sid())
    source = registration.derive_install_bound_identity_id(install_id, purpose="source_host_id", prefix="container-audit-source")
    identity = {"hostname": socket.gethostname(), "source_host_id": source, "producer_id": source,
                "producer_install_id": install_id,
                "pc_id": registration.derive_install_bound_identity_id(install_id, purpose="pc_id", prefix="container-audit-pc"),
                "pending_key_id": registration.derive_install_bound_identity_id(install_id, purpose="pending_key_id", prefix="pending-server-key"),
                "identity_source": "generated", "identity_loaded_from": "", "identity_persist_path": str(paths.identity_path),
                "producer_install_id_derivation": registration.INSTALL_IDENTITY_DERIVATION_VERSION,
                "install_bound_identity_derivation": registration.INSTALL_BOUND_IDENTITY_DERIVATION_VERSION,
                "existing_enrollment_contract_version": "", "existing_possession_key_fingerprint": ""}
    manifest = registration._build_container_audit_manifest(
        hostname=identity["hostname"], pc_id=identity["pc_id"], source_host_id=source, producer_install_id=install_id,
        endpoint_url=target["origin"] + onboarding.DEFAULT_ENDPOINT_PATH,
        secret_ref=registration._default_secret_ref(install_id),
        storage_paths=build_container_audit_storage_paths(application_path=str(paths.app_root)), identity_registry_status="self_enrolled")
    return {"identity": identity, "manifest": manifest, "manifest_hash": manifest_hash(manifest)}


@writer_sink("worker_enrollment_network")
def _verify_fresh_server(plan):
    import requests
    from tools import register_container_audit_worker_pc as registration

    target, candidate = plan["target"], plan["candidate"]
    paths = onboarding.resolve_current_user_onboarding_paths(plan["app_root"])
    ca = plan.get("tls_ca_bundle_path") or onboarding._configured_tls_ca_bundle_source(paths, os.environ) or True
    if plan.get("tls_ca_bundle_sha256") and onboarding._file_sha256(Path(ca)) != plan["tls_ca_bundle_sha256"]:
        raise ValueError("전환 TLS CA 사본이 변경됐습니다")
    with requests.Session() as session:
        session.trust_env = False
        response = session.get(target["origin"] + "/health/ready", timeout=30, allow_redirects=False, verify=ca)
        if response.status_code != 200 or response.headers.get("X-KMTech-Source-Commit") != target["acceptance"]["source_commit"]:
            raise ValueError("새 서버 TLS·준비 상태·source commit 대조 실패")
    identity = candidate["identity"]
    request = {"contract_version": "producer-reattach-challenge-request-v1",
               **{k: identity[k] for k in ("producer_id", "producer_install_id", "source_host_id")},
               "manifest_hash": candidate["manifest_hash"]}
    token = os.environ.get(registration.DEFAULT_ENROLLMENT_TOKEN_ENV, "")
    response = registration._post_enrollment_request(
        target["origin"] + registration.REATTACH_CHALLENGE_PATH, json=request,
        headers={"X-Producer-Enrollment-Token": token} if token else {}, timeout=30,
        allow_redirects=False, verify=ca)
    try:
        result = response.json()
    except ValueError as exc:
        raise ValueError("새 서버 최초 challenge 결과는 UNKNOWN입니다") from exc
    if response.status_code != 404 or not isinstance(result, dict) or result.get("error", {}).get("code") != "producer_identity_not_found":
        raise ValueError("새 서버에 기존 신원이 있거나 최초 challenge가 불명확합니다; 원본을 분리하지 않았습니다")
    return {"http_status": 404, "code": "producer_identity_not_found", "candidate_manifest_hash": candidate["manifest_hash"],
            "origin": target["origin"], "source_commit": target["acceptance"]["source_commit"], "observed_at": onboarding._now()}


def _pointer_path():
    return canonical_control_root() / "server-transition" / POINTER_NAME


def current_transition():
    pointer = _pointer_path()
    if not pointer.exists():
        return None
    binding = _json(pointer)
    plan = _json(binding["journal"], maximum=32 * 1024 * 1024)
    if (plan["schema"] != SCHEMA or plan["transition_id"] != binding["transition_id"]
            or plan["sid"] != _sid() or plan["target"] != binding["target"]):
        raise ValueError("전환 기록의 소유·대상이 다릅니다")
    return plan


def registration_binding(args, storage):
    plan = _json(args.fresh_transition_journal, maximum=32 * 1024 * 1024)
    _require_quiesced_authority(plan)
    current = current_transition()
    if (current is None or current["transition_id"] != plan["transition_id"] or plan["phase"] != "REGISTERING"
            or plan["sid"] != _sid() or str(storage.data_root) != plan["data_root"]
            or str(storage.direct_sync_root) != plan["direct_sync_root"]
            or args.endpoint_url != plan["target"]["origin"] + onboarding.DEFAULT_ENDPOINT_PATH
            or args.credential_scope != "current_user" or args.preserve_existing_machine_profile
            or str(Path(args.logistics_profile_path).resolve()) != plan["profile_path"]
            or not args.self_enroll or args.producer_id or args.producer_install_id or args.source_host_id or args.secret_ref
            or args.key_id or args.hostname or args.producer_identity_path or args.admin_recovery_secret_file
            or plan.get("initial_challenge", {}).get("code") != "producer_identity_not_found"):
        raise ValueError("동일 전환의 등록 결속을 확인하지 못했습니다")
    paths = onboarding.resolve_current_user_onboarding_paths(plan["app_root"])
    if _candidate(paths, plan["target"]) != plan["candidate"] or _possession() != plan["possession"]:
        raise ValueError("전환의 MachineGuid·SID·candidate·공유 키가 변경됐습니다")
    # A partly published same-transition response may be completed by reattach;
    # an unrelated identity/profile must never be silently overwritten.
    if paths.identity_path.exists():
        identity = _json(paths.identity_path)
        if any(identity.get(k) != plan["candidate"]["identity"][k] for k in ("producer_id", "producer_install_id", "source_host_id")) or identity.get("possession_key_fingerprint") != plan["possession"]["fingerprint"]:
            raise ValueError("부분 게시 신원이 이번 전환과 다릅니다")
    return plan


def validate_registration_response(plan, result):
    from tools import register_container_audit_worker_pc as registration

    candidate = plan["candidate"]
    receipt = result.get("client_receipt")
    bindings = {k: candidate["identity"][k] for k in ("producer_id", "producer_install_id", "source_host_id")}
    bindings["endpoint_url"] = plan["target"]["origin"] + onboarding.DEFAULT_ENDPOINT_PATH
    key = result.get("possession_key") or {}
    bundle = result.get("machine_credential_bundle") or {}
    # Bundle validation in the existing installer still checks every field;
    # this additional comparison prevents publishing a valid foreign scope.
    scope = (bundle.get("bindings") or {}).get("authority_scope_id")
    if (not isinstance(receipt, dict) or any(result.get(k) != v or receipt.get(k) != v for k, v in bindings.items())
            or receipt.get("receipt_schema_version") != "producer-self-enrollment-client-receipt-v1"
            or receipt.get("manifest_hash") != candidate["manifest_hash"]
            or candidate["manifest_hash"] not in (result.get("active_manifest_hashes") or [])
            or key.get("contract_version") != registration.POSSESSION_KEY_CONTRACT_VERSION
            or key.get("fingerprint") != plan["possession"]["fingerprint"]
            or receipt.get("possession_key_fingerprint") != plan["possession"]["fingerprint"]
            or type(result.get("credential_epoch")) is not int or result["credential_epoch"] < 1
            or receipt.get("credential_epoch") != result["credential_epoch"]
            or not result.get("key_id") or receipt.get("key_id") != result["key_id"]
            or receipt.get("authorization_state") != result.get("authorization_state")
            or scope != plan["target"]["scope"]):
        raise ValueError("새 등록 응답의 신원·scope·manifest·키·epoch 결속이 다릅니다")
    secret = result.get("secret")
    if not isinstance(secret, str) or not secret.strip() or hashlib.sha256(secret.encode()).hexdigest() != result.get("secret_fingerprint_sha256") or receipt.get("secret_fingerprint_sha256") != result.get("secret_fingerprint_sha256"):
        raise ValueError("새 등록 credential 응답 대조 실패")


@writer_sink("current_user_onboarding")
def prepare_registration(app_root, *, input_path, archive_root, transition_id, lifecycle_receipt, confirm, confirm_pending=False):
    _require_no_machine_environment()
    paths = onboarding.resolve_current_user_onboarding_paths(app_root)
    target = read_target(input_path, packet_root=paths.app_root.parent)
    expected = f"이 PC의 옛 자료를 보관하고 {target['origin']} / {target['scope']} / {target['deployment_id']}에 새로 등록합니다"
    if confirm != expected:
        raise ValueError("PC·앱·SID·새 대상의 명시 확인이 필요합니다")
    existing = current_transition()
    journal = Path(archive_root).resolve() / "transition-journal.json"
    if not existing and journal.is_file():
        # Power loss between the durable journal and its discovery pointer.
        # Recover only the same caller-bound journal, never create a new ID.
        existing = _json(journal, maximum=32 * 1024 * 1024)
        if existing.get("schema") != SCHEMA or existing.get("sid") != _sid() or existing.get("app_root") != str(paths.app_root):
            raise ValueError("연결되지 않은 전환 기록의 원 사용자·앱이 다릅니다")
    if existing and existing["phase"] != "RESTORED":
        if existing["transition_id"] != transition_id or existing["target"] != target or existing["archive_root"] != str(Path(archive_root).resolve()):
            raise ValueError("다른 전환이 진행 중입니다; 같은 전환의 상태를 다시 확인하세요")
        plan = existing
        plan["lifecycle_receipt"] = str(Path(lifecycle_receipt).resolve())
        _require_quiesced_authority(plan)
        if _possession() != plan["possession"]:
            raise ValueError("공유 키가 전환 시작과 다릅니다")
        _save(plan)
    else:
        lifecycle = _json(lifecycle_receipt, maximum=1024 * 1024) if Path(lifecycle_receipt).is_file() else {}
        plan = plan_archive(app_root, archive_root=archive_root, transition_id=transition_id,
                            preserve_active_removal=bool(lifecycle.get("fresh_transition", {}).get("original_removal")))
        plan.update(target=target, lifecycle_receipt=str(Path(lifecycle_receipt).resolve()), defer_machine=True,
                    possession=_possession(), candidate=_candidate(paths, target))
        _require_quiesced_authority(plan)
        if plan["work_observation"]["unresolved_files"] and not confirm_pending:
            raise ValueError("미전송 자료는 보관만 하며 새 서버에 보내지 않는다는 별도 확인이 필요합니다")
        _private_directory(Path(plan["archive_root"]), plan["sid"])
        ca = onboarding._configured_tls_ca_bundle_source(paths, os.environ)
        if ca:
            ca_source = Path(ca)
            _assert_no_reparse_components(ca_source)
            ca_target = Path(plan["archive_root"]) / "transition-ca.pem"
            if not ca_target.exists():
                ca_entry = {"source": str(ca_source), "archive": str(ca_target), "directory": False,
                            "files": _files(ca_source), "directories": [], "root_acl": _acl(ca_source)}
                _copy_entry(ca_entry)
            if onboarding._file_sha256(ca_target) != onboarding._file_sha256(ca_source):
                raise ValueError("전환 TLS CA 사본 대조 실패")
            plan["tls_ca_bundle_path"] = str(ca_target)
            plan["tls_ca_bundle_sha256"] = onboarding._file_sha256(ca_target)
        _save(plan)
    if not _pointer_path().exists() or existing is None or existing["phase"] == "RESTORED":
        _private_directory(_pointer_path().parent, plan["sid"])
        onboarding._write_json_atomic(_pointer_path(), {"schema": SCHEMA, "transition_id": transition_id,
            "journal": str(_journal_path(plan)), "target": target})
    if plan["phase"] == "PLANNED" and not plan.get("initial_challenge"):
        plan["attempts"].append({"stage": "initial_challenge", "status": "UNKNOWN", "started_at": onboarding._now()})
        _save(plan)
        try:
            plan["initial_challenge"] = _verify_fresh_server(plan)
            plan["attempts"][-1]["status"] = "PASS"
        except Exception as exc:
            plan["attempts"][-1]["error_type"] = type(exc).__name__
            _save(plan)
            raise
        _save(plan)
    if plan["phase"] in PHASES[:3]:
        plan = archive_state(plan, confirm_pending=confirm_pending)
    if plan["phase"] == "DETACHED":
        paths = onboarding.resolve_current_user_onboarding_paths(app_root)
        if onboarding.inspect_current_user_state(paths)["status"] != "ABSENT":
            raise ValueError("보관 뒤 활성 신원의 ABSENT를 확인하지 못했습니다")
        plan["identity_absent"] = True
        _save(plan)
    return plan


@writer_sink("current_user_onboarding")
def register_transition(plan):
    from tools import register_container_audit_worker_pc as registration

    _require_quiesced_authority(plan)
    if plan["phase"] in {"REGISTERED", "ACTIVATION_PENDING_RELEASE", "ACTIVATED"}:
        return plan
    if plan["phase"] not in {"DETACHED", "REGISTERING"} or plan.get("identity_absent") is not True:
        raise ValueError("원본 보관·ABSENT 확인 뒤 이어서 등록하세요")
    paths = onboarding.resolve_current_user_onboarding_paths(plan["app_root"])
    plan["phase"] = "REGISTERING"
    plan["attempts"].append({"stage": "registration", "status": "UNKNOWN", "started_at": onboarding._now()})
    _save(plan)  # A lost response is resumed only with this durable candidate.
    arguments = ["--app-root", str(paths.app_root), "--self-enroll", "--require-machine-credential-bundle",
                 "--credential-scope", "current_user", "--endpoint-url", plan["target"]["origin"] + onboarding.DEFAULT_ENDPOINT_PATH,
                 "--fresh-transition-journal", str(_journal_path(plan)), "--logistics-profile-path", str(paths.logistics_profile_path),
                 "--manifest-path", str(paths.producer_manifest_path), "--credential-path", str(paths.credential_path),
                 "--report-path", str(paths.registration_report_path)]
    ca = plan.get("tls_ca_bundle_path") or onboarding._configured_tls_ca_bundle_source(paths, os.environ)
    if ca and plan.get("tls_ca_bundle_sha256") and onboarding._file_sha256(Path(ca)) != plan["tls_ca_bundle_sha256"]:
        raise ValueError("전환 TLS CA 사본이 변경됐습니다")
    if ca:
        arguments.extend(["--tls-ca-bundle-path", ca])
    result = registration.main(arguments)
    if type(result) is not int or result != 0:
        raise ValueError("새 서버 등록 결과는 미완료입니다; 같은 전환으로 다시 확인하세요")
    state = onboarding.inspect_current_user_state(paths)
    profile = onboarding._default_profile_loader(paths.logistics_profile_path)
    if state["status"] != "READY" or state["base_url"].rstrip("/") != plan["target"]["origin"] or profile.authority_scope != plan["target"]["scope"] or _possession() != plan["possession"]:
        raise ValueError("새 서버 등록의 로컬 readback 결속 실패")
    plan["phase"] = "REGISTERED"
    plan["attempts"][-1]["status"] = "PASS"
    _save(plan)
    return plan


def _first_lease(plan):
    path = Path(plan["direct_sync_root"]) / "status/direct_sync_relay_status.json"
    if not path.is_file():
        return False
    report = _json(path, maximum=1024 * 1024)
    lease = report.get("runtime_lease") or {}
    try:
        expires = datetime.fromisoformat(str(lease.get("expires_at", "")).replace("Z", "+00:00"))
        valid_time = expires.tzinfo is not None and expires > datetime.now(timezone.utc)
    except ValueError:
        valid_time = False
    return (valid_time and lease.get("contract_version") == "producer-runtime-lease.v1"
            and lease.get("status") == "ACTIVE" and lease.get("server_grant_accepted") is True
            and bool(lease.get("runtime_instance_id")) and bool(lease.get("lease_id"))
            and type(lease.get("fence")) is int and lease["fence"] > 0
            and lease.get("producer_install_id") == plan["candidate"]["identity"]["producer_install_id"])


def complete_activation(plan, *, timeout_seconds=75):
    """Let the delegated single relay obtain its lease before publishing Run."""
    _require_quiesced_authority(plan)
    if plan["phase"] not in {"REGISTERED", "ACTIVATION_PENDING_RELEASE", "ACTIVATED"}:
        raise ValueError("새 서버 등록 검증 뒤 자동 시작을 활성화하세요")
    with writer_admission("current_user_onboarding_storage"):
        plan["attempts"].append({"stage": "activation", "status": "UNKNOWN", "started_at": onboarding._now()})
        _save(plan)
    deadline = time.monotonic() + timeout_seconds
    while not _first_lease(plan):
        if time.monotonic() >= deadline:
            raise ValueError("첫 relay lease는 UNKNOWN입니다; Run을 게시하지 않았습니다")
        time.sleep(0.25)
    with writer_admission("current_user_onboarding"):
        paths = onboarding.resolve_current_user_onboarding_paths(plan["app_root"])
        state = onboarding.inspect_current_user_state(paths)
        if state["status"] != "READY" or _possession() != plan["possession"]:
            raise ValueError("활성화 직전 신원·공유 키 readback 실패")
        queue = paths.queue_dir / "direct_sync_relay.sqlite3"
        conn = sqlite3.connect(queue.as_uri() + "?mode=ro", uri=True)
        try:
            if conn.execute("SELECT COUNT(*) FROM direct_sync_relay_batches").fetchone()[0] != 0:
                raise ValueError("새 queue에 예상하지 않은 업무가 있습니다; 자동 시작은 보류합니다")
        finally:
            conn.close()
        report = _json(paths.onboarding_report_path, maximum=1024 * 1024)
        if report.get("status") != "ACTIVATION_PENDING" or report.get("data_root") != plan["data_root"]:
            raise ValueError("이번 전환의 제어 relay 시작 기록이 다릅니다")
        report["relay_autostart"] = dict(onboarding.install_user_relay_autostart(paths.app_root))
        if report["relay_autostart"].get("status") != "PASS":
            raise ValueError("새 자동 시작 Run 게시 결과를 확인하지 못했습니다")
        report["status"] = "READY"
        onboarding._write_json_atomic(paths.onboarding_report_path, report)
        plan.update(phase="ACTIVATION_PENDING_RELEASE", first_lease="VERIFIED", new_queue_rows=0)
        plan["attempts"][-1]["status"] = "PASS"
        _save(plan)
    return plan


@writer_sink("current_user_lifecycle_restore")
def restore_archive(plan):
    _require_quiesced_authority(plan)
    # A request may have committed remotely. Absence of a local credential is
    # deliberately not proof that a remote registration/lease does not exist.
    if plan["phase"] in {"REGISTERING", "REGISTERED", "ACTIVATION_PENDING_RELEASE", "ACTIVATED"}:
        raise ValueError("새 서버 등록이 시작됐을 수 있어 되돌릴 수 없음 — 관리자 지원 필요. 같은 전환으로 이어서 등록하세요")
    if plan["phase"] in {"RESTORE_PENDING_RELEASE", "RESTORED"}:
        return plan
    pending = []
    for entry in reversed(plan["entries"]):
        if entry.get("shared_read_only"):
            if not _same_files(Path(entry["source"]), entry, original=True):
                raise ValueError("공유 profile이 변경됐습니다; 다른 앱의 상태를 덮어쓰지 않습니다")
            continue
        source, inactive = Path(entry["source"]), Path(entry["inactive"])
        if not inactive.exists():
            if not source.exists() or not _same_files(source, entry, original=True):
                raise ValueError("복원할 원본이 없거나 변경됐습니다")
            continue
        if not _same_files(inactive, entry, original=True):
            raise ValueError("복원할 비활성 원본이 변경됐습니다")
        if source.exists():
            raise ValueError("새 로컬 자료가 있습니다; 옛 자료를 덮어쓰지 않고 앞으로 복구하세요")
        pending.append(entry)
    plan["machine_restore_pending"] = any(e.get("machine_state") for e in pending) and bool(plan.get("defer_machine"))
    if plan["machine_restore_pending"]:
        _save(plan)
        return plan
    # Check the entire set first; no partial restore when new work or changed
    # ACLs exist anywhere in the active roots.
    for entry in pending:
        source, inactive = Path(entry["source"]), Path(entry["inactive"])
        inactive.rename(source)
        if not _same_files(source, entry, original=True) or _acl(source) != entry["root_acl"]:
            raise ValueError("원본 ACL·바이트 복원 대조 실패")
        entry["detached"] = False
        _save(plan)
    plan["phase"] = "RESTORE_PENDING_RELEASE"
    _save(plan)
    return plan


def _verified_release(plan, authorization_path, authorization_sha256):
    """Read the existing canonical release contract; never infer release from a phase."""
    from writer_session_fence import RELEASE_SCHEMA, WRITER_INVENTORY_SHA256

    if active_fence() is not None:
        raise ValueError("전환 잠금이 남아 있습니다. 관리자가 같은 전환의 재개를 실행하세요")
    path = Path(authorization_path)
    if not path.is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", authorization_sha256):
        raise ValueError("전환 마무리 증명의 경로·hash가 올바르지 않습니다")
    authorization = _json(path)
    if onboarding._file_sha256(path) != authorization_sha256:
        raise ValueError("전환 마무리 증명이 변경됐습니다")
    audit_path = Path(plan["lifecycle_receipt"])
    audit = _json(audit_path, maximum=1024 * 1024)
    fresh = audit.get("fresh_transition") or {}
    transaction = (audit.get("code_replacement") or {}).get("transaction_id")
    expected_phase = ("PRODUCT_COMPLETE",) if plan["phase"] in {"ACTIVATION_PENDING_RELEASE", "ACTIVATED"} else (
        "ROLLBACK_COMPLETE", "ROLLBACK_NATURAL_TRIGGER") if plan["phase"] in {"RESTORE_PENDING_RELEASE", "RESTORED"} else ()
    previous = plan.get("completion_release") or {}
    audit_sha = previous.get("install_audit_sha256") if plan["phase"] in {"ACTIVATED", "RESTORED"} and previous else onboarding._file_sha256(audit_path)
    if (audit.get("schema") != "container-audit-canonical-portable-install-v2"
            or audit.get("operation") != "PREPARE_FRESH_SERVER_REGISTRATION"
            or fresh.get("transition_id") != plan["transition_id"] or fresh.get("sid") != plan["sid"]
            or plan["sid"] != _sid() or fresh.get("quiesced") is not True
            or authorization.get("schema") != "container-audit-writer-release-authorization-v1"
            or authorization.get("status") != "AUTHORIZED" or authorization.get("app_id") != "container_audit"
            or authorization.get("phase") not in expected_phase
            or authorization.get("writer_inventory_sha256") != WRITER_INVENTORY_SHA256
            or authorization.get("install_audit_path") != str(audit_path)
            or authorization.get("install_audit_sha256") != audit_sha):
        raise ValueError("전환 완료의 원 사용자·단계·audit 결속이 다릅니다")
    bindings = {"session_id": fresh.get("session_id"), "attempt_id": fresh.get("attempt_id"),
                "replacement_transaction_id": transaction}
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value)
           or authorization.get(key) != value for key, value in bindings.items()):
        raise ValueError("전환 완료의 session·attempt·transaction이 다릅니다")
    receipt_path = canonical_control_root() / f"release-{transaction}-{authorization_sha256}.json"
    released = _json(receipt_path)
    expected = {"schema": RELEASE_SCHEMA, "status": "RELEASED", "app_id": "container_audit", **bindings,
                "writer_inventory_sha256": WRITER_INVENTORY_SHA256,
                "release_authorization_path": str(path), "release_authorization_sha256": authorization_sha256,
                "secret_values_recorded": False}
    if (set(released) != set(expected) | {"released_at_utc"}
            or any(released.get(key) != value for key, value in expected.items())
            or type(released.get("secret_values_recorded")) is not bool):
        raise ValueError("이번 전환의 잠금 해제 영수증을 확인하지 못했습니다")
    try:
        released_at = datetime.fromisoformat(released["released_at_utc"].replace("Z", "+00:00"))
        if released_at.tzinfo is None:
            raise ValueError("missing timezone")
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("잠금 해제 영수증의 시간이 올바르지 않습니다") from exc
    return {"authorization_path": str(path), "authorization_sha256": authorization_sha256,
            "install_audit_sha256": audit_sha, "phase": authorization["phase"],
            "receipt_path": str(receipt_path), "receipt_sha256": onboarding._file_sha256(receipt_path)}


@writer_sink("current_user_onboarding_storage")
def finalize_transition(plan, authorization_path, authorization_sha256):
    proof = _verified_release(plan, authorization_path, authorization_sha256)
    if plan["phase"] in {"ACTIVATED", "RESTORED"} and plan.get("completion_release") == proof:
        return plan
    final = "ACTIVATED" if proof["phase"] == "PRODUCT_COMPLETE" else "RESTORED"
    plan.update(phase=final, completion_release=proof)
    _save(plan)
    return plan


def transition_main(argv=None):
    parser = argparse.ArgumentParser(description="옛 자료 보관 후 새 서버 등록 / 다시 확인 / 가능한 경우 복원")
    parser.add_argument("--app-root", required=True)
    parser.add_argument("--action", choices=("plan", "preflight", "prepare", "register", "activate", "status", "restore", "complete"), required=True)
    parser.add_argument("--input", default="")
    parser.add_argument("--archive-root", default="")
    parser.add_argument("--transition-id", default="")
    parser.add_argument("--lifecycle-receipt", default="")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--confirm-pending", action="store_true")
    parser.add_argument("--report-path", default="")
    parser.add_argument("--release-authorization-path", default="")
    parser.add_argument("--release-authorization-sha256", default="")
    args = parser.parse_args(argv)
    try:
        if args.action == "preflight":
            _require_no_machine_environment()
            target = read_target(args.input, packet_root=Path(args.app_root).parent)
            expected = f"이 PC의 옛 자료를 보관하고 {target['origin']} / {target['scope']} / {target['deployment_id']}에 새로 등록합니다"
            if args.confirm != expected:
                raise ValueError("PC·SID·새 서버의 명시 확인이 필요합니다")
            possession = _possession()
            plan = current_transition()
            if plan and plan["phase"] != "RESTORED":
                if plan["transition_id"] != args.transition_id or plan["target"] != target or plan["archive_root"] != str(Path(args.archive_root).resolve()) or plan["possession"] != possession:
                    raise ValueError("진행 중 전환의 대상·소유·키가 다릅니다")
                if plan["phase"] == "ACTIVATED":
                    paths = onboarding.resolve_current_user_onboarding_paths(plan["app_root"])
                    state = onboarding.inspect_current_user_state(paths)
                    if state["status"] != "READY" or state["base_url"].rstrip("/") != target["origin"]:
                        raise ValueError("완료 전환의 신원 readback 실패")
                    if active_fence() is None:
                        proof = plan.get("completion_release") or {}
                        _verified_release(plan, proof.get("authorization_path", ""), proof.get("authorization_sha256", ""))
                        return 0  # The canonical owner also finished/released.
                if not args.lifecycle_receipt:
                    raise ValueError("진행 중인 전환은 원 영수증을 지정한 지원 재개로 이어서 실행하세요")
            return 10  # Validated; the canonical controller may acquire ownership.
        if args.action == "plan":
            plan = plan_archive(args.app_root, archive_root=args.archive_root, transition_id=args.transition_id)
            plan["target"] = read_target(args.input, packet_root=Path(args.app_root).parent)
            # PlanOnly never opens/provisions KSP or makes a registration call.
            summary = {key: plan[key] for key in ("transition_id", "phase", "pc", "sid", "data_root", "archive_root", "roots", "preserved", "bytes", "work_observation", "target")}
            summary["archive_locations"] = [{k: e[k] for k in ("source", "archive", "inactive")} for e in plan["entries"]]
            if args.report_path:
                with writer_admission("current_user_onboarding_storage"):
                    _private_directory(Path(args.report_path).parent, plan["sid"])
                    onboarding._write_json_atomic(Path(args.report_path), summary)
            print(json.dumps(summary, ensure_ascii=False))
            return 0
        if args.action == "prepare":
            plan = prepare_registration(args.app_root, input_path=args.input, archive_root=args.archive_root,
                transition_id=args.transition_id, lifecycle_receipt=args.lifecycle_receipt,
                confirm=args.confirm, confirm_pending=args.confirm_pending)
        else:
            plan = current_transition()
            if not plan or plan["transition_id"] != args.transition_id:
                raise ValueError("같은 전환 ID의 보존 기록이 필요합니다")
            if args.action == "complete":
                if str(Path(args.lifecycle_receipt).resolve()) != plan["lifecycle_receipt"]:
                    raise ValueError("전환 마무리는 마지막 정지 증명과 같은 audit에서 실행하세요")
                plan = finalize_transition(plan, args.release_authorization_path, args.release_authorization_sha256)
            elif args.action != "status":
                plan["lifecycle_receipt"] = str(Path(args.lifecycle_receipt).resolve())
                _require_quiesced_authority(plan)
                with writer_admission("current_user_onboarding_storage"):
                    _save(plan)
            if args.action == "register":
                plan = register_transition(plan)
            elif args.action == "activate":
                plan = complete_activation(plan)
            elif args.action == "restore":
                plan = restore_archive(plan)
        print(f"fresh_transition_status={plan['phase']}")
        print(f"fresh_transition_report={Path(plan['archive_root']) / 'transition-result.json'}")
        return 0
    except Exception as exc:
        # Neither a remote response body nor a secret-bearing exception crosses
        # the windowed host boundary. Detailed failure category stays durable.
        print(f"fresh_transition_status=UNKNOWN\nfresh_transition_error_type={type(exc).__name__}")
        return 4

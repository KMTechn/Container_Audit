"""Read-only installed-app readiness; never import the GUI entrypoint."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import sys
import time

sys.dont_write_bytecode = True

REASON_CATEGORIES = {
    "UPDATE_PENDING": "UPDATE_PENDING",
    "DEPLOY_FENCE": "DEPLOY_FENCE",
    "MACHINE_DEPLOY_FENCE": "DEPLOY_FENCE",
    "INSTALL_MISMATCH": "INSTALL_MISMATCH",
    "RELAY_AUTOSTART_MISMATCH": "INSTALL_MISMATCH",
    "DATA_GUARD_REFUSED": "DATA_GUARD",
    "ACCOUNT_MISMATCH": "ACCOUNT_MISMATCH",
    "FIRST_RUN_SETUP_REQUIRED": "ACCOUNT_MISMATCH",
    "MACHINE_ONBOARDING_PENDING": "ACCOUNT_MISMATCH",
    "FIRST_RUN_PENDING": "FIRST_RUN_PENDING",
    "ITEM_CATALOG_UNAVAILABLE": "CATALOG_OFFLINE",
    "ITEM_CATALOG_HTTP_403": "CATALOG_OFFLINE",
    "ITEM_CATALOG_HTTP_ERROR": "CATALOG_OFFLINE",
    "ITEM_CATALOG_TIMEOUT": "CATALOG_OFFLINE",
    "ITEM_CATALOG_UNREACHABLE": "CATALOG_OFFLINE",
    "ITEM_CATALOG_REQUEST_FAILED_NO_CACHE": "CATALOG_OFFLINE",
    "ITEM_CATALOG_PROFILE_LOAD_FAILED": "CATALOG_OFFLINE",
    "ITEM_CATALOG_PROFILE_INCOMPLETE": "CATALOG_OFFLINE",
    "ITEM_CATALOG_PROFILE_ABSENT": "CATALOG_OFFLINE",
    "ITEM_CATALOG_URL_NOT_TRUSTED": "CATALOG_OFFLINE",
    "ITEM_CATALOG_SNAPSHOT_UNAVAILABLE_AFTER_VERIFY": "CATALOG_OFFLINE",
    "ITEM_CATALOG_SNAPSHOT_PARSE_FAILED": "CATALOG_OFFLINE",
    "ALREADY_RUNNING": "ALREADY_RUNNING",
    "UNKNOWN_UPDATE": "UNKNOWN",
    "UNKNOWN_DEPLOY_FENCE": "UNKNOWN",
    "UNKNOWN_INSTALLATION": "UNKNOWN",
    "UNKNOWN_DATA_GUARD": "UNKNOWN",
    "UNKNOWN_ACCOUNT": "UNKNOWN",
    "UNKNOWN_CATALOG": "UNKNOWN",
    "UNKNOWN_PROCESS_LIST": "UNKNOWN",
    "UNKNOWN_RELAY_AUTOSTART": "UNKNOWN",
    "UNKNOWN_SLOW_INSTALLATION": "UNKNOWN",
    "UNKNOWN_SLOW_CHECK": "UNKNOWN",
    "UNKNOWN_CHECK": "UNKNOWN",
    "UNKNOWN_ARGUMENTS": "UNKNOWN",
}
REASON_CATEGORIES.update({f"TEST_{category}": category for category in (
    "UPDATE_PENDING", "DEPLOY_FENCE", "INSTALL_MISMATCH", "DATA_GUARD",
    "ACCOUNT_MISMATCH", "CATALOG_OFFLINE", "ALREADY_RUNNING", "FIRST_RUN_PENDING", "UNKNOWN",
)})
NONBLOCKING_CATEGORIES = frozenset({"ALREADY_RUNNING", "FIRST_RUN_PENDING"})


def startup_result(version="", build_sha="", reasons=()):
    reasons = list(dict.fromkeys(reason if reason in REASON_CATEGORIES else "UNKNOWN_CHECK"
                                 for reason in reasons))
    blocking = [reason for reason in reasons if REASON_CATEGORIES[reason] not in NONBLOCKING_CATEGORIES]
    categories = list(dict.fromkeys(REASON_CATEGORIES[reason] for reason in reasons))
    ready = not blocking
    return {
        "schema": "app_startup_check.v1", "app": "CA",
        "version": version if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", str(version)) else "",
        "build_sha": build_sha if re.fullmatch(r"[0-9a-f]{40}", str(build_sha)) else "",
        "startable": ready, "status": "READY" if ready else blocking[0],
        "reasons": reasons, "category": "READY" if ready else REASON_CATEGORIES[blocking[0]],
        "categories": (["READY"] if ready else []) + categories,
        "checked_at": datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds"),
    }


def catalog_refusal_reason(cause_code, *, http_status_code=None, exception_type=None):
    """Project existing refusal diagnostics to fixed codes; never emit their values."""
    candidate = "ITEM_CATALOG_" + cause_code if isinstance(cause_code, str) else ""
    if candidate not in REASON_CATEGORIES:
        return "UNKNOWN_CATALOG"
    if cause_code == "REQUEST_FAILED_NO_CACHE":
        if type(http_status_code) is int and http_status_code == 403:
            return "ITEM_CATALOG_HTTP_403"
        if type(http_status_code) is int and 400 <= http_status_code <= 599:
            return "ITEM_CATALOG_HTTP_ERROR"
        if exception_type in ("Timeout", "ConnectTimeout", "ReadTimeout", "TimeoutError"):
            return "ITEM_CATALOG_TIMEOUT"
        if exception_type in ("ConnectionError", "ProxyError", "SSLError", "ConnectError"):
            return "ITEM_CATALOG_UNREACHABLE"
        if exception_type not in (None, "", "ItemCatalogSyncError"):
            return "UNKNOWN_CATALOG"
    return candidate


def _already_running(app_root):
    """Observe matching GUI processes through Windows APIs, without mutexes."""
    class Process(ctypes.Structure):
        _fields_ = [("session", wintypes.DWORD), ("pid", wintypes.DWORD),
                    ("name", wintypes.LPWSTR), ("sid", wintypes.LPVOID)]

    class UnicodeString(ctypes.Structure):
        _fields_ = [("length", wintypes.WORD), ("maximum", wintypes.WORD),
                    ("buffer", wintypes.LPVOID)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
    native = ctypes.WinDLL("ntdll")
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    native.NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE, wintypes.ULONG, wintypes.LPVOID, wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG)]
    native.NtQueryInformationProcess.restype = wintypes.LONG
    wts.WTSEnumerateProcessesW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(Process)), ctypes.POINTER(wintypes.DWORD)]
    wts.WTSFreeMemory.argtypes = [wintypes.LPVOID]
    rows, count, session = ctypes.POINTER(Process)(), wintypes.DWORD(), wintypes.DWORD()
    if not kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
        raise OSError("process session unavailable")
    if not wts.WTSEnumerateProcessesW(None, 0, 1, ctypes.byref(rows), ctypes.byref(count)):
        raise OSError("process list unavailable")
    runtime = app_root.parent / "runtime"
    expected = {os.path.normcase(str(runtime / name)) for name in ("python.exe", "pythonw.exe")}
    try:
        for row in rows[:count.value]:
            if (row.pid == os.getpid() or row.session != session.value
                    or str(row.name).casefold() not in {"python.exe", "pythonw.exe"}):
                continue
            handle = kernel.OpenProcess(0x1000, False, row.pid)
            if not handle:
                if ctypes.get_last_error() == 87:
                    continue  # The process exited after enumeration.
                raise OSError("process image unavailable")
            try:
                image, size = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
                if not kernel.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
                    raise OSError("process image unavailable")
                if os.path.normcase(image.value) not in expected:
                    continue
                needed = wintypes.ULONG()
                native.NtQueryInformationProcess(handle, 60, None, 0, ctypes.byref(needed))
                if not ctypes.sizeof(UnicodeString) <= needed.value <= 65536:
                    raise OSError("process arguments unavailable")
                data = ctypes.create_string_buffer(needed.value)
                if native.NtQueryInformationProcess(handle, 60, data, len(data), ctypes.byref(needed)) < 0:
                    raise OSError("process arguments unavailable")
                text = UnicodeString.from_buffer(data)
                if (not text.buffer or text.length % 2 or text.buffer < ctypes.addressof(data)
                        or text.buffer + text.length > ctypes.addressof(data) + len(data)):
                    raise OSError("process arguments invalid")
                command = ctypes.wstring_at(text.buffer, text.length // 2).casefold()
                if ("--container-audit-user-relay" not in command
                        and "--container-audit-direct-sync-relay" not in command
                        and any(name in command for name in ("container_audit.py", "main.py"))):
                    return True
            finally:
                kernel.CloseHandle(handle)
        return False
    finally:
        wts.WTSFreeMemory(rows)


def check_startup(app_root):
    deadline = time.monotonic() + 10.0
    import socket
    import ssl  # Load the standard socket base before disabling creation.
    original = socket.socket

    def no_network(*_args, **_kwargs):
        raise OSError("network disabled during read-only startup check")

    # HTTP libraries may probe loopback IPv6 during import. No socket is created
    # in this isolated CLI process, including by accidental future network calls.
    socket.socket = no_network
    try:
        return _check_startup(app_root, deadline)
    finally:
        socket.socket = original


def _check_startup(app_root, deadline):
    from auto_update import (control_root, current_process_sid, ordinary_user_context,
                             optional_record, prepared_pending, read_json,
                             startup_requires_bootstrap)
    import current_user_onboarding as onboarding
    from data_generation_guard import InstalledReleaseMismatch
    from data_generation_guard import (_portable_runtime_release, _readonly_startup_probe,
                                       marker_paths, owner_roots)
    from kmtech_shared import data_generation as generation
    import item_catalog_sync as catalog
    from logistics_runtime_profile import legacy_label_transition_enabled
    from protected_admin import default_protected_admin_profile_path
    from writer_session_fence import active_fence, canonical_control_root
    from user_relay import _registry_get, user_relay_command_line

    app_root = Path(app_root).absolute()
    reasons, release = [], {}
    profile = None
    first_run_pending = False

    def within_budget():
        if time.monotonic() >= deadline:
            raise TimeoutError("read-only check budget exhausted")

    def inspect(stage, check):
        try:
            within_budget()
            reason = check()
            within_budget()
            if reason:
                reasons.append(reason)
        except (InstalledReleaseMismatch, onboarding.BootstrapIntegrityMismatch):
            reasons.append("INSTALL_MISMATCH")
        except TimeoutError:
            reasons.append("UNKNOWN_SLOW_" + ("INSTALLATION" if stage == "INSTALLATION" else "CHECK"))
        except Exception:
            reasons.append("UNKNOWN_" + stage)

    def installation():
        nonlocal release
        release = _portable_runtime_release(
            app_root=app_root,
            rehash_paths=frozenset({"portable-manifest.json", "app/Container_Audit.py",
                                    "app/startup_check.py"}),
            deadline=deadline,
        ) or {}
        return None if release else "INSTALL_MISMATCH"

    inspect("INSTALLATION", installation)

    def update():
        control = control_root(app_root)
        if control is None:
            return "INSTALL_MISMATCH"
        policy = read_json(control / "policy.json")
        if not ordinary_user_context(policy["operator_sid"]):
            return "ACCOUNT_MISMATCH"
        state = optional_record(control / "transition.json")
        active = read_json(control / "active.json")
        try:
            running_sha = read_json(app_root.parent / "portable-manifest.json")["source_commit"]
        except FileNotFoundError:
            return "INSTALL_MISMATCH"
        if startup_requires_bootstrap(
                state, prepared_present=prepared_pending(control, policy, state),
                running_sha=running_sha,
                active_sha=active["sha"]):
            return "UPDATE_PENDING"
        return None

    inspect("UPDATE", update)
    inspect("DEPLOY_FENCE", lambda: "DEPLOY_FENCE" if active_fence() is not None else None)
    def machine_fence():
        machine = Path(os.environ["PROGRAMDATA"]) / "KMTech/ContainerAudit/machine-install"
        try:
            (machine / "control/writer-session/active.json").stat()
        except FileNotFoundError:
            return None
        return "MACHINE_DEPLOY_FENCE" if onboarding.machine_deployment_fence_present(
            machine / "pending-onboarding.json") else None

    inspect("DEPLOY_FENCE", machine_fence)

    if release and time.monotonic() < deadline:
        with _readonly_startup_probe(release, within_budget):
            paths = None

            def account():
                nonlocal paths, profile, first_run_pending
                paths = onboarding.resolve_current_user_onboarding_paths(app_root)
                try:
                    machine_state = onboarding.consume_pending_machine_onboarding(app_root, read_only=True)
                except onboarding.CurrentUserOnboardingError as error:
                    if isinstance(error.__cause__, onboarding.MachineDeploymentFenced):
                        return "MACHINE_DEPLOY_FENCE"
                    if error.status == "PENDING_WORKER_SID_MISMATCH":
                        return "ACCOUNT_MISMATCH"
                    raise
                machine_reason = onboarding.startup_onboarding_reason(machine_state, machine=True)
                if machine_reason not in (None, "FIRST_RUN_PENDING"):
                    return machine_reason
                can_onboard = machine_reason == "FIRST_RUN_PENDING" or onboarding.first_run_onboarding_enabled()

                def loader(path):
                    nonlocal profile
                    profile = onboarding._default_profile_loader(path)
                    return profile

                state = onboarding.inspect_current_user_state(
                    paths, profile_loader=loader, credential_loader=onboarding.load_credentials_from_json)
                reason = onboarding.startup_onboarding_reason(state, can_onboard=can_onboard)
                if reason not in (None, "FIRST_RUN_PENDING"):
                    return reason
                first_run_pending = machine_reason == "FIRST_RUN_PENDING" or reason == "FIRST_RUN_PENDING"
                return "FIRST_RUN_PENDING" if first_run_pending else None

            inspect("ACCOUNT", account)

            def data():
                if paths is None:
                    return "UNKNOWN_DATA_GUARD"
                files = (paths.logistics_profile_path, default_protected_admin_profile_path())
                for root in owner_roots(paths.data_root, file_paths=files):
                    within_budget()
                    decision = generation.probe_downgrade(
                        marker_paths(root, current_process_sid()), release["version"],
                        app_id="container_audit", subject_sid=current_process_sid(),
                        target_build_id=release["build_id"])
                    if not decision["allowed"]:
                        return "DATA_GUARD_REFUSED" if decision["status"] == "REFUSE" else "UNKNOWN_DATA_GUARD"

            inspect("DATA_GUARD", data)

            def items():
                if legacy_label_transition_enabled():
                    return None
                if profile is None:
                    return None if first_run_pending else "ITEM_CATALOG_UNAVAILABLE"
                cache = catalog.default_cache_path()
                unreadable = False
                for path in (cache, catalog._cache_authority_path(cache), catalog._cache_recovery_path(cache)):
                    try:
                        if path.stat().st_size > 2 * 1024 * 1024:
                            return "UNKNOWN_CATALOG"
                        with path.open("rb") as stream:
                            stream.read(1)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        unreadable = True
                options = dict(url=profile.base_url.rstrip("/") + catalog.CATALOG_PATH,
                               source_host_id=profile.source_host_id, device_id=profile.device_id,
                               bearer_token=profile.bearer_token)
                if (catalog._read_authenticated_cache_payload(cache, **options)
                        or catalog._read_authenticated_recovery_payload(cache, **options)):
                    return None
                return "UNKNOWN_CATALOG" if unreadable else "ITEM_CATALOG_UNAVAILABLE"

            inspect("CATALOG", items)
            def relay_autostart():
                registered = _registry_get()
                if first_run_pending and registered in (None, ""):
                    return None  # Existing onboarding installs an absent entry before starting the GUI.
                return None if registered == user_relay_command_line(app_root) else "RELAY_AUTOSTART_MISMATCH"
            inspect("RELAY_AUTOSTART", relay_autostart)
    inspect("PROCESS_LIST", lambda: "ALREADY_RUNNING" if _already_running(app_root) else None)
    return startup_result(release.get("version", ""), release.get("build_id", ""), reasons)


def main(argv=None, *, app_root=None):
    try:
        if list(sys.argv[1:] if argv is None else argv) != ["--json"]:
            result = startup_result(reasons=["UNKNOWN_ARGUMENTS"])
        else:
            result = check_startup(app_root or Path(__file__).absolute().parent)
    except Exception:
        result = startup_result(reasons=["UNKNOWN_CHECK"])
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0 if result["startable"] else 20 if "UNKNOWN" in result["categories"] else 10


if __name__ == "__main__":
    sys.path[:0] = [str(Path(__file__).absolute().parent),
                   str(Path(__file__).absolute().parent / "site-packages")]
    raise SystemExit(main())

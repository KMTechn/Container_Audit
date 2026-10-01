"""Decisions for startup updates; code and business data have separate lifetimes.

The decision functions are pure. The protected bootstrap persists records before
switching a code pointer; business data is never copied or restored here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid
from contextlib import contextmanager
from typing import Any, Mapping

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(1, str(Path(__file__).resolve().parent / "site-packages"))

from writer_session_fence import writer_sink, _assert_no_reparse_components


SCHEMA = "container-audit-startup-update-v1"
READY_CHECKS = (
    "gui_initialized", "identity_readable", "ledger_readable",
    "unfinished_readable", "outbox_readable", "ordinary_user_relay",
)


def _sha(value: Any, *, length: int = 40) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{%d}" % length, value) is None:
        raise ValueError("update identity is malformed")
    return value


def _utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("update time is absent")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("update time must include an offset")
    return result.astimezone(timezone.utc)


def startup_action(
    transition: Mapping[str, Any] | None, *, prepared_present: bool,
) -> str:
    """Inspect both the candidate and the record, including before the task runs."""
    if transition is None:
        return "REQUEST_APPLY" if prepared_present else "START_CURRENT"
    if transition.get("schema") != SCHEMA:
        raise ValueError("startup update record is unsupported")
    phase = transition.get("phase")
    if phase == "PREPARED":
        return "REQUEST_APPLY"
    if phase in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"}:
        return "WAIT_FOR_TRIAL" if transition.get("trial_pid") else "REQUEST_TRIAL"
    if phase in {"ROLLBACK_PENDING", "UNKNOWN", "FAILED"}:
        return "WAIT_FOR_RECOVERY"
    if phase not in {"CONFIRMED", "ROLLED_BACK", "DEFERRED"}:
        raise ValueError("startup update phase is unsupported")
    return "REQUEST_APPLY" if prepared_present else "START_CURRENT"


def prepare_transition(
    *, previous_sha: str, candidate_sha: str, packet_sha256: str,
    forward_pin: str, rollback_pin: str, transition_id: str, nonce: str,
    now: str, failed_shas: list[str] | None = None,
) -> dict[str, Any]:
    previous_sha = _sha(previous_sha)
    candidate_sha = _sha(candidate_sha)
    if previous_sha == candidate_sha:
        raise ValueError("update does not change the version")
    failures = list(failed_shas or [])
    for failed in failures:
        _sha(failed)
    if candidate_sha in failures:
        raise ValueError("a failed version must not be reapplied")
    _utc(now)
    return {
        "schema": SCHEMA, "phase": "PREPARED",
        "previous_sha": previous_sha, "candidate_sha": candidate_sha,
        "packet_sha256": _sha(packet_sha256, length=64),
        "forward_pin": _sha(forward_pin, length=64),
        "rollback_pin": _sha(rollback_pin, length=64),
        "transition_id": _sha(transition_id, length=32),
        "nonce": _sha(nonce, length=32), "started_at": now,
        "failed_shas": failures, "trial_pid": None,
    }


def apply_transition(
    prepared: Mapping[str, Any], *, writers_absent: bool,
    packet_verified: bool, durable_prepared: bool, now: str,
) -> dict[str, Any]:
    """A false/unknown observation authorizes no pointer change."""
    if prepared.get("schema") != SCHEMA or prepared.get("phase") != "PREPARED":
        raise ValueError("update was not prepared")
    if writers_absent is not True or packet_verified is not True or durable_prepared is not True:
        raise ValueError("update requires writer absence, verification and durable preparation")
    _utc(now)
    return {**prepared, "phase": "APPLIED_PENDING_READY", "applied_at": now}


def bind_trial(
    transition: Mapping[str, Any], *, sha: str, pid: int,
    ordinary_user: bool, now: str,
) -> dict[str, Any]:
    phase = transition.get("phase")
    expected_sha = transition.get("previous_sha" if phase == "ROLLBACK_PENDING_READY" else "candidate_sha")
    if phase not in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"} or sha != expected_sha:
        raise ValueError("trial version differs from the pending version")
    if transition.get("trial_pid") is not None:
        raise ValueError("the trial has already been started")
    if type(pid) is not int or pid < 1 or ordinary_user is not True:
        raise ValueError("trial must be a live ordinary-user process")
    _utc(now)
    return {**transition, "trial_pid": pid, "trial_sha": sha, "trial_started_at": now}


def ready_matches(
    transition: Mapping[str, Any], ready: Mapping[str, Any], *,
    process_matches: bool, relay_matches: bool, now: str,
) -> bool:
    """PID/heartbeat/exit zero alone do not establish application readiness."""
    phase = transition.get("phase")
    if phase not in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"}:
        return False
    sha = transition.get("previous_sha" if phase == "ROLLBACK_PENDING_READY" else "candidate_sha")
    if (
        process_matches is not True or relay_matches is not True
        or type(ready.get("pid")) is not int or ready["pid"] < 1
        or ready["pid"] != transition.get("trial_pid")
        or ready.get("sha") != sha
        or ready.get("nonce") != transition.get("nonce")
        or ready.get("transition_id") != transition.get("transition_id")
        or any(ready.get(check) is not True for check in READY_CHECKS)
    ):
        return False
    try:
        return _utc(transition["trial_started_at"]) <= _utc(ready["ready_at"]) <= _utc(now)
    except (KeyError, TypeError, ValueError):
        return False


def confirm_transition(
    transition: Mapping[str, Any], ready: Mapping[str, Any], *,
    process_matches: bool, relay_matches: bool, now: str,
) -> dict[str, Any]:
    if not ready_matches(transition, ready, process_matches=process_matches, relay_matches=relay_matches, now=now):
        raise ValueError("update application readiness is unproven")
    rollback = transition["phase"] == "ROLLBACK_PENDING_READY"
    return {**transition, "phase": "ROLLED_BACK" if rollback else "CONFIRMED", "confirmed_at": now}


def request_rollback(transition: Mapping[str, Any], *, reason: str) -> dict[str, Any]:
    if transition.get("phase") != "APPLIED_PENDING_READY":
        raise ValueError("rollback requires a pending trial")
    failures = list(transition.get("failed_shas", []))
    candidate = _sha(transition.get("candidate_sha"))
    if candidate not in failures:
        failures.append(candidate)
    return {**transition, "phase": "ROLLBACK_PENDING", "reason": str(reason), "failed_shas": failures}


def rollback_transition(
    transition: Mapping[str, Any], *, writers_absent: bool,
    previous_verified: bool, durable_rollback: bool, nonce: str, now: str,
) -> dict[str, Any]:
    if transition.get("phase") != "ROLLBACK_PENDING":
        raise ValueError("rollback request is absent")
    if writers_absent is not True:
        return {**transition, "phase": "UNKNOWN", "reason": "writer absence is unproven"}
    if previous_verified is not True or durable_rollback is not True:
        raise ValueError("rollback requires verified previous code and a durable request")
    _utc(now)
    return {**transition, "phase": "ROLLBACK_PENDING_READY", "nonce": _sha(nonce, length=32), "trial_pid": None, "trial_sha": None, "trial_started_at": None, "rollback_at": now}


def recovery_sha(transition: Mapping[str, Any], *, pointer_sha: str) -> str:
    """Choose the recorded pointer after power loss; never restore user data."""
    if transition.get("schema") != SCHEMA:
        raise ValueError("startup update record is unsupported")
    phase = transition.get("phase")
    previous = _sha(transition.get("previous_sha"))
    candidate = _sha(transition.get("candidate_sha"))
    if pointer_sha not in {previous, candidate}:
        raise ValueError("active pointer differs from both recorded versions")
    if phase == "PREPARED":
        if pointer_sha != previous:
            raise ValueError("pointer changed before the applied record was durable")
        return previous
    if phase in {"APPLIED_PENDING_READY", "CONFIRMED"}:
        return candidate
    if phase in {"ROLLBACK_PENDING", "ROLLBACK_PENDING_READY", "ROLLED_BACK"}:
        return previous
    if phase in {"UNKNOWN", "FAILED"}:
        raise ValueError("unproven recovery must preserve the pointer and stop switching")
    raise ValueError("recovery phase is unsupported")


PIN_FIELDS = ("from_commit", "to_commit", "from_contract_sha256", "to_contract_sha256")


def directional_pin(
    approvals: list[Mapping[str, Any]], *, from_commit: str, to_commit: str,
    from_contract_sha256: str, to_contract_sha256: str,
) -> str:
    """Accept an explicit direction; the reverse pair never grants this one."""
    wanted = dict(zip(PIN_FIELDS, (
        _sha(from_commit), _sha(to_commit),
        _sha(from_contract_sha256, length=64), _sha(to_contract_sha256, length=64),
    )))
    if not isinstance(approvals, list):
        raise ValueError("approved update transitions must be a list")
    matched = False
    seen = set()
    for entry in approvals:
        if not isinstance(entry, Mapping) or set(entry) != set(PIN_FIELDS):
            raise ValueError("approved update transition fields differ")
        values = tuple(_sha(entry[field], length=40 if field.endswith("commit") else 64) for field in PIN_FIELDS)
        if values in seen:
            raise ValueError("approved update transitions are duplicated")
        seen.add(values)
        matched = matched or dict(entry) == wanted
    if not matched:
        raise ValueError("update direction has no exact approval")
    return hashlib.sha256(json.dumps(wanted, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def bidirectional_pins(
    approvals: list[Mapping[str, Any]], *, current: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[str, str]:
    if (
        not isinstance(current.get("data_api_contract_sha256"), str)
        or _sha(current["data_api_contract_sha256"], length=64)
        != _sha(candidate.get("data_api_contract_sha256"), length=64)
    ):
        raise ValueError("automatic rollback requires unchanged data and API contracts")
    if not approvals and current["writer_sink_inventory_contract_sha256"] == candidate["writer_sink_inventory_contract_sha256"]:
        fields = dict(zip(PIN_FIELDS, (current["source_commit"], candidate["source_commit"], current["writer_sink_inventory_contract_sha256"], candidate["writer_sink_inventory_contract_sha256"])))
        for name, value in fields.items():
            _sha(value, length=40 if name.endswith("commit") else 64)
        reverse = dict(zip(PIN_FIELDS, (fields["to_commit"], fields["from_commit"], fields["to_contract_sha256"], fields["from_contract_sha256"])))
        def identical_pin(pair):
            return hashlib.sha256(json.dumps({"rule": "IDENTICAL_WRITER_DATA_API", "pair": pair, "data_api_sha256": current["data_api_contract_sha256"]}, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        return identical_pin(fields), identical_pin(reverse)
    forward = directional_pin(
        approvals, from_commit=current["source_commit"], to_commit=candidate["source_commit"],
        from_contract_sha256=current["writer_sink_inventory_contract_sha256"],
        to_contract_sha256=candidate["writer_sink_inventory_contract_sha256"],
    )
    backward = directional_pin(
        approvals, from_commit=candidate["source_commit"], to_commit=current["source_commit"],
        from_contract_sha256=candidate["writer_sink_inventory_contract_sha256"],
        to_contract_sha256=current["writer_sink_inventory_contract_sha256"],
    )
    return forward, backward


def manifest_transition_pins(manifest: Mapping[str, Any], *, current: Mapping[str, Any], candidate: Mapping[str, Any]) -> tuple[str, str, dict[str, str], str]:
    """Only call after authentication of this complete manifest and packet."""
    pair = dict(zip(PIN_FIELDS, (current["source_commit"], candidate["source_commit"], current["writer_sink_inventory_contract_sha256"], candidate["writer_sink_inventory_contract_sha256"])))
    reverse = dict(zip(PIN_FIELDS, (pair["to_commit"], pair["from_commit"], pair["to_contract_sha256"], pair["from_contract_sha256"])))
    approvals = manifest.get("approved_transitions", [])
    if not isinstance(approvals, list) or (approvals and (len(approvals) != 2 or any(entry not in (pair, reverse) for entry in approvals))):
        raise ValueError("signed approvals must contain only the current/candidate pair and its reverse")
    forward, rollback = bidirectional_pins(approvals, current=current, candidate=candidate)
    return forward, rollback, reverse, "SIGNED_EXACT_PAIR" if approvals else "IDENTICAL_WRITER_DATA_API"


DATA_API_FILES = (
    "contract.lock.json", "tray_state.py", "event_contracts.py",
    "event_log_store.py", "transfer_store.py", "transfer_common.py",
    "transfer_client.py", "producer_runtime_client.py", "direct_sync_push.py",
    "logistics_runtime_profile.py", "storage_policy.py", "recovery_two_phase.py",
)


def data_api_contract_sha256(app_root: Path) -> str:
    digest = hashlib.sha256()
    for name in DATA_API_FILES:
        path = app_root / name
        _assert_no_reparse_components(path)
        digest.update((name + "\n").encode("ascii"))
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def unique_object(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate update record field")
        value[name] = item
    return value


def read_json(path: Path, *, maximum: int = 1024 * 1024) -> dict[str, Any]:
    _assert_no_reparse_components(path)
    if path.stat().st_size > maximum:
        raise ValueError("update record is oversized")
    with path.open("r", encoding="utf-8-sig") as source:
        value = json.load(source, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError("update record must be an object")
    return value


def policy_from_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    from update_service import assert_https_update_url

    if not isinstance(settings, Mapping):
        raise ValueError("auto-update settings must be an object")
    allowed = {"feed_url", "channel", "approved_transitions", "apply_during_work", "profile_auth"}
    if set(settings) - allowed:
        raise ValueError("auto-update settings contain unsupported fields")
    feed = settings.get("feed_url", "")
    if not isinstance(feed, str):
        raise ValueError("auto-update feed must be a string")
    if feed:
        feed = assert_https_update_url(feed)
    if settings.get("apply_during_work", False) is not False:
        raise ValueError("applying during work requires separate scanner acceptance")
    approvals = settings.get("approved_transitions", [])
    # Validate every entry even when this PC has no configured feed.
    if not isinstance(approvals, list):
        raise ValueError("approved transitions must be a list")
    for entry in approvals:
        if not isinstance(entry, Mapping) or set(entry) != set(PIN_FIELDS):
            raise ValueError("approved transition fields differ")
        directional_pin(approvals, **entry)
    channel = settings.get("channel", "stable")
    if not isinstance(channel, str) or re.fullmatch(r"[a-z0-9_-]{1,32}", channel) is None:
        raise ValueError("auto-update channel is malformed")
    auth = settings.get("profile_auth", False)
    if type(auth) is not bool:
        raise ValueError("profile authentication setting must be a boolean")
    return {"feed_url": feed, "channel": channel, "approved_transitions": list(approvals), "apply_during_work": False, "profile_auth": auth}


@writer_sink("auto_update_control")
def write_json_durable(path: Path, payload: Mapping[str, Any]) -> None:
    """Write-through replacement keeps the journal ahead of the active pointer."""
    import ctypes
    from ctypes import wintypes

    _assert_no_reparse_components(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(payload, output, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    if os.name == "nt":
        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        move.restype = wintypes.BOOL
        if not move(str(temporary), str(path), 0x1 | 0x8):
            raise OSError(ctypes.get_last_error(), "update write-through replacement failed")
    else:
        os.replace(temporary, path)


def control_root(app_root: Path) -> Path | None:
    code = app_root.absolute()
    if code.name != "app":
        return None
    bundle = code.parent
    if bundle.name == "current":
        managed = bundle.parent
    elif bundle.parent.name == "versions" and re.fullmatch(r"[0-9a-f]{40}", bundle.name):
        managed = bundle.parent.parent
    else:
        return None
    policy = managed / "update-control" / "policy.json"
    if not policy.is_file():
        return None
    _assert_no_reparse_components(policy)
    return policy.parent


def version_bundle(control: Path, sha: str) -> Path:
    return control.parent / "versions" / _sha(sha)


def version_manifest(bundle: Path) -> dict[str, Any]:
    value = read_json(bundle / "portable-manifest.json")
    if type(value.get("startup_update_protocol")) is not int or value["startup_update_protocol"] != 1:
        raise ValueError("version has no supported startup readiness protocol")
    _sha(value.get("source_commit"))
    _sha(value.get("writer_sink_inventory_contract_sha256"), length=64)
    if "version" not in value:
        version_source = (bundle / "app/Container_Audit.py").read_text(encoding="utf-8-sig")
        match = re.search(r'^CURRENT_VERSION\s*=\s*["\'](v[0-9]+\.[0-9]+\.[0-9]+)["\']\s*$', version_source, re.MULTILINE)
        if not match:
            raise ValueError("installed version literal is absent")
        value["version"] = match.group(1)
    value["data_api_contract_sha256"] = data_api_contract_sha256(bundle / "app")
    return value


def verify_prepared_packet(
    stage: Path, *, key_config: str, current_version: str, channel: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    from update_service import (
        file_sha256, verify_update_manifest_signature,
        update_candidate_from_private_manifest,
    )

    manifest = read_json(stage / "manifest.json")
    signature_path = stage / "manifest.sig"
    _assert_no_reparse_components(signature_path)
    if signature_path.stat().st_size > 16384:
        raise ValueError("update signature is oversized")
    verify_update_manifest_signature(manifest, signature_path.read_bytes(), key_config)
    candidate = update_candidate_from_private_manifest(manifest, current_version=current_version, expected_channel=channel)
    if candidate is None or candidate["archive_policy"].get("layout") != "canonical_portable":
        raise ValueError("update is not a targeted canonical portable candidate")
    packet = stage / "packet.zip"
    _assert_no_reparse_components(packet)
    if packet.stat().st_size != manifest["artifact"]["size_bytes"] or file_sha256(packet) != candidate["sha256"]:
        raise ValueError("prepared packet size or SHA256 differs")
    _sha(manifest.get("source_commit"))
    return manifest, candidate


def task_name(app_root: Path, operator_sid: str) -> str:
    if not isinstance(operator_sid, str) or re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", operator_sid) is None:
        raise ValueError("update operator SID is malformed")
    path = os.path.normcase(str(app_root.absolute())).replace("/", "\\")
    identity = hashlib.sha256((path + "\n" + operator_sid).encode("utf-8")).hexdigest()[:24]
    return "KMTech.ContainerAudit.StartupUpdate." + identity


def logon_task_xml(*, app_root: Path, operator_sid: str) -> str:
    """Generate only a fixed protected helper action, with a SID logon trigger."""
    from xml.sax.saxutils import escape

    task_name(app_root, operator_sid)
    root = str(app_root.absolute())
    if any(character in root for character in ('"', "\r", "\n")):
        raise ValueError("update install path is unsafe")
    arguments = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -File "' + root + '\\tools\\apply_prepared_update.ps1" -InstallRoot "' + root + '"'
    executable = system_executable("WindowsPowerShell/v1.0/powershell.exe")
    return (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        '<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>' + escape(operator_sid) + '</UserId></LogonTrigger></Triggers>'
        '<Principals><Principal id="System"><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
        '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>'
        '<Actions Context="System"><Exec><Command>' + escape(executable) + '</Command><Arguments>' + escape(arguments) + '</Arguments></Exec></Actions></Task>'
    )


def install_task_spec(app_root: Path, operator_sid: str) -> dict[str, str]:
    return {"name": task_name(app_root, operator_sid), "xml": logon_task_xml(app_root=app_root, operator_sid=operator_sid)}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def system_executable(relative: str) -> str:
    import ctypes
    from ctypes import wintypes

    if os.name != "nt":
        raise OSError("startup updates require Windows")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_directory = kernel.GetSystemDirectoryW
    get_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_directory.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    size = get_directory(buffer, len(buffer))
    if not size or size >= len(buffer):
        raise OSError(ctypes.get_last_error(), "Windows system directory is unobservable")
    return str(Path(buffer.value) / relative)


def optional_record(path: Path) -> dict[str, Any] | None:
    try:
        return read_json(path)
    except FileNotFoundError:
        return None


@contextmanager
def update_lock(control: Path, operator_sid: str, *, trial: bool = False):
    """One cross-session mutex shared by SYSTEM and the installed operator SID."""
    import ctypes
    from ctypes import wintypes

    task_name(control.parent / "current", operator_sid)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    class Attributes(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", wintypes.LPVOID), ("inherit", wintypes.BOOL)]
    descriptor = wintypes.LPVOID()
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.DWORD)]
    convert.restype = wintypes.BOOL
    sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100001;;;" + operator_sid + ")"
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise OSError(ctypes.get_last_error(), "update mutex ACL conversion failed")
    create = kernel.CreateMutexW
    create.argtypes = [ctypes.POINTER(Attributes), wintypes.BOOL, wintypes.LPCWSTR]
    create.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    identity = hashlib.sha256(os.path.normcase(str(control.absolute())).encode("utf-8")).hexdigest()[:24]
    attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
    try:
        handle = create(ctypes.byref(attributes), False, "Global\\KMTech.ContainerAudit.Update." + identity + (".Trial" if trial else ""))
    finally:
        kernel.LocalFree(descriptor)
    if not handle:
        raise OSError(ctypes.get_last_error(), "update mutex cannot be opened")
    acquired = False
    try:
        result = kernel.WaitForSingleObject(handle, 5000)
        acquired = result in {0, 0x80}
        if result != 0:
            raise RuntimeError("update mutex ownership is busy or abandoned")
        yield
    finally:
        if acquired:
            kernel.ReleaseMutex(handle)
        kernel.CloseHandle(handle)


@writer_sink("auto_update_control")
def fixed_helper(control: Path, mode: str, *, code_root: Path | None = None) -> str:
    import subprocess

    root = control.parent / "current"
    executable = system_executable("WindowsPowerShell/v1.0/powershell.exe")
    arguments = [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-File", str(root / "tools/apply_prepared_update.ps1"), "-InstallRoot", str(root), "-Mode", mode]
    if code_root is not None:
        arguments.extend(["-CodeRoot", str(code_root)])
    completed = subprocess.run(arguments, capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if completed.returncode:
        raise RuntimeError("fixed update helper failed: " + mode)
    return completed.stdout.strip()


def process_snapshot(control: Path) -> list[dict[str, Any]]:
    rows = json.loads(fixed_helper(control, "Observe"))
    if not isinstance(rows, list):
        raise ValueError("update process observation is incomplete")
    return rows


def writer_processes(rows: list[Mapping[str, Any]], *, own_pid: int) -> list[Mapping[str, Any]]:
    writers = []
    for row in rows:
        if row.get("pid") == own_pid:
            continue
        if row.get("bootstrap") is True:
            continue
        if row.get("observable") is not True:
            raise ValueError("an application process cannot be observed")
        writers.append(row)
    return writers


def process_matches_trial(row: Mapping[str, Any], *, state: Mapping[str, Any], sha: str, sid: str, role: str) -> bool:
    if role == "gui" and state.get("trial_pid") == row.get("pid") and state.get("trial_started_at"):
        if _utc(row.get("created_at")) != _utc(state["trial_started_at"]):
            return False
    return (
        row.get("observable") is True and row.get("sha") == sha
        and row.get("sid") == sid and row.get("role") == role
        and type(row.get("pid")) is int and row["pid"] > 0
        and row.get("ordinary_user") is True
        and _utc(row.get("created_at")) >= _utc(state["applied_at"] if role == "gui" and state["phase"] == "APPLIED_PENDING_READY" else state.get("rollback_at", state["applied_at"]))
    )


@writer_sink("auto_update_control")
def persist_switch(control: Path, state: Mapping[str, Any], sha: str) -> None:
    # An interrupted pointer write is repaired from this already-flushed record.
    write_json_durable(control / "transition.json", state)
    write_json_durable(control / "active.json", {"schema": SCHEMA, "sha": _sha(sha), "transition_id": state["transition_id"]})


def record_confirmed_policy(control: Path, state: Mapping[str, Any]) -> dict[str, Any]:
    """Record reverse authority only after durable GUI confirmation."""
    if state.get("phase") != "CONFIRMED" or state.get("policy_audit_applied") is True:
        return dict(state)
    pair = state.get("rollback_pair")
    if pair is None:
        return dict(state)
    directional_pin([pair], **pair)
    if pair["from_commit"] != state["candidate_sha"] or pair["to_commit"] != state["previous_sha"]:
        raise ValueError("confirmed reverse audit is bound to another transition")
    policy = read_json(control / "policy.json")
    write_json_durable(control / "policy.json", {**policy, "last_confirmed_rollback": pair, "rollback_authority": state["pin_authority"], "confirmed_transition_id": state["transition_id"]})
    settled = {**state, "policy_audit_applied": True}
    write_json_durable(control / "transition.json", settled)
    return settled


def apply_prepared(control: Path) -> int:
    """Preserve a failed preparation; never fall back after an uncertain switch."""
    fixed_helper(control, "Authority")
    policy = read_json(control / "policy.json")
    before = read_json(control / "active.json")
    try:
        return _apply_prepared(control)
    except Exception as error:
        with update_lock(control, policy["operator_sid"]):
            state = optional_record(control / "transition.json")
            pointer = read_json(control / "active.json")
            not_applied = pointer == before and (not state or state.get("phase") in {"CONFIRMED", "ROLLED_BACK", "DEFERRED", "PREPARED"})
            failure = {**(state or {}), "schema": SCHEMA,
                       "phase": "DEFERRED" if not_applied else "UNKNOWN",
                       "deferred_at": now_utc(), "reason": type(error).__name__}
            write_json_durable(control / ("failure-" + uuid.uuid4().hex + ".json"), failure)
            write_json_durable(control / "transition.json", failure)
        return 0 if not_applied else 20


def _apply_prepared(control: Path) -> int:
    """SYSTEM applies code only; the operator bootstrap launches the trial."""
    import time
    from update_service import file_sha256

    fixed_helper(control, "Authority")
    policy = read_json(control / "policy.json")
    # SYSTEM must never resolve user credentials or start a user process.
    os.environ["LOCALAPPDATA"] = policy["operator_local_app_data"]
    stage = Path(policy["staging_root"])
    with update_lock(control, policy["operator_sid"]):
        state = optional_record(control / "transition.json")
        if state and state["phase"] == "CONFIRMED":
            state = record_confirmed_policy(control, state)
        if state is None or state["phase"] in {"CONFIRMED", "ROLLED_BACK", "DEFERRED"}:
            if not prepared_pending(control, policy, state):
                return 0
            if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                deferred = {**(state or {}), "schema": SCHEMA, "phase": "DEFERRED", "deferred_at": now_utc(), "reason": "an existing application writer continues working"}
                write_json_durable(control / "transition.json", deferred)
                return 0  # A late task defers; it never stops an existing application.
            active = read_json(control / "active.json")
            current = version_manifest(version_bundle(control, active["sha"]))
            key = read_json(control.parent / "current/app/update-manifest-key-config.json")["manifest_public_key"]
            # Copy user-owned bytes, then authenticate the protected copy. No path,
            # executable or command supplied by the prepared marker is executed.
            protected = control / ("packet-" + uuid.uuid4().hex)
            create_protected_stage(protected)
            for name in ("manifest.json", "manifest.sig", "packet.zip"):
                copy_prepared_file(stage / name, protected / name, expected_owner_sid=policy["operator_sid"])
            manifest, candidate = verify_prepared_packet(protected, key_config=key, current_version=current["version"], channel=policy["channel"])
            sha = manifest["source_commit"]
            if sha in (state or {}).get("failed_shas", []):
                return 0
            extracted = protected / "extracted"
            extract_prepared_code(protected / "packet.zip", extracted, candidate["archive_policy"])
            target = extracted / "Container_Audit"
            candidate_manifest = version_manifest(target)
            if candidate_manifest["source_commit"] != sha or candidate_manifest["version"] != manifest["version"]:
                raise ValueError("signed target SHA differs from the packet")
            if file_sha256(target / "app/update-manifest-key-config.json") != file_sha256(control.parent / "current/app/update-manifest-key-config.json"):
                raise ValueError("candidate signing key differs from the installed key")
            forward, rollback, rollback_pair, pin_authority = manifest_transition_pins(manifest, current=current, candidate=candidate_manifest)
            # The fixed helper validates the portable tree and writes its own
            # integrity record. It never imports or executes candidate code.
            fixed_helper(control, "Verify", code_root=target)
            target_bundle = version_bundle(control, sha)
            if target_bundle.exists():
                fixed_helper(control, "Verify", code_root=target_bundle)
            preserve_candidate_version(target, target_bundle)
            state = prepare_transition(previous_sha=active["sha"], candidate_sha=sha, packet_sha256=candidate["sha256"], forward_pin=forward, rollback_pin=rollback, transition_id=uuid.uuid4().hex, nonce=uuid.uuid4().hex, now=now_utc(), failed_shas=(state or {}).get("failed_shas", []))
            preimage = "policy-before-" + state["transition_id"] + ".json"
            write_json_durable(control / preimage, policy)
            state = {**state, "rollback_pair": rollback_pair, "pin_authority": pin_authority, "policy_preimage": preimage}
            write_json_durable(control / "transition.json", state)
            state = apply_transition(state, writers_absent=not writer_processes(process_snapshot(control), own_pid=os.getpid()), packet_verified=True, durable_prepared=True, now=now_utc())
            persist_switch(control, state, sha)
        elif state["phase"] in {"UNKNOWN", "FAILED"}:
            return 20
        else:
            pointer = read_json(control / "active.json")
            if state["phase"] == "PREPARED":
                if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                    return 20
                fixed_helper(control, "Verify", code_root=version_bundle(control, state["candidate_sha"]))
                state = apply_transition(state, writers_absent=True, packet_verified=True, durable_prepared=True, now=now_utc())
                persist_switch(control, state, state["candidate_sha"])
            if state["phase"] == "ROLLBACK_PENDING":
                if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                    return 20
                fixed_helper(control, "Verify", code_root=version_bundle(control, state["previous_sha"]))
                state = rollback_transition(state, writers_absent=True, previous_verified=True, durable_rollback=True, nonce=uuid.uuid4().hex, now=now_utc())
                persist_switch(control, state, state["previous_sha"])
            sha = recovery_sha(state, pointer_sha=pointer["sha"])
            if pointer["sha"] != sha:
                if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                    return 20
                persist_switch(control, state, sha)
    deadline = time.monotonic() + 120
    resumed_rollback = False
    while time.monotonic() < deadline:
        with update_lock(control, policy["operator_sid"]):
            state = read_json(control / "transition.json")
            rows = process_snapshot(control)
            claim = optional_record(stage / "trial.json")
            sha = state["previous_sha"] if state["phase"] == "ROLLBACK_PENDING_READY" else state["candidate_sha"]
            if state.get("trial_pid") is None and claim and claim.get("nonce") == state["nonce"] and claim.get("transition_id") == state["transition_id"]:
                row = next((row for row in rows if row.get("pid") == claim.get("pid")), None)
                if row and process_matches_trial(row, state=state, sha=sha, sid=policy["operator_sid"], role="gui"):
                    state = bind_trial(state, sha=sha, pid=row["pid"], ordinary_user=True, now=row["created_at"])
                    write_json_durable(control / "transition.json", state)
            receipt = optional_record(stage / "ready.json")
            gui = next((row for row in rows if row.get("pid") == state.get("trial_pid")), None)
            relays = [row for row in rows if process_matches_trial(row, state=state, sha=sha, sid=policy["operator_sid"], role="relay")]
            process_ok = bool(gui and process_matches_trial(gui, state=state, sha=sha, sid=policy["operator_sid"], role="gui"))
            if receipt and ready_matches(state, receipt, process_matches=process_ok, relay_matches=len(relays) == 1, now=now_utc()):
                confirmed = confirm_transition(state, receipt, process_matches=process_ok, relay_matches=True, now=now_utc())
                write_json_durable(control / "transition.json", confirmed)
                record_confirmed_policy(control, confirmed)
                return 0
            if state.get("trial_pid") and gui is None:
                break
        time.sleep(0.25)
    with update_lock(control, policy["operator_sid"]):
        state = read_json(control / "transition.json")
        if state["phase"] == "ROLLBACK_PENDING_READY":
            write_json_durable(control / "transition.json", {**state, "phase": "FAILED", "reason": "previous version readiness failed"})
            return 20
        state = request_rollback(state, reason="candidate startup failed or readiness timed out")
        write_json_durable(control / "transition.json", state)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        with update_lock(control, policy["operator_sid"]):
            if not writer_processes(process_snapshot(control), own_pid=os.getpid()):
                old_bundle = version_bundle(control, state["previous_sha"])
                fixed_helper(control, "Verify", code_root=old_bundle)
                rollback = rollback_transition(state, writers_absent=True, previous_verified=True, durable_rollback=True, nonce=uuid.uuid4().hex, now=now_utc())
                persist_switch(control, rollback, state["previous_sha"])
                # Resume the same task state rather than recursively preparing.
                resumed_rollback = True
                break
        time.sleep(0.25)
    if resumed_rollback:
        return apply_prepared(control)
    write_json_durable(control / "transition.json", {**state, "phase": "UNKNOWN", "reason": "candidate normal stop could not be proven"})
    return 20


@writer_sink("auto_update_control")
def create_protected_stage(path: Path) -> None:
    _assert_no_reparse_components(path)
    path.mkdir()


@writer_sink("auto_update_control")
def extract_prepared_code(packet: Path, target: Path, archive_policy: Mapping[str, Any]) -> None:
    from update_service import safe_extract_update_zip

    # A short SYSTEM control admission delegates only extraction, and releases
    # before the ordinary-user GUI/relay waits for readiness.
    safe_extract_update_zip(packet, target, archive_policy=archive_policy)


@writer_sink("auto_update_control")
def copy_prepared_file(source: Path, target: Path, *, expected_owner_sid: str | None = None) -> None:
    import shutil

    _assert_no_reparse_components(source)
    _assert_no_reparse_components(target)
    with unredirected_source(source, expected_owner_sid=expected_owner_sid) as incoming:
        if os.fstat(incoming.fileno()).st_size > (512 * 1024 * 1024 if source.name == "packet.zip" else 1024 * 1024):
            raise ValueError("prepared input is oversized")
        with target.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing)
            outgoing.flush()
            os.fsync(outgoing.fileno())


@contextmanager
def unredirected_source(source: Path, *, expected_owner_sid: str | None = None):
    """Hold every parent and reject redirected/hardlinked SYSTEM input."""
    _assert_no_reparse_components(source)
    if os.name != "nt":
        with source.open("rb") as incoming:
            if os.fstat(incoming.fileno()).st_nlink != 1:
                raise ValueError("prepared input has multiple hardlinks")
            yield incoming
        return
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileInformation(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("created", wintypes.FILETIME), ("accessed", wintypes.FILETIME), ("written", wintypes.FILETIME), ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD), ("size_low", wintypes.DWORD), ("links", wintypes.DWORD), ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInformation)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    handles = []
    try:
        paths = [*reversed(source.absolute().parents), source.absolute()]
        for index, path in enumerate(paths):
            leaf = index == len(paths) - 1
            # Sharing neither write nor delete closes the check/open race for
            # the leaf and every ancestor, including directory reparse edits.
            handle = kernel.CreateFileW(str(path), 0x80000000 if leaf else 0x80, 1, None, 3, 0x00200000 | (0x02000000 if not leaf else 0x08000000), None)
            if handle in (None, ctypes.c_void_p(-1).value):
                raise OSError(ctypes.get_last_error(), "prepared input cannot be held read-only")
            handles.append(handle)
            info = FileInformation()
            if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
                raise OSError(ctypes.get_last_error(), "prepared input handle cannot be observed")
            if info.attributes & 0x400 or bool(info.attributes & 0x10) == leaf:
                raise ValueError("prepared input is redirected or has an unexpected type")
            if leaf and info.links != 1:
                raise ValueError("prepared input has multiple hardlinks")
        if expected_owner_sid is not None:
            advapi = ctypes.WinDLL("advapi32", use_last_error=True)
            advapi.GetSecurityInfo.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID)]
            advapi.GetSecurityInfo.restype = wintypes.DWORD
            advapi.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
            owner, descriptor, text = wintypes.LPVOID(), wintypes.LPVOID(), wintypes.LPWSTR()
            try:
                if advapi.GetSecurityInfo(handles[-1], 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(descriptor)):
                    raise OSError("prepared input owner cannot be observed")
                if not advapi.ConvertSidToStringSidW(owner, ctypes.byref(text)) or text.value != expected_owner_sid:
                    raise ValueError("prepared input is not owned by the installed operator")
            finally:
                if text:
                    kernel.LocalFree(text)
                if descriptor:
                    kernel.LocalFree(descriptor)
        fd = msvcrt.open_osfhandle(int(handles[-1]), os.O_RDONLY | os.O_BINARY | getattr(os, "O_NOINHERIT", 0))
        handles.pop()  # The Python stream owns the leaf handle from here.
        with os.fdopen(fd, "rb") as incoming:
            yield incoming
    finally:
        for handle in reversed(handles):
            kernel.CloseHandle(handle)


@writer_sink("auto_update_control")
def preserve_candidate_version(source: Path, target: Path) -> None:
    _assert_no_reparse_components(target)
    if target.exists():
        from update_service import file_sha256

        def inventory(root):
            values = {}
            for path in root.rglob("*"):
                _assert_no_reparse_components(path)
                if path.is_file() and path.name != "bootstrap-integrity.json":
                    values[path.relative_to(root).as_posix()] = file_sha256(path)
            return values
        if inventory(source) != inventory(target):
            raise ValueError("a version folder already has different bytes; preserve it for recovery")
        return  # Reuse only an independently verified, byte-identical version.
    os.rename(source, target)


def current_process_sid() -> str:
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    token, needed, sid_text = wintypes.HANDLE(), wintypes.DWORD(), wintypes.LPWSTR()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise OSError("update operator token cannot be observed")
    try:
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not 0 < needed.value < 65536:
            raise ValueError("update operator token is malformed")
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed.value, ctypes.byref(needed)):
            raise OSError("update operator SID cannot be observed")
        sid = ctypes.cast(buffer, ctypes.POINTER(wintypes.LPVOID)).contents
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise OSError("update operator SID cannot be formatted")
        return sid_text.value
    finally:
        if sid_text:
            kernel.LocalFree(sid_text)
        kernel.CloseHandle(token)


def ordinary_user_context(operator_sid: str | None = None) -> bool:
    from current_user_onboarding import _inspect_current_process_execution_context

    context = _inspect_current_process_execution_context()
    return context.get("status") == "PASS" and context.get("token_elevated") is False and context.get("integrity_level") == "MEDIUM" and (operator_sid is None or current_process_sid() == operator_sid)


def runtime_matches(app_root: Path) -> bool:
    executable = os.path.normcase(os.path.abspath(sys.executable))
    return executable in {os.path.normcase(str(app_root.parent / "runtime" / name)) for name in ("python.exe", "pythonw.exe")}


def assert_version_writer(app_root: Path, *, source: str, environ: Mapping[str, str]) -> None:
    """Fence old tools too; deployment delegation is checked by the caller."""
    if source == "auto_update_control":
        return
    control = control_root(app_root)
    if control is None:
        return
    if not runtime_matches(app_root):
        raise ValueError("writer must use its protected packet runtime")
    if not ordinary_user_context(read_json(control / "policy.json")["operator_sid"]):
        raise ValueError("writer is not the installed ordinary operator")
    state = optional_record(control / "transition.json")
    active = read_json(control / "active.json")
    own_sha = _sha(read_json(app_root.parent / "portable-manifest.json").get("source_commit"))
    if own_sha != active["sha"]:
        raise ValueError("writer code is not the active version")
    if state and state["phase"] not in {"CONFIRMED", "ROLLED_BACK", "DEFERRED"}:
        cleanup_sources = {"gui_settings_save", "event_outbox_stage", "event_outbox_project", "event_interprocess_lock", "event_csv_append", "event_csv_unlocked_append", "event_csv_idempotent_append", "persistent_relay_status"}
        if (state["phase"] in {"ROLLBACK_PENDING", "UNKNOWN", "FAILED"} and source in cleanup_sources
                and environ.get("KMTECH_CA_UPDATE_TRIAL_NONCE") == state.get("nonce")
                and (source == "persistent_relay_status" or state.get("trial_pid") == os.getpid())):
            return  # Only the bound trial's ordinary flush/close may finish.
        if state["phase"] not in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"} or environ.get("KMTECH_CA_UPDATE_TRIAL_NONCE") != state.get("nonce"):
            raise ValueError("writer denied by the startup transition")


def trial_context(app_root: Path) -> tuple[Path, dict[str, Any], dict[str, Any]] | None:
    control = control_root(app_root)
    if control is None:
        return None
    state = optional_record(control / "transition.json")
    if not state or state.get("phase") not in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY", "ROLLBACK_PENDING", "UNKNOWN", "FAILED"}:
        return None
    own_sha = version_manifest(app_root.parent)["source_commit"]
    expected = state.get("trial_sha") or (state["previous_sha"] if state["phase"] == "ROLLBACK_PENDING_READY" or state.get("rollback_at") else state["candidate_sha"])
    if own_sha != expected or os.environ.get("KMTECH_CA_UPDATE_TRIAL_NONCE") != state.get("nonce"):
        return None
    return control, read_json(control / "policy.json"), state


def prepared_pending(control: Path, policy: Mapping[str, Any], state: Mapping[str, Any] | None) -> bool:
    if not policy.get("feed_url"):
        return False
    path = Path(policy["staging_root"]) / "prepared.json"
    try:
        marker = optional_record(path)
    except (OSError, ValueError):
        return path.exists()  # A corrupt hint still requests SYSTEM verification.
    if marker is None:
        return False
    try:
        sha = _sha(marker.get("source_commit"))
    except ValueError:
        return True
    active = read_json(control / "active.json")
    return sha != active["sha"] and sha not in (state or {}).get("failed_shas", [])


def prepare_feed_packet(app_root: Path) -> dict[str, Any]:
    """The ordinary relay downloads; only completed authenticated bytes are marked."""
    from urllib.parse import urlsplit, urlunsplit
    import requests
    from update_service import verify_update_manifest_signature, update_candidate_from_private_manifest, file_sha256
    from current_user_onboarding import resolve_current_user_onboarding_paths, _default_profile_loader

    control = control_root(app_root)
    if control is None:
        return {"status": "OFF"}
    policy = read_json(control / "policy.json")
    if not policy.get("feed_url"):
        return {"status": "OFF"}
    key = read_json(control.parent / "current/app/update-manifest-key-config.json")["manifest_public_key"]
    active = read_json(control / "active.json")
    current = version_manifest(version_bundle(control, active["sha"]))
    profile = _default_profile_loader(resolve_current_user_onboarding_paths(app_root).logistics_profile_path) if policy.get("profile_auth") else None
    feed = urlsplit(policy["feed_url"])
    origin = lambda url: (url.scheme.lower(), (url.hostname or "").lower(), url.port or 443)
    if profile is not None and origin(feed) != origin(urlsplit(profile.base_url)):
        raise ValueError("profile authentication requires the configured authority origin")
    def fetch(session, url):
        session.cookies.clear()
        headers = {"Authorization": "Bearer " + profile.bearer_token} if profile is not None and origin(urlsplit(url)) == origin(feed) else {}
        response = session.get(url, headers=headers, timeout=10, stream=True, allow_redirects=False, verify=(profile.tls_ca_bundle_path or True) if profile is not None else True)
        if response.status_code != 200:
            response.close()
            raise ValueError("update download HTTP status differs")
        return response
    def bounded(response, maximum):
        with response:
            chunks = []
            count = 0
            for chunk in response.iter_content(65536):
                count += len(chunk)
                if count > maximum:
                    raise ValueError("update metadata is oversized")
                chunks.append(chunk)
            return b"".join(chunks)
    with requests.Session() as session:
        session.trust_env = False  # No ambient proxy/netrc credentials.
        manifest_bytes = bounded(fetch(session, policy["feed_url"]), 1024 * 1024)
        manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
        signature_url = urlunsplit((feed.scheme, feed.netloc, feed.path + ".sig", feed.query, ""))
        signature = bounded(fetch(session, signature_url), 16384)
        verify_update_manifest_signature(manifest, signature, key)
        candidate = update_candidate_from_private_manifest(manifest, current_version=current["version"], expected_channel=policy["channel"])
        if candidate is None:
            return {"status": "NO_UPDATE"}
        if candidate["archive_policy"].get("layout") != "canonical_portable":
            raise ValueError("daily updates require the canonical portable layout")
        sha = _sha(manifest.get("source_commit"))
        state = optional_record(control / "transition.json")
        if sha in (state or {}).get("failed_shas", []):
            return {"status": "FAILED_VERSION_PRESERVED", "source_commit": sha}
        stage = Path(policy["staging_root"])
        existing = optional_record(stage / "prepared.json")
        if existing and existing.get("source_commit") == sha and existing.get("packet_sha256") == candidate["sha256"]:
            return {"status": "PREPARED", "source_commit": sha}
        create_download_stage(stage)
        attempt = stage / ("download-" + uuid.uuid4().hex)
        create_protected_stage(attempt)
        write_download_bytes(attempt / "manifest.json", manifest_bytes)
        write_download_bytes(attempt / "manifest.sig", signature)
        write_download_bytes(attempt / "packet.zip", b"")
        count = 0
        with fetch(session, candidate["download_url"]) as response:
            for chunk in response.iter_content(256 * 1024):
                count += len(chunk)
                if count > min(manifest["artifact"]["size_bytes"], 512 * 1024 * 1024):
                    raise ValueError("update packet is oversized")
                write_download_chunk(attempt / "packet.zip", chunk)
        if count != manifest["artifact"]["size_bytes"] or file_sha256(attempt / "packet.zip") != candidate["sha256"]:
            raise ValueError("downloaded packet size or SHA256 differs")
        # Final fixed-name copies are replaced only after every byte is verified.
        publish_download(attempt, stage)
        write_json_durable(stage / "prepared.json", {"source_commit": sha, "packet_sha256": candidate["sha256"], "prepared_at": now_utc()})
        return {"status": "PREPARED", "source_commit": sha}


@writer_sink("auto_update_control")
def create_download_stage(path: Path) -> None:
    _assert_no_reparse_components(path)
    path.mkdir(parents=True, exist_ok=True)


@writer_sink("auto_update_control")
def write_download_bytes(path: Path, data: bytes) -> None:
    _assert_no_reparse_components(path)
    with path.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


@writer_sink("auto_update_control")
def write_download_chunk(path: Path, data: bytes) -> None:
    _assert_no_reparse_components(path)
    with path.open("ab") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


@writer_sink("auto_update_control")
def publish_download(attempt: Path, stage: Path) -> None:
    import shutil

    for name in ("manifest.json", "manifest.sig", "packet.zip"):
        temporary = stage / (name + "." + uuid.uuid4().hex + ".tmp")
        copy_prepared_file(attempt / name, temporary)
        os.replace(temporary, stage / name)


def trial_stop_requested(app_root: Path) -> bool:
    context = trial_context(app_root)
    return bool(context and context[2]["phase"] in {"ROLLBACK_PENDING", "UNKNOWN", "FAILED"})


def relay_ready_metadata(app_root: Path) -> dict[str, Any]:
    context = trial_context(app_root)
    if context is None:
        return {}
    _, _, state = context
    return {"process_id": os.getpid(), "source_commit": version_manifest(app_root.parent)["source_commit"], "update_nonce": state["nonce"], "ordinary_user": ordinary_user_context()}


def publish_gui_ready(app_root: Path) -> bool:
    """User-only readback; SYSTEM sees booleans, never identities or credentials."""
    import sqlite3
    from current_user_onboarding import resolve_current_user_onboarding_paths, inspect_current_user_state
    from user_relay import user_relay_status_path

    context = trial_context(app_root)
    if context is None:
        return True
    control, policy, state = context
    paths = resolve_current_user_onboarding_paths(app_root)
    if not ordinary_user_context() or inspect_current_user_state(paths).get("status") != "READY":
        return False
    # Read both existing durable queues without creating or migrating them.
    for database in (paths.ledger_path, paths.queue_dir / "direct_sync_relay.sqlite3"):
        _assert_no_reparse_components(database)
        if not database.is_file():
            return False
        try:
            with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
                if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    return False
        except sqlite3.Error:
            return False
    for path in paths.events_dir.glob("_current_tray_state_*.json"):
        read_json(path)
    for path in (paths.data_root / "parked_trays").rglob("*.json"):
        read_json(path)
    for path in (paths.events_dir / "_event_outbox").glob("*.json"):
        read_json(path)
    for path in paths.queue_dir.glob("*.json"):
        read_json(path)
    relay = optional_record(user_relay_status_path(paths.direct_sync_root))
    sha = version_manifest(app_root.parent)["source_commit"]
    if not relay or relay.get("status") != "RUNNING" or relay.get("source_commit") != sha or relay.get("update_nonce") != state["nonce"] or relay.get("ordinary_user") is not True:
        return False
    payload = {
        **{check: True for check in READY_CHECKS}, "pid": os.getpid(), "sha": sha,
        "nonce": state["nonce"], "transition_id": state["transition_id"], "ready_at": now_utc(),
    }
    write_json_durable(Path(policy["staging_root"]) / "ready.json", payload)
    return True


def startup_gate(app_root: Path, arguments: list[str], *, role: str = "gui") -> int | None:
    if arguments[:1] in (["--container-audit-user-relay"], ["--container-audit-direct-sync-relay"]):
        role = "relay"
    control = control_root(app_root)
    if control is None:
        return None
    if arguments and arguments[0] in {"--onboard-current-user", "--remove-current-user-setup", "--restore-current-user-lifecycle-after-replacement"}:
        return None  # Existing installer admission owns these modes.
    policy = read_json(control / "policy.json")
    if not ordinary_user_context(policy["operator_sid"]):
        return 20
    with update_lock(control, policy["operator_sid"]):
        state = optional_record(control / "transition.json")
        active = read_json(control / "active.json")
        sha = version_manifest(app_root.parent)["source_commit"]
        if sha == active["sha"] and state and state["phase"] in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"}:
            if os.environ.get("KMTECH_CA_UPDATE_TRIAL_NONCE") == state["nonce"] and ordinary_user_context():
                claim = optional_record(Path(policy["staging_root"]) / "trial.json")
                if claim and claim.get("nonce") == state["nonce"] and claim.get("transition_id") == state["transition_id"] and (role == "relay" or claim.get("pid") == os.getpid()):
                    return None
        if sha == active["sha"] and state and state["phase"] == "DEFERRED" and os.environ.get("KMTECH_CA_UPDATE_DEFERRED_AT") == state.get("deferred_at"):
            return None
        prepared = prepared_pending(control, policy, state)
        if not prepared and (not state or state["phase"] in {"CONFIRMED", "ROLLED_BACK", "DEFERRED"}) and sha == active["sha"]:
            return None
    request_bootstrap(control, arguments, role=role)
    return 0


@writer_sink("auto_update_control")
def request_bootstrap(control: Path, arguments: list[str], *, role: str) -> None:
    import subprocess

    root = control.parent / "current"
    subprocess.Popen([str(root / "runtime/pythonw.exe"), "-I", "-B", str(root / "app/auto_update.py"), "--bootstrap", "--role", role, "--", *arguments], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


@writer_sink("auto_update_control")
def request_apply_task(control: Path, policy: Mapping[str, Any]) -> None:
    import subprocess

    executable = system_executable("schtasks.exe")
    result = subprocess.run([executable, "/Run", "/TN", task_name(control.parent / "current", policy["operator_sid"])], capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError("the installed update task could not be requested")


@writer_sink("auto_update_control")
def launch_version(control: Path, sha: str, arguments: list[str], *, nonce: str = "", deferred_at: str = "") -> int:
    import subprocess

    bundle = version_bundle(control, sha)
    if version_manifest(bundle)["source_commit"] != sha:
        raise ValueError("active version identity differs")
    environment = dict(os.environ)
    environment.pop("KMTECH_CA_UPDATE_TRIAL_NONCE", None)
    environment.pop("KMTECH_CA_UPDATE_DEFERRED_AT", None)
    if nonce:
        environment["KMTECH_CA_UPDATE_TRIAL_NONCE"] = _sha(nonce, length=32)
    if deferred_at:
        _utc(deferred_at)
        environment["KMTECH_CA_UPDATE_DEFERRED_AT"] = deferred_at
    process = subprocess.Popen([str(bundle / "runtime/pythonw.exe"), "-I", "-B", str(bundle / "app/main.py"), *arguments], env=environment, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return process.pid


def bootstrap(app_root: Path, arguments: list[str], *, role: str) -> int:
    import time

    control = control_root(app_root)
    if control is None:
        raise ValueError("bootstrap requires the installed ordinary-user context")
    policy = read_json(control / "policy.json")
    if not ordinary_user_context(policy["operator_sid"]):
        raise ValueError("bootstrap requires the installed ordinary operator")
    requested = False
    requested_at = None
    saw_trial = False
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        with update_lock(control, policy["operator_sid"]):
            state = optional_record(control / "transition.json")
            if state and state["phase"] in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"}:
                saw_trial = True
            prepared = prepared_pending(control, policy, state)
            action = startup_action(state, prepared_present=prepared)
            active = read_json(control / "active.json")
            if state and state["phase"] in {"CONFIRMED", "ROLLED_BACK"} and saw_trial:
                return 0  # The already-launched GUI owns input and its ordinary relay.
            if state and state["phase"] == "DEFERRED" and requested_at and _utc(state["deferred_at"]) >= _utc(requested_at):
                launch_version(control, active["sha"], arguments, deferred_at=state["deferred_at"])
                return 0
            if action == "START_CURRENT":
                launch_version(control, active["sha"], arguments)
                return 0
            if action == "REQUEST_TRIAL":
                # Both the Run relay and a launcher request this same GUI trial.
                # The GUI's ordinary onboarding starts its single normal relay.
                with update_lock(control, policy["operator_sid"], trial=True):
                    state = read_json(control / "transition.json")
                    claim = optional_record(Path(policy["staging_root"]) / "trial.json")
                    if claim and claim.get("nonce") == state["nonce"]:
                        saw_trial = True
                    else:
                        gui_arguments = arguments[1:] if role == "relay" and arguments[:1] == ["--container-audit-user-relay"] else arguments
                        pid = launch_version(control, active["sha"], gui_arguments, nonce=state["nonce"])
                        write_json_durable(Path(policy["staging_root"]) / "trial.json", {"pid": pid, "nonce": state["nonce"], "transition_id": state["transition_id"]})
                        root_arguments = []
                        if "--data-root" in gui_arguments:
                            index = gui_arguments.index("--data-root")
                            if index + 1 >= len(gui_arguments):
                                raise ValueError("trial data root argument is absent")
                            root_arguments = gui_arguments[index:index + 2]
                        launch_version(control, active["sha"], ["--container-audit-user-relay", *root_arguments], nonce=state["nonce"])
                        saw_trial = True
            if action in {"REQUEST_APPLY", "WAIT_FOR_RECOVERY", "WAIT_FOR_TRIAL"} and not requested:
                requested_at = now_utc()
                request_apply_task(control, policy)
                requested = True
            if state and state["phase"] in {"UNKNOWN", "FAILED"}:
                return 20
        time.sleep(0.1)
    # The task may be delayed, but a timeout is never permission to launch code
    # through an unresolved transition or to terminate another process.
    return 20


def main(arguments: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--apply-prepared", action="store_true")
    parser.add_argument("--control-root", type=Path)
    parser.add_argument("--role", choices=("gui", "relay"), default="gui")
    parser.add_argument("--print-logon-task", action="store_true")
    parser.add_argument("--install-root", type=Path)
    parser.add_argument("--operator-sid")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args(arguments)
    if options.print_logon_task:
        if options.apply_prepared or options.bootstrap or options.arguments or options.install_root is None:
            raise ValueError("logon task generation arguments differ")
        print(json.dumps(install_task_spec(options.install_root, options.operator_sid)))
        return 0
    if options.apply_prepared:
        if options.bootstrap or options.arguments or options.control_root is None:
            raise ValueError("system updater arguments differ")
        expected = Path(__file__).resolve().parents[2] / "update-control"
        if options.control_root.absolute() != expected:
            raise ValueError("system updater control root differs")
        return apply_prepared(expected)
    if options.bootstrap:
        args = options.arguments[1:] if options.arguments[:1] == ["--"] else options.arguments
        if control_root(Path(__file__).resolve().parent) is None:
            from Container_Audit import main as application_main

            return int(application_main(args) or 0)
        return bootstrap(Path(__file__).resolve().parent, args, role=options.role)
    # Source/old-layout launch remains the ordinary portable main entrypoint.
    from Container_Audit import main as application_main

    return int(application_main(options.arguments) or 0)


if __name__ == "__main__":
    raise SystemExit(main())

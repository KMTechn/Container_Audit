"""Decisions for startup updates; code and business data have separate lifetimes.

The decision functions are pure. The protected bootstrap persists records before
switching a code pointer; business data is never copied or restored here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid
from contextlib import ExitStack, contextmanager
from typing import Any, Mapping

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(1, str(Path(__file__).resolve().parent / "site-packages"))

from writer_session_fence import WriterFencedError, writer_sink, _assert_no_reparse_components
from producer_runtime_client import DEFAULT_PRODUCER_USER_AGENT
from storage_policy import ensure_user_runtime_directory


SCHEMA = "container-audit-startup-update-v1"
APPLY_PROGRESS_TIMEOUT = 120
APPLY_REQUEST_PROGRESS_TIMEOUT = 60
READY_WINDOW_SECONDS = 900
# The bootstrap decision wait must outlast one whole READY window plus the
# normal-stop and settle tail it always had (the former 480 = 240 + 240).
BOOTSTRAP_OBSERVATION_CAP_SECONDS = READY_WINDOW_SECONDS + 240
# A transient failure of one candidate sha gets another chance; the failed
# list (permanent) is only for confirmed rejections.
RETRY_ATTEMPT_LIMIT = 3
RETRY_WINDOW_SECONDS = 24 * 60 * 60
UPDATE_RETRY_REVIEW_REQUIRED = 'UPDATE_RETRY_REVIEW_REQUIRED'
RETRY_REVIEW_MESSAGE = '업데이트를 세 번 시도했지만 끝내지 못했습니다 — 지금 판으로 작업은 그대로 할 수 있습니다 · 하루 뒤 저절로 다시 시도합니다 · 현장 관리자에게 알리세요'
STARTUP_PROGRESS_MESSAGE = '업데이트가 진행 중입니다. 잠시 뒤 다시 시작하세요.'
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
    try:
        return result.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("update time is outside the representable UTC range") from error


def startup_action(
    transition: Mapping[str, Any] | None, *, prepared_present: bool,
) -> str:
    """Inspect both the candidate and the record, including before the task runs."""
    if transition is None:
        return "REQUEST_APPLY" if prepared_present else "START_CURRENT"
    if transition.get("schema") != SCHEMA:
        raise ValueError("startup update record is unsupported")
    phase = transition.get("phase")
    if phase == "DEFERRED" and transition.get("recovery_pending") is True:
        return "WAIT_FOR_RECOVERY"
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
    retry_shas: Mapping[str, Any] | None = None,
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
    prepared = {
        "schema": SCHEMA, "phase": "PREPARED",
        "previous_sha": previous_sha, "candidate_sha": candidate_sha,
        "packet_sha256": _sha(packet_sha256, length=64),
        "forward_pin": _sha(forward_pin, length=64),
        "rollback_pin": _sha(rollback_pin, length=64),
        "transition_id": _sha(transition_id, length=32),
        "nonce": _sha(nonce, length=32), "started_at": now,
        "failed_shas": failures, "trial_pid": None,
    }
    if isinstance(retry_shas, Mapping) and retry_shas:
        prepared["retry_shas"] = dict(retry_shas)
    return prepared


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
    # Retained DEFERRED has no trustworthy timeout-only provenance: the
    # generation decision replaces the original reason, and failed_shas has
    # no transition identity. Keep late READY fail-closed for this schema.
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


def record_retry_chance(transition: Mapping[str, Any], sha: str, *, now: str) -> tuple[dict[str, Any], bool]:
    """Count one transient failure of ``sha``; return the new retry record and
    whether the sha has used up its chances inside the retry window."""
    sha = _sha(sha)
    current = _utc(now)
    entries: dict[str, Any] = {}
    raw = transition.get("retry_shas")
    for key, entry in (raw.items() if isinstance(raw, Mapping) else ()):
        try:
            _sha(key)
            age = (current - _utc(entry["first_at"])).total_seconds()
            if 0 <= age < RETRY_WINDOW_SECONDS and type(entry["attempts"]) is int and entry["attempts"] >= 1:
                _utc(entry["last_at"])
                entries[key] = {"attempts": entry["attempts"], "first_at": entry["first_at"], "last_at": entry["last_at"]}
        except (ValueError, KeyError, TypeError):
            continue
    prior = entries.get(sha)
    attempts = (prior["attempts"] if prior else 0) + 1
    entries[sha] = {"attempts": attempts, "first_at": prior["first_at"] if prior else now, "last_at": now}
    return entries, attempts >= RETRY_ATTEMPT_LIMIT


def _transient_preparation_error(error: BaseException) -> bool:
    """Unknown failures get a bounded retry; only proved rejections are final."""
    return getattr(error, "_preparation_rejection", False) is not True


def _preparation_rejection(message: str) -> ValueError:
    error = ValueError(message)
    error._preparation_rejection = True
    return error


@contextmanager
def _authenticated_preparation(sha: str):
    """Carry only the verified manifest identity through local validation errors."""
    sha = _sha(sha)
    try:
        yield
    except ValueError as error:
        error._preparation_signed_sha = sha
        raise


def _permanent_preparation_sha(error: BaseException) -> str:
    try:
        return _sha(getattr(error, "_preparation_signed_sha", None))
    except ValueError:
        return ""


def _retry_review_required(state: Mapping[str, Any] | None) -> bool:
    entries = (state or {}).get("retry_shas")
    if not isinstance(entries, Mapping) or (state or {}).get("preparation_retry_pending") is True:
        return False
    if (state or {}).get("reason_code") == "UPDATE_PREPARATION_FAILED":
        selected = [entry for entry in entries.values() if isinstance(entry, Mapping)
                    and entry.get("last_at") == state.get("deferred_at")]
    else:
        selected = [entries.get((state or {}).get("candidate_sha"))]
    for entry in selected:
        try:
            if (type(entry["attempts"]) is int and entry["attempts"] >= RETRY_ATTEMPT_LIMIT
                    and 0 <= (_utc(now_utc()) - _utc(entry["first_at"])).total_seconds() < RETRY_WINDOW_SECONDS):
                return True
        except (ValueError, TypeError, KeyError):
            pass
    return False


def _preparation_retry_due(state: Mapping[str, Any] | None, sha: str) -> bool:
    """Use the existing retry journal; restarting cannot reopen its interval."""
    if ((state or {}).get("preparation_retry_pending") is True
            or (not sha and (state or {}).get("reason_code") == "UPDATE_PREPARATION_FAILED")):
        try:
            if (_utc(now_utc()) - _utc(state["deferred_at"])).total_seconds() < READY_WINDOW_SECONDS:
                return False
        except (ValueError, KeyError, TypeError):
            return False  # A malformed protected clock cannot reopen this wait.
    raw = (state or {}).get("retry_shas")
    entry = raw.get(sha) if isinstance(raw, Mapping) else None
    if not isinstance(entry, Mapping):
        return True
    try:
        now = _utc(now_utc())
        age = (now - _utc(entry["first_at"])).total_seconds()
        if not 0 <= age < RETRY_WINDOW_SECONDS:
            return True
        if type(entry["attempts"]) is not int or entry["attempts"] < 1:
            return True
        return (entry["attempts"] < RETRY_ATTEMPT_LIMIT
                and (now - _utc(entry["last_at"])).total_seconds() >= READY_WINDOW_SECONDS)
    except (ValueError, KeyError, TypeError):
        return True  # Match record_retry_chance's handling of invalid entries.


def request_rollback(transition: Mapping[str, Any], *, reason: str, transient: bool = False,
                     now: str | None = None) -> dict[str, Any]:
    if transition.get("phase") != "APPLIED_PENDING_READY":
        raise ValueError("rollback requires a pending trial")
    failures = list(transition.get("failed_shas", []))
    candidate = _sha(transition.get("candidate_sha"))
    extra: dict[str, Any] = {}
    permanent = True
    if transient:
        extra["retry_shas"], _ = record_retry_chance(transition, candidate, now=now or now_utc())
        permanent = False
    if permanent and candidate not in failures:
        failures.append(candidate)
    return {**transition, "phase": "ROLLBACK_PENDING", "reason": str(reason), "failed_shas": failures, **extra}


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
    if transition.get("failure_decision", {}).get("selected_sha") != transition.get("previous_sha"):
        raise ValueError("rollback requires an observed unchanged data generation")
    _utc(now)
    # Pointer restoration alone does not prove that the restored relay is ready.
    # Reuse protocol 1's existing trial phase and its GUI/relay READY contract.
    restored = {**transition, "phase": "ROLLBACK_PENDING_READY", "nonce": _sha(nonce, length=32),
                "trial_pid": None, "trial_sha": None, "trial_started_at": None, "rollback_at": now}
    restored.pop("confirmed_at", None)
    return restored


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
    if phase == "ROLLBACK_PENDING":
        selected = transition.get("failure_decision", {}).get("selected_sha", candidate)
        if selected not in {previous, candidate}:
            raise ValueError("failure decision names another version")
        return selected
    if phase == "DEFERRED" and transition.get("retained_candidate") is True:
        if transition.get("failure_decision", {}).get("selected_sha") != candidate:
            raise ValueError("retained trial decision differs from candidate")
        return candidate
    if phase in {"ROLLBACK_PENDING_READY", "ROLLED_BACK"}:
        return previous
    if phase in {"UNKNOWN", "FAILED"}:
        raise ValueError("unproven recovery must preserve the pointer and stop switching")
    raise ValueError("recovery phase is unsupported")


def read_trial_generation(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Read the ordinary operator's shared commit slot, never SYSTEM's profile."""
    from kmtech_shared import data_generation as generation
    from writer_session_fence import canonical_control_root

    try:
        sid = policy["operator_sid"]
        generation._identity("container_audit", sid)
        local = Path(policy["operator_local_app_data"])
        if not local.is_absolute():
            raise ValueError("operator profile is not absolute")
        path = canonical_control_root({"LOCALAPPDATA": str(local)}) / "data-generation" / (sid + ".json")
        record = generation._read(path, "container_audit", sid)
        return {"status": "READ", "marker_path": str(path), "record": record}
    except (OSError, ValueError, TypeError, KeyError, generation.DataGenerationError):
        return {"status": "UNKNOWN"}


def decide_trial_failure(transition: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    """After normal writer stop, choose once from actual generation readback.

    The caller durably publishes this decision before changing any pointer.
    Both GUI and relay trials share this boundary; READY is never a G proxy.
    """
    from kmtech_shared import data_generation as generation

    if transition.get("phase") != "ROLLBACK_PENDING":
        raise ValueError("trial failure requires a normal-stop request")
    if transition.get("failure_decision") is not None:
        return dict(transition)
    before = transition.get("generation_before", {"status": "UNKNOWN"})
    after = read_trial_generation(policy)
    previous = transition.get("generation_previous_release", {})
    candidate = transition.get("generation_candidate_release", {})
    statuses = {}
    for name, release in (("previous", previous), ("candidate", candidate)):
        statuses[name] = generation.probe_downgrade(
            [after["marker_path"]] if after.get("status") == "READ" else [],
            release.get("version"), app_id="container_audit",
            subject_sid=policy.get("operator_sid"), target_build_id=release.get("source_commit"),
        )["status"]
    # An I/O race is uncertainty, even if a separate guard probe succeeded.
    stable = after == read_trial_generation(policy)
    unchanged = (stable and before.get("status") == after.get("status") == "READ"
                 and before == after and statuses["previous"] == "ALLOW")
    code = "TRIAL_GENERATION_UNCHANGED" if unchanged else "TRIAL_GENERATION_UNKNOWN"
    record = after.get("record") or {}
    if (not unchanged and stable and before.get("status") == after.get("status") == "READ"
            and record.get("build_id") == candidate.get("source_commit")
            and record.get("version") == candidate.get("version")):
        code = "TRIAL_GENERATION_ADVANCED"
    selected = transition["previous_sha"] if unchanged else transition["candidate_sha"]
    decision = {"before": before, "after": after, "previous_status": statuses["previous"],
                "candidate_status": statuses["candidate"], "selected_sha": selected,
                "code": code, "ready_result": "FAILED", "decided_at": now_utc()}
    state = {**transition, "failure_decision": decision}
    if not unchanged:
        state = {**state, "phase": "DEFERRED", "retained_candidate": True,
                 "deferred_at": now_utc(), "reason": code}
    return state


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


def manifest_transition_pins(manifest: Mapping[str, Any], *, current: Mapping[str, Any], candidate: Mapping[str, Any]) -> tuple[str, str, dict[str, str], str]:
    """Only call after authentication of this complete manifest and packet."""
    result = authorize_feed_transition(manifest, current=current, candidate=candidate)
    pair = result["pair"]
    return pair["forward_contract_sha256"], pair["rollback_contract_sha256"], result["rollback"], result["authority"]


CONTRACT_FILES = ("tools/container_writer_session_contract.json", "tools/container_writer_sink_inventory.json")


def source_version_literal(source: bytes) -> str:
    """Build consistency only; release authority is the signed manifest."""
    try:
        tree = ast.parse(source.decode("utf-8-sig"))
    except (UnicodeError, SyntaxError, ValueError) as error:
        raise ValueError("daily_update_actual_version_invalid") from error
    values = []
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        if any(isinstance(target, ast.Name) and target.id == "CURRENT_VERSION" for target in targets):
            values.append(node.value)
    if (len(values) != 1 or not isinstance(values[0], ast.Constant) or not isinstance(values[0].value, str)
            or re.fullmatch(r"v[0-9]+(?:\.[0-9]+){2,3}", values[0].value) is None):
        raise ValueError("daily_update_actual_version_invalid")
    return values[0].value


def version_identity(read_bytes) -> dict[str, Any]:
    """Hash actual portable bytes without importing or executing candidate code."""
    portable = json.loads(read_bytes("portable-manifest.json").decode("utf-8-sig"), object_pairs_hook=unique_object)
    if not isinstance(portable, dict) or portable.get("schema") != "container-audit-portable-tree-v1":
        raise ValueError("daily_update_requires_stock_portable_packet")
    version = portable.get("version")
    if not isinstance(version, str) or re.fullmatch(r"v[0-9]+(?:\.[0-9]+){2,3}", version) is None:
        raise ValueError("daily_update_stock_version_record_missing: 설치 판 번호 기록이 없는 옛 설치 파일입니다. 새 설치 파일로 지원 재설치를 진행하세요.")
    if source_version_literal(read_bytes("app/Container_Audit.py")) != version:
        raise ValueError("daily_update_stock_version_literal_mismatch")
    hashes = []
    for names in (CONTRACT_FILES, tuple("app/" + name for name in DATA_API_FILES)):
        digest = hashlib.sha256()
        for name in names:
            digest.update((name + "\n").encode("ascii"))
            digest.update(hashlib.sha256(read_bytes(name)).digest())
        hashes.append(digest.hexdigest())
    return dict(source_commit=_sha(portable.get("source_commit")), version=version,
                contract_sha256=hashes[0], data_api_contract_sha256=hashes[1])


def authorize_feed_transition(manifest: Mapping[str, Any], *, current: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Shared user/SYSTEM rule after installed-key signature and ZIP verification."""
    pair = manifest.get("auto_update")
    if not isinstance(pair, dict) or set(pair) != {"from_commit", "to_commit", "forward_contract_sha256", "rollback_contract_sha256"}:
        raise ValueError("invalid_bidirectional_update_pair")
    for name, value in pair.items():
        _sha(value, length=40 if name.endswith("commit") else 64)
    if pair["from_commit"] == pair["to_commit"]:
        raise ValueError("update_pair_same_commit")
    if pair["from_commit"] != _sha(current.get("source_commit")):
        raise ValueError("daily_update_from_commit_mismatch")
    if pair["to_commit"] != _sha(candidate.get("source_commit")):
        raise ValueError("daily_update_packet_commit_mismatch")
    if manifest.get("version") != candidate.get("version"):
        raise ValueError("daily_update_signed_version_mismatch")
    ordered = []
    for version in (current.get("version"), manifest.get("version")):
        if not isinstance(version, str) or re.fullmatch(r"v[0-9]+(?:\.[0-9]+){2,3}", version) is None:
            raise ValueError("daily_update_actual_version_invalid")
        parts = tuple(int(part) for part in version[1:].split("."))
        ordered.append(parts + (0,) * (4 - len(parts)))
    if ordered[1] <= ordered[0]:
        raise ValueError("daily_update_version_must_increase")
    forward = dict(from_commit=pair["from_commit"], to_commit=pair["to_commit"],
                   from_contract_sha256=_sha(current.get("contract_sha256"), length=64),
                   to_contract_sha256=_sha(candidate.get("contract_sha256"), length=64))
    reverse = dict(from_commit=forward["to_commit"], to_commit=forward["from_commit"],
                   from_contract_sha256=forward["to_contract_sha256"], to_contract_sha256=forward["from_contract_sha256"])
    approvals = manifest.get("approved_transitions")
    if not isinstance(approvals, list) or len(approvals) != 2 or forward not in approvals or reverse not in approvals:
        raise ValueError("daily_update_signed_exact_pair_required")
    for name, direction in (("forward_contract_sha256", forward), ("rollback_contract_sha256", reverse)):
        actual = directional_pin(approvals, **direction)
        if pair[name] != actual:
            raise ValueError("daily_update_direction_contract_mismatch")
    previous = _sha(current.get("data_api_contract_sha256"), length=64)
    target = _sha(candidate.get("data_api_contract_sha256"), length=64)
    return {"pair": dict(pair), "authority": "SIGNED_EXACT_PAIR", "rollback": reverse,
            "evidence": {"previous_data_api_sha256": previous, "candidate_data_api_sha256": target,
                         "consumer_bytes_equal": previous == target}}


DATA_API_FILES = (
    "contract.lock.json", "tray_state.py", "event_contracts.py",
    "event_log_store.py", "transfer_store.py", "transfer_common.py",
    "transfer_client.py", "producer_runtime_client.py", "direct_sync_push.py",
    "logistics_runtime_profile.py", "storage_policy.py", "recovery_two_phase.py",
    # Actual DDL, serialized commands, state migration and recovery consumers.
    "transfer_member_exchange.py", "terminal_operation_lease.py",
    "direct_sync_operator.py", "tools/direct_sync_relay_runner.py",
    "event_payloads.py", "event_stream_policy.py", "Container_Audit.py",
    "user_relay.py", "current_user_onboarding.py", "work_session_state.py",
    "tray_completion.py", "product_exchange.py", "product_scan.py",
    "parked_tray_store.py", "paired_preflight_handoff.py", "phs_reconciliation_workflow.py",
    "phs_label_workflow.py", "preflight_scan_hold.py", "session_history.py",
    "storage_utils.py", "recovery_file_read.py", "legacy_state_migration.py",
    "worker_registry.py", "protected_admin.py", "container_admin_pin.py", "pin_file_move.py",
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
    for attempt in range(3):
        try:
            if path.stat().st_size > maximum:
                raise ValueError("update record is oversized")
            with path.open("r", encoding="utf-8-sig") as source:
                value = json.load(source, object_pairs_hook=unique_object)
            break
        except PermissionError:
            if attempt == 2:
                raise
            time.sleep(0.05)
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
    from atomic_replace import atomic_replace
    _assert_no_reparse_components(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    # Policy/prepared/readiness bytes remain machine metadata. Only the mixed
    # transition and failure records contain free diagnostic fields.
    if path.name == "transition.json" or path.name.startswith("failure-"):
        payload = mixed_status_record(payload)
    text = (serialize_json_for_sink(payload) if path.name.startswith("failure-")
            else serialize_machine_metadata(payload))
    with temporary.open("x", encoding="utf-8", newline="\n") as output:
        output.write(text + "\n")
        output.flush()
        os.fsync(output.fileno())
    atomic_replace(temporary, path, write_through=True)


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


def _sink_policy() -> dict:
    return {"environment_names": frozenset(("DEFECT_FINAL_DEFECT_CLAIM_TOKEN", "DEFECT_FINAL_DEFECT_INTAKE_CLAIM_TOKEN", "DEFECT_LINKED_MANIFEST_LOCK_API_TOKEN", "DEFECT_LOGISTICS_API_TOKEN", "DEFECT_RETURN_MANIFEST_API_TOKEN", "DEFECT_SERVER_ACTIVE_LOCK_TOKEN", "DEFECT_TRANSFER_MANIFEST_API_TOKEN", "INSPECTION_WORKER_WAREHOUSE_RESPONSE_EXPORT_TOKEN", "KMTECH_DEFECT_WRITER_DELEGATION_TOKEN", "KMTECH_REWORK_TEMP_NG_CANDIDATE_TOKEN", "KMTECH_REWORK_TEMP_NG_CLAIM_TOKEN", "REWORK_ENROLLMENT_RESTORE_TOKEN", "REWORK_LOGISTICS_API_TOKEN", "CONTAINER_AUDIT_ENROLLMENT_TOKEN", "CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN", "CONTAINER_RUNTIME_SECRET", "KM_LOGISTICS_INSTALL_BEARER_TOKEN", "WORKER_ANALYSIS_LOGISTICS_API_TOKEN", "KMTECH_LABEL_WRITER_DELEGATION_TOKEN", "PRODUCER_SELF_ENROLL_TOKEN", "DIRECT_SYNC_AUTH_TOKEN", "PRODUCER_API_TOKEN", "LOGISTICS_API_TOKEN")),
            "sensitive_pattern": r"(?i)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|API_?KEY|COOKIE|SESSION_?KEY|DELEGATION|BEARER|ENROLLMENT_CODE|RESTORE_CODE|ADMIN_PIN)",
            "path_pattern": r"(?i)_(FILE|PATH|DIR|ROOT)$", "digest_pattern": r"(?i)_(sha256s?|fingerprint|hash)$", "short_digest_pattern": r"(?i)(pin|otp|password)", "env_marker": "[REDACTED:{name}]", "field_marker": "[REDACTED:field]",
            "compatibility_field_pattern": r"(?i)^(authorization|registration[_-]?(?:value|code))$",
            "diagnostic_fields": frozenset(("failure", "message", "detail", "stdout", "stderr", "stdout_tail", "stderr_tail")),
            "identifier_name_pattern": r"(?i)_(TRANSACTION|SESSION|ATTEMPT)_ID$",
            "identifier_value_pattern": r"(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})",
            "process_identifier_patterns": {
                r"(?i)_PID\Z": r"[1-9][0-9]{0,9}",
                r"(?i)_START\Z": r"(?:windows-filetime|linux-startticks):[1-9][0-9]{0,24}",
                r"(?i)_MUTEX\Z": r"(?:Local|Global)\\[A-Za-z0-9._-]{1,200}",
            },
            "short_marker": "[REDACTION_NOTE:short_value_skipped:{name}]", "full_byte_cap": 65536, "head_byte_cap": 8192,
            "truncation_marker": "\n[TRUNCATED: {omitted} bytes omitted]\n"}


def _structured_value_end(text: str, start: int) -> int:
    """Consume a bracketed sensitive value; incomplete records fail closed."""
    stack, quote, escaped = [], None, False
    index = start
    while index < len(text):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                if quote == "'" and index + 1 < len(text) and text[index + 1] == quote:
                    index += 1
                else:
                    quote = None
        elif char in "\"'":
            quote = char
        elif char in "{[":
            stack.append("}" if char == "{" else "]")
        elif char in "}]":
            if not stack or char != stack.pop():
                return len(text)
            if not stack:
                return index + 1
        index += 1
    return len(text)


def _known_value_pattern(value: str) -> str:
    """Match literal/mixed JSON spellings, including nested string escapes."""
    parts = []
    for character in value:
        units = character.encode("utf-16-be", errors="surrogatepass").hex()
        forms = {character, json.dumps(character, ensure_ascii=False)[1:-1],
                 "".join("\\u" + units[i:i + 4] for i in range(0, len(units), 4))}
        if character == "/":
            forms.add("\\/")
        for _ in range(3):
            forms.update(json.dumps(form, ensure_ascii=False)[1:-1] for form in tuple(forms))
        choices = []
        for form in forms:
            start, chunks = 0, []
            for match in re.finditer(r"\\+u([0-9a-f]{4})", form):
                chunks.append(re.escape(form[start:match.end() - 4]))
                chunks.append("".join("[" + digit + digit.upper() + "]" if digit in "abcdef" else digit
                                      for digit in match.group(1)))
                start = match.end()
            chunks.append(re.escape(form[start:]))
            choices.append("".join(chunks))
        parts.append("(?:" + "|".join(sorted(choices, key=len, reverse=True)) + ")")
    return "".join(parts)


def _assert_final_known_values(text: str, selected) -> str:
    # Notes and truncation metadata are generated after the replacement pass.
    if any(re.search(_known_value_pattern(value), text)
           for _, value in selected if len(value) >= 4):
        raise ValueError("REPORT_UNAVAILABLE")
    return text


def _redact_known_values(text: str, selected, policy) -> str:
    patterns = [(_known_value_pattern(value), policy["env_marker"].format(name=name))
                for name, value in selected]
    for pattern, marker in sorted(patterns, key=lambda item: len(item[0]), reverse=True):
        text = re.sub(pattern, lambda match: marker, text)
    if any(re.search(pattern, text) for pattern, _ in patterns):
        raise ValueError("REPORT_UNAVAILABLE")
    return text


def redact_for_sink(text: str, environ: Mapping[str, str] = os.environ, *, limit: int = 65536, _no_truncate: bool = False, _known_only: bool = False, _check_only: bool = False) -> str:
    policy = _sink_policy()
    text = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else str(text or "")
    selected, notes = [], []
    # Enumeration is internal to the redactor; no environment is emitted.
    for name, value in sorted(environ.items()):
        if name in policy["environment_names"] or (re.search(policy["sensitive_pattern"], name) and not re.search(policy["path_pattern"], name)):
            if (name not in policy["environment_names"]
                    and ((re.search(policy["identifier_name_pattern"], name)
                          and re.fullmatch(policy["identifier_value_pattern"], str(value)))
                         or any(re.search(pattern, name) and re.fullmatch(shape, str(value))
                                for pattern, shape in policy["process_identifier_patterns"].items()))):
                continue
            if not value:
                continue
            if _is_short_secret_value(value):
                notes.append(policy["short_marker"].format(name=name))
            else:
                selected.append((name, value))
    if _check_only:
        return _assert_final_known_values(text, selected)
    for name, value in sorted(selected, key=lambda item: (-len(item[1]), item[0])):
        variants = {value, json.dumps(value, ensure_ascii=True)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1], value.replace("'", "''"), value.replace('"', '""')}
        for variant in sorted(variants, key=len, reverse=True):
            text = text.replace(variant, policy["env_marker"].format(name=name))
    if _known_only:
        return _redact_known_values(text, selected, policy)
    # Field values are removed as a whole, before any head/tail selection.
    def redact_fields(value):
        if isinstance(value, dict):
            return {key: policy["field_marker"] if _redact_field(key, item, policy)
                    else redact_fields(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact_fields(item) for item in value]
        if isinstance(value, str):
            return redact_for_sink(value, {}, _no_truncate=True)
        return value
    try:
        parsed = json.loads(text)
        changed = redact_fields(parsed)
        if changed != parsed:
            text = json.dumps(changed, ensure_ascii=True)
    except (ValueError, TypeError):
        pass
    # Zero-width discovery does not consume an exception/mapping prefix as a
    # non-sensitive assignment and miss a sensitive assignment inside its value.
    assignments = r'''(?=(?<![\w"'])(?P<quote>["']?)(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)\s*[:=]\s*(?P<value>"(?:\\.|[^"\\])*(?:"|$)|'(?:''|\\.|[^'\\])*(?:'|$)|[^\s,;}\]"']+))'''
    spans = []
    for match in re.finditer(assignments, text):
        raw = match.group("value")
        if raw.startswith("[REDACTED:"):
            continue
        value = {"true": True, "false": False, "null": None}.get(raw, raw)
        if _redact_field(match.group("key"), value, policy):
            start, end = match.span("value")
            replacement = policy["field_marker"]
            if raw[0] in "{[":
                end = _structured_value_end(text, start)
                if match.group("quote"):
                    replacement = json.dumps(replacement)
            # Quoted mappings retain their value delimiters; the whole value
            # is still redacted before bounding, including exception prefixes.
            if match.group("quote") and len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
                start, end = start + 1, end - 1
            spans.append((start, end, replacement))
    # Sensitive values can contain another assignment; redact the outer span.
    merged = []
    for start, end, replacement in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end), merged[-1][2])
        else:
            merged.append((start, end, replacement))
    for start, end, replacement in reversed(merged):
        text = text[:start] + replacement + text[end:]
    # Repeat known-value replacement after all parse/serialization work.
    text = _redact_known_values(text, selected, policy)
    if notes:
        text += "\n" + "\n".join(notes)
    if _no_truncate:
        return _assert_final_known_values(text, selected)
    data, bound = text.encode("utf-8"), min(limit, policy["full_byte_cap"])
    if len(data) <= bound:
        return _assert_final_known_values(text, selected)
    head = data[:min(policy["head_byte_cap"], bound // 8)].decode("utf-8", errors="ignore").encode("utf-8")
    tail = b""
    budget = max(0, bound - len(head) - 80)
    for _ in range(8):
        tail = data[-budget:].decode("utf-8", errors="ignore").encode("utf-8") if budget else b""
        marker = policy["truncation_marker"].format(omitted=len(data) - len(head) - len(tail)).encode("utf-8")
        next_budget = max(0, bound - len(head) - len(marker))
        if next_budget == budget:
            break
        budget = next_budget
    marker = policy["truncation_marker"].format(omitted=len(data) - len(head) - len(tail)).encode("utf-8")
    assert len(head) + len(marker) + len(tail) <= bound
    return _assert_final_known_values((head + marker + tail).decode("utf-8"), selected)


def _redact_field(name, value, policy):
    if value is None or type(value) is bool:
        return False
    if re.search(policy["path_pattern"], name):
        return False
    if re.search(policy["digest_pattern"], name) and not re.search(policy["short_digest_pattern"], name):
        return False
    return bool(re.search(policy["sensitive_pattern"], name) or re.search(policy["compatibility_field_pattern"], name) or name.lower() in {"pin", "otp", "password"})


def redact_json_for_sink(value, environ: Mapping[str, str] = os.environ):
    policy = _sink_policy()
    if isinstance(value, dict):
        return {key: policy["field_marker"] if _redact_field(str(key), item, policy)
                else redact_json_for_sink(item, environ) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_json_for_sink(item, environ) for item in value]
    if isinstance(value, str):
        return redact_for_sink(value, environ)
    return value



def _is_short_secret_value(value) -> bool:
    """One shared boundary: the diagnostic redactor and the metadata check skip these."""
    return len(value) < 4


def assert_machine_metadata_no_secrets(text: str, environ=None) -> None:
    """Reject known secret bytes before any metadata file or temp is opened.

    Only the supplied environment is inspected; omitting it means an empty one.
    Callers pass the environment they write for (the process one when there is none).
    """
    policy = _sink_policy()
    environment = {} if environ is None else environ
    for name, value in environment.items():
        explicit = name in policy["environment_names"]
        if not explicit and (not re.search(policy["sensitive_pattern"], name)
                             or re.search(policy["path_pattern"], name)):
            continue
        if not value or _is_short_secret_value(value):
            continue
        if (not explicit and ((re.search(policy["identifier_name_pattern"], name)
                               and re.fullmatch(policy["identifier_value_pattern"], value))
                              or any(re.search(pattern, name) and re.fullmatch(shape, value)
                                     for pattern, shape in policy["process_identifier_patterns"].items()))):
            continue
        variants = {value, json.dumps(value, ensure_ascii=True)[1:-1],
                    json.dumps(value, ensure_ascii=False)[1:-1],
                    value.replace("'", "''"), value.replace('"', '""')}
        if any(variant in text for variant in variants):
            raise ValueError("MACHINE_METADATA_SECRET_DETECTED")


def serialize_machine_metadata(payload: Mapping[str, Any], environ: Mapping[str, str] | None = None) -> str:
    text = json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2)
    assert_machine_metadata_no_secrets(text, environ=os.environ if environ is None else environ)
    return text


def serialize_json_for_sink(payload: Mapping[str, Any]) -> str:
    """Redact before opening any file; keep a valid bounded JSON envelope."""
    safe = redact_json_for_sink(dict(payload))
    policy = _sink_policy()
    def diagnostics(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in policy["diagnostic_fields"] and isinstance(item, str):
                    yield value, key, item
                else:
                    yield from diagnostics(item)
        elif isinstance(value, list):
            for item in value:
                yield from diagnostics(item)
    for _ in range(512):
        encoded = redact_for_sink(json.dumps(safe, sort_keys=True, separators=(",", ":"), ensure_ascii=True), _no_truncate=True, _known_only=True)
        try:
            json.loads(encoded)
        except ValueError:
            raise ValueError("REPORT_UNAVAILABLE") from None
        if len(encoded.encode("utf-8")) + 1 <= policy["full_byte_cap"]:
            return encoded
        candidates = sorted(diagnostics(safe), key=lambda row: len(row[2].encode("utf-8")), reverse=True)
        if not candidates or len(candidates[0][2].encode("utf-8")) <= 300:
            raise ValueError("redacted JSON metadata exceeds sink byte limit")
        owner, key, value = candidates[0]
        owner[key] = redact_for_sink(value, {}, limit=max(300, len(value.encode("utf-8")) * 3 // 4))
        safe["sink_json_bounded"] = True
    raise ValueError("redacted JSON envelope could not be bounded")


def public_record(fields: Mapping[str, Any], allowed_codes, safe_messages) -> dict:
    """Contract section 0: publish only flat, explicitly typed fields."""
    patterns = {
        "key": r"[a-z][a-z0-9_]{0,63}",
        "identifier": r"[A-Za-z_][A-Za-z0-9_.]{0,127}",
        "sha256": r"[0-9a-f]{64}",
        "commit": r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
        "version": r"v?[0-9]{1,5}(?:\.[0-9]{1,5}){1,3}",
        "id": r"(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})",
        "utc": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z",
        "path": r'(?:[A-Za-z]:\\[^\x00-\x1f"<>|?*]{0,256}|/[^\x00-\x1f]{0,255})',
    }
    codes, messages = set(allowed_codes), set(safe_messages)

    def accepts(key, value):
        if value is None or type(value) is bool:
            return True
        # Exact names precede suffixes; notably exit_code is an integer.
        if key in {"status", "stage", "code"}:
            return isinstance(value, str) and value in codes
        if key == "guidance":
            return isinstance(value, str) and value in messages
        if key in {"exception_type", "location_module", "location_function"}:
            kind = "identifier"
        elif key in {"exit_code", "location_line"}:
            return type(value) is int
        elif key in {"version", "utc"}:
            kind = key
        elif key.endswith(("_status", "_stage", "_code")):
            return isinstance(value, str) and value in codes
        elif key.endswith("_message"):
            return isinstance(value, str) and value in messages
        elif key.endswith(("_count", "_bytes", "_ms", "_line")):
            return type(value) is int
        elif key.endswith("_sha256"):
            kind = "sha256"
        elif key.endswith("_commit"):
            kind = "commit"
        elif key.endswith("_version"):
            kind = "version"
        elif key.endswith("_id"):
            kind = "id"
        elif key.endswith("_utc"):
            kind = "utc"
        elif key.endswith(("_path", "_dir", "_root", "_file")):
            kind = "path"
        else:
            return False
        return isinstance(value, str) and re.fullmatch(patterns[kind], value) is not None

    result, rejected, invalid = {}, [], 0
    for key, value in fields.items():
        if not isinstance(key, str) or re.fullmatch(patterns["key"], key) is None:
            invalid += 1
        elif accepts(key, value):
            result[key] = value
        else:
            rejected.append(key)
    if rejected:
        result["nonconforming_fields"] = rejected
    if invalid:
        result["nonconforming_invalid_key_count"] = invalid
    if rejected or invalid:
        result["public_record_code"] = "PUBLIC_FIELD_NONCONFORMING"
    return result


UPDATE_RELAY_STOP_REQUESTED = "UPDATE_RELAY_STOP_REQUESTED"
TRIAL_RELAY_START_FAILED = "TRIAL_RELAY_START_FAILED"


PUBLIC_CODES = frozenset({
    UPDATE_RELAY_STOP_REQUESTED, TRIAL_RELAY_START_FAILED,
    'INSTALL_SERVER_ORIGIN_CHANGED', 'BOOTSTRAP_INTEGRITY_RECORD_ABSENT',
    'UPDATE_APPLY_REQUEST_FAILED', 'UPDATE_APPLY_NO_PROGRESS',
    'UPDATE_PREPARATION_FAILED', 'UPDATE_RETRY_REVIEW_REQUIRED', 'UPDATE_TERMINAL_RECOVERED',
    'UPDATE_GENERATION_UNKNOWN', 'UPDATE_PREVIOUS_CONFIRMED',
    'UPDATE_IN_PROGRESS', 'UPDATE_LOCK_WAIT_EXPIRED', 'UPDATE_LIFECYCLE_CHANGED', 'UPDATE_LIFECYCLE_UNKNOWN',
    'UPDATE_SUPERVISION_UNAVAILABLE', 'UPDATE_EXISTING_WRITER',
    'TRIAL_GENERATION_UNCHANGED', 'TRIAL_GENERATION_ADVANCED', 'TRIAL_GENERATION_UNKNOWN',
    'PASS', 'FAIL', 'FAILED', 'BLOCKED', 'UNKNOWN', 'SKIPPED', 'READY', 'ABSENT',
    'MISMATCH', 'NOT_CONFIGURED', 'START_REQUESTED', 'ALREADY_RUNNING',
    'REPORT_UNAVAILABLE', 'SUPPORT_FAILURE', 'SUPPORT_RESULT', 'ARGUMENT_INVALID',
    'runtime_error', 'ready', 'optional-not-configured', 'paused', 'running',
    'stopped', 'idle', 'acked', 'pending', 'failed_permanent', 'operator_review',
    'relay_operator', 'relay_runtime', 'relay_host', 'relay_bootstrap',
    'registration', 'runtime_profile_check', 'runtime_profile_install',
    'protected_admin_install', 'update_archive_check', 'relay_install',
    'argument_parse', 'portable_entrypoint', 'user_relay',
    'update_apply', 'onboarding', 'current_user_removal', 'replacement_lifecycle_restore',
    'lifecycle_operation_invalid', 'lifecycle_owned_namespace_collision',
    'lifecycle_namespace_parent_unavailable', 'lifecycle_data_namespace_collision',
    'lifecycle_removed_control_remains', 'lifecycle_register_requires_installed_code',
    'lifecycle_removed_tasks_remain_or_unknown', 'lifecycle_stock_protection_invalid',
    'lifecycle_stock_layout_invalid', 'lifecycle_stock_manifest_invalid',
    'lifecycle_control_incomplete', 'lifecycle_transition_requires_recovery',
    'lifecycle_confirmed_pointer_mismatch', 'lifecycle_rolled_back_pointer_mismatch',
    'lifecycle_pointer_mismatch', 'lifecycle_active_manifest_mismatch',
    'lifecycle_active_trust_key_mismatch', 'lifecycle_task_absence_or_unknown',
    'lifecycle_state_changed_during_verification', 'lifecycle_from_commit_mismatch',
    'WRITER_GATE_TIMEOUT', 'ACTIVE_WRITER_FENCE', 'FENCE_REPARSE_REJECTED',
    'FENCE_PATH_UNOBSERVABLE',
    'invalid_operator_input', 'unknown_command', 'operator_report_write_failed',
    'operator_audit_write_failed', 'hosted_relay_unhandled_exception',
    'data_generation_downgrade_refused', 'data_generation_unknown',
    'pause', 'resume', 'status', 'retry-dead', 'resolve-review', 'restore-spool',
})
SAFE_MESSAGES = (
    '입력 항목을 확인하고 다시 실행하세요.',
    '자료를 보존하고 관리자 지원 복구를 요청하세요.',
    '설정 파일과 설치 경로를 확인하고 다시 실행하세요.',
    '업데이트가 진행 중입니다. 잠시 뒤 다시 시작하세요.',
)
SAFE_MESSAGES += (RETRY_REVIEW_MESSAGE,)
_CONFIGURATION_STAGES = frozenset({
    'runtime_profile_check', 'runtime_profile_install', 'protected_admin_install',
    'update_archive_check', 'registration', 'relay_install',
})


def support_record(fields=None, *, stage, error=None):
    # Caller-selected paths and diagnostic payloads confer no publication
    # authority. Preserve only code/location fields at this public boundary.
    permitted = {'status', 'code', 'reason_code', 'error_code', 'operation_code',
                 'exit_code', 'exception_type', 'location_module',
                 'location_function', 'location_line', 'audit_write_status',
                 'audit_write_error_code', 'transition_code', 'retained_candidate', 'apply_claim_sha256'}
    values = {name: value for name, value in dict(fields or {}).items()
              if name in permitted}
    values.update(stage=stage, report_status='REPORT_UNAVAILABLE')
    if error is not None:
        values.setdefault('status', 'FAILED')
        values.update(reason_code='SUPPORT_FAILURE',
                      exception_type=type(error).__module__ + '.' + type(error).__name__)
        frame = error.__traceback__
        if frame is not None:
            while frame.tb_next is not None:
                frame = frame.tb_next
            values.update(location_module=frame.tb_frame.f_globals.get('__name__'),
                          location_function=frame.tb_frame.f_code.co_name,
                          location_line=frame.tb_lineno)
    else:
        values.setdefault('reason_code', 'SUPPORT_RESULT')
    values['guidance'] = (RETRY_REVIEW_MESSAGE if values.get('reason_code') == UPDATE_RETRY_REVIEW_REQUIRED
                          else SAFE_MESSAGES[0] if stage == 'argument_parse'
                          else SAFE_MESSAGES[2] if stage in _CONFIGURATION_STAGES
                          else SAFE_MESSAGES[1])
    return public_record(values, PUBLIC_CODES, SAFE_MESSAGES)


def emit_support_record(fields=None, *, stage, error=None, file=None, policy=None):
    record = support_record(fields, stage=stage, error=error)
    if policy is not None:
        try:
            write_json_durable(Path(policy['staging_root']) / 'startup-support.json', record)
        except (OSError, ValueError, TypeError, KeyError, WriterFencedError):
            pass  # Keep the safe launch when its existing diagnostic sink is unavailable.
    print('CONTAINER_AUDIT_SUPPORT=' + json.dumps(
        record,
        ensure_ascii=True, separators=(',', ':')), file=file or sys.stdout)


def run_support_main(main, *, stage):
    try:
        return main()
    except Exception as error:
        emit_support_record(stage=stage, error=error, file=sys.stderr)
        return 1


class SupportArgumentParser(argparse.ArgumentParser):
    """Argument failures must not echo user input or parser-generated sentences."""
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('prog', 'Container_Audit support')
        super().__init__(*args, **kwargs)

    def error(self, message):
        emit_support_record({'status': 'FAILED', 'reason_code': 'ARGUMENT_INVALID',
                             'exit_code': 2}, stage='argument_parse', file=sys.stderr)
        self.exit(2)


# Registration only: these diagnostic sentences are literals in product code.
REGISTERED_DIAGNOSTIC_MESSAGES = frozenset({
    ' must not point at the legacy Syncthing folder',
    '; ',
    'admin recovery succeeded but the consumed protected authorization file could not be deleted: ',
    'blocked_reason',
    'data_generation_unknown',
    'destination_path already exists',
    'direct-sync relay is paused by local operator control',
    'direct-sync relay operator pause marker is invalid',
    'direct-sync relay paused before upload',
    'direct-sync upload failed before returning a result: ',
    'disk pressure check failed: ',
    'free space is below configured direct-sync relay minimum',
    'hosted DirectSync relay failed unexpectedly: ',
    'legacy exact replay was explicitly not committed',
    'message',
    'persisted credential exact readback differs from the prepared credential',
    'persisted manifest hash differs from the server-authorized manifest hash',
    'producer ingest error response is not valid JSON',
    'producer ingest redirected; redirects are not allowed',
    'producer ingest response receipt is missing or invalid',
    'producer ingest transport error: ',
    'producer manifest identity is incomplete',
    'producer manifest invalid: ',
    'producer manifest is unavailable',
    'producer manifest must be a JSON object',
    'producer manifest stream does not match Container_Audit legacy CSV',
    'raw artifact restore body does not match requested artifact',
    'raw artifact restore could not write destination: ',
    'raw artifact restore redirected; redirects are not allowed',
    'raw artifact restore response headers do not match requested artifact',
    'raw artifact restore returned HTTP ',
    'raw artifact restore transport error: ',
    'relay lease changed before final status update',
    'relay queue database error: ',
    'source file cannot be read before upload: ',
    'source file changed after upload plan was built; rebuild the direct sync upload plan',
    'spooled file cannot be read: ',
    'spooled file content does not match queued content hash/byte length',
    'upload metadata identity is incomplete',
})

_DIAGNOSTIC_KEYS = frozenset({
    "blocked_reason", "error_message", "runtime_status_write_error_message",
    "runtime_log_write_error_message", "stdout", "stderr", "stdout_tail", "stderr_tail", "command_line", "argv",
    "message", "detail", "command",
})
_AUTHENTICATED_CONTAINER_KEYS = frozenset({
    'identity', 'source_identity', 'credential', 'profile', 'manifest',
    'metadata', 'receipt', 'server_receipt', 'credential_ref',
})
_FAILURE_DETAIL_KEYS = frozenset({'failure', 'failure_details', 'failure_evidence',
                                'failure_evidence_refs', 'original_failure_text', 'traceback'})


def mixed_status_record(value):
    """Keep the existing schema and machine values; replace diagnostic leaves only.

    No publication fields are added to an authenticated or status record.
    This is called only for unprotected mixed status, never credentials or journals.
    """
    def diagnostic(item):
        if isinstance(item, str):
            return item if not item or item in REGISTERED_DIAGNOSTIC_MESSAGES or item in PUBLIC_CODES else "SUPPORT_FAILURE"
        if isinstance(item, dict):
            return {key: diagnostic(child) for key, child in item.items()}
        if isinstance(item, list):
            return [diagnostic(child) for child in item]
        return item

    def failure_detail(item):
        if isinstance(item, dict):
            return {key: child if key in {'type', 'exception_type', 'hresult',
                                          'win32_error', 'winerror', 'errno'}
                    else failure_detail(child) for key, child in item.items()}
        if isinstance(item, list):
            return [failure_detail(child) for child in item]
        return diagnostic(item)

    if isinstance(value, dict):
        return {key: child if key in _AUTHENTICATED_CONTAINER_KEYS else
                failure_detail(child) if key in _FAILURE_DETAIL_KEYS else
                diagnostic(child) if key in _DIAGNOSTIC_KEYS or
                _redact_field(str(key), child, _sink_policy()) or
                (key == 'last_result' and isinstance(child, str))
                else mixed_status_record(child) for key, child in value.items()}
    if isinstance(value, list):
        return [mixed_status_record(child) for child in value]
    return value


def serialize_mixed_status_record(value):
    """Preserve machine fields and the existing compact report representation."""
    projected = mixed_status_record(value)
    # Reuse metadata admission before opening a temporary file. Applying the
    # diagnostic redactor again would replace authenticated containers/types.
    serialize_machine_metadata(projected)
    return json.dumps(projected, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


# Fixed public wording and computed-field prefixes registered without changing
# their existing emitters (contract 0e / coordinator five-source criterion).
REGISTERED_PUBLIC_LITERALS = (
    'BLOCKED: ',
    'BLOCKED: --reader-principal is required for an actual install',
    'BLOCKED: bearer token environment value is missing',
    'BLOCKED: credential entries do not match',
    'BLOCKED: protected administrator hidden input failed',
    'BLOCKED: unsupported command-line argument',
    'bootstrap_integrity=',
    'current_user_removal_report=',
    'current_user_removal_status=',
    'data_preserved=true',
    'direct_sync_operator_audit_write_error_code=',
    'direct_sync_operator_audit_write_status=',
    'direct_sync_operator_operation=',
    'direct_sync_operator_report_error_code=',
    'direct_sync_operator_report_status=',
    'direct_sync_operator_status=',
    'direct_sync_relay_status=',
    'direct_sync_scan_attempted_count=',
    'direct_sync_scan_enqueued_count=',
    'direct_sync_scan_no_new_count=',
    'direct_sync_scan_status=',
    'direct_sync_scan_terminal_blocked_count=',
    'machine_code_removal_command=INSTALL_CANONICAL_PORTABLE.ps1 -Uninstall',
    'manifest_hash_verification=FAIL',
    'manifest_hash_verification=PASS',
    'onboarding_action=',
    'onboarding_input_binding=',
    'onboarding_report=',
    'onboarding_status=',
    'registration_response=superseded',
    'replacement_lifecycle_restore_action=',
    'replacement_lifecycle_restore_report=',
    'replacement_lifecycle_restore_status=',
)
SAFE_MESSAGES += REGISTERED_PUBLIC_LITERALS + tuple(sorted(REGISTERED_DIAGNOSTIC_MESSAGES))
PUBLIC_CODES |= frozenset({
    'ABSENT',
    'ABSENT_RETRYABLE',
    'BLOCKED',
    'DEFERRED_CANONICAL_RELEASE',
    'FAIL',
    'FAILED',
    'FAILED_VERSION_PRESERVED',
    'LOCAL_REGISTRATION_WRITTEN_PENDING_SECRET',
    'NOT_REGISTERED',
    'NOT_TESTED',
    'NO_UPDATE',
    'OFF',
    'PASS',
    'PASS_DATA_PRESERVED',
    'PREPARED',
    'READY',
    'RECOVERY_REQUIRED',
    'RESUME_TWO_PHASE_RECOVERY',
    'RUNNING',
    'SKIPPED',
    'START_REQUESTED',
    'STOP_REQUESTED',
    'UNKNOWN',
    'existing_terminal_blocked',
    'existing_terminal_delta_blocked',
    'hosted_relay_unhandled_exception',
    'invalid_operator_input',
    'operator_supplied_uncontacted',
    'optional-not-configured',
    'reattached',
    'recorded',
    'recorded_from_acked_target',
    'recovered',
    'reused',
    'rotated',
    'runtime_error',
    'scheduled_task_command_start_failed',
    'unknown_command',
    'upgraded',
})

# Source-derived fixed code registration; existing emitters remain unchanged.
PUBLIC_CODES |= frozenset(['ABSENT', 'ABSENT_RETRYABLE', 'BLOCKED', 'DEFERRED_CANONICAL_RELEASE', 'FAIL', 'FAILED', 'FAILED_VERSION_PRESERVED', 'INSTALLER_CHILD_FAILURE', 'LOCAL_REGISTRATION_WRITTEN_PENDING_SECRET', 'NOT_REGISTERED', 'NOT_TESTED', 'NO_UPDATE', 'OFF', 'PASS', 'PASS_DATA_PRESERVED', 'PREPARED', 'READY', 'RECOVERY_REQUIRED', 'RESUME_TWO_PHASE_RECOVERY', 'RUNNING', 'SKIPPED', 'START_REQUESTED', 'STOP_REQUESTED', 'UNKNOWN', 'blocked', 'disk_pressure_check_failed', 'existing_terminal_blocked', 'existing_terminal_delta_blocked', 'hosted_relay_unhandled_exception', 'invalid', 'invalid_operator_input', 'not_applicable', 'not_checked', 'not_found', 'not_initialized', 'operator_pause_resume_failed', 'operator_pause_write_failed', 'operator_review', 'operator_review_committed_receipt_not_retryable', 'operator_review_receipt_invalid', 'operator_supplied_uncontacted', 'optional-not-configured', 'pass', 'paused', 'producer_manifest_identity_incomplete', 'producer_manifest_invalid', 'producer_manifest_stream_mismatch', 'producer_manifest_unavailable', 'reattached', 'recorded', 'recorded_from_acked_target', 'recovered', 'relay_db_not_initialized', 'relay_db_open_failed', 'relay_db_schema_unavailable', 'relay_db_unavailable', 'relay_failure_cause_not_approved_for_retry', 'relay_metadata_invalid', 'relay_not_found', 'relay_queue_db_error', 'relay_status_changed', 'relay_status_not_retryable_by_operator', 'reused', 'rotated', 'runtime_error', 'runtime_status_invalid', 'runtime_status_not_found', 'runtime_status_unreadable', 'scheduled_task_command_start_failed', 'spooled_file_digest_mismatch', 'spooled_file_missing', 'unavailable', 'unknown_command', 'upgraded'])
PUBLIC_CODES |= frozenset(['relay_source_failure_cleared', 'vanished', 'no_new_bytes', 'source_csv_header_invalid', 'source_csv_utf8_invalid', 'source_csv_content_invalid', 'source_file_read_failed', 'source_delta_write_failed'])
REGISTERED_POWERSHELL_PUBLIC_LITERALS = ('CONTAINER_AUDIT_INSTALL_HELPER=', 'CONTAINER_AUDIT_SUPPORT=', 'ConvertTo-Json', 'ConvertTo-KmtechRedactedSinkText', 'Count', 'Current-user runtime restored. New verified code remains at ', 'Data', 'Get-FileSha256', 'HelperStageEvidenceRoot', 'INSTALLATION_EVIDENCE_FINAL_AUDIT_SAVE_FAILED', 'INSTALLATION_EVIDENCE_FINAL_EVIDENCE_SAVE_FAILED', 'IsNullOrWhiteSpace', 'ResultPath', 'Stdout', 'acl_owner_sid=S-1-5-32-544', 'acl_readback_status=', 'acl_readback_status=UNKNOWN', 'aggregate_sha256=', 'ancestor_trust_failure', 'ancestor_trust_failure=', 'bootstrap_status=', 'bootstrap_status=DRY_RUN', 'code_placement_preflight_failure=', 'code_placement_preflight_failure=CONTAINER_PLACEMENT_ELEVATION_FAILED', 'code_placement_preflight_failure=CONTAINER_PLACEMENT_LOG_WRITE_FAILED', 'container_recovery_receipt=', 'container_recovery_receipt_sha256=', 'container_recovery_status=', 'dacl_normalized=true', 'elevation_points=1:code_placement', 'failure_code', 'file_count=', 'hiberboot_enabled=', 'hiberboot_read_status=', 'identity_profile_created=false', 'installation_elevation_result_path=', 'installation_evidence_status=', 'installation_evidence_summary_path=', 'installation_stage_evidence_root=', 'name', 'operator_message', 'path', 'protected_admin_provision=PASS mode=', 'record', 'release_layout=', 'removal_child_failure', 'replacement_receipt_sha256=', 'replacement_receipt_status=OLD_PRESERVED_NEW_VERIFIED', 'replacement_receipt_validation_evidence=', 'replacement_receipt_validation_evidence_sha256=', 'replacement_receipt_validation_status=', 'replacement_restore_evidence_sha256=', 'replacement_restore_receipt_required_at_apply=true', 'replacement_restore_schema=container-audit-verified-replacement-v1', 'replacement_restore_status=', 'replacement_restore_status=DRY_RUN', 'replacement_restore_status=ROLLBACK_FAILED', 'replacement_rollback_status=PRESERVED', 'replacement_transaction_id=', 'retirement_child_failure', 'retirement_failure_summary=', 'retirement_recovery_child_failure', 'retirement_recovery_failure_summary=', 'rollback', 'rollback_audit_status=UNAVAILABLE', 'rollback_evidence_failure_record_status=UNAVAILABLE', 'rollback_evidence_status=UNAVAILABLE', 'sha256', 'startup_update_status=NOT_TESTED_HOST', 'startup_update_status=REGISTERED_LOGON_SYSTEM_CODE_ONLY', 'startup_update_task=', 'status', 'stderr', 'stdout', 'summary_path', 'tls_ca_bootstrap_configured=', 'tls_ca_bootstrap_status=ABSENT', 'tls_ca_bootstrap_status=PASS', 'writer_restore_receipt=', 'writer_restore_receipt_sha256=', 'writer_restore_status=', 'writer_session_receipt=', 'writer_session_receipt_sha256=', 'writer_session_status=', 'writer_session_validation_failure_code=', 'writer_session_validation_status=', '관리자 암호를 입력한 다음 같은 암호를 다시 입력하세요.', '자료 판이 옛 판의 실행을 허용하지 않아 옛 전송 예약 작업을 되살리지 않았습니다. 자료와 복구 기록을 보존하고 관리자 지원 복구를 요청하세요.')
SAFE_MESSAGES += REGISTERED_POWERSHELL_PUBLIC_LITERALS




def failure_user_line(error: object) -> str:
    safe = _failure_text(error, limit=65536)
    lines = [line.strip() for line in safe.splitlines() if line.strip()
             and not line.strip().startswith(("[TRUNCATED:", "[REDACTION_NOTE:"))]
    return (lines[-1] if lines else "Failure detail unavailable")[:300]


def _failure_text(value, *, limit: int = 16384) -> str:
    environment = dict(os.environ)
    text = redact_for_sink(value, environment, _no_truncate=True)
    # Decode quoted field names/values instead of stopping at escaped quotes
    # or a comma inside a credential object. No credential store lookup.
    sensitive = r"authorization|credential|password|secret|token|signature|apikey|accesskey|privatekey"
    decoder, spans, covered = json.JSONDecoder(), [], 0
    for match in re.finditer(r'"(?P<key>(?:\\.|[^"\\])*)"\s*[:=]\s*', text):
        if match.start() < covered:
            continue
        try:
            key = json.loads('"' + match.group("key") + '"')
        except ValueError:
            continue
        if re.search(sensitive, key.replace("-", "").replace("_", ""), re.IGNORECASE) is None:
            continue
        try:
            value, end = decoder.raw_decode(text, match.end())
            if not _redact_field(key, value, _sink_policy()):
                continue
        except ValueError:
            end = len(text)  # Malformed sensitive JSON is never partly retained.
        spans.append((match.end(), end))
        covered = end
    for start, end in reversed(spans):
        text = text[:start] + "[REDACTED:field]" + text[end:]
    text = re.sub(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s?#]*@",
                  lambda match: match.group(1) + "[redacted]@", text)
    # Quoted JSON keys were handled above. Keep assignments, query/header
    # fields and Python-style quoted keys, including hyphenated API keys.
    text = re.sub(r'''(?ix)(?<![\w"])(\b[A-Za-z0-9_-]*(?:authorization|credential|password|secret|token|signature|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_-]*'?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^\r\n;&}]+)''',
                  lambda match: match.group(0) if "[REDACTED:" in match.group(0) else match.group(1) + "[REDACTED:field]", text)
    text = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED:field]", text)
    final = redact_for_sink(text, {}, limit=limit)
    return redact_for_sink(final, environment, _check_only=True)


def _failure_details(error: BaseException) -> list[dict]:
    details, seen = [], set()
    while error is not None and id(error) not in seen and len(details) < 16:
        seen.add(id(error))
        item = {"type": type(error).__module__ + "." + type(error).__name__,
                "message": _failure_text(getattr(error, "original_failure_text", error), limit=4096)}
        for name in ("errno", "winerror", "exit_code"):
            value = getattr(error, name, None)
            if type(value) is int:
                item[name] = value
        for name in ("stdout", "stderr"):
            value = getattr(error, name, None)
            if isinstance(value, (str, bytes)):
                item[name] = _failure_text(value)
                item[name + "_truncated"] = len(value) > 16384
        details.append(item)
        error = error.__cause__ or error.__context__
    return details



def _write_failure_evidence(control: Path, error: BaseException) -> list[dict]:
    """No original files: update-control has no verified reader protection."""
    return []


def installation_root(app_root: Path) -> Path | None:
    code = app_root.absolute()
    if code.name != 'app':
        return None
    bundle = code.parent
    if bundle.name == 'current':
        return bundle.parent
    if bundle.parent.name == 'versions' and re.fullmatch(r'[0-9a-f]{40}', bundle.name):
        return bundle.parent.parent
    return None


LIFECYCLE_RECOVERY = '자료와 등록 및 전송 대기를 보존하고 지원 제거를 먼저 실행한 뒤 다시 설치하세요.'


def verify_lifecycle_stock(bundle: Path) -> dict[str, Any]:
    from current_user_onboarding import _read_replacement_tree_identity, _windows_acl_identity
    identity = _read_replacement_tree_identity(bundle, bundle, acl_identity_reader=_windows_acl_identity)
    if identity['owner_sid'] != 'S-1-5-32-544' or identity['access_rules_protected'] is not True:
        raise ValueError('lifecycle_stock_protection_invalid')
    return identity


@writer_sink("auto_update_control")
def supported_tasks_absent(fixed: Path, *, operation: str = "inspect") -> bool:
    """Removal markers do not substitute for actual task absence."""
    import subprocess
    escaped = str(fixed).replace("'", "''")
    library = Path(__file__).resolve().parent / "tools/bootstrap_integrity.ps1"
    if not library.is_file():
        library = Path(__file__).resolve().parent.parent / "tools/bootstrap_integrity.ps1"
    _assert_no_reparse_components(library)
    if not library.is_file():
        raise ValueError("lifecycle_task_reader_unavailable")
    escaped_library = str(library).replace("'", "''")
    allow_legacy = "$true" if operation == "install" else "$false"
    script = ("$ErrorActionPreference='Stop';. '" + escaped_library + "';$root='" + escaped + "';"
              "foreach($t in @(Get-ScheduledTask -ErrorAction Stop)){"
              "if($t.TaskName -ieq 'direct-sync-relay-container-audit'){"
              "if(-not " + allow_legacy + " -or -not(Get-BootstrapOfficialLegacyRelayIdentity $t).matched){exit 5}}"
              "elseif($t.TaskName -ieq 'container-audit-isolated-qualification-authority'){exit 5};"
              "if($t.TaskName -cmatch '^KMTech\\.ContainerAudit\\.StartupUpdate\\.[0-9a-f]{24}$'){"
              "[xml]$x=Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop;"
              "foreach($a in @($x.Task.Actions.Exec)){if(([string]$a.Arguments).IndexOf($root,[StringComparison]::OrdinalIgnoreCase) -ge 0){exit 5}}}};exit 0")
    result = subprocess.run([system_executable('WindowsPowerShell/v1.0/powershell.exe'), '-NoLogo', '-NoProfile',
                             '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], capture_output=True,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode not in (0, 5):
        raise subprocess.CalledProcessError(result.returncode, "lifecycle-task-query", output=result.stdout, stderr=result.stderr)
    return result.returncode == 0


def _resolve_task_principal_sid(identity: str) -> str:
    """Resolve one SID/account through Windows; never compare account spelling."""
    import ctypes
    from ctypes import wintypes
    if os.name != 'nt':
        raise OSError('task principal resolution unavailable')
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
    advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    sid_pointer = wintypes.LPVOID()
    allocated = False
    if identity[:2].upper() == 'S-':
        if not advapi.ConvertStringSidToSidW('S-' + identity[2:], ctypes.byref(sid_pointer)):
            raise ValueError('task SID invalid')
        allocated = True
    else:
        advapi.LookupAccountNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPVOID,
            ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
        advapi.LookupAccountNameW.restype = wintypes.BOOL
        size, domain_size, use = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
        advapi.LookupAccountNameW(None, identity, None, ctypes.byref(size), None, ctypes.byref(domain_size), ctypes.byref(use))
        if ctypes.get_last_error() != 122 or not 0 < size.value <= 65536 or domain_size.value > 65536:
            raise OSError('task account SID unknown')
        buffer = ctypes.create_string_buffer(size.value)
        domain = ctypes.create_unicode_buffer(max(1, domain_size.value))
        if not advapi.LookupAccountNameW(None, identity, buffer, ctypes.byref(size), domain, ctypes.byref(domain_size), ctypes.byref(use)):
            raise OSError('task account SID unknown')
        sid_pointer = ctypes.cast(buffer, wintypes.LPVOID)
    text = wintypes.LPWSTR()
    try:
        if not advapi.ConvertSidToStringSidW(sid_pointer, ctypes.byref(text)):
            raise OSError('task principal SID unknown')
        return text.value
    finally:
        if text:
            kernel.LocalFree(ctypes.cast(text, wintypes.HLOCAL))
        if allocated:
            kernel.LocalFree(sid_pointer)


def task_trigger_identity_status(task, operator_sid: str) -> str:
    ns = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    triggers = task.findall('t:Triggers/t:LogonTrigger', ns)
    users = task.findall('t:Triggers/t:LogonTrigger/t:UserId', ns)
    if len(triggers) != 1 or len(users) != 1 or len(users[0]):
        return 'INVALID'
    identity = users[0].text
    if not isinstance(identity, str) or not identity.strip() or identity != identity.strip():
        return 'INVALID'
    if not isinstance(operator_sid, str) or re.fullmatch(r'S-\d+(?:-\d+)+', operator_sid) is None:
        return 'INVALID'
    try:
        wanted = _resolve_task_principal_sid(operator_sid)
    except (ValueError, OSError):
        return 'INVALID'
    is_sid = identity[:2].upper() == 'S-'
    try:
        actual = _resolve_task_principal_sid(identity)
    except ValueError:
        return 'INVALID' if is_sid else 'UNKNOWN'
    except OSError:
        return 'UNKNOWN'
    return 'MATCHED' if actual == wanted else 'DIFFERS'


def task_readback_value_matches(path: str, actual: str | None, expected: str) -> bool:
    """Normalize only native spellings of the same task field value."""
    if not isinstance(actual, str) or not actual or actual != actual.strip():
        return False
    if path == 't:Principals/t:Principal/t:UserId':
        try:
            return _resolve_task_principal_sid(actual) == 'S-1-5-18'
        except (ValueError, OSError):
            return False
    if path in {'t:Settings/t:AllowHardTerminate', 't:Settings/t:Hidden'}:
        return actual.lower() in ({'true', '1'} if expected == 'true' else {'false', '0'})
    if path == 't:Actions/t:Exec/t:Arguments':
        return actual in (expected, expected.replace(' -ExecutionPolicy Bypass -File ', ' -File ', 1))
    return actual == expected


@writer_sink("auto_update_control")
def supported_task_present(fixed: Path, sid: str) -> bool:
    """Read the actual derived task without executing installed support code."""
    import subprocess
    import xml.etree.ElementTree as xml

    name = task_name(fixed, sid)
    script = r"""Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
""" + "$ErrorActionPreference='Stop';$s=New-Object -ComObject 'Schedule.Service';$s.Connect();$t=$s.GetFolder('\\').GetTask('" + name + "');[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);[Console]::Write($t.Xml)"
    result = subprocess.run([system_executable('WindowsPowerShell/v1.0/powershell.exe'), '-NoLogo', '-NoProfile',
                             '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], capture_output=True, encoding='utf-8',
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode or len(result.stdout) > 1024 * 1024:
        return False
    try:
        actual = xml.fromstring(result.stdout); expected = xml.fromstring(logon_task_xml(app_root=fixed, operator_sid=sid))
        ns = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
        paths = ('t:Triggers/t:LogonTrigger/t:UserId', 't:Principals/t:Principal/t:UserId',
                 't:Principals/t:Principal/t:RunLevel', 't:Actions/t:Exec/t:Command',
                 't:Actions/t:Exec/t:Arguments', 't:Settings/t:AllowHardTerminate', 't:Settings/t:Hidden')
        return (len(actual.findall('t:Actions/t:Exec', ns)) == 1
                and len(actual.findall('t:Triggers/t:LogonTrigger', ns)) == 1
                and len(actual.findall('t:Principals/t:Principal', ns)) == 1
                and task_trigger_identity_status(actual, sid) == 'MATCHED'
                and all(len(actual.findall(path, ns)) == 1 and not len(actual.find(path, ns))
                    and task_readback_value_matches(path, actual.findtext(path, namespaces=ns),
                                                    expected.findtext(path, namespaces=ns))
                    for path in paths if path != 't:Triggers/t:LogonTrigger/t:UserId'))
    except (ValueError, xml.ParseError):
        return False


def assert_failed_support_quiescent(control: Path, policy: Mapping[str, Any], state: Mapping[str, Any]) -> None:
    """Read-only proof; a phase name never grants support admission."""
    from writer_session_fence import active_fence, canonical_control_root

    if writer_processes(process_snapshot(control), own_pid=os.getpid()):
        raise ValueError('failed_support_writers_present')
    roots = [canonical_control_root()]
    if policy.get('operator_local_app_data'):
        roots.append(canonical_control_root({'LOCALAPPDATA': policy['operator_local_app_data']}))
    if os.name == 'nt':
        if not os.environ.get('PROGRAMDATA'):
            raise ValueError('failed_support_machine_fence_unobservable')
        machine = Path(os.environ['PROGRAMDATA']) / 'KMTech/ContainerAudit/machine-install/control/writer-session'
        roots.append(machine)
    for root in dict.fromkeys(roots):
        if active_fence(root) is not None:
            raise ValueError('failed_support_writer_fence_present')
    if prepared_pending(control, policy, state):
        raise ValueError('failed_support_prepared_pending')


def resolve_lifecycle_context(root: Path, *, operation: str = 'inspect', expected_from_commit: str | None = None, startup: bool = False, failed_support_preflight: bool = False) -> dict[str, Any]:
    """Removal needs scope; install/register require actual healthy stock bytes."""
    if operation not in {'inspect', 'install', 'register', 'uninstall', 'user_remove'}:
        raise ValueError('lifecycle_operation_invalid')
    root = root.absolute(); fixed = root / 'current'; control = root / 'update-control'
    if operation in {'uninstall', 'user_remove'}:
        return dict(status='PASS', lifecycle_state='REMOVAL_READY', fixed_root=str(fixed),
                    owner_app_root=str(fixed / 'app'), active_code_root=None, active_app_root=None, from_commit=None)
    try:
        _assert_no_reparse_components(root)
        for path in (fixed, control, root / 'versions'):
            _assert_no_reparse_components(path)
            if path.exists() and not path.is_dir():
                raise ValueError('lifecycle_owned_namespace_collision')
        data_root = os.environ.get('CONTAINER_AUDIT_DATA_ROOT')
        if data_root:
            data = Path(data_root).absolute()
            for reserved in (fixed, control, root / 'versions', root / 'removal-evidence'):
                if data == reserved or data in reserved.parents or reserved in data.parents:
                    raise ValueError('lifecycle_data_namespace_collision')
        records = [control / name for name in ('policy.json', 'active.json', 'transition.json')]
        present = [path.exists() for path in records]
        if not fixed.exists():
            if any(present):
                raise ValueError('lifecycle_removed_control_remains')
            if operation == 'register':
                raise ValueError('lifecycle_register_requires_installed_code')
            if not supported_tasks_absent(fixed, operation=operation):
                raise ValueError('lifecycle_removed_tasks_remain_or_unknown')
            return dict(status='PASS', lifecycle_state='REMOVED', fixed_root=str(fixed),
                        owner_app_root=str(fixed / 'app'), active_code_root=None, active_app_root=None, from_commit=None)
        verify_lifecycle_stock(fixed)
        owner = read_json(fixed / 'portable-manifest.json')
        if owner.get('schema') != 'container-audit-portable-tree-v1':
            raise ValueError('lifecycle_stock_manifest_invalid')
        owner_sha = _sha(owner.get('source_commit'))
        active_root = fixed; active_sha = owner_sha
        if any(present):
            if not all(present):
                raise ValueError('lifecycle_control_incomplete')
            policy, pointer, state = [read_json(path) for path in records]
            failed_support = (state.get('phase') == 'FAILED' and operation == 'install'
                              and failed_support_preflight is True and not startup)
            if (policy.get('schema') != 'container-audit-startup-update-policy-v1' or pointer.get('schema') != SCHEMA
                    or state.get('schema') != SCHEMA
                    or (state.get('phase') not in {'CONFIRMED', 'DEFERRED', 'ROLLED_BACK'} and not failed_support)):
                raise ValueError('lifecycle_transition_requires_recovery')
            active_sha = _sha(pointer.get('sha'))
            if state.get('phase') == 'CONFIRMED' and state.get('candidate_sha') != active_sha:
                raise ValueError('lifecycle_confirmed_pointer_mismatch')
            if state.get('phase') == 'ROLLED_BACK' and state.get('previous_sha') != active_sha:
                raise ValueError('lifecycle_rollback_pointer_mismatch')
            active_root = version_bundle(control, active_sha)
            verify_lifecycle_stock(active_root)
            actual = read_json(active_root / 'portable-manifest.json')
            if actual.get('schema') != owner.get('schema') or actual.get('source_commit') != active_sha:
                raise ValueError('lifecycle_active_manifest_mismatch')
            for bundle in (fixed, active_root):
                _assert_no_reparse_components(bundle / 'app/update-manifest-key-config.json')
            if ((fixed / 'app/update-manifest-key-config.json').read_bytes()
                    != (active_root / 'app/update-manifest-key-config.json').read_bytes()):
                raise ValueError('lifecycle_active_trust_key_mismatch')
            if supported_task_present(fixed, policy.get('operator_sid')) is not True:
                raise ValueError('lifecycle_task_absence_or_unknown')
            if failed_support:
                try:
                    assert_failed_support_quiescent(control, policy, state)
                    observed = read_trial_generation(policy)
                    if (observed.get('status') != 'READ' or observed.get('record') is None
                            or current_generation_status(control, policy, active_sha) != 'ALLOW'
                            or read_trial_generation(policy) != observed):
                        raise ValueError('lifecycle_failed_support_generation_unknown')
                    assert_failed_support_quiescent(control, policy, state)
                except (TypeError, KeyError) as error:
                    raise ValueError('lifecycle_failed_support_observation_unknown') from error
            try:
                if [read_json(path) for path in records] != [policy, pointer, state]:
                    if not startup: raise ValueError('lifecycle_state_changed_during_verification')
                    with startup_update_lock(control, policy) as acquired:
                        if not acquired:
                            raise RuntimeError('lifecycle_state_unobservable')
                        latest = [read_json(path) for path in records]
                        diagnostic = {'deferred_at', 'reason', 'failure_details', 'failure_evidence'}
                        semantic = lambda value: {key: item for key, item in value.items() if key not in diagnostic}
                        if latest[:2] != [policy, pointer] or semantic(latest[2]) != semantic(state):
                            raise ValueError('lifecycle_state_changed_during_verification')
            except (OSError, ValueError, RuntimeError) as error:
                if not startup:
                    raise
                status = 'CHANGED' if str(error) == 'lifecycle_state_changed_during_verification' else 'UNKNOWN'
                emit_support_record({'reason_code': 'UPDATE_LIFECYCLE_' + status, 'exit_code': 0}, stage='onboarding', policy=policy)
                return {'status': status}
        if expected_from_commit is not None and _sha(expected_from_commit) != active_sha:
            raise ValueError('lifecycle_from_commit_mismatch')
        return dict(status='PASS', lifecycle_state='HEALTHY', fixed_root=str(fixed), owner_app_root=str(fixed / 'app'),
                    active_code_root=str(active_root), active_app_root=str(active_root / 'app'),
                    from_commit=active_sha, bootstrap_commit=owner_sha, managed=any(present))
    except (OSError, ValueError, RuntimeError) as error:
        raise ValueError(LIFECYCLE_RECOVERY + ' [' + type(error).__name__ + ']') from error


def version_bundle(control: Path, sha: str) -> Path:
    return control.parent / "versions" / _sha(sha)


def version_manifest(bundle: Path, *, require_version: bool = False) -> dict[str, Any]:
    value = read_json(bundle / "portable-manifest.json")
    if type(value.get("startup_update_protocol")) is not int or value["startup_update_protocol"] != 1:
        raise ValueError("version has no supported startup readiness protocol")
    _sha(value.get("source_commit"))
    _sha(value.get("writer_sink_inventory_contract_sha256"), length=64)
    def read_bytes(name):
        path = bundle / name
        _assert_no_reparse_components(path)
        return path.read_bytes()
    if require_version or 'version' in value:
        value.update(version_identity(read_bytes))
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
    with _authenticated_preparation(manifest.get("source_commit")):
        candidate = update_candidate_from_private_manifest(manifest, current_version=current_version, expected_channel=channel)
        if candidate is None or candidate["archive_policy"].get("layout") != "canonical_portable":
            raise ValueError("update is not a targeted canonical portable candidate")
        packet = stage / "packet.zip"
        _assert_no_reparse_components(packet)
        if packet.stat().st_size != manifest["artifact"]["size_bytes"] or file_sha256(packet) != candidate["sha256"]:
            raise ValueError("prepared packet size or SHA256 differs")
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
    arguments = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + root + '\\tools\\apply_prepared_update.ps1" -InstallRoot "' + root + '"'
    executable = system_executable("WindowsPowerShell/v1.0/powershell.exe")
    return (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        '<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>' + escape(operator_sid) + '</UserId></LogonTrigger></Triggers>'
        '<Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
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
def update_lock(control: Path, operator_sid: str, *, trial: bool = False, timeout_ms: int = 5000):
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
    create = kernel.CreateMutexExW
    create.argtypes = [ctypes.POINTER(Attributes), wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    create.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    identity = hashlib.sha256(os.path.normcase(str(control.absolute())).encode("utf-8")).hexdigest()[:24]
    attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
    try:
        handle = create(ctypes.byref(attributes), "Global\\KMTech.ContainerAudit.Update." + identity + (".Trial" if trial else ""), 0, 0x00100001)
    finally:
        kernel.LocalFree(descriptor)
    if not handle:
        raise OSError(ctypes.get_last_error(), "update mutex cannot be opened")
    acquired = False
    try:
        result = kernel.WaitForSingleObject(handle, timeout_ms)
        acquired = result in {0, 0x80}
        if result != 0:
            error = RuntimeError("update mutex ownership is busy or abandoned")
            error.wait_result = result
            raise error
        yield
    finally:
        if acquired:
            kernel.ReleaseMutex(handle)
        kernel.CloseHandle(handle)


def _ready_window_deadline(control: Path) -> float | None:
    """Read protected window bounds only; ownership still requires a fresh read."""
    try:
        state = read_json(control / "transition.json")
        if state.get("schema") != SCHEMA:
            return None
        if state.get("phase") == "APPLIED_PENDING_READY":
            timestamp = state["applied_at"]
        elif state.get("phase") == "ROLLBACK_PENDING_READY":
            timestamp = state.get("rollback_at", state["applied_at"])
        else:
            return None
        started = time.monotonic()
        elapsed = (_utc(now_utc()) - _utc(timestamp)).total_seconds()
        if not 0 <= elapsed < READY_WINDOW_SECONDS:
            return None
        return started + (READY_WINDOW_SECONDS - elapsed)
    except Exception:
        # A failed window probe never turns the original busy into permission.
        return None


@contextmanager
def _ready_window_update_lock(control: Path, operator_sid: str, *, deadline: float | None = None):
    """Retry only acquisition busy, without renewing the caller's READY window."""
    with ExitStack() as stack:
        while True:
            try:
                stack.enter_context(update_lock(control, operator_sid))
                break
            except RuntimeError as error:
                if (str(error) != "update mutex ownership is busy or abandoned"
                        or getattr(error, "wait_result", None) != 0x102):
                    raise
                if deadline is None:
                    deadline = _ready_window_deadline(control)
                if deadline is None or time.monotonic() >= deadline:
                    raise
        # Keep the protected body outside the acquisition exception handler.
        yield


@writer_sink("auto_update_control")
def fixed_helper(control: Path, mode: str, *, code_root: Path | None = None) -> str:
    return _run_fixed_helper(control, mode, code_root=code_root)


def _run_fixed_helper(control: Path, mode: str, *, code_root: Path | None = None) -> str:
    import subprocess

    root = control.parent / "current"
    executable = system_executable("WindowsPowerShell/v1.0/powershell.exe")
    arguments = [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", str(root / "tools/apply_prepared_update.ps1"), "-InstallRoot", str(root), "-Mode", mode]
    if code_root is not None:
        arguments.extend(["-CodeRoot", str(code_root)])
    completed = subprocess.run(arguments, capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if completed.returncode:
        error = RuntimeError("fixed update helper failed: " + mode)
        error.stdout, error.stderr, error.exit_code = completed.stdout, completed.stderr, completed.returncode
        raise error
    return completed.stdout.strip()


def process_snapshot(control: Path) -> list[dict[str, Any]]:
    # Observe lists processes and mutates no product state. Keep its slow
    # PowerShell wait outside writer admission so trial GUI/relay can enter.
    rows = json.loads(_run_fixed_helper(control, "Observe"))
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
    pointer = read_json(control / "active.json")
    if pointer.get("sha") != sha or pointer.get("transition_id") != state["transition_id"]:
        raise ValueError("active pointer readback differs from durable decision")


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


def native_process_identity(pid: int) -> dict[str, Any]:
    """Observe process lifetime without treating inaccessible owners as absent."""
    import ctypes
    from ctypes import wintypes

    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return {"status": "UNKNOWN"}
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000 | 0x00100000, False, pid)
    if not handle:
        return {"status": "ABSENT" if ctypes.get_last_error() == 87 else "UNKNOWN"}
    try:
        wait = kernel.WaitForSingleObject(handle, 0)
        if wait == 0:
            return {"status": "ABSENT"}
        if wait != 258:
            return {"status": "UNKNOWN"}
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(value) for value in times]):
            return {"status": "UNKNOWN"}
        identity = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        return {"status": "LIVE", "creation_identity": str(identity)}
    finally:
        kernel.CloseHandle(handle)


def new_apply_claim() -> dict[str, Any]:
    owner = native_process_identity(os.getpid())
    if owner["status"] != "LIVE":
        raise ValueError("apply owner creation identity is unobservable")
    return {"schema": "code-update-apply-claim-v1", "status": "RUNNING",
            "pid": os.getpid(), "creation_identity": owner["creation_identity"],
            "started_at": now_utc()}


def apply_claim_status(control: Path) -> str:
    """A protected claim is progress evidence, never pointer or READY authority."""
    try:
        claim = optional_record(control / "apply-claim.json")
        if claim is None:
            return "NONE"
        if claim.get("schema") != "code-update-apply-claim-v1":
            return "UNKNOWN"
        if claim.get("status") == "SETTLED":
            return "NONE"
        if claim.get("status") != "RUNNING" or not isinstance(claim.get("creation_identity"), str):
            return "UNKNOWN"
        owner = native_process_identity(claim.get("pid"))
        if owner["status"] != "LIVE":
            return owner["status"]
        return "LIVE" if owner["creation_identity"] == claim["creation_identity"] else "ABSENT"
    except (OSError, ValueError, TypeError, KeyError):
        return "UNKNOWN"


def complete_apply_claim(control: Path) -> None:
    """Durably retire only this process's claim through the existing writer sink."""
    try:
        claim = optional_record(control / "apply-claim.json")
        if not claim or claim.get("pid") != os.getpid() or claim.get("status") != "RUNNING":
            return
        owner = native_process_identity(os.getpid())
        if owner.get("creation_identity") != claim.get("creation_identity"):
            return
        write_json_durable(control / "apply-claim.json", {**claim, "status": "SETTLED", "completed_at": now_utc()})
    except (OSError, ValueError, TypeError, KeyError):
        emit_support_record({"reason_code": "REPORT_UNAVAILABLE"}, stage="update_apply")


def emit_progress_guidance() -> None:
    report = support_record({"reason_code": "UPDATE_IN_PROGRESS"}, stage="update_apply")
    report["guidance"] = STARTUP_PROGRESS_MESSAGE
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


def update_relay_stop_requested(policy: Mapping[str, Any]) -> bool:
    """Read the installed operator's relay marker, including when running as SYSTEM."""
    from user_relay import user_relay_stop_path

    local = Path(policy["operator_local_app_data"])
    if not local.is_absolute():
        raise ValueError("operator profile is not absolute")
    root = local / "KMTech" / "DirectSync" / "container_audit"
    _assert_no_reparse_components(root)
    return user_relay_stop_path(root).exists()


def defer_stopped_update(control: Path, state) -> None:
    """Match pre-apply writer deferral; there is no trial to recover yet."""
    deferred = {**(state or {}), "schema": SCHEMA, "phase": "DEFERRED",
                "deferred_at": now_utc(), "reason_code": UPDATE_RELAY_STOP_REQUESTED}
    deferred.pop("recovery_pending", None)
    write_json_durable(control / "transition.json", deferred)


def apply_prepared(control: Path) -> int:
    """Preserve a failed preparation; never fall back after an uncertain switch."""
    from contextlib import nullcontext

    policy, before = None, None
    try:
        fixed_helper(control, "Authority")
        policy = read_json(control / "policy.json")
        before = read_json(control / "active.json")
        return _apply_prepared(control)
    except Exception as error:
        with update_lock(control, policy["operator_sid"]) if policy else nullcontext():
            state = optional_record(control / "transition.json")
            # Authority/policy/active failures are also preparation failures.
            # An in-flight journal remains UNKNOWN until a later SYSTEM decide.
            not_applied = (not state or state.get("phase") in {"CONFIRMED", "ROLLED_BACK", "DEFERRED", "PREPARED"})
            if before is not None:
                try:
                    not_applied = not_applied and read_json(control / "active.json") == before
                except (OSError, ValueError):
                    not_applied = False
            try:
                failed_prepared_sha = _sha(read_json(Path(policy["staging_root"]) / "prepared.json").get("source_commit")) if policy and not_applied else ""
            except (OSError, ValueError, KeyError, TypeError):
                failed_prepared_sha = ""
            failure = {**(state or {}), "schema": SCHEMA,
                       "phase": "DEFERRED" if not_applied else "UNKNOWN",
                       "deferred_at": now_utc(), "reason_code": "UPDATE_PREPARATION_FAILED",
                       "reason": type(error).__name__, "failure_details": _failure_details(error), "failure_evidence": [],
                       "failed_prepared_sha": failed_prepared_sha,
                       "failed_prepared_marker_sha256": prepared_failure_identity(policy) if policy and not_applied else ""}
            failure.pop("preparation_retry_pending", None)
            if not_applied and _transient_preparation_error(error):
                failure["failed_prepared_sha"] = ""
                failure["failed_prepared_marker_sha256"] = ""
                if failed_prepared_sha:
                    failure["retry_shas"], _ = record_retry_chance(
                        state or {}, failed_prepared_sha, now=failure["deferred_at"])
                else:
                    failure["preparation_retry_pending"] = True
            elif not_applied:
                signed_sha = _permanent_preparation_sha(error)
                if signed_sha:
                    failure["failed_shas"] = sorted(set(failure.get("failed_shas", [])) | {signed_sha})
            failure = mixed_status_record(failure)
            write_json_durable(control / ("failure-" + uuid.uuid4().hex + ".json"), failure)
            write_json_durable(control / "transition.json", failure)
        return 0 if not_applied else 20

    finally:
        complete_apply_claim(control)


def settle_trial_failure(control: Path, state: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    """SYSTEM only, with writer absence and the update lock already proved."""
    state = decide_trial_failure({**state, "phase": "ROLLBACK_PENDING",
                                  "recovery_pending": False}, policy)
    write_json_durable(control / "transition.json", state)
    selected = state["failure_decision"]["selected_sha"]
    fixed_helper(control, "Verify", code_root=version_bundle(control, selected))
    if selected == state["previous_sha"]:
        state = rollback_transition(state, writers_absent=True, previous_verified=True,
                                    durable_rollback=True, nonce=uuid.uuid4().hex, now=now_utc())
    persist_switch(control, state, selected)
    return state


class _RollbackReadyPending(Exception):
    """Release update ownership before observing the restored ordinary trial."""


def observe_trial_ready(control, policy, state, rows, claim, receipt, *, deadline):
    """Candidate and rollback use the same process-bound READY validation."""
    import time

    sha = state["previous_sha"] if state["phase"] == "ROLLBACK_PENDING_READY" else state["candidate_sha"]
    if state.get("trial_pid") is None and claim and claim.get("nonce") == state["nonce"] and claim.get("transition_id") == state["transition_id"]:
        row = next((row for row in rows if row.get("pid") == claim.get("pid")), None)
        if row and process_matches_trial(row, state=state, sha=sha, sid=policy["operator_sid"], role="gui"):
            state = bind_trial(state, sha=sha, pid=row["pid"], ordinary_user=True, now=row["created_at"])
            write_json_durable(control / "transition.json", state)
    gui = next((row for row in rows if row.get("pid") == state.get("trial_pid")), None)
    relays = [row for row in rows if process_matches_trial(row, state=state, sha=sha, sid=policy["operator_sid"], role="relay")]
    process_ok = bool(gui and process_matches_trial(gui, state=state, sha=sha, sid=policy["operator_sid"], role="gui"))
    if time.monotonic() < deadline and receipt and ready_matches(state, receipt, process_matches=process_ok, relay_matches=len(relays) == 1, now=now_utc()):
        confirmed = confirm_transition(state, receipt, process_matches=process_ok, relay_matches=True, now=now_utc())
        write_json_durable(control / "transition.json", confirmed)
        record_confirmed_policy(control, confirmed)
        return confirmed, True, False
    return state, False, bool(state.get("trial_pid") and gui is None)


def wait_for_rollback_ready(control: Path, policy: Mapping[str, Any]) -> int:
    """Resume the existing recovery window without renewing it after a restart."""
    import time

    stage = Path(policy["staging_root"])
    with _ready_window_update_lock(control, policy["operator_sid"]):
        state = read_json(control / "transition.json")
        if state.get("phase") == "ROLLED_BACK":
            return 0
        if state.get("phase") != "ROLLBACK_PENDING_READY":
            return 20
        remaining = max(0.0, READY_WINDOW_SECONDS - (_utc(now_utc()) - _utc(state.get("rollback_at", state["applied_at"]))).total_seconds())
    deadline = time.monotonic() + min(READY_WINDOW_SECONDS, remaining)
    while time.monotonic() < deadline:
        with _ready_window_update_lock(control, policy["operator_sid"], deadline=deadline):
            state = read_json(control / "transition.json")
            if state.get("phase") == "ROLLED_BACK":
                return 0
            if (state.get("phase") != "ROLLBACK_PENDING_READY"
                    or read_json(control / "active.json")["sha"] != state["previous_sha"]):
                return 20
            try:
                rows = process_snapshot(control)
                claim = optional_record(stage / "trial.json")
                receipt = optional_record(stage / "ready.json")
                state, confirmed, exited = observe_trial_ready(
                    control, policy, state, rows, claim, receipt, deadline=deadline)
            except (OSError, ValueError, TypeError, KeyError) as error:
                # Unreadable or forged evidence cannot confirm or renew the trial.
                write_json_durable(control / "transition.json", {**state, "last_ready_error": type(error).__name__})
                confirmed = exited = False
            if confirmed:
                return 0
            if exited:
                break
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
    with update_lock(control, policy["operator_sid"]):
        state = read_json(control / "transition.json")
        if state.get("phase") == "ROLLED_BACK":
            return 0
        if state.get("phase") == "ROLLBACK_PENDING_READY":
            write_json_durable(control / "transition.json", {**state, "phase": "FAILED", "reason": "previous version readiness failed"})
    return 20


def _apply_prepared(control: Path) -> int:
    try:
        return _apply_prepared_once(control)
    except _RollbackReadyPending:
        return wait_for_rollback_ready(control, read_json(control / "policy.json"))


def _apply_prepared_once(control: Path) -> int:
    """SYSTEM applies code only; the operator bootstrap launches the trial."""
    from user_relay import RELAY_NORMAL_STOP_TIMEOUT_SECONDS
    import time
    from update_service import file_sha256

    opened_here = False
    fixed_helper(control, "Authority")
    policy = read_json(control / "policy.json")
    # SYSTEM must never resolve user credentials or start a user process.
    os.environ["LOCALAPPDATA"] = policy["operator_local_app_data"]
    stage = Path(policy["staging_root"])
    with _ready_window_update_lock(control, policy["operator_sid"]):
        state = optional_record(control / "transition.json")
        if state and state.get("reason_code") == "UPDATE_PREPARATION_FAILED" and state["phase"] == "DEFERRED" and not state.get("recovery_pending") and not prepared_pending(control, policy, state):
            return 0
        write_json_durable(control / "apply-claim.json", new_apply_claim())
        if state and state["phase"] == "CONFIRMED":
            state = record_confirmed_policy(control, state)
        if state and state.get("recovery_pending") is True:
            if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                return 0  # Pending recovery never admits a new prepared packet.
            state = settle_trial_failure(control, state, policy)
        if state and state["phase"] in {"APPLIED_PENDING_READY", "UNKNOWN", "FAILED"}:
            rows = process_snapshot(control)
            writers = writer_processes(rows, own_pid=os.getpid())
            claim = optional_record(stage / "trial.json")
            bound = state.get("trial_pid")
            if (not bound and claim and claim.get("nonce") == state.get("nonce")
                    and claim.get("transition_id") == state.get("transition_id")):
                bound = claim.get("pid")
            trial_live = state["phase"] == "APPLIED_PENDING_READY" and any(
                row.get("pid") == bound and process_matches_trial(row, state=state,
                    sha=state["candidate_sha"], sid=policy["operator_sid"], role="gui") for row in writers)
            if writers and not trial_live:
                # A later SYSTEM invocation never stops an ordinary active writer
                # or upgrades its unconfirmed trial to CONFIRMED.
                write_json_durable(control / "transition.json", {**state, "phase": "DEFERRED",
                    "retained_candidate": False, "deferred_at": now_utc(), "reason_code": "UPDATE_EXISTING_WRITER",
                    "recovery_pending": True, "recovery_phase": state["phase"],
                    "recovery_reason_code": state.get("reason_code")})
                return 0
        if state and state["phase"] == "ROLLBACK_PENDING_READY":
            pointer = read_json(control / "active.json")
            selected = recovery_sha(state, pointer_sha=pointer["sha"])
            if pointer["sha"] != selected:
                if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                    return 20
                fixed_helper(control, "Verify", code_root=version_bundle(control, selected))
                persist_switch(control, state, selected)
            raise _RollbackReadyPending
        if state and state["phase"] in {"UNKNOWN", "FAILED"}:
            if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                return 20
            state = settle_trial_failure(control, state, policy)
            if state["phase"] == "ROLLBACK_PENDING_READY":
                raise _RollbackReadyPending
        if state and state.get("retained_candidate") is True and state["phase"] == "DEFERRED":
            # Resume an interrupted decision publication without retrying the trial.
            selected = recovery_sha(state, pointer_sha=read_json(control / "active.json")["sha"])
            if read_json(control / "active.json")["sha"] != selected:
                fixed_helper(control, "Verify", code_root=version_bundle(control, selected))
                persist_switch(control, state, selected)
                return 20
        if state is None or state["phase"] in {"CONFIRMED", "ROLLED_BACK", "DEFERRED"}:
            if not prepared_pending(control, policy, state):
                return 0
            if update_relay_stop_requested(policy):
                defer_stopped_update(control, state)
                return 0
            if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                deferred = {**(state or {}), "schema": SCHEMA, "phase": "DEFERRED", "deferred_at": now_utc(), "reason": "an existing application writer continues working"}
                write_json_durable(control / "transition.json", deferred)
                return 0  # A late task defers; it never stops an existing application.
            active = read_json(control / "active.json")
            fixed_helper(control, "Verify", code_root=version_bundle(control, active["sha"]))
            current = version_manifest(version_bundle(control, active["sha"]), require_version=True)
            key = read_json(control.parent / "current/app/update-manifest-key-config.json")["manifest_public_key"]
            # Copy user-owned bytes, then authenticate the protected copy. No path,
            # executable or command supplied by the prepared marker is executed.
            protected = control / ("packet-" + uuid.uuid4().hex)
            create_protected_stage(protected)
            for name in ("manifest.json", "manifest.sig", "packet.zip"):
                copy_prepared_file(stage / name, protected / name, expected_owner_sid=policy["operator_sid"])
            try:
                manifest, candidate = verify_prepared_packet(protected, key_config=key, current_version=current["version"], channel=policy["channel"])
            except ValueError as error:
                error._preparation_rejection = True
                raise
            sha = manifest["source_commit"]
            if sha in (state or {}).get("failed_shas", []):
                return 0
            with _authenticated_preparation(sha):
                extracted = protected / "extracted"
                try:
                    extract_prepared_code(protected / "packet.zip", extracted, candidate["archive_policy"])
                except ValueError as error:
                    error._preparation_rejection = True
                    raise
                target = extracted / "Container_Audit"
                # Verify stock bytes before reading version/contract authority.
                fixed_helper(control, "Verify", code_root=target)
                try:
                    candidate_manifest = version_manifest(target, require_version=True)
                except ValueError as error:
                    error._preparation_rejection = True
                    raise
                if candidate_manifest["source_commit"] != sha or candidate_manifest["version"] != manifest["version"]:
                    raise _preparation_rejection("signed target SHA differs from the packet")
                if file_sha256(target / "app/update-manifest-key-config.json") != file_sha256(control.parent / "current/app/update-manifest-key-config.json"):
                    raise _preparation_rejection("candidate signing key differs from the installed key")
                try:
                    forward, rollback, rollback_pair, pin_authority = manifest_transition_pins(manifest, current=current, candidate=candidate_manifest)
                except ValueError as error:
                    error._preparation_rejection = True
                    raise
            # The fixed helper validates the portable tree and writes its own
            # integrity record. It never imports or executes candidate code.
            target_bundle = version_bundle(control, sha)
            if target_bundle.exists():
                fixed_helper(control, "Verify", code_root=target_bundle)
            preserve_candidate_version(target, target_bundle)
            generation_before = read_trial_generation(policy)
            if generation_before.get("status") != "READ":
                write_json_durable(control / "transition.json", {**(state or {}), "schema": SCHEMA,
                    "phase": "DEFERRED", "deferred_at": now_utc(), "reason_code": "UPDATE_GENERATION_UNKNOWN"})
                return 0
            state = prepare_transition(previous_sha=active["sha"], candidate_sha=sha, packet_sha256=candidate["sha256"], forward_pin=forward, rollback_pin=rollback, transition_id=uuid.uuid4().hex, nonce=uuid.uuid4().hex, now=now_utc(), failed_shas=(state or {}).get("failed_shas", []), retry_shas=(state or {}).get("retry_shas"))
            preimage = "policy-before-" + state["transition_id"] + ".json"
            write_json_durable(control / preimage, policy)
            state = {**state, "rollback_pair": rollback_pair, "pin_authority": pin_authority, "policy_preimage": preimage,
                     "protected_packet": protected.name,
                     "generation_before": generation_before,
                     "generation_previous_release": {name: current[name] for name in ("version", "source_commit")},
                     "generation_candidate_release": {name: candidate_manifest[name] for name in ("version", "source_commit")}}
            write_json_durable(control / "transition.json", state)
            state = apply_transition(state, writers_absent=not writer_processes(process_snapshot(control), own_pid=os.getpid()), packet_verified=True, durable_prepared=True, now=now_utc())
            opened_here = True
            persist_switch(control, state, sha)
        else:
            pointer = read_json(control / "active.json")
            if state["phase"] == "PREPARED":
                if update_relay_stop_requested(policy):
                    defer_stopped_update(control, state)
                    return 0
                protected_name = state.get("protected_packet")
                if not isinstance(protected_name, str) or re.fullmatch(r"packet-[0-9a-f]{32}", protected_name) is None:
                    raise _preparation_rejection("daily_update_prepared_authentication_missing")
                old_bundle = version_bundle(control, state["previous_sha"])
                target_bundle = version_bundle(control, state["candidate_sha"])
                fixed_helper(control, "Verify", code_root=old_bundle)
                fixed_helper(control, "Verify", code_root=target_bundle)
                key = read_json(control.parent / "current/app/update-manifest-key-config.json")["manifest_public_key"]
                previous_manifest = version_manifest(old_bundle, require_version=True)
                try:
                    resumed_manifest, resumed_candidate = verify_prepared_packet(control / protected_name, key_config=key,
                        current_version=previous_manifest["version"], channel=policy["channel"])
                except ValueError as error:
                    error._preparation_rejection = True
                    raise
                with _authenticated_preparation(resumed_manifest["source_commit"]):
                    try:
                        forward, reverse, rollback_pair, authority = manifest_transition_pins(resumed_manifest,
                            current=previous_manifest, candidate=version_manifest(target_bundle, require_version=True))
                    except ValueError as error:
                        error._preparation_rejection = True
                        raise
                    if (resumed_candidate["sha256"] != state["packet_sha256"] or forward != state["forward_pin"]
                            or reverse != state["rollback_pin"] or rollback_pair != state.get("rollback_pair")
                            or authority != state.get("pin_authority")):
                        raise _preparation_rejection("daily_update_prepared_binding_mismatch")
                if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                    return 20
                fixed_helper(control, "Verify", code_root=version_bundle(control, state["candidate_sha"]))
                state = apply_transition(state, writers_absent=True, packet_verified=True, durable_prepared=True, now=now_utc())
                opened_here = True
                persist_switch(control, state, state["candidate_sha"])
            if state["phase"] == "ROLLBACK_PENDING":
                if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                    return 20
                settled = settle_trial_failure(control, state, policy)
                if settled.get("retained_candidate"):
                    return 20
                raise _RollbackReadyPending
            sha = recovery_sha(state, pointer_sha=pointer["sha"])
            if pointer["sha"] != sha:
                if writer_processes(process_snapshot(control), own_pid=os.getpid()):
                    return 20
                persist_switch(control, state, sha)
    remaining = READY_WINDOW_SECONDS - (_utc(now_utc()) - _utc(state["applied_at"])).total_seconds()
    deadline = time.monotonic() + min(READY_WINDOW_SECONDS, max(0.0, remaining))
    while time.monotonic() < deadline:
        with _ready_window_update_lock(control, policy["operator_sid"], deadline=deadline):
            state = read_json(control / "transition.json")
            if state["phase"] in {"CONFIRMED", "ROLLED_BACK"}:
                return 0
            if state["phase"] not in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"}:
                return 20
            rows = process_snapshot(control)
            claim = None
            receipt = None
            try:
                claim = optional_record(stage / "trial.json")
                receipt = optional_record(stage / "ready.json")
            except OSError as error:
                # A contested user proof is unconfirmed; keep the original
                # journal deadline and normal stop/rollback decision alive.
                state = {**state, "last_ready_error": type(error).__name__}
                write_json_durable(control / "transition.json", state)
            state, confirmed, exited = observe_trial_ready(
                control, policy, state, rows, claim, receipt, deadline=deadline)
            if confirmed:
                return 0
            if exited:
                break
        time.sleep(0.25)
    with update_lock(control, policy["operator_sid"]):
        state = read_json(control / "transition.json")
        if state["phase"] in {"CONFIRMED", "ROLLED_BACK"}:
            return 0
        if state["phase"] == "ROLLBACK_PENDING_READY":
            write_json_durable(control / "transition.json", {**state, "phase": "FAILED", "reason": "previous version readiness failed"})
            return 20
        if opened_here:
            # Failed launch, early exit, and timeout are unknown without
            # verification evidence and consume only a bounded retry chance.
            state = request_rollback(state, reason="candidate startup failed or readiness timed out",
                                     transient=True, now=now_utc())
        else:
            if state["phase"] != "APPLIED_PENDING_READY":
                raise ValueError("rollback requires a pending trial")
            # Keep inherited uncertainty for the generation decision. Every failed
            # READY attempt consumes the same bounded retry chance exactly once.
            state = {**state, "phase": "UNKNOWN"}
            state["retry_shas"], _ = record_retry_chance(
                state, state["candidate_sha"], now=now_utc())
        state = {**state, "normal_stop_started_at": state.get("normal_stop_started_at") or now_utc()}
        write_json_durable(control / "transition.json", state)
    # The fixed PS5.1 apply helper merges stderr under ErrorActionPreference=Stop.
    # This wait intentionally emits no diagnostic stream (lane ANSWER-3).
    remaining = RELAY_NORMAL_STOP_TIMEOUT_SECONDS - (_utc(now_utc()) - _utc(state["normal_stop_started_at"])).total_seconds()
    deadline = time.monotonic() + min(RELAY_NORMAL_STOP_TIMEOUT_SECONDS, max(0.0, remaining))
    while time.monotonic() < deadline:
        with update_lock(control, policy["operator_sid"]):
            if not writer_processes(process_snapshot(control), own_pid=os.getpid()):
                settled = settle_trial_failure(control, state, policy)
                if settled.get("retained_candidate"):
                    return 20
                raise _RollbackReadyPending
        time.sleep(0.25)
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
    _copy_prepared_bytes(source, target, expected_owner_sid=expected_owner_sid)


def _copy_prepared_bytes(source: Path, target: Path, *, expected_owner_sid: str | None = None) -> None:
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


def prepared_failure_identity(policy: Mapping[str, Any]) -> str:
    if not isinstance(policy.get("staging_root"), str) or not policy["staging_root"]: return ""
    path = Path(policy["staging_root"]) / "prepared.json"
    try:
        _assert_no_reparse_components(path)
        with path.open("rb") as source:
            return hashlib.sha256(source.read(1024 * 1024 + 1)).hexdigest()
    except (OSError, ValueError):
        return hashlib.sha256(b"unreadable prepared marker:" + os.fsencode(path)).hexdigest()


def prepared_pending(control: Path, policy: Mapping[str, Any], state: Mapping[str, Any] | None) -> bool:
    if not policy.get("feed_url"):
        return False
    if (state or {}).get("preparation_retry_pending") is True and not _preparation_retry_due(state, ""):
        return False
    path = Path(policy["staging_root"]) / "prepared.json"
    if (state or {}).get("reason_code") == "UPDATE_PREPARATION_FAILED":
        identity = prepared_failure_identity(policy)
        if identity and identity == state.get("failed_prepared_marker_sha256"):
            return False
    try:
        marker = optional_record(path)
    except (OSError, ValueError):
        return path.exists() and _preparation_retry_due(state, "")  # Verify when the saved wait permits.
    if marker is None:
        return False
    try:
        sha = _sha(marker.get("source_commit"))
    except ValueError:
        return True
    active = read_json(control / "active.json")
    return (sha != active["sha"] and sha not in (state or {}).get("failed_shas", [])
            and _preparation_retry_due(state, sha))


def prepare_feed_packet(app_root: Path) -> dict[str, Any]:
    """The ordinary relay downloads; only completed authenticated bytes are marked."""
    from urllib.parse import urlsplit, urlunsplit
    import requests
    from update_service import (verify_update_manifest_signature, update_candidate_from_private_manifest,
                                file_sha256, assert_https_update_url, is_github_hosted_update_url,
                                validate_update_archive, _is_zip_symlink, _validate_windows_archive_path)
    from current_user_onboarding import resolve_current_user_onboarding_paths, _default_profile_loader

    control = control_root(app_root)
    if control is None:
        return {"status": "OFF"}
    policy = read_json(control / "policy.json")
    if not policy.get("feed_url"):
        return {"status": "OFF"}
    key = read_json(control.parent / "current/app/update-manifest-key-config.json")["manifest_public_key"]
    active = read_json(control / "active.json")
    active_bundle = version_bundle(control, active["sha"])
    verify_lifecycle_stock(active_bundle)
    current = version_manifest(active_bundle, require_version=True)
    profile = _default_profile_loader(resolve_current_user_onboarding_paths(app_root).logistics_profile_path) if policy.get("profile_auth") else None
    feed_url = assert_https_update_url(policy["feed_url"])
    if is_github_hosted_update_url(feed_url):
        raise ValueError("daily update feed cannot use hosted update aliases")
    feed = urlsplit(feed_url)
    origin = lambda url: (url.scheme.lower(), (url.hostname or "").lower(), url.port or 443)
    if profile is not None and origin(feed) != origin(urlsplit(profile.base_url)):
        raise ValueError("profile authentication requires the configured authority origin")
    def fetch(session, url):
        url = assert_https_update_url(url)
        if is_github_hosted_update_url(url):
            raise ValueError("daily update download cannot use hosted update aliases")
        session.cookies.clear()
        headers = {"Authorization": "Bearer " + profile.bearer_token} if profile is not None and origin(urlsplit(url)) == origin(feed) else {}
        headers["User-Agent"] = DEFAULT_PRODUCER_USER_AGENT
        response = session.get(url, headers=headers, timeout=10, stream=True, allow_redirects=False, verify=(profile.tls_ca_bundle_path or True) if profile is not None else True)
        if response.status_code != 200 or response.url != url:
            response.close()
            raise ValueError(f"update download HTTP status differs (코드 {response.status_code})")
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
        manifest_bytes = bounded(fetch(session, feed_url), 1024 * 1024)
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
        def run_attempt(attempt, temporary_paths):
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
            import zipfile
            with zipfile.ZipFile(attempt / "packet.zip") as archive:
                entries = archive.infolist()
                validate_update_archive(archive, candidate["archive_policy"])
                prefix = entries[0].filename.split("/", 1)[0] + "/"
                for entry in entries:
                    _validate_windows_archive_path(entry.filename)
                    if _is_zip_symlink(entry):
                        raise ValueError("update ZIP contains a redirected entry")
                def read_candidate_bytes(name):
                    entry = archive.getinfo(prefix + name)
                    if entry.file_size > 16 * 1024 * 1024:
                        raise ValueError("update identity input is oversized")
                    return archive.read(entry)
                authorize_feed_transition(manifest, current=current, candidate=version_identity(read_candidate_bytes))
            # Prepare all authenticated bytes before any fixed name is replaced.
            temporary_paths.update(stage_prepared_copies(attempt, stage))
            publish_download(stage, temporary_paths)
            write_json_durable(stage / "prepared.json", {"source_commit": sha, "packet_sha256": candidate["sha256"], "prepared_at": now_utc()})
            return {"status": "PREPARED", "source_commit": sha}

        return _run_download_attempt(stage, run_attempt)


@writer_sink("auto_update_control")
def create_download_stage(path: Path) -> None:
    _assert_no_reparse_components(path)
    ensure_user_runtime_directory(path)


@writer_sink("auto_update_control", probe_only=True)
def write_download_bytes(path: Path, data: bytes) -> None:
    _assert_no_reparse_components(path)
    with path.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


@writer_sink("auto_update_control", probe_only=True)
def write_download_chunk(path: Path, data: bytes) -> None:
    _assert_no_reparse_components(path)
    with path.open("ab") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _discard_prepared_copies(stage: Path, temporary_paths: Mapping[str, Path]) -> None:
    _assert_no_reparse_components(stage)
    for name, temporary in temporary_paths.items():
        if (name not in ("manifest.json", "manifest.sig", "packet.zip")
                or temporary.parent.absolute() != stage.absolute()
                or re.fullmatch(re.escape(name) + r"\.[0-9a-f]{32}\.tmp", temporary.name) is None):
            raise ValueError("prepared temporary path differs from this attempt")
        _assert_no_reparse_components(temporary)
    for temporary in temporary_paths.values():
        temporary.unlink(missing_ok=True)


@writer_sink("auto_update_control", probe_only=True)
def stage_prepared_copies(attempt: Path, stage: Path) -> dict[str, Path]:
    temporary_paths = {name: stage / (name + "." + uuid.uuid4().hex + ".tmp")
                       for name in ("manifest.json", "manifest.sig", "packet.zip")}
    for temporary in temporary_paths.values():
        _assert_no_reparse_components(temporary)
        if temporary.exists():
            raise FileExistsError("prepared temporary already exists")
    try:
        for name, temporary in temporary_paths.items():
            try:
                _copy_prepared_bytes(attempt / name, temporary)
            except FileExistsError:
                # An exclusive-create collision belongs to somebody else.
                temporary_paths = {key: value for key, value in temporary_paths.items() if key != name}
                raise
    except BaseException as failure:
        try:
            _discard_prepared_copies(stage, temporary_paths)
        except Exception as cleanup_error:
            failure.add_note("UPDATE_ATTEMPT_CLEANUP_FAILED: " + type(cleanup_error).__name__)
        raise
    return temporary_paths


@writer_sink("auto_update_control")
def publish_download(stage: Path, temporary_paths: Mapping[str, Path]) -> None:
    from atomic_replace import atomic_replace
    for name in ("manifest.json", "manifest.sig", "packet.zip"):
        atomic_replace(temporary_paths[name], stage / name)


@writer_sink("auto_update_control", probe_only=True)
def _run_download_attempt(stage: Path, run) -> dict[str, Any]:
    # This probe owns the entire attempt. Its finally must finish even if a
    # fence starts during an off-admission write; a fresh cleanup probe would
    # refuse and leave the packet behind. Only this attempt's temporary names
    # may be removed, never fixed names or prepared.json.
    create_download_stage(stage)
    attempt = stage / ("download-" + uuid.uuid4().hex)
    temporary_paths: dict[str, Path] = {}
    failure = None
    try:
        create_protected_stage(attempt)
        return run(attempt, temporary_paths)
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            if (attempt.parent.absolute() != stage.absolute()
                    or re.fullmatch(r"download-[0-9a-f]{32}", attempt.name) is None):
                raise ValueError("download attempt path differs")
            _assert_no_reparse_components(attempt)
            entries = list(attempt.iterdir()) if attempt.exists() else []
            for entry in entries:
                if entry.name not in ("manifest.json", "manifest.sig", "packet.zip"):
                    raise ValueError("download attempt contains an unexpected entry")
                _assert_no_reparse_components(entry)
                if not entry.is_file():
                    raise ValueError("download attempt entry is not a file")
            _discard_prepared_copies(stage, temporary_paths)
            for entry in entries:
                entry.unlink()
            if attempt.exists():
                attempt.rmdir()
        except Exception as cleanup_error:
            if failure is None:
                raise
            failure.add_note("UPDATE_ATTEMPT_CLEANUP_FAILED: " + type(cleanup_error).__name__)



def trial_stop_requested(app_root: Path) -> bool:
    context = trial_context(app_root)
    return bool(context and context[2]["phase"] in {"ROLLBACK_PENDING", "UNKNOWN", "FAILED"})


def relay_ready_metadata(app_root: Path) -> dict[str, Any]:
    control = control_root(app_root)
    if control is None:
        return {"process_id": os.getpid()}
    policy = read_json(control / "policy.json")
    report = {"process_id": os.getpid(), "source_commit": version_manifest(app_root.parent)["source_commit"],
              "ordinary_user": ordinary_user_context(policy["operator_sid"])}
    context = trial_context(app_root)
    if context is not None:
        report["update_nonce"] = context[2]["nonce"]
    return report


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


def startup_requires_bootstrap(state, *, prepared_present, running_sha, active_sha):
    """The ordinary startup decision, shared with the read-only checker."""
    return not (
        not prepared_present and not (state and state.get("recovery_pending") is True)
        and (not state or state["phase"] in {"CONFIRMED", "ROLLED_BACK", "DEFERRED"})
        and running_sha == active_sha
    )


@contextmanager
def startup_update_lock(control: Path, policy: Mapping[str, Any], *, deadline: float | None = None, wait_check=None):
    started = time.monotonic()
    limit = started + APPLY_PROGRESS_TIMEOUT
    acquired = False
    with ExitStack() as stack:
        while True:
            if apply_claim_status(control) in {"LIVE", "UNKNOWN"}:
                limit = started + 240
            remaining = min(limit, deadline if deadline is not None else limit) - time.monotonic()
            try:
                stack.enter_context(update_lock(control, policy["operator_sid"], timeout_ms=max(0, min(5000, int(remaining * 1000)))))
                acquired = True
                break
            except RuntimeError as error:
                if str(error) != "update mutex ownership is busy or abandoned" or getattr(error, "wait_result", 0x102) != 0x102:
                    raise
                if wait_check is not None and not wait_check():
                    break
                if time.monotonic() >= min(limit, deadline if deadline is not None else limit):
                    break
                time.sleep(min(0.1, max(0, min(limit, deadline if deadline is not None else limit) - time.monotonic())))
        try:
            if sys.stderr is not None and "--apply-prepared" not in sys.argv:
                print(json.dumps({"stage": "update_lock_wait",
                    "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
                    "acquired": acquired}), file=sys.stderr)
        except Exception:
            pass
        yield acquired


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
    with startup_update_lock(control, policy) as acquired:
        state = optional_record(control / "transition.json")
        active = read_json(control / "active.json")
        manifest = version_manifest(app_root.parent)
        sha = manifest["source_commit"]
        try:
            from startup_check_report import observe
            observe("release_identity", {"version": manifest.get("version"), "build_id": sha})
        except Exception:
            pass
        if not acquired:
            if sha == active["sha"] and startup_action(state, prepared_present=False) == "START_CURRENT" and (not (state or {}).get("retained_candidate") or sha == recovery_sha(state, pointer_sha=sha)) and current_generation_status(control, policy, sha) == "ALLOW":
                emit_support_record({"reason_code": "UPDATE_LOCK_WAIT_EXPIRED", "exit_code": 0}, stage="update_apply", policy=policy)
                return None
            emit_progress_guidance()
            return 20
        if sha == active["sha"] and state and state["phase"] in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"}:
            if os.environ.get("KMTECH_CA_UPDATE_TRIAL_NONCE") == state["nonce"] and ordinary_user_context():
                claim = optional_record(Path(policy["staging_root"]) / "trial.json")
                if claim and claim.get("nonce") == state["nonce"] and claim.get("transition_id") == state["transition_id"] and (role == "relay" or claim.get("pid") == os.getpid()):
                    return None
        deferred_at = os.environ.get("KMTECH_CA_UPDATE_DEFERRED_AT")
        rollback_recovery_gui = bool(state and state["phase"] == "ROLLBACK_PENDING_READY"
                                     and role == "gui" and apply_claim_status(control) == "ABSENT")
        if sha == active["sha"] and deferred_at and (not state or state["phase"] in {"PREPARED", "CONFIRMED", "ROLLED_BACK", "DEFERRED", "FAILED", "UNKNOWN", "APPLIED_PENDING_READY"} or rollback_recovery_gui):
            _utc(deferred_at)
            if state and state["phase"] in {"PREPARED", "FAILED", "UNKNOWN", "APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"}:
                assert_ordinary_recovery(control, policy, sha, deferred_at)
            # Ordinary active-code admission only. The unchanged G guard still
            # runs before data access; this grants no pointer or trial authority.
            return None
        prepared = prepared_pending(control, policy, state)
        if not startup_requires_bootstrap(state, prepared_present=prepared, running_sha=sha, active_sha=active["sha"]):
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
        error = RuntimeError("the installed update task could not be requested")
        error.stdout, error.stderr, error.exit_code = result.stdout, result.stderr, result.returncode
        raise error


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


def current_generation_status(control: Path, policy: Mapping[str, Any], sha: str) -> str:
    from kmtech_shared import data_generation as generation

    try:
        observed = read_trial_generation(policy)
        if observed.get("status") != "READ":
            return "UNKNOWN"
        release = version_manifest(version_bundle(control, sha), require_version=True)
        return generation.probe_downgrade([observed["marker_path"]], release["version"],
            app_id="container_audit", subject_sid=policy["operator_sid"], target_build_id=sha)["status"]
    except (OSError, ValueError, TypeError, KeyError):
        return "UNKNOWN"


def assert_ordinary_recovery(control: Path, policy: Mapping[str, Any], sha: str, started_at: str) -> list[Mapping[str, Any]]:
    """Caller owns the update lock; native process creation registers writers."""
    if read_json(control / "active.json")["sha"] != sha:
        raise ValueError("ordinary recovery code is not the active version")
    if current_generation_status(control, policy, sha) != "ALLOW":
        raise ValueError("ordinary recovery requires current data generation allowance")
    started = _utc(started_at)
    writers = writer_processes(process_snapshot(control), own_pid=os.getpid())
    for row in writers:
        if (row.get("sha") != sha or row.get("sid") != policy["operator_sid"]
                or row.get("ordinary_user") is not True or row.get("role") not in {"gui", "relay"}
                or _utc(row.get("created_at")) < started):
            raise ValueError("an earlier or unrelated writer prevents ordinary recovery")
    return writers


def _launch_bootstrap_version(control: Path, sha: str, arguments: list[str], *, deadline: float, **kwargs) -> int:
    """Retry transient relay admission within this bootstrap's existing window."""
    while True:
        try:
            return launch_version(control, sha, arguments, **kwargs)
        except WriterFencedError as error:
            if arguments[:1] != ["--container-audit-user-relay"] or error.code != "WRITER_GATE_TIMEOUT":
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            # launch_version has unwound its writer admission before waiting.
            time.sleep(min(0.1, remaining))
            if time.monotonic() >= deadline:
                raise



def _bootstrap_recovery_gui(control: Path, policy: Mapping[str, Any], state, active, arguments,
                            *, claim_status: str, deadline: float) -> int | None:
    """Caller owns the update lock; only a settled ordinary relay admits a GUI."""
    phase = (state or {}).get("phase")
    eligible = (phase in {"FAILED", "UNKNOWN"}
                or phase == "DEFERRED" and state.get("recovery_pending") is True
                or phase in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"} and claim_status == "ABSENT")
    if not eligible or claim_status not in {"NONE", "ABSENT"}:
        return None
    try:
        writers = writer_processes(process_snapshot(control), own_pid=os.getpid())
        if not writers:
            return None
        if any(row.get("role") == "gui" for row in writers):
            return 0
        if len(writers) != 1 or writers[0].get("role") != "relay":
            raise ValueError("GUI recovery requires exactly one ordinary relay")
        relay = writers[0]
        if type(relay.get("pid")) is not int or relay["pid"] <= 0:
            raise ValueError("relay process identity is unreadable")
        boundary = relay.get("created_at")
        if _utc(boundary) > _utc(now_utc()):
            raise ValueError("relay creation time is in the future")
        proved = assert_ordinary_recovery(control, policy, active["sha"], boundary)
        if (len(proved) != 1 or proved[0].get("role") != "relay"
                or type(proved[0].get("pid")) is not int
                or proved[0].get("pid") != relay.get("pid")
                or proved[0].get("created_at") != boundary):
            raise ValueError("relay observation changed during recovery proof")
        _launch_bootstrap_version(control, active["sha"], arguments, deadline=deadline, deferred_at=boundary)
        return 0
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        emit_progress_guidance()
        return 20


def _bootstrap_existing_writers(control: Path, policy: Mapping[str, Any], active, arguments,
                                *, role: str, deadline: float) -> int | None:
    """Caller owns the update lock; relay success requires launch or live proof."""
    try:
        writers = writer_processes(process_snapshot(control), own_pid=os.getpid())
        if not writers:
            return None
        if role != "relay":
            return 0
        sha = active["sha"]
        deferred_at = os.environ.get("KMTECH_CA_UPDATE_DEFERRED_AT")
        if deferred_at:
            if _utc(deferred_at) >= _utc(now_utc()):
                raise ValueError("ordinary recovery boundary must precede this request")
            # Return the exact observation that passed the existing cohort proof.
            writers = assert_ordinary_recovery(control, policy, sha, deferred_at)
        else:
            # A logon request has no inherited boundary. It may reuse a proven
            # ordinary relay, but cannot create a new cohort beside a writer.
            if read_json(control / "active.json")["sha"] != sha or current_generation_status(control, policy, sha) != "ALLOW":
                raise ValueError("ordinary relay reuse requires the active allowed version")
            for row in writers:
                if (row.get("sha") != sha or row.get("sid") != policy["operator_sid"]
                        or row.get("ordinary_user") is not True or row.get("role") not in {"gui", "relay"}):
                    raise ValueError("an unrelated writer prevents ordinary relay reuse")
                _utc(row.get("created_at"))
        if any(row.get("role") == "relay" for row in writers):
            return 0
        if not deferred_at:
            raise ValueError("ordinary relay launch requires the inherited boundary")
        _launch_bootstrap_version(control, sha, arguments, deadline=deadline, deferred_at=deferred_at)
        return 0
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        if role != "relay":
            raise
        emit_progress_guidance()
        return 20


def start_current(control: Path, policy: Mapping[str, Any], state, active, arguments, *, code: str, report_once: bool = False, deadline: float | None = None) -> int:
    """Reuse ordinary launch and publish only the E9 allowlisted support fields."""
    if _retry_review_required(state):
        code = UPDATE_RETRY_REVIEW_REQUIRED
    report = support_record({"reason_code": code,
        "transition_code": (state or {}).get("failure_decision", {}).get("code", code),
        "retained_candidate": (state or {}).get("retained_candidate") is True}, stage="update_apply")
    try:
        report_path = Path(policy["staging_root"]) / "startup-support.json"
        previous = None
        if code == "UPDATE_LOCK_WAIT_EXPIRED":
            report["exit_code"] = 0
        if report_once:
            claim_hash = hashlib.sha256((control / "apply-claim.json").read_bytes()).hexdigest()
            report = support_record({**report, "apply_claim_sha256": claim_hash}, stage="update_apply")
            previous = optional_record(report_path)
        if not (report_once and previous and previous.get("reason_code") == code
                and previous.get("apply_claim_sha256") == report["apply_claim_sha256"]):
            if code in {UPDATE_RELAY_STOP_REQUESTED, UPDATE_RETRY_REVIEW_REQUIRED}:
                emit_support_record(report, stage="update_apply", policy=policy)
            else:
                write_json_durable(report_path, report)
    except (OSError, ValueError, TypeError, WriterFencedError):
        # A support sink failure cannot turn a safe ordinary launch into a stop.
        emit_support_record({"reason_code": "REPORT_UNAVAILABLE"}, stage="update_apply")
    started_at = now_utc()
    if state and state["phase"] in {"PREPARED", "FAILED", "UNKNOWN", "APPLIED_PENDING_READY"}:
        try:
            assert_ordinary_recovery(control, policy, active["sha"], started_at)
        except (OSError, ValueError, TypeError, KeyError):
            emit_progress_guidance()
            return 20
    if deadline is None:
        launch_version(control, active["sha"], arguments, deferred_at=started_at)
    else:
        _launch_bootstrap_version(control, active["sha"], arguments, deadline=deadline, deferred_at=started_at)
    return 0


def bootstrap(app_root: Path, arguments: list[str], *, role: str) -> int:
    try:
        return _bootstrap(app_root, arguments, role=role)
    except (OSError, RuntimeError) as error:
        if isinstance(error, OSError):
            if error.args[1:] != ("update mutex cannot be opened",):
                raise
        elif str(error) != "update mutex ownership is busy or abandoned":
            raise
        record = support_record({"reason_code": "UPDATE_IN_PROGRESS"}, stage="update_apply")
        record["guidance"] = SAFE_MESSAGES[3]
        print(json.dumps(record, ensure_ascii=False, sort_keys=True))
        return 20


def bootstrap_supervision_deadline(state, *, started: float, now: float, utc_now: str) -> float:
    """Observe durable stage clocks without reopening any of their windows."""
    from user_relay import RELAY_NORMAL_STOP_TIMEOUT_SECONDS
    phase = (state or {}).get("phase")
    timestamp, window = None, 0
    if phase == "APPLIED_PENDING_READY":
        timestamp, window = state.get("applied_at"), READY_WINDOW_SECONDS
    elif phase == "ROLLBACK_PENDING_READY":
        timestamp, window = state.get("rollback_at", state.get("applied_at")), READY_WINDOW_SECONDS
    elif phase in {"ROLLBACK_PENDING", "UNKNOWN"}:
        timestamp, window = state.get("normal_stop_started_at"), RELAY_NORMAL_STOP_TIMEOUT_SECONDS
    stage_end = now + (window - (_utc(utc_now) - _utc(timestamp)).total_seconds()) if timestamp else started
    return min(started + BOOTSTRAP_OBSERVATION_CAP_SECONDS, max(started + 240, stage_end + 15))


def _bootstrap_trial_relay(control, policy, state, active, gui_arguments, attempts, *, deadline):
    """One sampled start attempt per nonce, with process-local retry accounting."""
    if apply_claim_status(control) == "ABSENT":
        return  # The caller resumes the existing ordinary recovery proof path.
    attempt = attempts.setdefault(state["nonce"], {
        "count": 0, "previous": None, "reported": False, "relay": None})
    relay = attempt["relay"]
    if relay is not None:
        identity = native_process_identity(relay["pid"])
        if identity.get("status") == "UNKNOWN" or identity == relay["identity"]:
            return  # Uncertainty never establishes absence or permits a restart.
        attempt["relay"] = None
    count, previous, reported = attempt["count"], attempt["previous"], attempt["reported"]
    if count >= 3 or previous is not None and time.monotonic() - previous < 2:
        return
    if time.monotonic() >= deadline:
        return
    # Absence and launch must share update→trial ownership. Only the first
    # sample, or a known relay lifetime ending, needs the slow census.
    rows = writer_processes(process_snapshot(control), own_pid=os.getpid())
    if time.monotonic() >= deadline:
        return
    relays = [row for row in rows if process_matches_trial(row, state=state,
        sha=active["sha"], sid=policy["operator_sid"], role="relay")]
    if relays:
        pid = relays[0]["pid"]
        identity = native_process_identity(pid)
        if identity.get("status") == "LIVE":
            attempt["relay"] = {"pid": pid, "identity": identity}
        return
    root_arguments = []
    if "--data-root" in gui_arguments:
        index = gui_arguments.index("--data-root")
        if index + 1 >= len(gui_arguments):
            raise ValueError("trial data root argument is absent")
        root_arguments = gui_arguments[index:index + 2]
    count += 1
    attempt.update(count=count, previous=time.monotonic())
    try:
        pid = _launch_bootstrap_version(control, active["sha"],
            ["--container-audit-user-relay", *root_arguments], nonce=state["nonce"], deadline=deadline)
        identity = native_process_identity(pid)
        if identity.get("status") == "LIVE":
            attempt["relay"] = {"pid": pid, "identity": identity}
    except OSError:
        if count == 3 and not reported:
            emit_support_record({"reason_code": TRIAL_RELAY_START_FAILED}, stage="update_apply", policy=policy)
            attempt["reported"] = True


class _BootstrapObservationChanged(Exception):
    """Discard an observation after its protected context or owner changed."""


class _BootstrapPoll:
    """Suspend update→trial ownership for reads, then validate before use.

    The caller keeps the existing launch/claim critical sections. A read never
    carries either update mutex or writer admission into the slow operation.
    """

    def __init__(self, control, policy, *, deadline, wait_check=None):
        self.control, self.policy, self.deadline = control, policy, deadline
        self.wait_check = wait_check
        self.ownership, self.trial_ownership = ExitStack(), ExitStack()
        self.in_trial = False
        self.acquired = False

    def _startup_lock(self):
        options = {"deadline": self.deadline}
        if self.wait_check is not None:
            options["wait_check"] = self.wait_check
        return startup_update_lock(self.control, self.policy, **options)

    def __enter__(self):
        self.acquired = self.ownership.enter_context(self._startup_lock())
        return self

    def __exit__(self, *error):
        try:
            self.trial_ownership.__exit__(*error)
        finally:
            self.ownership.__exit__(*error)

    @contextmanager
    def trial(self):
        self.trial_ownership.enter_context(update_lock(
            self.control, self.policy["operator_sid"], trial=True))
        self.in_trial = True
        try:
            yield
        finally:
            self.in_trial = False
            self.trial_ownership.close()

    def _records(self):
        stage = Path(self.policy["staging_root"])
        return [optional_record(path) for path in (
            self.control / "transition.json", self.control / "active.json",
            self.control / "apply-claim.json", stage / "trial.json",
            stage / "ready.json", stage / "trial-failure.json", stage / "prepared.json")]

    @staticmethod
    def _identities(records):
        pids = {record.get(key) for record in records if isinstance(record, Mapping)
                for key in ("pid", "trial_pid")
                if type(record.get(key)) is int and record[key] > 0}
        return {pid: native_process_identity(pid) for pid in pids}

    def read(self, operation):
        records = self._records()
        # SYSTEM's apply owner keeps the existing LIVE/UNKNOWN contract. Its
        # protected PID/birth record and derived status are rechecked below;
        # ordinary bootstrap must not gain a new right to query SYSTEM.
        identities = self._identities(records[:2] + records[3:])
        claim_status = apply_claim_status(self.control)
        self.trial_ownership.close()
        self.ownership.close()
        result, failure = None, None
        try:
            result = operation()
        except Exception as error:
            failure = error
        # New native rows must retain their lifetime across reacquisition too.
        rows = [row for row in result if isinstance(row, Mapping)
                and row.get("observable") is True and row.get("role") in {"gui", "relay"}
                and row.get("pid") != os.getpid()] if isinstance(result, list) else []
        observed = self._identities(rows)
        births_match = True
        for row in rows:
            try:
                birth = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
                    microseconds=int(observed[row["pid"]]["creation_identity"]) // 10)
                births_match = births_match and birth == _utc(row.get("created_at"))
            except (KeyError, TypeError, ValueError, OverflowError):
                births_match = False
        self.acquired = self.ownership.enter_context(self._startup_lock())
        if not self.acquired:
            raise _BootstrapObservationChanged()
        if self.in_trial:
            self.trial_ownership.enter_context(update_lock(
                self.control, self.policy["operator_sid"], trial=True))
        if (not births_match or self._records() != records
                or apply_claim_status(self.control) != claim_status
                or time.monotonic() >= self.deadline):
            raise _BootstrapObservationChanged()
        for expected in (identities, observed):
            for pid, identity in expected.items():
                if (identity.get("status") == "UNKNOWN"
                        or expected is observed and identity.get("status") != "LIVE"
                        or native_process_identity(pid) != identity):
                    raise _BootstrapObservationChanged()
        if failure is not None:
            raise failure
        return result


def _bootstrap(app_root: Path, arguments: list[str], *, role: str) -> int:
    import time

    control = control_root(app_root)
    if control is None:
        raise ValueError("bootstrap requires the installed ordinary-user context")
    policy = read_json(control / "policy.json")
    if not ordinary_user_context(policy["operator_sid"]):
        raise ValueError("bootstrap requires the installed ordinary operator")
    requested = False
    requested_at = None
    progress_deadline = None
    saw_trial = False
    apply_started = False
    started = time.monotonic()
    deadline = started + 240
    relay_attempts = {}
    live_apply_wait = False

    def apply_pending(state):
        return state is None or state.get("phase") in {
            "PREPARED", "APPLIED_PENDING_READY", "ROLLBACK_PENDING", "ROLLBACK_PENDING_READY"
        }

    def apply_decided(state):
        return bool(state and state.get("phase") in {"DEFERRED", "CONFIRMED", "ROLLED_BACK"})

    def still_waiting_for_apply():
        return (time.monotonic() < started + BOOTSTRAP_OBSERVATION_CAP_SECONDS
                and apply_claim_status(control) == "LIVE"
                and apply_pending(optional_record(control / "transition.json")))

    def extend_live_apply_wait():
        nonlocal deadline, live_apply_wait
        now = time.monotonic()
        if now >= started + BOOTSTRAP_OBSERVATION_CAP_SECONDS or (not live_apply_wait and now < deadline):
            return False
        claim_status = apply_claim_status(control)
        pending = optional_record(control / "transition.json")
        if not (live_apply_wait and apply_decided(pending)):
            if claim_status != "LIVE" or not apply_pending(pending):
                return False
        # Unlocked observations only choose another protected poll. A decision
        # uses the remaining original cap without renewing any stage window.
        deadline = started + BOOTSTRAP_OBSERVATION_CAP_SECONDS
        live_apply_wait = True
        return True

    while time.monotonic() < deadline or extend_live_apply_wait():
        if live_apply_wait and not extend_live_apply_wait():
            break
        try:
            poll_options = {"deadline": deadline}
            if live_apply_wait:
                poll_options["wait_check"] = still_waiting_for_apply
            with _BootstrapPoll(control, policy, **poll_options) as poll:
                if not poll.acquired:
                    if extend_live_apply_wait():
                        raise _BootstrapObservationChanged()
                    break
                state = optional_record(control / "transition.json")
                deadline = (started + BOOTSTRAP_OBSERVATION_CAP_SECONDS if live_apply_wait else
                    bootstrap_supervision_deadline(state, started=started,
                        now=time.monotonic(), utc_now=now_utc()))
                poll.deadline = deadline
                claim_status = apply_claim_status(control)
                if (live_apply_wait and not apply_decided(state)
                        and (claim_status != "LIVE" or not apply_pending(state))):
                    break
                if (live_apply_wait and apply_decided(state)
                        and claim_status in {"LIVE", "UNKNOWN"}):
                    # SYSTEM publishes its decision before settling its claim.
                    # Keep the original cap and make the decision under a new lock.
                    raise _BootstrapObservationChanged()
                apply_started = apply_started or claim_status in {"LIVE", "UNKNOWN"} or bool(state and state["phase"] in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"})
                if state and state["phase"] in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"}:
                    saw_trial = True
                if (claim_status in {"LIVE", "UNKNOWN"}
                        and not (state and state["phase"] in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"})
                        and not (live_apply_wait and apply_decided(state))):
                    raise _BootstrapObservationChanged()
                prepared = poll.read(lambda: prepared_pending(control, policy, state))
                action = startup_action(state, prepared_present=prepared)
                active = read_json(control / "active.json")
                gui_arguments = arguments[1:] if role == "relay" and arguments[:1] == ["--container-audit-user-relay"] else arguments
                if role == "gui":
                    recovery_gui = _bootstrap_recovery_gui(control, policy, state, active, arguments,
                                                           claim_status=claim_status, deadline=deadline)
                    if recovery_gui is not None:
                        return recovery_gui
                if state and state["phase"] == "DEFERRED" and state.get("retained_candidate") is True:
                    if active["sha"] != recovery_sha(state, pointer_sha=active["sha"]):
                        action = "WAIT_FOR_RECOVERY"
                    elif prepared:
                        action = "REQUEST_APPLY"
                    else:
                        return start_current(control, policy, state, active, arguments, code="UPDATE_TERMINAL_RECOVERED", deadline=deadline)
                if state and state["phase"] in {"CONFIRMED", "ROLLED_BACK"} and saw_trial:
                    if state["phase"] == "ROLLED_BACK":
                        return start_current(control, policy, state, active, arguments, code="UPDATE_PREVIOUS_CONFIRMED", deadline=deadline)
                    return 0  # The already-launched GUI owns input and its ordinary relay.
                if state and state["phase"] == "DEFERRED" and requested_at and _utc(state["deferred_at"]) >= _utc(requested_at):
                    code = state.get("reason_code")
                    if code not in {"UPDATE_PREPARATION_FAILED", "UPDATE_EXISTING_WRITER", UPDATE_RELAY_STOP_REQUESTED}:
                        code = "UPDATE_TERMINAL_RECOVERED"
                    launch_arguments = gui_arguments if code == UPDATE_RELAY_STOP_REQUESTED else arguments
                    return start_current(control, policy, state, active, launch_arguments, code=code, deadline=deadline)
                if claim_status == "ABSENT":
                    existing = _bootstrap_existing_writers(control, policy, active, arguments, role=role, deadline=deadline)
                    if existing is not None:
                        return existing
                    if current_generation_status(control, policy, active["sha"]) != "ALLOW":
                        emit_progress_guidance()
                        return 20
                    return start_current(control, policy, state, active, arguments, code="UPDATE_SUPERVISION_UNAVAILABLE", report_once=True, deadline=deadline)
                if action == "START_CURRENT":
                    if state and state["phase"] in {"ROLLED_BACK", "DEFERRED"}:
                        return start_current(control, policy, state, active, arguments, code="UPDATE_TERMINAL_RECOVERED", deadline=deadline)
                    _launch_bootstrap_version(control, active["sha"], arguments, deadline=deadline)
                    return 0
                if state and state["phase"] in {"UNKNOWN", "FAILED"}:
                    if claim_status not in {"LIVE", "UNKNOWN"}:
                        existing = _bootstrap_existing_writers(control, policy, active, arguments, role=role, deadline=deadline)
                        if existing is not None:
                            return existing
                        if current_generation_status(control, policy, active["sha"]) == "ALLOW" and not prepared:
                            return start_current(control, policy, state, active, arguments, code="UPDATE_TERMINAL_RECOVERED", deadline=deadline)
                if action in {"REQUEST_APPLY", "REQUEST_TRIAL", "WAIT_FOR_RECOVERY", "WAIT_FOR_TRIAL"} and not requested:
                    if action == "REQUEST_APPLY" and update_relay_stop_requested(policy):
                        return start_current(control, policy, state, active, gui_arguments,
                            code=UPDATE_RELAY_STOP_REQUESTED, deadline=deadline)
                    requested_at = now_utc()
                    progress_deadline = time.monotonic() + APPLY_REQUEST_PROGRESS_TIMEOUT
                    try:
                        request_apply_task(control, policy)
                    except Exception:
                        if apply_started or apply_claim_status(control) in {"LIVE", "UNKNOWN"}:
                            requested = True
                            continue
                        if not state or state["phase"] in {"PREPARED", "CONFIRMED", "ROLLED_BACK", "DEFERRED", "FAILED", "UNKNOWN", "APPLIED_PENDING_READY"}:
                            if state and state["phase"] == "APPLIED_PENDING_READY":
                                existing = _bootstrap_existing_writers(control, policy, active, arguments, role=role, deadline=deadline)
                                if existing is not None:
                                    return existing
                            code = "UPDATE_SUPERVISION_UNAVAILABLE" if state and state["phase"] == "APPLIED_PENDING_READY" else "UPDATE_APPLY_REQUEST_FAILED"
                            return start_current(control, policy, state, active, arguments, code=code, deadline=deadline)
                        raise
                    requested = True
                    # The task may already have settled or switched this journal.
                    # Release ownership and reread it before creating a trial.
                    continue
                if requested and progress_deadline is not None:
                    claim_status = apply_claim_status(control)
                    if claim_status == "ABSENT":
                        if state and state["phase"] == "APPLIED_PENDING_READY":
                            existing = _bootstrap_existing_writers(control, policy, active, arguments, role=role, deadline=deadline)
                            if existing is not None:
                                return existing
                        return start_current(control, policy, state, active, arguments, code="UPDATE_SUPERVISION_UNAVAILABLE", report_once=True, deadline=deadline)
                    if claim_status in {"LIVE", "UNKNOWN"}:
                        apply_started = True
                    if not apply_started and time.monotonic() >= progress_deadline:
                        return start_current(control, policy, state, active, arguments, code="UPDATE_APPLY_NO_PROGRESS", deadline=deadline)
                if action in {"REQUEST_TRIAL", "WAIT_FOR_TRIAL"}:
                    # Both the Run relay and a launcher request this same GUI trial.
                    # The GUI's ordinary onboarding starts its single normal relay.
                    with poll.trial():
                        state = read_json(control / "transition.json")
                        if state["phase"] not in {"APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"}:
                            continue
                        trial_at = state.get("rollback_at", state["applied_at"]) if state["phase"] == "ROLLBACK_PENDING_READY" else state["applied_at"]
                        if (_utc(now_utc()) - _utc(trial_at)).total_seconds() >= READY_WINDOW_SECONDS:
                            raise _BootstrapObservationChanged()
                        claim = optional_record(Path(policy["staging_root"]) / "trial.json")
                        if state.get("trial_pid") or claim and claim.get("nonce") == state["nonce"]:
                            saw_trial = True
                        else:
                            pid = _launch_bootstrap_version(control, active["sha"], gui_arguments, nonce=state["nonce"], deadline=deadline)
                            write_json_durable(Path(policy["staging_root"]) / "trial.json", {"pid": pid, "nonce": state["nonce"], "transition_id": state["transition_id"]})
                            saw_trial = True
                        _bootstrap_trial_relay(control, policy, state, active, gui_arguments,
                            relay_attempts, deadline=min(deadline, time.monotonic() + max(0.0,
                                READY_WINDOW_SECONDS - (_utc(now_utc()) - _utc(trial_at)).total_seconds())))
        except _BootstrapObservationChanged:
            pass
        except RuntimeError as error:
            if str(error) != 'update mutex ownership is busy or abandoned' or getattr(error, 'wait_result', 0x102) != 0x102:
                raise
            if apply_claim_status(control) not in {"LIVE", "UNKNOWN"}:
                raise
        time.sleep(0.1)
    state = optional_record(control / "transition.json")
    if (live_apply_wait and time.monotonic() >= started + BOOTSTRAP_OBSERVATION_CAP_SECONDS
            and ((state is None and apply_claim_status(control) == "LIVE")
                 or (apply_decided(state) and apply_claim_status(control) in {"LIVE", "UNKNOWN"}))):
        # An absent journal cannot authorize launch while apply still owns the cap.
        emit_progress_guidance()
        return 20
    active = read_json(control / "active.json")
    if startup_action(state, prepared_present=False) == "START_CURRENT" and (not (state or {}).get("retained_candidate") or active["sha"] == recovery_sha(state, pointer_sha=active["sha"])) and current_generation_status(control, policy, active["sha"]) == "ALLOW":
        return start_current(control, policy, state, active, arguments, code="UPDATE_LOCK_WAIT_EXPIRED", deadline=deadline)
    if apply_claim_status(control) == "UNKNOWN":
        try:
            with update_lock(control, policy["operator_sid"]):
                try:
                    stale_claim = time.time() - (control / "apply-claim.json").stat().st_mtime > 15 * 60
                except OSError:
                    stale_claim = False
                if stale_claim and apply_claim_status(control) == "UNKNOWN":
                    state = optional_record(control / "transition.json")
                    active = read_json(control / "active.json")
                    existing = _bootstrap_existing_writers(control, policy, active, arguments, role=role, deadline=deadline)
                    if existing is not None:
                        return existing
                    if current_generation_status(control, policy, active["sha"]) == "ALLOW" and not prepared_pending(control, policy, state):
                        return start_current(control, policy, state, active, arguments, code="UPDATE_SUPERVISION_UNAVAILABLE", report_once=True, deadline=deadline)
        except RuntimeError as error:
            if str(error) != 'update mutex ownership is busy or abandoned':
                raise
    emit_progress_guidance()
    return 20


def main(arguments: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = SupportArgumentParser()
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--apply-prepared", action="store_true")
    parser.add_argument("--control-root", type=Path)
    parser.add_argument("--role", choices=("gui", "relay"), default="gui")
    parser.add_argument("--print-logon-task", action="store_true")
    parser.add_argument("--install-root", type=Path)
    parser.add_argument("--operator-sid")
    parser.add_argument('--lifecycle-context', action='store_true')
    parser.add_argument('--operation', choices=('inspect', 'install', 'register', 'uninstall', 'user_remove'), default='inspect')
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args(arguments)
    if options.lifecycle_context:
        if options.bootstrap or options.apply_prepared or options.print_logon_task or options.arguments or options.install_root is None:
            raise ValueError('lifecycle context arguments differ')
        try:
            context = resolve_lifecycle_context(options.install_root.absolute().parent, operation=options.operation)
            print(json.dumps(context, ensure_ascii=True))
            return 0
        except (OSError, ValueError, RuntimeError) as error:
            print(json.dumps(mixed_status_record(dict(status='FAILED', message=LIFECYCLE_RECOVERY, error_type=type(error).__name__, failure_details=_failure_details(error))), ensure_ascii=True))
            return 20
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
    raise SystemExit(run_support_main(main, stage='update_apply'))

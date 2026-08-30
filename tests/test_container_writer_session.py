from datetime import datetime, timezone
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "tools" / "container_writer_session.ps1"
CONTRACT = ROOT / "tools" / "container_writer_session_contract.json"


def _powershell() -> str:
    executable = shutil.which("powershell.exe")
    if not executable:
        pytest.skip("Windows PowerShell 5.1 is required")
    return executable


def _argument_value(arguments: tuple[str, ...], name: str) -> str | None:
    try:
        return arguments[arguments.index(name) + 1]
    except (ValueError, IndexError):
        return None


def _session_authority_name(arguments: tuple[str, ...]) -> str | None:
    values = [
        _argument_value(arguments, "-SessionId"),
        _argument_value(arguments, "-AttemptId"),
        _argument_value(arguments, "-OrchestratorSha256"),
        _argument_value(arguments, "-ReplacementTransactionId"),
        _argument_value(arguments, "-ExpectedContractSha256"),
    ]
    lengths = [32, 32, 64, 32, 64]
    if any(value is None for value in values):
        return None
    if any(
        len(value) != length or any(char not in "0123456789abcdef" for char in value)
        for value, length in zip(values, lengths, strict=True)
    ):
        return None
    canonical = "\n".join(
        ["container-audit-deployment-session-authority-v1", *values]
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"Local\\KMTech.ContainerAudit.DeploymentSession.{digest}"


@contextmanager
def _held_session_authority(name: str | None):
    if name is None:
        yield
        return
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    handle = kernel32.CreateMutexW(None, True, name)
    if not handle:
        raise ctypes.WinError()
    try:
        yield
    finally:
        assert kernel32.ReleaseMutex(handle)
        assert kernel32.CloseHandle(handle)


def _run_adapter(
    *arguments: str, session_authority: bool = True
) -> subprocess.CompletedProcess[str]:
    authority_name = _session_authority_name(arguments) if session_authority else None
    with _held_session_authority(authority_name):
        return subprocess.run(
            [
                _powershell(),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ADAPTER),
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )


def _contract_sha256() -> str:
    return hashlib.sha256(CONTRACT.read_bytes()).hexdigest()


def _squash_whitespace(value: str) -> str:
    return "".join(value.split())


def _production_arguments(mode: str, tmp_path: Path, *, session_id: str) -> list[str]:
    evidence = tmp_path / f"{mode.lower()}-evidence.json"
    arguments = [
        "-Mode",
        mode,
        "-InstallRoot",
        str(tmp_path / "apps" / "current"),
        "-EvidencePath",
        str(evidence),
        "-PreparedReceiptPath",
        str(tmp_path / "missing-prepared.json"),
        "-PreparedReceiptSha256",
        "e" * 64,
        "-HistoricalReceiptPath",
        str(tmp_path / "missing-historical.json"),
        "-HistoricalReceiptSha256",
        "d" * 64,
        "-SessionId",
        session_id,
        "-AttemptId",
        "b" * 32,
        "-SessionStartedAtUtc",
        datetime.now(timezone.utc).isoformat(),
        "-OrchestratorSha256",
        "c" * 64,
        "-ExpectedContractSha256",
        _contract_sha256(),
        "-ReplacementTransactionId",
        "f" * 32,
        "-ReplacementReceiptPath",
        str(tmp_path / "missing-replacement.json"),
        "-ReplacementReceiptSha256",
        "1" * 64,
        "-LifecycleRestoreReceiptPath",
        str(tmp_path / "missing-lifecycle-restore.json"),
        "-LifecycleRestoreReceiptSha256",
        "5" * 64,
        "-ExpectedSourceCommit",
        "2" * 40,
        "-ExpectedSourceAggregateSha256",
        "3" * 64,
        "-HelperPath",
        str(tmp_path / "missing-helper.ps1"),
        "-ExpectedHelperSha256",
        "4" * 64,
        "-RestoreEvidencePath",
        str(tmp_path / "code-restore.json"),
        "-WriterRestoreEvidencePath",
        str(tmp_path / "writer-restore.json"),
    ]
    if mode == "RestoreWriter":
        arguments.extend(["-RestoreEvidenceSha256", "6" * 64])
    if mode == "Recover":
        lifecycle_sha_index = arguments.index("-LifecycleRestoreReceiptSha256")
        del arguments[lifecycle_sha_index : lifecycle_sha_index + 2]
    return arguments


def _valid_prepared_payload(path: Path, arguments: list[str]) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    identity = {
        "status": "PASS",
        "task_name": "direct-sync-relay-container-audit",
        "task_path": "\\",
        "execute": r"C:\KMTech\Apps\Container_Audit\current\runtime\python.exe",
        "working_directory": r"C:\KMTech\Apps\Container_Audit\current\app",
        "arguments_sha256": "6" * 64,
        "expected_main_bound": True,
        "expected_mode_bound": True,
        "raw_arguments_recorded": False,
        "principal_user": "operator",
        "principal_sid": "S-1-5-21-1-2-3-1001",
        "logon_type": "Interactive",
        "run_level": "Limited",
        "trigger_type": "MSFT_TaskTimeTrigger",
        "trigger_start_boundary": now.isoformat(),
        "trigger_repetition_interval": "PT1M",
        "start_when_available": True,
        "multiple_instances": "IgnoreNew",
        "definition_sha256": "7" * 64,
        "binding_sha256": "5" * 64,
    }
    pre = {
        "captured_at_utc": now.isoformat(),
        "enabled": True,
        "state": "Ready",
        "last_task_result": 0,
        "last_run_time_utc": now.isoformat(),
        "next_run_time_utc": now.isoformat(),
        "exact_writer_process_count": 0,
        "identity": identity,
    }
    post = json.loads(json.dumps(pre))
    post["enabled"] = False
    post["state"] = "Disabled"
    fingerprint = {
        "path": str(path.parent / "effect.json"),
        "bytes": 1,
        "mtime_utc": now.isoformat(),
        "sha256": "8" * 64,
        "contents_recorded": False,
    }
    session_id = _argument_value(tuple(arguments), "-SessionId")
    attempt_id = _argument_value(tuple(arguments), "-AttemptId")
    orchestrator = _argument_value(tuple(arguments), "-OrchestratorSha256")
    transaction = _argument_value(tuple(arguments), "-ReplacementTransactionId")
    contract_sha = _argument_value(tuple(arguments), "-ExpectedContractSha256")
    authority = _session_authority_name(tuple(arguments))
    assert all((session_id, attempt_id, orchestrator, transaction, contract_sha, authority))
    return {
        "schema": "container-audit-writer-session-prepared-v3",
        "status": "PREPARED_DISABLED",
        "app_id": "container_audit",
        "session_id": session_id,
        "attempt_id": attempt_id,
        "replacement_transaction_id": transaction,
        "session_started_at_utc": _argument_value(tuple(arguments), "-SessionStartedAtUtc"),
        "orchestrator_sha256": orchestrator,
        "session_authority_mutex_name": authority,
        "adapter_sha256": hashlib.sha256(ADAPTER.read_bytes()).hexdigest(),
        "contract_sha256": contract_sha,
        "evidence_path": str(path),
        "started_at_utc": now.isoformat(),
        "completed_at_utc": now.isoformat(),
        "secret_values_recorded": False,
        "historical_capability": {
            "schema": "container-audit-canonical-writer-lifecycle-v1",
            "receipt_sha256": _argument_value(tuple(arguments), "-HistoricalReceiptSha256"),
            "eight_points_pass": True,
            "capability_binding_sha256": "5" * 64,
        },
        "pre_readback": pre,
        "disable": {
            "status": "COMMAND_SUCCEEDED",
            "post_readback": post,
            "binding_unchanged": True,
        },
        "quiescence": {
            "status": "PASS",
            "trigger_boundary_utc": now.isoformat(),
            "stable_baseline": {"log": fingerprint, "runtime_status": fingerprint},
            "after_trigger": {"log": fingerprint, "runtime_status": fingerprint},
            "last_run_time_unchanged": True,
            "log_unchanged": True,
            "runtime_status_unchanged": True,
            "exact_writer_process_count": 0,
        },
        "failure": {
            "status": "NONE",
            "stage": "",
            "code": "",
            "failure_type": "",
            "silently_ignored": False,
            "emergency_restore_attempted": False,
            "emergency_restore_succeeded": None,
            "safety_fence": None,
            "retain_disabled_requested": False,
        },
    }


def test_writer_session_negative_injections_are_fail_closed_and_nonmutating():
    completed = _run_adapter("-Mode", "SelfTest")

    assert completed.returncode == 0, completed.stderr or completed.stdout
    result = json.loads(completed.stdout)
    assert result["schema"] == "container-audit-writer-session-self-test-v1"
    assert result["status"] == "PASS"
    assert result["system_mutation_attempted"] is False
    assert result["system_mutation_attempt_count"] == 0
    assert result["secret_values_recorded"] is False
    assert {item["name"]: item["status"] for item in result["checks"]} == {
        "public_guard_rejects_absent_session_authority": "PASS",
        "public_guard_accepts_actively_held_session_authority": "PASS",
        "public_guard_rejects_released_session_authority": "PASS",
        "valid_current_session_prepared_receipt": "PASS",
        "stale_session_rejected": "PASS",
        "wrong_transaction_rejected": "PASS",
        "wrong_contract_rejected": "PASS",
        "historical_binding_mismatch_rejected": "PASS",
        "prepared_string_boolean_rejected": "PASS",
        "prepared_string_integer_rejected": "PASS",
        "prepared_nested_extra_field_rejected": "PASS",
        "prepared_wrong_session_authority_rejected": "PASS",
        "expired_session_rejected": "PASS",
        "invalid_replacement_receipt_rejected": "PASS",
        "replacement_receipt_accepts_exact_types": "PASS",
        "replacement_receipt_rejects_string_integer": "PASS",
        "historical_boolean_contract_accepts_exact_types": "PASS",
        "historical_string_boolean_rejected": "PASS",
        "base64url_possession_fingerprint_accepted": "PASS",
        "hex_possession_fingerprint_rejected": "PASS",
        "lifecycle_structural_guard_accepts_exact_boolean_types": "PASS",
        "lifecycle_string_boolean_rejected": "PASS",
        "lifecycle_extra_field_rejected": "PASS",
        "lifecycle_limited_execution_context_accepted": "PASS",
        "lifecycle_elevated_execution_context_rejected": "PASS",
        "lifecycle_string_elevation_context_rejected": "PASS",
        "lifecycle_mutation_evidence_accepts_exact_nested_contract": "PASS",
        "lifecycle_mutation_evidence_rejects_extra_field": "PASS",
        "lifecycle_mutation_evidence_rejects_writer_mode": "PASS",
        "lifecycle_mutation_evidence_rejects_string_pid": "PASS",
        "live_relay_readback_accepts_exact_current_process": "PASS",
        "live_relay_readback_rejects_registry_kind_drift": "PASS",
        "live_relay_readback_rejects_duplicate_process": "PASS",
        "live_relay_readback_rejects_extra_runtime_process": "PASS",
        "live_relay_readback_rejects_wrong_owner": "PASS",
        "live_relay_readback_rejects_stale_process": "PASS",
        "live_relay_readback_rejects_observation_query_failure": "PASS",
        "code_restore_structural_guard_accepts_exact_boolean_types": "PASS",
        "code_restore_string_boolean_rejected": "PASS",
        "code_restore_extra_field_rejected": "PASS",
        "code_restore_failed_root_mismatch_rejected": "PASS",
        "pre_enable_guard_accepts_exact_disabled_readback": "PASS",
        "pre_enable_guard_rejects_string_boolean": "PASS",
        "pre_enable_guard_rejects_binding_drift": "PASS",
        "pre_enable_guard_rejects_live_process": "PASS",
        "pre_enable_guard_rejects_string_integer": "PASS",
        "prepared_before_replacement_accepted": "PASS",
        "reordered_replacement_rejected_before_restore": "PASS",
        "replacement_before_code_accepted": "PASS",
        "reordered_code_rejected_before_lifecycle": "PASS",
        "restore_temporal_order_accepted": "PASS",
        "reordered_lifecycle_receipt_rejected": "PASS",
        "code_restore_failure_explicit_and_writer_not_run": "PASS",
        "lifecycle_restore_failure_explicit_and_writer_not_run": "PASS",
        "writer_restore_failure_explicit": "PASS",
    }


def test_selftest_uses_common_live_readback_guard_not_private_value_validator():
    text = ADAPTER.read_text(encoding="utf-8")
    selftest = text[
        text.index("function Invoke-ContainerWriterSessionSelfTest") : text.index(
            "if ($Mode -ceq 'selftest')"
        )
    ]

    assert "Test-ContainerUserRelayLiveReadbackValues" not in selftest
    assert selftest.count("Test-ContainerUserRelayLiveReadback ") >= 7
    assert "live_relay_readback_rejects_observation_query_failure" in selftest


def test_public_contract_mode_is_pinned_machine_readable_and_nonmutating():
    completed = _run_adapter(
        "-Mode",
        "Contract",
        "-ExpectedContractSha256",
        _contract_sha256(),
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    result = json.loads(completed.stdout)
    assert result["schema"] == "container-audit-writer-session-contract-readback-v1"
    assert result["status"] == "PASS"
    assert result["contract_sha256"] == _contract_sha256()
    assert result["adapter_sha256"] == hashlib.sha256(ADAPTER.read_bytes()).hexdigest()
    assert result["public_modes"] == [
        "Contract",
        "Prepare",
        "ValidatePrepared",
        "RestoreWriter",
    ]
    assert result["compatibility_modes"] == ["ValidateReplacement", "Recover"]
    assert result["operations"] == json.loads(CONTRACT.read_text(encoding="utf-8"))[
        "operations"
    ]
    assert result["operations"]["RestoreWriter"]["mutation_class"] == (
        "SCHEDULED_WRITER_ENABLE_NATURAL_TRIGGER_READBACK_AND_"
        "LIFECYCLE_FAILURE_CONTAINMENT"
    )
    assert result["receipt_schemas"] == {
        "prepared": "container-audit-writer-session-prepared-v3",
        "restored": "container-audit-writer-session-restored-v2",
        "recovery": "container-audit-window-recovery-v1",
        "replacement": "container-audit-verified-replacement-v1",
        "replacement_validation": "container-audit-replacement-receipt-validation-v1",
        "lifecycle_restore": "container-audit-replacement-lifecycle-restore-v1",
        "historical": "container-audit-canonical-writer-lifecycle-v1",
    }
    assert result["lifecycle_restore"]["transaction_argument"] == (
        "ReplacementTransactionId"
    )
    assert result["lifecycle_restore"]["product_mode"] == (
        "--restore-current-user-lifecycle-after-replacement"
    )
    assert result["lifecycle_restore"]["require_same_session_receipt"] is True
    assert result["lifecycle_restore"]["writer_mode_output_argument"] == "EvidencePath"
    assert (
        result["lifecycle_restore"]["recover_writer_output_argument"]
        == "WriterRestoreEvidencePath"
    )
    assert (
        result["lifecycle_restore"]["require_code_restore_before_writer_restore"]
        is True
    )
    assert (
        result["lifecycle_restore"]["require_lifecycle_restore_before_writer_restore"]
        is True
    )
    assert (
        result["lifecycle_restore"][
            "require_live_current_user_lifecycle_before_writer_restore"
        ]
        is True
    )
    assert (
        result["lifecycle_restore"][
            "producer_code_tree_read_locked_through_execution"
        ]
        is True
    )
    assert (
        result["lifecycle_restore"][
            "require_non_elevated_medium_integrity_lifecycle_producer"
        ]
        is True
    )
    assert result["system_mutation_attempted"] is False
    assert result["secret_values_recorded"] is False


def test_public_contract_mode_rejects_invalid_contract_hash():
    completed = _run_adapter(
        "-Mode",
        "Contract",
        "-ExpectedContractSha256",
        "g" * 64,
    )

    assert completed.returncode != 0
    assert "expectedwritersessioncontractSHA-256ismalformed." in _squash_whitespace(
        completed.stdout + completed.stderr
    )


@pytest.mark.parametrize(
    ("mode", "marker"),
    [
        ("Prepare", "writer_session_status=FAIL"),
        ("ValidatePrepared", "writer_session_validation_status=FAIL"),
        ("ValidateReplacement", "replacement_receipt_validation_status=FAIL"),
        ("RestoreWriter", "writer_restore_status=FAIL"),
        ("Recover", "container_recovery_status=FAIL"),
    ],
)
def test_public_modes_accept_valid_hex_and_reach_fail_closed_boundary(
    tmp_path: Path,
    mode: str,
    marker: str,
):
    completed = _run_adapter(
        *_production_arguments(mode, tmp_path, session_id="a" * 32)
    )

    combined = completed.stdout + completed.stderr
    assert completed.returncode == 20, combined
    assert marker in combined
    assert "sessionidismalformed." not in _squash_whitespace(combined)
    assert not (tmp_path / "apps" / "current").exists()
    assert not (tmp_path / "code-restore.json").exists()
    assert not (tmp_path / "writer-restore.json").exists()
    evidence_path = tmp_path / f"{mode.lower()}-evidence.json"
    if mode == "ValidatePrepared":
        assert not evidence_path.exists()
    else:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8-sig"))
        assert evidence["status"] == "FAIL"
    assert not list(tmp_path.glob("*.tmp.*"))
    assert not list(tmp_path.glob("*.bak.*"))


def test_public_mode_rejects_self_consistent_tuple_without_live_session_authority(
    tmp_path: Path,
):
    arguments = _production_arguments("ValidatePrepared", tmp_path, session_id="a" * 32)
    started_index = arguments.index("-SessionStartedAtUtc") + 1
    arguments[started_index] = datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() - 2 * 60 * 60,
        tz=timezone.utc,
    ).isoformat()

    completed = _run_adapter(*arguments, session_authority=False)

    combined = _squash_whitespace(completed.stdout + completed.stderr)
    assert completed.returncode != 0
    assert "sessionauthoritymutexisabsentornotactivelyheld" in combined
    assert "writer_session_validation_status=" not in completed.stdout
    assert not list(tmp_path.rglob("*"))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("quiescence", "log_unchanged"), "false"),
        (("quiescence", "exact_writer_process_count"), "0"),
        (("pre_readback", "last_task_result"), "0"),
    ],
)
def test_public_validate_prepared_rejects_string_coercion_before_live_readback(
    tmp_path: Path, path: tuple[str, str], value: str
):
    arguments = _production_arguments(
        "ValidatePrepared", tmp_path, session_id="a" * 32
    )
    prepared_path = Path(
        _argument_value(tuple(arguments), "-PreparedReceiptPath") or ""
    )
    payload = _valid_prepared_payload(prepared_path, arguments)
    parent, field = path
    assert isinstance(payload[parent], dict)
    payload[parent][field] = value
    prepared_path.write_text(json.dumps(payload), encoding="utf-8")
    receipt_hash_index = arguments.index("-PreparedReceiptSha256") + 1
    arguments[receipt_hash_index] = hashlib.sha256(prepared_path.read_bytes()).hexdigest()

    completed = _run_adapter(*arguments)

    combined = completed.stdout + completed.stderr
    assert completed.returncode == 20, combined
    assert "writer_session_validation_status=FAIL" in combined
    assert (
        "writer_session_validation_failure_code=PREPARED_RECEIPT_CONTRACT_INVALID"
        in combined
    )
    assert not (tmp_path / "code-restore.json").exists()
    assert not (tmp_path / "writer-restore.json").exists()


def test_public_validate_prepared_exact_types_pass_contract_guard_before_readback(
    tmp_path: Path,
):
    arguments = _production_arguments(
        "ValidatePrepared", tmp_path, session_id="a" * 32
    )
    prepared_path = Path(
        _argument_value(tuple(arguments), "-PreparedReceiptPath") or ""
    )
    payload = _valid_prepared_payload(prepared_path, arguments)
    prepared_path.write_text(json.dumps(payload), encoding="utf-8")
    receipt_hash_index = arguments.index("-PreparedReceiptSha256") + 1
    arguments[receipt_hash_index] = hashlib.sha256(prepared_path.read_bytes()).hexdigest()

    completed = _run_adapter(*arguments)

    combined = completed.stdout + completed.stderr
    assert completed.returncode == 20, combined
    assert "writer_session_validation_status=FAIL" in combined
    assert "PREPARED_RECEIPT_CONTRACT_INVALID" not in combined
    assert not (tmp_path / "code-restore.json").exists()
    assert not (tmp_path / "writer-restore.json").exists()


@pytest.mark.parametrize(
    ("mode", "marker"),
    [
        ("Prepare", "writer_session_status="),
        ("ValidatePrepared", "writer_session_validation_status="),
        ("ValidateReplacement", "replacement_receipt_validation_status="),
        ("RestoreWriter", "writer_restore_status="),
        ("Recover", "container_recovery_status="),
    ],
)
def test_public_modes_reject_invalid_hex_before_dispatch(
    tmp_path: Path,
    mode: str,
    marker: str,
):
    completed = _run_adapter(
        *_production_arguments(mode, tmp_path, session_id="g" * 32)
    )

    combined = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "sessionidismalformed." in _squash_whitespace(combined)
    assert marker not in combined
    assert not (tmp_path / f"{mode.lower()}-evidence.json").exists()
    assert not (tmp_path / "apps" / "current").exists()
    assert not (tmp_path / "code-restore.json").exists()
    assert not (tmp_path / "writer-restore.json").exists()


@pytest.mark.parametrize("mode", ["ValidatePrepared", "RestoreWriter", "Recover"])
@pytest.mark.parametrize(
    ("option", "replacement"),
    [
        ("-PreparedReceiptSha256", None),
        ("-PreparedReceiptSha256", "g" * 64),
        ("-HistoricalReceiptSha256", None),
        ("-HistoricalReceiptSha256", "g" * 64),
    ],
)
def test_prepared_validator_rejects_missing_or_malformed_hashes_without_product_mutation(
    tmp_path: Path, mode: str, option: str, replacement: str | None
):
    arguments = _production_arguments(mode, tmp_path, session_id="a" * 32)
    option_index = arguments.index(option)
    if replacement is None:
        del arguments[option_index : option_index + 2]
    else:
        arguments[option_index + 1] = replacement

    completed = _run_adapter(*arguments)

    assert completed.returncode != 0
    assert not (tmp_path / "apps" / "current").exists()
    assert not (tmp_path / "code-restore.json").exists()
    assert not (tmp_path / "missing-lifecycle-restore.json").exists()
    assert not (tmp_path / "writer-restore.json").exists()


@pytest.mark.parametrize(
    "mode", ["Prepare", "ValidateReplacement", "RestoreWriter", "Recover"]
)
@pytest.mark.parametrize("same_as_parent", [False, True])
def test_mutating_modes_reject_evidence_inside_install_parent(
    tmp_path: Path, mode: str, same_as_parent: bool
):
    install_parent = tmp_path / "apps"
    install_root = install_parent / "current"
    arguments = _production_arguments(mode, tmp_path, session_id="a" * 32)
    arguments[arguments.index("-InstallRoot") + 1] = str(install_root)
    arguments[arguments.index("-EvidencePath") + 1] = str(
        install_parent if same_as_parent else install_parent / "forbidden-evidence.json"
    )
    if mode == "Recover":
        arguments[arguments.index("-RestoreEvidencePath") + 1] = str(
            install_parent / "forbidden-code-restore.json"
        )

    completed = _run_adapter(*arguments)

    assert completed.returncode != 0
    combined = _squash_whitespace(completed.stdout + completed.stderr)
    assert "outsidethemutableinstallparent." in combined
    assert not install_root.exists()
    assert not install_parent.exists()


def test_prepare_rejects_historical_receipt_inside_install_parent_before_mutation(
    tmp_path: Path,
):
    install_parent = tmp_path / "apps"
    arguments = _production_arguments("Prepare", tmp_path, session_id="a" * 32)
    arguments[arguments.index("-HistoricalReceiptPath") + 1] = str(
        install_parent / "historical.json"
    )

    completed = _run_adapter(*arguments)

    assert completed.returncode != 0
    assert "outsidethemutableinstallparent." in _squash_whitespace(
        completed.stdout + completed.stderr
    )
    assert not (tmp_path / "prepare-evidence.json").exists()
    assert not (install_parent / "current").exists()


def test_prepare_rejects_conditional_short_name_alias_inside_install_parent(
    tmp_path: Path,
):
    install_parent = tmp_path / "Container_Audit_Long_Install_Parent"
    install_parent.mkdir()
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetShortPathNameW(
        str(install_parent), buffer, len(buffer)
    )
    if length == 0 or Path(buffer.value) == install_parent:
        pytest.skip("8.3 alias is unavailable on this volume")
    arguments = _production_arguments("Prepare", tmp_path, session_id="a" * 32)
    arguments[arguments.index("-InstallRoot") + 1] = str(install_parent / "current")
    arguments[arguments.index("-EvidencePath") + 1] = str(
        Path(buffer.value) / "forbidden.json"
    )

    completed = _run_adapter(*arguments)

    assert completed.returncode != 0
    assert "outsidethemutableinstallparent." in _squash_whitespace(
        completed.stdout + completed.stderr
    )
    assert not (install_parent / "forbidden.json").exists()
    assert not (install_parent / "current").exists()


@pytest.mark.parametrize(
    ("first_option", "second_option"),
    [
        ("-EvidencePath", "-RestoreEvidencePath"),
        ("-EvidencePath", "-LifecycleRestoreReceiptPath"),
        ("-EvidencePath", "-WriterRestoreEvidencePath"),
        ("-RestoreEvidencePath", "-LifecycleRestoreReceiptPath"),
        ("-RestoreEvidencePath", "-WriterRestoreEvidencePath"),
        ("-LifecycleRestoreReceiptPath", "-WriterRestoreEvidencePath"),
    ],
)
def test_recover_rejects_aliased_output_paths_before_mutation(
    tmp_path: Path, first_option: str, second_option: str
):
    arguments = _production_arguments("Recover", tmp_path, session_id="a" * 32)
    first_value = arguments[arguments.index(first_option) + 1]
    arguments[arguments.index(second_option) + 1] = first_value

    completed = _run_adapter(*arguments)

    assert completed.returncode != 0
    assert (
        "Recoveryoutputpathsmustbeabsent,pairwisedistinct,andoutside"
        "themutableinstallparent."
    ) in _squash_whitespace(completed.stdout + completed.stderr)
    assert not (tmp_path / "recover-evidence.json").exists()
    assert not (tmp_path / "code-restore.json").exists()
    assert not (tmp_path / "missing-lifecycle-restore.json").exists()
    assert not (tmp_path / "writer-restore.json").exists()


def test_recover_rejects_conditional_short_name_output_alias_before_mutation(
    tmp_path: Path,
):
    output_parent = tmp_path / "Container_Audit_Long_Recovery_Evidence_Parent"
    output_parent.mkdir()
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetShortPathNameW(
        str(output_parent), buffer, len(buffer)
    )
    if length == 0 or Path(buffer.value) == output_parent:
        pytest.skip("8.3 alias is unavailable on this volume")
    arguments = _production_arguments("Recover", tmp_path, session_id="a" * 32)
    long_output = output_parent / "combined.json"
    short_alias = Path(buffer.value) / "combined.json"
    arguments[arguments.index("-EvidencePath") + 1] = str(long_output)
    arguments[arguments.index("-RestoreEvidencePath") + 1] = str(short_alias)

    completed = _run_adapter(*arguments)

    assert completed.returncode != 0
    assert (
        "Recoveryoutputpathsmustbeabsent,pairwisedistinct,andoutside"
        "themutableinstallparent."
    ) in _squash_whitespace(completed.stdout + completed.stderr)
    assert not long_output.exists()
    assert not (tmp_path / "missing-lifecycle-restore.json").exists()
    assert not (tmp_path / "writer-restore.json").exists()


def test_recover_rejects_existing_late_output_before_mutation(tmp_path: Path):
    lifecycle_path = tmp_path / "missing-lifecycle-restore.json"
    lifecycle_path.write_text("preexisting", encoding="utf-8")
    arguments = _production_arguments("Recover", tmp_path, session_id="a" * 32)

    completed = _run_adapter(*arguments)

    assert completed.returncode != 0
    assert (
        "Recoveryoutputpathsmustbeabsent,pairwisedistinct,andoutside"
        "themutableinstallparent."
    ) in _squash_whitespace(completed.stdout + completed.stderr)
    assert lifecycle_path.read_text(encoding="utf-8") == "preexisting"
    assert not (tmp_path / "recover-evidence.json").exists()
    assert not (tmp_path / "code-restore.json").exists()
    assert not (tmp_path / "writer-restore.json").exists()


def test_recover_rejects_output_through_reparse_parent_before_mutation(
    tmp_path: Path,
):
    real_parent = tmp_path / "real-evidence"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-evidence"
    try:
        os.symlink(real_parent, linked_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    arguments = _production_arguments("Recover", tmp_path, session_id="a" * 32)
    for option, filename in [
        ("-EvidencePath", "combined.json"),
        ("-RestoreEvidencePath", "code.json"),
        ("-LifecycleRestoreReceiptPath", "lifecycle.json"),
        ("-WriterRestoreEvidencePath", "writer.json"),
    ]:
        arguments[arguments.index(option) + 1] = str(linked_parent / filename)

    completed = _run_adapter(*arguments)

    assert completed.returncode != 0
    assert "containsareparse-pointancestor." in _squash_whitespace(
        completed.stdout + completed.stderr
    )
    assert list(real_parent.iterdir()) == []
    assert not (tmp_path / "apps" / "current").exists()


def test_writer_session_adapter_exposes_only_natural_trigger_restore():
    source = ADAPTER.read_text(encoding="utf-8")
    recovery = source[source.index("function Invoke-ContainerRecovery") :]

    assert "Start-ScheduledTask" not in source
    assert "Enable-ScheduledTask" in source
    assert "Disable-ScheduledTask" in source
    assert "natural trigger survival was not observed" in source
    assert "CODE_RESTORE_FAILED" in source
    assert "WRITER_RESTORE_FAILED" in source
    assert "PREPARED_RECEIPT_OR_LIVE_DISABLED_INVALID" in source
    assert "Invoke-ContainerLifecycleFailureContainment" in source
    assert "removal_status=PASS_DATA_PRESERVED" in source
    assert "CONTAINER_WRITER_DIRECT_PREFLIGHT_FAILED" in source
    assert "CONTAINER_WRITER_PREPARE_FINAL_EVIDENCE_FAILED" in source
    assert "PREPARE_FINAL_EVIDENCE_FAILED_RETAIN_DISABLED" in source
    assert "Open-PinnedReadLock $HelperPath" in source
    assert "Open-PinnedReadLock $Script:IntegrityHelperPath" in source
    assert "Open-PinnedReadLock $ReplacementReceiptPath" in source
    assert "Open-ContainerVerifiedTreeReadLocks $root $root $replacement.old" in source
    assert (
        "Open-ContainerVerifiedTreeReadLocks $producer $root $replacement.new"
        in source
    )
    assert "if (Test-CanonicalSamePath $outputPaths[$left] $outputPaths[$right])" in source
    assert recovery.index("Test-ContainerPreparedBeforeReplacement") < recovery.index(
        "-RestoreVerifiedReplacement"
    )
    assert recovery.index("Test-ContainerReplacementBeforeCode") < recovery.index(
        "Invoke-ContainerLifecycleRestoreProduct"
    )


def test_writer_session_adapter_is_pinned_by_portable_manifest_contract():
    builder = (ROOT / "tools" / "build_portable_release_candidate.py").read_text(
        encoding="utf-8"
    )
    installer = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")
    canonical_installer = (ROOT / "INSTALL_CANONICAL_PORTABLE.ps1").read_text(
        encoding="utf-8"
    )

    assert '"tools/container_writer_session.ps1"' in builder
    assert '"writer_session_adapter_sha256"' in builder
    assert '"tools/container_writer_session_contract.json"' in builder
    assert '"writer_session_contract_sha256"' in builder
    assert "tools\\container_writer_session.ps1" in installer
    assert "writer_session_adapter_sha256" in installer
    assert "tools\\container_writer_session_contract.json" in installer
    assert "writer_session_contract_sha256" in installer
    assert "tools\\container_writer_session.ps1" in canonical_installer
    assert "writer_session_adapter_sha256" in canonical_installer
    assert "tools\\container_writer_session_contract.json" in canonical_installer
    assert "writer_session_contract_sha256" in canonical_installer

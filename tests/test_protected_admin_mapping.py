from __future__ import annotations

import ast
import copy
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import time

import pytest

import Container_Audit as container_audit_module
from Container_Audit import ContainerAudit
from logistics_runtime_profile import LogisticsRuntimeConfigurationError
import protected_admin as protected_admin_module
from protected_admin import (
    MAX_PROTECTED_ADMIN_ITERATIONS,
    MAX_PROTECTED_ADMIN_PROFILE_BYTES,
    PROTECTED_ADMIN_DISPLAY_NAME,
    PROTECTED_ADMIN_ITERATIONS,
    PROTECTED_ADMIN_OPERATOR_ID,
    PROTECTED_ADMIN_ROLE,
    ProtectedAdminProfileError,
    build_protected_admin_profile,
    default_protected_admin_profile_path,
    display_operator_name,
    is_protected_admin_code,
    load_protected_admin_profile,
    operator_role,
    persistent_operator_name,
    redact_authenticated_credential_entry,
    redact_protected_admin_identity,
    sanitize_persistent_value,
)
from tools import install_protected_admin as installer
from parked_tray_store import ParkedTrayStore
from tray_state import tray_session_to_state
from worker_registry import WorkerRegistry


TEST_ADMIN_CODE = "135790"
TEST_OTHER_CODE = "246801"
TEST_READER_SID = "S-1-5-21-111111111-222222222-333333333-1001"


@pytest.fixture(autouse=True)
def _provisioned_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "protected" / "protected_admin.json"
    target.parent.mkdir(parents=True)
    target.write_text(
        json.dumps(
            build_protected_admin_profile(TEST_ADMIN_CODE),
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONTAINER_AUDIT_PROTECTED_ADMIN_PROFILE", str(target))
    return target


class _Variable:
    def __init__(self, value: str):
        self.value = value

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value


class _Entry:
    def __init__(self, variable: _Variable):
        self.variable = variable
        self.show = ""
        self.values = []

    def get(self) -> str:
        return self.variable.get()

    def configure(self, **kwargs) -> None:
        if "show" in kwargs:
            self.show = kwargs["show"]
        if "values" in kwargs:
            self.values = list(kwargs["values"])


class _Root:
    @staticmethod
    def winfo_exists() -> bool:
        return True


class _Pane:
    @staticmethod
    def winfo_ismapped() -> bool:
        return True


def test_synthetic_code_is_canonical_admin_and_never_registered_as_worker(
    tmp_path: Path,
) -> None:
    registry_path = tmp_path / "worker_registry.json"
    registry = WorkerRegistry(str(registry_path))

    assert is_protected_admin_code(TEST_ADMIN_CODE)
    assert not is_protected_admin_code(TEST_OTHER_CODE)
    with pytest.raises(ValueError):
        registry.register(TEST_ADMIN_CODE)
    with pytest.raises(ValueError):
        registry.mark_recent(TEST_ADMIN_CODE)
    assert not registry.has_worker(TEST_ADMIN_CODE)
    assert operator_role(TEST_ADMIN_CODE) == PROTECTED_ADMIN_ROLE
    assert operator_role(PROTECTED_ADMIN_OPERATOR_ID) == "WORKER"
    assert display_operator_name(PROTECTED_ADMIN_OPERATOR_ID) == PROTECTED_ADMIN_DISPLAY_NAME
    assert not registry_path.exists()


def test_reserved_numeric_and_internal_identity_are_scrubbed_from_registry(
    tmp_path: Path,
) -> None:
    registry_path = tmp_path / "worker_registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "workers": [
                    {"name": TEST_ADMIN_CODE, "active": True},
                    {"name": PROTECTED_ADMIN_OPERATOR_ID, "active": True},
                    {"name": "작업자A", "active": True},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    registry = WorkerRegistry(str(registry_path))

    assert registry.list_workers() == ["작업자A"]
    persisted = registry_path.read_text(encoding="utf-8")
    assert TEST_ADMIN_CODE not in persisted
    assert PROTECTED_ADMIN_OPERATOR_ID not in persisted


def test_start_work_replaces_code_before_state_logs_or_worker_ui(tmp_path: Path) -> None:
    variable = _Variable(TEST_ADMIN_CODE)
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_entry_var = variable
    app.worker_entry = _Entry(variable)
    app.worker_registry = WorkerRegistry(str(tmp_path / "worker_registry.json"))
    app._authenticated_protected_admin = False
    app.worker_name = ""
    app.worker_role = ""
    app.root = _Root()
    app.paned_window = _Pane()
    app._load_session_state = lambda: None
    app._drain_phs_replacement_waiting_projections = lambda: None
    app._load_current_tray_state = lambda: None
    app._refresh_transfer_post_review_state = lambda: None
    logged = []
    app._log_event = lambda event, detail=None, **kwargs: logged.append((event, detail)) or True

    app.start_work()

    assert app.worker_name == PROTECTED_ADMIN_OPERATOR_ID
    assert app.worker_role == PROTECTED_ADMIN_ROLE
    assert variable.get() == PROTECTED_ADMIN_DISPLAY_NAME
    assert app.worker_entry.show == ""
    assert TEST_ADMIN_CODE not in repr(logged)
    assert PROTECTED_ADMIN_OPERATOR_ID not in repr(logged)
    assert not (tmp_path / "worker_registry.json").exists()


def test_tray_and_parked_state_force_canonical_identity_to_display(
    tmp_path: Path,
) -> None:
    tray = type(
        "Tray",
        (),
        {
            "master_label_code": "",
            "item_code": "",
            "item_name": "",
            "item_spec": "",
            "scanned_barcodes": [],
            "scan_times": [],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 0.0,
            "start_time": None,
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )()
    state = tray_session_to_state(tray, worker_name=PROTECTED_ADMIN_OPERATOR_ID)
    assert state["worker_name"] == PROTECTED_ADMIN_DISPLAY_NAME

    store = ParkedTrayStore(tmp_path / "parked")
    parked_path = store.save_state(
        state,
        worker_name=PROTECTED_ADMIN_OPERATOR_ID,
        master_label="legacy",
    )
    assert PROTECTED_ADMIN_OPERATOR_ID not in parked_path.name
    assert PROTECTED_ADMIN_OPERATOR_ID not in parked_path.read_text(encoding="utf-8")


def test_dynamic_builder_uses_a_fresh_random_salt() -> None:
    first = build_protected_admin_profile(TEST_ADMIN_CODE)
    second = build_protected_admin_profile(TEST_ADMIN_CODE)

    assert first["verifier"]["salt_hex"] != second["verifier"]["salt_hex"]
    assert first["verifier"]["digest_hex"] != second["verifier"]["digest_hex"]
    assert len(first["verifier"]["salt_hex"]) == 32
    assert len(first["verifier"]["digest_hex"]) == 64


def test_public_helper_surface_is_plan_c_cross_import_compatible() -> None:
    required = {
        "PROTECTED_ADMIN_DEFAULT_ITERATIONS",
        "PROTECTED_ADMIN_ITERATIONS",
        "PROTECTED_ADMIN_MAX_ITERATIONS",
        "PROTECTED_ADMIN_MIN_ITERATIONS",
        "canonical_operator_id",
        "display_operator_name",
        "is_protected_admin_code",
        "persistent_operator_name",
        "redact_authenticated_credential_entry",
        "redact_protected_admin_code",
        "redact_protected_admin_identity",
        "sanitize_persistent_value",
        "validate_protected_admin_profile",
    }
    assert required <= set(protected_admin_module.__all__)
    assert "profile_path" in inspect.signature(is_protected_admin_code).parameters
    assert (
        inspect.signature(display_operator_name)
        .parameters["authenticated_credential_entry"]
        .default
        is False
    )
    assert protected_admin_module.PROTECTED_ADMIN_MIN_ITERATIONS >= 600_000
    assert (
        protected_admin_module.PROTECTED_ADMIN_ITERATIONS
        == protected_admin_module.PROTECTED_ADMIN_DEFAULT_ITERATIONS
    )
    assert installer.__all__ == [
        "build_parser",
        "install_protected_admin_profile",
        "load_installed_profile",
        "main",
    ]
    assert (
        inspect.signature(installer.install_protected_admin_profile)
        .parameters["candidate"]
        .kind
        is inspect.Parameter.POSITIONAL_OR_KEYWORD
    )


def test_profile_size_is_rejected_before_unbounded_read(
    _provisioned_profile: Path,
) -> None:
    _provisioned_profile.write_bytes(
        b"x" * (MAX_PROTECTED_ADMIN_PROFILE_BYTES + 1)
    )
    with pytest.raises(ProtectedAdminProfileError):
        load_protected_admin_profile(_provisioned_profile)
    assert not is_protected_admin_code(
        TEST_ADMIN_CODE,
        profile_path=_provisioned_profile,
    )


def test_protected_profile_uses_override_and_secure_atomic_call_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "ProgramData" / "protected" / "protected_admin.json"
    monkeypatch.setenv("CONTAINER_AUDIT_PROTECTED_ADMIN_PROFILE", str(target))
    monkeypatch.setattr(installer, "_resolve_reader_sid", lambda _value: TEST_READER_SID)
    events: list[str] = []

    def label(path: Path, directory: bool) -> str:
        if directory:
            return "directory"
        if Path(path) == target:
            return "final"
        return "temporary"

    def apply_acl(path, _reader_sid, *, directory):
        kind = label(Path(path), directory)
        if kind == "temporary":
            assert Path(path).stat().st_size == 0
        events.append(f"{kind}-apply")

    def verify_acl(path, _reader_sid, *, directory):
        events.append(f"{label(Path(path), directory)}-verify")

    monkeypatch.setattr(installer, "_apply_exact_acl", apply_acl)
    monkeypatch.setattr(installer, "_verify_exact_acl", verify_acl)
    real_write_and_sync = installer._write_and_sync

    def write_and_trace(fd, data):
        events.append("write-fsync")
        real_write_and_sync(fd, data)

    monkeypatch.setattr(installer, "_write_and_sync", write_and_trace)
    real_replace = installer.os.replace

    def replace_with_trace(source, destination):
        events.append("replace")
        return real_replace(source, destination)

    monkeypatch.setattr(installer.os, "replace", replace_with_trace)

    assert default_protected_admin_profile_path() == str(target)
    assert installer.install_protected_admin_profile(dry_run=True)["status"] == "dry-run"
    assert not target.exists()

    report = installer.install_protected_admin_profile(
        candidate=TEST_ADMIN_CODE,
        profile_path=target,
        reader_principal="machine-reader",
    )
    installed = installer.load_installed_profile(target)

    assert report["role"] == PROTECTED_ADMIN_ROLE
    assert PROTECTED_ADMIN_OPERATOR_ID not in json.dumps(report, ensure_ascii=False)
    assert installed == load_protected_admin_profile(target)
    assert is_protected_admin_code(TEST_ADMIN_CODE)
    assert events == [
        "directory-apply",
        "directory-verify",
        "temporary-apply",
        "temporary-verify",
        "write-fsync",
        "temporary-verify",
        "replace",
        "final-apply",
        "final-verify",
    ]


def test_profile_is_required_and_direct_internal_id_never_authenticates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing" / "protected_admin.json"
    monkeypatch.setenv("CONTAINER_AUDIT_PROTECTED_ADMIN_PROFILE", str(missing))

    assert not is_protected_admin_code(TEST_ADMIN_CODE)
    assert operator_role(PROTECTED_ADMIN_OPERATOR_ID) == "WORKER"


def test_profile_rejects_duplicate_fields(_provisioned_profile: Path) -> None:
    payload = _provisioned_profile.read_text(encoding="utf-8")
    duplicate = payload[:-1] + ', "role": "ADMIN"}'
    _provisioned_profile.write_text(duplicate, encoding="utf-8")

    assert not is_protected_admin_code(TEST_ADMIN_CODE)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"extra": True}),
        lambda value: value.update({"operator_id": "other"}),
        lambda value: value["verifier"].update({"extra": True}),
        lambda value: value["verifier"].update({"algorithm": "other"}),
        lambda value: value["verifier"].update(
            {"iterations": PROTECTED_ADMIN_ITERATIONS - 1}
        ),
        lambda value: value["verifier"].update(
            {"iterations": MAX_PROTECTED_ADMIN_ITERATIONS + 1}
        ),
        lambda value: value["verifier"].update({"iterations": True}),
        lambda value: value["verifier"].update({"salt_hex": "a" * 30}),
        lambda value: value["verifier"].update({"salt_hex": "A" * 32}),
        lambda value: value["verifier"].update({"digest_hex": "a" * 62}),
        lambda value: value["verifier"].update({"digest_hex": "A" * 64}),
    ],
)
def test_profile_rejects_non_exact_schema(
    _provisioned_profile: Path,
    mutation,
) -> None:
    payload = copy.deepcopy(load_protected_admin_profile(_provisioned_profile))
    mutation(payload)
    _provisioned_profile.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProtectedAdminProfileError):
        load_protected_admin_profile(_provisioned_profile)
    assert not is_protected_admin_code(TEST_ADMIN_CODE)


def test_reparse_inspection_failure_is_wrapped_and_authentication_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_inspection(*_args, **_kwargs):
        raise LogisticsRuntimeConfigurationError("inspection failed")

    monkeypatch.setattr(
        protected_admin_module,
        "assert_path_has_no_reparse_components",
        fail_inspection,
    )

    with pytest.raises(ProtectedAdminProfileError):
        load_protected_admin_profile()
    assert not is_protected_admin_code(TEST_ADMIN_CODE)


def test_log_and_recovery_identity_are_display_only_without_numeric_overredaction(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "events.csv"
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = PROTECTED_ADMIN_OPERATOR_ID
    app.log_file_path = str(log_path)
    app._plan_b_event_detail = lambda _event, detail, **_kwargs: detail
    app._trigger_session_direct_sync = lambda _event: None

    assert app._log_event(
        "TEST_EVENT",
        detail={
            "submitted_by": PROTECTED_ADMIN_OPERATOR_ID,
            "business_value": TEST_ADMIN_CODE,
        },
        synchronous=True,
    )

    persisted = log_path.read_text(encoding="utf-8")
    assert TEST_ADMIN_CODE in persisted
    assert PROTECTED_ADMIN_OPERATOR_ID not in persisted
    assert PROTECTED_ADMIN_DISPLAY_NAME in persisted
    assert persistent_operator_name(PROTECTED_ADMIN_OPERATOR_ID) == PROTECTED_ADMIN_DISPLAY_NAME


def test_durable_transfer_stores_receive_display_alias_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = PROTECTED_ADMIN_OPERATOR_ID
    app.log_file_path = "events.csv"
    app.current_tray = type("Tray", (), {"master_label_code": "MASTER"})()
    captured_waiting: dict[str, object] = {}
    captured_blocks: list[dict[str, object]] = []

    class Store:
        @staticmethod
        def mark_phs_replacement_waiting(**kwargs):
            captured_waiting.update(kwargs)
            return {}

        @staticmethod
        def record_exchange_block(*, reason_code, details):
            captured_blocks.append(dict(details))
            return reason_code

    runtime = type("Runtime", (), {"store": Store()})()
    app._transfer_seal_runtime = lambda: runtime
    app._phs_replacement_waiting_session_id = lambda _context: "session"
    app._phs_replacement_waiting_locations = lambda _context: ["PHS_GOOD"]
    app._project_phs_replacement_waiting_row = lambda _row: None

    app._mark_phs_replacement_waiting({}, ("old", "new"))

    assert captured_waiting["operator"] == PROTECTED_ADMIN_DISPLAY_NAME

    app.transfer_seal_coordinator = type(
        "Coordinator",
        (),
        {"client": object(), "store": Store()},
    )()
    app._exact_transfer_exchange_blocked = lambda: True
    app.log_file_path = ""
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "showwarning",
        lambda *_args, **_kwargs: None,
    )

    assert app._block_unsafe_exact_exchange()
    assert app._block_unsafe_exact_master_label_replacement()
    assert all(
        row["operator"] == PROTECTED_ADMIN_DISPLAY_NAME
        for row in captured_blocks
    )


def test_general_sanitizers_leave_unrelated_six_digit_values_unchanged() -> None:
    payload = " ".join(f"{value:06d}" for value in range(60))
    started = time.perf_counter()

    assert redact_protected_admin_identity(payload) == payload
    assert time.perf_counter() - started < 0.2
    assert sanitize_persistent_value(
        {"item_code": "123456", "submitted_by": TEST_ADMIN_CODE}
    ) == {"item_code": "123456", "submitted_by": TEST_ADMIN_CODE}
    assert sanitize_persistent_value(
        {"submitted_by": f"  {TEST_ADMIN_CODE}  "}
    ) == {"submitted_by": f"  {TEST_ADMIN_CODE}  "}
    assert persistent_operator_name(TEST_ADMIN_CODE) == TEST_ADMIN_CODE
    assert display_operator_name(TEST_ADMIN_CODE) == TEST_ADMIN_CODE
    assert redact_authenticated_credential_entry(
        TEST_ADMIN_CODE,
        authenticated=False,
    ) == TEST_ADMIN_CODE
    assert redact_authenticated_credential_entry(
        TEST_ADMIN_CODE,
        authenticated=True,
    ) == "[protected-admin]"
    assert redact_authenticated_credential_entry(
        f"  {TEST_ADMIN_CODE}  ",
        authenticated=True,
    ) == "[protected-admin]"
    assert redact_authenticated_credential_entry(
        f"credential={TEST_ADMIN_CODE}",
        authenticated=True,
    ) == "[protected-admin]"
    assert (
        protected_admin_module.redact_protected_admin_code(
            PROTECTED_ADMIN_DISPLAY_NAME
        )
        == PROTECTED_ADMIN_DISPLAY_NAME
    )


def test_provisioner_removes_new_profile_when_final_acl_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "install-target" / "protected_admin.json"
    monkeypatch.setattr(installer, "_resolve_reader_sid", lambda _value: TEST_READER_SID)
    monkeypatch.setattr(installer, "_apply_exact_acl", lambda *_args, **_kwargs: None)

    def verify_acl(path, _reader_sid, *, directory):
        if not directory and Path(path) == target:
            raise RuntimeError("final ACL failed")

    monkeypatch.setattr(installer, "_verify_exact_acl", verify_acl)

    with pytest.raises(RuntimeError):
        installer.install_protected_admin_profile(
            candidate=TEST_ADMIN_CODE,
            profile_path=target,
            reader_principal="machine-reader",
        )
    assert not target.exists()


def test_failed_reprovision_restores_existing_valid_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "install-target" / "protected_admin.json"
    target.parent.mkdir(parents=True)
    original = build_protected_admin_profile(TEST_ADMIN_CODE)
    target.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setattr(installer, "_resolve_reader_sid", lambda _value: TEST_READER_SID)
    monkeypatch.setattr(installer, "_apply_exact_acl", lambda *_args, **_kwargs: None)
    final_verifications = 0

    def verify_acl(path, _reader_sid, *, directory):
        nonlocal final_verifications
        if not directory and Path(path) == target:
            final_verifications += 1
            if final_verifications == 2:
                raise RuntimeError("new final ACL failed")

    monkeypatch.setattr(installer, "_verify_exact_acl", verify_acl)

    with pytest.raises(RuntimeError):
        installer.install_protected_admin_profile(
            candidate=TEST_OTHER_CODE,
            profile_path=target,
            reader_principal="machine-reader",
            replace=True,
        )

    assert installer.load_installed_profile(target) == original
    assert final_verifications >= 3


def test_failed_restore_invalidates_target_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "install-target" / "protected_admin.json"
    target.parent.mkdir(parents=True)
    target.write_text(
        json.dumps(build_protected_admin_profile(TEST_ADMIN_CODE)),
        encoding="utf-8",
    )
    monkeypatch.setattr(installer, "_resolve_reader_sid", lambda _value: TEST_READER_SID)
    monkeypatch.setattr(installer, "_apply_exact_acl", lambda *_args, **_kwargs: None)
    target_verifications = 0

    def fail_new_and_restored_acl(path, _reader_sid, *, directory):
        nonlocal target_verifications
        if not directory and Path(path) == target:
            target_verifications += 1
            if target_verifications >= 2:
                raise RuntimeError("injected target ACL readback failure")

    monkeypatch.setattr(installer, "_verify_exact_acl", fail_new_and_restored_acl)

    with pytest.raises(RuntimeError):
        installer.install_protected_admin_profile(
            TEST_OTHER_CODE,
            profile_path=target,
            reader_principal="machine-reader",
            replace=True,
        )
    assert not target.exists()


@pytest.mark.parametrize(
    "principal",
    ["", "Everyone", "BUILTIN\\Users", "Authenticated Users", "name;injection"],
)
def test_provisioner_rejects_broad_or_malformed_reader_names(principal: str) -> None:
    with pytest.raises(ValueError):
        installer._validate_reader_principal(principal)


def test_acl_contract_rejects_broad_reader_sids() -> None:
    with pytest.raises(ValueError):
        installer._expected_acl_sddl("S-1-1-0", directory=True)
    sddl = installer._expected_acl_sddl(TEST_READER_SID, directory=False)
    assert sddl.count("(A;") == 3
    assert "SY" in sddl and "BA" in sddl and TEST_READER_SID in sddl


def test_cli_gets_two_matching_entries_only_from_getpass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "cli" / "protected_admin.json"
    entries = iter([TEST_ADMIN_CODE, TEST_ADMIN_CODE])
    prompts: list[str] = []

    def fake_getpass(prompt: str) -> str:
        prompts.append(prompt)
        return next(entries)

    captured: dict[str, object] = {}

    def fake_install(**kwargs):
        captured.update(kwargs)
        return {
            "status": "installed",
            "schema_version": 1,
            "role": "ADMIN",
            "profile_path": str(target),
        }

    monkeypatch.setattr(installer.getpass, "getpass", fake_getpass)
    monkeypatch.setattr(installer, "install_protected_admin_profile", fake_install)

    assert installer.main(
        ["--profile-path", str(target), "--reader-principal", "machine-reader"]
    ) == 0
    assert len(prompts) == 2
    assert captured["candidate"] == TEST_ADMIN_CODE
    option_strings = {
        option
        for action in installer.build_parser()._actions
        for option in action.option_strings
    }
    assert not any(
        marker in option.casefold()
        for option in option_strings
        for marker in ("code", "credential", "password", "secret")
    )


def test_cli_rejects_mismatched_entries_before_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = iter([TEST_ADMIN_CODE, TEST_OTHER_CODE])
    monkeypatch.setattr(installer.getpass, "getpass", lambda _prompt: next(entries))
    monkeypatch.setattr(
        installer,
        "install_protected_admin_profile",
        lambda **_kwargs: pytest.fail("installer must not receive mismatched credentials"),
    )

    assert installer.main(["--reader-principal", "machine-reader"]) == 2


def test_cli_rejects_credential_arguments_without_reflecting_them(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        installer.getpass,
        "getpass",
        lambda _prompt: pytest.fail("unknown arguments must be rejected before input"),
    )
    assert installer.main(["--code", TEST_ADMIN_CODE]) == 2
    output = capsys.readouterr()
    assert TEST_ADMIN_CODE not in output.out + output.err


def test_cli_dry_run_ignores_credential_environment_and_does_not_prompt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("PROTECTED_ADMIN_CODE", TEST_ADMIN_CODE)
    monkeypatch.setattr(
        installer.getpass,
        "getpass",
        lambda _prompt: pytest.fail("dry-run must not request a protected code"),
    )
    assert installer.main(["--dry-run"]) == 0
    output = capsys.readouterr()
    assert TEST_ADMIN_CODE not in output.out + output.err


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL integration test")
@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS", "").lower() == "true",
    reason="GitHub Actions is not the trusted Windows ACL integration target",
)
def test_windows_empty_temp_file_acl_readback_is_exact(tmp_path: Path) -> None:
    identity = subprocess.run(
        ["whoami.exe"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if identity.returncode != 0 or not identity.stdout.strip():
        pytest.skip("current Windows identity is unavailable")
    try:
        reader_sid = installer._resolve_reader_sid(identity.stdout.strip())
    except (OSError, RuntimeError, ValueError) as exc:
        pytest.skip(f"Windows ACL integration unavailable: {exc.__class__.__name__}")
    directory = tmp_path / "empty-profile-directory"
    installer._harden_profile_directory(directory, reader_sid)
    installer._verify_exact_acl(directory, reader_sid, directory=True)
    target = tmp_path / "empty-profile.tmp"
    target.write_bytes(b"")
    installer._harden_profile_file(target, reader_sid)
    assert target.read_bytes() == b""


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL integration test")
@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS", "").lower() == "true",
    reason="GitHub Actions is not the trusted Windows ACL integration target",
)
def test_windows_temp_profile_acl_integration(tmp_path: Path) -> None:
    import ctypes

    if not bool(ctypes.windll.shell32.IsUserAnAdmin()):
        pytest.skip("Windows ACL integration requires an elevated test process")
    identity = subprocess.run(
        ["whoami.exe"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if identity.returncode != 0 or not identity.stdout.strip():
        pytest.skip("current Windows identity is unavailable")
    target = tmp_path / "acl-integration" / "protected_admin.json"
    principal = identity.stdout.strip()
    try:
        reader_sid = installer._resolve_reader_sid(principal)
    except (OSError, RuntimeError, ValueError) as exc:
        pytest.skip(f"Windows ACL integration unavailable: {exc.__class__.__name__}")
    installer.install_protected_admin_profile(
        candidate=TEST_ADMIN_CODE,
        profile_path=target,
        reader_principal=principal,
    )
    installer._verify_exact_acl(target.parent, reader_sid, directory=True)
    installer._verify_exact_acl(target, reader_sid, directory=False)
    assert installer.load_installed_profile(target)["role"] == PROTECTED_ADMIN_ROLE


def test_source_has_no_embedded_default_verifier_or_reconstruction_helper() -> None:
    repository = Path(__file__).resolve().parents[1]
    production_paths = [
        repository / "protected_admin.py",
        repository / "tools" / "install_protected_admin.py",
        repository / "Container_Audit.py",
    ]
    production_sources = [path.read_text(encoding="utf-8") for path in production_paths]
    protected_source, installer_source, _app_source = production_sources
    combined = "\n".join(production_sources)

    assert "PROTECTED_ADMIN_SALT_HEX" not in protected_source
    assert "PROTECTED_ADMIN_DIGEST_HEX" not in protected_source
    assert "protected_admin_profile_payload" not in protected_source
    assert "protected_admin_profile_payload" not in installer_source
    assert "getpass.getpass" in installer_source
    assert "secrets.token_bytes" in protected_source
    assert not re.search(
        r"(?i)(?:salt|digest)[^\n=]*=\s*['\"][0-9a-f]{32,64}['\"]",
        combined,
    )
    for path, source in zip(production_paths, production_sources):
        six_digit_literals = [
            node.value
            for node in ast.walk(ast.parse(source, filename=str(path)))
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and len(node.value) == 6
            and node.value.isascii()
            and node.value.isdecimal()
        ]
        assert six_digit_literals == []

"""Runtime directory creation uses fake ProgramData entirely under pytest's root."""

import importlib
from pathlib import Path

import pytest

import auto_update
import direct_sync_auto_bootstrap as bootstrap
import storage_policy
import user_relay
from tools import direct_sync_relay_install_pack as install_pack


@pytest.fixture
def fake_machine(tmp_path, monkeypatch):
    program_data = tmp_path / "fake-program-data"
    local = tmp_path / "fake-local-app-data"
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.delenv("CONTAINER_AUDIT_DATA_ROOT", raising=False)
    monkeypatch.setattr(storage_policy, "_persisted_data_root", lambda: None)
    return program_data / "KMTech", local


JSON_WRITERS = [
    ("container_audit_product_host", "_write_json_atomic"),
    ("container_audit_product_host", "_append_jsonl"),
    ("current_user_onboarding", "_write_json_atomic"),
    ("current_user_onboarding", "_write_json_atomic_create_new"),
    ("direct_sync_auto_bootstrap", "_write_json"),
    ("direct_sync_operator", "_write_json_atomic"),
    ("direct_sync_operator", "_append_jsonl"),
    ("direct_sync_push", "_write_json_atomic"),
    ("direct_sync_push", "_prepare_status_temp"),
    ("direct_sync_runtime", "_write_json_atomic"),
    ("direct_sync_runtime", "_append_jsonl"),
    ("user_relay", "_write_json_atomic"),
    ("tools.direct_sync_relay_operator", "_write_json_atomic"),
    ("tools.direct_sync_relay_install_pack", "_write_json"),
]


@pytest.mark.parametrize("module,function", JSON_WRITERS)
@pytest.mark.parametrize("ancestor_exists", [False, True])
def test_runtime_writers_do_not_create_machine_ancestors(
    fake_machine, module, function, ancestor_exists,
):
    machine, _ = fake_machine
    if ancestor_exists:
        machine.mkdir(parents=True)
    target = machine / "ContainerAudit" / "machine-install" / "status" / "result.json"
    writer = getattr(importlib.import_module(module), function)

    with pytest.raises(ValueError, match="MACHINE_RUNTIME_DIRECTORY_NOT_PREPARED"):
        writer(target, {"scope": "directory-regression"})

    assert not (machine / "ContainerAudit").exists()
    assert machine.exists() is ancestor_exists


@pytest.mark.parametrize("root_kind", ["business", "relay", "machine-install"])
def test_storage_setup_refuses_unprepared_machine_root(fake_machine, root_kind):
    machine, _ = fake_machine
    suffix = {"business": "ContainerAudit", "relay": "DirectSync/container_audit",
              "machine-install": "ContainerAudit/machine-install"}[root_kind]

    with pytest.raises(ValueError, match="MACHINE_RUNTIME_DIRECTORY_NOT_PREPARED"):
        paths = storage_policy.build_container_audit_storage_paths(data_root=machine / suffix)
        storage_policy.ensure_container_audit_storage_dirs(paths)

    assert not machine.exists()


@pytest.mark.parametrize("flag,suffix", [
    ("--direct-sync-root", "DirectSync/container_audit"),
    ("--scan-source-dir", "ContainerAudit/events"),
])
def test_real_user_relay_entry_refuses_machine_override_before_relay(
    fake_machine, tmp_path, monkeypatch, flag, suffix,
):
    machine, _ = fake_machine
    notices = []
    # Installed startup admission is outside this directory regression; root
    # selection and relay main are real, and the owner probe must stay untouched.
    monkeypatch.setattr(auto_update, "startup_gate", lambda *_args, **_kwargs: None)
    import data_generation_guard
    monkeypatch.setattr(data_generation_guard, "probe_before_owner_paths",
                        lambda *_args, **_kwargs: pytest.fail("unprepared machine root reached owner probe"))
    monkeypatch.setattr(user_relay, "_notify_data_root_error", lambda: notices.append("blocked"))
    monkeypatch.setattr(user_relay, "acquire_runtime_instance",
                        lambda *_: pytest.fail("unprepared machine root reached relay acquisition"))

    assert user_relay.main(["--app-root", str(tmp_path / "app"), flag,
                            str(machine / suffix), "--once"]) == 1

    assert notices == ["blocked"]
    assert not machine.exists()


def test_session_command_refuses_machine_root_before_launch(fake_machine, tmp_path):
    machine, local = fake_machine
    app = tmp_path / "app"
    app.mkdir()
    (app / "Container_Audit.py").write_text("# owned source entry\n", encoding="utf-8")
    with pytest.raises(ValueError, match="MACHINE_RUNTIME_DIRECTORY_NOT_PREPARED"):
        bootstrap.build_session_direct_sync_command(
            app_root=app, direct_sync_root=machine / "DirectSync/container_audit",
            scan_source_dir=local / "events",
        )
    assert not machine.exists()


def test_update_download_does_not_create_machine_ancestors(fake_machine):
    machine, _ = fake_machine
    with pytest.raises(ValueError, match="MACHINE_RUNTIME_DIRECTORY_NOT_PREPARED"):
        auto_update.create_download_stage(machine / "ContainerAudit/updates")
    assert not machine.exists()


def test_legacy_wrapper_requires_machine_directories_prepared(fake_machine):
    machine, _ = fake_machine
    root = machine / "DirectSync/container_audit"
    with pytest.raises(ValueError, match="MACHINE_RUNTIME_DIRECTORY_NOT_PREPARED"):
        install_pack._write_scheduled_task_wrapper(root / "bin/relay.cmd", ["owned-command"])
    assert not machine.exists()


def test_legacy_acl_plan_does_not_create_machine_paths_or_apply_acl(fake_machine, monkeypatch):
    machine, _ = fake_machine
    monkeypatch.setattr(install_pack, "_run_command",
                        lambda *_: pytest.fail("unprepared machine path reached ACL command"))
    result = install_pack._apply_task_runtime_acl({
        "status": "PASS", "enabled": False,
        "paths": [str(machine / "DirectSync/container_audit")],
    })
    assert result["status"] == "FAIL"
    assert "MACHINE_RUNTIME_DIRECTORY_NOT_PREPARED" in result["blocked_reason"]
    assert not machine.exists()


def test_local_storage_still_creates_its_directories(fake_machine):
    machine, local = fake_machine
    paths = storage_policy.build_container_audit_storage_paths()
    storage_policy.ensure_container_audit_storage_dirs(paths)
    assert paths.data_root == local / "KMTech/ContainerAudit"
    assert paths.status_dir.is_dir()
    assert paths.events_dir.is_dir()
    assert not machine.exists()


@pytest.mark.parametrize("module,function", JSON_WRITERS)
def test_prepared_machine_directory_is_used_without_mkdir(fake_machine, monkeypatch, module, function):
    machine, _ = fake_machine
    prepared = machine / "ContainerAudit/machine-install/status"
    prepared.mkdir(parents=True)
    original_mkdir = Path.mkdir

    def no_machine_mkdir(path, *args, **kwargs):
        if path == machine or machine in path.parents:
            pytest.fail("runtime attempted mkdir in an already prepared machine tree")
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", no_machine_mkdir)
    writer = getattr(importlib.import_module(module), function)
    writer(prepared / "result.json", {"scope": "directory-regression"})
    assert prepared.is_dir()


def test_machine_guard_does_not_match_a_sibling_name(fake_machine):
    machine, _ = fake_machine
    sibling = machine.parent / "KMTech-other/data"
    storage_policy.ensure_user_runtime_directory(sibling)
    assert sibling.is_dir()
    assert not machine.exists()


def test_missing_onboarding_machine_profile_is_rejected_before_state_write(fake_machine, tmp_path):
    import current_user_onboarding as onboarding
    machine, local = fake_machine
    environ = {"PROGRAMDATA": str(machine.parent), "LOCALAPPDATA": str(local),
               "CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH": str(machine / "Logistics/profile.json")}
    with pytest.raises(ValueError, match="MACHINE_RUNTIME_DIRECTORY_NOT_PREPARED"):
        onboarding.resolve_current_user_onboarding_paths(tmp_path / "app", environ=environ)
    assert not machine.exists()

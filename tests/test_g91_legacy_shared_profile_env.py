"""G91: an app-specific profile env naming the old shared profile is ignored."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import logistics_runtime_profile as lrp
from current_user_onboarding import onboard_current_user, resolve_current_user_onboarding_paths
from tests import test_current_user_onboarding as base
from tests.test_current_user_onboarding import _isolate_onboarding_control_root  # noqa: F401  (autouse)

ENV = "CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH"
FAKE_PROFILE = b"legacy-shared-profile-fixture"
FAKE_SECRET = b"legacy-shared-secret-fixture"


def _fixture(tmp_path):
    program_data = tmp_path / "ProgramData"
    shared = program_data / "KMTech" / "Logistics"
    (shared / "secrets").mkdir(parents=True)
    profile = shared / "runtime-profile.json"
    secret = shared / "secrets" / "bearer-token.dpapi"
    profile.write_bytes(FAKE_PROFILE)
    secret.write_bytes(FAKE_SECRET)
    os.utime(profile, (1_600_000_000, 1_600_000_000))
    os.utime(secret, (1_600_000_000, 1_600_000_000))
    (tmp_path / "tmp").mkdir()
    local = tmp_path / "Local"
    local.mkdir()
    app_root = tmp_path / "hardened-app"
    app_root.mkdir()
    return program_data, shared, profile, secret, local, app_root


def _forms(tmp_path, shared):
    profile = str(shared / "runtime-profile.json")
    link = tmp_path / "junction-to-shared"
    import _winapi

    _winapi.CreateJunction(str(shared), str(link))
    return {
        "case": profile.swapcase(),
        "slash": profile.replace("\\", "/"),
        "trailing": profile + "\\",
        "verbatim": "\\?\\" + profile,
        "secret_dir_file": str(shared / "secrets" / "bearer-token.dpapi"),
        "junction": str(link / "runtime-profile.json"),
        "none": "",
    }


def _snap(*paths):
    return [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths]


@pytest.mark.skipif(os.name != "nt", reason="Windows path rules")
@pytest.mark.parametrize(
    "form", ["case", "slash", "trailing", "verbatim", "secret_dir_file", "junction", "none"]
)
def test_first_setup_ignores_legacy_shared_profile_env(tmp_path, form, monkeypatch):
    program_data, shared, profile, secret, local, app_root = _fixture(tmp_path)
    forms = _forms(tmp_path, shared)
    import runtime_instance_win32

    monkeypatch.setattr(runtime_instance_win32, "known_program_data", lambda: program_data)
    before = _snap(profile, secret)
    environment = {
        "CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "user-state"),
        ENV: forms[form],
    }
    paths = resolve_current_user_onboarding_paths(app_root, environ=environment)

    def register(selected):
        base._ready_state(selected)
        return 0

    result = onboard_current_user(
        app_root,
        environ=environment,
        require_bootstrap_integrity=False,
        registration_runner=register,
        profile_loader=base._profile_loader,
        credential_loader=base._credential_loader,
        ledger_factory=base._ledger_factory,
        autostart_installer=base._autostart,
        relay_launcher=base._relay_start,
    )
    assert result["status"] == "READY"
    assert paths.logistics_profile_path.is_relative_to((tmp_path / "user-state").resolve())
    assert paths.logistics_profile_path.is_file()
    assert _snap(profile, secret) == before


def test_sibling_and_app_specific_paths_are_respected(tmp_path):
    program_data, shared, *_ = _fixture(tmp_path)
    env = {"PROGRAMDATA": str(program_data)}
    for sibling in (
        program_data / "KMTech" / "Logistics2" / "runtime-profile.json",
        shared / "profiles" / "Container_Audit" / "runtime-profile.json",
        shared / "secretsX" / "a.dpapi",
    ):
        env[ENV] = str(sibling)
        assert not lrp.is_legacy_shared_profile_path(str(sibling), env)
        assert lrp.default_logistics_profile_path(env) == sibling
        assert lrp.app_profile_env_value(env) == str(sibling)

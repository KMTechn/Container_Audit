from __future__ import annotations

import json
import os
import stat
from types import SimpleNamespace

import pytest
import logistics_runtime_profile as runtime_module

from logistics_runtime_profile import (
    LogisticsRuntimeConfigurationError,
    default_logistics_profile_path,
    load_logistics_runtime_profile,
    protect_machine_secret,
    unprotect_machine_secret,
)
from transfer_seal import logistics_transfer_client_from_env
from tools.install_logistics_runtime_profile import (
    install_runtime_profile,
    main as install_main,
)
from tools.check_logistics_runtime_profile import main as readiness_main


def _profile(tmp_path, **changes):
    profile_path = tmp_path / "machine" / "profile.json"
    secret_path = profile_path.parent / "secrets" / "bearer-token.dpapi"
    secret_path.parent.mkdir(parents=True)
    secret_path.write_bytes(b"encrypted-token")
    value = {
        "contract_version": "km-logistics-runtime-profile-v1",
        "base_url": "https://logistics.example.invalid",
        "authority_scope": "scope-machine",
        "authority_epoch": 7,
        "authority_plane": "AUTHORITATIVE",
        "plane_epoch": 3,
        "device_id": "container-pc-01",
        "source_host_id": "container-host-01",
        "bearer_token_ref": "dpapi:secrets/bearer-token.dpapi",
        "timeout_seconds": 4,
    }
    value.update(changes)
    profile_path.write_text(json.dumps(value), encoding="utf-8")
    return profile_path


def _env(monkeypatch, profile_path):
    monkeypatch.setenv("KM_LOGISTICS_REQUIRED", "1")
    monkeypatch.setenv("KM_LOGISTICS_PROFILE_PATH", str(profile_path))


def test_default_profile_path_matches_shared_four_app_contract(tmp_path):
    assert default_logistics_profile_path({"PROGRAMDATA": str(tmp_path)}) == (
        tmp_path / "KMTech" / "Logistics" / "runtime-profile.json"
    )


def _capabilities():
    return {
        "capability_ids": ["bundle_member_replacement_v1"],
        "capabilities": {
            "bundle_member_replacement_v1": {
                "enabled": True,
                "command_type": "REPLACE_BUNDLE_MEMBERS",
                "resolver_contract_version": "logistics-good-replacement-source-v1",
                "resolver_path": "/logistics/api/v1/replacements/good-source/resolve",
                "max_pairs": 2,
                "atomic": True,
                "two_bundle_cas": True,
                "sealed_transfer_package": False,
                "replacement_source_bundle_cardinality": "EXACTLY_ONE_ACTIVE_MEMBER",
                "multi_member_source_policy": "REJECT_STALE_PHYSICAL_LABEL",
                "multi_member_source_error_code": "REPLACEMENT_SOURCE_NOT_SINGLETON",
                "target_label_action": "RETAIN_IDENTITY_LABEL",
                "target_label_identity_remains_valid": True,
                "target_label_membership_bound": False,
            }
        },
    }


class _Response:
    status_code = 200

    def __init__(self, capabilities=None):
        self.capabilities = capabilities or _capabilities()

    def json(self):
        return {"ok": True, "data": self.capabilities}


class _Session:
    def __init__(self, *, fail=False, capabilities=None):
        self.fail = fail
        self.capabilities = capabilities
        self.headers = None

    def request(self, _method, _url, **kwargs):
        if self.fail:
            raise OSError("token=DO_NOT_LOG")
        self.headers = kwargs["headers"]
        return _Response(self.capabilities)


def test_machine_profile_uses_dpapi_reference_and_redacts_token(tmp_path, monkeypatch):
    path = _profile(tmp_path)
    _env(monkeypatch, path)

    resolved = load_logistics_runtime_profile(
        decryptor=lambda value: "machine-secret" if value == b"encrypted-token" else ""
    )

    assert resolved is not None
    assert resolved.authority_scope == "scope-machine"
    assert resolved.authority_plane == "AUTHORITATIVE"
    assert "machine-secret" not in repr(resolved)


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI round-trip")
def test_machine_scope_dpapi_round_trip_never_contains_plaintext():
    token = "DPAPI-ROUNDTRIP-SECRET"

    protected = protect_machine_secret(token)

    assert protected
    assert token.encode("utf-8") not in protected
    assert unprotect_machine_secret(protected) == token


@pytest.mark.parametrize(
    "mode,attributes",
    [(stat.S_IFLNK, 0), (stat.S_IFREG, 0x400)],
)
def test_dpapi_secret_path_rejects_reparse_before_resolving(
    tmp_path, monkeypatch, mode, attributes
):
    path = _profile(tmp_path)
    secret_path = path.parent / "secrets" / "bearer-token.dpapi"
    original_lstat = runtime_module.os.lstat

    def fake_lstat(candidate):
        if runtime_module.Path(candidate) == secret_path:
            return SimpleNamespace(
                st_mode=mode,
                st_file_attributes=attributes,
            )
        return original_lstat(candidate)

    monkeypatch.setattr(runtime_module.os, "lstat", fake_lstat)

    with pytest.raises(LogisticsRuntimeConfigurationError, match="symlink|junction"):
        runtime_module._resolve_secret_path(
            path,
            "dpapi:secrets/bearer-token.dpapi",
        )


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"base_url": "http://logistics.example.invalid"}, "HTTPS"),
        ({"base_url": "https://logistics.example.invalid/prefix"}, "HTTPS"),
        ({"base_url": "https://logistics.example.invalid:99999"}, "valid URL"),
        ({"base_url": "https://127.0.0.1:8443"}, "loopback"),
        ({"authority_plane": "SHADOW_CANDIDATE"}, "AUTHORITATIVE"),
        ({"bearer_token_ref": "dpapi:../token.dpapi"}, "profile directory"),
        ({"bearer_token": "plaintext"}, "plaintext"),
    ],
)
def test_invalid_machine_profile_fails_closed(tmp_path, monkeypatch, changes, message):
    path = _profile(tmp_path, **changes)
    _env(monkeypatch, path)

    with pytest.raises(LogisticsRuntimeConfigurationError, match=message):
        load_logistics_runtime_profile(decryptor=lambda _value: "secret")


def test_duplicate_profile_fields_and_whitespace_token_fail_closed(tmp_path, monkeypatch):
    path = _profile(tmp_path)
    raw = path.read_text(encoding="utf-8")
    path.write_text(
        raw.replace(
            '"base_url":',
            '"base_url":"https://attacker.invalid","base_url":',
            1,
        ),
        encoding="utf-8",
    )
    _env(monkeypatch, path)

    with pytest.raises(LogisticsRuntimeConfigurationError, match="duplicate field"):
        load_logistics_runtime_profile(decryptor=lambda _value: "secret")

    path = _profile(tmp_path / "token")
    _env(monkeypatch, path)
    with pytest.raises(LogisticsRuntimeConfigurationError, match="token"):
        load_logistics_runtime_profile(decryptor=lambda _value: "secret with spaces")


def test_required_mode_never_borrows_legacy_process_credentials(tmp_path, monkeypatch):
    missing = tmp_path / "missing.json"
    _env(monkeypatch, missing)
    monkeypatch.setenv("WORKER_ANALYSIS_LOGISTICS_API_BASE_URL", "https://legacy.invalid")
    monkeypatch.setenv("WORKER_ANALYSIS_LOGISTICS_API_TOKEN", "legacy-secret")
    monkeypatch.setenv("WORKER_ANALYSIS_LOGISTICS_SOURCE_HOST_ID", "legacy-host")

    with pytest.raises(LogisticsRuntimeConfigurationError, match="profile is missing"):
        logistics_transfer_client_from_env(profile_decryptor=lambda _value: "secret")


@pytest.mark.skipif(os.name != "nt", reason="Windows Machine environment trust boundary")
def test_hklm_machine_profile_ignores_process_path_override(tmp_path, monkeypatch):
    machine = _profile(tmp_path / "machine-profile")
    process = _profile(tmp_path / "process-profile", base_url="https://attacker.invalid")
    monkeypatch.setenv("KM_LOGISTICS_PROFILE_PATH", str(process))
    monkeypatch.setenv("KM_LOGISTICS_REQUIRED", "0")
    values = {
        "KM_LOGISTICS_PROFILE_PATH": str(machine),
        "KM_LOGISTICS_REQUIRED": "1",
    }
    monkeypatch.setattr(
        runtime_module,
        "_machine_environment_value",
        lambda name: values.get(name, ""),
    )

    resolved = load_logistics_runtime_profile(decryptor=lambda _value: "machine-secret")

    assert resolved is not None
    assert resolved.base_url == "https://logistics.example.invalid"
    assert resolved.required is True


def test_required_startup_performs_authenticated_capability_probe(tmp_path, monkeypatch):
    path = _profile(tmp_path)
    _env(monkeypatch, path)
    session = _Session()

    client = logistics_transfer_client_from_env(
        session=session,
        profile_decryptor=lambda _value: "machine-secret",
    )

    assert client is not None
    assert client.authoritative_required is True
    assert session.headers["Authorization"] == "Bearer machine-secret"
    assert "machine-secret" not in repr(client)


@pytest.mark.parametrize("replacement", [None, "UNKNOWN_ERROR_CODE"])
def test_required_startup_rejects_missing_or_unknown_singleton_contract(
    tmp_path, monkeypatch, replacement
):
    path = _profile(tmp_path)
    _env(monkeypatch, path)
    capabilities = _capabilities()
    capability = capabilities["capabilities"]["bundle_member_replacement_v1"]
    if replacement is None:
        capability.pop("multi_member_source_error_code")
    else:
        capability["multi_member_source_error_code"] = replacement

    with pytest.raises(
        LogisticsRuntimeConfigurationError,
        match="capability readiness is incomplete",
    ):
        logistics_transfer_client_from_env(
            session=_Session(capabilities=capabilities),
            profile_decryptor=lambda _value: "machine-secret",
        )


def test_required_startup_transport_failure_is_sanitized(tmp_path, monkeypatch):
    path = _profile(tmp_path)
    _env(monkeypatch, path)

    with pytest.raises(LogisticsRuntimeConfigurationError) as captured:
        logistics_transfer_client_from_env(
            session=_Session(fail=True),
            profile_decryptor=lambda _value: "machine-secret",
        )

    assert "DO_NOT_LOG" not in str(captured.value)


def test_installer_dry_run_is_write_free_and_never_prints_token(tmp_path, monkeypatch, capsys):
    token = "INSTALL-SECRET-MUST-NOT-PRINT"
    target = tmp_path / "not-created" / "profile.json"
    monkeypatch.setenv("INSTALL_TOKEN_TEST", token)

    result = install_main(
        [
            "--profile-path", str(target),
            "--base-url", "https://logistics.example.invalid",
            "--authority-scope", "scope-machine",
            "--authority-epoch", "7",
            "--plane-epoch", "3",
            "--device-id", "container-pc-01",
            "--source-host-id", "container-host-01",
            "--token-env", "INSTALL_TOKEN_TEST",
            "--dry-run",
        ]
    )
    captured = capsys.readouterr()

    assert result == 0
    assert token not in captured.out + captured.err
    assert not target.parent.exists()


def test_installer_validates_before_any_write_and_readiness_missing_is_blocked(tmp_path):
    target = tmp_path / "not-created" / "profile.json"
    with pytest.raises(LogisticsRuntimeConfigurationError, match="HTTPS"):
        install_runtime_profile(
            profile_path=target,
            base_url="http://invalid.example",
            authority_scope="scope-machine",
            authority_epoch=7,
            authority_plane="AUTHORITATIVE",
            plane_epoch=3,
            device_id="container-pc-01",
            source_host_id="container-host-01",
            bearer_token="secret",
        )
    assert not target.parent.exists()
    assert readiness_main(["--profile-path", str(target)]) == 2


def test_installer_requires_reader_principal_before_any_write(tmp_path):
    target = tmp_path / "not-created" / "profile.json"

    with pytest.raises(ValueError, match="reader_principal"):
        install_runtime_profile(
            profile_path=target,
            base_url="https://logistics.example.invalid",
            authority_scope="scope-machine",
            authority_epoch=7,
            authority_plane="AUTHORITATIVE",
            plane_epoch=3,
            device_id="container-pc-01",
            source_host_id="container-host-01",
            bearer_token="secret",
        )

    assert not target.parent.exists()

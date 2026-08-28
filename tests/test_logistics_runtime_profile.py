from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import Container_Audit as container_module
import logistics_runtime_profile as runtime_module

from logistics_runtime_profile import (
    LogisticsRuntimeConfigurationError,
    TEST1_ISOLATED_LEGACY_OVERRIDE_ENV,
    default_logistics_profile_path,
    load_logistics_runtime_profile,
    protect_current_user_secret,
    protect_machine_secret,
    unprotect_current_user_secret,
    unprotect_machine_secret,
)
from transfer_seal import TransferSealError, logistics_transfer_client_from_env
from tools.install_logistics_runtime_profile import (
    install_runtime_profile,
    install_tls_ca_bundle_for_existing_profile,
    main as install_main,
)
from tools import install_logistics_runtime_profile as installer_module
from tools.check_logistics_runtime_profile import main as readiness_main


def test_gui_startup_builds_client_without_network_readiness_probe(monkeypatch):
    calls = []
    sentinel = object()

    def fake_factory(*, probe_required=True):
        calls.append(probe_required)
        return sentinel

    monkeypatch.setattr(
        container_module,
        "logistics_transfer_client_from_env",
        fake_factory,
    )

    assert container_module.container_startup_logistics_client() is sentinel
    assert calls == [False]


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


def _private_ca_pem() -> bytes:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Container Audit Test Private CA")]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def test_default_profile_path_is_container_audit_scoped(tmp_path):
    assert default_logistics_profile_path({"PROGRAMDATA": str(tmp_path)}) == (
        tmp_path
        / "KMTech"
        / "Logistics"
        / "profiles"
        / "Container_Audit"
        / "runtime-profile.json"
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
    assert resolved.ledger_plane == "AUTHORITATIVE"
    assert "machine-secret" not in repr(resolved)


def test_machine_profile_defaults_to_no_explicit_tls_ca_bundle(tmp_path, monkeypatch):
    path = _profile(tmp_path)
    _env(monkeypatch, path)

    resolved = load_logistics_runtime_profile(
        decryptor=lambda _value: "machine-secret"
    )

    assert resolved is not None
    assert resolved.tls_ca_bundle_path == ""
    assert resolved.redacted_summary()["tls_private_ca_configured"] is False


def test_machine_profile_resolves_durable_tls_ca_bundle(tmp_path, monkeypatch):
    profile_root = tmp_path / "machine"
    ca_bundle = profile_root / "tls" / "ca-bundle.pem"
    ca_bundle.parent.mkdir(parents=True)
    ca_bundle.write_bytes(b"private-ca-fixture")
    path = _profile(tmp_path, tls_ca_bundle_path=str(ca_bundle.resolve()))
    _env(monkeypatch, path)

    resolved = load_logistics_runtime_profile(
        decryptor=lambda _value: "machine-secret"
    )

    assert resolved is not None
    assert resolved.tls_ca_bundle_path == str(ca_bundle.resolve())
    assert resolved.redacted_summary()["tls_private_ca_configured"] is True


@pytest.mark.parametrize("location", ["outside", "missing"])
def test_machine_profile_tls_ca_bundle_fails_closed_outside_owned_profile(
    tmp_path, monkeypatch, location
):
    if location == "outside":
        ca_bundle = tmp_path / "outside-ca.pem"
        ca_bundle.write_bytes(b"outside-private-ca-fixture")
    else:
        ca_bundle = tmp_path / "machine" / "tls" / "missing-ca.pem"
    path = _profile(tmp_path, tls_ca_bundle_path=str(ca_bundle.resolve()))
    _env(monkeypatch, path)

    with pytest.raises(
        LogisticsRuntimeConfigurationError,
        match=("inside the profile directory" if location == "outside" else "unavailable"),
    ):
        load_logistics_runtime_profile(decryptor=lambda _value: "machine-secret")


def test_required_profile_separates_authority_mode_from_selected_ledger_plane(
    tmp_path, monkeypatch
):
    path = _profile(tmp_path, ledger_plane="SHADOW_CANDIDATE")
    _env(monkeypatch, path)

    client = logistics_transfer_client_from_env(
        session=_Session(),
        profile_decryptor=lambda _value: "machine-secret",
    )

    assert client is not None
    assert client.authority_plane == "AUTHORITATIVE"
    assert client.ledger_plane == "SHADOW_CANDIDATE"
    client.assert_authority(
        "scope-machine",
        authority_epoch=7,
        ledger_plane="SHADOW_CANDIDATE",
        plane_epoch=3,
    )
    with pytest.raises(TransferSealError, match="ledger plane"):
        client.assert_authority(
            "scope-machine",
            authority_epoch=7,
            ledger_plane="AUTHORITATIVE",
            plane_epoch=3,
        )


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
        ({"ledger_plane": "UNKNOWN"}, "ledger_plane"),
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


def _enable_valid_test1_legacy_override(monkeypatch):
    run_root = runtime_module.Path(
        r"C:\KMTech\Test1\Runs\run-container-20260804"
    )
    ca_bundle = run_root / "tls" / "test1-ca.pem"
    monkeypatch.setattr(runtime_module.sys, "platform", "win32")
    monkeypatch.setenv(TEST1_ISOLATED_LEGACY_OVERRIDE_ENV, "1")
    monkeypatch.setenv("COMPUTERNAME", "TEST1")
    monkeypatch.setenv(
        "CONTAINER_AUDIT_DATA_ROOT",
        str(run_root / "ContainerAudit"),
    )
    monkeypatch.setenv(
        "WORKER_ANALYSIS_LOGISTICS_API_BASE_URL",
        "https://127.0.0.1:18443",
    )
    monkeypatch.setenv(
        "WORKER_ANALYSIS_LOGISTICS_API_TOKEN",
        "test1-container-token",
    )
    monkeypatch.setenv(
        "WORKER_ANALYSIS_LOGISTICS_AUTHORITY_SCOPE_ID",
        "TEST1-CONTAINER-RUN",
    )
    monkeypatch.setenv(
        "WORKER_ANALYSIS_LOGISTICS_SOURCE_HOST_ID",
        "test1-container-host",
    )
    monkeypatch.setenv(
        "WORKER_ANALYSIS_LOGISTICS_DEVICE_ID",
        "test1-container-device",
    )
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(ca_bundle))
    monkeypatch.delenv("KM_LOGISTICS_PROFILE_PATH", raising=False)
    monkeypatch.delenv("KM_LOGISTICS_REQUIRED", raising=False)

    original_is_file = runtime_module.Path.is_file
    original_stat = runtime_module.Path.stat
    monkeypatch.setattr(
        runtime_module.Path,
        "is_file",
        lambda path: path == ca_bundle or original_is_file(path),
    )
    monkeypatch.setattr(
        runtime_module.Path,
        "stat",
        lambda path: (
            SimpleNamespace(st_size=20)
            if path == ca_bundle
            else original_stat(path)
        ),
    )
    return run_root, ca_bundle


def test_test1_isolated_legacy_override_uses_only_process_environment(
    monkeypatch,
):
    _enable_valid_test1_legacy_override(monkeypatch)
    machine_reads = []
    monkeypatch.setattr(
        runtime_module,
        "_machine_environment_value",
        lambda name: machine_reads.append(name)
        or {
            "KM_LOGISTICS_PROFILE_PATH": (
                r"C:\ProgramData\KMTech\Logistics\runtime-profile.json"
            ),
            "KM_LOGISTICS_REQUIRED": "1",
        }.get(name, ""),
    )

    assert runtime_module._runtime_environment(None) is os.environ
    assert load_logistics_runtime_profile(required=True) is None
    client = logistics_transfer_client_from_env(
        session=_Session(),
        probe_required=False,
    )

    assert client is not None
    assert client.base_url == "https://127.0.0.1:18443"
    assert client.source_host_id == "test1-container-host"
    assert client.device_id == "test1-container-device"
    assert client.authoritative_required is False
    assert machine_reads == []


@pytest.mark.parametrize(
    ("environment_name", "value", "message"),
    [
        (
            TEST1_ISOLATED_LEGACY_OVERRIDE_ENV,
            "true",
            "must be exactly 1",
        ),
        ("COMPUTERNAME", "TEST10", "COMPUTERNAME=TEST1"),
        (
            "KM_LOGISTICS_PROFILE_PATH",
            "",
            "anchors to be absent",
        ),
        (
            "KM_LOGISTICS_REQUIRED",
            "0",
            "anchors to be absent",
        ),
        (
            "CONTAINER_AUDIT_DATA_ROOT",
            "",
            "nonempty CONTAINER_AUDIT_DATA_ROOT",
        ),
        (
            "CONTAINER_AUDIT_DATA_ROOT",
            r"C:\KMTech\Test1\Runs",
            "nonempty run directory",
        ),
        (
            "CONTAINER_AUDIT_DATA_ROOT",
            r"C:\ProgramData\KMTech\Test1\Runs\run-container-20260804",
            "CONTAINER_AUDIT_DATA_ROOT under",
        ),
        (
            "WORKER_ANALYSIS_LOGISTICS_API_BASE_URL",
            "http://127.0.0.1:18443",
            "exact loopback origin",
        ),
        (
            "WORKER_ANALYSIS_LOGISTICS_API_BASE_URL",
            "https://localhost:18443",
            "exact loopback origin",
        ),
        (
            "WORKER_ANALYSIS_LOGISTICS_API_BASE_URL",
            "https://127.0.0.1:18443/",
            "exact loopback origin",
        ),
        (
            "WORKER_ANALYSIS_LOGISTICS_API_BASE_URL",
            "https://127.0.0.1:65536",
            "exact HTTPS loopback origin",
        ),
        (
            "WORKER_ANALYSIS_LOGISTICS_AUTHORITY_SCOPE_ID",
            "PLANT-01",
            "TEST1- authority scope",
        ),
        (
            "WORKER_ANALYSIS_LOGISTICS_AUTHORITY_SCOPE_ID",
            "TEST1-CONTAINER RUN",
            "TEST1- authority scope",
        ),
        (
            "WORKER_ANALYSIS_LOGISTICS_SOURCE_HOST_ID",
            "container-host",
            "test1- source host",
        ),
        (
            "WORKER_ANALYSIS_LOGISTICS_SOURCE_HOST_ID",
            "test1-container host",
            "test1- source host",
        ),
        (
            "WORKER_ANALYSIS_LOGISTICS_DEVICE_ID",
            "container-device",
            "test1- device",
        ),
        (
            "WORKER_ANALYSIS_LOGISTICS_API_TOKEN",
            "test1 token",
            "valid token",
        ),
        (
            "REQUESTS_CA_BUNDLE",
            (
                r"C:\KMTech\Test1\Runs\other-run"
                r"\tls\test1-ca.pem"
            ),
            "same run directory",
        ),
        (
            "REQUESTS_CA_BUNDLE",
            r"C:\ProgramData\test1-ca.pem",
            "REQUESTS_CA_BUNDLE under",
        ),
        (
            "REQUESTS_CA_BUNDLE",
            (
                r"C:\KMTech\Test1\Runs\run-container-20260804"
                r"\tls\missing.pem"
            ),
            "non-reparse file",
        ),
    ],
)
def test_test1_isolated_legacy_override_rejects_invalid_envelope(
    monkeypatch,
    environment_name,
    value,
    message,
):
    _enable_valid_test1_legacy_override(monkeypatch)
    monkeypatch.setenv(environment_name, value)
    machine_reads = []
    monkeypatch.setattr(
        runtime_module,
        "_machine_environment_value",
        lambda name: machine_reads.append(name) or "",
    )

    with pytest.raises(LogisticsRuntimeConfigurationError, match=message):
        load_logistics_runtime_profile(required=True)
    assert machine_reads == []


def test_test1_isolated_legacy_override_rejects_non_windows(monkeypatch):
    _enable_valid_test1_legacy_override(monkeypatch)
    monkeypatch.setattr(runtime_module.sys, "platform", "linux")

    with pytest.raises(LogisticsRuntimeConfigurationError, match="requires Windows"):
        load_logistics_runtime_profile(required=True)


def test_test1_isolated_legacy_override_rejects_reparse_ca_bundle(
    monkeypatch,
):
    _run_root, ca_bundle = _enable_valid_test1_legacy_override(monkeypatch)
    original_lstat = runtime_module.os.lstat

    def fake_lstat(path):
        if runtime_module.Path(path) == ca_bundle:
            return SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_file_attributes=0x400,
            )
        return original_lstat(path)

    monkeypatch.setattr(runtime_module.os, "lstat", fake_lstat)
    with pytest.raises(
        LogisticsRuntimeConfigurationError,
        match="symlink|junction",
    ):
        load_logistics_runtime_profile(required=True)


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


@pytest.mark.skipif(os.name != "nt", reason="Windows Machine environment trust boundary")
def test_scoped_profile_supersedes_legacy_machine_profile_path(tmp_path, monkeypatch):
    scoped = _profile(tmp_path / "scoped-profile")
    legacy = _profile(tmp_path / "legacy-profile", base_url="https://legacy.invalid")
    monkeypatch.setattr(runtime_module, "_canonical_machine_profile_path", lambda: scoped)
    monkeypatch.setattr(
        runtime_module,
        "_machine_environment_value",
        lambda name: {
            "KM_LOGISTICS_PROFILE_PATH": str(legacy),
            "KM_LOGISTICS_REQUIRED": "1",
        }.get(name, ""),
    )

    resolved = load_logistics_runtime_profile(decryptor=lambda _value: "scoped-secret")

    assert resolved is not None
    assert resolved.profile_path == str(scoped.resolve())
    assert resolved.base_url == "https://logistics.example.invalid"


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
            "--ledger-plane", "SHADOW_CANDIDATE",
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
    report = json.loads(captured.out)
    assert report["authority_plane"] == "AUTHORITATIVE"
    assert report["ledger_plane"] == "SHADOW_CANDIDATE"
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


def test_installer_rejects_invalid_tls_ca_before_any_profile_write(
    tmp_path, monkeypatch
):
    target = tmp_path / "not-created" / "profile.json"
    invalid_ca = tmp_path / "invalid-ca.pem"
    invalid_ca.write_bytes(b"not-a-pem-certificate")
    monkeypatch.setattr(
        installer_module,
        "protect_current_user_secret",
        lambda value: b"protected:" + value.encode("utf-8"),
    )

    with pytest.raises(
        LogisticsRuntimeConfigurationError,
        match="only PEM certificates",
    ):
        install_runtime_profile(
            profile_path=target,
            base_url="https://logistics.example.invalid",
            authority_scope="scope-current-user",
            authority_epoch=7,
            authority_plane="AUTHORITATIVE",
            plane_epoch=3,
            device_id="container-pc-user",
            source_host_id="container-host-user",
            bearer_token="secret",
            tls_ca_bundle_path=invalid_ca,
            credential_scope="current_user",
        )

    assert not target.parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="CurrentUser DPAPI is Windows-only")
def test_current_user_dpapi_roundtrip():
    token = "CURRENT-USER-DPAPI-TEST-TOKEN"

    protected = protect_current_user_secret(token)

    assert protected != token.encode("utf-8")
    assert unprotect_current_user_secret(protected) == token


def test_current_user_profile_install_needs_no_machine_acl_and_reads_back(
    tmp_path, monkeypatch
):
    target = tmp_path / "profiles" / "Container_Audit" / "runtime-profile.json"
    ca_source = tmp_path / "private-ca.cert.pem"
    ca_payload = _private_ca_pem()
    ca_source.write_bytes(ca_payload)
    token = "CURRENT-USER-PROFILE-TOKEN"
    monkeypatch.setattr(
        installer_module,
        "_secure_profile_directory",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("current-user profile must not apply a machine ACL")
        ),
    )
    monkeypatch.setattr(
        installer_module,
        "protect_current_user_secret",
        lambda value: b"protected:" + value.encode("utf-8"),
    )
    monkeypatch.setattr(
        installer_module,
        "unprotect_current_user_secret",
        lambda value: value.removeprefix(b"protected:").decode("utf-8"),
    )

    report = install_runtime_profile(
        profile_path=target,
        base_url="https://logistics.example.invalid",
        authority_scope="scope-current-user",
        authority_epoch=7,
        authority_plane="AUTHORITATIVE",
        plane_epoch=3,
        device_id="container-pc-user",
        source_host_id="container-host-user",
        bearer_token=token,
        tls_ca_bundle_path=ca_source,
        credential_scope="current_user",
    )

    profile = json.loads(target.read_text(encoding="utf-8"))
    secret_path = target.parent / "secrets" / "bearer-token.dpapi"
    ca_target = target.parent / "tls" / "ca-bundle.pem"
    assert report["credential_scope"] == "current_user"
    assert profile["credential_scope"] == "current_user"
    assert profile["tls_ca_bundle_path"] == str(ca_target)
    assert secret_path.read_bytes() == b"protected:" + token.encode("utf-8")
    assert ca_target.read_bytes() == ca_payload


def test_existing_current_user_profile_can_add_ca_without_rotating_secret(
    tmp_path, monkeypatch
):
    target = tmp_path / "profiles" / "Container_Audit" / "runtime-profile.json"
    token = "CURRENT-USER-PROFILE-TOKEN"
    monkeypatch.setattr(
        installer_module,
        "protect_current_user_secret",
        lambda value: b"protected:" + value.encode("utf-8"),
    )
    monkeypatch.setattr(
        installer_module,
        "unprotect_current_user_secret",
        lambda value: value.removeprefix(b"protected:").decode("utf-8"),
    )
    install_runtime_profile(
        profile_path=target,
        base_url="https://logistics.example.invalid",
        authority_scope="scope-current-user",
        authority_epoch=7,
        authority_plane="AUTHORITATIVE",
        plane_epoch=3,
        device_id="container-pc-user",
        source_host_id="container-host-user",
        bearer_token=token,
        credential_scope="current_user",
    )
    secret_path = target.parent / "secrets" / "bearer-token.dpapi"
    secret_before = secret_path.read_bytes()
    ca_source = tmp_path / "private-ca.cert.pem"
    ca_payload = _private_ca_pem()
    ca_source.write_bytes(ca_payload)

    report = install_tls_ca_bundle_for_existing_profile(
        profile_path=target,
        tls_ca_bundle_path=ca_source,
        credential_scope="current_user",
    )

    ca_target = target.parent / "tls" / "ca-bundle.pem"
    profile = json.loads(target.read_text(encoding="utf-8"))
    assert report["status"] == "upgraded"
    assert profile["tls_ca_bundle_path"] == str(ca_target.resolve())
    assert ca_target.read_bytes() == ca_payload
    assert secret_path.read_bytes() == secret_before


def _recovery_machine_bundle(*, logistics_token, manifest_hash="a" * 64):
    producer_id = "container-producer-recovery"
    install_id = "container-install-recovery"
    source_host_id = "container-host-recovery"
    device_id = "container-device-recovery"
    endpoint_url = "https://worker.example.invalid/api/producer-ingest/v1/source-file"
    producer_secret = "producer-secret-recovery"
    key_id = "producer-key-recovery"
    return {
        "producer_id": producer_id,
        "producer_install_id": install_id,
        "source_host_id": source_host_id,
        "endpoint_url": endpoint_url,
        "key_id": key_id,
        "secret": producer_secret,
        "active_manifest_hashes": [manifest_hash],
        "machine_credential_bundle": {
            "contract_version": (
                installer_module.MACHINE_CREDENTIAL_BUNDLE_CONTRACT_VERSION
            ),
            "bindings": {
                "app": "ContainerAudit",
                "program": "Container_Audit",
                "source_host_id": source_host_id,
                "device_id": device_id,
                "authority_scope_id": "scope-recovery",
            },
            "credentials": {
                "producer_ingest": {
                    "audience": "producer-ingest-hmac-v1",
                    "auth_scheme": "hmac-sha256",
                    "key_id": key_id,
                    "secret": producer_secret,
                },
                "logistics": {
                    "audience": "worker-analysis-logistics-v1",
                    "auth_scheme": "bearer",
                    "token_header": "X-Logistics-API-Token",
                    "token": logistics_token,
                },
            },
            "profiles": {
                "logistics": {
                    "contract_version": installer_module.PROFILE_CONTRACT_VERSION,
                    "base_url": "https://logistics.example.invalid",
                    "authority_scope": "scope-recovery",
                    "authority_epoch": 7,
                    "authority_plane": "AUTHORITATIVE",
                    "ledger_plane": "AUTHORITATIVE",
                    "plane_epoch": 3,
                    "device_id": device_id,
                    "source_host_id": source_host_id,
                    "timeout_seconds": 10,
                }
            },
        },
    }


def _install_recovery_profile_fixture(tmp_path, monkeypatch, *, token="OLD-TOKEN"):
    target = tmp_path / "profiles" / "Container_Audit" / "runtime-profile.json"
    monkeypatch.setattr(
        installer_module,
        "protect_current_user_secret",
        lambda value: b"protected:" + value.encode("utf-8"),
    )
    monkeypatch.setattr(
        installer_module,
        "unprotect_current_user_secret",
        lambda value: value.removeprefix(b"protected:").decode("utf-8"),
    )
    install_runtime_profile(
        profile_path=target,
        base_url="https://logistics.example.invalid",
        authority_scope="scope-recovery",
        authority_epoch=7,
        authority_plane="AUTHORITATIVE",
        ledger_plane="AUTHORITATIVE",
        plane_epoch=3,
        device_id="container-device-recovery",
        source_host_id="container-host-recovery",
        bearer_token=token,
        timeout_seconds=10.0,
        credential_scope="current_user",
    )
    return target


def test_recovery_bundle_rotates_only_current_user_token_and_preserves_profile(
    tmp_path,
    monkeypatch,
):
    target = _install_recovery_profile_fixture(tmp_path, monkeypatch)
    profile_before = target.read_bytes()
    response = _recovery_machine_bundle(logistics_token="NEW-TOKEN")

    result = installer_module.ensure_runtime_profile_from_enrollment_bundle(
        response,
        expected_app="ContainerAudit",
        expected_program="Container_Audit",
        expected_source_host_id="container-host-recovery",
        expected_device_id="container-device-recovery",
        profile_path=target,
        credential_scope="current_user",
        allow_existing_token_rotation=True,
        expected_producer_id="container-producer-recovery",
        expected_producer_install_id="container-install-recovery",
        expected_manifest_hash="a" * 64,
        expected_endpoint_url=response["endpoint_url"],
    )

    readback = load_logistics_runtime_profile(
        required=True,
        profile_path=target,
        decryptor=installer_module.unprotect_current_user_secret,
    )
    assert result["status"] == "rotated"
    assert result["non_secret_profile_preserved"] is True
    assert target.read_bytes() == profile_before
    assert readback.bearer_token == "NEW-TOKEN"


def test_recovery_bundle_binding_mismatch_preserves_existing_profile_and_token(
    tmp_path,
    monkeypatch,
):
    target = _install_recovery_profile_fixture(tmp_path, monkeypatch)
    profile_before = target.read_bytes()
    secret_path = target.parent / "secrets" / "bearer-token.dpapi"
    secret_before = secret_path.read_bytes()
    response = _recovery_machine_bundle(logistics_token="NEW-TOKEN")

    with pytest.raises(ValueError, match="producer_id binding mismatch"):
        installer_module.ensure_runtime_profile_from_enrollment_bundle(
            response,
            expected_app="ContainerAudit",
            expected_program="Container_Audit",
            expected_source_host_id="container-host-recovery",
            expected_device_id="container-device-recovery",
            profile_path=target,
            credential_scope="current_user",
            allow_existing_token_rotation=True,
            expected_producer_id="wrong-producer",
            expected_producer_install_id="container-install-recovery",
            expected_manifest_hash="a" * 64,
            expected_endpoint_url=response["endpoint_url"],
        )

    assert target.read_bytes() == profile_before
    assert secret_path.read_bytes() == secret_before


def test_recovery_bundle_rotation_readback_failure_restores_old_token(
    tmp_path,
    monkeypatch,
):
    target = _install_recovery_profile_fixture(tmp_path, monkeypatch)
    profile_before = target.read_bytes()
    secret_path = target.parent / "secrets" / "bearer-token.dpapi"
    secret_before = secret_path.read_bytes()
    response = _recovery_machine_bundle(logistics_token="NEW-TOKEN")
    original_loader = installer_module.load_logistics_runtime_profile
    calls = {"count": 0}

    def fail_first_rotated_readback(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("simulated rotated-token readback interruption")
        return original_loader(*args, **kwargs)

    monkeypatch.setattr(
        installer_module,
        "load_logistics_runtime_profile",
        fail_first_rotated_readback,
    )

    with pytest.raises(
        RuntimeError,
        match="simulated rotated-token readback interruption",
    ):
        installer_module.ensure_runtime_profile_from_enrollment_bundle(
            response,
            expected_app="ContainerAudit",
            expected_program="Container_Audit",
            expected_source_host_id="container-host-recovery",
            expected_device_id="container-device-recovery",
            profile_path=target,
            credential_scope="current_user",
            allow_existing_token_rotation=True,
            expected_producer_id="container-producer-recovery",
            expected_producer_install_id="container-install-recovery",
            expected_manifest_hash="a" * 64,
            expected_endpoint_url=response["endpoint_url"],
        )

    assert target.read_bytes() == profile_before
    assert secret_path.read_bytes() == secret_before

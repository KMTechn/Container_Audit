import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import direct_sync_push
import isolated_qualification
import item_catalog_sync
import logistics_runtime_profile
from terminal_operation_lease import (
    OperationLeaseManager,
    OperationLeaseStore,
    PinnedOperationLeaseKeyring,
)
from tools import isolated_qualification_authority as authority
from transfer_seal import (
    transfer_operation_lease_binding,
    validate_compact_phs2_preflight,
)


ROOT = Path(__file__).resolve().parents[1]


def _initialize(monkeypatch, tmp_path):
    report_path = tmp_path / "initialize-report.json"
    operator_root = tmp_path / "operator-local-app-data"
    operator_root.mkdir()
    monkeypatch.setenv(isolated_qualification.SOURCE_TEST_MODE_ENV, "1")
    monkeypatch.setenv("COMPUTERNAME", "QUALIFICATION-TEST-HOST")
    suffix = hashlib.sha256(str(tmp_path).encode("utf-8")).hexdigest()[:8]
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path.parent / f"pd-{suffix}"))
    state_root = isolated_qualification.default_state_root()
    result = authority.initialize_authority(
        state_root=state_root,
        operator_user_sid="S-1-5-21-100-200-300-504",
        operator_local_app_data_root=str(operator_root),
        port=18470,
        report_path=report_path,
    )
    return state_root, report_path, result


def _profile_values(base_url):
    return {
        "contract_version": logistics_runtime_profile.PROFILE_CONTRACT_VERSION,
        "bearer_token_ref": logistics_runtime_profile.DEFAULT_TOKEN_REF,
        "base_url": base_url,
        "source_host_id": "qualification-source",
        "device_id": "QUALIFICATION-PC",
        "authority_scope": authority.QUALIFICATION_SCOPE,
        "authority_epoch": 1,
        "authority_plane": "AUTHORITATIVE",
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 1,
        "timeout_seconds": 10,
    }


def test_source_escape_hatch_is_explicit_source_only_and_never_frozen(monkeypatch, tmp_path):
    state_root = tmp_path / "qualification-authority"
    operator_root = tmp_path / "operator-local-app-data"
    operator_root.mkdir()
    monkeypatch.setenv(isolated_qualification.SOURCE_TEST_MODE_ENV, "1")

    assert isolated_qualification.assert_windows_sandbox_operator_context(
        operator_user_sid="not-a-sandbox-sid",
        operator_local_app_data_root=str(operator_root),
        state_root=state_root,
    ) is True

    monkeypatch.setattr(isolated_qualification.sys, "frozen", True, raising=False)
    with pytest.raises(
        isolated_qualification.IsolatedQualificationError,
        match="Windows Sandbox|canonical",
    ):
        isolated_qualification.assert_windows_sandbox_operator_context(
            operator_user_sid="S-1-5-21-100-200-300-504",
            operator_local_app_data_root=str(operator_root),
            state_root=state_root,
        )


def test_runtime_generated_context_is_loopback_only_secret_free_and_bound(monkeypatch, tmp_path):
    state_root, report_path, result = _initialize(monkeypatch, tmp_path)

    assert result["status"] == "INITIALIZED"
    assert result["source_test_mode"] is True
    assert result["loopback_only"] is True
    assert result["production_write_enabled"] is False
    assert result["committed_secret_present"] is False
    assert result["private_values_in_report"] is False
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert not ({"producer_secret", "logistics_token"} & set(report))

    context_path = state_root / isolated_qualification.CONTEXT_FILENAME
    context = isolated_qualification.load_isolated_qualification_context(context_path)
    assert context.server_base_url == "https://127.0.0.1:18470"
    assert context.endpoint_url == (
        "https://127.0.0.1:18470/api/producer-ingest/v1/source-file"
    )
    assert Path(context.ca_bundle_path).is_file()
    with pytest.raises(
        isolated_qualification.IsolatedQualificationError,
        match="differs from the requested",
    ):
        isolated_qualification.load_isolated_qualification_context(
            context_path,
            expected_endpoint_url=(
                "https://127.0.0.1:18471/api/producer-ingest/v1/source-file"
            ),
        )

    private = json.loads(
        (state_root / authority.PRIVATE_STATE_FILENAME).read_text(encoding="utf-8")
    )
    assert set(private) == authority._expected_private_fields()
    assert private["enrolled_producer_id"] == ""
    assert private["enrolled_producer_install_id"] == ""


def test_production_endpoint_guard_still_rejects_loopback_without_context():
    with pytest.raises(direct_sync_push.DirectSyncPushError, match="loopback"):
        direct_sync_push.validate_endpoint_url(
            "https://127.0.0.1:18470/api/producer-ingest/v1/source-file"
        )


def test_logistics_loopback_requires_exact_context_and_private_ca(monkeypatch, tmp_path):
    state_root, _report_path, result = _initialize(monkeypatch, tmp_path)
    context_path = state_root / isolated_qualification.CONTEXT_FILENAME
    context = isolated_qualification.load_isolated_qualification_context(context_path)

    profile = logistics_runtime_profile.profile_from_values(
        _profile_values(context.server_base_url),
        profile_path=tmp_path / "runtime-profile.json",
        bearer_token="runtime-only-test-token",
        required=True,
    )
    assert profile.isolated_qualification_authority_id == result["authority_instance_id"]
    assert profile.tls_ca_bundle_path == context.ca_bundle_path
    assert profile.redacted_summary()["tls_private_ca_configured"] is True
    catalog_url = f"{context.server_base_url}{item_catalog_sync.CATALOG_PATH}"
    assert item_catalog_sync._is_trusted_authenticated_catalog_url(catalog_url, profile)
    assert not item_catalog_sync._is_trusted_authenticated_catalog_url(
        f"{context.server_base_url}/not-the-catalog", profile
    )

    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "different-program-data"))
    with pytest.raises(
        logistics_runtime_profile.LogisticsRuntimeConfigurationError,
        match="valid isolated qualification context",
    ):
        logistics_runtime_profile.profile_from_values(
            _profile_values(context.server_base_url),
            profile_path=tmp_path / "other-runtime-profile.json",
            bearer_token="runtime-only-test-token",
            required=True,
        )


def test_packaged_operator_fixture_and_signed_lease_pass_real_client_validation(tmp_path):
    fields = {
        "PHS": "2",
        "SRC": "KMTECH_INPUT_TAG",
        "ITG": authority.QUALIFICATION_INPUT_TAG,
        "CLC": authority.QUALIFICATION_ITEM_CODE,
        "LBL": authority.QUALIFICATION_WORK_LABEL,
        "HSH": authority.QUALIFICATION_ACTIVE_LABEL_HASH[:16],
    }
    preflight = validate_compact_phs2_preflight(fields, authority._build_snapshot())

    assert preflight.item_id == authority.QUALIFICATION_ITEM_CODE
    assert preflight.member_count == 2
    assert preflight.normalized_barcodes == authority.QUALIFICATION_PRODUCT_BARCODES
    assert preflight.active_label_qr_payload == authority.QUALIFICATION_MASTER_QR

    client = SimpleNamespace(
        device_id="QUALIFICATION-PC",
        source_host_id="qualification-source",
    )
    snapshot = authority._build_snapshot()
    artifact = authority._operation_lease_artifact(
        snapshot=snapshot,
        scan_payload=authority.QUALIFICATION_MASTER_QR,
        device_id=client.device_id,
        source_host_id=client.source_host_id,
        lease_key=ec.generate_private_key(ec.SECP256R1()),
    )
    binding = transfer_operation_lease_binding(
        client=client,
        scan_payload=authority.QUALIFICATION_MASTER_QR,
        preflight=preflight,
        operation_snapshot=snapshot,
        site_id=authority.QUALIFICATION_SITE,
    )
    manager = OperationLeaseManager(
        OperationLeaseStore(tmp_path / "operation-lease.db"),
        PinnedOperationLeaseKeyring(tmp_path / "operation-lease-keyring.json"),
    )
    issue_request = {
        "authority_scope_id": authority.QUALIFICATION_SCOPE,
        "operation": authority.TRANSFER_OPERATION,
        "scan_payload": authority.QUALIFICATION_MASTER_QR,
    }
    issue_key = manager.issue_idempotency_key(
        device_id=client.device_id,
        source_host_id=client.source_host_id,
        authority_scope_id=authority.QUALIFICATION_SCOPE,
        scan_payload=authority.QUALIFICATION_MASTER_QR,
        explicit_new=True,
    )
    normalized, claims = manager.accept_authenticated(
        artifact=artifact,
        expected=binding,
        issue_request=issue_request,
        issue_idempotency_key=issue_key,
    )
    assert normalized["status"] == "ACTIVE"
    assert claims["quantity"] == 2
    assert claims["item_id"] == authority.QUALIFICATION_ITEM_CODE


def test_release_package_and_installer_own_qualification_authority():
    required = __import__("update_service").REQUIRED_UPDATE_ARCHIVE_FILES
    assert {
        "Container_Audit/Container_Audit_Qualification_Authority.exe",
        "Container_Audit/tools/isolated_qualification_authority.py",
        "Container_Audit/isolated_qualification.py",
    } <= required

    builder = (ROOT / "tools" / "build_frozen_release_candidate.ps1").read_text(
        encoding="utf-8"
    )
    installer = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")
    assert '"Container_Audit_Qualification_Authority"' in builder
    assert '"tools/isolated_qualification_authority.py"' in builder
    assert "EnableWindowsSandboxQualification" in installer
    assert "Windows Sandbox qualification cannot be combined with a ServerBaseUrl override." in installer
    assert "container-audit-isolated-qualification-authority" in installer
    assert "qualification_authority_process_status=ABSENT" in installer
    assert "qualification_authority_task_status=ABSENT" in installer
    assert '"*S-1-5-32-545:RX"' in installer
    assert '"*S-1-5-32-545:(OI)(CI)RX"' not in installer
    assert '"*S-1-5-32-545:R"' in installer


def test_untrusted_profile_marker_cannot_broaden_catalog_origin():
    fake_profile = SimpleNamespace(
        isolated_qualification_authority_id="qualification-" + ("a" * 32),
        base_url="https://127.0.0.1:18470",
    )
    assert not item_catalog_sync._is_trusted_authenticated_catalog_url(
        "https://127.0.0.1:18471/inbound/api/item-catalog.csv",
        fake_profile,
    )

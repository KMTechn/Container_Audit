from pathlib import Path
import subprocess

import pytest
import update_service
from tools import install_logistics_runtime_profile as machine_profiles


ROOT = Path(__file__).resolve().parents[1]


def _assert_powershell_ast(path: Path) -> None:
    escaped = str(path).replace("'", "''")
    command = (
        "$tokens=$null;$errors=$null;"
        f"[void][System.Management.Automation.Language.Parser]::ParseFile('{escaped}',[ref]$tokens,[ref]$errors);"
        "if($errors.Count){$errors|ForEach-Object{$_.Message}|Write-Error;exit 1}"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )


def _machine_bundle():
    return {
        "key_id": "container-producer-key-1",
        "secret": "container-producer-secret-1",
        "machine_credential_bundle": {
            "contract_version": "producer-self-enrollment-machine-credentials-v1",
            "bindings": {
                "app": "ContainerAudit",
                "program": "Container_Audit",
                "source_host_id": "container-host-1",
                "device_id": "CONTAINER-PC-1",
                "authority_scope_id": "PROD-SCOPE",
            },
            "credentials": {
                "producer_ingest": {
                    "audience": "producer-ingest-hmac-v1",
                    "auth_scheme": "hmac-sha256",
                    "key_id": "container-producer-key-1",
                    "secret": "container-producer-secret-1",
                },
                "logistics": {
                    "audience": "worker-analysis-logistics-v1",
                    "auth_scheme": "bearer",
                    "token_header": "X-Logistics-API-Token",
                    "token": "kmta1.container-secret",
                }
            },
            "profiles": {
                "logistics": {
                    "contract_version": "km-logistics-runtime-profile-v1",
                    "base_url": "https://worker.kmtecherp.com",
                    "authority_scope": "PROD-SCOPE",
                    "authority_epoch": 7,
                    "authority_plane": "AUTHORITATIVE",
                    "ledger_plane": "AUTHORITATIVE",
                    "plane_epoch": 3,
                    "device_id": "CONTAINER-PC-1",
                    "source_host_id": "container-host-1",
                    "timeout_seconds": 10,
                }
            },
        }
    }


def test_package_installer_uses_tokenless_self_enrollment_and_system_task():
    text = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")

    assert "#Requires -RunAsAdministrator" not in text
    assert "Invoke-SelfElevated $MyInvocation.MyCommand.Path $PSBoundParameters $args" in text
    assert "WindowsBuiltInRole]::Administrator" in text
    assert "-Verb RunAs" in text
    assert "-Wait -PassThru" in text
    _assert_powershell_ast(ROOT / "INSTALL_THIS_PC.ps1")
    assert "--self-enroll" in text
    assert "--enrollment-token-env" in text
    assert "Read-Host" not in text
    assert "ExistingProducerManifestPath" in text
    assert "ExistingCredentialPath" in text
    assert "ExistingRegistrationReportPath" in text
    assert "ProducerIdentityPath" in text
    assert "ProducerInstallId" in text
    assert "--producer-identity-path" in text
    assert "--producer-install-id" in text
    assert "--producer-id" in text
    assert "--source-host-id" in text
    assert "Producer identity seed file does not exist." in text
    assert "--verify-manifest-hash" in text
    assert "Existing producer manifest differs from its verified registration report." in text
    assert "Get-FileHash" not in text
    assert "--enrollment-token `" not in text
    assert "machine-scope DPAPI" in text
    assert "system_service_account" in text
    assert 'run_user -cne "SYSTEM"' in text
    assert "--task-run-user" not in text
    assert "TaskRunPassword" not in text
    assert "Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop" in text
    assert "Remove-NewMachineProfilesFromRegistrationReport" in text
    assert r'KMTech\Logistics\profiles\Container_Audit' in text
    assert "created_paths" in text
    assert "Unregister-ScheduledTask -TaskName $TaskName" in text
    assert "persisted_manifest_hash_verified" in text
    assert "runtime.manifest_hash" in text
    assert "AuthorizedManifestHash" in text
    assert "Wait-CurrentRuntimeLease" in text
    assert 'lease.status -ceq "ACTIVE"' in text
    assert "lease.server_grant_accepted" in text
    assert "lease.producer_install_id" in text
    assert "lease.runtime_instance_id" in text
    assert "lease.lease_id" in text
    assert "lease.expires_at" in text
    assert "Wait-CleanAcceptedReceipt" not in text
    assert "APPLIED_UNPROVEN" in text
    assert '"C:\\KMTech\\Apps\\Container_Audit\\current"' in text
    assert '"C:\\ProgramData\\KMTech\\DirectSync\\container_audit"' in text
    assert '"bin\\direct-sync-relay-container-audit.vbs"' in text
    assert '"queue\\direct_sync_relay.sqlite3"' in text
    assert "field_layout_contract" in text
    assert "production_layout_matches" in text
    assert "AllowNoncanonicalLayoutForTest" in text
    assert "--allow-noncanonical-layout-for-test" in text
    assert "KMTECH_FACTORY_INSTALL_TEST_MODE" in text


def test_package_installer_has_honest_uninstall_and_confirmed_pristine_rollback():
    text = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")

    assert "PurgeContainerAuditState" in text
    assert "ConfirmPermanentContainerAuditDataRemoval" in text
    assert "RollbackReportPath" in text
    assert "Destructive rollback requires -ConfirmPermanentContainerAuditDataRemoval." in text
    assert "Destructive rollback requires an external -RollbackReportPath." in text
    assert "uninstall_status=PASS_DATA_PRESERVED" in text
    assert "data_preserved=true" in text
    assert "install_status=UNINSTALLED" not in text
    assert "rollback_status=PASS" in text
    assert "Test-RollbackPostconditions" in text
    assert 'status = if ($remaining.Count -eq 0) { "PASS" } else { "FAIL" }' in text
    assert "contains_credential_content = $false" in text

    inventory = text[text.index("$rollbackInventory = @(") : text.index("if ($DryRun.IsPresent)")]
    ordered_markers = [
        'order = 1; kind = "scheduled_task"; name = $qualificationAuthorityTaskName',
        'order = 2; kind = "scheduled_task"; name = $expectedTaskName',
        'order = 3; kind = "shortcut"',
        'order = 4; kind = "directory"; path = $expectedLogisticsProfileRoot',
        'order = 5; kind = "directory"; path = $expectedDirectSyncRoot',
        'order = 6; kind = "directory"; path = $expectedOperatorDataRoot',
        'order = 7; kind = "directory"; path = $expectedOperatorCatalogRoot',
        'order = 8; kind = "directory"; path = $expectedUpdateBackupRoot',
        'order = 9; kind = "directory"; path = $expectedUpdateEvidenceRoot',
        'order = 10; kind = "directory"; path = $expectedInstallRoot',
    ]
    positions = [inventory.index(marker) for marker in ordered_markers]
    assert positions == sorted(positions)
    assert "application_root_is_last" in text
    apply_block = text[
        text.index("[void]$rollbackResults.Add((Remove-OwnedQualificationAuthorityTask") :
        text.index("$rollbackReport.parent_cleanup")
    ]
    apply_markers = [
        "Remove-OwnedQualificationAuthorityTask",
        "Remove-OwnedScheduledTask",
        "Remove-OwnedShortcut",
        "Remove-ExactOwnedTree $expectedLogisticsProfileRoot",
        "Remove-ExactOwnedTree $expectedDirectSyncRoot",
        "Remove-ExactOwnedTree $expectedOperatorDataRoot",
        "Remove-ExactOwnedTree $expectedOperatorCatalogRoot",
        "Remove-ExactOwnedTree $expectedUpdateBackupRoot",
        "Remove-ExactOwnedTree $expectedUpdateEvidenceRoot",
        "Remove-ExactOwnedTree $expectedInstallRoot",
    ]
    apply_positions = [apply_block.index(marker) for marker in apply_markers]
    assert apply_positions == sorted(apply_positions)


def test_package_installer_guards_exact_owned_rollback_boundaries():
    text = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")

    assert "Get-StrictFullPath" in text
    assert "Assert-ExactCanonicalPath" in text
    assert "Assert-NoReparsePoint" in text
    assert "FileAttributes]::ReparsePoint" in text
    assert "must not be a filesystem root" in text
    assert "must not contain traversal segments" in text
    assert "must not contain an alternate data stream" in text
    assert "Assert-ApplicationParentInventory" in text
    assert "contains a foreign child" in text
    assert "Assert-DirectSyncOwnership" in text
    assert "Assert-NoOwnedProcess" in text
    assert "Get-OwnedScheduledTaskState" in text
    assert "A conflicting scheduled task exists" in text
    assert "Get-OwnedShortcutState" in text
    assert "A conflicting Start Menu shortcut exists" in text
    assert "Assert-ExternalRollbackReportPath" in text
    assert "outside every deletion target" in text
    assert "fresh absent external file" in text
    assert 'Remove-Item -LiteralPath "C:\\ProgramData\\KMTech"' not in text
    assert 'Remove-Item -LiteralPath "C:\\KMTech\\Apps"' not in text
    assert 'Remove-Item -LiteralPath $OperatorLocalAppDataRoot -Recurse' not in text


def test_package_installer_creates_owned_all_users_shortcut_and_reports_pending_launch():
    text = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")

    assert "SpecialFolder]::CommonPrograms" in text
    assert "Get-ContainerAuditShortcutName" in text
    assert "[char]0xC774" in text
    assert "[char]0xC801" in text
    assert "[char]0xAC80" in text
    assert "[char]0xC0AC" in text
    assert "[char]0xC2DC" in text
    assert "[char]0xC2A4" in text
    assert "[char]0xD15C" in text
    assert "Install-OwnedShortcut" in text
    assert "Remove-OwnedShortcut" in text
    assert '$shortcut.TargetPath = $ExpectedTarget' in text
    assert '$shortcut.WorkingDirectory = $ExpectedWorkingDirectory' in text
    assert '$shortcut.Arguments = ""' in text
    assert '$shortcut.IconLocation = "$ExpectedTarget,0"' in text
    assert "Desktop" not in text
    assert "operator_readiness_status=PENDING_FIRST_LAUNCH" in text
    assert "first_launch_catalog_status=NOT_TESTED" in text
    assert "operator_catalog_cache_path=$operatorCatalogCachePath" in text
    assert text.rindex("Wait-CurrentRuntimeLease $relayStarted") < text.rindex(
        "Install-OwnedShortcut $expectedShortcutPath"
    )


def test_package_installer_captures_operator_identity_before_elevation_without_acl_change():
    text = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")

    capture = text.index("$currentOperator = Get-CurrentOperatorContext")
    elevation = text.index(
        "Invoke-SelfElevated $MyInvocation.MyCommand.Path $PSBoundParameters $args"
    )
    assert capture < elevation
    assert '$PSBoundParameters["OperatorUserSid"]' in text
    assert '$PSBoundParameters["OperatorLocalAppDataRoot"]' in text
    assert "Assert-OperatorContext" in text
    assert "ProfileList\\$Sid" in text
    assert '$DataRoot = Join-Path $OperatorLocalAppDataRoot "KMTech\\ContainerAudit"' in text
    assert "icacls" not in text[:elevation].lower()
    assert "Set-Acl" not in text


def test_frozen_release_requires_common_installer_entrypoint():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    verifier = (ROOT / "tools" / "verify_frozen_release_artifact.py").read_text(
        encoding="utf-8"
    )

    assert "PyInstaller" not in workflow
    assert "safe_extract_update_zip" in verifier
    assert "Container_Audit/INSTALL_THIS_PC.ps1" in update_service.REQUIRED_UPDATE_ARCHIVE_FILES


def test_enrollment_bundle_installs_strict_machine_profile_without_logging_token(monkeypatch, tmp_path):
    observed = {}
    monkeypatch.setattr(
        machine_profiles,
        "install_runtime_profile",
        lambda **kwargs: observed.update(kwargs) or {"status": "installed", "created_paths": []},
    )

    result = machine_profiles.ensure_runtime_profile_from_enrollment_bundle(
        _machine_bundle(),
        expected_app="ContainerAudit",
        expected_program="Container_Audit",
        expected_source_host_id="container-host-1",
        expected_device_id="CONTAINER-PC-1",
        profile_path=tmp_path / "runtime-profile.json",
    )

    assert result == {"status": "installed", "created_paths": []}
    assert observed["bearer_token"] == "kmta1.container-secret"
    assert "kmta1.container-secret" not in str(result)
    invalid = _machine_bundle()
    invalid["machine_credential_bundle"]["profiles"]["logistics"]["unexpected"] = True
    with pytest.raises(ValueError, match="profile fields"):
        machine_profiles.ensure_runtime_profile_from_enrollment_bundle(
            invalid,
            expected_app="ContainerAudit",
            expected_program="Container_Audit",
            expected_source_host_id="container-host-1",
            expected_device_id="CONTAINER-PC-1",
            profile_path=tmp_path / "other.json",
        )


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("bundle_extra", "bundle fields"),
        ("bindings_extra", "binding fields"),
        ("profiles_extra", "profile sections"),
        ("credentials_extra", "credential sections"),
        ("producer_extra", "producer ingest credential fields"),
        ("producer_contract", "producer ingest credential contract"),
        ("producer_key_mismatch", "producer ingest credential contract"),
        ("producer_secret_mismatch", "producer ingest credential contract"),
        ("logistics_extra", "logistics credential fields"),
        ("logistics_contract", "logistics credential contract"),
        ("shared_secret", "distinct secrets"),
    ],
)
def test_enrollment_bundle_rejects_nonfinal_server_shapes(
    monkeypatch, tmp_path, case, message
):
    invalid = _machine_bundle()
    bundle = invalid["machine_credential_bundle"]
    producer = bundle["credentials"]["producer_ingest"]
    logistics = bundle["credentials"]["logistics"]
    if case == "bundle_extra":
        bundle["unexpected"] = True
    elif case == "bindings_extra":
        bundle["bindings"]["unexpected"] = True
    elif case == "profiles_extra":
        bundle["profiles"]["unexpected"] = {}
    elif case == "credentials_extra":
        bundle["credentials"]["unexpected"] = {}
    elif case == "producer_extra":
        producer["unexpected"] = True
    elif case == "producer_contract":
        producer["auth_scheme"] = "bearer"
    elif case == "producer_key_mismatch":
        producer["key_id"] = "other-key"
    elif case == "producer_secret_mismatch":
        producer["secret"] = "other-secret"
    elif case == "logistics_extra":
        logistics["unexpected"] = True
    elif case == "logistics_contract":
        logistics["token_header"] = "Authorization"
    elif case == "shared_secret":
        logistics["token"] = invalid["secret"]
    monkeypatch.setattr(
        machine_profiles,
        "install_runtime_profile",
        lambda **_kwargs: pytest.fail("invalid bundle reached profile installer"),
    )
    with pytest.raises(ValueError, match=message):
        machine_profiles.ensure_runtime_profile_from_enrollment_bundle(
            invalid,
            expected_app="ContainerAudit",
            expected_program="Container_Audit",
            expected_source_host_id="container-host-1",
            expected_device_id="CONTAINER-PC-1",
            profile_path=tmp_path / f"{case}.json",
        )

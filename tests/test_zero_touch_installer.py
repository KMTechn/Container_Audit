from pathlib import Path
import json
import os
import re
import subprocess

import pytest
import update_service
from direct_sync_push import manifest_hash
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


def _run_installer_functions(function_names, body, *, cwd=None, env=None):
    installer = str(ROOT / "INSTALL_THIS_PC.ps1").replace("'", "''")
    names = ",".join(f"'{name}'" for name in function_names)
    command = (
        "$tokens=$null;$errors=$null;"
        f"$ast=[System.Management.Automation.Language.Parser]::ParseFile('{installer}',[ref]$tokens,[ref]$errors);"
        "if($errors.Count){throw 'installer parse failed'};"
        f"foreach($name in @({names})){{"
        "$definition=$ast.Find({param($node) "
        "$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -ceq $name},$true);"
        "if($null -eq $definition){throw \"missing function: $name\"};"
        "Invoke-Expression $definition.Extent.Text};"
        + body
    )
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
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
    assert "Invoke-ContainerAuditWorkerPcRegistration" in text
    assert "SELF_ENROLLMENT_REGISTERED" in text
    assert "GetEnvironmentVariable($EnrollmentTokenEnv, 'Process')" in text
    assert "Read-Host" not in text
    assert "ExistingProducerManifestPath" in text
    assert "ExistingCredentialPath" in text
    assert "ExistingRegistrationReportPath" in text
    assert "ProducerIdentityPath" in text
    assert "ProducerInstallId" in text
    assert "Producer identity seed file does not exist." in text
    assert "Assert-ContainerAuditManifestHash" in text
    assert "Existing producer manifest differs from its verified registration report." in text
    assert not re.search(r"(?mi)^\s*&\s+\$(?:installExe|InstallExecutable)\b", text)
    assert "$registrationExe" not in text
    assert "Container_Audit_Worker_PC_Register.exe" not in text
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
    assert '"bin\\direct-sync-relay-container-audit.cmd"' in text
    assert "wscript.exe" not in text
    assert '"cmd.exe"' in text
    assert "/d /q /c $ExpectedLauncherPath" in text
    assert '"queue\\direct_sync_relay.sqlite3"' in text
    assert "field_layout_contract" in text
    assert "production_layout_matches" in text
    assert "AllowNoncanonicalLayoutForTest" in text
    assert "local_test_override_enabled" in text
    assert "KMTECH_FACTORY_INSTALL_TEST_MODE" in text


def test_public_installer_has_no_direct_packaged_boundary_a_helper_invocations():
    installer_path = ROOT / "INSTALL_THIS_PC.ps1"
    escaped = str(installer_path).replace("'", "''")
    command = (
        "$tokens=$null;$errors=$null;"
        f"$ast=[System.Management.Automation.Language.Parser]::ParseFile('{escaped}',[ref]$tokens,[ref]$errors);"
        "if($errors.Count){$errors|ForEach-Object{$_.Message}|Write-Error;exit 1};"
        "$direct=@($ast.FindAll({param($node) "
        "$node -is [System.Management.Automation.Language.CommandAst] -and "
        "$node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand -and "
        "$node.CommandElements.Count -gt 0 -and "
        "$node.CommandElements[0] -is [System.Management.Automation.Language.VariableExpressionAst] -and "
        "@('installExe','InstallExecutable') -ccontains $node.CommandElements[0].VariablePath.UserPath"
        "},$true));"
        "if($direct.Count){$direct|ForEach-Object{$_.Extent.Text}|Write-Error;exit 2};exit 0"
    )
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    text = installer_path.read_text(encoding="utf-8")
    assert "Invoke-ContainerAuditWorkerPcRegistration" in text
    assert "Assert-ContainerAuditManifestHash" in text
    assert "Install-ContainerAuditDirectSyncTask" in text
    assert "Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction Stop" in text
    assert "Register-ScheduledTask `" in text
    assert "-LogonType ServiceAccount" in text
    assert "-RunLevel Highest" in text
    assert "-MultipleInstances IgnoreNew" in text
    assert "-RepetitionInterval (New-TimeSpan -Minutes 1)" in text

    native_apply = text[
        text.index("function Install-ContainerAuditDirectSyncTask") :
        text.index("function Test-SamePath")
    ]
    for required in (
        "--db-path",
        "--spool-dir",
        "--producer-manifest-path",
        "--credential-path",
        "--upload-status-dir",
        "--runtime-status-path",
        "--log-path",
        "--operator-pause-path",
        "--min-free-bytes",
        "--max-active-queue-count",
        "--max-active-queue-age-seconds",
        "--require-runtime-lease-before-scan",
        "--scan-source-dir",
        "--source-glob",
        "--min-source-file-age-seconds",
        "--drain-after-scan",
    ):
        assert required in native_apply
    assert "Container_Audit_DirectSync_Relay.exe" in native_apply
    assert "Write-AtomicUtf8JsonFile $ReportPath $report" in native_apply
    assert native_apply.index("$report.status = 'APPLYING'") < native_apply.index(
        "Write-AtomicFileBytes $launcherPath $wrapperBytes"
    ) < native_apply.index("Register-ScheduledTask `")
    assert "Start-ScheduledTask" not in native_apply
    assert "execution_mode = 'in_process_native_powershell'" in native_apply

    boundary_b = text[text.index("$relayStarted = (Get-Date).ToUniversalTime()") :]
    assert "Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop" in boundary_b
    assert "Wait-CurrentRuntimeLease $relayStarted $DirectSyncRoot $authorizedManifestHash" in boundary_b
    assert 'lease.status -ceq "ACTIVE"' in text
    assert "lease.server_grant_accepted" in text
    assert "lease.runtime_instance_id" in text
    assert "lease.lease_id" in text


def test_native_manifest_hash_matches_python_and_rejects_duplicate_keys(tmp_path):
    payload = {
        "z": [True, None, 7, "quote=\" slash=\\ newline=\n"],
        "a": {
            "format": "<source_host_id>/<producer_role>",
            "unicode": "e\u0301 한글 😀",
        },
    }
    source = tmp_path / "manifest.json"
    source.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"a":1,"\\u0061":2}\n', encoding="utf-8")
    source_ps = str(source).replace("'", "''")
    duplicate_ps = str(duplicate).replace("'", "''")
    body = (
        f"try{{[void](Read-BoundedJson '{duplicate_ps}' 'duplicate fixture');"
        "Write-Error 'duplicate key was accepted';exit 61}"
        "catch{if($_.Exception.Message -notlike '*duplicate JSON key*'){Write-Error $_;exit 62}};"
        f"$payload=Read-BoundedJson '{source_ps}' 'canonical fixture';"
        "$hash=Get-CanonicalJsonSha256 $payload;[Console]::Out.Write($hash);exit 0"
    )
    completed = _run_installer_functions(
        [
            "Read-BoundedJson",
            "ConvertTo-PythonJsonString",
            "ConvertTo-PythonCanonicalJson",
            "Assert-JsonHasNoDuplicateObjectKeys",
            "Get-CanonicalJsonSha256",
        ],
        body,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert completed.stdout.strip() == manifest_hash(payload)


def test_native_public_endpoint_policy_rejects_local_and_private_addresses():
    body = (
        "$blocked=@("
        "'https://127.0.0.1/api/producer-ingest/v1/source-file',"
        "'https://10.0.0.7/api/producer-ingest/v1/source-file',"
        "'https://[::1]/api/producer-ingest/v1/source-file');"
        "foreach($endpoint in $blocked){try{Assert-ContainerAuditPublicEndpoint $endpoint;exit 81}catch{}};"
        "Assert-ContainerAuditPublicEndpoint 'https://8.8.8.8/api/producer-ingest/v1/source-file';exit 0"
    )
    completed = _run_installer_functions(
        [
            "Test-ContainerAuditUnsafeEndpointAddress",
            "Assert-ContainerAuditPublicEndpoint",
        ],
        body,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_shared_owned_task_removal_executes_in_process_and_reports_transitions(tmp_path):
    report_path = tmp_path / "install-report.json"
    report_ps = str(report_path).replace("'", "''")
    body = (
        "$script:removed=$false;$script:stopCalls=0;$script:statuses=@();"
        "function Get-OwnedScheduledTaskState{param($Name,$ExpectedLauncherPath)"
        "[ordered]@{status='OWNED';task_name=$Name}};"
        "function Stop-ScheduledTask{[CmdletBinding()]param([string]$TaskName)"
        "$script:stopCalls+=1};"
        "function Unregister-ScheduledTask{[CmdletBinding(SupportsShouldProcess=$true)]param([string]$TaskName)"
        "$script:removed=$true};"
        "function Get-ScheduledTask{[CmdletBinding()]param([string]$TaskName)"
        "if($script:removed){return @()};return [pscustomobject]@{TaskName=$TaskName}};"
        "function Write-AtomicUtf8JsonFile{param($Path,$Payload)"
        "$script:statuses+=@([string]$Payload.status);"
        "$json=$Payload|ConvertTo-Json -Depth 20;"
        "[IO.File]::WriteAllText($Path,$json,(New-Object System.Text.UTF8Encoding($false)))};"
        f"$result=Remove-OwnedScheduledTask 'direct-sync-relay-container-audit' "
        f"'C:\\ProgramData\\KMTech\\DirectSync\\container_audit\\bin\\direct-sync-relay-container-audit.cmd' "
        f"'C:\\KMTech\\Apps\\Container_Audit\\current' "
        f"'C:\\ProgramData\\KMTech\\DirectSync\\container_audit' '{report_ps}';"
        "if($result.status -cne 'ABSENT' -or -not $script:removed -or $script:stopCalls -ne 1){exit 71};"
        "if(($script:statuses -join ',') -cne 'APPLYING,PASS'){exit 72};exit 0"
    )
    completed = _run_installer_functions(["Remove-OwnedScheduledTask"], body)

    assert completed.returncode == 0, completed.stderr or completed.stdout
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "PASS"
    assert report["scheduled_task_delete"]["postcondition"] == "ABSENT"
    assert report["execution_mode"] == "in_process_native_powershell"
    assert report["installer_process_id"] > 0


def test_nonproduction_server_and_test_identity_override_is_documented():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    installer = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")
    bootstrap = (ROOT / "direct_sync_auto_bootstrap.py").read_text(encoding="utf-8")
    heading = "### 격리 비프로덕션 서버 설치/실행 오버라이드"

    assert heading in readme
    section = readme[readme.index(heading) :]
    next_heading = section.find("\n## ", 1)
    if next_heading >= 0:
        section = section[:next_heading]

    for marker in (
        "$NonProductionServerBaseUrl",
        "$TestProducerIdentityPath",
        "-ServerBaseUrl",
        "-ProducerIdentityPath",
        "-SourceHostId",
        "-ProducerInstallId",
        "-ProducerId",
        "CONTAINER_AUDIT_DIRECT_SYNC_BOOTSTRAP",
        "CONTAINER_AUDIT_DIRECT_SYNC_SERVER_BASE_URL",
        "producer_manifest.json",
        "credential.json",
    ):
        assert marker in section
    assert "https://worker.kmtecherp.com" not in section

    for marker in (
        "[string]$ServerBaseUrl",
        "[string]$ProducerIdentityPath",
        "[string]$ProducerInstallId",
        "[string]$ProducerId",
        "[string]$SourceHostId",
        '"--endpoint-url", $endpointUrl',
        '"--producer-identity-path", $ProducerIdentityPath',
        '"--producer-install-id", $ProducerInstallId',
        '"--producer-id", $ProducerId',
        '"--source-host-id", $SourceHostId',
    ):
        assert marker in installer
    assert 'os.environ.get("CONTAINER_AUDIT_DIRECT_SYNC_SERVER_BASE_URL"' in bootstrap


def test_public_installer_accepts_http_override_with_windows_sandbox_qualification():
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "INSTALL_THIS_PC.ps1"),
            "-DryRun",
            "-EnableWindowsSandboxQualification",
            "-ServerBaseUrl",
            "http://192.168.45.98:18089",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    output = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert "ServerBaseUrl must be" not in output
    assert "Release package is incomplete. Missing:" in output


def test_public_installer_rejects_http_override_without_windows_sandbox_qualification():
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "INSTALL_THIS_PC.ps1"),
            "-DryRun",
            "-ServerBaseUrl",
            "http://192.168.45.98:18089",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    output = completed.stdout + completed.stderr

    assert completed.returncode != 0
    assert "ServerBaseUrl must be" in output
    assert "Release package is incomplete. Missing:" not in output


def test_public_installer_materializes_fresh_canonical_payload_and_preserves_owned_update_boundary(
    tmp_path,
):
    source = tmp_path / "ordinary-extraction" / "Container_Audit"
    target_parent = tmp_path / "canonical" / "Container_Audit"
    target = target_parent / "current"
    (source / "assets").mkdir(parents=True)
    (source / "INSTALL_THIS_PC.ps1").write_bytes(b"public installer\r\n")
    (source / "Container_Audit.exe").write_bytes(b"frozen application bytes")
    (source / "assets" / "Item.csv").write_bytes(b"item,quantity\r\nA,60\r\n")
    escaped_source = str(source).replace("'", "''")
    escaped_target = str(target).replace("'", "''")
    escaped_parent = str(target_parent).replace("'", "''")
    body = (
        "Set-StrictMode -Version Latest;"
        f"$source='{escaped_source}';$target='{escaped_target}';$parent='{escaped_parent}';"
        "$result=Initialize-CanonicalApplicationRoot $source $target $parent;"
        "if(-not (Test-SamePath $result $target)){Write-Error 'canonical result mismatch';exit 51};"
        "if([System.IO.File]::ReadAllText((Join-Path $target 'Container_Audit.exe')) "
        "-cne 'frozen application bytes'){Write-Error 'application bytes mismatch';exit 52};"
        "if([System.IO.File]::ReadAllText((Join-Path $target 'assets\\Item.csv')) "
        "-cne \"item,quantity`r`nA,60`r`n\"){Write-Error 'nested payload mismatch';exit 53};"
        "[System.IO.File]::WriteAllText((Join-Path $source 'Container_Audit.exe'),'replacement bytes');"
        "$blocked=$false;try{[void](Initialize-CanonicalApplicationRoot $source $target $parent)}"
        "catch{$blocked=$_.Exception.Message -like '*owned update flow*'};"
        "if(-not $blocked){Write-Error 'existing canonical target was not blocked';exit 54};"
        "if([System.IO.File]::ReadAllText((Join-Path $target 'Container_Audit.exe')) "
        "-cne 'frozen application bytes'){Write-Error 'owned target was overwritten';exit 55};"
        "exit 0"
    )

    assert not target_parent.exists()
    completed = _run_installer_functions(
        [
            "Test-SamePath",
            "Get-StrictFullPath",
            "Assert-ExactCanonicalPath",
            "Test-PathWithin",
            "Assert-NoReparsePoint",
            "Assert-OwnedTree",
            "Assert-ApplicationParentInventory",
            "Remove-ExactOwnedTree",
            "Initialize-CanonicalApplicationRoot",
        ],
        body,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert (target / "INSTALL_THIS_PC.ps1").read_bytes() == b"public installer\r\n"


def test_canonical_bootstrap_stack_survives_strict_mode_and_rejects_descendant_reparse(
    tmp_path,
):
    installer = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")
    start = installer.index("function Assert-NoReparsePoint")
    end = installer.index("function Assert-OperatorContext", start)
    traversal = installer[start:end]
    assert (
        "$pendingDirectories = [System.Collections.Generic.Stack[string]]::new()"
        in traversal
    )
    assert "New-Object System.Collections.Generic.Stack[string]" not in traversal

    root = tmp_path / "ordinary-extraction"
    outside = tmp_path / "outside"
    escaped_root = str(root).replace("'", "''")
    escaped_outside = str(outside).replace("'", "''")
    body = (
        "Set-StrictMode -Version Latest;"
        f"$root='{escaped_root}';$outside='{escaped_outside}';"
        "[void](New-Item -ItemType Directory -Path $root -Force);"
        "[void](New-Item -ItemType Directory -Path $outside -Force);"
        "$link=Join-Path $root 'linked';"
        "[void](New-Item -ItemType Junction -Path $link -Target $outside);"
        "$blocked=$false;"
        "try{Assert-NoReparsePoint $root 'ordinary extraction' -IncludeDescendants}"
        "catch{$blocked=$_.Exception.Message -like '*descendant reparse point*'};"
        "if(-not $blocked){Write-Error 'descendant reparse point was not rejected';exit 61};"
        "exit 0"
    )

    completed = _run_installer_functions(
        ["Get-StrictFullPath", "Assert-NoReparsePoint"],
        body,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_public_installer_continues_from_canonical_bytes_without_qualification_layout_bypass():
    text = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")
    start = text.index("$packageRoot = $releaseSourceRoot")
    end = text.index("$reuseExistingIdentity = (", start)
    canonical_bootstrap = text[start:end]

    assert "Initialize-CanonicalApplicationRoot" in canonical_bootstrap
    assert "$expectedInstallRoot" in canonical_bootstrap
    assert "$expectedApplicationParent" in canonical_bootstrap
    assert "EnableWindowsSandboxQualification" not in canonical_bootstrap
    assert canonical_bootstrap.index("Initialize-CanonicalApplicationRoot") < canonical_bootstrap.index(
        '$appExe = Join-Path $packageRoot "Container_Audit.exe"'
    )
    assert '$actualInstallRoot = [System.IO.Path]::GetFullPath($packageRoot)' in text
    assert "production_apply_allowed = $productionLayoutMatches" in text


def test_http_server_override_requires_qualification_and_other_inputs_stay_blocked():
    installer = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")
    assert (
        "$allowExplicitHttpServerBaseUrl = "
        '$PSBoundParameters.ContainsKey("ServerBaseUrl")'
    ) not in installer
    assert (
        "$allowExplicitHttpServerBaseUrl = "
        "$EnableWindowsSandboxQualification.IsPresent"
    ) in installer
    assert (
        "Assert-HttpsServerBaseUrl $ServerBaseUrl "
        "-AllowExplicitHttp:$allowExplicitHttpServerBaseUrl"
    ) in installer
    assert "$qualificationServerBaseUri = [System.Uri]$ServerBaseUrl" in installer
    assert '$qualificationServerBaseUri.Scheme -cne "http"' in installer

    body = (
        "Assert-HttpsServerBaseUrl 'https://worker.kmtecherp.com';"
        "Assert-HttpsServerBaseUrl 'http://192.168.45.98:18089' -AllowExplicitHttp;"
        "$blocked=@("
        "@{value='http://192.168.45.98:18089';allow=$false},"
        "@{value='ftp://192.168.45.98:18089';allow=$true},"
        "@{value='http://user@192.168.45.98:18089';allow=$true},"
        "@{value='http://192.168.45.98:18089?query=1';allow=$true},"
        "@{value='http://192.168.45.98:18089#fragment';allow=$true}"
        ");"
        "foreach($case in $blocked){"
        "$rejected=$false;"
        "try{Assert-HttpsServerBaseUrl $case.value -AllowExplicitHttp:$case.allow}"
        "catch{$rejected=$true};"
        "if(-not $rejected){Write-Error ('URL unexpectedly accepted: '+$case.value);exit 41}"
        "};exit 0"
    )
    completed = _run_installer_functions(["Assert-HttpsServerBaseUrl"], body)

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_package_installer_has_honest_uninstall_and_confirmed_pristine_rollback():
    text = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")

    assert "PurgeContainerAuditState" in text
    assert "ConfirmPermanentContainerAuditDataRemoval" in text
    assert "RollbackReportPath" in text
    assert "Destructive rollback requires -ConfirmPermanentContainerAuditDataRemoval." in text
    assert "Destructive rollback requires an external -RollbackReportPath." in text
    assert "uninstall_status=PASS_DATA_PRESERVED" in text
    assert "application_root_status=ABSENT" in text
    assert "data_preserved=true" in text
    assert "install_status=UNINSTALLED" not in text
    assert "rollback_status=PASS" in text
    assert "Test-RollbackPostconditions" in text
    assert 'status = if ($remaining.Count -eq 0) { "PASS" } else { "FAIL" }' in text
    assert "contains_credential_content = $false" in text
    assert "[Environment]::CurrentDirectory = $safePath" in text
    uninstall_start = text.index("if ($Uninstall.IsPresent)")
    plain_start = text.index("if (-not $PurgeContainerAuditState.IsPresent)", uninstall_start)
    plain_end = text.index("$externalReportPath = Assert-ExternalRollbackReportPath", plain_start)
    plain_uninstall = text[plain_start:plain_end]
    assert "Remove-OwnedCurrentApplicationFootprint $actualInstallRoot $expectedInstallRoot" in plain_uninstall

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
        "Set-ProcessWorkingDirectoryOutsideOwnedTree $expectedInstallRoot",
        "Remove-ExactOwnedTree $expectedInstallRoot",
    ]
    apply_positions = [apply_block.index(marker) for marker in apply_markers]
    assert apply_positions == sorted(apply_positions)


def test_plain_uninstall_removes_only_current_application_footprint(tmp_path):
    application_parent = tmp_path / "application" / "Container_Audit"
    application_root = application_parent / "current"
    update_backups = application_parent / ".current.update-backups"
    unrelated_sibling = application_parent / "unrelated-sibling"
    application_root.mkdir(parents=True)
    update_backups.mkdir()
    unrelated_sibling.mkdir()
    (application_root / "Container_Audit.exe").write_bytes(b"owned application bytes")
    backup_marker = update_backups / "backup.bin"
    sibling_marker = unrelated_sibling / "keep.bin"
    backup_marker.write_bytes(b"preserved update backup")
    sibling_marker.write_bytes(b"unrelated sibling")
    escaped_root = str(application_root).replace("'", "''")
    environment = os.environ.copy()
    environment["TEMP"] = str(tmp_path / "temp")
    environment["TMP"] = environment["TEMP"]
    body = (
        f"$owned='{escaped_root}';"
        "if(-not (Test-SamePath ([Environment]::CurrentDirectory) $owned)){"
        "Write-Error 'process did not start inside owned root';exit 41};"
        "$result=Remove-OwnedCurrentApplicationFootprint $owned $owned;"
        "if($result.status -cne 'ABSENT'){Write-Error 'owned root was not removed';exit 42};"
        "exit 0"
    )

    result = _run_installer_functions(
        [
            "Test-SamePath",
            "Get-StrictFullPath",
            "Assert-ExactCanonicalPath",
            "Test-PathWithin",
            "Set-ProcessWorkingDirectoryOutsideOwnedTree",
            "Assert-NoReparsePoint",
            "Assert-OwnedTree",
            "Assert-NoOwnedProcess",
            "Remove-ExactOwnedTree",
            "Remove-OwnedCurrentApplicationFootprint",
        ],
        body,
        cwd=application_root,
        env=environment,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert not application_root.exists()
    assert backup_marker.read_bytes() == b"preserved update backup"
    assert sibling_marker.read_bytes() == b"unrelated sibling"


def test_destructive_rollback_releases_process_cwd_before_application_root_delete(tmp_path):
    application_root = tmp_path / "application" / "current"
    application_root.mkdir(parents=True)
    marker = application_root / "packaged-config.json"
    marker.write_text("{}\n", encoding="utf-8")
    escaped_root = str(application_root).replace("'", "''")
    environment = os.environ.copy()
    environment["TEMP"] = str(tmp_path / "temp")
    environment["TMP"] = environment["TEMP"]
    body = (
        f"$owned='{escaped_root}';"
        "if(-not (Test-SamePath ([Environment]::CurrentDirectory) $owned)){"
        "Write-Error 'process did not start inside owned root';exit 31};"
        "$result=Set-ProcessWorkingDirectoryOutsideOwnedTree $owned;"
        "if($result.status -cne 'PASS' -or -not $result.outside_application_root){"
        "Write-Error 'working directory relocation did not pass';exit 32};"
        "Remove-Item -LiteralPath $owned -Recurse -Force -ErrorAction Stop;"
        "if(Test-Path -LiteralPath $owned){Write-Error 'owned root survived';exit 33};"
        "exit 0"
    )

    result = _run_installer_functions(
        [
            "Test-SamePath",
            "Get-StrictFullPath",
            "Test-PathWithin",
            "Set-ProcessWorkingDirectoryOutsideOwnedTree",
        ],
        body,
        cwd=application_root,
        env=environment,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert not application_root.exists()


def test_qualification_authority_shutdown_is_exact_and_precedes_owned_tree_removal():
    text = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")
    shutdown = text[
        text.index("function Get-OwnedQualificationAuthorityProcesses") :
        text.index("function Assert-OwnedTree")
    ]

    assert "Name='Container_Audit_Qualification_Authority.exe'" in shutdown
    assert "Test-SamePath ([string]$_.ExecutablePath) $Executable" in shutdown
    assert (
        "Get-CimInstance Win32_Process -Filter "
        '"Name=\'Container_Audit_Qualification_Authority.exe\'" '
        "-ErrorAction SilentlyContinue"
    ) not in shutdown
    assert "process identity could not be proven" in shutdown
    assert "ProcessId=$processId AND Name='Container_Audit_Qualification_Authority.exe'" in shutdown
    assert "Stop-Process -Id $processId -Force -ErrorAction Stop" in shutdown
    assert "Stop-OwnedQualificationAuthorityProcesses $Executable" in shutdown
    assert shutdown.index("Unregister-ScheduledTask") < shutdown.index(
        "Stop-OwnedQualificationAuthorityProcesses $Executable"
    )
    assert "process removal postcondition failed" in shutdown

    rollback = text[
        text.index("[void]$rollbackResults.Add((Remove-OwnedQualificationAuthorityTask") :
        text.index("$rollbackReport.parent_cleanup")
    ]
    assert rollback.index("Remove-OwnedQualificationAuthorityTask") < rollback.index(
        "Remove-ExactOwnedTree $expectedDirectSyncRoot"
    )


@pytest.mark.parametrize(
    ("cim_body", "expected_error"),
    [
        ("throw 'synthetic CIM failure'", "synthetic CIM failure"),
        (
            "[pscustomobject]@{Name='Container_Audit_Qualification_Authority.exe';"
            "ExecutablePath=$null;ProcessId=4242}",
            "process identity could not be proven",
        ),
    ],
)
def test_qualification_authority_enumeration_fails_closed_on_uncertainty(
    cim_body, expected_error
):
    body = (
        "function Get-CimInstance{[CmdletBinding()]param([string]$ClassName,[string]$Filter)"
        + cim_body
        + "};"
        "function Test-SamePath{param($Actual,$Expected)return $Actual -ceq $Expected};"
        "try{[void](Get-OwnedQualificationAuthorityProcesses 'C:\\owned\\authority.exe');"
        "Write-Error 'enumeration failed open';exit 11}"
        f"catch{{if($_.Exception.Message -notlike '*{expected_error}*'){{Write-Error $_;exit 12}};exit 0}}"
    )

    result = _run_installer_functions(
        ["Get-OwnedQualificationAuthorityProcesses"], body
    )

    assert result.returncode == 0, result.stderr or result.stdout


def test_qualification_authority_shutdown_never_reports_a_live_orphan_absent():
    body = (
        "$script:clock=[datetime]'2026-08-21T00:00:00Z';$script:stopCalls=0;"
        "function Get-CimInstance{[CmdletBinding()]param([string]$ClassName,[string]$Filter)"
        "[pscustomobject]@{Name='Container_Audit_Qualification_Authority.exe';"
        "ExecutablePath='C:\\owned\\authority.exe';ProcessId=4242}};"
        "function Test-SamePath{param($Actual,$Expected)return $Actual -ceq $Expected};"
        "function Get-Date{return $script:clock};"
        "function Start-Sleep{[CmdletBinding()]param([int]$Milliseconds)"
        "$script:clock=$script:clock.AddSeconds(20)};"
        "function Stop-Process{[CmdletBinding()]param([uint32]$Id,[switch]$Force)"
        "$script:stopCalls+=1};"
        "try{Stop-OwnedQualificationAuthorityProcesses 'C:\\owned\\authority.exe';"
        "Write-Error 'live orphan was reported absent';exit 21}"
        "catch{if($_.Exception.Message -notlike '*removal postcondition failed*'){Write-Error $_;exit 22};"
        "if($script:stopCalls -lt 1){Write-Error 'owned PID was never stopped';exit 23};exit 0}"
    )

    result = _run_installer_functions(
        [
            "Get-OwnedQualificationAuthorityProcesses",
            "Stop-OwnedQualificationAuthorityProcesses",
        ],
        body,
    )

    assert result.returncode == 0, result.stderr or result.stdout


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


class _RecordingLeaseSession:
    """Records the runtime-lease origin without granting a lease."""

    def __init__(self):
        self.urls = []

    def post(self, url, **kwargs):
        self.urls.append(url)
        return _LeaseUnavailable()


class _LeaseUnavailable:
    status_code = 503
    headers = {}

    def json(self):
        return {"error": {"code": "runtime_lease_unavailable"}, "retryable": True}


class _AcceptedReceipt:
    """Minimal accepted producer-ingest receipt for the posted metadata."""

    status_code = 200
    headers = {}

    def __init__(self, metadata):
        request_id = "request-qualification-1"
        self._payload = {
            "status": "accepted",
            "committed": True,
            "client_batch_id": metadata["client_batch_id"],
            "server_source_file_id": (
                f"{metadata['source_host_id']}/{metadata['producer_role']}/"
                f"{metadata['stream_name']}/{metadata['relative_path']}"
            ),
            "request_id": request_id,
            "upload_id": request_id,
            "retryable": False,
            "next_retry_after": None,
            "error": None,
            "totals": {
                "inserted": metadata["row_count"],
                "replayed": 0,
                "errors": 0,
                "quarantined": 0,
            },
        }

    def json(self):
        return self._payload


class _AcceptingIngestSession:
    """Records the exact origin the product actually submits to."""

    def __init__(self):
        self.urls = []

    def post(self, url, *, data, **kwargs):
        self.urls.append(url)
        return _AcceptedReceipt(json.loads(data["metadata"]))


def test_qualification_switch_keeps_the_explicitly_bound_submission_origin(
    monkeypatch, tmp_path
):
    """DIRECTION seq 21 D21-1(ii): the authority must not capture the submission route.

    Both branches run the whole executed route: the installer's routing decision,
    the producer manifest/credential it writes, the runtime-lease target the relay
    derives, and the actual upload POST the product performs.
    """

    import dataclasses
    import sqlite3

    import direct_sync_push
    import direct_sync_runtime
    import isolated_qualification
    import producer_runtime_client
    from tools import isolated_qualification_authority as authority
    from tools import register_container_audit_worker_pc as register

    production_origin = "https://worker.kmtecherp.com"
    authority_origin = "https://127.0.0.1:18473"
    explicit_origin = "http://192.168.45.98:18089"
    ingest_path = "/api/producer-ingest/v1/source-file"
    lease_path = "/api/producer-ingest/v1/runtime-lease"

    # 1. Installer routing. The explicit-parameter presence bit decides, so an
    #    explicitly supplied production default is honoured too.
    body = (
        "Set-StrictMode -Version Latest;"
        f"$production='{production_origin}';$authority='{authority_origin}';"
        f"$explicit='{explicit_origin}';"
        "Write-Output (Resolve-ProducerSubmissionBaseUrl $explicit $true $authority);"
        "Write-Output (Resolve-ProducerSubmissionBaseUrl $production $true $authority);"
        "Write-Output (Resolve-ProducerSubmissionBaseUrl $production $false $authority);"
        "$rejected=$false;"
        "try{Assert-HttpsServerBaseUrl $explicit}catch{$rejected=$true};"
        "if(-not $rejected){Write-Error 'switch-off HTTP override was accepted';exit 71};"
        "exit 0"
    )
    completed = _run_installer_functions(
        ["Assert-HttpsServerBaseUrl", "Resolve-ProducerSubmissionBaseUrl"],
        body,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert completed.stdout.split() == [
        explicit_origin,
        production_origin,
        authority_origin,
    ]

    operator_root = tmp_path / "operator-local-app-data"
    operator_root.mkdir()
    monkeypatch.setenv(isolated_qualification.SOURCE_TEST_MODE_ENV, "1")
    monkeypatch.setenv("COMPUTERNAME", "QUALIFICATION-ROUTING-HOST")
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "program-data"))
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(tmp_path / "data-root"))
    state_root = isolated_qualification.default_state_root()
    authority.initialize_authority(
        state_root=state_root,
        operator_user_sid="S-1-5-21-100-200-300-504",
        operator_local_app_data_root=str(operator_root),
        port=18473,
        report_path=tmp_path / "initialize-report.json",
    )
    context_path = state_root / isolated_qualification.CONTEXT_FILENAME
    assert isolated_qualification.load_isolated_qualification_context(
        context_path
    ).endpoint_url == f"{authority_origin}{ingest_path}"

    source_csv = tmp_path / "qualification-event-log.csv"
    source_csv.write_text(
        "timestamp,worker_name,event,details\n"
        '2026-08-23T00:00:00,worker,SCAN_OK,"{ ""product_barcode"": ""BC-1"" }"\n',
        encoding="utf-8",
    )

    def _register(case, extra):
        paths = {
            name: tmp_path / f"{case}-{name}.json"
            for name in ("manifest", "credential", "report")
        }
        code = register.main(
            [
                "--app-root",
                str(ROOT),
                "--manifest-path",
                str(paths["manifest"]),
                "--credential-path",
                str(paths["credential"]),
                "--report-path",
                str(paths["report"]),
                *extra,
            ]
        )
        return code, paths

    def _submitted_urls(case, endpoint_url, *, expect_authority_ca):
        """Run the real credential load, lease derivation, and upload POST."""

        credential_path = tmp_path / f"{case}-credential.json"
        credential = json.loads(credential_path.read_text(encoding="utf-8"))
        credential.pop("secret_ref", None)
        credential.pop("secret_data_dir", None)
        credential["secret"] = "qualification-only-test-secret"
        credential["runtime_lease_mode"] = "observe"
        credential_path.write_text(
            json.dumps(credential, ensure_ascii=False), encoding="utf-8"
        )
        credentials = direct_sync_runtime.load_credentials_from_json(credential_path)
        assert credentials.endpoint_url == endpoint_url
        # The loopback qualification CA follows the authority origin only.
        expected_ca = (
            str(
                isolated_qualification.load_isolated_qualification_context(
                    context_path
                ).ca_bundle_path
            )
            if expect_authority_ca
            else ""
        )
        assert credentials.tls_ca_bundle_path == expected_ca
        direct_sync_push.validate_credentials_endpoint(credentials)
        lease_session = _RecordingLeaseSession()
        lease_db = tmp_path / f"{case}-runtime.sqlite3"
        with sqlite3.connect(lease_db) as conn:
            producer_runtime_client.init_runtime_schema(conn)
        preparation = producer_runtime_client.ensure_runtime_authority(
            db_path=lease_db,
            credentials=credentials,
            producer_install_id="container-audit-qualification-install",
            session=lease_session,
        )
        assert preparation.error_code != "runtime_authority_scope_invalid", preparation
        plan = direct_sync_push.build_source_file_plan(
            source_file_path=source_csv,
            producer_manifest_path=tmp_path / f"{case}-manifest.json",
            credentials=credentials,
        )
        session = _AcceptingIngestSession()
        result = direct_sync_push.upload_source_file(
            plan, credentials, session=session, status_dir=tmp_path / f"{case}-status"
        )
        assert result.success, result
        return lease_session.urls, session.urls

    # Switch ON + explicit origin: the bound origin survives all the way to the
    # runtime lease and the receipt POST the product actually issues.
    code, paths = _register(
        "bound-origin",
        [
            "--endpoint-url",
            f"{explicit_origin}{ingest_path}",
            "--isolated-qualification-context",
            str(context_path),
        ],
    )
    assert code == 0, paths["report"].read_text(encoding="utf-8")
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    report = json.loads(paths["report"].read_text(encoding="utf-8"))
    assert manifest["sync"]["server_ingest_target"] == f"{explicit_origin}{ingest_path}"
    assert report["isolated_qualification_mode"] is True
    assert authority_origin not in json.dumps(manifest)
    lease_urls, submitted = _submitted_urls(
        "bound-origin",
        f"{explicit_origin}{ingest_path}",
        expect_authority_ca=False,
    )
    assert lease_urls == [f"{explicit_origin}{lease_path}"]
    assert submitted == [f"{explicit_origin}{ingest_path}"]

    # Switch ON without an explicit origin: the prior loopback authority route.
    code, paths = _register(
        "authority-origin",
        [
            "--endpoint-url",
            f"{authority_origin}{ingest_path}",
            "--isolated-qualification-context",
            str(context_path),
        ],
    )
    assert code == 0, paths["report"].read_text(encoding="utf-8")
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    assert manifest["sync"]["server_ingest_target"] == f"{authority_origin}{ingest_path}"
    lease_urls, submitted = _submitted_urls(
        "authority-origin",
        f"{authority_origin}{ingest_path}",
        expect_authority_ca=True,
    )
    assert lease_urls == [f"{authority_origin}{lease_path}"]
    assert submitted == [f"{authority_origin}{ingest_path}"]

    # Switch ON + an explicitly supplied production default: still the bound
    # origin, and still without the loopback authority's private CA.
    code, paths = _register(
        "bound-production",
        [
            "--endpoint-url",
            f"{production_origin}{ingest_path}",
            "--isolated-qualification-context",
            str(context_path),
        ],
    )
    assert code == 0, paths["report"].read_text(encoding="utf-8")
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    assert manifest["sync"]["server_ingest_target"] == f"{production_origin}{ingest_path}"
    lease_urls, submitted = _submitted_urls(
        "bound-production",
        f"{production_origin}{ingest_path}",
        expect_authority_ca=False,
    )
    assert lease_urls == [f"{production_origin}{lease_path}"]
    assert submitted == [f"{production_origin}{ingest_path}"]

    # Switch OFF: the production default stands and explicit HTTP stays rejected.
    code, paths = _register("default", [])
    assert code == 0, paths["report"].read_text(encoding="utf-8")
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    assert manifest["sync"]["server_ingest_target"] == register.DEFAULT_ENDPOINT_URL
    assert manifest["sync"]["server_ingest_target"] == f"{production_origin}{ingest_path}"
    lease_urls, submitted = _submitted_urls(
        "default", register.DEFAULT_ENDPOINT_URL, expect_authority_ca=False
    )
    assert lease_urls == [f"{production_origin}{lease_path}"]
    assert submitted == [register.DEFAULT_ENDPOINT_URL]

    code, paths = _register(
        "unqualified-http",
        ["--endpoint-url", f"{explicit_origin}{ingest_path}"],
    )
    assert code == 2
    blocked = json.loads(paths["report"].read_text(encoding="utf-8"))["blocked_reason"]
    assert "https" in blocked

    bound_credentials = direct_sync_runtime.load_credentials_from_json(
        tmp_path / "bound-origin-credential.json"
    )
    with pytest.raises(
        direct_sync_push.DirectSyncPushError, match="must not be used off the authority"
    ):
        direct_sync_push.validate_credentials_endpoint(
            dataclasses.replace(
                bound_credentials,
                tls_ca_bundle_path=str(
                    isolated_qualification.load_isolated_qualification_context(
                        context_path
                    ).ca_bundle_path
                ),
            )
        )

    # A production credential without a qualification context still refuses an
    # HTTP runtime-lease origin.
    with pytest.raises(ValueError, match="credential-free HTTPS"):
        producer_runtime_client._runtime_endpoint(f"{explicit_origin}{ingest_path}")

"""Actual PowerShell failure boundaries, including the Windows console wire bytes."""
import json
import os
import re
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.powershell_contracts import run_functions as _run_functions

ROOT = Path(__file__).resolve().parents[1]


def run_functions(tmp_path, *args, **kwargs):
    source, names, script = args
    result = _run_functions(tmp_path, source, names,
                            "Set-StrictMode -Version Latest\n" + script, **kwargs)
    # Record only error identifiers and source line numbers, never diagnostics.
    kinds = re.findall(r"FullyQualifiedErrorId\s*:\s*([A-Za-z0-9_.]+)", result.stderr)
    lines = re.findall(r"(?:\.ps1:|\.ps1\s*:\s*)([0-9]+)", result.stderr)
    (tmp_path / "boundary-observation.json").write_text(json.dumps({
        "rc": result.returncode, "error_types": kinds, "lines": lines,
        "public_line_count": result.stdout.count("CONTAINER_AUDIT_INSTALL_CANONICAL="),
    }), encoding="utf-8")
    return result


@pytest.mark.parametrize("fault", ["preparation", "redaction", "private", "public", "public-after-output", "machine-public"])
def test_outer_failure_helpers_cannot_suppress_public_record(tmp_path, fault):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1",
        ["Write-CanonicalInstallationPublicRecord"], r'''
$machineWorker=$null;$audit=$null;$canonicalWriterFenceActive=$false
$Uninstall=$false;$RestoreVerifiedReplacement=$false;$CompleteRetiredRemoval=$false
$enteredPlacementTry=($env:FAULT -ne 'preparation')
$Script:CanonicalPreparationAdmissionFailed=$false
$Script:CanonicalInstallerSourceInventorySha256=''
function Write-CanonicalPreparationAdmissionFailure {if($env:FAULT -eq 'preparation'){throw 'injected'} }
function ConvertTo-KmtechRedactedSinkText {if($env:FAULT -eq 'redaction'){throw 'injected'};return 'FIXED'}
function Write-InstallationCaughtFailure {if($env:FAULT -eq 'private'){throw 'injected'}}
if($env:FAULT -eq 'public'){function Write-CanonicalInstallationPublicRecord {throw 'injected'}}
if($env:FAULT -eq 'public-after-output'){function Write-CanonicalInstallationPublicRecord {Write-Output 'uncommitted';throw 'injected'}}
if($env:FAULT -eq 'machine-public'){$machineWorker=[pscustomobject]@{};function Write-CanonicalMachinePublicRecord {Write-Output 'uncommitted';throw 'injected'}}
$text=[IO.File]::ReadAllText($env:CA_CONTRACT_SOURCE)
$begin=$text.LastIndexOf('} catch {'+"`n"+'    $outputFailure=$_')
if($begin -lt 0){$text=$text.Replace("`r`n","`n");$begin=$text.LastIndexOf('} catch {'+"`n"+'    $outputFailure=$_')}
$end=$text.IndexOf('} finally {',$begin)
$body=$text.Substring($begin+9,$end-$begin-9)
& ([scriptblock]::Create('try {throw "original"} catch {'+$body+'}'))
''', values={"FAULT": fault})
    lines = [line for line in result.stdout.splitlines() if line.startswith("CONTAINER_AUDIT_INSTALL_CANONICAL=")]
    assert result.returncode == (4 if fault == "machine-public" else 1)
    assert len(lines) == 1
    payload = json.loads(lines[0].split("=", 1)[1])
    assert payload["status"] == "FAILED"
    assert payload["report_status"] == "REPORT_UNAVAILABLE"
    assert "original" not in result.stdout + result.stderr
    assert "injected" not in result.stdout + result.stderr
    assert "uncommitted" not in result.stdout + result.stderr


def test_hidden_quiesce_receipt_uses_actual_binding_reader(tmp_path):
    result = run_functions(tmp_path, ROOT / "INSTALL_THIS_PC.ps1", ["Write-InstallationHelperPublicRecord"], r'''
$quiesceFull=Join-Path $env:CA_CONTRACT_ROOT 'hidden-receipt.json'
[IO.File]::WriteAllText($quiesceFull,'{"status":"PASS_DATA_PRESERVED"}')
[IO.File]::SetAttributes($quiesceFull,[IO.FileAttributes]::Hidden)
if(-not (Test-Path -LiteralPath $quiesceFull -PathType Leaf)){throw 'Hidden receipt was not found'}
function Get-FileSha256 {return ('a'*64)}
$ExpectedQuiesceReceiptSha256='a'*64
$text=[IO.File]::ReadAllText($env:CA_CONTRACT_SOURCE)
$begin=$text.IndexOf("    if (`$ExpectedQuiesceReceiptSha256 -cnotmatch")
$end=$text.IndexOf('    if ([string]$quiesce.status',$begin)
& ([scriptblock]::Create($text.Substring($begin,$end-$begin)))
Write-Output 'READ_OK'
''')
    assert result.returncode == 0
    assert result.stdout.strip() == "READ_OK"


@pytest.mark.parametrize("variable", ["logFull", "UninstallAuditPath", "AuditPath",
                                     "WriterFencePreparedReceiptPath", "RollbackAuditPath", "path"])
def test_other_hidden_control_file_metadata_readers(tmp_path, variable):
    result = run_functions(tmp_path, ROOT / "INSTALL_THIS_PC.ps1",
        ["Write-InstallationHelperPublicRecord"], r'''
$file=Join-Path $env:CA_CONTRACT_ROOT 'hidden-control.json'
[IO.File]::WriteAllText($file,'{}')
[IO.File]::SetAttributes($file,[IO.FileAttributes]::Hidden)
Set-Variable -Name $env:CONTROL_VARIABLE -Value $file
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$tokens,[ref]$errors)
$commands=@($ast.FindAll({param($node)
 $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Get-Item' -and
 $node.Extent.Text -match ('\$'+$env:CONTROL_VARIABLE+'(?:\s|$)')
},$true))
if(-not $commands.Count){throw 'Control reader not found'}
foreach($command in $commands){
 $item=& ([scriptblock]::Create($command.Extent.Text))
 if($item.Length -ne 2){throw 'Control bytes differ'}
}
Write-Output 'READ_OK'
''', values={"CONTROL_VARIABLE": variable})
    assert result.returncode == 0
    assert result.stdout.strip() == "READ_OK"


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
def test_minimal_rollback_audit_omits_conditional_failure_code(tmp_path, engine):
    # The audit writer initializes code_replacement without failure_code; only
    # classified placement failures append that optional diagnostic field.
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1",
        ["Write-CanonicalInstallationPublicRecord"], r'''
$audit='{"status":"FAILED_ROLLED_BACK","rollback":{"runtime_restored":true},"code_replacement":{}}'|ConvertFrom-Json
$canonicalWriterFenceActive=$false
Write-CanonicalInstallationPublicRecord -ExitCode 1
''', engine=engine)
    assert result.returncode == 0
    record = json.loads(result.stdout.strip().split("=", 1)[1])
    assert record["reason_code"] == "INSTALLER_CANONICAL_FAILURE"
    assert record["report_status"] == "REPORT_UNAVAILABLE"


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
def test_minimal_child_evidence_summary_omits_journal_details(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1",
        ["Read-InstallationEvidenceChildSummary"], r'''
function Assert-BootstrapNoReparsePoint {}
function Test-BootstrapSamePath($a,$b) {return $a -ceq $b}
function Get-FileSha256 {return ('a'*64)}
$record=[ordered]@{root=$env:CA_CONTRACT_ROOT;status='COMPLETE';recording_failed=$false}
$record|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $env:CA_CONTRACT_ROOT 'evidence-status.json') -Encoding UTF8
$result=Read-InstallationEvidenceChildSummary $env:CA_CONTRACT_ROOT
if($result.status -cne 'COMPLETE' -or $result.recording_failed){throw 'Summary changed'}
Write-Output 'READ_OK'
''', engine=engine)
    assert result.returncode == 0
    assert result.stdout.strip() == "READ_OK"


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
def test_minimal_shortcut_record_omits_updated_entry_preimage(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1",
        ["Read-BootstrapWorkerShortcutRecord"], r'''
function Assert-BootstrapWorkerShortcutPath {}
function Get-BootstrapWorkerShortcutFolders {return [pscustomobject]@{path=$env:CA_CONTRACT_ROOT}}
$root=Join-Path $env:CA_CONTRACT_ROOT 'app'
$record=[ordered]@{schema='container-audit-worker-shortcuts-v1';install_root=$root;scope='User';
 entries=@([ordered]@{path=(Join-Path $env:CA_CONTRACT_ROOT 'created.lnk');action='created'})}
$path=Join-Path $env:CA_CONTRACT_ROOT 'shortcuts.json'
$record|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $path -Encoding UTF8
$read=Read-BootstrapWorkerShortcutRecord $root $path 'User'
if($read.entries.Count -ne 1 -or $read.entries[0].action -cne 'created'){throw 'Shortcut record changed'}
Write-Output 'READ_OK'
''', engine=engine)
    assert result.returncode == 0
    assert result.stdout.strip() == "READ_OK"


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
def test_minimal_removal_marker_omits_emergency_shortcut_extension(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1",
        ["Update-BootstrapEmergencyRemovalMarker"], r'''
function Assert-BootstrapNoReparsePoint {}
function Get-BootstrapEmergencyRemovalState {
 return [pscustomobject]@{shortcut_path=(Join-Path $env:CA_CONTRACT_ROOT 'emergency.lnk');
  directory_path=$env:CA_CONTRACT_ROOT;shortcut_exists=$false;directory_exists=$false;
  cleanup_status='ABSENT';target_exists=$null}
}
function Write-Utf8Json($Path,$Record) {
 if($Record.emergency_shortcut.cleanup_status -cne 'ABSENT' -or $Record.retained_paths.Count -ne 0){throw 'Removal marker changed'}
 Write-Output 'READ_OK'
}
$record=[ordered]@{schema='container-audit-supported-removal-v1';lifecycle_state='REMOVED';
 retained_paths=@();artifact_dispositions=@()}
$record|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $env:CA_CONTRACT_ROOT 'removed.json') -Encoding UTF8
Update-BootstrapEmergencyRemovalMarker (Join-Path $env:CA_CONTRACT_ROOT 'app')
''', engine=engine)
    assert result.returncode == 0
    assert result.stdout.strip() == "READ_OK"


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
def test_minimal_fallback_summary_omits_optional_reason_code(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1",
        ["Get-CanonicalMachineHelperReason"], r'''
$line='installation_failure_summary={"schema":"container-audit-installation-fallback-v1","exit_code":73,"failure":{},"child":null,"evidence_failure":null}'
$Error.Clear()
$reason=Get-CanonicalMachineHelperReason $line
if($reason -cne 'PLACEMENT_HELPER_FAILED'){throw 'Missing reason changed classification'}
if(@($Error|Where-Object {$_.FullyQualifiedErrorId -match 'PropertyNotFound'}).Count){throw 'Optional field raised PropertyNotFound'}
Write-Output 'READ_OK'
''', engine=engine)
    assert result.returncode == 0
    assert result.stdout.strip() == "READ_OK"


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
def test_minimal_failed_capture_omits_unavailable_stream_metadata(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1",
        ["Read-CanonicalRetiredRemovalCapture"], r'''
$Script:InstallationEvidenceFailed=$false
$Script:InstallationEvidenceFailureCodes=[Collections.Generic.List[string]]::new()
$stream='{"path":""}'|ConvertFrom-Json
$summary='{"recording_failed":true,"failure_codes":["CHILD_STREAM_IO_OR_ACL_FAILURE"]}'|ConvertFrom-Json
$text=Read-CanonicalRetiredRemovalCapture $stream $summary
if($text -cne '' -or -not $Script:InstallationEvidenceFailed -or $Script:InstallationEvidenceFailureCodes.Count -ne 1){throw 'Capture failure changed'}
Write-Output 'READ_OK'
''', engine=engine)
    assert result.returncode == 0
    assert result.stdout.strip() == "READ_OK"


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
def test_minimal_integrity_record_passes_actual_writer_and_reader(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1",
        ["Write-BootstrapIntegrityRecord", "Assert-BootstrapIntegrityRecord", "Test-BootstrapJsonInteger"], r'''
$BootstrapIntegrityFileName='bootstrap-integrity.json'
$BootstrapIntegritySchema='container-audit-bootstrap-integrity-v1'
function Get-StrictFullPath($Path,$Purpose) {return [IO.Path]::GetFullPath($Path)}
function Get-CodeInventory {return [pscustomobject]@{path='Container_Audit.exe';size=1;sha256=('a'*64)}}
function Get-CodeInventoryInRecordOrder {return (Get-CodeInventory)}
function Get-InventoryAggregate {return ('b'*64)}
function Write-Utf8Json($Path,$Payload) {$Payload|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $Path -Encoding UTF8}
$record=Write-BootstrapIntegrityRecord $env:CA_CONTRACT_ROOT '.'
$read=Assert-BootstrapIntegrityRecord $env:CA_CONTRACT_ROOT
if($read.status -cne 'PASS' -or $read.file_count -ne 1){throw 'Integrity record changed'}
Write-Output 'READ_OK'
''', engine=engine)
    assert result.returncode == 0
    assert result.stdout.strip() == "READ_OK"


PRODUCERS = [
    ("INSTALL_CANONICAL_PORTABLE.ps1", "Write-CanonicalInstallationPublicRecord", "Write-CanonicalInstallationPublicRecord -ExitCode 1"),
    ("INSTALL_CANONICAL_PORTABLE.ps1", "Write-CanonicalMachinePublicRecord", "Write-CanonicalMachinePublicRecord 'MACHINE_INSTALL_FAILED'"),
    ("INSTALL_THIS_PC.ps1", "Write-InstallationHelperPublicRecord", "Write-InstallationHelperPublicRecord @{status='FAILED'}"),
    ("INSTALL_THIS_PC.ps1", "Write-InstallationHelperPublicRecord", "Write-InstallationHelperPublicRecord @{status='PASS';reason_code='HIBERBOOT_ENABLED'}"),
    ("tools/bootstrap_integrity.ps1", "Write-InstallationTransactionTerminalFailure", "Write-InstallationTransactionTerminalFailure"),
    ("tools/bootstrap_integrity.ps1", "Start-BootstrapNormalProducerWrapper", "try {Start-BootstrapNormalProducerWrapper ('x'*1024) $null @() @()} catch {}"),
    ("tools/apply_prepared_update.ps1", "sink:update-child", ""),
    ("tools/apply_prepared_update.ps1", "sink:update-catch", ""),
    ("tools/provision_protected_admin_acl.ps1", "sink:support", ""),
    ("tools/container_writer_fence.ps1", "Write-ContainerMachineRecoveryGuidance", "Write-ContainerMachineRecoveryGuidance ([pscustomobject]@{owner_kind='canonical_installer';replacement_transaction_id='fixed'}) ''"),
]


@pytest.mark.parametrize("source,name,invoke", PRODUCERS, ids=[row[1] for row in PRODUCERS])
def test_public_failure_wire_bytes_are_console_independent(tmp_path, source, name, invoke):
    outputs = []
    is_pass = "status='PASS'" in invoke
    # The approved vectors avoid unrelated PS5/PS7 JSON escaping differences.
    vector_path = ROOT / "tests/fixtures/g36_public_line_vectors.json"
    vectors = json.loads(vector_path.read_text(encoding="utf-8"))["vectors"]
    for engine in ("powershell", "pwsh"):
        assert shutil.which(engine), "Required PowerShell engine unavailable"
        for codepage in (949, 65001):
            folder = tmp_path / (engine + str(codepage));folder.mkdir()
            script = r'''
$audit=$null;$canonicalWriterFenceActive=$false
function Get-CanonicalMachineFailureReason {return ''}
function Write-InstallationEvidenceEvent {}
function Get-ContainerWriterFenceControlRoot {return 'E:\isolated\machine-install\update-control\fence'}
function ConvertTo-KmtechPublicRecord {
 param($Fields,$AllowedCodes,$SafeMessages)
 if($env:WIRE_PASS -ceq '1'){return [ordered]@{status='PASS';guidance=$script:VectorText}}
 return [ordered]@{guidance=$script:VectorText}
}
function ConvertTo-Json {
 param([Parameter(ValueFromPipeline=$true)]$InputObject,[switch]$Compress,[int]$Depth)
 end {
  if($env:WIRE_PASS -ceq '1'){return Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $InputObject -Compress}
  return Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject ([ordered]@{guidance=$script:VectorText}) -Compress
 }
}
$vectors=(Get-Content -LiteralPath $env:VECTORS -Raw -Encoding UTF8|ConvertFrom-Json).vectors
[Console]::OutputEncoding=[Text.Encoding]::GetEncoding([int]$env:CODEPAGE)
foreach($vector in $vectors){
 $script:VectorText=[string]$vector.text
 if($env:WIRE_FUNCTION.StartsWith('sink:')){
  $public=[ordered]@{guidance=$script:VectorText}
  $lines=@([IO.File]::ReadAllLines($env:WIRE_SOURCE)|Where-Object {$_ -match 'CONTAINER_AUDIT_' -and $_ -match 'ConvertTo-Json'})
  $index=if($env:WIRE_FUNCTION -ceq 'sink:update-catch'){1}else{0}
  & ([scriptblock]::Create($lines[$index]))
 }else{
 ''' + invoke + r'''
 }
}
 '''
            driver = folder / "wire.ps1"
            driver.write_text(r'''
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:WIRE_SOURCE,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Source parse failed'}
if(-not $env:WIRE_FUNCTION.StartsWith('sink:')){
 $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $env:WIRE_FUNCTION},$true)
 . ([scriptblock]::Create($function.Extent.Text))
}
''' + script, encoding="utf-8-sig")
            environment = dict(os.environ, CODEPAGE=str(codepage), VECTORS=str(vector_path),
                               WIRE_SOURCE=str(ROOT / source), WIRE_FUNCTION=name,
                               WIRE_PASS="1" if is_pass else "0")
            result = subprocess.run([shutil.which(engine), "-NoLogo", "-NoProfile", "-NonInteractive",
                                     "-ExecutionPolicy", "Bypass", "-File", str(driver)],
                                    env=environment, capture_output=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            assert result.returncode == 0
            raw = result.stderr if name == "Write-ContainerMachineRecoveryGuidance" else result.stdout
            assert raw and all(byte < 0x80 for byte in raw)
            assert raw.endswith(b"\r\n")
            lines = raw.decode("ascii").splitlines()
            assert len(lines) == len(vectors)
            for line, vector in zip(lines, vectors):
                body = line.split("=", 1)[1]
                prefix = '{"status":"PASS","guidance":' if is_pass else '{"guidance":'
                assert body == prefix + vector["expected_json_string_ascii"] + '}'
                expected = {"guidance": vector["text"]}
                if is_pass:
                    expected["status"] = "PASS"
                assert json.loads(body) == expected
            outputs.append(raw)
    assert all(output == outputs[0] for output in outputs)


@pytest.mark.parametrize("source", ["INSTALL_CANONICAL_PORTABLE.ps1", "tools/apply_prepared_update.ps1"])
def test_fixed_fallback_wire_bytes_need_no_conversion_helper(tmp_path, source):
    outputs = []
    for engine in ("powershell", "pwsh"):
        for codepage in (949, 65001):
            driver = tmp_path / (engine + str(codepage) + ".ps1")
            driver.write_text(r'''
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
[Console]::OutputEncoding=[Text.Encoding]::GetEncoding([int]$env:CODEPAGE)
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:WIRE_SOURCE,[ref]$tokens,[ref]$errors)
$values=@($ast.FindAll({param($node)
 $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
 $node.Value -match '^CONTAINER_AUDIT_[A-Z_]+=\{'
},$true))
if(-not $values.Count){throw 'Fallback not found'}
foreach($value in $values){Write-Output $value.Value}
''', encoding="utf-8-sig")
            environment = dict(os.environ, CODEPAGE=str(codepage), WIRE_SOURCE=str(ROOT / source))
            result = subprocess.run([shutil.which(engine), "-NoLogo", "-NoProfile", "-NonInteractive",
                                     "-ExecutionPolicy", "Bypass", "-File", str(driver)],
                                    env=environment, capture_output=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            assert result.returncode == 0
            raw = result.stdout
            assert raw.endswith(b"\r\n")
            assert all(byte in (10, 13) or 0x20 <= byte <= 0x7e for byte in raw)
            for line in raw.decode("ascii").splitlines():
                record = json.loads(line.split("=", 1)[1])
                assert record["status"] == "FAILED"
                assert record["report_status"] == "REPORT_UNAVAILABLE"
            outputs.append(raw)
    assert all(output == outputs[0] for output in outputs)


def test_python_installer_failure_uses_the_same_ascii_vectors(monkeypatch, capsys):
    import auto_update
    import current_user_onboarding as onboarding

    vectors = json.loads((ROOT / "tests/fixtures/g36_public_line_vectors.json").read_text(encoding="utf-8"))["vectors"]
    for vector in vectors:
        monkeypatch.setattr(auto_update, "public_record", lambda *args: {"guidance": vector["text"]})
        onboarding.emit_installer_failure(RuntimeError("fixture"), "onboarding")
        line = capsys.readouterr().err.strip()
        raw = line.encode("ascii")
        assert raw and all(0x20 <= byte <= 0x7e for byte in raw)
        body = line.split("=", 1)[1]
        assert body == '{"guidance":' + vector["expected_json_string_ascii"] + '}'
        assert json.loads(body) == {"guidance": vector["text"]}


def test_python_recovery_failure_uses_ascii_for_each_vector(capsys):
    from writer_session_fence import _emit_machine_recovery_guidance

    vectors = json.loads((ROOT / "tests/fixtures/g36_public_line_vectors.json").read_text(encoding="utf-8"))["vectors"]
    for vector in vectors:
        _emit_machine_recovery_guidance({"owner_kind": "canonical_installer",
                                         "replacement_transaction_id": vector["text"]},
                                        Path("E:/isolated/machine-install/control/writer-session"))
        line = capsys.readouterr().err.strip()
        assert line.encode("ascii")
        record = json.loads(line.split("=", 1)[1])
        assert vector["text"] in record["guidance"]

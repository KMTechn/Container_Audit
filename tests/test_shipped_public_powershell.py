"""Native public boundaries reuse the same attempt's existing private writer."""
import hashlib
import json
from pathlib import Path
import re

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/structured_public_vectors.json'
VECTORS = json.loads(FIXTURE.read_bytes())['vectors']


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('vector', VECTORS, ids=lambda vector: vector['id'])
def test_helper_public_and_every_existing_private_evidence_sink(tmp_path, engine, vector):
    input_path = tmp_path / 'input.json'
    input_path.write_text(json.dumps(vector), encoding='utf-8')
    result = run_functions(tmp_path, ROOT / 'INSTALL_THIS_PC.ps1',
        ['Get-InstallationHelperPublicFailure', 'Write-InstallationHelperPublicRecord'], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/bootstrap_integrity.ps1')
if(Test-InstallationEvidencePrivileged){throw 'This test requires the ordinary operator token.'}
$vector=Get-Content -LiteralPath $env:CA_PUBLIC_VECTOR -Raw -Encoding UTF8|ConvertFrom-Json
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'private') $sid
$canonicalAst=[Management.Automation.Language.Parser]::ParseFile($env:CA_PUBLIC_CANONICAL,[ref]$null,[ref]$null)
foreach($name in @('Write-CanonicalInstallationPublicRecord','ConvertTo-CanonicalAuditJson','Save')){
    $canonicalFunction=@($canonicalAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if($canonicalFunction.Count -ne 1){throw 'Actual canonical public boundary is missing.'}
    Invoke-Expression $canonicalFunction[0].Extent.Text
}
$audit=@{status='FAILED';failure=$vector.text;failure_details=@{message=$vector.text;stdout=$vector.text;stderr=$vector.text;type='System.InvalidOperationException'};
    credential=@{opaque='machine credential';kind='reference'};preimage=@{data='original machine bytes';error_message='machine protocol'}}
Save (Join-Path $env:CA_CONTRACT_ROOT 'caller-audit.json') $audit $true
Save (Join-Path $root 'private-audit.json') $audit $true
$childSource=Join-Path $env:CA_CONTRACT_ROOT 'structured-child.ps1'
$childCode=@'
$value=Get-Content -LiteralPath $args[0] -Raw -Encoding UTF8|ConvertFrom-Json
[Console]::Out.Write([string]$value.text)
[Console]::Error.Write([string]$value.text)
'@
[IO.File]::WriteAllText($childSource,$childCode,[Text.UTF8Encoding]::new($true))
$child=Invoke-InstallationEvidenceChild 'structured-child' (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell/v1.0/powershell.exe') @('-NoProfile','-NonInteractive','-File',$childSource,$env:CA_PUBLIC_VECTOR)
if($child.ExitCode -ne 0){throw 'Structured child fixture failed.'}
Write-InstallationHelperPublicRecord @{stdout=$child.Stdout;stderr=$child.Stderr;status='PASS'}
try{throw ([InvalidOperationException]::new([string]$vector.text))}
catch{
    Write-InstallationCaughtFailure $_
    $public=Get-InstallationHelperPublicFailure $_ 1
    [Console]::Out.WriteLine('HELPER_FAILURE='+($public|ConvertTo-Json -Depth 4 -Compress))
    Write-InstallationHelperPublicRecord @{status='FAILED';error_message=$vector.text;stdout=$vector.text;report_path=$vector.text}
    Write-CanonicalInstallationPublicRecord $_ 1
}
Write-InstallationEvidenceEvent @{event='STRUCTURED_PROBE';diagnostic=$vector.text;stdout=$vector.text;stderr=$vector.text;command_line=$vector.text}
$summary=Complete-InstallationEvidence
foreach($file in Get-ChildItem -LiteralPath $root -File){
    $acl=Get-Acl -LiteralPath $file.FullName -ErrorAction Stop
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($rule.AccessControlType -eq 'Allow' -and
           -not($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
           ([int64]$rule.FileSystemRights -band 1) -and
           $rule.IdentityReference.Value -cnotin @($sid,'S-1-5-18','S-1-5-32-544')){throw 'Existing private writer grants another reader.'}
    }
}
[Console]::Out.WriteLine('PRIVATE_ROOT='+$root)
''', engine=engine, values={'CA_PUBLIC_VECTOR': str(input_path),
                           'CA_PUBLIC_CANONICAL': str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1')})
    if result.returncode:
        pytest.fail('Native public probe failed; exit=' + str(result.returncode), pytrace=False)
    fragments = re.findall(r'[0-9a-f]{64}', vector['text'])
    if any(fragment in result.stdout + result.stderr for fragment in fragments):
        pytest.fail('Structured fragment reached native public output', pytrace=False)
    public = json.loads(next(line.split('=', 1)[1] for line in result.stdout.splitlines()
                            if line.startswith('HELPER_FAILURE=')))
    assert public['status'] == 'FAILED' and public['exit_code'] == 1
    assert 'report_status' not in public
    path = Path(public['report_path'])
    assert path.parent.name.startswith('private.evidence.')
    assert hashlib.sha256(path.read_bytes()).hexdigest() == public['report_sha256']
    assert len(path.read_bytes()) <= 65536
    canonical = json.loads(next(line.split('=', 1)[1] for line in result.stdout.splitlines()
                                if line.startswith('CONTAINER_AUDIT_INSTALL_CANONICAL=')))
    assert canonical['reason_code'] == 'INSTALLER_CANONICAL_FAILURE'
    assert canonical['report_path'] == public['report_path']
    assert canonical['report_sha256'] == public['report_sha256']
    audit_path = tmp_path / 'caller-audit.json'
    if any(fragment in audit_path.read_text(encoding='utf-8') for fragment in fragments):
        pytest.fail('Structured fragment reached unprotected canonical audit', pytrace=False)
    audit = json.loads(audit_path.read_bytes())
    assert audit['failure'] == 'SUPPORT_FAILURE'
    assert audit['failure_details'] == {'message': 'SUPPORT_FAILURE', 'stdout': 'SUPPORT_FAILURE',
                                       'stderr': 'SUPPORT_FAILURE', 'type': 'System.InvalidOperationException'}
    assert audit['credential'] == {'opaque': 'machine credential', 'kind': 'reference'}
    assert audit['preimage'] == {'data': 'original machine bytes', 'error_message': 'machine protocol'}
    # Additional structured shapes are P2 when confined to protected evidence.
    # Keep only counts and paths in this measurement, never diagnostic text.
    measurements = [{'file': file.name, 'bytes': file.stat().st_size,
                     'fragment_count': sum(file.read_bytes().count(fragment.encode())
                                           for fragment in fragments)}
                    for file in path.parent.iterdir() if file.is_file()]
    (tmp_path / 'private-measurements.json').write_text(json.dumps(measurements), encoding='utf-8')


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_helper_refuses_caller_injected_report_authority(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / 'INSTALL_THIS_PC.ps1',
        ['Get-InstallationHelperPublicFailure'], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/bootstrap_integrity.ps1')
if(Test-InstallationEvidencePrivileged){throw 'This test requires the ordinary operator token.'}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'private') $sid
$path=Join-Path $root 'injected.json'
[IO.File]::WriteAllText($path,'{}')
$failure=[InvalidOperationException]::new('synthetic')
$failure.Data['installation_original_failure_reference']=@{path=$path;sha256=Get-FileSha256 $path;atomic_published=$true}
$public=Get-InstallationHelperPublicFailure $failure 1
if($public.report_status -cne 'REPORT_UNAVAILABLE' -or $public.Contains('report_path')){throw 'Caller authority was accepted.'}
'PASS'
''', engine=engine)
    if result.returncode or result.stdout.strip() != 'PASS':
        pytest.fail('Native caller report authority was accepted or probe failed', pytrace=False)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('vector', VECTORS, ids=lambda vector: vector['id'])
def test_update_authority_failure_has_only_public_codes(tmp_path, engine, vector):
    input_path = tmp_path / 'input.json'
    input_path.write_text(json.dumps(vector), encoding='utf-8')
    result = run_functions(tmp_path, ROOT / 'tools/apply_prepared_update.ps1',
        ['Get-StartupUpdatePublicFailure'], r'''
. (Join-Path $env:CA_PRODUCT_ROOT 'tools/bootstrap_integrity.ps1')
$script:StartupUpdateBootstrapLoaded=$true
$vector=Get-Content -LiteralPath $env:CA_PUBLIC_VECTOR -Raw -Encoding UTF8|ConvertFrom-Json
$catch=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[0].CatchClauses[0].Body.Extent.Text
try{throw ([InvalidOperationException]::new([string]$vector.text))}
catch{Invoke-Expression $catch.Substring(1,$catch.Length-2)}
''', engine=engine, values={'CA_PUBLIC_VECTOR': str(input_path), 'CA_PRODUCT_ROOT': str(ROOT)})
    if result.returncode != 1:
        pytest.fail('Update authority failure exit changed', pytrace=False)
    fragments = re.findall(r'[0-9a-f]{64}', vector['text'])
    if any(fragment in result.stdout + result.stderr for fragment in fragments):
        pytest.fail('Structured fragment reached update authority public output', pytrace=False)
    public = json.loads(next(line.split('=', 1)[1] for line in result.stdout.splitlines()
                            if line.startswith('CONTAINER_AUDIT_UPDATE=')))
    assert public['report_status'] == 'REPORT_UNAVAILABLE'
    assert public['reason_code'] == 'STARTUP_UPDATE_FAILURE'
    assert 'report_path' not in public

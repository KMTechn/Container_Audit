"""Run the whole canonical entrypoint with an isolated RunAs cancellation."""
import json
from pathlib import Path
import shutil

import pytest

from tests.powershell_contracts import run_powershell
from tests.test_canonical_installation_callers import _bind_packet
from tests.test_canonical_portable_uninstall import _setup, _tree
from tools.check_release_version import read_current_version


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_whole_canonical_cancelled_placement_releases_fresh_preimage(tmp_path, engine):
    env, source, install, protected = _setup(tmp_path)
    # The uninstall fixture intentionally has no release version and invalid
    # credential JSON. Fresh installation uses the real readonly preflight.
    version = read_current_version(Path(__file__).resolve().parents[1] / 'Container_Audit.py')
    (source / 'app/Container_Audit.py').write_text('CURRENT_VERSION = ' + repr(version) + '\n', encoding='utf-8')
    manifest_path = source / 'portable-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['version'] = version
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    for path in protected:
        if path.name == 'credentials.json':
            path.write_text('{}', encoding='utf-8')
    protected_before = {path: path.read_bytes() for path in protected}
    # Preserve the unused installed fixture instead of deleting a tree.
    install.rename(tmp_path / 'unused-current')
    absent = {'exists': False, 'kind': '', 'data': ''}
    registry = tmp_path / 'registry.json'
    registry.write_text(json.dumps(absent), encoding='utf-8')
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig')
    boundary = "$bootstrapChild = Invoke-InstallationEvidenceChild 'placement-helper' $winps $bootstrap"
    assert text.count(boundary) == 1
    replacement = r'''
function Invoke-IsolatedCancelledPlacement {
    function Test-InstallationEvidencePrivileged {return $false}
    function Assert-InstallationEvidenceProtectedPath {}
    function Get-InstallationEvidenceControlRoot {return Join-Path $env:CA_UNINSTALL_ROOT 'isolated-control'}
    function New-InstallationMemoryTransport {return @{Encoded='isolated';Paths=@()}}
    function Remove-InstallationMemoryTransport {}
    function Start-Process {
        param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru)
        if($Verb -cne 'RunAs' -or $WindowStyle -cne 'Hidden'){throw 'unexpected elevation boundary'}
        [IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'uac-cancelled.json'),'{"runas_calls":1,"visible_windows":0}')
        throw [InvalidOperationException]::new('ISOLATED_USER_CANCELLED_ELEVATION')
    }
    try {
        Invoke-InstallationElevationCapture -Target (Join-Path $source 'INSTALL_THIS_PC.ps1') -Arguments @('-isolated') -AuditBase $elevationLogPath -OperatorSid $operatorSid
        throw 'cancellation seam not reached'
    } catch {Write-InstallationCaughtFailure $_}
    return [pscustomobject]@{ExitCode=1;Stdout='code_placement_preflight_failure=CONTAINER_PLACEMENT_ELEVATION_FAILED';Stderr='';ProcessId=0;Streams=@{};FailureDiagnostic=@{}}
}
$bootstrapChild = Invoke-IsolatedCancelledPlacement
'''
    canonical.write_text(text.replace(boundary, replacement), encoding='utf-8-sig')
    _bind_packet(source)
    source_before = _tree(source)
    executable = shutil.which(engine)
    assert executable is not None
    result = run_powershell([executable, '-NoLogo', '-NoProfile', '-NonInteractive',
        '-File', str(canonical), '-SourceRoot', str(source), '-InstallRoot', str(install),
        '-EvidencePath', str(tmp_path / 'cancel-audit.json'),
        '-AllowNoncanonicalLayoutForTest', '-SkipSignatureValidationForTest'], env=env)
    (tmp_path / 'cancel-stdout.log').write_text(result.stdout, encoding='utf-8')
    (tmp_path / 'cancel-stderr.log').write_text(result.stderr, encoding='utf-8')
    assert result.returncode == 1
    assert json.loads((tmp_path / 'uac-cancelled.json').read_text()) == {'runas_calls': 1, 'visible_windows': 0}
    audit = json.loads((tmp_path / 'cancel-audit.json').read_text(encoding='utf-8-sig'))
    assert audit['status'] == 'FAILED_ROLLED_BACK'
    assert audit['code_replacement']['failure_code'] == 'CONTAINER_PLACEMENT_ELEVATION_FAILED'
    assert audit['code_replacement']['current_absent_before_placement'] is True
    assert audit['rollback']['steps']['generation_readback']['status'] == 'NOT_APPLICABLE_NO_CURRENT'
    assert audit['rollback']['runtime_restored'] is True
    assert audit['rollback']['steps']['fence_release']['status'] == 'PASS'
    # Preserve the original cancellation once in the protected report while
    # every public sink retains the fixed status and exception type only.
    sentinel = 'ISOLATED_USER_CANCELLED_ELEVATION'
    assert sentinel not in result.stdout + result.stderr
    assert sentinel not in (tmp_path / 'cancel-audit.json').read_text(encoding='utf-8-sig')
    reports = Path(env['LOCALAPPDATA']) / 'KMTech/ContainerAudit/install-audit'
    assert sum(sentinel in path.read_text(encoding='utf-8-sig')
               for path in reports.rglob('original-failure*.json')) == 1
    assert not install.exists()
    assert json.loads(registry.read_text(encoding='utf-8-sig')) == absent
    assert _tree(source) == source_before
    assert {path: path.read_bytes() for path in protected} == protected_before
    control = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/control'
    assert not (control / 'writer-session/active.json').exists()
    assert not (control / 'container_audit_user_relay.stop.json').exists()
    public = [json.loads(line.split('=', 1)[1]) for line in result.stdout.splitlines()
              if line.startswith('CONTAINER_AUDIT_INSTALL_CANONICAL=')]
    assert any(row.get('install_status') == 'FAILED_ROLLED_BACK' and
               row.get('reason_code') == 'CONTAINER_PLACEMENT_ELEVATION_FAILED' for row in public)

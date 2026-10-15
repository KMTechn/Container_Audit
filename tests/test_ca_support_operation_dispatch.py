from pathlib import Path
import json
import shutil

import pytest

from tests.powershell_contracts import run_powershell
from tests.test_canonical_portable_uninstall import _setup, _sha
from tests.test_canonical_installation_callers import _bind_packet


@pytest.mark.parametrize('operation', ['restore', 'complete_removal', 'new_install'])
def test_real_top_level_classifies_support_before_worker_requirement(tmp_path, operation):
    """Execute the full top-level argument dispatcher with production flags.

    Stop at the first packet-admission boundary; the receipt/runtime/fence
    behavior is covered by the public restore and retirement lifecycle tests.
    """
    env, source, install, _ = _setup(tmp_path)
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig')
    anchor = '# Classify the requested operation before applying the new-install requirement.'
    assert text.count(anchor) == 1
    # OS identity and the allowed installation location are the only top-level
    # inputs replaced. No operation flag, WorkerAccount guard, or PlanOnly seam.
    probe = """
$testMode=$false
$SkipSignatureValidationForTest=$false
$CanonicalRoot=$InstallRoot
function Get-CanonicalInstallationCallerSecurity {
    return [pscustomobject]@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;session_id=1;elevated=$false}
}
function Manifest([string]$Root,[bool]$UnsignedOk) {
    if($testMode -or $PlanOnly){throw 'PRODUCTION_TOP_LEVEL_REQUIRED'}
    # Ordinary new installation also reaches its validated continuation lookup
    # before the required account decision. Probe that decision directly here.
    if($canonicalOperation -ceq 'INSTALL'){
        try{Assert-CanonicalOperatingWorkerAccount $canonicalOperation}
        catch{
            if($_.Exception.Message.Contains('WorkerAccount')){
                [IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'account-refused.txt'),'REFUSED')
            }
            throw
        }
    }
    [IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'support-dispatch.txt'),$canonicalOperation)
    exit 23
}
"""
    canonical.write_text(text.replace(anchor, probe + anchor), encoding='utf-8-sig', newline='\n')
    _bind_packet(source)
    args = [shutil.which('powershell'), '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(canonical),
            '-SourceRoot', str(source), '-InstallRoot', str(install)]
    if operation == 'restore':
        args += ['-RestoreVerifiedReplacement', '-RestoreReceiptPath', str(tmp_path / 'receipt.json'),
                 '-RestoreReceiptSha256', 'a' * 64]
    elif operation == 'complete_removal':
        args += ['-CompleteRetiredRemoval', '-OldSourceRoot', str(tmp_path / 'old-packet'),
                 '-RetiredRemovalReceiptSha256', 'a' * 64, '-RetiredStopMarkerSha256', 'b' * 64]
    result = run_powershell(args, env=env, capture_output=True, text=True)
    marker = tmp_path / 'support-dispatch.txt'
    (tmp_path / 'dispatch-summary.json').write_text(json.dumps({
        'rc': result.returncode, 'marker': marker.exists(),
        'account_refusal': 'WorkerAccount' in result.stderr + result.stdout,
        'expected_dispatch': marker.exists() and marker.read_text() in {'RESTORE', 'COMPLETE_RETIRED_REMOVAL'},
    }))
    if operation == 'new_install':
        assert result.returncode != 0 and not marker.exists()
        assert (tmp_path / 'account-refused.txt').read_text() == 'REFUSED'
    else:
        assert result.returncode == 23
        assert marker.read_text() == ('RESTORE' if operation == 'restore' else 'COMPLETE_RETIRED_REMOVAL')

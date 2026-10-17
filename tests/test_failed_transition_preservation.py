"""The real removal helper must verify a copy before moving FAILED evidence."""
import json
import hashlib
import re

import pytest

from tests.powershell_contracts import run_functions
from tests.test_convergent_removal import NAMES, REPO


COPY_OBSERVER = r'''
$script:FailedTransitionCopies = 0
function Copy-Item {
    [CmdletBinding()]
    param([string]$LiteralPath, [string]$Path, [string]$Destination,
          [switch]$Recurse, [switch]$Force)
    Microsoft.PowerShell.Management\Copy-Item @PSBoundParameters
    if ($LiteralPath -and (Split-Path -Leaf $LiteralPath) -ceq 'transition.json') {
        $script:FailedTransitionCopies++
        if ($env:CA_FAILED_COPY_MISMATCH -ceq '1') {
            [IO.File]::WriteAllText($Destination, 'copy readback differs')
        }
    }
}
'''

DRIVER = r'''
$ErrorActionPreference='Stop'
$testOverride=$true
. $env:CA_REMOVAL_LIBRARY
function Assert-ContainerRemovalQuiescent {}
function Invoke-ContainerAtomicReplace([string]$Source,[string]$Destination,[string]$Mode) {
    Move-Item -LiteralPath $Source -Destination $Destination
}
function Write-ContainerStartupUpdateRecord([string]$Path,$Payload) {
    [IO.File]::WriteAllText($Path,($Payload|ConvertTo-Json -Depth 12))
}
function Get-BootstrapEmergencyShortcutPath { Join-Path $env:CA_REMOVAL_ROOT 'absent-shortcut.lnk' }
function Get-BootstrapEmergencyRemovalState { return @{status='ABSENT'} }
$failed=$false;$kind='';$missing=''
try { [void](Invoke-ContainerConvergentRemoval (Join-Path $env:CA_REMOVAL_ROOT 'current') $null) }
catch {
    $failed=$true;$kind=$_.Exception.GetType().Name
    if($_.Exception -is [Management.Automation.CommandNotFoundException] -and
        $_.Exception.CommandName -match '^[A-Za-z][A-Za-z0-9-]{0,100}$'){$missing=$_.Exception.CommandName}
}
[IO.File]::WriteAllText((Join-Path $env:CA_REMOVAL_ROOT 'result.json'),
    (@{failed=$failed;error_type=$kind;missing_function=$missing;copy_count=$script:FailedTransitionCopies}|ConvertTo-Json -Compress))
'''


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh"])
@pytest.mark.parametrize("mismatch", [False, True])
def test_failed_transition_copy_readback_precedes_any_removal(tmp_path, engine, mismatch):
    root = tmp_path / "managed"
    current = root / "current"
    current.mkdir(parents=True)
    rows = []
    for relative in ("app/main.py", "runtime/pythonw.exe", "portable-manifest.json"):
        path = current / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = b"isolated removal inventory member"
        path.write_bytes(raw)
        rows.append(dict(path=relative, size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    (current / "bootstrap-integrity.json").write_text(json.dumps(dict(
        schema_version="container-audit-bootstrap-integrity-v1", status="PASS", files=rows,
    )), encoding="utf-8")
    control = root / "update-control"
    control.mkdir()
    transition = control / "transition.json"
    transition.write_text(json.dumps({
        "schema": "container-audit-startup-update-v1", "phase": "FAILED",
        "reason": "readiness verification failed",
        "last_ready_error": "readiness result unavailable",
    }), encoding="utf-8")
    raw = transition.read_bytes()
    script = COPY_OBSERVER + DRIVER
    result = run_functions(tmp_path, REPO / "INSTALL_THIS_PC.ps1", NAMES, script,
                           engine=engine, values={
                               "CA_REMOVAL_ROOT": str(root), "CA_REMOVAL_CUT": "",
                               "CA_REMOVAL_LIBRARY": str(REPO / "tools/bootstrap_integrity.ps1"),
                               "CA_FAILED_COPY_MISMATCH": "1" if mismatch else "0",
                           })
    text = result.stdout + result.stderr
    kinds = [name for name in ("CommandNotFoundException", "ParameterBindingException", "RuntimeException",
                              "PropertyNotFoundStrict", "NamedParameterNotFound", "InvalidOperationException") if name in text]
    diagnostic = dict(returncode=result.returncode, types=kinds,
                      lines=[int(value) for value in re.findall(r"\.ps1:([0-9]+)", text)],
                      symbols=[name for name in ("FailedTransitionCopies", "Copy-Item", "Assert-BootstrapExactFileCopy",
                          "Assert-BootstrapSupportQuiescent", "Read-BootstrapLifecycleJson", "REMOVAL_MACHINE_ARTIFACT_REMAINS",
                          "REMOVAL_REQUIRES_PRODUCT_PROCESS_STOP", "REMOVAL_PROCESS_OBSERVATION_UNKNOWN",
                          "FAILED_TRANSITION_COPY_READBACK_FAILED", "PermissionDenied", "ParameterBinding") if name in text])
    (tmp_path / "removal-diagnostic.json").write_text(json.dumps(diagnostic), encoding="utf-8")
    assert result.returncode == 0
    decision = json.loads((root / "result.json").read_text())
    assert decision["failed"] == mismatch
    assert decision["copy_count"] > 0
    if mismatch:
        assert transition.read_bytes() == raw
    else:
        assert not transition.exists()
        evidence = list((root / "removal-evidence").glob("*/update-control/transition.json"))
        assert len(evidence) == 1 and evidence[0].read_bytes() == raw

"""Removal failures restore owned installation bytes on disposable NTFS trees."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


REPO = Path(__file__).resolve().parents[1]
PRODUCT = "Container"
SCHEMA = "container-audit"

DRIVER = r'''
param([string]$Repo,[string]$Root,[string]$Product,[string]$Cut,[string]$Source)
$ErrorActionPreference='Stop'
. (Join-Path $Repo 'tools/bootstrap_integrity.ps1')
$parseTokens=$null;$parseErrors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$parseTokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'product parse failed'}
foreach($node in $tree.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){
    Invoke-Expression $node.Extent.Text
}
$testOverride=$true;$MachineControlRoot='';$WriterFenceReplacementTransactionId=''
$script:ContainerRemovalAttestedNewPlacement=$false;$script:ContainerMachineRemovalProofKind=''
$script:failures=0;$script:restoreLock=$null
Set-Item ('function:Assert-'+$Product+'RemovalQuiescent') {param($ApplicationRoot,$ExcludeProcessIds)}
function Move-Item {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Destination)
    if($Cut -cin @('after-move','restore-failure') -and (Split-Path -Leaf $LiteralPath) -ceq 'second.bin' -and $script:failures -eq 0){
        Microsoft.PowerShell.Management\Move-Item @PSBoundParameters
        if($Cut -ceq 'restore-failure'){
            $script:restoreLock=[IO.File]::Open($Destination,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
        }
        $script:failures++;throw 'INJECTED_AFTER_RENAME'
    }
    Microsoft.PowerShell.Management\Move-Item @PSBoundParameters
}
if($Product -ceq 'Label'){
    function Invoke-LabelAtomicReplace {
        param([string]$Source,[string]$Destination,[string]$Mode)
        Move-Item -LiteralPath $Source -Destination $Destination
    }
}
$writer={param([string]$Path,$Payload)
    if($Cut -ceq 'marker' -and (Split-Path -Leaf $Path) -ceq 'removed.json'){throw 'INJECTED_MARKER_WRITE'}
    [IO.File]::WriteAllText($Path,($Payload|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))
}
Set-Item ('function:Write-'+$Product+'StartupUpdateRecord') $writer
$locked=$null
if($Cut -cin @('lock-read','lock-none')){
    $share=if($Cut -ceq 'lock-read'){[IO.FileShare]::Read}else{[IO.FileShare]::None}
    $locked=[IO.File]::Open((Join-Path $Root 'update-control/policy.json'),[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
}
$extra=Join-Path $Root '관리용/emergency.lnk'
$begin={if($Cut -ceq 'shortcut-before'){[IO.File]::Delete($extra);throw 'INJECTED_EMERGENCY_FAILURE'}}
$finish={if($Cut -ceq 'shortcut-after'){[IO.File]::Delete($extra);throw 'INJECTED_SHORTCUT_FAILURE'}}
$failure=$false;$guidance=$false
try{[void](& ('Invoke-'+$Product+'ConvergentRemoval') -InstallRoot (Join-Path $Root 'current') -TaskFolder $null -AdditionalPreimageFiles @(@{path=$extra;allowed_hash=''}) -BeforeRemoval $begin -AfterRemoval $finish)}
catch{$failure=$true;for($cause=$_.Exception;$null -ne $cause;$cause=$cause.InnerException){if($cause.Message -ceq '설치 손상: 자료를 보존한 상태로 승인된 새 판을 다시 설치하세요.'){$guidance=$true}}}
finally{if($null -ne $locked){$locked.Dispose()};if($null -ne $script:restoreLock){$script:restoreLock.Dispose()}}
[IO.File]::WriteAllText((Join-Path $Root 'outcome.json'),(@{failed=$failure;guidance=$guidance}|ConvertTo-Json))
'''


def make_tree(root):
    current = root / "current"
    current.mkdir(parents=True)
    owned = {"first.bin": b"first installation bytes", "nested/second.bin": b"second installation bytes"}
    rows = []
    for name, raw in owned.items():
        path = current / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        rows.append(dict(path=name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    (current / "bootstrap-integrity.json").write_text(json.dumps(dict(
        schema_version=SCHEMA + "-bootstrap-integrity-v1", status="PASS", files=rows)), encoding="utf-8")
    control = root / "update-control"
    control.mkdir()
    (control / "policy.json").write_bytes(b'{"fixture":"owned control"}')
    (root / "business").mkdir()
    (root / "business/ledger.bin").write_bytes(b"quantity=7;membership=3")
    (root / "관리용").mkdir()
    (root / "관리용/emergency.lnk").write_bytes(b"owned emergency shortcut bytes")
    return {p.relative_to(root): p.read_bytes() for folder in (current, control, root / "business", root / "관리용")
            for p in folder.rglob("*") if p.is_file()}


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
@pytest.mark.parametrize("cut", ["lock-read", "lock-none", "after-move", "marker", "shortcut-before", "shortcut-after", "restore-failure", "success"])
def test_removal_restores_owned_bytes_on_late_failure(tmp_path, engine, cut):
    executable = shutil.which(engine)
    if not executable:
        pytest.skip("PowerShell engine unavailable")
    root = tmp_path / "application"
    before = make_tree(root)
    driver = tmp_path / "restore-contract.ps1"
    driver.write_text(DRIVER, encoding="utf-8-sig")
    environment = dict(os.environ, PROGRAMDATA=str(tmp_path / "programdata"))
    result = subprocess.run([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(driver),
                             "-Repo", str(REPO), "-Root", str(root), "-Product", PRODUCT, "-Cut", cut,
                             "-Source", os.environ.get("REMOVAL_RESTORE_SOURCE", str(REPO / "INSTALL_THIS_PC.ps1"))],
                            env=environment, capture_output=True, creationflags=0x08000000)
    assert result.returncode == 0, "isolated removal contract driver failed"
    outcome = json.loads((root / "outcome.json").read_text(encoding="utf-8-sig"))
    assert (root / "business/ledger.bin").read_bytes() == before[Path("business/ledger.bin")]
    if cut == "restore-failure":
        assert outcome["failed"] and outcome["guidance"]
        reports = list((root / "removal-evidence").glob("*/rollback.json"))
        assert len(reports) == 1
        record = json.loads(reports[0].read_text(encoding="utf-8-sig"))
        assert record["status"] == "ROLLBACK_FAILED"
        assert record["installation_damaged"] is True
        assert record["business_data_and_registration_preserved"] is True
        assert record["failure_types"]
        assert not (root / "removed.json").exists()
    elif cut == "success":
        assert not outcome["failed"]
        assert not (root / "current").exists()
        assert json.loads((root / "removed.json").read_text(encoding="utf-8-sig"))["lifecycle_state"] == "REMOVED"
    else:
        assert outcome["failed"], "late failure must return failure"
        actual = {p.relative_to(root): p.read_bytes() for folder in (root / "current", root / "update-control", root / "business", root / "관리용")
                  for p in folder.rglob("*") if p.is_file()}
        assert actual == before, "late removal failure must restore the exact original file set and bytes"
        assert not (root / "removed.json").exists()

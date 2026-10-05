"""The consumed legacy task path executes exactly its verified helper bytes."""
import pytest
from pathlib import Path
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("corrupt", (False, True))
def test_legacy_task_helper_binding(tmp_path, engine, corrupt):
    result = run_functions(tmp_path, ROOT / "INSTALL_THIS_PC.ps1", ["Remove-OwnedLegacyTask"], r'''
. $env:CA_CONTRACT_LIBRARY
$owned=Join-Path $env:CA_CONTRACT_ROOT 'owned'
[void][IO.Directory]::CreateDirectory((Join-Path $owned 'tools'))
$helper=Join-Path $owned 'tools\container_writer_fence.ps1'
$body='function Remove-ContainerScheduledTaskUnderWriterFence { $script:remaining=@(); $script:removals++ }'
[IO.File]::WriteAllText($helper,$body,[Text.UTF8Encoding]::new($false))
$pin=Get-FileSha256 $helper
@{writer_fence_helper_sha256=$pin}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $owned 'portable-manifest.json') -Encoding UTF8
$script:removals=0
$script:remaining=@([pscustomobject]@{TaskName='owned-task';TaskPath='\';Actions=@([pscustomobject]@{Execute='owned';Arguments=$owned})})
function Get-LegacyTaskByNameFailClosed {return $script:remaining}
if($env:CA_CONTRACT_CORRUPT -ceq 'True'){
    [IO.File]::WriteAllText($helper,$body+'; throw "unverified helper executed"',[Text.UTF8Encoding]::new($false))
    try{Remove-OwnedLegacyTask 'owned-task' $owned;throw 'invalid helper admitted'}catch{
        if($_.Exception.Message -cne 'Legacy task removal writer-fence helper pin differs.'){throw}
    }
    if($script:removals -ne 0 -or $script:remaining.Count -ne 1){throw 'rejection changed task seam'}
}else{
    Remove-OwnedLegacyTask 'owned-task' $owned
    if($script:removals -ne 1 -or $script:remaining.Count -ne 0){throw 'verified helper was not consumed'}
}
'PASS'
''', engine=engine, values={"CA_CONTRACT_LIBRARY": str(ROOT / "tools/bootstrap_integrity.ps1"),
                           "CA_CONTRACT_CORRUPT": str(corrupt)})
    assert result.returncode == 0, result.stdout + result.stderr

"""Official relay discovery and retirement evidence, using isolated scheduler seams."""
import pytest
from tests.powershell_contracts import run_functions
from tests.test_official_legacy_relay_identity import CANONICAL, XML_SETUP


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('count', (0, 1, 2))
def test_writer_discovery_returns_flat_objects_and_rejects_ambiguous_names(tmp_path, engine, count):
    result = run_functions(tmp_path, CANONICAL, ['Get-CanonicalOfficialLegacyRelayWriters'], XML_SETUP + r'''
function Get-ScheduledTask {
    param($ErrorAction)
    foreach($i in 1..([int]$env:CA_TASK_COUNT)){
        if([int]$env:CA_TASK_COUNT -gt 0){$task}
    }
}
function Export-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction);return $xml}
$rejected=$false
try{$writers=@(Get-CanonicalOfficialLegacyRelayWriters)}catch{$rejected=$_.Exception.Message -ceq 'OFFICIAL_LEGACY_NAME_CARDINALITY_UNKNOWN'}
if([int]$env:CA_TASK_COUNT -gt 1){if(-not $rejected){throw 'Ambiguous official writers admitted.'}}
else{
 if($rejected -or $writers.Count -ne [int]$env:CA_TASK_COUNT){throw 'Discovery count differs.'}
 if($writers.Count -and ($writers[0] -is [array] -or $writers[0].observed_enabled -isnot [bool])){throw 'Scheduler object was nested or its bool was lost.'}
}
'PASS'
''', engine=engine, values={'CA_TASK_COUNT': str(count)})
    assert result.returncode == 0, result.stderr

